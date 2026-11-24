"""Router initiated recommendations only. No command executor or device client."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4
import json

from services.optimization_protocol import DOCUMENT, PULL_PATH, RESULT_PATH, parse_request
from services.router_poll_service import PollError, RouterPollService
from services.routeros_poll_service import RouterOSPollService
from services.router_protocol import ProtocolError, parse_utc_timestamp, utc_text
from services.workflow_service import evaluate, optimization_enabled

AUTH_FIELDS=('active','controller_auth_enabled','controller_auth_ref','controller_auth_key_ids','traffic_source_ip')

class OptimizationPullService:
    def __init__(self,storage,config):
        self.storage,self.config=storage,config

    def check_rate_limit(self,source,now=None):
        RouterPollService(self.storage,self.config).check_rate_limit(source,now,state_document=DOCUMENT)

    def handle(self,raw,key_id,signature,source,kind='optimization',now=None,count_attempt=True):
        now=now or datetime.now(UTC)
        if not isinstance(now,datetime) or now.utcoffset() is None:
            raise PollError('Controller time unavailable.',503,'clock_unavailable')
        if count_attempt: self.check_rate_limit(source,now)
        try:
            payload=parse_request(raw,kind)
        except ProtocolError as exc:
            raise PollError('Invalid optimization request.',400,'invalid_request') from exc
        path=PULL_PATH if kind=='optimization' else RESULT_PATH
        authorized=RouterOSPollService(self.storage,self.config).authenticate(payload,raw,key_id,signature,path,now)
        def exchange(state,inputs,windows,results):
            router=next((r for r in inputs['routers.json'] if r['router_id']==payload['router_id']),None)
            if router is None or any((type(router.get(k)),router.get(k)) != (type(authorized.get(k)),authorized.get(k)) for k in AUTH_FIELDS):
                raise PollError('Authorization changed; retry.',409,'authorization_changed')
            if router.get('traffic_source_ip'):
                from ipaddress import ip_address
                try:
                    source_matches = ip_address(router['traffic_source_ip']) == ip_address(source)
                except (ValueError, TypeError):
                    source_matches = False
                if not source_matches:
                    raise PollError('Source not authorized.',403,'source_mismatch')
            seen=[r for r in state['seen_requests'] if parse_utc_timestamp(r['expires_at'])>=now]
            if any(r['router_id']==payload['router_id'] and r['request_id']==payload['request_id'] for r in seen):
                raise PollError('Request already accepted.',409,'replayed_request')
            if len(seen)>=10000: raise PollError('Replay capacity unavailable.',503,'request_capacity')
            state['seen_requests']=[*seen,{'router_id':payload['router_id'],'request_id':payload['request_id'],
                'expires_at':utc_text(datetime.fromtimestamp(payload['timestamp'],UTC)+timedelta(seconds=self.config.get('ROUTER_REQUEST_MAX_AGE_SECONDS',120)))}]
            issued=int(now.timestamp()); expiry=issued+min(60,self.config.get('ROUTER_RESPONSE_TTL_SECONDS',60))
            response={'protocol_version':'2.0','router_id':payload['router_id'],'request_id':payload['request_id'],
                'response_id':str(uuid4()),'mode':'advisory','action':'none','execution_authorized':False,
                'routing_changes_enabled':False,'issued_at_unix':issued,'expires_at_unix':expiry,
                'recommendation':None,'status':'optimization_unavailable'}
            if kind=='optimization_result':
                # Receipt ACKs cannot prove application. Advisory mode cannot
                # authenticate a claim of authorized execution that never existed.
                if payload['result']=='applied':
                    raise PollError('This decision did not authorize execution.',403,'execution_not_authorized')
                delivery=next((d for d in state['deliveries'] if d['router_id']==payload['router_id']
                    and d['response_id']==payload['response_id'] and d['decision_id']==payload['decision_id']
                    and d['decision_version']==payload['decision_version']),None)
                if delivery is None or parse_utc_timestamp(delivery['expires_at'])<=now:
                    raise PollError('Decision delivery expired or unknown.',409,'unknown_delivery')
                if delivery['result'] is not None:
                    raise PollError('Application result already recorded.',409,'result_already_recorded')
                delivery.update(result=payload['result'],result_at=utc_text(now))
                response.update(status='application_result_recorded',result=payload['result'])
                return response
            preview = evaluate(inputs,windows,results,self.config,now) if optimization_enabled(inputs['automation_settings.json']) else None
            if preview and preview['workflow_version']==2 and preview['status']=='ready':
                group=next((g for g in preview['adaptive']['groups'] if g['aggregation_router_id']==payload['router_id']),None)
                if group and group['decision_id'] and parse_utc_timestamp(group['expires_at'])>now:
                    expiry=min(expiry,int(parse_utc_timestamp(group['expires_at']).timestamp()))
                    if expiry>issued:
                        response.update(status='advisory_recommendation',recommendation=group,expires_at_unix=expiry)
                        if len(json.dumps(response,ensure_ascii=True,separators=(',',':')).encode('utf-8')) > 8192:
                            raise PollError('Advisory response exceeds the native client size limit.',503,'response_capacity')
                        live=[d for d in state['deliveries'] if parse_utc_timestamp(d['expires_at'])>now]
                        state['deliveries']=[*live[-999:],{'router_id':payload['router_id'],'response_id':response['response_id'],
                            'decision_id':group['decision_id'],'decision_version':group['decision_version'],
                            'issued_at':utc_text(now),'expires_at':utc_text(datetime.fromtimestamp(expiry,UTC)),
                            'result':None,'result_at':None}]
            # Same safe public projection as V1's check-in metadata, in a
            # separate document so poll/ACK counters and delivery remain unchanged.
            state['routers'][payload['router_id']]={'last_request_at':utc_text(datetime.fromtimestamp(payload['timestamp'],UTC)),
                'last_authenticated_at':utc_text(now),'last_response_id':response['response_id'],
                'last_response_issued_at':utc_text(now),'mode':'dry_run'}
            return response
        return self.storage.optimization_exchange(exchange)

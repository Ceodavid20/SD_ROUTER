"""Strict independent advisory pull/result contract; legacy poll/ACK is unchanged."""
import json
import re
from services.router_protocol import MAX_REQUEST_BYTES, ProtocolError
from services.routeros_protocol import _constant, _identity, _object, _unix, _uuid4

PULL_PATH = '/api/controller/v2/optimization'
RESULT_PATH = '/api/controller/v2/optimization/result'
DOCUMENT = 'optimization_communication.json'
FIELDS = {'protocol_version','router_id','request_id','timestamp','request_type'}

def parse_request(raw, kind):
    if not isinstance(raw,bytes) or not raw or len(raw)>MAX_REQUEST_BYTES:
        raise ProtocolError('Invalid optimization request size.')
    try:
        payload=json.loads(raw.decode('utf-8'),object_pairs_hook=_object,parse_constant=_constant)
    except (ValueError,UnicodeError,RecursionError) as exc:
        raise ProtocolError('Invalid optimization JSON.') from exc
    extra={'response_id','decision_id','decision_version','result'} if kind=='optimization_result' else set()
    if (not isinstance(payload,dict) or set(payload)!=FIELDS|extra or payload['protocol_version']!='2.0'
            or payload['request_type']!=kind or kind not in ('optimization','optimization_result')):
        raise ProtocolError('Invalid optimization fields.')
    _identity(payload['router_id']); _uuid4(payload['request_id']); _unix(payload['timestamp'])
    if extra:
        _uuid4(payload['response_id'])
        if (not isinstance(payload['decision_id'],str) or not re.fullmatch('[a-f0-9]{64}',payload['decision_id'])
                or type(payload['decision_version']) is not int or not 1<=payload['decision_version']<=2**53-1
                or payload['result'] not in ('not_applied','failed','rejected','applied')):
            raise ProtocolError('Invalid optimization application result.')
    return payload


def validate_state(state):
    from services.router_communication_state import validate_communication_state
    from services.json_storage import ValidationError
    from services.router_protocol import parse_utc_timestamp
    if not isinstance(state,dict) or set(state)!={'schema_version','routers','seen_requests','rate_limits','deliveries'}:
        raise ValidationError('Invalid optimization communication state.')
    validate_communication_state({k:v for k,v in state.items() if k!='deliveries'})
    if not isinstance(state['deliveries'],list) or len(state['deliveries'])>1000:
        raise ValidationError('Invalid optimization delivery capacity.')
    for record in state['deliveries']:
        if not isinstance(record,dict) or set(record)!={'router_id','response_id','decision_id','decision_version','issued_at','expires_at','result','result_at'}:
            raise ValidationError('Invalid optimization delivery record.')
        try:
            _identity(record['router_id']); _uuid4(record['response_id'])
            parse_utc_timestamp(record['issued_at']); parse_utc_timestamp(record['expires_at'])
            if record['result_at'] is not None: parse_utc_timestamp(record['result_at'])
            if (not isinstance(record['decision_id'],str) or not re.fullmatch('[a-f0-9]{64}',record['decision_id'])
                    or type(record['decision_version']) is not int or record['decision_version']<1
                    or record['result'] not in (None,'not_applied','failed','rejected')
                    or (record['result'] is None)!=(record['result_at'] is None)):
                raise ProtocolError('Invalid delivery result.')
        except ProtocolError as exc:
            raise ValidationError('Invalid optimization delivery metadata.') from exc

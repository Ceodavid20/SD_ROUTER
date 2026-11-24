"""Synthetic traffic only; no network or production registry access."""
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import json
from uuid import uuid4

import pytest

from device_app import create_device_app
from services.adaptive_routing import DEFAULT_SETTINGS, feedback_weights, minmax_targets, pcc_distribution, routing_cost
from services.json_storage import ValidationError
from services.path_config_service import PathConfigService
from services.routeros_protocol import ROUTEROS_TRAFFIC_PATH, sign_routeros_request
from services.traffic_service import TrafficService
from services.workflow_service import WorkflowService

NOW = datetime.now(UTC).replace(microsecond=0)
SECRET = "synthetic-adaptive-test-secret-012345678901"

@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Router contact attempted"))
    monkeypatch.setenv("TEST_AGG_PRIMARY_SECRET", SECRET)
    app = create_device_app({"TESTING": True, "DATA_DIR": tmp_path/'data', "OUTPUT_DIR": tmp_path/'output',
        "AUTH_ENABLED": False, "SIMULATION_MODE": True, "LIVE_ROUTING_ENABLED": False,
        "ROUTER_RATE_LIMIT_ATTEMPTS": 1000})
    storage = app.extensions['json_storage']
    storage.write_json('routers.json', [
        {"router_id":"MAIN", "name":"Synthetic main", "controller_auth_enabled":True,
         "controller_auth_ref":"TEST_AGG", "controller_auth_key_ids":["PRIMARY"],
         "interface_name":"to-mtn", "monitoring_interfaces":["to-mtn", "to-glo"], "monitoring_enabled":True},
        {"router_id":"MTN", "name":"Synthetic MTN", "carrier":"MTN", "capacity_confirmed":True},
        {"router_id":"GLO", "name":"Synthetic Glo", "carrier":"GLO", "capacity_confirmed":True}])
    for rid, cap in (("MTN",8_000_000_000),("GLO",4_000_000_000)):
        PathConfigService(storage).add_path({"aggregation_router_id":"MAIN", "carrier_router_id":rid,
            "carrier":rid, "aggregation_interface":"to-"+rid.lower(), "carrier_interface":"ether1",
            "path_capacity_bps":str(cap), "route_role":"primary", "monitor_router_id":"MAIN"})
    service = WorkflowService(storage, app.config)
    service.save_settings({"optimization_objective":"adaptive_mlu", "monitoring_interval_seconds":"10", "averaging_window":"3"})
    return app, storage, service

def send(lab, iface, counter, at=NOW, request_id=None):
    raw = json.dumps({"protocol_version":"2.0", "router_id":"MAIN", "request_id":request_id or str(uuid4()),
        "timestamp":int(at.timestamp()), "request_type":"traffic", "interface":iface, "tx_octets":counter}).encode()
    return TrafficService(lab[1],lab[0].config).handle(raw,"PRIMARY",sign_routeros_request(SECRET,raw,"PRIMARY",ROUTEROS_TRAFFIC_PATH),"127.0.0.1", now=at)

def populate(lab, mtn_bps=4e9, glo_bps=3.8e9, count=3, end=NOW):
    for iface, rate in (("to-mtn",mtn_bps),("to-glo",glo_bps)):
        for index in range(count+1):
            send(lab,iface,1000+int(rate*10/8)*index,end-timedelta(seconds=10*(count-index)))

@pytest.mark.parametrize('demand,a,b',[(3,2,1),(6,4,2),(9,6,3),(9.6,6.4,3.2),(12,8,4)])
def test_requested_mlu_cases(demand,a,b):
    target=minmax_targets(demand*1e9,[8e9,4e9])
    assert target == pytest.approx([a*1e9,b*1e9])
    assert sum(target)==pytest.approx(demand*1e9)
    assert target[0]/8e9 == pytest.approx(target[1]/4e9)

@pytest.mark.parametrize('rates,state', [((6e9,3e9),'balanced'),((6.4e9,3.2e9),'balanced'),
    ((8e9,4e9),'congestion_risk'),((4e9,3.8e9),'unbalanced'),((9e9,4e9),'physical_capacity_exceeded'),((0,0),'balanced')])
def test_integrated_states_and_demand_conservation(lab,rates,state):
    populate(lab,*rates)
    result=lab[2].calculate(now=NOW)
    group=result['adaptive']['groups'][0]
    assert group['status']==state
    assert group['demand_bps']==pytest.approx(sum(rates))
    if sum(rates)<=12e9:
        assert result['status']=='ready'
        assert sum(x['target_bps'] for x in group['links'])==pytest.approx(sum(rates))
        assert all(x['actual_routing_metric'] is None and x['applied_weight'] is None for x in group['links'])
    else:
        assert group['excess_demand_bps']==1e9
        assert all(x['target_bps'] is None for x in group['links'])
        assert group['decision_id'] is None
    assert group['verified_improvement'] is None
    assert result['routing_changes_enabled'] is False

def test_cost_formula_and_tiny_rates():
    assert routing_cost(8e9,0)==13
    assert routing_cost(4e9,.95)==116
    assert routing_cost(8e9,.5)==25
    assert routing_cost(4e9,.2)==29
    assert minmax_targets(.000008,[8e9,4e9]) == pytest.approx([.000008*2/3,.000008/3])

def test_feedback_converges_under_explicit_deterministic_test_model():
    # Test model: many equal-size independent new connections, total load 9Gbps.
    # Production never substitutes this predicted response for observed TX.
    weights=[.4,.6]
    imbalances=[]
    for _ in range(100):
        u=[9e9*weights[0]/8e9,9e9*weights[1]/4e9]
        imbalances.append(abs(u[0]-u[1]))
        previous=weights
        weights=feedback_weights(previous,u)
        assert sum(weights)==pytest.approx(1)
        assert max(abs(x-y) for x,y in zip(weights,previous))<=.05+1e-12
    assert imbalances[-1]<=.05
    assert all(a>=b-1e-12 for a,b in zip(imbalances,imbalances[1:]))
    assert feedback_weights(weights,[.75,.75])==weights

def test_multi_interface_counters_never_mix_replay_or_reset(lab):
    populate(lab,80,8)
    state=lab[1].read_json('router_traffic_v2.json')
    assert state['schema_version']==2
    assert state['routers']['MAIN']['tx_mbps']==.00008
    assert state['interfaces']['MAIN']['to-glo']['tx_mbps']==.000008
    assert len(lab[1].list_traffic())==6
    result=lab[2].calculate(now=NOW)
    assert result['adaptive']['groups'][0]['demand_bps']==88
    send(lab,'to-glo',0,NOW+timedelta(seconds=10))
    reset=lab[2].calculate(now=NOW+timedelta(seconds=10))
    assert reset['status']=='blocked'
    assert reset['adaptive']['groups'][0]['links'][1]['measurement']['state']=='counter_reset'
    assert reset['adaptive']['groups'][0]['links'][0]['measurement']['state']=='ready'

def test_missing_stale_and_shared_interface_withhold_decisions(lab):
    populate(lab,count=1)
    assert lab[2].calculate(now=NOW)['adaptive']['groups'][0]['status']=='insufficient_samples'
    assert lab[2].calculate(now=NOW+timedelta(seconds=181))['adaptive']['groups'][0]['status']=='stale_measurements'
    lab[1].update_json('routing_paths.json',lambda c:{**c,'paths':[{**p,'aggregation_interface':'to-mtn'} for p in c['paths']]})
    assert lab[2].calculate(now=NOW)['adaptive']['groups'][0]['status']=='configuration_required'

def test_carrier_telemetry_cannot_replace_main_tx(lab):
    populate(lab)
    lab[1].update_json('routing_paths.json',lambda c:{**c,'paths':[{**p,'monitor_router_id':p['carrier_router_id']} for p in c['paths']]})
    result=lab[2].calculate(now=NOW)
    assert result['status']=='blocked'
    assert any('health telemetry only' in i['message'] for i in result['issues'])

def test_hold_down_dedup_and_no_advisory_feedback_windup(lab):
    populate(lab)
    first=lab[2].calculate(now=NOW)
    assert lab[2].calculate(now=NOW)['evaluation_id']==first['evaluation_id']
    assert len(lab[1].read_json('optimization_results.json'))==1
    # Real counter update; no decision application has occurred.
    for iface,rate in [('to-mtn',2e9),('to-glo',3.8e9)]:
        record=(lab[1].read_json('router_traffic_v2.json')['routers']['MAIN'] if iface=='to-mtn' else lab[1].read_json('router_traffic_v2.json')['interfaces']['MAIN'][iface])
        send(lab,iface,record['tx_octets']+int(rate*10/8),NOW+timedelta(seconds=10))
    held=lab[2].calculate(now=NOW+timedelta(seconds=10))
    assert held['status']=='hold_down'
    assert held['adaptive']['groups'][0]['decision_id'] is None
    assert all(x['recommended_weight'] is None for x in held['adaptive']['groups'][0]['links'])

def test_unknown_or_injected_result_fields_rejected(lab):
    populate(lab)
    original=lab[2].calculate(now=NOW)
    for target in ('secret','metric','weights','demand'):
        result=deepcopy(original)
        if target=='secret': result['adaptive']['private_key']='do-not-allow'
        elif target=='metric': result['adaptive']['groups'][0]['links'][0]['actual_routing_metric']=10
        elif target=='weights': result['adaptive']['groups'][0]['links'][0]['recommended_weight']=.999
        else: result['adaptive']['groups'][0]['demand_bps']=0
        with pytest.raises(ValidationError): lab[1].write_json('optimization_results.json',[result])

def test_pcc_baseline_and_nonoverlap():
    assert [x['bucket_count'] for x in pcc_distribution([2/3,1/3],3)]==[2,1]
    assert [x['first_bucket'] for x in pcc_distribution([2/3,1/3],3)]==[0,2]

@pytest.mark.parametrize('available,rates,expected',[
    (['available','unavailable'],(4e9,1e9),'carrier_unavailable'),
    (['unavailable','available'],(4e9,1e9),'insufficient_capacity'),
    (['unavailable','unavailable'],(0,0),'carrier_unavailable'),
])
def test_confirmed_carrier_failure_and_unmet_demand(lab,available,rates,expected):
    populate(lab,*rates)
    lab[1].update_json('routing_paths.json',lambda c:{**c,'paths':[{**p,'carrier_availability':a} for p,a in zip(c['paths'],available)]})
    result=lab[2].calculate(now=NOW)
    group=result['adaptive']['groups'][0]
    assert group['status']==expected
    assert group['unmet_demand_bps']==max(0,sum(rates)-group['healthy_capacity_bps'])
    if sum(rates)>group['healthy_capacity_bps'] or group['healthy_capacity_bps']==0:
        assert group['decision_id'] is None and all(x['target_bps'] is None for x in group['links'])
    else:
        assert group['links'][1]['target_bps']==0
        assert group['links'][0]['target_bps']==sum(rates)

def test_api_diagnostic_failure_is_not_carrier_failure(lab):
    populate(lab)
    lab[1].update_json('routers.json',lambda rows:[{**r,'connection_status':'disconnected'} for r in rows])
    group=lab[2].calculate(now=NOW)['adaptive']['groups'][0]
    assert all(x['eligible'] and x['availability']=='unknown' for x in group['links'])


def request(lab,kind='optimization',path=None,now=NOW,body_changes=None,signature_secret=SECRET,extra_raw=None,source='127.0.0.1'):
    from services.optimization_protocol import PULL_PATH,RESULT_PATH
    path=path or (PULL_PATH if kind=='optimization' else RESULT_PATH)
    body={'protocol_version':'2.0','router_id':'MAIN','request_id':str(uuid4()),'timestamp':int(now.timestamp()),'request_type':kind,**(body_changes or {})}
    raw=extra_raw if extra_raw is not None else json.dumps(body).encode()
    return lab[0].test_client().post(path,data=raw,content_type='application/json',
        headers={'X-SDR-Key-Id':'PRIMARY','X-SDR-Signature':sign_routeros_request(signature_secret,raw,'PRIMARY',path)},
        environ_overrides={'REMOTE_ADDR':source})


def test_advisory_pull_and_result_are_separate_from_poll_receipt(lab):
    populate(lab)
    before=lab[1].read_json('router_communication_v2.json')
    lab[2].calculate(now=NOW)
    response=request(lab)
    assert response.status_code==200
    reply=response.get_json()
    assert reply['status']=='advisory_recommendation' and reply['execution_authorized'] is False
    assert reply['action']=='none' and reply['mode']=='advisory'
    recommendation=reply['recommendation']
    fields={k:recommendation[k] for k in ('decision_id','decision_version')}
    fields.update(response_id=reply['response_id'],result='applied')
    rejected=request(lab,'optimization_result',body_changes=fields)
    assert rejected.status_code==403 and rejected.get_json()['code']=='execution_not_authorized'
    fields['result']='not_applied'
    accepted=request(lab,'optimization_result',body_changes=fields)
    assert accepted.status_code==200 and accepted.get_json()['status']=='application_result_recorded'
    assert request(lab,'optimization_result',body_changes=fields).status_code==409
    assert lab[1].read_json('router_communication_v2.json')==before
    assert lab[2].graph_data()['verified_comparisons']==[]


def test_pull_replay_timestamp_strict_json_and_wrong_path_signatures(lab):
    from services.optimization_protocol import PULL_PATH
    nonce=str(uuid4())
    assert request(lab,body_changes={'request_id':nonce}).status_code==200
    assert request(lab,body_changes={'request_id':nonce}).status_code==409
    assert request(lab,body_changes={'timestamp':int(NOW.timestamp())-1000}).status_code==401
    assert request(lab,body_changes={'timestamp':int(NOW.timestamp())+1000}).status_code==401
    assert request(lab,body_changes={'rx_octets':1}).status_code==400
    assert request(lab,body_changes={'timestamp':True}).status_code==400
    assert request(lab,signature_secret='wrong-synthetic-key-0123456789012345').status_code==401
    assert request(lab,extra_raw=b'{"router_id":"MAIN","router_id":"MAIN"}').status_code==400
    assert request(lab,extra_raw=b'{"value":NaN}').status_code==400
    raw=json.dumps({'protocol_version':'2.0','router_id':'MAIN','request_id':str(uuid4()),'timestamp':int(NOW.timestamp()),'request_type':'optimization'}).encode()
    wrong=sign_routeros_request(SECRET,raw,'PRIMARY',ROUTEROS_TRAFFIC_PATH)
    assert lab[0].test_client().post(PULL_PATH,data=raw,content_type='application/json',headers={'X-SDR-Key-Id':'PRIMARY','X-SDR-Signature':wrong}).status_code==401


def test_pull_https_rate_limits_revocation_and_endpoint_isolation(lab):
    from app import create_app
    from services.optimization_protocol import PULL_PATH
    assert request(lab,source='192.0.2.50').status_code==403
    assert create_app({**lab[0].config,'TESTING':True}).test_client().post(PULL_PATH).status_code==404
    lab[0].config['ROUTER_RATE_LIMIT_ATTEMPTS']=1
    assert request(lab).status_code==200
    assert request(lab).status_code==429
    # Changing auth cannot leave a cached recommendation accessible.
    lab[0].config['ROUTER_RATE_LIMIT_ATTEMPTS']=100
    lab[1].update_json('routers.json',lambda rows:[{**r,'controller_auth_enabled':False} if r['router_id']=='MAIN' else r for r in rows])
    assert request(lab).status_code==401


def test_pull_never_delivers_stale_unrelated_or_held_plan(lab):
    from services.optimization_pull_service import OptimizationPullService
    from services.optimization_protocol import PULL_PATH
    populate(lab)
    lab[2].calculate(now=NOW)
    later=NOW+timedelta(seconds=181)
    raw=json.dumps({'protocol_version':'2.0','router_id':'MAIN','request_id':str(uuid4()),'timestamp':int(later.timestamp()),'request_type':'optimization'}).encode()
    reply=OptimizationPullService(lab[1],lab[0].config).handle(raw,'PRIMARY',sign_routeros_request(SECRET,raw,'PRIMARY',PULL_PATH),'127.0.0.1',now=later)
    assert reply['recommendation'] is None and reply['status']=='optimization_unavailable'


def test_graphs_use_actual_history_and_never_predictions_or_ack_as_after(lab):
    from app import create_app
    populate(lab,4e9,3.8e9)
    lab[2].calculate(now=NOW)
    graphs=lab[2].graph_data()
    assert len(graphs['actual'])==2
    assert graphs['actual'][0]['points'][-1]['mbps']==4000
    assert graphs['actual'][1]['points'][-1]['utilization_percent']==95
    assert graphs['verified_comparisons']==[]
    page=create_app(lab[0].config).test_client().get('/optimization')
    assert page.status_code==200
    html=page.get_data(as_text=True)
    assert html.count('data-live-tx ')==1 and 'Recent changes' in html
    assert all(x not in html for x in ('utilization-chart','verified-chart','prediction-chart','health-chart'))
    assert 'Recommendations' in html and 'Advisory' in html
    assert 'Traffic analysis' not in html and 'Estimated financial cost' not in html
    assert SECRET not in html
    lab[1].update_json('routing_paths.json',lambda c:{**c,'paths':[{**p,'aggregation_interface':'to-mtn'} for p in c['paths']]})
    assert lab[2].graph_data()['actual']==[]


def test_new_interface_authorization_disables_collection_and_requires_csrf(lab):
    from app import create_app
    from services.router_service import RouterService
    from services.router_poll_service import PollError
    browser=create_app(lab[0].config).test_client()
    assert browser.post('/routers/MAIN/monitoring-interfaces',data={'interfaces':'a\nb'}).status_code==400
    RouterService(lab[1],lab[0].config).configure_monitoring_interfaces('MAIN',['to-mtn','to-glo','new-channel'])
    assert lab[1].read_json('routers.json')[0]['monitoring_enabled'] is False
    with pytest.raises(PollError): send(lab,'new-channel',1000)


def test_multi_interface_nonce_is_shared_and_unknown_interface_rejected(lab):
    from services.router_poll_service import PollError
    nonce=str(uuid4())
    send(lab,'to-mtn',1000,request_id=nonce)
    with pytest.raises(PollError) as replay: send(lab,'to-glo',1000,request_id=nonce)
    assert replay.value.code=='replayed_request'
    with pytest.raises(PollError) as unknown: send(lab,'not-authorized',1000)
    assert unknown.value.code=='interface_mismatch'


def test_expired_result_and_auth_metadata_race_are_rejected(lab,monkeypatch):
    from services.optimization_protocol import RESULT_PATH
    from services.optimization_pull_service import OptimizationPullService
    from services.router_poll_service import PollError
    populate(lab)
    lab[2].calculate(now=NOW)
    reply=request(lab).get_json()
    recommendation=reply['recommendation']
    at=datetime.fromtimestamp(reply['expires_at_unix']+1,UTC)
    body={'protocol_version':'2.0','router_id':'MAIN','request_id':str(uuid4()),'timestamp':int(at.timestamp()),
          'request_type':'optimization_result','response_id':reply['response_id'],
          'decision_id':recommendation['decision_id'],'decision_version':recommendation['decision_version'],'result':'failed'}
    raw=json.dumps(body).encode()
    with pytest.raises(PollError) as expired:
        OptimizationPullService(lab[1],lab[0].config).handle(raw,'PRIMARY',sign_routeros_request(SECRET,raw,'PRIMARY',RESULT_PATH),'127.0.0.1',kind='optimization_result',now=at)
    assert expired.value.code=='unknown_delivery'
    original=lab[1].optimization_exchange
    def change_and_exchange(callback):
        lab[1].update_json('routers.json',lambda rows:[{**r,'controller_auth_enabled':False} if r['router_id']=='MAIN' else r for r in rows])
        return original(callback)
    monkeypatch.setattr(lab[1],'optimization_exchange',change_and_exchange)
    response=request(lab)
    assert response.status_code==409 and response.get_json()['code']=='authorization_changed'


def test_native_clients_are_disabled_and_cannot_write_routes(lab,tmp_path,monkeypatch):
    monkeypatch.setenv("TEST_AGG_PRIMARY_SECRET", "a"*64)
    from services.traffic_setup_service import prepare_optimization_client, render_traffic_script
    result=prepare_optimization_client(lab[1],'MAIN','PRIMARY','https://controller.example',tmp_path/'bundle',config=lab[0].config)
    script=(tmp_path/'bundle'/'controller-optimization.rsc').read_text()
    assert result['enabled'] is False
    assert ':local sdrOptimizationEnabled false;' in script
    assert 'check-certificate=yes' in script and 'http-max-redirect-count=0' in script
    assert 'decision_version' in script and 'expires_at_unix' in script and 'not_applied' in script
    assert all(command not in script for command in ('/ip/route','/ip route','/routing/ospf','/ip/firewall/mangle',':parse'))
    assert (tmp_path/'bundle'/'controller-optimization.rsc').stat().st_mode & 0o777==0o600
    multi=render_traffic_script('MAIN','PRIMARY','a'*64,'https://controller.example',['to-mtn','to-glo'])
    assert multi.startswith(':local sdrTrafficEnabled false;')
    assert ':local sdrInterface "to-mtn";' in multi and ':local sdrInterface "to-glo";' in multi
    assert 'rx-byte' not in multi


def test_low_rate_graph_and_targets_preserve_precision(lab):
    populate(lab,8,8)
    result=lab[2].calculate(now=NOW)
    assert result['adaptive']['groups'][0]['links'][0]['target_bps']==pytest.approx(16*2/3)
    graph=lab[2].graph_data()
    assert graph['actual'][0]['points'][-1]['mbps']==.000008


def test_no_publication_of_unchanged_advisory_or_integrating_unapplied_weights(lab):
    populate(lab)
    first=lab[2].calculate(now=NOW)
    group=first['adaptive']['groups'][0]
    weights=[x['recommended_weight'] for x in group['links']]
    for t in (10,20,30):
        state=lab[1].read_json('router_traffic_v2.json')
        for iface,rate in [('to-mtn',4e9),('to-glo',3.8e9)]:
            record=state['routers']['MAIN'] if iface=='to-mtn' else state['interfaces']['MAIN'][iface]
            send(lab,iface,record['tx_octets']+int(rate*10/8),NOW+timedelta(seconds=t))
        preview=lab[2].preview(now=NOW+timedelta(seconds=t))
        assert [x['recommended_weight'] for x in preview['adaptive']['groups'][0]['links']]==weights
        assert preview['adaptive']['groups'][0]['decision_version']==1
        lab[2].calculate(now=NOW+timedelta(seconds=t))
    assert len(lab[1].read_json('optimization_results.json'))==1


@pytest.mark.parametrize('baseline,buckets', [([7/12,5/12],3),([7/12,5/12],300),([.1,.2,.3,.4],300)])
def test_discrete_pcc_respects_weight_step(baseline,buckets):
    from services.adaptive_routing import bounded_pcc_distribution
    desired=feedback_weights(baseline,[i/10 for i in range(len(baseline))])
    distribution=bounded_pcc_distribution(desired,baseline,buckets,.05)
    if distribution is None:
        assert buckets==3
    else:
        assert sum(x['bucket_count'] for x in distribution)==buckets
        assert all(abs(x['bucket_count']/buckets-w)<=.05+1e-12 for x,w in zip(distribution,baseline))


def test_advisory_worker_once_publishes_without_any_browser_request(lab,monkeypatch):
    import serve_optimizer
    populate(lab)
    monkeypatch.setattr(serve_optimizer,'load_config',lambda:lab[0].config)
    monkeypatch.setattr(serve_optimizer,'signal',lambda *_:None)
    assert not lab[1].read_json('optimization_results.json')
    assert serve_optimizer.main(['--once'])==0
    assert lab[1].read_json('optimization_results.json')[-1]['objective']=='adaptive_mlu'
    assert serve_optimizer.main(['--once'])==0
    assert len(lab[1].read_json('optimization_results.json'))==1


def test_pull_scope_and_persistent_replay_survive_restart(lab,monkeypatch):
    from services.optimization_protocol import PULL_PATH
    populate(lab)
    lab[2].calculate(now=NOW)
    nonce=str(uuid4())
    assert request(lab,body_changes={'request_id':nonce}).status_code==200
    restarted=create_device_app(lab[0].config)
    assert request((restarted,lab[1],lab[2]),body_changes={'request_id':nonce}).status_code==409
    monkeypatch.setenv('CARRIER_PRIMARY_SECRET',SECRET)
    lab[1].update_json('routers.json',lambda rows:[{**r,'controller_auth_enabled':True,
        'controller_auth_ref':'CARRIER','controller_auth_key_ids':['PRIMARY']} if r['router_id']=='MTN' else r for r in rows])
    reply=request(lab,body_changes={'router_id':'MTN'}).get_json()
    assert reply['status']=='optimization_unavailable' and reply['recommendation'] is None


@pytest.mark.parametrize('field,value', [('status',[]),('demand_bps',None),('total_capacity_bps',None)])
def test_corrupt_adaptive_storage_fails_with_validation_error(lab,field,value):
    populate(lab)
    result=deepcopy(lab[2].calculate(now=NOW))
    result['adaptive']['groups'][0][field]=value
    with pytest.raises(ValidationError): lab[1].write_json('optimization_results.json',[result])


@pytest.mark.parametrize('field', ['utilization_percent','target_utilization_percent','adjustment_bps'])
def test_ready_adaptive_link_requires_all_calculated_numbers(lab,field):
    populate(lab)
    result=deepcopy(lab[2].calculate(now=NOW))
    result['adaptive']['groups'][0]['links'][0][field]=None
    with pytest.raises(ValidationError): lab[1].write_json('optimization_results.json',[result])


def test_chart_provenance_separates_counter_restart_series(lab):
    populate(lab,80,8)
    first=lab[2].graph_data()['actual'][1]['points'][-1]
    send(lab,'to-glo',0,NOW+timedelta(seconds=10))
    send(lab,'to-glo',10,NOW+timedelta(seconds=20))
    graph=lab[2].graph_data()['actual'][1]['points']
    assert graph[-1]['series_id'] != first['series_id']
    assert graph[-1]['mbps']==.000008
    assert all(p['at']!= (NOW+timedelta(seconds=10)).isoformat(timespec='microseconds').replace('+00:00','Z') for p in graph)


def test_unchanged_decision_refreshes_saved_measurements_and_expiry_in_place(lab):
    populate(lab)
    first=lab[2].calculate(now=NOW)
    initial=first['adaptive']['groups'][0]
    for seconds in (60,120,180):
        state=lab[1].read_json('router_traffic_v2.json')
        for iface,rate in [('to-mtn',4e9),('to-glo',3.8e9)]:
            record=state['routers']['MAIN'] if iface=='to-mtn' else state['interfaces']['MAIN'][iface]
            send(lab,iface,record['tx_octets']+int(rate*60/8),NOW+timedelta(seconds=seconds))
        saved=lab[2].calculate(now=NOW+timedelta(seconds=seconds))
        group=saved['adaptive']['groups'][0]
        assert group['decision_id']==initial['decision_id']
        assert group['decision_version']==initial['decision_version']
        assert group['generated_at']==initial['generated_at']
        assert saved['source_fingerprint']!=first['source_fingerprint']
        assert len(lab[1].read_json('optimization_results.json'))==1
    latest=lab[2].read_latest(now=NOW+timedelta(seconds=190))
    assert latest['is_current'] is True
    assert latest['adaptive']['groups'][0]['expires_at']>initial['expires_at']
    assert len(lab[2].graph_data()['events'])==1


def test_live_tx_feed_is_read_only_precise_and_uses_only_main_egress(lab):
    from app import create_app
    populate(lab,80,8)
    client=create_app(lab[0].config).test_client()
    before={name:lab[1].read_json(name) for name in lab[1].DEFAULTS}
    response=client.get('/api/optimization/live')
    assert response.status_code==200 and response.cache_control.no_store
    payload=response.get_json()
    assert payload['refresh_seconds']==5
    assert len(payload['series'])==2
    assert payload['series'][0]['current_mbps']==.00008
    assert payload['series'][1]['current_mbps']==.000008
    assert payload['summary']['total_mbps']==pytest.approx(.000088)
    assert all(row['router_id']=='MAIN' for row in payload['series'])
    assert payload['series'][0]['points'][-1]['mbps']==.00008
    assert 'carrier_health' not in payload and 'verified_comparisons' not in payload
    assert SECRET not in response.get_data(as_text=True)
    assert {name:lab[1].read_json(name) for name in lab[1].DEFAULTS}==before


def test_live_tx_feed_keeps_stale_history_but_withholds_current_rate(lab):
    from services.optimization_graphs import live_view
    populate(lab,80,8)
    payload=live_view(lab[1],lab[0].config,now=NOW+timedelta(seconds=181))
    assert all(row['state']=='stale' and row['current_mbps'] is None for row in payload['series'])
    assert all(len(row['points'])==3 for row in payload['series'])
    assert payload['summary']['total_mbps'] is None and payload['summary']['reporting']==0


def test_live_tx_endpoint_preserves_browser_auth_and_device_isolation(lab):
    from app import create_app
    config={**lab[0].config,'AUTH_ENABLED':True,'ADMIN_USERNAME':'synthetic-user',
            'ADMIN_PASSWORD_HASH':'synthetic-hash','SECRET_KEY':'synthetic-live-chart-session-key'}
    assert create_app(config).test_client().get('/api/optimization/live').status_code==401
    assert lab[0].test_client().get('/api/optimization/live').status_code==404


def test_change_history_separates_recorded_monitoring_from_advisory_and_application(lab):
    from services.optimization_graphs import live_view
    populate(lab)
    lab[1].append_activity('monitoring','Approved isolated carrier TX VLAN handoffs and independent main TX channels verified; routing execution remains disabled.')
    lab[2].calculate(now=NOW)
    reply=request(lab).get_json()
    rec=reply['recommendation']
    response=request(lab,'optimization_result',body_changes={'response_id':reply['response_id'],
        'decision_id':rec['decision_id'],'decision_version':rec['decision_version'],'result':'not_applied'})
    assert response.status_code==200
    changes=live_view(lab[1],lab[0].config,now=NOW)['changes']
    by_title={c['title']:c['status'] for c in changes}
    assert by_title['Carrier TX handoffs connected']=='Applied'
    assert by_title['Recommendation v1']=='Advisory'
    assert by_title['Router reported no change']=='Not applied'
    assert not any('routing applied' in c['title'].lower() for c in changes)


def test_live_change_projection_never_exposes_unknown_legacy_fields_or_messages(lab):
    from services.optimization_graphs import live_view
    populate(lab)
    lab[1].append_activity('legacy',SECRET,{'password':SECRET})
    lab[1].update_json('activity_logs.json',lambda rows:[*rows,{
        'event_id':SECRET,'timestamp':NOW.isoformat().replace('+00:00','Z'),'category':'monitoring',
        'message':'Outbound traffic monitoring setting updated.', 'details':{'enabled':True,'router_id':SECRET,'secret':SECRET}}])
    lab[1].update_json('routers.json',lambda rows:[{**r,'unknown_private_key':SECRET,
        **({'name':{'private':SECRET}} if r['router_id']=='MAIN' else {})} for r in rows])
    payload=live_view(lab[1],lab[0].config,now=NOW)
    assert SECRET not in json.dumps(payload)
    assert payload['routers'][0]['name']=='MAIN'


def test_dashboard_and_optimization_show_one_live_graph_without_instruction_panels(lab):
    from app import create_app
    populate(lab)
    client=create_app(lab[0].config).test_client()
    for path in ('/','/optimization'):
        page=client.get(path)
        assert page.status_code==200
        html=page.get_data(as_text=True)
        assert html.count('id="tx-chart"')==1
        assert 'http-equiv="refresh"' not in html
        assert 'data-tx-reading-values' in html and 'data-tx-follow' in html
        assert all(s not in html for s in ('Routing mechanism and communication','Graph B','Graph C','health-chart','prediction-chart','verified-chart'))
    assert 'data-live-changes' in client.get('/optimization').get_data(as_text=True)


def test_optimization_off_withholds_outputs_without_stopping_tx_or_erasing_history(lab,monkeypatch):
    from services.optimization_graphs import live_view
    populate(lab)
    lab[2].calculate(now=NOW)
    names=('routers.json','routing_paths.json','router_traffic_v2.json','traffic_history.json','optimization_results.json','averages.json','routing_costs.json')
    before={name:lab[1].read_json(name) for name in names}
    assert lab[2].set_optimization_enabled(False) is True
    monkeypatch.setattr('services.adaptive_routing.evaluate_adaptive',lambda *a,**k:pytest.fail('Optimizer ran while off'))
    paused=lab[2].preview(now=NOW)
    assert paused['status']=='disabled' and not paused['allocations'] and not paused['adaptive']['groups']
    assert lab[2].read_latest(now=NOW)['is_current'] is False
    payload=live_view(lab[1],lab[0].config,now=NOW)
    assert payload['summary']['optimization_enabled'] is False
    assert payload['summary']['optimization_status']=='off' and payload['summary']['reporting']==2
    assert payload['summary']['total_mbps']==pytest.approx(7800)
    assert payload['recommendations']==[] and len(payload['series'])==2
    assert {name:lab[1].read_json(name) for name in names}==before
    # Genuine telemetry remains accepted on both channels with optimization off.
    state=lab[1].read_json('router_traffic_v2.json')
    for iface in ('to-mtn','to-glo'):
        record=state['routers']['MAIN'] if iface=='to-mtn' else state['interfaces']['MAIN'][iface]
        send(lab,iface,record['tx_octets']+1000,NOW+timedelta(seconds=10))
    assert len(lab[1].list_traffic())==8


def test_off_blocks_manual_and_delayed_worker_publication_under_the_storage_lock(lab,monkeypatch):
    from services.workflow_service import WorkflowError
    populate(lab)
    lab[2].calculate(now=NOW)
    before=lab[1].read_json('optimization_results.json')
    original=lab[1].calculate_workflow
    def pause_then_commit(callback):
        lab[2].set_optimization_enabled(False)
        return original(callback)
    monkeypatch.setattr(lab[1],'calculate_workflow',pause_then_commit)
    with pytest.raises(WorkflowError,match='off'):
        lab[2].calculate(now=NOW+timedelta(seconds=1))
    assert lab[1].read_json('optimization_results.json')==before


def test_disabled_device_pull_keeps_auth_replay_and_no_action_contract(lab,monkeypatch):
    populate(lab)
    lab[2].calculate(now=NOW)
    lab[2].set_optimization_enabled(False)
    monkeypatch.setattr('services.optimization_pull_service.evaluate',lambda *a,**k:pytest.fail('Device pull ran optimizer while off'))
    deliveries=lab[1].read_json('optimization_communication.json')['deliveries']
    nonce=str(uuid4())
    response=request(lab,body_changes={'request_id':nonce})
    assert response.status_code==200
    payload=response.get_json()
    assert len(payload)==12 and payload['status']=='optimization_unavailable' and payload['recommendation'] is None
    assert payload['action']=='none' and payload['execution_authorized'] is False
    assert request(lab,body_changes={'request_id':nonce}).status_code==409
    assert request(lab,signature_secret='wrong-test-secret-01234567890123456789').status_code==401
    assert lab[1].read_json('optimization_communication.json')['deliveries']==deliveries


def test_optimizer_switch_persists_after_restart_and_resume_preserves_monitor_settings(lab):
    from app import create_app
    populate(lab)
    original=lab[2].calculate(now=NOW)
    settings=lab[1].read_json('automation_settings.json')
    lab[2].set_optimization_enabled(False)
    restarted=create_device_app(lab[0].config)
    service=WorkflowService(restarted.extensions['json_storage'],restarted.config)
    assert service.preview(now=NOW)['status']=='disabled'
    assert service.set_optimization_enabled(True) is True
    resumed=service.calculate(now=NOW)
    assert resumed['status']=='ready'
    assert resumed['adaptive']['groups'][0]['decision_id']==original['adaptive']['groups'][0]['decision_id']
    assert resumed['routing_changes_enabled'] is False
    assert lab[1].read_json('automation_settings.json')==settings
    assert create_app(lab[0].config).test_client().get('/api/optimization/live').get_json()['summary']['optimization_enabled'] is True


def test_optimizer_switch_requires_admin_csrf_and_strict_boolean_form(lab):
    from app import create_app
    from werkzeug.datastructures import MultiDict
    populate(lab)
    client=create_app(lab[0].config).test_client()
    assert client.get('/workflow/optimization').status_code==405
    assert client.post('/workflow/optimization',data={'optimization_enabled':'false'}).status_code==400
    client.get('/optimization')
    with client.session_transaction() as session:csrf=session['csrf_token']
    for value in ('yes','1','','off'):
        assert client.post('/workflow/optimization',data={'csrf_token':csrf,'optimization_enabled':value}).status_code==400
    assert client.post('/workflow/optimization',data=MultiDict([('csrf_token',csrf),('optimization_enabled','true'),('optimization_enabled','false')])).status_code==400
    response=client.post('/workflow/optimization',data={'csrf_token':csrf,'optimization_enabled':'false'},headers={'Accept':'application/json'})
    assert response.status_code==200 and response.get_json()=={'optimization_enabled':False,'routing_changes_enabled':False}
    assert client.get('/api/optimization').get_json()['calculation']['status']=='disabled'
    before=lab[1].read_json('optimization_results.json')
    assert client.post('/workflow/calculate',data={'csrf_token':csrf}).status_code==302
    assert lab[1].read_json('optimization_results.json')==before
    private=create_app({**lab[0].config,'AUTH_ENABLED':True,'ADMIN_USERNAME':'synthetic',
        'ADMIN_PASSWORD_HASH':'synthetic-hash','SECRET_KEY':'synthetic-optimization-control-session'})
    assert private.test_client().post('/workflow/optimization',data={'optimization_enabled':'true'}).status_code==302
    assert lab[0].test_client().post('/workflow/optimization').status_code==404


def test_switch_changes_are_recorded_once_and_worker_skips_when_off(lab,monkeypatch,capsys):
    import serve_optimizer
    from services.optimization_graphs import recent_changes
    populate(lab)
    lab[2].set_optimization_enabled(False)
    lab[2].set_optimization_enabled(False)
    assert len([r for r in lab[1].read_json('activity_logs.json') if r['category']=='optimization_control'])==1
    monkeypatch.setattr(serve_optimizer,'load_config',lambda:lab[0].config)
    monkeypatch.setattr(serve_optimizer,'signal',lambda *_:None)
    monkeypatch.setattr(serve_optimizer.WorkflowService,'calculate',lambda *_:pytest.fail('Off worker attempted calculation'))
    assert serve_optimizer.main(['--once'])==0
    assert 'Optimization is off' in capsys.readouterr().out
    assert not lab[1].read_json('optimization_results.json')
    assert any(r['title']=='Optimization paused' for r in recent_changes(lab[1]))


@pytest.mark.parametrize('invalid',[0,1,'true','false',None,[],{}])
def test_stored_optimizer_enablement_is_a_real_boolean(lab,invalid):
    with pytest.raises(ValidationError):
        lab[1].update_json('automation_settings.json',lambda s:{**s,'optimization_enabled':invalid})


def test_off_wins_if_toggle_changes_during_a_live_dashboard_snapshot(lab,monkeypatch):
    from services.optimization_graphs import live_view
    populate(lab)
    original=WorkflowService.preview
    def preview_then_pause(self,**kwargs):
        result=original(self,**kwargs)
        self.set_optimization_enabled(False)
        return result
    monkeypatch.setattr(WorkflowService,'preview',preview_then_pause)
    view=live_view(lab[1],lab[0].config,now=NOW)
    assert view['summary']['optimization_enabled'] is False
    assert view['recommendations']==[]


def test_worker_observes_switch_changes_without_waiting_for_sample_interval(lab,monkeypatch):
    import serve_optimizer
    populate(lab)
    lab[2].set_optimization_enabled(False)
    waits=[]
    class ControlledStop:
        stopped=False
        def is_set(self):return self.stopped
        def set(self):self.stopped=True
        def wait(self,seconds):
            waits.append(seconds)
            if len(waits)==1:
                assert not lab[1].read_json('optimization_results.json')
                lab[2].set_optimization_enabled(True)
            elif len(waits)==2:
                assert len(lab[1].read_json('optimization_results.json'))==1
                lab[2].set_optimization_enabled(False)
            else:self.stopped=True
    monkeypatch.setattr(serve_optimizer,'Event',ControlledStop)
    monkeypatch.setattr(serve_optimizer,'signal',lambda *_:None)
    monkeypatch.setattr(serve_optimizer,'load_config',lambda:lab[0].config)
    assert serve_optimizer.main([])==0
    assert waits and all(delay<=5 for delay in waits)
    assert len(lab[1].read_json('optimization_results.json'))==1


def test_switch_html_and_legacy_settings_default_to_existing_enabled_state(lab):
    from app import create_app
    populate(lab)
    lab[1].update_json('automation_settings.json',lambda s:{k:v for k,v in s.items() if k!='optimization_enabled'})
    client=create_app(lab[0].config).test_client()
    html=client.get('/optimization').get_data(as_text=True)
    assert 'id="optimization-toggle"' in html and 'aria-checked="true"' in html
    lab[2].set_optimization_enabled(False)
    html=client.get('/optimization').get_data(as_text=True)
    assert 'aria-checked="false"' in html and 'Optimization off' in html
    from services.workflow_state import validate_workflow_result
    validate_workflow_result({k:v for k,v in lab[2].preview(now=NOW).items() if k != "recommendations"})

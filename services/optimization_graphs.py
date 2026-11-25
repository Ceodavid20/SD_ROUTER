"""Public chart projection. Every actual point comes from immutable TX history."""
from collections import Counter
from services.router_protocol import parse_utc_timestamp
from services.traffic_service import monitored_interfaces
from services.router_protocol import ProtocolError


def graph_data(storage, *, include_context=True, config=None, now=None):
    from datetime import UTC, datetime
    from services.link_quality import quality_view
    config = config or {}
    now = now or datetime.now(UTC)
    inputs, results = storage.read_workflow_snapshot()
    quality_state = storage.read_json("link_quality.json")
    from services.live_samples import path_view
    live_inputs = storage.live_snapshot()
    routers={r['router_id']:r for r in inputs['routers.json']}
    paths=[p for p in inputs['routing_paths.json']['paths'] if p['relationship_status']=='operator_selected']
    counts=Counter((p['aggregation_router_id'],p['aggregation_interface']) for p in paths)
    series=[]
    histories = {}
    for path in paths:
        rid,iface=path['aggregation_router_id'],path['aggregation_interface']
        router=routers.get(rid,{})
        try: authorized=iface in monitored_interfaces(router)
        except ProtocolError: authorized=False
        if (path.get('monitor_router_id')!=rid or counts[(rid,iface)]!=1 or not authorized
                or router.get('monitoring_enabled') is not True or not path['path_capacity_bps']):
            continue
        if rid not in histories:
            histories[rid] = storage.list_traffic(limit=3000,router_id=rid)
        rows = histories[rid]
        points=[{'at':row['timestamp'],'mbps':row['tx_mbps'],
                 'utilization_percent':row['tx_mbps']*1e6/path['path_capacity_bps']*100,
                 'series_id':row.get('series_id')}
                for row in rows if row['interface']==iface][-500:]
        series.append({'id':path['path_id'],'name':path['carrier'],'router_id':rid,'interface':iface,
                       'source':rid+' / '+iface,'points':points,
                       'quality':quality_view(path, router, quality_state, config, now)})
        if path.get('live_sampling_enabled') is True:
            sampled = path_view(path, live_inputs, config, now)
            first = sampled['points'][0]['at'] if sampled['points'] else None
            qfirst = sampled['quality']['points'][0]['at'] if sampled['quality']['points'] else None
            sampled['quality']['points'] = [p for p in series[-1]['quality']['points'] if qfirst is None or p['at'] < qfirst] + sampled['quality']['points']
            series[-1].update({k: v for k, v in sampled.items() if k != 'points'})
            series[-1]['points'] = [p for p in points if first is None or p['at'] < first] + sampled['points']
    if not include_context:
        return {'actual': series, 'max_gap_seconds': max(180, inputs['automation_settings.json']['monitoring_interval_seconds']*3)}
    # Carrier-side TX is deliberately separate: it is not main-router demand.
    health=[]
    for router in routers.values():
        if router.get('carrier') and router.get('interface_name'):
            points=[{'at':r['timestamp'],'mbps':r['tx_mbps'],'series_id':r.get('series_id')} for r in storage.list_traffic(limit=500,router_id=router['router_id'])
                    if r['interface']==router['interface_name']]
            health.append({'name':router['carrier'],'source':router['router_id']+' / '+router['interface_name'],'points':points})
    events=[]
    seen=set()
    for result in results:
        if result.get('workflow_version')!=2: continue
        for group in result['adaptive']['groups']:
            if group['decision_id'] and (group['decision_id'],group['decision_version']) not in seen:
                seen.add((group['decision_id'],group['decision_version']))
                events.append({'at':group['generated_at'],'kind':'advisory_published',
                               'decision_id':group['decision_id'],'version':group['decision_version']})
    # There are no execution-authorized decisions in this release. A receipt
    # acknowledgement must never create a verified before/after comparison.
    return {'actual':series,'carrier_health':health,'events':events[-100:],
            'verified_comparisons':[], 'verified_status':'No execution-authorized routing application has been confirmed.',
            'safe_utilization_percent':inputs['automation_settings.json'].get('adaptive_optimization',{}).get('safe_utilization_percent',80),
            'max_gap_seconds':max(180,inputs['automation_settings.json']['monitoring_interval_seconds']*3)}


def recent_changes(storage, limit=10):
    """Project recorded operational events; proposals and receipts are never applied changes."""
    from services.router_protocol import ROUTER_ID
    import hashlib
    registered = {row['router_id'] for row in storage.read_json('routers.json')}
    events = []
    for row in storage.list_activity(limit=150):
        message, category = row.get('message'), row.get('category')
        if not isinstance(message, str):
            continue
        title = None
        status = 'Saved'
        if category == 'monitoring':
            if message.startswith('Approved isolated carrier') and ('verified' in message or 'configured' in message):
                title, status = 'Carrier TX handoffs connected', 'Applied'
            elif message == 'Outbound traffic monitoring setting updated.':
                enabled = row.get('details', {}).get('enabled') if isinstance(row.get('details'), dict) else None
                if type(enabled) is bool:
                    title, status = ('TX collection enabled' if enabled else 'TX collection paused'), 'Applied'
            elif message == 'Outbound TX monitoring interface configured.':
                title = 'TX interface saved'
            elif message in ('RTT jitter enabled.', 'RTT jitter disabled.'):
                title, status = message[:-1], 'Saved'
            elif message in ('Second-by-second sampling enabled.', 'Second-by-second sampling disabled.'):
                title, status = message[:-1], 'Saved'
        elif category == 'routing':
            if message.startswith('Routing path ') and message.endswith((' added.', ' updated.', ' removed.')):
                title = 'Path settings saved'
            elif message == 'Congestion limits updated.':
                title = 'Optimization limits saved'
        elif category == 'routers' and message.startswith('Router ') and 'settings updated' in message:
            title = 'Router settings saved'
        if category == 'optimization_control' and message in ('Optimization enabled.', 'Optimization paused.'):
            title, status = ('Optimization enabled' if message == 'Optimization enabled.' else 'Optimization paused'), 'Applied'
        if category == 'controller' and message == 'Live TX dashboard updated.':
            title, status = 'Interactive TX dashboard updated', 'Applied'
        if title and isinstance(row.get('timestamp'), str):
            try:
                parse_utc_timestamp(row['timestamp'])
            except ProtocolError:
                continue
            detail = None
            rid = row.get('details', {}).get('router_id') if isinstance(row.get('details'), dict) else None
            if isinstance(rid, str) and ROUTER_ID.fullmatch(rid) and rid in registered:
                detail = rid
            events.append({'id': 'activity:' + hashlib.sha256((row['timestamp'] + title + str(detail)).encode()).hexdigest(),
                           'at': row['timestamp'], 'title': title, 'status': status, 'detail': detail})
    _, results = storage.read_workflow_snapshot()
    seen = set()
    for result in reversed(results):
        if result.get('workflow_version') != 2:
            continue
        for group in result['adaptive']['groups']:
            identity = (group['aggregation_router_id'], group['decision_id'], group['decision_version'])
            if not group['decision_id'] or identity in seen:
                continue
            seen.add(identity)
            shares = [f"{link['carrier']} {link['recommended_weight'] * 100:.2f}%"
                      for link in group['links'] if link['recommended_weight'] is not None]
            events.append({'id': 'decision:' + ':'.join(map(str, identity)), 'at': group['generated_at'],
                           'title': f"Recommendation v{group['decision_version']}", 'status': 'Advisory',
                           'detail': ' · '.join(shares)})
    state = storage.read_json('optimization_communication.json')
    for delivery in state['deliveries']:
        result = delivery['result']
        if result is None:
            continue
        events.append({'id': 'report:' + delivery['response_id'], 'at': delivery['result_at'],
                       'title': {'not_applied': 'Router reported no change', 'failed': 'Application reported failed',
                                 'rejected': 'Router rejected recommendation'}[result],
                       'status': {'not_applied': 'Not applied', 'failed': 'Failed', 'rejected': 'Rejected'}[result],
                       'detail': delivery['router_id']})
    events.sort(key=lambda row: parse_utc_timestamp(row['at']), reverse=True)
    return events[:limit]


def live_view(storage, config, *, now=None):
    """Small browser-only snapshot: real main-egress TX, recommendations, recorded changes."""
    from datetime import UTC, datetime
    from services.router_protocol import utc_text
    from services.traffic_service import project_traffic_status
    from services.workflow_service import WorkflowService, optimization_enabled
    current = now or datetime.now(UTC)
    preview = WorkflowService(storage, config).preview(now=current)
    graph = graph_data(storage, include_context=False, config=config, now=current)
    inputs, _ = storage.read_workflow_snapshot()
    inventory = {row['router_id']: row for row in inputs['routers.json']}
    settings = inputs['automation_settings.json']
    enabled = optimization_enabled(settings)
    recommendations = []
    adaptive_links = {link['path_id']: link for group in preview.get('adaptive', {}).get('groups', [])
                      for link in group['links']}
    for row in graph['actual']:
        router = inventory.get(row['router_id'])
        status = project_traffic_status(inputs['router_traffic_v2.json'], settings, config,
            [{**router, 'interface_name': row['interface']}], now=current)[row['router_id']] if router else {}
        if 'sample_interval_seconds' not in row:
            row.update(state=status.get('state', 'awaiting'), current_mbps=status.get('tx_mbps'),
                       sampled_at=status.get('last_sample_at'), sample_interval_seconds=settings['monitoring_interval_seconds'])
        link = adaptive_links.get(row['id'])
        if link:
            measured = link['measurement']['average_bps']
            ready = preview['status'] == 'ready'
            recommendations.append({'id': row['id'], 'name': row['name'],
                'actual_mbps': measured/1e6 if measured is not None else None,
                'target_mbps': link['target_bps']/1e6 if ready and link['target_bps'] is not None else None,
                'change_mbps': link['adjustment_bps']/1e6 if ready and link['adjustment_bps'] is not None else None,
                'cost': link['calculated_cost'], 'weight': link['recommended_weight'] if ready else None})
    # Keep historical calculation objectives readable without substituting their
    # carrier-side measurements into the main-router TX graph.
    if preview['workflow_version'] == 1:
        recommendations = [{'id': r['path_id'], 'name': r['carrier'], 'actual_mbps': r['current_mbps'],
            'target_mbps': r['recommended_mbps'], 'change_mbps': r['change_mbps'], 'cost': None, 'weight': None}
            for r in preview['allocations']]
    if not enabled:
        recommendations = []
    series = graph['actual']
    router_states = project_traffic_status(inputs['router_traffic_v2.json'], settings, config,
                                           list(inventory.values()), now=current)
    public_routers = []
    for rid, router in inventory.items():
        name = router.get('name')
        public_routers.append({'id': rid, 'name': name if isinstance(name, str) and 0 < len(name) <= 128 else rid,
                              'state': router_states[rid]['state'], 'sampled_at': router_states[rid]['last_sample_at']})
    receiving = [row for row in series if row['state'] == 'measured' and row['current_mbps'] is not None]
    return {'updated_at': utc_text(current), 'refresh_seconds': config.get('DASHBOARD_REFRESH_SECONDS', 5),
        'sample_interval_seconds': min((s['sample_interval_seconds'] for s in series), default=settings['monitoring_interval_seconds']),
        'max_gap_seconds': graph['max_gap_seconds'], 'series': series,
        'summary': {'total_mbps': sum(row['current_mbps'] for row in receiving) if series and len(receiving) == len(series) else None,
                    'reporting': len(receiving), 'links': len(series), 'optimization_status': preview['status'] if enabled else 'off', 'optimization_enabled': enabled,
                    'routing_changes_enabled': False},
        'recommendations': recommendations, 'changes': recent_changes(storage), 'routers': public_routers}

"""Real-time measurements must never be fabricated from minute averages."""
from copy import deepcopy
from datetime import timedelta
import json

import pytest

from app import create_app
from device_app import create_device_app
from services.json_storage import ValidationError
from services.link_quality import summarize
from services.live_samples import DOCUMENT, LiveSampleClient, LiveSampleService, live_delta
from services.optimization_graphs import live_view
from services.router_protocol import utc_text
from services.routeros_api import RouterAPIError
from services.workflow_service import policy_fingerprint
from test_link_quality import NOW, enable, quality_lab


@pytest.fixture
def realtime(quality_lab, monkeypatch):
    app, storage, paths, path, *_ = quality_lab
    app.config.update(LIVE_SAMPLE_INTERVAL_SECONDS=1, LIVE_SAMPLE_TIMEOUT_SECONDS=3)
    calls, data = [], {"counter": 1000, "rtts": [1, 2, 4, 4, 6, 7, 7, 8]}
    class Client:
        def __init__(self, *args, **kwargs):
            calls.append((args[:2], kwargs))
        def read_live(self, channels):
            calls.append(channels)
            return {interface: {"at": utc_text(NOW), "tx_octets": data["counter"],
                "quality": {"at": utc_text(NOW), "target": target, **summarize(data["rtts"])} if target else None}
                for interface, target in channels.items()}
    monkeypatch.setattr("services.live_samples.LiveSampleClient", Client)
    return quality_lab, LiveSampleService(storage, app.config), calls, data


def start(lab):
    enable(lab)
    lab[2].configure_live_sampling(lab[3]["path_id"], True)


def test_live_sampling_default_disabled_makes_no_device_requests(realtime):
    lab, service, calls, _ = realtime
    assert service.collect("MAIN", now=NOW) is None and calls == []
    assert lab[1].read_json(DOCUMENT) == {"schema_version": 1, "routers": {}}
    assert live_delta(lab[1], lab[0].config, now=NOW)["series"] == []


def test_one_second_counter_deltas_and_both_metrics_have_real_measurements(realtime):
    lab, service, calls, data = realtime
    before = {name: lab[1].read_json(name) for name in ("routers.json", "router_traffic_v2.json", "traffic_history.json", "router_config.json")}
    start(lab)
    first = service.collect("MAIN", now=NOW)["wanA"]
    assert first["state"] == "baseline" and first["mbps"] is None
    data["counter"] += 125_000
    second = service.collect("MAIN", now=NOW + timedelta(seconds=1))["wanA"]
    assert second["mbps"] == 1 and second["elapsed_seconds"] == 1
    assert second["quality"]["jitter_ms"] == 1 and second["quality"]["replies"] == 8
    assert calls[0][1]["tls"] is True and calls[1] == {"wanA": "10.8.0.2"}
    dto = live_view(lab[1], lab[0].config, now=NOW + timedelta(seconds=1))
    assert dto["series"][0]["current_mbps"] == 1
    assert dto["series"][0]["quality"]["current_jitter_ms"] == 1
    assert dto["sample_interval_seconds"] == dto["series"][0]["quality"]["interval_seconds"] == 1
    assert {name: lab[1].read_json(name) for name in before} == before
    assert "synthetic-private-password" not in json.dumps(dto) and "rx-byte" not in json.dumps(dto)


def test_rate_uses_actual_fractional_elapsed_time_not_a_guessed_second(realtime):
    lab, service, _, data = realtime
    start(lab); service.collect("MAIN", now=NOW)
    data["counter"] += 125_000
    point = service.collect("MAIN", now=NOW + timedelta(seconds=1.25))["wanA"]
    assert point["mbps"] == .8 and point["elapsed_seconds"] == 1.25


def test_small_scheduler_wakeup_variations_do_not_skip_alternate_seconds(realtime):
    lab, service, _, data = realtime
    start(lab);service.collect("MAIN", now=NOW)
    data["counter"] += 1000
    assert service.collect("MAIN", now=NOW + timedelta(seconds=.999))["wanA"]["state"] == "measured"
    assert service.collect("MAIN", now=NOW + timedelta(seconds=1.1)) is None


def test_fast_sampling_replaces_the_slow_jitter_probe_loop(realtime):
    lab, *_ = realtime
    start(lab)
    assert lab[4].collect(lab[3]["path_id"], now=NOW) is None
    assert lab[5] == []


def test_multiple_paths_share_one_authenticated_connection(realtime):
    lab, service, calls, _ = realtime
    second = lab[2].add_path({"aggregation_router_id": "MAIN", "carrier_router_id": "UP2",
        "aggregation_interface": "wanB", "carrier_interface": "uplink", "path_capacity_bps": "1000", "monitor_router_id": "MAIN"})
    start(lab); lab[2].configure_live_sampling(second["path_id"], True)
    assert set(service.collect("MAIN", now=NOW)) == {"wanA", "wanB"}
    assert len(calls) == 2 and calls[1] == {"wanA": "10.8.0.2", "wanB": None}


def test_cadence_leases_and_nonoverlapping_batches(realtime, monkeypatch):
    lab, service, calls, data = realtime
    start(lab)
    class Concurrent:
        def __init__(self, *a, **k): pass
        def read_live(self, channels):
            assert service.collect("MAIN", now=NOW + timedelta(seconds=.2)) is None
            return {"wanA": {"at": utc_text(NOW), "tx_octets": data["counter"], "quality": None}}
    monkeypatch.setattr("services.live_samples.LiveSampleClient", Concurrent)
    assert service.collect("MAIN", now=NOW)
    assert service.collect("MAIN", now=NOW + timedelta(seconds=.9)) is None


def test_disabling_or_changing_authorization_discards_inflight_data(realtime, monkeypatch):
    lab, service, _, _ = realtime
    start(lab)
    class Changing:
        def __init__(self, *a, **k): pass
        def read_live(self, channels):
            lab[2].configure_live_sampling(lab[3]["path_id"], False)
            return {"wanA": {"at": utc_text(NOW), "tx_octets": 1234, "quality": None}}
    monkeypatch.setattr("services.live_samples.LiveSampleClient", Changing)
    assert service.collect("MAIN", now=NOW) is None
    assert lab[1].read_json(DOCUMENT)["routers"]["MAIN"]["channels"]["wanA"]["points"] == []


@pytest.mark.parametrize("mutation", ["tls", "network", "inactive", "monitoring_off"])
def test_tls_source_and_target_authorization_are_required(realtime, mutation):
    lab, service, calls, _ = realtime
    start(lab)
    if mutation == "network":
        lab[0].config["ROUTER_ALLOWED_NETWORKS"] = ["192.168.0.0/16"]
    else:
        key, value = {"tls": ("api_tls", False), "inactive": ("active", False), "monitoring_off": ("monitoring_enabled", False)}[mutation]
        lab[1].update_json("routers.json", lambda rows: [{**r, key: value} if r["router_id"] == "MAIN" else r for r in rows])
    result = service.collect("MAIN", now=NOW)
    assert result is None or result["wanA"]["state"] == "unavailable"
    assert calls == []


def test_resets_staleness_and_unavailable_values_never_fabricate_zero(realtime, monkeypatch):
    lab, service, _, data = realtime
    start(lab);service.collect("MAIN", now=NOW)
    data["counter"] += 1000
    service.collect("MAIN", now=NOW + timedelta(seconds=1))
    stale = live_delta(lab[1], lab[0].config, now=NOW + timedelta(seconds=5))["series"][0]
    assert stale["current_mbps"] is None and stale["quality"]["current_jitter_ms"] is None
    data["counter"] = 1
    assert service.collect("MAIN", now=NOW + timedelta(seconds=5))["wanA"]["state"] == "counter_reset"
    class Failing:
        def __init__(self, *a, **k): pass
        def read_live(self, channels): raise RouterAPIError("Unavailable")
    service.close()
    monkeypatch.setattr("services.live_samples.LiveSampleClient", Failing)
    failed = service.collect("MAIN", now=NOW + timedelta(seconds=6))["wanA"]
    assert failed["state"] == "unavailable" and failed["mbps"] is None


def test_long_sampling_gap_starts_a_new_series_and_real_zero_is_kept(realtime):
    lab, service, _, data = realtime
    start(lab);service.collect("MAIN", now=NOW)
    second = service.collect("MAIN", now=NOW + timedelta(seconds=1))["wanA"]
    assert second["mbps"] == 0
    gap = service.collect("MAIN", now=NOW + timedelta(seconds=5))["wanA"]
    assert gap["state"] == "gap_reset" and gap["series_id"] != second["series_id"]


def test_jitter_loss_breaks_lines_independently_of_tx(realtime):
    lab, service, _, data = realtime
    start(lab);service.collect("MAIN", now=NOW)
    data["rtts"] = [None] * 8
    service.collect("MAIN", now=NOW + timedelta(seconds=1))
    data["rtts"] = [1] * 8
    service.collect("MAIN", now=NOW + timedelta(seconds=2))
    rows = live_delta(lab[1], lab[0].config, now=NOW + timedelta(seconds=2))["series"][0]["quality"]["points"]
    assert rows[1]["jitter_ms"] is None and rows[2]["jitter_ms"] == 0
    assert len({r["series_id"] for r in rows}) == 3


@pytest.mark.parametrize("field,value", [("mbps", float("nan")), ("tx_octets", -1), ("elapsed_seconds", 0), ("rx-byte", 999), ("password", "must-not-be-stored")])
def test_high_resolution_schema_rejects_bad_values_and_unsolicited_fields(realtime, field, value):
    lab, service, _, data = realtime
    start(lab);service.collect("MAIN", now=NOW)
    data["counter"] += 1000
    service.collect("MAIN", now=NOW + timedelta(seconds=1))
    state = lab[1].read_json(DOCUMENT)
    state["routers"]["MAIN"]["channels"]["wanA"]["points"][-1][field] = value
    with pytest.raises(ValidationError): lab[1].write_json(DOCUMENT, state)


def test_live_opt_in_has_csrf_and_does_not_reset_routing_policy(realtime):
    lab, *_ = realtime
    original = policy_fingerprint(lab[1].read_workflow_snapshot()[0])
    start(lab)
    assert policy_fingerprint(lab[1].read_workflow_snapshot()[0]) == original
    client = create_app(lab[0].config).test_client()
    assert client.post('/routing-paths/' + lab[3]['path_id'] + '/live-sampling', data={'live_sampling_enabled': 'false'}).status_code == 400
    html = client.get('/routing-paths').text
    assert 'name="live_sampling_enabled"' in html
    lab[2].save_path(lab[3]['path_id'], {**lab[3], 'aggregation_interface': 'wanB', 'path_capacity_bps': str(lab[3]['path_capacity_bps'])})
    assert lab[1].read_json('routing_paths.json')['paths'][0]['live_sampling_enabled'] is False


def test_delta_endpoint_authentication_cursor_and_persistence(realtime):
    lab, service, _, data = realtime
    start(lab);service.collect("MAIN", now=NOW)
    data["counter"] += 1000
    service.collect("MAIN", now=NOW + timedelta(seconds=1))
    app = create_app(lab[0].config); client = app.test_client()
    response = client.get('/api/optimization/samples')
    assert response.status_code == 200 and response.cache_control.no_store
    assert len(response.json['series'][0]['points']) == 2
    assert client.get('/api/optimization/samples?after=invalid').status_code == 400
    assert client.get('/api/optimization/samples?after=2099-01-01T00:00:00Z').status_code == 400
    app.config['AUTH_ENABLED'] = True
    assert client.get('/api/optimization/samples').status_code == 401
    assert create_device_app(lab[0].config).test_client().get('/api/optimization/samples').status_code == 404


def test_bounded_history_retains_seconds_and_restarts_without_touching_device_history(realtime):
    from services.live_samples import MAX_POINTS
    lab, service, _, data = realtime
    start(lab); service.collect("MAIN", now=NOW)
    state = lab[1].read_json(DOCUMENT)
    channel = state["routers"]["MAIN"]["channels"]["wanA"]
    template = channel["points"][0]
    rows = []
    for index in range(MAX_POINTS):
        row = deepcopy(template); row["at"] = utc_text(NOW - timedelta(seconds=MAX_POINTS - index))
        row["quality"]["at"] = row["at"]; rows.append(row)
    channel["points"] = rows
    lab[1].write_json(DOCUMENT, state)
    data["counter"] += 1000
    service.collect("MAIN", now=NOW + timedelta(seconds=1))
    restarted = create_app(lab[0].config)
    rows = restarted.extensions["json_storage"].read_json(DOCUMENT)["routers"]["MAIN"]["channels"]["wanA"]["points"]
    assert len(rows) == MAX_POINTS and rows[-1]["at"] == utc_text(NOW + timedelta(seconds=1))
    assert lab[1].list_traffic() == []


def test_combined_client_projects_only_selected_tx_and_bounded_rtt(monkeypatch):
    from test_router_discovery_api import Socket, sentence
    reply = sentence('!done')
    reply += sentence('!re', '=name=wanA', '=tx-byte=1234', '=rx-byte=9999', '=password=do-not-return') + sentence('!done')
    for seq in range(8):reply += sentence('!re', '=seq='+str(seq), '=time=1ms', '=password=do-not-return')
    reply += sentence('!done')
    connection = Socket(reply)
    monkeypatch.setattr('socket.create_connection', lambda *a, **k: connection)
    result = LiveSampleClient('10.8.0.1', 9876, 'test', 'test', tls=False).read_live({'wanA': '10.8.0.2'})
    assert result['wanA']['tx_octets'] == 1234 and result['wanA']['quality']['jitter_ms'] == 0
    assert b'=interval=50ms' in connection.sent and b'?name=wanA' in connection.sent
    assert b'rx-byte' not in connection.sent and 'do-not-return' not in json.dumps(result)


def test_persistent_transport_authenticates_once_and_closes_on_failure(monkeypatch):
    from test_router_discovery_api import Socket, sentence
    def batch(counter):
        return sentence('!re', '=name=wanA', '=tx-byte='+str(counter)) + sentence('!done')
    connection = Socket(sentence('!done') + batch(1000) + batch(2000))
    calls = []
    def connect(*a, **k):calls.append(1);return connection
    monkeypatch.setattr('socket.create_connection', connect)
    client = LiveSampleClient('10.8.0.1', 9876, 'test', 'test', tls=False, persistent=True)
    assert client.read_live({'wanA': None})['wanA']['tx_octets'] == 1000
    assert client.read_live({'wanA': None})['wanA']['tx_octets'] == 2000
    assert len(calls) == 1 and bytes(connection.sent).count(b'/login') == 1 and not connection.closed
    with pytest.raises(RouterAPIError):client.read_live({'wanA': None})
    assert connection.closed and client._socket is None

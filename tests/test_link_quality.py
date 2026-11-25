"""RTT jitter uses real probe durations, never bandwidth counter differences."""
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import json

import pytest

from app import create_app
from services.json_storage import StorageService, ValidationError
from services.link_quality import DOCUMENT, LinkQualityService, summarize
from services.optimization_graphs import live_view
from services.path_config_service import PathConfigService
from services.routeros_api import RouterAPIError
from services.routeros_probe import RouterOSProbeClient, probe_address, rtt_milliseconds
from services.workflow_service import policy_fingerprint

NOW = datetime.now(UTC).replace(microsecond=0)


@pytest.mark.parametrize("value,expected", [("123us", .123), ("1ms250us", 1.25), ("25ns", .000025),
    ("2s3ms4us", 2003.004), ("00:00:00.012345", 12.345), ("00:00:01", 1000), ("0ms", 0)])
def test_routeros_rtt_units_are_converted_to_milliseconds(value, expected):
    assert rtt_milliseconds(value) == pytest.approx(expected)


@pytest.mark.parametrize("value", ["123", "-1ms", "nanms", "infms", "1us1ms", "1ms1ms", "00:60:00", "61s", None, True])
def test_ambiguous_or_invalid_rtt_is_rejected(value):
    with pytest.raises(ValueError):
        rtt_milliseconds(value)


def test_adjacent_rtt_variation_and_real_zero():
    result = summarize([1, 2, 4, 4, 6, 7, 7, 8])
    assert result == {"jitter_ms": 1, "mean_rtt_ms": 4.875, "replies": 8, "probes_requested": 8, "adjacent_pairs": 7, "status": "measured"}
    assert summarize([2] * 8)["jitter_ms"] == 0
    assert summarize([None] * 8)["jitter_ms"] is None


def test_lost_packets_do_not_create_fake_pairs_or_zero_jitter():
    assert summarize([1, None, 99, None, 1, None, 99, None])["jitter_ms"] is None
    result = summarize([1, 3, None, 20, 24, None, None, None])
    assert result["jitter_ms"] == 3 and result["adjacent_pairs"] == 2 and result["status"] == "partial"
    assert summarize([4, *([None] * 7)])["status"] == "insufficient_replies"


@pytest.mark.parametrize("target", [1234, "example.test", "127.0.0.1", "0.0.0.0", "224.0.0.1", "fe80::1", "2001:db8::1%eth1", "10.8.0.2\n=disabled=no"])
def test_probe_targets_are_literal_unicast_addresses(target):
    with pytest.raises(ValueError):
        probe_address(target)


@pytest.fixture
def quality_lab(tmp_path, monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Unexpected router contact"))
    env = tmp_path / "api.env"
    env.write_text("READER_USERNAME=synthetic-read-account\nREADER_PASSWORD=synthetic-private-password\n")
    env.chmod(0o600)
    app = create_app({"TESTING": True, "AUTH_ENABLED": False, "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "out",
        "API_CREDENTIALS_ENV_FILE": env, "ROUTER_CA_FILE": None, "ROUTER_ALLOWED_NETWORKS": ["10.8.0.0/24"],
        "JITTER_INTERVAL_SECONDS": 60, "JITTER_API_TIMEOUT_SECONDS": 10})
    storage = app.extensions["json_storage"]
    storage.write_json("routers.json", [
        {"router_id": "MAIN", "name": "Main router", "ip_address": "10.8.0.1", "api_port": 9876, "api_tls": True,
         "credential_ref": "READER", "api_credentials_source": "private_env", "interface_name": "wanA", "monitoring_interfaces": ["wanA", "wanB"], "monitoring_enabled": True},
        {"router_id": "UP1", "name": "Fibre", "carrier": "Fibre"}, {"router_id": "UP2", "name": "Satellite", "carrier": "Satellite"}])
    paths = PathConfigService(storage)
    path = paths.add_path({"aggregation_router_id": "MAIN", "carrier_router_id": "UP1", "aggregation_interface": "wanA",
        "carrier_interface": "provider-port", "path_capacity_bps": "123000000", "monitor_router_id": "MAIN", "route_role": "primary"})
    samples = [1, 2, 4, 4, 6, 7, 7, 8]
    calls = []
    class Probe:
        def __init__(self, *args, **kwargs):
            calls.append((args[0], args[1], kwargs))
        def ping(self, target, interface):
            assert target == "10.8.0.2" and interface == "wanA"
            return samples
    monkeypatch.setattr("services.link_quality.RouterOSProbeClient", Probe)
    return app, storage, paths, path, LinkQualityService(storage, app.config), calls, samples


def enable(lab):
    app, _, paths, path, *_ = lab
    paths.configure_jitter(path["path_id"], "10.8.0.2", True, app.config)


def test_default_disabled_has_no_network_contact(quality_lab):
    app, storage, _, path, service, calls, _ = quality_lab
    assert service.collect(path["path_id"], now=NOW) is None
    assert calls == [] and storage.read_json(DOCUMENT)["links"] == {}
    view = live_view(storage, app.config, now=NOW)
    assert view["series"][0]["quality"]["state"] == "disabled"
    assert view["series"][0]["quality"]["current_jitter_ms"] is None


def test_measured_quality_is_private_finite_and_independent_of_tx_and_optimization(quality_lab):
    app, storage, _, path, service, calls, _ = quality_lab
    before = {name: storage.read_json(name) for name in ("routers.json", "router_traffic_v2.json", "traffic_history.json", "router_config.json")}
    enable(quality_lab)
    storage.update_json("automation_settings.json", lambda s: {**s, "optimization_enabled": False})
    result = service.collect(path["path_id"], now=NOW)
    assert result["jitter_ms"] == 1 and result["status"] == "measured"
    assert calls[0][0:2] == ("10.8.0.1", 9876) and calls[0][2]["tls"] is True
    assert {name: storage.read_json(name) for name in before} == before
    payload = live_view(storage, app.config, now=NOW)
    quality = payload["series"][0]["quality"]
    assert quality["current_jitter_ms"] == 1 and quality["points"][0]["target"] == "10.8.0.2"
    assert payload["summary"]["optimization_enabled"] is False
    assert "synthetic-private-password" not in json.dumps(payload)
    assert "rx-byte" not in json.dumps(payload)
    stale = live_view(storage, app.config, now=NOW+timedelta(seconds=181))["series"][0]["quality"]
    assert stale["state"] == "stale" and stale["current_jitter_ms"] is None and stale["points"]


def test_probe_cadence_is_locked_between_workers(quality_lab, monkeypatch):
    _, _, _, path, service, calls, samples = quality_lab
    enable(quality_lab)
    class ConcurrentProbe:
        def __init__(self, *args, **kwargs): pass
        def ping(self, target, interface):
            assert service.collect(path["path_id"], now=NOW+timedelta(seconds=1)) is None
            return samples
    monkeypatch.setattr("services.link_quality.RouterOSProbeClient", ConcurrentProbe)
    assert service.collect(path["path_id"], now=NOW)
    assert service.collect(path["path_id"], now=NOW+timedelta(seconds=59)) is None


def test_inflight_target_or_enablement_change_discards_observation(quality_lab, monkeypatch):
    app, storage, paths, path, service, _, samples = quality_lab
    enable(quality_lab)
    class ChangingProbe:
        def __init__(self, *args, **kwargs): pass
        def ping(self, target, interface):
            paths.configure_jitter(path["path_id"], target, False, app.config)
            return samples
    monkeypatch.setattr("services.link_quality.RouterOSProbeClient", ChangingProbe)
    assert service.collect(path["path_id"], now=NOW) is None
    assert storage.read_json(DOCUMENT)["links"][path["path_id"]]["samples"] == []


def test_failures_remain_gaps_and_start_new_series(quality_lab, monkeypatch):
    _, storage, _, path, service, _, samples = quality_lab
    enable(quality_lab)
    first = service.collect(path["path_id"], now=NOW)
    class FailingProbe:
        def __init__(self, *a, **k): pass
        def ping(self, *a): raise RouterAPIError("Fixed safe failure.")
    monkeypatch.setattr("services.link_quality.RouterOSProbeClient", FailingProbe)
    failed = service.collect(path["path_id"], now=NOW+timedelta(seconds=61))
    assert failed["status"] == "unavailable" and failed["jitter_ms"] is None
    assert failed["series_id"] != first["series_id"]
    assert storage.read_json(DOCUMENT)["links"][path["path_id"]]["lease_id"] is None


def test_plaintext_api_never_used_for_probes(quality_lab):
    _, storage, _, path, service, calls, _ = quality_lab
    enable(quality_lab)
    storage.update_json("routers.json", lambda rows: [{**r, "api_tls": False} if r["router_id"] == "MAIN" else r for r in rows])
    assert service.collect(path["path_id"], now=NOW)["status"] == "unavailable"
    assert calls == []


def test_jitter_settings_do_not_invalidate_routing_fingerprint(quality_lab):
    _, storage, _, _, _, _, _ = quality_lab
    inputs, _ = storage.read_workflow_snapshot()
    before = policy_fingerprint(inputs)
    enable(quality_lab)
    inputs, _ = storage.read_workflow_snapshot()
    assert policy_fingerprint(inputs) == before


def test_jitter_settings_are_csrf_protected_and_reject_outside_targets(quality_lab):
    app, storage, paths, path, *_ = quality_lab
    before = storage.read_json("routing_paths.json")
    client = app.test_client()
    assert client.post('/routing-paths/'+path['path_id']+'/jitter', data={"jitter_enabled": "true", "jitter_target": "10.8.0.2"}).status_code == 400
    assert storage.read_json("routing_paths.json") == before
    with pytest.raises(ValidationError):
        paths.configure_jitter(path["path_id"], "8.8.8.8", True, app.config)


def test_corrupted_or_injected_quality_fields_rejected(quality_lab):
    _, storage, _, path, service, *_ = quality_lab
    enable(quality_lab)
    service.collect(path["path_id"], now=NOW)
    original = storage.read_json(DOCUMENT)
    for field, value in (("jitter_ms", -1), ("jitter_ms", float("nan")), ("replies", 1), ("password", "must-not-expose")):
        changed = deepcopy(original)
        changed["links"][path["path_id"]]["samples"][0][field] = value
        with pytest.raises(ValidationError):
            storage.write_json(DOCUMENT, changed)


@pytest.mark.parametrize("words", [["/ping", "=address=10.8.0.2", "=interface=wanA", "=count=9999", "=interval=200ms"],
    ["/ping", "=address=example.test", "=interface=wanA", "=count=8", "=interval=200ms"],
    ["/system/script/run", "=.id=*A"], ["/ip/route/set", "=distance=1"]])
def test_probe_command_allowlist_preserves_write_restrictions(words):
    client = RouterOSProbeClient("10.8.0.1", 9876, "test", "test")
    with pytest.raises(RouterAPIError):
        client._talk(words)


def test_probe_parses_per_packet_frames_and_drops_unsolicited_fields(monkeypatch):
    from test_router_discovery_api import Socket, sentence
    reply = sentence("!done")
    for seq in range(8):
        reply += sentence("!re", "=seq="+str(seq), "=time="+str(seq+1)+"ms", "=rx-byte=999", "=password=do-not-return")
    reply += sentence("!done")
    connection = Socket(reply)
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: connection)
    result = RouterOSProbeClient("10.8.0.1", 9876, "test-user", "test-pass", tls=False).ping("10.8.0.2", "wanA")
    assert result == [1,2,3,4,5,6,7,8] and connection.closed
    assert b"=interface=wanA" in connection.sent and b"=count=8" in connection.sent
    assert b"rx-byte" not in connection.sent

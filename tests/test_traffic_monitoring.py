"""TX ingestion integration, counter math and durable failure recovery.

All data/keys are synthetic and every network connection is forbidden.
"""

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import json
import multiprocessing
from uuid import uuid4

import pytest

from app import create_app
from device_app import create_device_app
from services.json_storage import StorageError, StorageService, ValidationError
from services.router_poll_service import PollError
from services.routeros_protocol import (
    ROUTEROS_ACK_PATH, ROUTEROS_POLL_PATH, ROUTEROS_TRAFFIC_PATH, sign_routeros_request,
)
from services.traffic_service import TrafficService
from services.traffic_service import read_traffic_status
from services.router_service import RouterService, RouterValidationError
from services.traffic_state import TRAFFIC_DOCUMENT, validate_traffic_state


SECRET = "synthetic-tx-test-key-0123456789abcdefghijklmnopqrstuvwxyz"
OTHER_SECRET = "synthetic-other-tx-key-0123456789abcdefghijklmnopqrstuvwxyz"
NOW = datetime(2026, 11, 23, 12, tzinfo=UTC)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Telemetry contacted a router"))


@pytest.fixture
def config(tmp_path):
    return {
        "TESTING": True, "SIMULATION_MODE": True, "LIVE_ROUTING_ENABLED": False,
        "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output",
        "ROUTER_RATE_LIMIT_ATTEMPTS": 100, "ROUTER_RATE_LIMIT_WINDOW_SECONDS": 60,
        "ROUTER_REQUEST_MAX_AGE_SECONDS": 120, "ROUTER_CLOCK_SKEW_SECONDS": 30,
    }


@pytest.fixture
def app(config, monkeypatch):
    monkeypatch.setenv("TEST_TX_R1_PRIMARY_SECRET", SECRET)
    application = create_device_app(config)
    application.extensions["json_storage"].write_json("routers.json", [{
        "router_id": "TEST-TX-R1", "name": "Synthetic TX router",
        "controller_auth_ref": "TEST_TX_R1", "controller_auth_enabled": True,
        "controller_auth_key_ids": ["PRIMARY"], "monitoring_enabled": False,
        "interface_name": "test-uplink", "connection_status": "disconnected",
        "legacy_secret": "synthetic-hidden-registry-value",
    }])
    return application


def store(app):
    return app.extensions["json_storage"]


def state(app):
    return store(app).read_json(TRAFFIC_DOCUMENT)


def registry(app, **changes):
    def change(rows):
        rows[0].update(changes)
        return rows
    store(app).update_json("routers.json", change)


def enable(app):
    registry(app, monitoring_enabled=True)


def payload(**changes):
    return {
        "protocol_version": "2.0", "router_id": "TEST-TX-R1", "request_id": str(uuid4()),
        "timestamp": int(datetime.now(UTC).timestamp()), "request_type": "traffic",
        "interface": "test-uplink", "tx_octets": 1000, **changes,
    }


def encoded(body):
    return json.dumps(body, separators=(",", ":")).encode()


def headers(raw, *, secret=SECRET, key_id="PRIMARY", path=ROUTEROS_TRAFFIC_PATH):
    return {"X-SDR-Key-Id": key_id, "X-SDR-Signature": sign_routeros_request(secret, raw, key_id, path)}


def send(app, body=None, *, secret=SECRET, key_id="PRIMARY", path=ROUTEROS_TRAFFIC_PATH, **options):
    raw = encoded(body or payload())
    return app.test_client().post(path, data=raw, content_type="application/json",
                                 headers=headers(raw, secret=secret, key_id=key_id, path=path), **options)


def exchange(app, seconds=0, counter=1000, *, body=None, now=None):
    current = NOW + timedelta(seconds=seconds)
    body = body or payload(timestamp=int(current.timestamp()), tx_octets=counter)
    raw = encoded(body)
    return TrafficService(store(app), app.config).handle(
        raw, "PRIMARY", headers(raw)["X-SDR-Signature"], "127.0.0.1", now=now or current,
    )


def test_monitoring_is_disabled_until_explicitly_enabled_and_does_not_consume_nonce(app):
    body = payload()
    assert send(app, body).status_code == 403
    assert state(app)["routers"] == {} and state(app)["seen_requests"] == []
    assert store(app).list_traffic() == []
    enable(app)
    response = send(app, body)
    assert response.status_code == 200
    assert response.get_json()["sample_state"] == "baseline"
    assert response.get_json()["tx_mbps"] is None
    assert store(app).list_traffic() == []


def test_counter_delta_uses_decimal_mbps_and_elapsed_sample_time(app):
    enable(app)
    first = exchange(app, 0, 1_000_000)
    assert first["sample_state"] == "baseline" and first["tx_mbps"] is None
    measured = exchange(app, 10, 16_625_000)
    assert measured["tx_mbps"] == 12.5
    assert measured["sample_state"] == "measured"
    assert measured["action"] == "none" and measured["configuration"] == {}
    history = store(app).list_traffic()
    assert len(history) == 1
    assert history[0]["tx_mbps"] == 12.5 and history[0]["interval_seconds"] == 10
    assert history[0]["tx_octets"] == 16_625_000
    assert history[0]["interface"] == "test-uplink"
    assert exchange(app, 20, 16_625_000)["tx_mbps"] == 0
    assert len(store(app).list_traffic()) == 2


def test_large_counters_subtract_as_integers_before_conversion(app):
    enable(app)
    exchange(app, 0, 2**64 - 2_000_000)
    assert exchange(app, 1, 2**64 - 1_000_000)["tx_mbps"] == 8


@pytest.mark.parametrize("seconds", [0, -1])
def test_duplicate_or_out_of_order_sample_time_does_not_rewind_baseline(app, seconds):
    enable(app)
    exchange(app)
    before = deepcopy(state(app)["routers"])
    with pytest.raises(PollError) as error:
        exchange(app, seconds, 5000)
    assert error.value.code == "out_of_order_sample"
    assert state(app)["routers"] == before
    assert len(state(app)["seen_requests"]) == 1
    assert store(app).list_traffic() == []


def test_counter_decrease_rebaselines_instead_of_emitting_negative_or_wrap_spike(app):
    enable(app)
    exchange(app, 0, 2**64 - 1)
    reset = exchange(app, 10, 100)
    assert reset["sample_state"] == "counter_reset" and reset["tx_mbps"] is None
    assert store(app).list_traffic() == []
    assert exchange(app, 20, 10_000_100)["tx_mbps"] == 8


def test_long_gaps_rebaseline_and_resume_on_next_reading(app):
    enable(app)
    exchange(app)
    gap = exchange(app, 181, 1_000_000)
    assert gap["sample_state"] == "gap_reset" and gap["tx_mbps"] is None
    assert exchange(app, 191, 11_000_000)["tx_mbps"] == 8


def test_only_the_one_configured_interface_can_report(app):
    enable(app)
    for interface in ("ether2", "test-uplink,ether2", "TEST-UPLINK"):
        assert send(app, payload(interface=interface)).status_code == 403
    assert state(app)["routers"] == {}
    registry(app, interface_name="replacement-uplink")
    assert send(app).status_code == 403
    assert send(app, payload(interface="replacement-uplink")).status_code == 200


@pytest.mark.parametrize("interface", [None, "", "bad\ninterface"])
def test_enabled_legacy_router_with_invalid_interface_fails_closed(app, interface):
    registry(app, monitoring_enabled=True, interface_name=interface)
    assert send(app).status_code == 403
    assert state(app)["routers"] == {}


def test_interface_and_generation_changes_establish_new_baselines(app):
    enable(app)
    exchange(app)
    registry(app, interface_name="new-uplink")
    changed = payload(timestamp=int((NOW + timedelta(seconds=10)).timestamp()), interface="new-uplink")
    assert exchange(app, body=changed, seconds=10)["sample_state"] == "baseline"
    registry(app, interface_name="test-uplink", monitoring_generation=str(uuid4()))
    assert exchange(app, 20, 1_000_000)["sample_state"] == "baseline"
    assert store(app).list_traffic() == []


@pytest.mark.parametrize("secret", [OTHER_SECRET, "x" * 32])
def test_wrong_signature_is_generic_and_cannot_write_traffic(app, secret):
    enable(app)
    result = send(app, secret=secret)
    assert result.status_code == 401
    assert result.get_json()["error"] == "Router authentication failed."
    assert state(app)["routers"] == {} and store(app).list_traffic() == []


@pytest.mark.parametrize("changes", [
    {"router_id": "UNKNOWN"}, {"rx_octets": 42}, {"configuration": {"cost": 1}},
    {"rx": {"octets": 0}}, {"tx_mbps": 10},
])
def test_unknown_identity_and_extra_metrics_cannot_create_readings(app, changes):
    enable(app)
    assert send(app, payload(**changes)).status_code == (401 if "router_id" in changes else 400)
    assert state(app)["routers"] == {} and store(app).list_traffic() == []


def test_missing_headers_and_body_or_path_tampering_are_rejected(app):
    enable(app)
    raw = encoded(payload())
    client = app.test_client()
    assert client.post(ROUTEROS_TRAFFIC_PATH, data=raw, content_type="application/json").status_code == 401
    for signed in (headers(raw, path=ROUTEROS_POLL_PATH), headers(raw + b" ")):
        assert client.post(ROUTEROS_TRAFFIC_PATH, data=raw, content_type="application/json", headers=signed).status_code == 401
    assert state(app)["routers"] == {}


@pytest.mark.parametrize("changes", [
    {"controller_auth_enabled": False}, {"controller_auth_enabled": "true"},
    {"controller_auth_ref": "../ENV"}, {"controller_auth_key_ids": []},
    {"controller_auth_key_ids": ["PRIMARY", "PRIMARY"]},
])
def test_disabled_or_invalid_authentication_metadata_is_rejected(app, changes):
    enable(app)
    registry(app, **changes)
    assert send(app).status_code == 401
    assert state(app)["routers"] == {}


def test_rotated_keys_and_revocation_take_effect_without_restart(app, monkeypatch):
    enable(app)
    monkeypatch.setenv("TEST_TX_R1_NEXT_SECRET", OTHER_SECRET)
    registry(app, controller_auth_key_ids=["NEXT"])
    assert send(app).status_code == 401
    assert send(app, key_id="NEXT", secret=OTHER_SECRET).status_code == 200
    registry(app, controller_auth_enabled=False)
    assert send(app, key_id="NEXT", secret=OTHER_SECRET).status_code == 401


@pytest.mark.parametrize("seconds", [-121, 31])
def test_stale_or_future_timestamp_is_rejected(app, seconds):
    enable(app)
    body = payload(timestamp=int((NOW + timedelta(seconds=seconds)).timestamp()))
    with pytest.raises(PollError) as error:
        exchange(app, body=body, now=NOW)
    assert error.value.status == 401 and state(app)["routers"] == {}


@pytest.mark.parametrize("skew", [0, 30])
def test_nonce_retained_through_signed_timestamp_expiry_inclusive(app, skew):
    enable(app)
    body = payload(timestamp=int((NOW + timedelta(seconds=skew)).timestamp()))
    exchange(app, body=body)
    expiry = NOW + timedelta(seconds=skew + 120)
    for check_at in (expiry - timedelta(microseconds=1), expiry):
        with pytest.raises(PollError) as error:
            exchange(app, body=body, now=check_at)
        assert error.value.code == "replayed_request"
    with pytest.raises(PollError) as error:
        exchange(app, body=body, now=expiry + timedelta(microseconds=1))
    assert error.value.status == 401


def test_replay_and_baseline_survive_restart_without_duplicate_history(app, config):
    enable(app)
    exchange(app)
    body = payload(timestamp=int((NOW + timedelta(seconds=10)).timestamp()), tx_octets=10_001_000)
    exchange(app, 10, body=body)
    restarted = create_device_app(config)
    with pytest.raises(PollError) as error:
        exchange(restarted, 10, body=body)
    assert error.value.code == "replayed_request"
    assert len(store(restarted).list_traffic()) == 1
    assert exchange(restarted, 20, 20_001_000)["tx_mbps"] == 8


def test_concurrent_replay_has_one_acceptance_and_one_history_append(app):
    enable(app)
    exchange(app)
    body = payload(timestamp=int((NOW + timedelta(seconds=10)).timestamp()), tx_octets=10_001_000)
    def attempt(_):
        try:
            exchange(app, 10, body=body)
            return 200
        except PollError as error:
            return error.status
    with ThreadPoolExecutor(max_workers=4) as pool:
        statuses = list(pool.map(attempt, range(4)))
    assert statuses.count(200) == 1 and statuses.count(409) == 3
    assert len(store(app).list_traffic()) == 1


def test_malformed_and_oversized_attempts_count_once_and_limit_survives_restart(app, config):
    app.config["ROUTER_RATE_LIMIT_ATTEMPTS"] = 3
    client = app.test_client()
    assert client.post(ROUTEROS_TRAFFIC_PATH, data=b"{", content_type="text/plain").status_code == 415
    assert client.post(ROUTEROS_TRAFFIC_PATH, data=b"{", content_type="application/json").status_code == 400
    assert client.post(ROUTEROS_TRAFFIC_PATH, data=b" " * 8193, content_type="application/json").status_code == 413
    config["ROUTER_RATE_LIMIT_ATTEMPTS"] = 3
    restarted = create_device_app(config)
    response = send(restarted)
    assert response.status_code == 429 and response.headers["Retry-After"] == "60"
    assert len(state(app)["rate_limits"]) == 1


def test_traffic_limits_do_not_spend_polling_or_acknowledgement_budget(app):
    app.config["ROUTER_RATE_LIMIT_ATTEMPTS"] = 2
    assert send(app).status_code == 403
    assert send(app).status_code == 403
    assert send(app).status_code == 429
    body = {key: value for key, value in payload(request_type="poll").items() if key not in {"interface", "tx_octets"}}
    poll = send(app, body, path=ROUTEROS_POLL_PATH)
    assert poll.status_code == 200
    ack = {**body, "request_type": "ack", "request_id": str(uuid4()), "response_id": poll.get_json()["response_id"]}
    assert send(app, ack, path=ROUTEROS_ACK_PATH).status_code == 200


@pytest.mark.parametrize("option", ["query", "encoding"])
def test_query_parameters_and_content_encoding_are_rejected(app, option):
    raw = encoded(payload())
    signed = headers(raw)
    if option == "encoding":
        signed["Content-Encoding"] = "gzip"
    response = app.test_client().post(ROUTEROS_TRAFFIC_PATH + ("?x=1" if option == "query" else ""),
        data=raw, content_type="application/json", headers=signed)
    assert response.status_code == 400 and state(app)["routers"] == {}


def test_transport_and_listener_separation_remain_enforced(app, config):
    enable(app)
    assert send(app, environ_overrides={"REMOTE_ADDR": "192.0.2.10"}).status_code == 403
    app.config["SIMULATION_MODE"] = False
    assert send(app).status_code == 403
    raw = encoded(payload())
    assert app.test_client().post(ROUTEROS_TRAFFIC_PATH, data=raw, content_type="application/json",
        headers={**headers(raw), "X-Forwarded-Proto": "https"}).status_code == 403
    assert send(app, base_url="https://controller.test").status_code == 200
    assert app.test_client().get(ROUTEROS_TRAFFIC_PATH).status_code == 405
    browser = create_app({**config, "AUTH_ENABLED": False})
    assert browser.test_client().post(ROUTEROS_TRAFFIC_PATH, json={}).status_code == 404


@pytest.mark.parametrize("change", [{"monitoring_enabled": False}, {"interface_name": "new-uplink"},
    {"controller_auth_enabled": False}, {"controller_auth_key_ids": []}])
def test_concurrent_authorization_change_cannot_accept_a_stale_snapshot(app, monkeypatch, change):
    enable(app)
    original = store(app).commit_traffic
    def changed(updater):
        registry(app, **change)
        return original(updater)
    monkeypatch.setattr(store(app), "commit_traffic", changed)
    with pytest.raises(PollError) as error:
        exchange(app)
    assert error.value.code == "authorization_changed"
    assert state(app)["routers"] == {} and state(app)["seen_requests"] == []


def test_no_credentials_raw_body_or_signature_in_response_history_or_logs(app, caplog):
    enable(app)
    raw = encoded(payload())
    signed = headers(raw)
    success = app.test_client().post(ROUTEROS_TRAFFIC_PATH, data=raw, headers=signed, content_type="application/json")
    failed = send(app, secret=OTHER_SECRET)
    malformed = app.test_client().post(ROUTEROS_TRAFFIC_PATH,
        data=encoded({"secret": SECRET, "rx_octets": 123}), content_type="application/json")
    public = success.get_data(as_text=True) + failed.get_data(as_text=True) + malformed.get_data(as_text=True)
    public += json.dumps(store(app).read_json("activity_logs.json")) + caplog.text
    for value in (SECRET, OTHER_SECRET, signed["X-SDR-Signature"], "synthetic-hidden-registry-value"):
        assert value not in public


def test_traffic_does_not_change_poll_ack_inventory_routing_or_automation_state(app):
    enable(app)
    names = ["routers.json", "routing_paths.json", "automation_settings.json", "router_config.json",
             "router_communication.json", "router_communication_v2.json"]
    before = {name: store(app).read_json(name) for name in names}
    exchange(app)
    exchange(app, 10, 10_001_000)
    assert {name: store(app).read_json(name) for name in names} == before
    assert app.config["SIMULATION_MODE"] is True and app.config["LIVE_ROUTING_ENABLED"] is False


def test_write_failure_before_commit_leaves_nonce_and_counter_available_for_retry(app, monkeypatch):
    enable(app)
    exchange(app)
    baseline = deepcopy(state(app)["routers"])
    original = store(app)._write_unlocked
    def fail_commit(name, value, **options):
        if name == TRAFFIC_DOCUMENT and value["pending_reading"] is not None:
            raise StorageError("Synthetic commit failure")
        return original(name, value, **options)
    body = payload(timestamp=int((NOW + timedelta(seconds=10)).timestamp()), tx_octets=10_001_000)
    with monkeypatch.context() as patch:
        patch.setattr(store(app), "_write_unlocked", fail_commit)
        with pytest.raises(StorageError):
            exchange(app, 10, body=body)
    assert state(app)["routers"] == baseline and len(state(app)["seen_requests"]) == 1
    assert store(app).list_traffic() == []
    assert exchange(app, 10, body=body)["tx_mbps"] == 8
    assert len(store(app).list_traffic()) == 1


@pytest.mark.parametrize("written", ["none", "partial", "full"])
def test_committed_append_recovers_once_after_restart_at_each_write_stage(app, config, monkeypatch, written):
    enable(app)
    exchange(app)
    def interrupted(state_value):
        pending = state_value["pending_reading"]
        if pending is None:
            return
        line = StorageService._traffic_bytes(pending["reading"])
        if written != "none":
            path = store(app).data_dir / pending["file"]
            with path.open("ab") as stream:
                stream.write(line[:len(line) // 2] if written == "partial" else line)
        raise StorageError("Synthetic interrupted append")
    body = payload(timestamp=int((NOW + timedelta(seconds=10)).timestamp()), tx_octets=10_001_000)
    with monkeypatch.context() as patch:
        patch.setattr(store(app), "_flush_pending_traffic_unlocked", interrupted)
        with pytest.raises(StorageError):
            exchange(app, 10, body=body)
    assert state(app)["pending_reading"] is not None
    restarted = create_device_app(config)
    assert state(restarted)["pending_reading"] is None
    assert len(store(restarted).list_traffic()) == 1
    with pytest.raises(PollError) as error:
        exchange(restarted, 10, body=body)
    assert error.value.code == "replayed_request"
    assert len(store(restarted).list_traffic()) == 1


def test_corrupt_state_returns_safe_503_without_resetting_history(app):
    path = app.config["DATA_DIR"] / TRAFFIC_DOCUMENT
    damaged = '{"secret":"synthetic-corrupt-data"'
    path.write_text(damaged)
    response = send(app)
    assert response.status_code == 503
    assert response.get_json() == {"error": "Controller storage is unavailable."}
    assert path.read_text() == damaged
    assert "synthetic-corrupt-data" not in response.get_data(as_text=True)


def test_invalid_state_and_rx_metadata_are_not_saved(app):
    valid = state(app)
    validate_traffic_state(valid)
    for change in ({"rx_octets": 1}, {"pending_reading": {}}, {"schema_version": True}):
        with pytest.raises(ValidationError):
            store(app).write_json(TRAFFIC_DOCUMENT, {**valid, **change})
    assert state(app) == valid


@pytest.mark.parametrize("counter", [0, 50, 2**64 - 1])
def test_counter_decrease_and_wrap_require_new_baseline_without_fabricated_zero(app, counter):
    enable(app)
    previous = 2**64 - 1 if counter != 2**64 - 1 else 1
    exchange(app, 0, previous)
    second = exchange(app, 10, counter)
    if counter < previous:
        assert second["sample_state"] == "counter_reset" and second["tx_mbps"] is None
        assert store(app).list_traffic() == []
        assert exchange(app, 20, counter + 1_250_000)["tx_mbps"] == 1
    else:
        assert second["sample_state"] == "measured"
        assert second["tx_mbps"] > 0


@pytest.mark.parametrize("seconds", [0, -1])
def test_out_of_order_or_duplicate_sample_time_cannot_rewind_baseline(app, seconds):
    enable(app)
    exchange(app)
    before = deepcopy(state(app)["routers"])
    with pytest.raises(PollError) as error:
        exchange(app, seconds, 2000)
    assert error.value.code == "out_of_order_sample"
    assert state(app)["routers"] == before and store(app).list_traffic() == []
    assert len(state(app)["seen_requests"]) == 1


def test_long_gap_rebaselines_and_next_sample_resumes_measurement(app):
    enable(app)
    exchange(app)
    gap = exchange(app, 181, 1_000_000)
    assert gap["sample_state"] == "gap_reset" and gap["tx_mbps"] is None
    assert store(app).list_traffic() == []
    assert exchange(app, 191, 2_250_000)["tx_mbps"] == 1


def test_rate_limit_window_expires_and_replay_capacity_fails_closed(app, monkeypatch):
    enable(app)
    app.config["ROUTER_RATE_LIMIT_ATTEMPTS"] = 1
    exchange(app)
    with pytest.raises(PollError) as error:
        exchange(app, 1)
    assert error.value.status == 429
    exchange(app, 60, 1001)
    monkeypatch.setattr("services.traffic_service.MAX_REPLAY_RECORDS", 2)
    with pytest.raises(PollError) as error:
        exchange(app, 120, 1002)
    assert error.value.code == "request_capacity"
    assert len(state(app)["seen_requests"]) == 2
    assert state(app)["routers"]["TEST-TX-R1"]["tx_octets"] == 1001


def test_one_routers_key_cannot_impersonate_another_or_share_its_baseline(app, monkeypatch):
    enable(app)
    monkeypatch.setenv("TEST_TX_R2_PRIMARY_SECRET", OTHER_SECRET)
    store(app).update_json("routers.json", lambda rows: [*rows, {
        "router_id": "TEST-TX-R2", "controller_auth_ref": "TEST_TX_R2",
        "controller_auth_enabled": True, "controller_auth_key_ids": ["PRIMARY"],
        "monitoring_enabled": True, "interface_name": "test-uplink",
    }])
    assert send(app, payload(router_id="TEST-TX-R2")).status_code == 401
    assert send(app, payload(router_id="TEST-TX-R2"), secret=OTHER_SECRET).status_code == 200
    assert set(state(app)["routers"]) == {"TEST-TX-R2"}
    assert send(app).get_json()["sample_state"] == "baseline"


def test_legacy_history_is_retained_and_new_samples_use_existing_segments(app):
    old = {"router_id": "LEGACY", "interface": "old-uplink", "timestamp": "2026-11-22T12:00:00Z", "tx_mbps": 12}
    store(app).append_traffic(old)
    enable(app)
    exchange(app)
    exchange(app, 10, 10_001_000)
    history = store(app).list_traffic()
    assert history[0] == old and len(history) == 2
    assert len(store(app).read_json("traffic_history.json")["segments"]) == 2


def test_pending_history_conflict_is_preserved_for_repair(app, config, monkeypatch):
    enable(app)
    exchange(app)
    def interrupt(state_value):
        if state_value["pending_reading"]:
            raise StorageError("Synthetic interrupt")
    with monkeypatch.context() as patch:
        patch.setattr(store(app), "_flush_pending_traffic_unlocked", interrupt)
        with pytest.raises(StorageError):
            exchange(app, 10, 10_001_000)
    pending = state(app)["pending_reading"]
    path = store(app).data_dir / pending["file"]
    path.write_bytes(b"unrelated bytes")
    with pytest.raises(StorageError, match="conflict"):
        create_device_app(config)
    assert path.read_bytes() == b"unrelated bytes"
    assert state(app)["pending_reading"] == pending


def test_explicit_enable_disable_and_reenable_preserve_history_and_reset_baseline(app):
    service = RouterService(store(app), app.config)
    service.set_monitoring("TEST-TX-R1", True)
    exchange(app)
    exchange(app, 10, 10_001_000)
    service.set_monitoring("TEST-TX-R1", False)
    with pytest.raises(PollError) as error:
        exchange(app, 20, 20_001_000)
    assert error.value.code == "monitoring_disabled"
    service.set_monitoring("TEST-TX-R1", True)
    assert exchange(app, 30, 30_001_000)["sample_state"] == "baseline"
    assert len(store(app).list_traffic()) == 1


def test_enable_requires_one_interface_and_provisioned_controller_authentication(app):
    service = RouterService(store(app), app.config)
    for change in ({"interface_name": ""}, {"interface_name": "test-uplink", "controller_auth_enabled": False}):
        registry(app, **change)
        with pytest.raises(RouterValidationError):
            service.set_monitoring("TEST-TX-R1", True)
        assert store(app).read_json("routers.json")[0]["monitoring_enabled"] is False
    with pytest.raises(RouterValidationError):
        service.set_monitoring("TEST-TX-R1", "true")


def test_inventory_interface_change_away_and_back_cannot_reuse_previous_baseline(app):
    service = RouterService(store(app), app.config)
    service.set_monitoring("TEST-TX-R1", True)
    exchange(app)
    for interface in ("temporary-uplink", "test-uplink"):
        service.edit_router("TEST-TX-R1", {"name": "Synthetic TX router", "interface_name": interface})
    assert exchange(app, 10, 10_001_000)["sample_state"] == "baseline"
    assert store(app).list_traffic() == []


@pytest.mark.parametrize("age,expected", [(0, "measured"), (180, "measured"), (181, "stale")])
def test_status_hides_stale_rates(app, age, expected):
    enable(app)
    exchange(app)
    exchange(app, 10, 10_001_000)
    summary = read_traffic_status(store(app), app.config, store(app).read_json("routers.json"),
                                  now=NOW + timedelta(seconds=10 + age))["TEST-TX-R1"]
    assert summary["state"] == expected
    assert summary["tx_mbps"] == (8 if expected == "measured" else None)


def test_frontend_shows_live_tx_history_and_disabled_by_default_without_network(app, config):
    browser = create_app({**config, "AUTH_ENABLED": False})
    client = browser.test_client()
    before = client.get("/monitoring").get_data(as_text=True)
    assert "Disabled" in before and "Enable monitoring" in before and "No readings recorded." in before
    enable(app)
    current = datetime.now(UTC).replace(microsecond=0)
    for ago, counter in ((10, 1000), (0, 10_001_000)):
        at = current - timedelta(seconds=ago)
        exchange(app, body=payload(timestamp=int(at.timestamp()), tx_octets=counter), now=at)
    page = client.get("/monitoring").get_data(as_text=True)
    assert "Receiving" in page and "8000.000" in page and "test-uplink" in page
    assert "Current outbound (Kbps)" in page and "Outbound (Kbps)" in page
    assert "Disable monitoring" in page and "No readings recorded." not in page
    assert "synthetic-hidden-registry-value" not in page
    status = client.get("/api/system/status").get_json()
    assert status["outbound_mbps"] == 8 and status["monitoring"] == "receiving"
    assert "8.000 Mbps outbound" in client.get("/").get_data(as_text=True)
    assert client.get("/api/routers").get_json()["routers"][0]["traffic_monitoring"]["tx_mbps"] == 8
    registry(app, monitoring_enabled=False)
    assert client.get("/api/system/status").get_json()["outbound_mbps"] is None
    assert "8000.000" in client.get("/monitoring").get_data(as_text=True)  # preserved history


@pytest.mark.parametrize("delta,displayed", [(1, "0.000133"), (1655, "0.221"), (7500, "1.000"), (0, "0.000")])
def test_small_tx_rates_are_visible_in_current_reading_and_history(app, config, delta, displayed):
    enable(app)
    current = datetime.now(UTC).replace(microsecond=0)
    for ago, counter in ((60, 1000), (0, 1000 + delta)):
        at = current - timedelta(seconds=ago)
        exchange(app, body=payload(timestamp=int(at.timestamp()), tx_octets=counter), now=at)
    client = create_app({**config, "AUTH_ENABLED": False}).test_client()
    page = client.get("/monitoring").get_data(as_text=True)
    assert "Receiving" in page
    assert page.count(f"<td>{displayed}</td>") == 2
    assert f"{displayed} Kbps outbound" in client.get("/").get_data(as_text=True)
    assert client.get("/api/system/status").get_json()["outbound_mbps"] == pytest.approx(delta * 8 / 60 / 1_000_000)


def test_monitoring_refresh_does_not_collect_or_change_samples(app, config):
    enable(app)
    exchange(app)
    before = {name: store(app).read_json(name) for name in (
        "routers.json", "router_traffic_v2.json", "router_communication.json", "router_communication_v2.json",
    )}
    client = create_app({**config, "AUTH_ENABLED": False}).test_client()
    for _ in range(2):
        page = client.get("/monitoring").get_data(as_text=True)
        assert '<meta http-equiv="refresh" content="15">' in page
        assert "Updates automatically every 15 seconds" in page
    assert '<meta http-equiv="refresh"' not in client.get("/routers").get_data(as_text=True)
    assert {name: store(app).read_json(name) for name in before} == before


def test_monitoring_action_requires_csrf_and_explicit_boolean_and_survives_restart(app, config):
    browser = create_app({**config, "AUTH_ENABLED": False})
    client = browser.test_client()
    url = "/routers/TEST-TX-R1/monitoring"
    assert client.post(url, data={"monitoring_enabled": "true"}).status_code == 400
    assert store(app).read_json("routers.json")[0]["monitoring_enabled"] is False
    client.get("/monitoring")
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    for value in ("", "1", "on"):
        assert client.post(url, data={"csrf_token": csrf, "monitoring_enabled": value}).status_code == 302
        assert store(app).read_json("routers.json")[0]["monitoring_enabled"] is False
    assert client.post(url, data={"csrf_token": csrf, "monitoring_enabled": "true"}).status_code == 302
    assert store(app).read_json("routers.json")[0]["monitoring_enabled"] is True
    restarted = create_device_app(config)
    assert store(restarted).read_json("routers.json")[0]["monitoring_enabled"] is True


def test_monitoring_action_requires_administrator_when_auth_enabled(app, config):
    from werkzeug.security import generate_password_hash
    browser = create_app({**config, "AUTH_ENABLED": True,
        "SECRET_KEY": "synthetic-session-key-for-monitoring-tests",
        "ADMIN_USERNAME": "synthetic-admin", "ADMIN_PASSWORD_HASH": generate_password_hash("synthetic-password")})
    response = browser.test_client().post("/routers/TEST-TX-R1/monitoring", data={"monitoring_enabled": "true"})
    assert response.status_code == 302 and "/login" in response.headers["Location"]
    assert store(app).read_json("routers.json")[0]["monitoring_enabled"] is False


def test_no_network_total_when_any_enabled_router_lacks_a_current_rate(app, config):
    enable(app)
    current = datetime.now(UTC).replace(microsecond=0)
    for ago, counter in ((10, 1000), (0, 10_001_000)):
        at = current - timedelta(seconds=ago)
        exchange(app, body=payload(timestamp=int(at.timestamp()), tx_octets=counter), now=at)
    store(app).update_json("routers.json", lambda rows: [*rows, {"router_id": "AWAITING-R2", "monitoring_enabled": True}])
    browser = create_app({**config, "AUTH_ENABLED": False})
    status = browser.test_client().get("/api/system/status").get_json()
    assert status["outbound_mbps"] is None
    assert status["traffic_monitoring"] == {"enabled": 2, "measured": 1}


def test_live_replay_capacity_fails_closed_instead_of_evicting_protection(app, monkeypatch):
    enable(app)
    monkeypatch.setattr("services.traffic_service.MAX_REPLAY_RECORDS", 1)
    first = payload(timestamp=int(NOW.timestamp()))
    exchange(app, body=first)
    with pytest.raises(PollError) as error:
        exchange(app, 10, 10_001_000)
    assert error.value.status == 503 and error.value.code == "request_capacity"
    assert state(app)["seen_requests"][0]["request_id"] == first["request_id"]
    assert state(app)["routers"]["TEST-TX-R1"]["tx_octets"] == 1000
    assert store(app).list_traffic() == []
    assert exchange(app, 181, 10_001_000)["sample_state"] == "gap_reset"
    assert len(state(app)["seen_requests"]) == 1


def test_two_routers_use_independent_tx_baselines_and_cannot_impersonate(app, monkeypatch):
    enable(app)
    monkeypatch.setenv("TEST_TX_R2_PRIMARY_SECRET", OTHER_SECRET)
    store(app).update_json("routers.json", lambda rows: [*rows, {
        "router_id": "TEST-TX-R2", "controller_auth_ref": "TEST_TX_R2",
        "controller_auth_enabled": True, "controller_auth_key_ids": ["PRIMARY"],
        "monitoring_enabled": True, "interface_name": "test-uplink",
    }])
    assert send(app, payload(router_id="TEST-TX-R2"), secret=SECRET).status_code == 401
    assert send(app, payload(router_id="TEST-TX-R2", tx_octets=9_000_000), secret=OTHER_SECRET).status_code == 200
    exchange(app)
    assert exchange(app, 10, 10_001_000)["tx_mbps"] == 8
    assert state(app)["routers"]["TEST-TX-R2"]["tx_octets"] == 9_000_000


def _process_sample(config, body):
    """A separate process uses the on-disk locks and inherited synthetic key."""
    from unittest.mock import patch
    storage = StorageService(config["DATA_DIR"], config["OUTPUT_DIR"])
    raw = encoded(body)
    with patch("socket.create_connection", side_effect=AssertionError("Unexpected network")):
        try:
            TrafficService(storage, config).handle(raw, "PRIMARY", headers(raw)["X-SDR-Signature"],
                "127.0.0.1", now=datetime.fromtimestamp(body["timestamp"], UTC))
            return 200
        except PollError as error:
            return error.status


def test_replay_and_history_are_serialized_across_processes(app, config):
    enable(app)
    exchange(app)
    body = payload(timestamp=int((NOW + timedelta(seconds=10)).timestamp()), tx_octets=10_001_000)
    with ProcessPoolExecutor(max_workers=2, mp_context=multiprocessing.get_context("spawn")) as pool:
        futures = [pool.submit(_process_sample, config, body) for _ in range(2)]
        statuses = [future.result(timeout=30) for future in futures]
    assert sorted(statuses) == [200, 409]
    assert len(store(app).list_traffic()) == 1

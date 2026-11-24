"""ZTP trust, single-use grants, dynamic credentials and interrupted enrollment."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from uuid import uuid4

from dotenv import dotenv_values
import pytest

from app import create_app
from device_app import create_device_app
from services.enrollment_service import ENROLLMENT_PATH, EnrollmentService, create_enrollment_grant
from services.json_storage import StorageError
from services.routeros_protocol import ROUTEROS_TRAFFIC_PATH, sign_routeros_request


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Enrollment test contacted a device"))


@pytest.fixture(scope="module")
def public_ca(tmp_path_factory):
    root = tmp_path_factory.mktemp("ztp-test-ca")
    command = ["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
               "-subj", "/CN=Isolated Enrollment Test CA", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.pem")]
    assert subprocess.run(command, capture_output=True).returncode == 0
    return root / "ca.pem"


@pytest.fixture
def setup(tmp_path, public_ca):
    env = tmp_path / ".env"
    env.write_text("SIMULATION_MODE=true\nLIVE_ROUTING_ENABLED=false\n"); env.chmod(0o600)
    config = {"TESTING": True, "AUTH_ENABLED": False, "SIMULATION_MODE": True, "LIVE_ROUTING_ENABLED": False,
              "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output", "ENROLLMENT_ENABLED": True,
              "CONTROLLER_BASE_URL": "https://controller.example.test:18443",
              "CONTROLLER_CREDENTIALS_ENV_FILE": env, "API_CREDENTIALS_ENV_FILE": env,
              "ROUTER_RATE_LIMIT_ATTEMPTS": 100}
    app = create_device_app(config)
    return app, app.extensions["json_storage"], config, env, public_ca, tmp_path


def grant(setup, **changes):
    app, storage, config, _, ca, root = setup
    result = create_enrollment_grant(storage, config, root / ("bootstrap-" + uuid4().hex), ca,
                                     interface="wan-custom", enable_monitoring=True, **changes)
    source = Path(result["bootstrap_script"]).read_text()
    token = re.search(r':local sdrToken "([^"]+)";', source)[1]
    return result, token


def body(**changes):
    return {"protocol_version": "1.0", "request_type": "enroll", "request_id": str(uuid4()),
            "timestamp": int(datetime.now(UTC).timestamp()), "router_name": "New live test router",
            "device_id": "02:00:00:AB:CD:EF", "interface": "wan-custom", **changes}


def enroll(setup, token, payload=None, **options):
    return setup[0].test_client().post(ENROLLMENT_PATH, data=json.dumps(payload or body()),
        content_type="application/json", headers={"Authorization": "Bearer " + token},
        base_url="https://controller.example.test", **options)


def test_bootstrap_is_private_and_ledger_contains_only_token_hash(setup, caplog):
    result, token = grant(setup)
    _, storage, _, _, _, _ = setup
    state = storage.read_json("router_enrollment.json")
    assert token not in json.dumps(state) + caplog.text + json.dumps(result)
    assert state["grants"][result["enrollment_id"]]["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    directory = Path(result["output_dir"])
    assert directory.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in directory.iterdir())
    source = Path(result["bootstrap_script"]).read_text()
    assert "check-certificate=yes" in source and "http-max-redirect-count=0" in source
    assert "policy=read,test" in source and "use-script-permissions" in source
    assert "rx-byte" not in source and "/ip/route" not in source and "/routing/" not in source


def test_new_router_enrolls_and_immediately_sends_tx_without_restart(setup):
    _, token = grant(setup)
    app, storage, config, env, _, _ = setup
    response = enroll(setup, token)
    assert response.status_code == 200
    reply = response.get_json()
    row = storage.read_json("routers.json")[0]
    assert row["router_id"].startswith("RTR-") and row["interface_name"] == "wan-custom"
    assert row["capacity_mbps"] is None and row["monitoring_enabled"] is True
    assert row["controller_credentials_source"] == "private_env"
    variable = f'{row["controller_auth_ref"]}_{row["controller_auth_key_ids"][0]}_SECRET'
    assert variable not in os.environ
    secret = dotenv_values(env, interpolate=False)[variable]
    now = int(datetime.now(UTC).timestamp())
    for ago, counter, expected in ((10, 1000, "baseline"), (0, 10_001_000, "measured")):
        raw = json.dumps({"protocol_version": "2.0", "request_type": "traffic", "router_id": row["router_id"],
            "request_id": str(uuid4()), "timestamp": now - ago, "interface": "wan-custom", "tx_octets": counter}).encode()
        key = row["controller_auth_key_ids"][0]
        r = app.test_client().post(ROUTEROS_TRAFFIC_PATH, data=raw, content_type="application/json",
            headers={"X-SDR-Key-Id": key, "X-SDR-Signature": sign_routeros_request(secret, raw, key, ROUTEROS_TRAFFIC_PATH)},
            base_url="https://controller.example.test")
        assert r.status_code == 200 and r.get_json()["sample_state"] == expected
    assert storage.list_traffic()[0]["tx_mbps"] == 8
    browser = create_app(config).test_client()
    page = browser.get("/routers").get_data(as_text=True)
    assert row["router_id"] in page and secret not in page and token not in page
    assert reply["mode"] == "dry_run" and reply["routing_changes_enabled"] is False


def test_token_is_single_use_even_after_restart(setup):
    _, token = grant(setup)
    assert enroll(setup, token).status_code == 200
    app, storage, config, *_ = setup
    before = storage.read_json("routers.json")
    assert enroll(setup, token).status_code == 409
    restarted = create_device_app(config)
    r = restarted.test_client().post(ENROLLMENT_PATH, json=body(), headers={"Authorization": "Bearer " + token}, base_url="https://controller.example.test")
    assert r.status_code == 409 and storage.read_json("routers.json") == before


def test_enrollment_requires_https_even_when_simulation_loopback_is_allowed(setup):
    _, token = grant(setup)
    response = setup[0].test_client().post(ENROLLMENT_PATH, json=body(), headers={"Authorization": "Bearer " + token})
    assert response.status_code == 403 and setup[1].read_json("routers.json") == []


@pytest.mark.parametrize("changes,status", [
    ({"timestamp": True}, 400), ({"timestamp": 1.5}, 400), ({"interface": "other-wan"}, 403),
    ({"rx_octets": 1}, 400), ({"router_id": "IMPERSONATE"}, 400), ({"request_id": "bad"}, 400),
    ({"router_name": "bad\nname"}, 400), ({"device_id": "bad\nid"}, 400),
    ({"timestamp": 1}, 401), ({"timestamp": 9_000_000_000}, 401),
])
def test_invalid_or_out_of_scope_requests_do_not_consume_token(setup, changes, status):
    result, token = grant(setup)
    assert enroll(setup, token, body(**changes)).status_code == status
    assert setup[1].read_json("router_enrollment.json")["grants"][result["enrollment_id"]]["used_at"] is None
    assert setup[1].read_json("routers.json") == []


def test_expired_and_unknown_tokens_fail_without_credentials_or_registration(setup):
    result, token = grant(setup, ttl_seconds=60, now=datetime.now(UTC) - timedelta(seconds=61))
    assert enroll(setup, token).status_code == 401
    assert enroll(setup, "0" * 32 + "." + "a" * 43).status_code == 401
    assert setup[1].read_json("routers.json") == []


def test_concurrent_token_claims_register_exactly_one_router(setup):
    _, token = grant(setup)
    with ThreadPoolExecutor(max_workers=4) as pool:
        statuses = list(pool.map(lambda _: enroll(setup, token).status_code, range(4)))
    assert sorted(statuses) == [200, 409, 409, 409]
    assert len(setup[1].read_json("routers.json")) == 1


def test_enrollment_rate_limit_is_separate_and_persistent(setup):
    _, token = grant(setup)
    app, storage, config, *_ = setup
    app.config["ROUTER_RATE_LIMIT_ATTEMPTS"] = 1
    assert enroll(setup, "0" * 32 + "." + "a" * 43).status_code == 401
    assert enroll(setup, token).status_code == 429
    assert storage.read_json("router_communication.json")["rate_limits"] == {}
    assert storage.read_json("router_traffic_v2.json")["rate_limits"] == {}


def test_failed_private_secret_write_leaves_grant_unused(setup, monkeypatch):
    result, token = grant(setup)
    def fail(*a, **k):
        raise OSError("Synthetic private file failure")
    monkeypatch.setattr("services.enrollment_service.update_private_environment", fail)
    assert enroll(setup, token).status_code == 503
    assert setup[1].read_json("routers.json") == []
    assert setup[1].read_json("router_enrollment.json")["grants"][result["enrollment_id"]]["used_at"] is None


def test_committed_enrollment_recovers_registry_after_interrupted_write(setup, monkeypatch):
    result, token = grant(setup)
    app, storage, config, *_ = setup
    original = storage._write_unlocked
    failed = False
    def interrupt(name, value, **kwargs):
        nonlocal failed
        if name == "routers.json" and not failed:
            failed = True
            raise StorageError("Synthetic registry interruption")
        return original(name, value, **kwargs)
    monkeypatch.setattr(storage, "_write_unlocked", interrupt)
    assert enroll(setup, token).status_code == 503
    pending = json.loads((storage.data_dir / "router_enrollment.json").read_text())
    assert pending["pending"] is not None and pending["grants"][result["enrollment_id"]]["used_at"] is not None
    recovered = create_device_app(config).extensions["json_storage"]
    assert len(recovered.read_json("routers.json")) == 1
    assert recovered.read_json("router_enrollment.json")["pending"] is None
    assert enroll(setup, token).status_code == 409


def test_existing_active_router_needs_explicit_reenrollment_authorization(setup):
    _, token = grant(setup, router_id="EXISTING-R1")
    assert enroll(setup, token).status_code == 200
    old = deepcopy(setup[1].read_json("routers.json"))
    _, second = grant(setup, router_id="EXISTING-R1")
    assert enroll(setup, second).status_code == 409
    assert setup[1].read_json("routers.json") == old


def test_default_grant_registers_but_keeps_monitoring_disabled(setup):
    app, storage, config, _, ca, root = setup
    result = create_enrollment_grant(storage, config, root / "disabled", ca, interface="wan-custom")
    token = re.search(r':local sdrToken "([^"]+)";', Path(result["bootstrap_script"]).read_text())[1]
    reply = enroll(setup, token)
    assert reply.status_code == 200 and reply.get_json()["monitoring_enabled"] is False
    assert storage.read_json("routers.json")[0]["monitoring_enabled"] is False
    assert storage.read_json("routers.json")[0]["capacity_confirmed"] is False


def test_concurrent_uses_have_exactly_one_success_and_one_router(setup):
    _, token = grant(setup)
    with ThreadPoolExecutor(max_workers=4) as workers:
        statuses = list(workers.map(lambda _: enroll(setup, token).status_code, range(4)))
    assert sorted(statuses) == [200, 409, 409, 409]
    assert len(setup[1].read_json("routers.json")) == 1


def test_expired_token_and_wrong_source_are_rejected_without_registration(setup):
    result, token = grant(setup, management_ip="192.0.2.11", bind_source=True)
    assert enroll(setup, token).status_code == 403
    assert setup[1].read_json("routers.json") == []
    at = datetime.now(UTC) + timedelta(seconds=1000)
    raw = json.dumps(body(timestamp=int(at.timestamp()))).encode()
    from services.router_poll_service import PollError
    with pytest.raises(PollError) as caught:
        EnrollmentService(setup[1], setup[2]).enroll(raw, "Bearer " + token, "192.0.2.11", now=at)
    assert caught.value.status == 401


def test_duplicate_fields_encoding_and_content_type_are_rejected(setup):
    result, token = grant(setup)
    client = setup[0].test_client()
    options = {"base_url":"https://controller.example.test", "headers":{"Authorization":"Bearer " + token}}
    assert client.post(ENROLLMENT_PATH, data="{}", content_type="text/plain", **options).status_code == 415
    assert client.post(ENROLLMENT_PATH + "?x=1", json=body(), **options).status_code == 400
    raw = json.dumps(body())[:-1] + ',"interface":"wan-custom"}'
    assert client.post(ENROLLMENT_PATH, data=raw, content_type="application/json", **options).status_code == 400
    assert setup[1].read_json("routers.json") == []


def test_enrollment_rate_limit_is_independent_from_poll_and_traffic(setup):
    _, token = grant(setup)
    app, storage, *_ = setup
    app.config["ROUTER_RATE_LIMIT_ATTEMPTS"] = 1
    assert enroll(setup, "invalid").status_code == 401
    assert enroll(setup, token).status_code == 429
    assert storage.read_json("router_communication.json")["rate_limits"] == {}
    assert storage.read_json("router_traffic_v2.json")["rate_limits"] == {}


def test_enrollment_endpoint_never_appears_on_browser_app(setup):
    assert create_app(setup[2]).test_client().post(ENROLLMENT_PATH).status_code == 404
    page = create_app(setup[2]).test_client().get("/routers/connect").get_data(as_text=True)
    assert "Zero-touch provisioning" in page
    assert "https://controller.example.test:18443" + ENROLLMENT_PATH in page
    assert "single-use" in page and "trusted bootstrap" in page


def test_per_router_interval_controls_counter_gaps_without_hardcoded_ether1(setup):
    _, token = grant(setup, interval_seconds=300)
    response = enroll(setup, token)
    assert response.status_code == 200 and response.get_json()["interval_seconds"] == 300
    app, storage, config, env, *_ = setup
    row = storage.read_json("routers.json")[0]
    key = row["controller_auth_key_ids"][0]
    secret = dotenv_values(env, interpolate=False)[f'{row["controller_auth_ref"]}_{key}_SECRET']
    from services.traffic_service import TrafficService, read_traffic_status
    start = datetime.now(UTC)
    for offset, counter in ((0, 1000), (300, 300_001_000)):
        at = start + timedelta(seconds=offset)
        raw = json.dumps({"protocol_version":"2.0", "router_id":row["router_id"], "request_type":"traffic",
                          "request_id":str(uuid4()), "timestamp":int(at.timestamp()),
                          "interface":"wan-custom", "tx_octets":counter}).encode()
        result = TrafficService(storage, config).handle(raw, key, sign_routeros_request(secret, raw, key, ROUTEROS_TRAFFIC_PATH), "192.0.2.99", now=at)
    assert result["sample_state"] == "measured" and result["tx_mbps"] == 8
    status = read_traffic_status(storage, config, [row], now=start + timedelta(seconds=800))[row["router_id"]]
    assert status["state"] == "measured" and status["stale_after_seconds"] == 900

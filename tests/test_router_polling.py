"""Exercise router-initiated communication without contacting any device."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import hmac
import json
from uuid import UUID, uuid4

import pytest

from device_app import create_device_app


ENDPOINT = "/api/controller/v1/poll"
ROUTER_ID = "TEST-R1"
SECRET = "test-only-router-poll-secret-0123456789abcdef"
OTHER_SECRET = "other-test-router-poll-secret-0123456789abcdef"


@pytest.fixture(autouse=True)
def no_router_network_connections(monkeypatch):
    def unexpected_connection(*args, **kwargs):
        pytest.fail("A local polling test attempted an outbound network connection")

    monkeypatch.setattr("socket.create_connection", unexpected_connection)


@pytest.fixture
def app_config(tmp_path):
    return {
        "TESTING": True,
        "SIMULATION_MODE": True,
        "LIVE_ROUTING_ENABLED": False,
        "DATA_DIR": tmp_path / "data",
        "OUTPUT_DIR": tmp_path / "output",
        "ROUTER_RATE_LIMIT_ATTEMPTS": 100,
        "ROUTER_RATE_LIMIT_WINDOW_SECONDS": 60,
    }


@pytest.fixture
def app(app_config, monkeypatch):
    monkeypatch.setenv("TEST_POLL_R1_PRIMARY_SECRET", SECRET)
    application = create_device_app(app_config)
    application.extensions["json_storage"].write_json("routers.json", [{
        "router_id": ROUTER_ID,
        "name": "Test router",
        "controller_auth_ref": "TEST_POLL_R1",
        "controller_auth_enabled": True,
        "controller_auth_key_ids": ["PRIMARY"],
        "connection_status": "disconnected",
    }])
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def timestamp(value=None):
    return (value or datetime.now(UTC)).isoformat().replace("+00:00", "Z")


def request_body(**overrides):
    return {
        "protocol_version": "1.0",
        "router_id": ROUTER_ID,
        "request_id": str(uuid4()),
        "timestamp": timestamp(),
        "request_type": "poll",
        **overrides,
    }


def encoded(payload):
    return json.dumps(payload, separators=(",", ":")).encode()


def signed_headers(raw, *, secret=SECRET, key_id="PRIMARY", path=ENDPOINT):
    canonical = (
        "SDR-POLL-V1\nPOST\n" + path + "\n" + key_id + "\n"
        + sha256(raw).hexdigest()
    ).encode()
    return {
        "X-SDR-Key-Id": key_id,
        "X-SDR-Signature": hmac.new(secret.encode(), canonical, sha256).hexdigest(),
    }


def poll(client, payload=None, *, secret=SECRET, **kwargs):
    raw = encoded(payload or request_body())
    return client.post(
        ENDPOINT, data=raw, content_type="application/json",
        headers=signed_headers(raw, secret=secret), **kwargs,
    )


def communication_state(app):
    return app.extensions["json_storage"].read_json("router_communication.json")


def test_authenticated_poll_returns_only_versioned_no_action_json(app, client):
    payload = request_body()
    response = poll(client, payload)

    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert response.headers["Cache-Control"] == "no-store"
    body = response.get_json()
    assert set(body) == {
        "protocol_version", "router_id", "request_id", "response_id", "status",
        "mode", "action", "configuration", "reason", "issued_at", "expires_at",
        "poll_after_seconds",
    }
    assert body["protocol_version"] == "1.0"
    assert body["router_id"] == ROUTER_ID
    assert body["request_id"] == payload["request_id"]
    assert UUID(body["response_id"]).version == 4
    assert body["status"] == "authenticated"
    assert body["mode"] == "dry_run"
    assert body["action"] == "none"
    assert body["configuration"] == {}
    assert body["reason"] == "optimization_unavailable"
    assert type(body["poll_after_seconds"]) is int
    issued = datetime.fromisoformat(body["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
    assert 0 < (expires - issued).total_seconds() <= 300

    record = communication_state(app)["routers"][ROUTER_ID]
    assert record["last_authenticated_at"]
    assert record["last_response_id"] == body["response_id"]
    assert record["last_response_issued_at"] == body["issued_at"]
    assert record["mode"] == "dry_run"
    assert not record.get("last_applied_instruction")
    assert not record.get("last_received_response_id")
    # A successful poll is independent from the optional native API diagnostic.
    assert app.extensions["json_storage"].read_json("routers.json")[0]["connection_status"] == "disconnected"


@pytest.mark.parametrize("headers", [{}, {"X-SDR-Key-Id": "PRIMARY"}])
def test_missing_authentication_is_rejected(app, client, headers):
    response = client.post(
        ENDPOINT, data=encoded(request_body()), content_type="application/json",
        headers=headers,
    )
    assert response.status_code == 401
    assert response.is_json
    assert ROUTER_ID not in communication_state(app)["routers"]


def test_wrong_secret_and_unknown_router_have_generic_authentication_errors(client):
    wrong = poll(client, secret=OTHER_SECRET)
    unknown = poll(client, request_body(router_id="UNKNOWN-ROUTER"))

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.get_json() == unknown.get_json()
    assert "UNKNOWN-ROUTER" not in unknown.get_data(as_text=True)


def test_disabled_router_is_rejected_immediately(app, client):
    storage = app.extensions["json_storage"]

    def disable(routers):
        routers[0]["controller_auth_enabled"] = False
        return routers

    storage.update_json("routers.json", disable)
    assert poll(client).status_code == 401
    assert ROUTER_ID not in communication_state(app)["routers"]


@pytest.mark.parametrize("delta", [timedelta(hours=-1), timedelta(hours=1)])
def test_expired_or_future_dated_request_is_rejected(app, client, delta):
    response = poll(client, request_body(timestamp=timestamp(datetime.now(UTC) + delta)))

    assert response.status_code == 401
    assert ROUTER_ID not in communication_state(app)["routers"]


def test_replay_is_rejected_and_does_not_advance_check_in(app, client):
    payload = request_body()
    assert poll(client, payload).status_code == 200
    before = deepcopy(communication_state(app)["routers"][ROUTER_ID])

    response = poll(client, payload)

    assert response.status_code == 409
    assert response.is_json
    assert communication_state(app)["routers"][ROUTER_ID] == before


def test_replay_protection_survives_application_restart(app, app_config):
    payload = request_body()
    assert poll(app.test_client(), payload).status_code == 200

    restarted = create_device_app(app_config)

    assert poll(restarted.test_client(), payload).status_code == 409


@pytest.mark.parametrize("future_skew", [0, 30])
def test_replay_nonce_survives_until_signed_timestamp_expiry_inclusive(app, future_skew):
    """Future-dated requests need longer retention than time-since-receipt."""
    from services.router_poll_service import PollError, RouterPollService

    app.config.update(ROUTER_REQUEST_MAX_AGE_SECONDS=120, ROUTER_CLOCK_SKEW_SECONDS=30)
    now = datetime(2030, 1, 1, tzinfo=UTC)
    signed_at = now + timedelta(seconds=future_skew)
    expires_at = signed_at + timedelta(seconds=120)
    payload = request_body(timestamp=timestamp(signed_at))
    raw = encoded(payload)
    signature = signed_headers(raw)["X-SDR-Signature"]
    service = RouterPollService(app.extensions["json_storage"], app.config)
    service.poll(payload, raw, "PRIMARY", signature, "127.0.0.1", now=now)
    original = deepcopy(communication_state(app)["routers"][ROUTER_ID])
    nonce = next(row for row in communication_state(app)["seen_requests"]
                 if row["request_id"] == payload["request_id"])
    assert datetime.fromisoformat(nonce["expires_at"].replace("Z", "+00:00")) == expires_at

    for check_at in (expires_at - timedelta(microseconds=1), expires_at):
        with pytest.raises(PollError) as rejected:
            service.poll(payload, raw, "PRIMARY", signature, "127.0.0.1", now=check_at)
        assert rejected.value.status == 409
        assert rejected.value.code == "replayed_request"

    with pytest.raises(PollError) as expired:
        service.poll(payload, raw, "PRIMARY", signature, "127.0.0.1",
                     now=expires_at + timedelta(microseconds=1))
    assert expired.value.status == 401
    assert communication_state(app)["routers"][ROUTER_ID] == original


def test_rate_limit_bounds_failed_authentication_attempts(app, client):
    app.config["ROUTER_RATE_LIMIT_ATTEMPTS"] = 3
    for _ in range(3):
        assert poll(client, secret=OTHER_SECRET).status_code == 401

    response = poll(client, secret=OTHER_SECRET)

    assert response.status_code == 429
    assert response.is_json
    assert ROUTER_ID not in communication_state(app)["routers"]


def test_failed_authentication_rate_limit_survives_restart(app, app_config):
    app.config["ROUTER_RATE_LIMIT_ATTEMPTS"] = 3
    app_config["ROUTER_RATE_LIMIT_ATTEMPTS"] = 3
    for _ in range(3):
        assert poll(app.test_client(), secret=OTHER_SECRET).status_code == 401

    restarted = create_device_app(app_config)

    assert poll(restarted.test_client(), secret=OTHER_SECRET).status_code == 429


@pytest.mark.parametrize(("content_type", "expected_status"), [
    ("application/json", 400), ("text/plain", 415),
])
def test_malformed_requests_consume_quota_without_logging_raw_input(app, client, content_type, expected_status):
    app.config["ROUTER_RATE_LIMIT_ATTEMPTS"] = 3
    malformed = ('{"secret":"' + SECRET + '",broken-json').encode()
    for _ in range(3):
        response = client.post(ENDPOINT, data=malformed, content_type=content_type)
        assert response.status_code == expected_status
    for _ in range(3):
        response = client.post(ENDPOINT, data=malformed, content_type=content_type)
        assert response.status_code == 429

    events = app.extensions["json_storage"].read_json("activity_logs.json")
    assert sum(event["message"] == "Invalid router polling request rejected." for event in events) == 3
    assert sum(event["message"] == "Router polling rate limit reached." for event in events) == 1
    assert SECRET not in json.dumps(events)
    assert ROUTER_ID not in communication_state(app)["routers"]


def test_replayed_request_audit_volume_is_bounded_by_attempt_quota(app, client):
    app.config["ROUTER_RATE_LIMIT_ATTEMPTS"] = 3
    payload = request_body()
    assert poll(client, payload).status_code == 200
    authenticated_before = deepcopy(communication_state(app)["routers"][ROUTER_ID])
    for _ in range(2):
        assert poll(client, payload).status_code == 409
    for _ in range(3):
        assert poll(client, payload).status_code == 429

    events = app.extensions["json_storage"].read_json("activity_logs.json")
    assert sum(event["message"] == "Replayed router polling request rejected." for event in events) == 2
    assert sum(event["message"] == "Router polling rate limit reached." for event in events) == 1
    assert communication_state(app)["routers"][ROUTER_ID] == authenticated_before
    assert SECRET not in json.dumps(events)
    assert payload["request_id"] not in json.dumps(events)


@pytest.mark.parametrize("raw", [
    b"{invalid-json}",
    b"[]",
    b'{"protocol_version":"1.0","protocol_version":"1.0"}',
    b'{"protocol_version":NaN}',
])
def test_invalid_json_is_rejected(client, raw):
    response = client.post(
        ENDPOINT, data=raw, content_type="application/json", headers=signed_headers(raw),
    )
    assert response.status_code == 400
    assert response.is_json


@pytest.mark.parametrize("change", [
    {"protocol_version": "2.0"},
    {"request_id": "not-a-request-id"},
    {"timestamp": "2026-11-19T09:00:00"},
    {"request_type": "set_ospf_cost"},
    {"router_id": "../other-router"},
    {"configuration": {"cost": 22}},
])
def test_invalid_poll_contract_is_rejected(client, change):
    response = poll(client, request_body(**change))
    assert response.status_code == 400
    assert response.is_json


def test_content_type_and_size_limits_are_enforced(client):
    raw = encoded(request_body())
    wrong_type = client.post(
        ENDPOINT, data=raw, content_type="text/plain", headers=signed_headers(raw),
    )
    assert wrong_type.status_code == 415
    assert wrong_type.is_json
    oversized = client.post(
        ENDPOINT, data=b" " * 8193, content_type="application/json",
    )
    assert oversized.status_code == 413
    assert oversized.is_json


def test_signature_binds_body_and_endpoint_path(client):
    payload = request_body()
    original = encoded(payload)
    changed = encoded({**payload, "request_id": str(uuid4())})
    tampered = client.post(
        ENDPOINT, data=changed, content_type="application/json",
        headers=signed_headers(original),
    )
    assert tampered.status_code == 401
    wrong_path = client.post(
        ENDPOINT, data=original, content_type="application/json",
        headers=signed_headers(original, path="/another-endpoint"),
    )
    assert wrong_path.status_code == 401


def test_one_router_key_cannot_impersonate_a_different_registered_router(app, client, monkeypatch):
    storage = app.extensions["json_storage"]
    monkeypatch.setenv("TEST_POLL_R2_PRIMARY_SECRET", OTHER_SECRET)
    second = {
        "router_id": "TEST-R2", "name": "Second test router",
        "controller_auth_ref": "TEST_POLL_R2", "controller_auth_enabled": True,
        "controller_auth_key_ids": ["PRIMARY"],
    }
    storage.update_json("routers.json", lambda routers: [*routers, second])

    assert poll(client, request_body(router_id="TEST-R2"), secret=SECRET).status_code == 401
    assert poll(client, request_body(router_id="TEST-R2"), secret=OTHER_SECRET).status_code == 200
    assert ROUTER_ID not in communication_state(app)["routers"]


def test_key_rotation_and_revocation_take_effect_without_rewriting_credentials(app, client, monkeypatch):
    storage = app.extensions["json_storage"]
    monkeypatch.setenv("TEST_POLL_R1_NEXT_SECRET", OTHER_SECRET)

    def rotate(routers):
        routers[0]["controller_auth_key_ids"] = ["PRIMARY", "NEXT"]
        return routers

    storage.update_json("routers.json", rotate)
    raw = encoded(request_body())
    accepted = client.post(
        ENDPOINT, data=raw, content_type="application/json",
        headers=signed_headers(raw, secret=OTHER_SECRET, key_id="NEXT"),
    )
    assert accepted.status_code == 200

    def retire_primary(routers):
        routers[0]["controller_auth_key_ids"] = ["NEXT"]
        return routers

    storage.update_json("routers.json", retire_primary)
    assert poll(client).status_code == 401
    raw = encoded(request_body())
    assert client.post(
        ENDPOINT, data=raw, content_type="application/json",
        headers=signed_headers(raw, secret=OTHER_SECRET, key_id="NEXT"),
    ).status_code == 200


def test_failed_authentication_does_not_replace_a_previous_success(app, client):
    assert poll(client).status_code == 200
    before = deepcopy(communication_state(app)["routers"][ROUTER_ID])

    assert poll(client, secret=OTHER_SECRET).status_code == 401

    assert communication_state(app)["routers"][ROUTER_ID] == before


def test_testing_mode_does_not_bypass_authentication_or_https_policy(app, client):
    app.config["SIMULATION_MODE"] = False

    assert poll(client).status_code == 403
    secure = poll(client, base_url="https://controller.test")
    assert secure.status_code == 200
    raw = encoded(request_body())
    assert client.post(
        ENDPOINT, data=raw, content_type="application/json",
        base_url="https://controller.test",
    ).status_code == 401


def test_simulation_plain_http_is_limited_to_loopback_clients(client):
    response = poll(client, environ_overrides={"REMOTE_ADDR": "192.0.2.99"})
    assert response.status_code == 403
    assert response.is_json


def test_untrusted_forwarded_headers_cannot_bypass_transport_guard(app, client):
    for simulation in (True, False):
        app.config["SIMULATION_MODE"] = simulation
        raw = encoded(request_body())
        headers = {
            **signed_headers(raw),
            "X-Forwarded-Proto": "https",
            "X-Forwarded-For": "127.0.0.1",
            "Forwarded": "for=127.0.0.1;proto=https",
        }
        response = client.post(
            ENDPOINT, data=raw, headers=headers, content_type="application/json",
            environ_overrides={"REMOTE_ADDR": "192.0.2.99"},
        )
        assert response.status_code == 403
        assert response.is_json
    assert ROUTER_ID not in communication_state(app)["routers"]


def test_live_routing_cannot_be_enabled_even_for_a_test_application(app_config):
    app_config["LIVE_ROUTING_ENABLED"] = True

    with pytest.raises(ValueError, match="Live routing execution is not implemented"):
        create_device_app(app_config)

    assert not app_config["DATA_DIR"].exists()


@pytest.mark.parametrize("path", ["/", "/routers", "/login", "/api/routers", "/api/system/status", "/router-config/TEST-R1"])
def test_device_application_does_not_expose_browser_or_legacy_routes(client, path):
    response = client.get(path)
    assert response.status_code == 404
    assert response.is_json


def test_polling_endpoint_rejects_unexpected_http_method(client):
    response = client.get(ENDPOINT)
    assert response.status_code == 405
    assert response.is_json


def test_secrets_and_signatures_do_not_reach_responses_or_logs(app, client):
    raw = encoded(request_body())
    headers = signed_headers(raw)
    success = client.post(ENDPOINT, data=raw, headers=headers, content_type="application/json")
    failure = poll(client, secret=OTHER_SECRET)
    logs = json.dumps(app.extensions["json_storage"].read_json("activity_logs.json"))
    exposed = success.get_data(as_text=True) + failure.get_data(as_text=True) + logs

    assert success.status_code == 200
    assert failure.status_code == 401
    assert SECRET not in exposed
    assert OTHER_SECRET not in exposed
    assert headers["X-SDR-Signature"] not in exposed


def test_corrupt_communication_storage_fails_closed_with_safe_json(app, client):
    storage = app.extensions["json_storage"]
    registry_before = storage.read_json("routers.json")
    state_path = app.config["DATA_DIR"] / "router_communication.json"
    damaged = '{"schema_version":1,"secret":"' + SECRET
    state_path.write_text(damaged)

    response = poll(client)

    assert response.status_code == 503
    assert response.get_json() == {"error": "Controller storage is unavailable."}
    assert "traceback" not in response.get_data(as_text=True).lower()
    assert SECRET not in response.get_data(as_text=True)
    assert state_path.read_text() == damaged
    assert storage.read_json("routers.json") == registry_before
    assert registry_before[0]["connection_status"] == "disconnected"


def test_stored_legacy_proposal_cannot_be_delivered_by_handshake(app, client):
    storage = app.extensions["json_storage"]
    proposal = {
        "schema_version": 1, "command_id": "test-only-proposal", "router_id": ROUTER_ID,
        "timestamp": timestamp(), "mode": "live", "action": "update_routing_configuration",
        "configuration": {"interface": "test-uplink", "cost": 22},
    }
    storage.write_router_config(proposal)

    response = poll(client)

    assert response.status_code == 200
    assert response.get_json()["action"] == "none"
    assert response.get_json()["configuration"] == {}
    assert storage.read_router_config(ROUTER_ID) == proposal


def test_concurrent_duplicate_requests_have_one_successful_consumption(app):
    payload = request_body()

    def submit(_):
        with app.test_client() as client:
            return poll(client, payload).status_code

    with ThreadPoolExecutor(max_workers=4) as executor:
        statuses = list(executor.map(submit, range(4)))

    assert statuses.count(200) == 1
    assert statuses.count(409) == 3


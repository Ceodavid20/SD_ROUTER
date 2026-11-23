"""V2 protocol and receipt tests using isolated data and no live routers."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
from uuid import uuid4

import pytest

from device_app import create_device_app
from services.controller_status_service import read_controller_status
from services.json_storage import ValidationError
from services.router_poll_service import PollError
from services.router_protocol import ProtocolError
from services.routeros_poll_service import RouterOSPollService, validate_routeros_state
from services.routeros_protocol import (
    ROUTEROS_ACK_PATH, ROUTEROS_POLL_PATH, parse_routeros_request,
    sign_routeros_request, validate_routeros_response,
)

SECRET = "v2-test-only-secret-0123456789abcdefghijklmnopqrstuvwxyz"
OTHER_SECRET = "v2-other-test-secret-0123456789abcdefghijklmnopqrstuvwxyz"
NOW = datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("V2 test contacted a router"))


def payload(request_type="poll", **changes):
    result = {
        "protocol_version": "2.0", "router_id": "TEST-V2-R1",
        "request_id": str(uuid4()), "timestamp": int(datetime.now(UTC).timestamp()),
        "request_type": request_type,
    }
    if request_type == "ack":
        result["response_id"] = str(uuid4())
    return {**result, **changes}


def encoded(body):
    return json.dumps(body, separators=(",", ":")).encode()


def headers(raw, request_type="poll", secret=SECRET, key_id="PRIMARY"):
    path = ROUTEROS_POLL_PATH if request_type == "poll" else ROUTEROS_ACK_PATH
    return {"X-SDR-Key-Id": key_id, "X-SDR-Signature": sign_routeros_request(secret, raw, key_id, path)}


@pytest.fixture
def app_config(tmp_path):
    return {
        "TESTING": True, "SIMULATION_MODE": True, "LIVE_ROUTING_ENABLED": False,
        "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output",
        "ROUTER_RATE_LIMIT_ATTEMPTS": 100,
    }


@pytest.fixture
def app(app_config, monkeypatch):
    monkeypatch.setenv("TEST_V2_R1_PRIMARY_SECRET", SECRET)
    application = create_device_app(app_config)
    application.extensions["json_storage"].write_json("routers.json", [{
        "router_id": "TEST-V2-R1", "name": "V2 test router",
        "controller_auth_ref": "TEST_V2_R1", "controller_auth_enabled": True,
        "controller_auth_key_ids": ["PRIMARY"], "connection_status": "disconnected",
    }])
    return application


def send(app, body=None, request_type="poll", secret=SECRET, key_id="PRIMARY"):
    raw = encoded(body or payload(request_type))
    path = ROUTEROS_POLL_PATH if request_type == "poll" else ROUTEROS_ACK_PATH
    return app.test_client().post(path, data=raw, content_type="application/json",
                                 headers=headers(raw, request_type, secret, key_id))


def state(app):
    return app.extensions["json_storage"].read_json("router_communication_v2.json")


def test_protocol_signature_matches_independent_standard_hmac():
    raw = b'{"protocol_version":"2.0"}'
    canonical = ("SDR-POLL-V2\nPOST\n/api/controller/v2/poll\nPRIMARY\n" + hashlib.sha512(raw).hexdigest()).encode()
    expected = hmac.new(SECRET.encode(), canonical, hashlib.sha512).hexdigest()
    assert sign_routeros_request(SECRET, raw, "PRIMARY") == expected
    assert len(expected) == 128
    assert sign_routeros_request(SECRET, raw, "PRIMARY", ROUTEROS_ACK_PATH) != expected


def test_protocol_fixed_signature_vector_for_routeros_interoperability():
    raw = b'{"protocol_version":"2.0","router_id":"TEST-V2-R1","request_id":"36becb7e-17c5-4dd7-8c96-d5c1de359ab4","timestamp":1795089600,"request_type":"poll"}'
    expected = (
        "f5d1cf04f2f819a4094ddc714a974a9ea2b6da55191729af1f86c1c5184fe369b"
        "989a99b9cb0fadba5c8a210d556becadadded97bef66fa0d70861e7d358b43f"
    )
    assert sign_routeros_request("test-only-routeros-vector-key-0123456789", raw, "PRIMARY") == expected


def test_protocol_request_and_ack_are_explicitly_versioned():
    poll = payload(timestamp=int(NOW.timestamp()))
    assert parse_routeros_request(encoded(poll)) == poll
    ack = payload("ack", timestamp=int(NOW.timestamp()))
    assert parse_routeros_request(encoded(ack), "ack") == ack
    with pytest.raises(ProtocolError):
        parse_routeros_request(encoded(ack))
    with pytest.raises(ProtocolError):
        parse_routeros_request(encoded(poll), "ack")


@pytest.mark.parametrize("changes", [
    {"protocol_version": "1.0"}, {"timestamp": "2026-11-19T12:00:00Z"},
    {"timestamp": 1.5}, {"timestamp": True}, {"timestamp": 0}, {"timestamp": -1},
    {"timestamp": 2**53}, {"router_id": "../private"}, {"request_id": "not-a-uuid"},
    {"request_type": "execute"}, {"configuration": {"interface": "test", "cost": 22}},
])
def test_protocol_invalid_request_is_rejected(changes):
    with pytest.raises(ProtocolError):
        parse_routeros_request(encoded(payload(**changes)))


@pytest.mark.parametrize("raw", [
    b"", b"[]", b"{", b" " * 8193,
    b'{"protocol_version":"2.0","protocol_version":"2.0"}', b'{"timestamp":NaN}',
])
def test_protocol_malformed_json_is_rejected(raw):
    with pytest.raises(ProtocolError):
        parse_routeros_request(raw)


def test_poll_is_authenticated_without_api_connectivity(app):
    response = send(app)
    assert response.status_code == 200
    body = response.get_json()
    validate_routeros_response(body)
    assert body["action"] == "none" and body["configuration"] == {}
    record = state(app)["routers"]["TEST-V2-R1"]
    assert record["last_response_id"] == body["response_id"]
    assert record["last_received_response_id"] is None and record["last_received_at"] is None
    assert record["mode"] == "dry_run" and record["last_request_type"] == "poll"
    assert app.extensions["json_storage"].read_json("routers.json")[0]["connection_status"] == "disconnected"


def test_receipt_ack_confirms_receipt_only_and_keeps_poll_identity(app):
    first = send(app).get_json()
    reply = send(app, payload("ack", response_id=first["response_id"]), "ack")
    assert reply.status_code == 200
    body = reply.get_json()
    validate_routeros_response(body, "ack")
    assert body["acknowledged_response_id"] == first["response_id"]
    record = state(app)["routers"]["TEST-V2-R1"]
    assert record["last_response_id"] == first["response_id"]
    assert record["last_received_response_id"] == first["response_id"] and record["last_received_at"]
    assert record["last_request_type"] == "ack" and "last_applied_instruction" not in record
    assert body["action"] == "none" and body["configuration"] == {}
    again = send(app, payload("ack", response_id=first["response_id"]), "ack")
    assert again.status_code == 200
    assert state(app)["routers"]["TEST-V2-R1"]["last_received_at"] == record["last_received_at"]


@pytest.mark.parametrize("step_seconds", [0, 1])
def test_out_of_order_and_fresh_duplicate_acks_never_rewind_newer_receipt(app, step_seconds):
    storage = app.extensions["json_storage"]
    service = RouterOSPollService(storage, app.config)

    def exchange(step, request_type="poll", response_id=None):
        current = NOW + timedelta(seconds=step * step_seconds)
        body = payload(request_type, timestamp=int(current.timestamp()))
        if response_id is not None:
            body["response_id"] = response_id
        raw = encoded(body)
        reply = service.handle(
            raw, "PRIMARY", headers(raw, request_type)["X-SDR-Signature"],
            "127.0.0.1", request_type, now=current,
        )
        validate_routeros_response(reply, request_type)
        assert reply["action"] == "none" and reply["configuration"] == {}
        return reply

    first = exchange(0)
    latest = exchange(1)
    exchange(2, "ack", latest["response_id"])
    confirmed = deepcopy(state(app)["routers"]["TEST-V2-R1"])
    old_receipt = exchange(3, "ack", first["response_id"])
    assert old_receipt["acknowledged_response_id"] == first["response_id"]
    first_received_at = next(
        item["received_at"] for item in state(app)["issued_responses"]
        if item["response_id"] == first["response_id"]
    )
    exchange(4, "ack", first["response_id"])
    record = state(app)["routers"]["TEST-V2-R1"]
    assert record["last_response_id"] == latest["response_id"]
    assert record["last_received_response_id"] == latest["response_id"]
    assert record["last_received_at"] == confirmed["last_received_at"]
    receipts = {item["response_id"]: item["received_at"] for item in state(app)["issued_responses"]}
    assert receipts[first["response_id"]] == first_received_at
    assert receipts[latest["response_id"]] == confirmed["last_received_at"]
    status = read_controller_status(
        storage, app.config, storage.read_json("routers.json"),
        now=NOW + timedelta(seconds=4 * step_seconds),
    )["TEST-V2-R1"]
    assert status["latest_response_received"] is True and status["receipt_state"] == "received"
    # A new unacknowledged poll must not let an old duplicate replace the
    # newest previously acknowledged response either.
    newer = exchange(5)
    exchange(6, "ack", first["response_id"])
    record = state(app)["routers"]["TEST-V2-R1"]
    assert record["last_response_id"] == newer["response_id"]
    assert record["last_received_response_id"] == latest["response_id"]
    exchange(7, "ack", newer["response_id"])
    exchange(8, "ack", latest["response_id"])
    assert state(app)["routers"]["TEST-V2-R1"]["last_received_response_id"] == newer["response_id"]


def test_old_ack_cannot_rewind_receipt_after_newer_response_record_expires(app):
    storage = app.extensions["json_storage"]
    service = RouterOSPollService(storage, app.config)

    def exchange(seconds, request_type="poll", response_id=None):
        current = NOW + timedelta(seconds=seconds)
        body = payload(request_type, timestamp=int(current.timestamp()))
        if response_id is not None:
            body["response_id"] = response_id
        raw = encoded(body)
        return service.handle(
            raw, "PRIMARY", headers(raw, request_type)["X-SDR-Signature"],
            "127.0.0.1", request_type, now=current,
        )

    # Different configured TTLs can leave an older response live after a
    # newer response expires and is removed from the bounded response list.
    app.config["ROUTER_RESPONSE_TTL_SECONDS"] = 300
    oldest = exchange(0)
    exchange(0, "ack", oldest["response_id"])
    app.config["ROUTER_RESPONSE_TTL_SECONDS"] = 1
    newer = exchange(1)
    exchange(1, "ack", newer["response_id"])
    expected = deepcopy(state(app)["routers"]["TEST-V2-R1"])
    latest = exchange(3)
    exchange(3, "ack", oldest["response_id"])
    record = state(app)["routers"]["TEST-V2-R1"]
    assert record["last_response_id"] == latest["response_id"]
    assert record["last_received_response_id"] == newer["response_id"]
    assert record["last_received_at"] == expected["last_received_at"]


def test_ack_rejects_unknown_or_other_routers_response(app, monkeypatch):
    assert send(app, request_type="ack").status_code == 409
    first = send(app).get_json()
    store = app.extensions["json_storage"]
    monkeypatch.setenv("TEST_V2_R2_PRIMARY_SECRET", OTHER_SECRET)
    store.update_json("routers.json", lambda rows: [*rows, {
        "router_id": "TEST-V2-R2", "controller_auth_ref": "TEST_V2_R2",
        "controller_auth_enabled": True, "controller_auth_key_ids": ["PRIMARY"],
    }])
    attacker = payload("ack", router_id="TEST-V2-R2", response_id=first["response_id"])
    assert send(app, attacker, "ack", OTHER_SECRET).status_code == 409
    assert state(app)["routers"]["TEST-V2-R1"]["last_received_at"] is None
    assert "TEST-V2-R2" not in state(app)["routers"]


def test_request_replay_rejected_after_restart(app, app_config):
    body = payload()
    assert send(app, body).status_code == 200
    before = deepcopy(state(app)["routers"])
    restarted = create_device_app(app_config)
    assert send(restarted, body).status_code == 409
    assert state(restarted)["routers"] == before


def test_ack_nonce_replay_rejected(app):
    first = send(app).get_json()
    body = payload("ack", response_id=first["response_id"])
    assert send(app, body, "ack").status_code == 200
    before = deepcopy(state(app)["routers"])
    assert send(app, body, "ack").status_code == 409
    assert state(app)["routers"] == before


@pytest.mark.parametrize("age", [-3600, 3600])
def test_expired_or_future_epoch_timestamp_is_rejected(app, age):
    body = payload(timestamp=int(datetime.now(UTC).timestamp()) + age)
    assert send(app, body).status_code == 401
    assert state(app)["routers"] == {}


def test_invalid_signature_unknown_disabled_and_rotated_keys(app, monkeypatch):
    assert send(app, secret=OTHER_SECRET).status_code == 401
    assert send(app, payload(router_id="UNKNOWN")).status_code == 401
    storage = app.extensions["json_storage"]
    monkeypatch.setenv("TEST_V2_R1_NEXT_SECRET", OTHER_SECRET)

    def rotate(rows):
        rows[0]["controller_auth_key_ids"] = ["NEXT"]
        return rows
    storage.update_json("routers.json", rotate)
    assert send(app).status_code == 401
    assert send(app, secret=OTHER_SECRET, key_id="NEXT").status_code == 200

    def revoke(rows):
        rows[0]["controller_auth_enabled"] = False
        return rows
    storage.update_json("routers.json", revoke)
    assert send(app, secret=OTHER_SECRET, key_id="NEXT").status_code == 401


def test_no_secret_or_signature_is_logged_or_returned(app):
    raw = encoded(payload())
    signed = headers(raw)
    ok = app.test_client().post(ROUTEROS_POLL_PATH, data=raw, content_type="application/json", headers=signed)
    failed = send(app, secret=OTHER_SECRET)
    logged = json.dumps(app.extensions["json_storage"].read_json("activity_logs.json"))
    combined = logged + ok.get_data(as_text=True) + failed.get_data(as_text=True)
    assert SECRET not in combined and OTHER_SECRET not in combined
    assert signed["X-SDR-Signature"] not in combined


def test_concurrent_replay_has_exactly_one_acceptance(app):
    body = payload()
    with ThreadPoolExecutor(max_workers=4) as pool:
        statuses = list(pool.map(lambda _: send(app, body).status_code, range(4)))
    assert statuses.count(200) == 1 and statuses.count(409) == 3


def test_expired_receipt_cannot_be_acknowledged(app):
    storage = app.extensions["json_storage"]
    service = RouterOSPollService(storage, app.config)
    first_payload = payload(timestamp=int(NOW.timestamp()))
    raw = encoded(first_payload)
    response = service.handle(raw, "PRIMARY", headers(raw)["X-SDR-Signature"], "127.0.0.1", now=NOW)
    later = NOW + timedelta(seconds=61)
    ack = payload("ack", timestamp=int(later.timestamp()), response_id=response["response_id"])
    raw = encoded(ack)
    with pytest.raises(PollError) as error:
        service.handle(raw, "PRIMARY", headers(raw, "ack")["X-SDR-Signature"], "127.0.0.1", "ack", now=later)
    assert error.value.status == 409
    assert state(app)["routers"]["TEST-V2-R1"]["last_received_at"] is None


def test_protocol_no_action_response_rejects_command_or_epoch_mismatch(app):
    body = send(app).get_json()
    for mutation in (
        {"action": "execute"}, {"configuration": {"cost": 22}},
        {"expires_at_unix": body["expires_at_unix"] + 1},
        {"issued_at_unix": True}, {"poll_after_seconds": False},
    ):
        with pytest.raises(ProtocolError):
            validate_routeros_response({**body, **mutation})


def test_state_validator_rejects_unknown_fields_and_record_inconsistency(app):
    send(app)
    valid = state(app)
    validate_routeros_state(valid)
    invalid = deepcopy(valid)
    invalid["routers"]["TEST-V2-R1"]["last_received_at"] = valid["routers"]["TEST-V2-R1"]["last_authenticated_at"]
    with pytest.raises(ValidationError):
        validate_routeros_state(invalid)
    with pytest.raises(ValidationError):
        validate_routeros_state({**valid, "secret": SECRET})


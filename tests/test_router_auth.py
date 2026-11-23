"""Protocol and per-router authentication tests use no device or real secret."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
import hashlib
import hmac
import json
from uuid import uuid1, uuid4

import pytest

from services.router_auth_service import AuthenticationError, RouterAuthService
from services.router_protocol import (
    POLL_PATH, ProtocolError, parse_poll_request, parse_utc_timestamp, sign_request,
    utc_text, validate_poll_response,
)


NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
SECRET = "test-only-router-secret-not-used-on-any-device"
SECOND_SECRET = "test-only-rotated-secret-not-used-on-any-device"


class Registry:
    """Read-only test registry; authentication must never call a write method."""

    def __init__(self):
        self.records = [{
            "router_id": "TEST-ROUTER-1", "name": "Local authentication fixture",
            "controller_auth_ref": "TEST_POLL_ROUTER",
            "controller_auth_enabled": True,
            "controller_auth_key_ids": ["PRIMARY"],
        }]

    def read_json(self, name):
        assert name == "routers.json"
        return deepcopy(self.records)


@pytest.fixture
def registry():
    return Registry()


@pytest.fixture
def auth(registry, monkeypatch):
    monkeypatch.setenv("TEST_POLL_ROUTER_PRIMARY_SECRET", SECRET)
    monkeypatch.setenv("TEST_POLL_ROUTER_NEXT_SECRET", SECOND_SECRET)
    return RouterAuthService(registry, {
        "ROUTER_REQUEST_MAX_AGE_SECONDS": 120,
        "ROUTER_CLOCK_SKEW_SECONDS": 30,
    })


def request_payload(**updates):
    return {
        "protocol_version": "1.0", "router_id": "TEST-ROUTER-1",
        "request_id": str(uuid4()), "timestamp": utc_text(NOW),
        "request_type": "poll", **updates,
    }


def encoded(payload):
    return json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()


def response_payload(**updates):
    return {
        "protocol_version": "1.0", "router_id": "TEST-ROUTER-1",
        "request_id": str(uuid4()), "response_id": str(uuid4()),
        "status": "authenticated", "mode": "dry_run", "action": "none",
        "configuration": {}, "reason": "optimization_unavailable",
        "issued_at": utc_text(NOW), "expires_at": utc_text(NOW + timedelta(seconds=60)),
        "poll_after_seconds": 60, **updates,
    }


def test_valid_request_parses_and_authenticates_without_storage_writes(auth, registry):
    payload = request_payload()
    raw = encoded(payload)
    before = deepcopy(registry.records)

    assert parse_poll_request(raw) == payload
    result = auth.authenticate(payload, raw, "PRIMARY", sign_request(SECRET, raw, "PRIMARY"), NOW)

    assert result["router_id"] == "TEST-ROUTER-1"
    assert registry.records == before
    assert SECRET not in repr(result)


def test_signature_has_a_documented_independent_test_vector():
    raw = b'{"fixed":"bytes"}'
    canonical = (
        "SDR-POLL-V1\nPOST\n/api/controller/v1/poll\nPRIMARY\n"
        + hashlib.sha256(raw).hexdigest()
    ).encode("ascii")
    expected = hmac.new(SECRET.encode(), canonical, hashlib.sha256).hexdigest()

    assert sign_request(SECRET, raw, "PRIMARY") == expected
    assert len(expected) == 64


@pytest.mark.parametrize("change", [
    {"protocol_version": "2.0"}, {"protocol_version": 1}, {"router_id": "../admin"},
    {"router_id": "bad\nrouter"}, {"router_id": ""}, {"router_id": "x" * 65},
    {"request_id": str(uuid1())}, {"request_id": "123"},
    {"request_id": str(uuid4()).upper()}, {"request_type": "execute"},
    {"timestamp": "2026-11-19T12:00:00"},
    {"timestamp": "2026-11-19T12:00:00+00:00"},
    {"timestamp": "2026-02-30T12:00:00Z"},
    {"timestamp": "2026-11-19T12:00:00.1234567Z"},
    {"password": "test-only-unwanted-property"},
])
def test_request_rejects_wrong_fields_types_and_identifiers(change):
    with pytest.raises(ProtocolError):
        parse_poll_request(encoded(request_payload(**change)))


@pytest.mark.parametrize("raw", [
    b"", b"[1, 2]", b"null", b"true", b"{", b"\xff", b" " * 8193,
    b'{"router_id":"first","router_id":"second"}',
    b'{"number":NaN}', b'{"number":Infinity}', b'{"number":-Infinity}',
])
def test_invalid_json_has_safe_protocol_error(raw):
    with pytest.raises(ProtocolError) as error:
        parse_poll_request(raw)
    assert "Traceback" not in str(error.value)


def test_missing_request_field_is_rejected():
    payload = request_payload()
    del payload["request_id"]
    with pytest.raises(ProtocolError):
        parse_poll_request(encoded(payload))


def test_malformed_signature_and_wrong_secret_are_indistinguishable(auth):
    payload = request_payload()
    raw = encoded(payload)
    for signature in ("", "f" * 63, "z" * 64, "A" * 64,
                      sign_request(SECOND_SECRET, raw, "PRIMARY")):
        with pytest.raises(AuthenticationError) as error:
            auth.authenticate(payload, raw, "PRIMARY", signature, NOW)
        assert str(error.value) == "Router authentication failed."
        assert error.value.code == "authentication_failed"
        assert SECRET not in str(error.value)


@pytest.mark.parametrize("field,value", [
    ("controller_auth_enabled", False), ("controller_auth_enabled", "true"),
    ("controller_auth_ref", "../ENV"), ("controller_auth_ref", ""),
    ("controller_auth_key_ids", []), ("controller_auth_key_ids", "PRIMARY"),
    ("controller_auth_key_ids", ["PRIMARY", "PRIMARY"]),
    ("controller_auth_key_ids", ["primary"]),
])
def test_revoked_or_invalid_registration_is_rejected(auth, registry, field, value):
    registry.records[0][field] = value
    payload = request_payload()
    raw = encoded(payload)
    with pytest.raises(AuthenticationError, match="Router authentication failed"):
        auth.authenticate(payload, raw, "PRIMARY", sign_request(SECRET, raw, "PRIMARY"), NOW)


def test_unknown_router_and_missing_credentials_are_rejected(auth, registry, monkeypatch):
    payload = request_payload(router_id="UNREGISTERED")
    raw = encoded(payload)
    with pytest.raises(AuthenticationError):
        auth.authenticate(payload, raw, "PRIMARY", sign_request(SECRET, raw, "PRIMARY"), NOW)
    payload = request_payload()
    raw = encoded(payload)
    monkeypatch.delenv("TEST_POLL_ROUTER_PRIMARY_SECRET")
    with pytest.raises(AuthenticationError):
        auth.authenticate(payload, raw, "PRIMARY", sign_request(SECRET, raw, "PRIMARY"), NOW)


@pytest.mark.parametrize("secret", ["", "x" * 31, "x" * 4097])
def test_weak_or_oversized_secrets_are_rejected(auth, monkeypatch, secret):
    payload = request_payload()
    raw = encoded(payload)
    monkeypatch.setenv("TEST_POLL_ROUTER_PRIMARY_SECRET", secret)
    with pytest.raises(AuthenticationError):
        auth.authenticate(payload, raw, "PRIMARY", sign_request(SECRET, raw, "PRIMARY"), NOW)


@pytest.mark.parametrize("method,path", [("GET", POLL_PATH), ("POST", "/other")])
def test_signature_is_bound_to_method_and_endpoint(auth, method, path):
    payload = request_payload()
    raw = encoded(payload)
    signature = sign_request(SECRET, raw, "PRIMARY", method=method, path=path)
    with pytest.raises(AuthenticationError):
        auth.authenticate(payload, raw, "PRIMARY", signature, NOW)


def test_signature_is_bound_to_exact_body_bytes_and_identity(auth, registry):
    payload = request_payload()
    raw = encoded(payload)
    signature = sign_request(SECRET, raw, "PRIMARY")
    spaced = json.dumps(payload, indent=2).encode()
    with pytest.raises(AuthenticationError):
        auth.authenticate(payload, spaced, "PRIMARY", signature, NOW)
    different = {**payload, "router_id": "OTHER-ROUTER"}
    with pytest.raises(AuthenticationError):
        auth.authenticate(different, raw, "PRIMARY", signature, NOW)


def test_key_rotation_and_revocation_take_effect_without_auth_cache(auth, registry):
    payload = request_payload()
    raw = encoded(payload)
    registry.records[0]["controller_auth_key_ids"] = ["PRIMARY", "NEXT"]
    for key_id, secret in (("PRIMARY", SECRET), ("NEXT", SECOND_SECRET)):
        assert auth.authenticate(payload, raw, key_id, sign_request(secret, raw, key_id), NOW)
    # Relabelling an old-key signature cannot authenticate as the next key.
    with pytest.raises(AuthenticationError):
        auth.authenticate(payload, raw, "NEXT", sign_request(SECRET, raw, "PRIMARY"), NOW)
    registry.records[0]["controller_auth_key_ids"] = ["NEXT"]
    with pytest.raises(AuthenticationError):
        auth.authenticate(payload, raw, "PRIMARY", sign_request(SECRET, raw, "PRIMARY"), NOW)
    assert auth.authenticate(payload, raw, "NEXT", sign_request(SECOND_SECRET, raw, "NEXT"), NOW)


@pytest.mark.parametrize("seconds,code", [(-121, "expired_request"), (31, "future_request")])
def test_expired_and_future_signed_requests_are_rejected(auth, seconds, code):
    payload = request_payload(timestamp=utc_text(NOW + timedelta(seconds=seconds)))
    raw = encoded(payload)
    with pytest.raises(AuthenticationError) as error:
        auth.authenticate(payload, raw, "PRIMARY", sign_request(SECRET, raw, "PRIMARY"), NOW)
    assert error.value.code == code
    assert str(error.value) == "Router authentication failed."


@pytest.mark.parametrize("seconds", [-120, 0, 30])
def test_freshness_boundary_is_explicit(auth, seconds):
    payload = request_payload(timestamp=utc_text(NOW + timedelta(seconds=seconds)))
    raw = encoded(payload)
    assert auth.authenticate(payload, raw, "PRIMARY", sign_request(SECRET, raw, "PRIMARY"), NOW)


def test_utc_serialization_normalizes_aware_offsets_and_rejects_naive():
    local = datetime(2026, 11, 19, 13, 0, tzinfo=timezone(timedelta(hours=1)))
    assert utc_text(local) == "2026-11-19T12:00:00.000000Z"
    assert parse_utc_timestamp(utc_text(local)) == NOW
    with pytest.raises(ProtocolError):
        utc_text(datetime(2026, 11, 19, 12))


def test_valid_no_action_response():
    validate_poll_response(response_payload())


@pytest.mark.parametrize("change", [
    {"protocol_version": "2.0"}, {"router_id": "../router"},
    {"request_id": "not-a-uuid"}, {"response_id": str(uuid1())},
    {"status": "applied"}, {"mode": "live"}, {"action": "set_ospf_cost"},
    {"configuration": {"interface": "ether1", "cost": 22}},
    {"configuration": []}, {"reason": "ready_for_live_changes"},
    {"expires_at": utc_text(NOW)},
    {"expires_at": utc_text(NOW - timedelta(seconds=1))},
    {"expires_at": utc_text(NOW + timedelta(seconds=301))},
    {"poll_after_seconds": True}, {"poll_after_seconds": 0},
    {"poll_after_seconds": 86401}, {"password": "test-only-unwanted-property"},
])
def test_unsafe_or_malformed_response_is_rejected(change):
    with pytest.raises(ProtocolError):
        validate_poll_response(response_payload(**change))


def test_missing_response_field_is_rejected():
    payload = response_payload()
    del payload["expires_at"]
    with pytest.raises(ProtocolError):
        validate_poll_response(payload)

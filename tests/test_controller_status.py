"""Controller check-ins are independent from optional RouterOS API diagnostics."""

from datetime import UTC, datetime, timedelta
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app import create_app
from services.controller_status_service import read_controller_status
from services.json_storage import StorageService, ValidationError
from services.router_service import RouterService
from services.routeros_api import RouterAPIError
from services.status_service import read_status


NOW = datetime(2026, 11, 19, 10, 0, tzinfo=UTC)
ROUTER_ID = "TEST-STATUS-R1"


def stamp(value):
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def registry(**changes):
    return {
        "router_id": ROUTER_ID, "name": "Status test router",
        "controller_auth_ref": "TEST_STATUS", "controller_auth_enabled": True,
        "controller_auth_key_ids": ["PRIMARY"], "connection_status": "disconnected",
        **changes,
    }


def v1_record(at, *, response_id=None):
    return {
        "last_request_at": stamp(at), "last_authenticated_at": stamp(at),
        "last_response_id": response_id or str(uuid4()),
        "last_response_issued_at": stamp(at), "mode": "dry_run",
    }


def v2_record(at, *, response_id=None, response_at=None, received_id=None, received_at=None):
    issued = response_at or at
    return {
        "last_request_at": stamp(at), "last_authenticated_at": stamp(at),
        "last_response_id": response_id or str(uuid4()),
        "last_response_issued_at": stamp(issued),
        "last_response_expires_at": stamp(issued + timedelta(seconds=60)),
        "last_received_response_id": received_id,
        "last_received_at": stamp(received_at or at) if received_id else None,
        "mode": "dry_run", "last_request_type": "ack" if received_id else "poll",
    }


@pytest.fixture
def storage(tmp_path):
    store = StorageService(tmp_path / "data", tmp_path / "output")
    store.initialize()
    store.write_json("routers.json", [registry()])
    return store


def save_record(storage, version, record, router_id=ROUTER_ID):
    name = "router_communication.json" if version == "1.0" else "router_communication_v2.json"
    state = storage.read_json(name)
    state["routers"][router_id] = record
    storage.write_json(name, state)


def summary(storage, **config):
    return read_controller_status(
        storage, config, storage.read_json("routers.json"), now=NOW,
    )[ROUTER_ID]


@pytest.mark.parametrize("changes", [
    {"controller_auth_enabled": False}, {"controller_auth_ref": ""},
    {"controller_auth_key_ids": []}, {"controller_auth_key_ids": ["invalid-key"]},
])
def test_incomplete_or_disabled_authorization_is_never_shown_as_connected(storage, changes):
    storage.write_json("routers.json", [registry(**changes)])
    save_record(storage, "2.0", v2_record(NOW))
    result = summary(storage)
    assert result["state"] == "disabled"
    assert result["last_authenticated_at"] == stamp(NOW)


def test_provisioned_router_without_checkins_is_awaiting_not_connected(storage):
    result = summary(storage)
    assert result["state"] == "awaiting"
    assert result["last_authenticated_at"] is None
    assert result["protocol_version"] is None
    assert result["receipt_state"] == "not_issued"
    assert result["latest_response_received"] is False


@pytest.mark.parametrize("key_ids", [
    ["PRIMARY", "PRIMARY"], ["PRIMARY", "invalid-key"], "PRIMARY", None,
    ["PRIMARY", {"unknown": "test-only-private-key-metadata"}],
])
def test_inventory_and_status_counts_reject_exact_malformed_registry_keys(storage, key_ids):
    storage.write_json("routers.json", [registry(controller_auth_key_ids=key_ids)])
    save_record(storage, "2.0", v2_record(datetime.now(UTC)))
    result = RouterService(storage, {}).list_routers()[0]
    assert result["controller_polling"]["state"] == "disabled"
    counts = read_status(storage, {})["controller_polling"]
    assert counts == {"disabled": 1, "awaiting": 0, "authenticated": 0, "stale": 0}
    assert "test-only-private-key-metadata" not in json.dumps(result)


@pytest.mark.parametrize(("age", "state"), [(0, "authenticated"), (180, "authenticated"), (181, "stale")])
def test_checkins_become_stale_after_three_default_poll_intervals(storage, age, state):
    save_record(storage, "2.0", v2_record(NOW - timedelta(seconds=age)))
    assert summary(storage)["state"] == state
    assert summary(storage)["stale_after_seconds"] == 180


@pytest.mark.parametrize(("interval", "age", "expected"), [
    (1, 60, "authenticated"), (120, 359, "authenticated"), (120, 361, "stale"),
])
def test_staleness_uses_configured_interval_with_minimum_grace(storage, interval, age, expected):
    save_record(storage, "1.0", v1_record(NOW - timedelta(seconds=age)))
    result = summary(storage, ROUTER_POLL_INTERVAL=interval)
    assert result["state"] == expected
    assert result["stale_after_seconds"] == max(3 * interval, 180)


def test_implausible_future_checkin_is_not_presented_as_current_connection(storage):
    save_record(storage, "2.0", v2_record(NOW + timedelta(minutes=10)))
    assert summary(storage)["state"] == "stale"


@pytest.mark.parametrize("newest", ["1.0", "2.0"])
def test_latest_authentication_is_selected_across_protocol_versions(storage, newest):
    records = {
        "1.0": v1_record(NOW if newest == "1.0" else NOW - timedelta(minutes=5)),
        "2.0": v2_record(NOW if newest == "2.0" else NOW - timedelta(minutes=5)),
    }
    for version, record in records.items():
        save_record(storage, version, record)
    result = summary(storage)
    assert result["protocol_version"] == newest
    assert result["last_authenticated_at"] == stamp(NOW)
    assert result["last_response_id"] == records[newest]["last_response_id"]
    assert result["state"] == "authenticated"


def test_recent_ack_does_not_hide_a_newer_response_issued_by_other_protocol(storage):
    v1 = v1_record(NOW - timedelta(seconds=30))
    older_id = str(uuid4())
    save_record(storage, "1.0", v1)
    save_record(storage, "2.0", v2_record(
        NOW, response_id=older_id, response_at=NOW - timedelta(seconds=50), received_id=older_id,
    ))
    result = summary(storage)
    assert result["protocol_version"] == "2.0"
    assert result["last_response_protocol_version"] == "1.0"
    assert result["last_response_id"] == v1["last_response_id"]
    assert result["last_received_response_id"] == older_id
    assert result["latest_response_received"] is False
    assert result["receipt_state"] == "not_supported"


def test_receipt_confirms_only_the_response_id_actually_acknowledged(storage):
    response_id = str(uuid4())
    save_record(storage, "2.0", v2_record(NOW, response_id=response_id, received_id=response_id))
    result = summary(storage)
    assert result["latest_response_received"] is True
    assert result["receipt_state"] == "received"
    assert result["last_received_at"] == stamp(NOW)
    assert not any("applied" in field for field in result)


def test_new_poll_does_not_inherit_an_older_response_receipt(storage):
    previous = str(uuid4())
    current = str(uuid4())
    save_record(storage, "2.0", v2_record(
        NOW, response_id=current, received_id=previous, received_at=NOW - timedelta(seconds=40),
    ))
    result = summary(storage)
    assert result["state"] == "authenticated"
    assert result["last_response_id"] == current
    assert result["last_received_response_id"] == previous
    assert result["latest_response_received"] is False
    assert result["receipt_state"] == "previous_response"


def test_exact_issued_response_receipt_overrides_older_summary_pointer(storage):
    old_id, latest_id = str(uuid4()), str(uuid4())
    save_record(storage, "2.0", v2_record(
        NOW, response_id=latest_id, response_at=NOW - timedelta(seconds=10), received_id=old_id,
    ))
    state = storage.read_json("router_communication_v2.json")
    state["issued_responses"] = [{
        "router_id": ROUTER_ID, "request_id": str(uuid4()), "response_id": latest_id,
        "issued_at": stamp(NOW - timedelta(seconds=10)),
        "expires_at": stamp(NOW + timedelta(seconds=50)),
        "received_at": stamp(NOW - timedelta(seconds=5)),
    }]
    storage.write_json("router_communication_v2.json", state)
    result = summary(storage)
    assert result["last_received_response_id"] == old_id
    assert result["latest_response_received"] is True
    assert result["receipt_state"] == "received"


def test_status_projection_never_exposes_keys_or_unknown_registry_data(storage):
    storage.write_json("routers.json", [registry(
        private_secret="test-only-do-not-expose",
        legacy_details={"token": "test-only-nested-private-value"},
    )])
    save_record(storage, "2.0", v2_record(NOW))
    result = summary(storage)
    public = json.dumps(result)
    for value in ("PRIMARY", "TEST_STATUS", "test-only-do-not-expose", "test-only-nested-private-value"):
        assert value not in public
    assert not any("key" in name or "secret" in name for name in result)


def test_unregistered_checkin_records_do_not_add_inventory(storage):
    save_record(storage, "2.0", v2_record(NOW), router_id="UNLISTED-STATUS-R2")
    result = read_controller_status(storage, {}, storage.read_json("routers.json"), now=NOW)
    assert set(result) == {ROUTER_ID}


def test_inventory_listing_is_read_only_and_api_failure_does_not_override_authenticated_poll(storage, monkeypatch):
    save_record(storage, "2.0", v2_record(datetime.now(UTC)))
    before = {
        path: path.read_bytes()
        for path in [*storage.data_dir.glob("*.json"), *storage.output_dir.glob("*.json")]
    }
    monkeypatch.setattr("socket.create_connection", lambda *args, **kwargs: pytest.fail("Status opened a router connection"))
    result = RouterService(storage, {}).list_routers()[0]
    assert result["connection_status"] == "disconnected"
    assert result["controller_polling"]["state"] == "authenticated"
    assert {path: path.read_bytes() for path in before} == before


def test_failed_optional_api_check_preserves_controller_connection_and_receipts(storage, monkeypatch):
    response_id = str(uuid4())
    save_record(storage, "2.0", v2_record(
        datetime.now(UTC), response_id=response_id, received_id=response_id,
    ))
    storage.write_json("routers.json", [registry(
        ip_address="10.0.0.8", api_port=8729, api_tls=True, credential_ref="TEST_STATUS_API",
    )])
    communication_before = storage.read_json("router_communication_v2.json")
    monkeypatch.setenv("TEST_STATUS_API_USERNAME", "test-only-api-user")
    monkeypatch.setenv("TEST_STATUS_API_PASSWORD", "test-only-private-api-password")

    def unavailable():
        raise RouterAPIError("Router API request timed out.")

    monkeypatch.setattr(
        "services.router_service.RouterOSReadOnlyClient",
        lambda *args, **kwargs: SimpleNamespace(read_resource=unavailable),
    )
    service = RouterService(storage, {"ROUTER_ALLOWED_NETWORKS": ["10.0.0.0/8"]})
    diagnostic = service.test_api(ROUTER_ID)
    assert diagnostic["connection_status"] == "disconnected"
    assert "timed out" in diagnostic["last_error"]
    result = service.list_routers()[0]
    assert result["controller_polling"]["state"] == "authenticated"
    assert result["controller_polling"]["latest_response_received"] is True
    assert storage.read_json("router_communication_v2.json") == communication_before
    assert "test-only-private-api-password" not in json.dumps(result)


def test_status_counts_report_controller_authentication_separately_from_legacy_api_readiness(storage):
    save_record(storage, "2.0", v2_record(datetime.now(UTC)))
    result = read_status(storage, {})
    assert result["readiness"] == "verification_required"
    assert result["controller_polling"] == {"authenticated": 1, "disabled": 0, "awaiting": 0, "stale": 0}


def test_invalid_communication_json_fails_closed_without_exposing_unknown_fields(storage):
    state = storage.read_json("router_communication_v2.json")
    state["routers"][ROUTER_ID] = v2_record(NOW)
    state["routers"][ROUTER_ID]["secret"] = "test-only-corrupt-private-field"
    (storage.data_dir / "router_communication_v2.json").write_text(json.dumps(state))
    with pytest.raises(ValidationError):
        summary(storage)


def test_router_page_and_dashboard_show_polling_independently_of_api_diagnostic(tmp_path, monkeypatch):
    app = create_app({
        "TESTING": True, "AUTH_ENABLED": False, "SECRET_KEY": "test-only-controller-status-session-key",
        "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output",
    })
    store = app.extensions["json_storage"]
    store.write_json("routers.json", [registry(private_secret="test-only-hidden-registry-secret")])
    old_receipt = str(uuid4())
    save_record(store, "2.0", v2_record(datetime.now(UTC), received_id=old_receipt))
    monkeypatch.setattr("socket.create_connection", lambda *args, **kwargs: pytest.fail("Browser status contacted router"))
    client = app.test_client()
    page = client.get("/routers")
    assert page.status_code == 200
    content = page.get_data(as_text=True)
    assert "Controller polling" in content and "Optional API diagnostic" in content
    assert "Authenticated" in content and "Disconnected" in content
    assert "Previous response received; latest receipt pending" in content
    assert "A receipt confirms delivery only. Routing changes are off." in content
    assert "test-only-hidden-registry-secret" not in content
    assert 'action="/routers/add"' not in content
    dashboard = client.get("/").get_data(as_text=True)
    assert "1 of 1 routers have recent authenticated controller check-ins." in dashboard
    assert "Optional API diagnostics" in dashboard
    api_router = client.get("/api/routers").get_json()["routers"][0]
    assert api_router["controller_polling"]["state"] == "authenticated"
    assert api_router["connection_status"] == "disconnected"

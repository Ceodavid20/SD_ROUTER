"""Registry edits stay independent of API reachability and secret provisioning."""

import json

import pytest

from app import create_app
from services.json_storage import StorageService
from services.router_service import RouterService, RouterValidationError


@pytest.fixture
def service(tmp_path):
    storage = StorageService(tmp_path / "data", tmp_path / "output")
    storage.initialize()
    storage.write_json("routers.json", [])
    return RouterService(storage, {
        "ROUTER_ALLOWED_NETWORKS": ["10.0.0.0/8"],
        "ALLOW_PLAINTEXT_API": False,
    })


def minimal_form(**changes):
    return {
        "router_id": "TEST-R1", "name": "Test router",
        "controller_auth_ref": "TEST_POLL_R1", **changes,
    }


def provision_test_metadata(service):
    service.add_router(minimal_form())

    def provision(routers):
        routers[0].update({
            "controller_auth_enabled": True,
            "controller_auth_key_ids": ["PRIMARY", "ROTATION"],
            "last_authenticated_at": "2026-11-19T10:00:00Z",
            "last_applied_instruction": {"response_id": "test-response", "status": "none"},
            "future_communication_metadata": {"revision": 3},
            "legacy_secret": "test-only-never-render-this-secret",
            "legacy_details": {"token": "test-only-private-nested-value"},
        })
        return routers

    service.storage.update_json("routers.json", provision)


def test_router_can_register_without_management_ip_or_router_api(service, monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Registration contacted a router"))
    record = service.add_router(minimal_form(
        controller_auth_enabled=True, controller_auth_key_ids=["PRIMARY"],
        password="test-only-not-a-form-field",
    ))

    assert record["ip_address"] == ""
    assert record["connection_status"] == "untested"
    assert record["controller_auth_ref"] == "TEST_POLL_R1"
    assert record["controller_auth_enabled"] is False
    assert record["controller_auth_key_ids"] == []
    assert "test-only-not-a-form-field" not in json.dumps(service.storage.read_json("routers.json"))


def test_api_diagnostic_still_requires_management_ip(service, monkeypatch):
    service.add_router(minimal_form())
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Missing IP reached a socket"))

    result = service.test_api("TEST-R1")

    assert result["connection_status"] == "blocked"
    assert "Management IP" in result["last_error"]


@pytest.mark.parametrize("reference", ["../secret", "lowercase", "WITH-DASH", "A" * 65])
def test_invalid_controller_auth_reference_is_rejected(service, reference):
    with pytest.raises(RouterValidationError):
        service.add_router(minimal_form(controller_auth_ref=reference))

    assert service.storage.read_json("routers.json") == []


def test_edit_preserves_auth_keys_and_unknown_communication_metadata(service):
    provision_test_metadata(service)

    result = service.edit_router("TEST-R1", {
        "name": "Updated router", "ip_address": "",
    })
    saved = service.storage.read_json("routers.json")[0]

    assert saved["name"] == "Updated router"
    assert saved["controller_auth_ref"] == "TEST_POLL_R1"
    assert saved["controller_auth_enabled"] is True
    assert saved["controller_auth_key_ids"] == ["PRIMARY", "ROTATION"]
    assert saved["last_authenticated_at"] == "2026-11-19T10:00:00Z"
    assert saved["last_applied_instruction"]["status"] == "none"
    assert saved["future_communication_metadata"] == {"revision": 3}
    for payload in (result, service.list_routers()):
        public = json.dumps(payload)
        assert "test-only-never-render-this-secret" not in public
        assert "test-only-private-nested-value" not in public


def test_same_reference_retains_provisioning_but_form_cannot_enable_keys(service):
    service.add_router(minimal_form())
    result = service.edit_router("TEST-R1", minimal_form(
        controller_auth_enabled=True, controller_auth_key_ids=["PRIMARY"],
    ))

    assert result["controller_auth_enabled"] is False
    assert result["controller_auth_key_ids"] == []

    routers = service.storage.read_json("routers.json")
    routers[0].update(controller_auth_enabled=True, controller_auth_key_ids=["PRIMARY"])
    service.storage.write_json("routers.json", routers)
    unchanged = service.edit_router("TEST-R1", minimal_form())
    assert unchanged["controller_auth_enabled"] is True
    assert unchanged["controller_auth_key_ids"] == ["PRIMARY"]


@pytest.mark.parametrize("new_reference", ["REPLACEMENT_POLL_KEY", ""])
def test_changing_reference_disables_old_keys_until_provisioned(service, new_reference):
    provision_test_metadata(service)

    result = service.edit_router("TEST-R1", minimal_form(controller_auth_ref=new_reference))
    saved = service.storage.read_json("routers.json")[0]

    assert result["controller_auth_ref"] == new_reference
    assert saved["controller_auth_enabled"] is False
    assert saved["controller_auth_key_ids"] == []
    assert saved["last_authenticated_at"] == "2026-11-19T10:00:00Z"


def test_public_projection_filters_malformed_key_ids_without_exposing_unknown_fields():
    public = RouterService._public({
        "router_id": "TEST-R1", "name": "Test router",
        "controller_auth_ref": "TEST_POLL_R1", "controller_auth_enabled": True,
        "controller_auth_key_ids": ["PRIMARY", "PRIMARY", None, "invalid-key", {"secret": "test-only-private"}],
        "unknown_private_value": "test-only-private",
    })

    assert public["controller_auth_key_ids"] == ["PRIMARY"]
    assert "test-only-private" not in json.dumps(public)


def test_router_page_keeps_management_ip_optional_and_api_diagnostic_separate(tmp_path):
    app = create_app({
        "TESTING": True, "AUTH_ENABLED": False,
        "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output",
    })

    response = app.test_client().get("/routers")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Controller authentication reference" in page
    assert "Run optional API diagnostic" in page
    assert "Its result is separate from controller polling." in page
    assert 'name="controller_auth_ref"' in page
    assert 'name="controller_auth_enabled"' not in page
    assert 'name="controller_auth_key_ids"' not in page
    ip_input = page.split('id="edit-MTN-LAGOS-address"', 1)[1].split(">", 1)[0]
    assert "required" not in ip_input
    assert 'action="/routers/add"' not in page

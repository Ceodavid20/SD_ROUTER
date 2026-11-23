"""Private API login setup, live reload and complete local prerequisites."""

from types import SimpleNamespace
import json
import os
import re
import sys

from dotenv import dotenv_values
import pytest

from app import create_app
from services.api_credentials_service import APICredentialError, api_credentials, configure_api_credentials
from services.router_service import RouterService


USERNAME = "test-only-api-account"
PASSWORD = "test-only-password-$with-special-'characters"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Credential setup contacted a router"))


@pytest.fixture
def setup(tmp_path):
    env = tmp_path / ".env"
    env.write_text("# Existing configuration\nSIMULATION_MODE=true\nLIVE_ROUTING_ENABLED=false\nUNRELATED_SETTING='preserve-this'\n")
    env.chmod(0o600)
    app = create_app({
        "TESTING": True, "AUTH_ENABLED": False, "SIMULATION_MODE": True, "LIVE_ROUTING_ENABLED": False,
        "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output",
        "API_CREDENTIALS_ENV_FILE": env, "ALLOW_PLAINTEXT_API": False,
        "ROUTER_ALLOWED_NETWORKS": ["10.0.0.0/8"],
    })
    storage = app.extensions["json_storage"]
    storage.write_json("routers.json", [{
        "router_id": "TEST-EXISTING-R1", "name": "Existing router", "ip_address": "10.0.0.10",
        "api_port": 8729, "api_tls": True, "credential_ref": "", "interface_name": "ether1",
        "monitoring_enabled": True, "controller_auth_enabled": True, "controller_auth_ref": "TEST_POLL_REF",
        "controller_auth_key_ids": ["PRIMARY"], "connection_status": "blocked", "last_error": "Previous setup error",
        "last_checked_at": "2026-11-23T10:00:00Z", "legacy_secret": "test-only-private-registry-data",
    }])
    return app, storage, RouterService(storage, app.config), env


def test_setup_preserves_router_transport_polling_tx_and_routing_settings(setup):
    app, storage, _, env = setup
    before = storage.read_json("routers.json")[0]
    protected = {name: storage.read_json(name) for name in (
        "router_communication.json", "router_communication_v2.json", "router_traffic_v2.json",
        "router_config.json", "automation_settings.json", "routing_paths.json")}
    configure_api_credentials(storage, app.config, before["router_id"], USERNAME, PASSWORD)
    row = storage.read_json("routers.json")[0]
    for key, value in before.items():
        if key not in {"credential_ref", "connection_status", "last_checked_at", "last_error"}:
            assert row[key] == value
    assert row["credential_ref"].startswith("SDR_API_") and row["api_credentials_source"] == "private_env"
    assert row["connection_status"] == "untested" and row["last_error"] is None
    assert {name: storage.read_json(name) for name in protected} == protected
    values = dotenv_values(env, interpolate=False)
    assert values[row["credential_ref"] + "_USERNAME"] == USERNAME
    assert values[row["credential_ref"] + "_PASSWORD"] == PASSWORD
    assert values["SIMULATION_MODE"] == "true" and values["LIVE_ROUTING_ENABLED"] == "false"
    assert values["UNRELATED_SETTING"] == "preserve-this"
    assert "# Existing configuration" in env.read_text() and env.stat().st_mode & 0o777 == 0o600


def test_new_credentials_are_available_without_server_restart(setup):
    app, storage, service, _ = setup
    assert service.list_routers()[0]["api_diagnostics"]["ready"] is False
    configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, PASSWORD)
    row = storage.read_json("routers.json")[0]
    assert api_credentials(row, app.config) == (USERNAME, PASSWORD)
    assert row["credential_ref"] + "_PASSWORD" not in os.environ
    assert service.list_routers()[0]["api_diagnostics"]["ready"] is True
    configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, "test-only-updated-password")
    assert api_credentials(storage.read_json("routers.json")[0], app.config)[1] == "test-only-updated-password"


def test_all_missing_prerequisites_are_shown_together(setup):
    _, storage, service, _ = setup
    storage.update_json("routers.json", lambda rows: [{**rows[0], "ip_address": "", "api_port": None, "api_tls": False}])
    readiness = service.list_routers()[0]["api_diagnostics"]
    assert readiness["ready"] is False
    messages = " ".join(readiness["requirements"])
    for text in ("Management IP", "API port", "Unencrypted", "credential reference"):
        assert text in messages


def test_setup_does_not_authorize_unencrypted_connections(setup):
    app, storage, service, _ = setup
    storage.update_json("routers.json", lambda rows: [{**rows[0], "api_tls": False, "api_port": 8728}])
    configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, PASSWORD)
    result = service.test_api("TEST-EXISTING-R1")
    assert result["connection_status"] == "blocked" and "Unencrypted" in result["last_error"]
    assert app.config["ALLOW_PLAINTEXT_API"] is False


def test_only_explicit_diagnostic_uses_the_private_credentials(setup, monkeypatch):
    app, storage, service, _ = setup
    configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, PASSWORD)
    calls = []
    def client(host, port, username, password, **kwargs):
        assert (host, port) == ("10.0.0.10", 8729)
        assert (username, password) == (USERNAME, PASSWORD) and kwargs["tls"] is True
        calls.append(True)
        return SimpleNamespace(read_resource=lambda: {"version": "7.21.4", "board-name": "CHR"})
    monkeypatch.setattr("services.router_service.RouterOSReadOnlyClient", client)
    service.list_routers()
    assert calls == []
    assert service.test_api("TEST-EXISTING-R1")["connection_status"] == "connected" and calls == [True]


def test_secrets_are_absent_from_registry_logs_pages_and_json(setup, caplog):
    app, storage, _, _ = setup
    configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, PASSWORD)
    combined = json.dumps(storage.read_json("routers.json")) + json.dumps(storage.read_json("activity_logs.json"))
    for path in ("/routers", "/api/routers", "/monitoring", "/api/system/status"):
        response = app.test_client().get(path)
        assert response.status_code == 200
        combined += response.get_data(as_text=True)
    assert USERNAME not in combined + caplog.text and PASSWORD not in combined + caplog.text


def test_unknown_router_and_invalid_credentials_leave_storage_unchanged(setup):
    app, storage, _, env = setup
    before_env, before_rows = env.read_bytes(), storage.read_json("routers.json")
    with pytest.raises(APICredentialError):
        configure_api_credentials(storage, app.config, "UNKNOWN", USERNAME, PASSWORD)
    for username, password in (("", PASSWORD), (USERNAME, ""), ("bad\nname", PASSWORD), (USERNAME, "bad\npassword")):
        with pytest.raises(APICredentialError):
            configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", username, password)
    assert env.read_bytes() == before_env and storage.read_json("routers.json") == before_rows


def test_permissions_and_symlinks_fail_closed(setup, tmp_path):
    app, storage, _, env = setup
    configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, PASSWORD)
    row = storage.read_json("routers.json")[0]
    env.chmod(0o644)
    with pytest.raises(APICredentialError):
        api_credentials(row, app.config)
    env.chmod(0o600)
    linked = tmp_path / "linked.env"
    linked.symlink_to(env)
    with pytest.raises(APICredentialError):
        api_credentials(row, {**app.config, "API_CREDENTIALS_ENV_FILE": linked})


def test_frontend_shows_private_setup_command_without_password_input(setup):
    app, storage, _, _ = setup
    page = app.test_client().get("/routers").get_data(as_text=True)
    assert "configure-router-api --router-id TEST-EXISTING-R1" in page and 'type="password"' not in page
    assert "Checking it does not enable API-SSL" in page
    configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, PASSWORD)
    assert "Complete API diagnostic setup" not in app.test_client().get("/routers").get_data(as_text=True)


@pytest.mark.parametrize("submitted_reference", ["", "OLD_ENV_REFERENCE", None])
def test_saving_an_old_router_form_preserves_private_login_and_enabled_button(setup, submitted_reference):
    app, storage, service, _ = setup
    client = app.test_client()
    # The browser has a form from before the terminal credential setup.
    old_page = client.get("/routers").get_data(as_text=True)
    assert 'disabled' in re.search(r'<button\b[^>]*>Run optional API diagnostic</button>', old_page)[0]
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, PASSWORD)
    configured = storage.read_json("routers.json")[0]
    form = {
        "csrf_token": csrf, "name": "Updated router name", "ip_address": "10.0.0.10",
        "api_port": "8729", "api_tls": "1", "interface_name": "ether1",
    }
    if submitted_reference is not None:
        form["credential_ref"] = submitted_reference
    response = client.post("/routers/TEST-EXISTING-R1/edit", data=form, follow_redirects=True)
    assert response.status_code == 200
    saved = storage.read_json("routers.json")[0]
    assert saved["name"] == "Updated router name"
    assert saved["credential_ref"] == configured["credential_ref"]
    assert saved["api_credentials_source"] == "private_env"
    assert api_credentials(saved, app.config) == (USERNAME, PASSWORD)
    assert service.api_diagnostic_readiness(saved)["ready"] is True
    page = response.get_data(as_text=True)
    assert 'disabled' not in re.search(r'<button\b[^>]*>Run optional API diagnostic</button>', page)[0]
    credential_input = re.search(r'<input\b[^>]*id="edit-TEST-EXISTING-R1-credentials"[^>]*>', page)[0]
    assert "readonly" in credential_input
    assert "Complete API diagnostic setup" not in page


def test_edit_preserves_credentials_rotated_during_the_settings_save(setup, monkeypatch):
    app, storage, service, _ = setup
    configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, PASSWORD)
    old_reference = storage.read_json("routers.json")[0]["credential_ref"]
    original_update = storage.update_json
    def rotate_before_edit(name, updater):
        if name == "routers.json":
            monkeypatch.setattr(storage, "update_json", original_update)
            configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, "new-test-only-password")
        return original_update(name, updater)
    monkeypatch.setattr(storage, "update_json", rotate_before_edit)
    service.edit_router("TEST-EXISTING-R1", {
        "name": "Existing router", "ip_address": "10.0.0.10", "api_port": "8729",
        "api_tls": "1", "credential_ref": old_reference,
    })
    saved = storage.read_json("routers.json")[0]
    assert saved["credential_ref"] != old_reference
    assert api_credentials(saved, app.config) == (USERNAME, "new-test-only-password")
    assert service.api_diagnostic_readiness(saved)["ready"] is True


def test_unmanaged_environment_references_remain_editable(setup, monkeypatch):
    app, storage, service, _ = setup
    monkeypatch.setenv("EXTERNAL_REF_USERNAME", USERNAME)
    monkeypatch.setenv("EXTERNAL_REF_PASSWORD", PASSWORD)
    service.edit_router("TEST-EXISTING-R1", {
        "name": "Existing router", "ip_address": "10.0.0.10", "api_port": "8729",
        "api_tls": "1", "credential_ref": "EXTERNAL_REF",
    })
    saved = storage.read_json("routers.json")[0]
    assert saved["credential_ref"] == "EXTERNAL_REF"
    assert api_credentials(saved, app.config) == (USERNAME, PASSWORD)
    assert service.list_routers()[0]["api_credentials_managed"] is False


def test_diagnostic_button_post_requires_csrf_and_uses_mocked_read_only_client(setup, monkeypatch):
    app, storage, _, _ = setup
    configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, PASSWORD)
    calls = []
    def client(*args, **kwargs):
        calls.append(True)
        return SimpleNamespace(read_resource=lambda: {"version": "7.21.4", "board-name": "CHR"})
    monkeypatch.setattr("services.router_service.RouterOSReadOnlyClient", client)
    browser = app.test_client()
    page = browser.get("/routers").get_data(as_text=True)
    assert 'disabled' not in re.search(r'<button\b[^>]*>Run optional API diagnostic</button>', page)[0]
    assert browser.post("/routers/TEST-EXISTING-R1/test-api").status_code == 400
    assert calls == []
    with browser.session_transaction() as session:
        csrf = session["csrf_token"]
    response = browser.post("/routers/TEST-EXISTING-R1/test-api", data={"csrf_token": csrf}, follow_redirects=True)
    assert response.status_code == 200 and calls == [True]
    assert "Read-only API connection verified" in response.get_data(as_text=True)


def test_cli_prompts_privately_and_accepts_no_password_argument(setup, monkeypatch, capsys):
    import manage
    app, _, _, _ = setup
    monkeypatch.setattr("config.load_config", lambda: dict(app.config))
    answers, prompts = iter((USERNAME, PASSWORD)), []
    def prompt(label):
        prompts.append(label)
        return next(answers)
    monkeypatch.setattr(manage, "getpass", prompt)
    monkeypatch.setattr(sys, "argv", ["manage.py", "configure-router-api", "--router-id", "TEST-EXISTING-R1"])
    manage.main()
    output = capsys.readouterr().out
    assert len(prompts) == 2 and USERNAME not in output and PASSWORD not in output
    assert "No router was contacted" in output


def test_failed_secret_write_cannot_bind_an_unstored_credential_reference(setup, monkeypatch):
    app, storage, _, env = setup
    before, contents = storage.read_json("routers.json"), env.read_bytes()
    def fail(*args, **kwargs):
        raise OSError("Synthetic private-file failure")
    monkeypatch.setattr("services.api_credentials_service.update_private_environment", fail)
    with pytest.raises(OSError):
        configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, PASSWORD)
    assert storage.read_json("routers.json") == before and env.read_bytes() == contents


def test_concurrent_endpoint_change_does_not_bind_credentials_to_another_target(setup, monkeypatch):
    app, storage, _, _ = setup
    original = storage.update_json
    def change(name, updater):
        if name == "routers.json":
            original(name, lambda rows: [{**rows[0], "ip_address": "10.0.0.11"}])
        return original(name, updater)
    monkeypatch.setattr(storage, "update_json", change)
    with pytest.raises(APICredentialError):
        configure_api_credentials(storage, app.config, "TEST-EXISTING-R1", USERNAME, PASSWORD)
    row = storage.read_json("routers.json")[0]
    assert row["ip_address"] == "10.0.0.11" and row["credential_ref"] == ""


def test_cli_refuses_input_that_could_be_echoed(setup, monkeypatch, capsys):
    from getpass import GetPassWarning
    import manage
    app, storage, _, env = setup
    before, contents = storage.read_json("routers.json"), env.read_bytes()
    monkeypatch.setattr("config.load_config", lambda: dict(app.config))
    monkeypatch.setattr(sys, "argv", ["manage.py", "configure-router-api", "--router-id", "TEST-EXISTING-R1"])
    def unsafe_input(prompt):
        import warnings
        warnings.warn("Hidden input unavailable", GetPassWarning)
        pytest.fail("A prompt fell back to echoed input")
    monkeypatch.setattr(manage, "getpass", unsafe_input)
    with pytest.raises(SystemExit):
        manage.main()
    assert storage.read_json("routers.json") == before and env.read_bytes() == contents
    assert "interactive terminal" in capsys.readouterr().err

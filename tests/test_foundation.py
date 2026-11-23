import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from services.json_storage import StorageError, StorageService
from services.router_service import RouterService


TEST_PASSWORD = "test-only-company-admin-password"
TEST_PASSWORD_HASH = generate_password_hash(TEST_PASSWORD)
SEEDED_ROUTER_IDS = {
    "MTN-LAGOS", "MTN-ABUJA", "GLO-LAGOS", "GLO-ABUJA",
    "LAGOS-AGG-1", "LAGOS-AGG-2",
}


def configured_app(storage_dirs):
    return create_app({
        "TESTING": True,
        "AUTH_ENABLED": True,
        "SECRET_KEY": "test-only-session-secret",
        "ADMIN_USERNAME": "testadmin",
        "ADMIN_PASSWORD_HASH": TEST_PASSWORD_HASH,
        "ROUTER_CONFIG_TOKEN": "",
        **storage_dirs,
    })


def signed_in_client(app):
    import hashlib

    client = app.test_client()
    with client.session_transaction() as session:
        session["admin_user"] = app.config["ADMIN_USERNAME"]
        session["admin_fingerprint"] = hashlib.sha256(
            app.config["ADMIN_PASSWORD_HASH"].encode()
        ).hexdigest()
        session["csrf_token"] = "test-only-csrf-token"
    return client


class PageHeadings(HTMLParser):
    """Read main headings without relying on frontend CSS classes."""

    def __init__(self) -> None:
        super().__init__()
        self.headings: list[str] = []
        self._heading_parts: list[str] | None = None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag == "h1":
            self._heading_parts = []

    def handle_data(self, data: str) -> None:
        if self._heading_parts is not None:
            self._heading_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "h1" and self._heading_parts is not None:
            self.headings.append(" ".join("".join(self._heading_parts).split()))
            self._heading_parts = None


@pytest.fixture
def storage_dirs(tmp_path: Path) -> dict[str, object]:
    return {"DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output"}


@pytest.fixture
def app(storage_dirs):
    return configured_app(storage_dirs)


@pytest.fixture
def client(app):
    return signed_in_client(app)


@pytest.fixture
def storage(storage_dirs):
    service = StorageService(storage_dirs["DATA_DIR"], storage_dirs["OUTPUT_DIR"])
    service.initialize()
    return service


@pytest.mark.parametrize(
    ("url", "heading"),
    [
        ("/", "Dashboard"),
        ("/routers", "Routers"),
        ("/routers/connect", "Router connection"),
        ("/routing-paths", "Routing paths"),
        ("/monitoring", "Traffic monitoring"),
        ("/mathematics", "Traffic analysis"),
        ("/optimization", "Optimization"),
        ("/json-output", "Router output"),
        ("/automation", "Automation"),
        ("/settings", "Settings"),
        ("/logs", "Activity"),
    ],
)
def test_each_page_loads_with_its_own_heading(client, url, heading):
    response = client.get(url)
    assert response.status_code == 200
    assert response.mimetype == "text/html"
    parser = PageHeadings()
    parser.feed(response.get_data(as_text=True))
    parser.close()
    assert parser.headings == [heading]


def test_topology_page_and_endpoint_are_removed(client):
    for path in ("/topology", "/api/topology"):
        assert client.get(path).status_code == 404

    page = client.get("/routing-paths").get_data(as_text=True).lower()
    assert "topology" not in page


def test_all_required_storage_files_are_initialized(app):
    data_dir = Path(app.config["DATA_DIR"])
    output_dir = Path(app.config["OUTPUT_DIR"])
    expected_data = {
        "routers.json",
        "traffic_history.json",
        "averages.json",
        "optimization_results.json",
        "routing_costs.json",
        "routing_paths.json",
        "router_communication.json",
        "router_communication_v2.json",
        "router_traffic_v2.json",
        "automation_settings.json",
        "activity_logs.json",
    }
    assert {path.name for path in data_dir.glob("*.json")} == expected_data
    assert (output_dir / "router_config.json").is_file()
    for path in [*data_dir.glob("*.json"), output_dir / "router_config.json"]:
        json.loads(path.read_text(encoding="utf-8"))
    assert {
        router["router_id"]
        for router in app.extensions["json_storage"].read_json("routers.json")
    } == SEEDED_ROUTER_IDS


def test_status_returns_json_with_safe_storage_defaults(client):
    response = client.get("/api/system/status")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    status = response.get_json()
    expected = {
        "mode": "simulation",
        "data_source": "router",
        "controller_access": "read_only",
        "readiness": "verification_required",
        "router_count": 6,
        "storage": "ready",
        "monitoring": "not_started",
        "optimization": "not_started",
        "automation": "off",
        "routing_changes_enabled": False,
        "monitoring_interval_seconds": 60,
        "averaging_window": 5,
    }
    assert {key: status[key] for key in expected} == expected


def test_dashboard_and_api_require_administrator_login(app):
    anonymous = app.test_client()
    page = anonymous.get("/")
    assert page.status_code == 302
    assert "/login" in page.headers["Location"]
    api = anonymous.get("/api/system/status")
    assert api.status_code == 401
    assert api.mimetype == "application/json"


def test_administrator_can_log_in_with_valid_credentials(app):
    anonymous = app.test_client()
    page = anonymous.get("/login")
    assert page.status_code == 200
    with anonymous.session_transaction() as session:
        csrf = session["csrf_token"]
    response = anonymous.post("/login", data={
        "username": "testadmin", "password": TEST_PASSWORD, "csrf_token": csrf,
    })
    assert response.status_code == 302
    assert anonymous.get("/").status_code == 200


def test_local_functionality_mode_opens_all_pages_without_administrator_setup(storage_dirs):
    app = create_app({
        "TESTING": True,
        "AUTH_ENABLED": False,
        "SECRET_KEY": None,
        "ADMIN_USERNAME": "",
        "ADMIN_PASSWORD_HASH": "",
        "ROUTER_CONFIG_TOKEN": "",
        **storage_dirs,
    })
    anonymous = app.test_client()
    for path in (
        "/", "/routers", "/routers/connect", "/routing-paths", "/monitoring", "/mathematics", "/optimization",
        "/json-output", "/automation", "/settings", "/logs",
    ):
        page = anonymous.get(path)
        assert page.status_code == 200, path
        assert page.mimetype == "text/html"
        assert "Administrator setup required" not in page.get_data(as_text=True)
    for path in ("/api/system/status", "/api/routers"):
        response = anonymous.get(path)
        assert response.status_code == 200, path
        assert response.mimetype == "application/json"
    assert anonymous.get("/api/system/status").get_json()["routing_changes_enabled"] is False
    assert anonymous.get("/router-config/R1").status_code == 503


def test_paused_login_redirects_to_dashboard_and_hides_signout(app):
    app.config["AUTH_ENABLED"] = False
    anonymous = app.test_client()
    with anonymous.session_transaction() as session:
        session["admin_user"] = "previous-admin-session"
    for method, path in (("get", "/login"), ("post", "/login"), ("post", "/logout")):
        response = getattr(anonymous, method)(path)
        assert response.status_code == 302
        assert response.headers["Location"] == "/"
    page = anonymous.get("/")
    assert page.status_code == 200
    assert "Sign out" not in page.get_data(as_text=True)


def test_functionality_mode_keeps_form_validation_and_csrf(app, monkeypatch):
    app.config["AUTH_ENABLED"] = False
    app.extensions["json_storage"].write_json("routers.json", [])
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Form action contacted a device"))
    anonymous = app.test_client()
    anonymous.get("/routers")
    form = {
        "router_id": "R1", "name": "Company router",
        "ip_address": "10.20.0.1", "model": "CCR2116", "routeros_version": "7.21.4",
        "api_port": "8728", "ssh_port": "53722", "credential_ref": "ROUTER_R1",
    }
    RouterService(app.extensions["json_storage"], app.config).add_router(form)
    anonymous.get("/routers")
    assert anonymous.post("/routers/R1/edit", data=form).status_code == 400
    assert app.extensions["json_storage"].read_json("routers.json")[0]["name"] == "Company router"
    with anonymous.session_transaction() as session:
        form["csrf_token"] = session["csrf_token"]
    form["name"] = "Updated company router"
    assert anonymous.post("/routers/R1/edit", data=form).status_code == 302
    assert [router["router_id"] for router in app.extensions["json_storage"].read_json("routers.json")] == ["R1"]


def test_paused_login_does_not_require_secrets_for_unused_administrator_config(storage_dirs):
    app = create_app({
        "TESTING": True,
        "AUTH_ENABLED": False,
        "SECRET_KEY": None,
        "ADMIN_USERNAME": "previous-admin",
        "ADMIN_PASSWORD_HASH": TEST_PASSWORD_HASH,
        **storage_dirs,
    })
    assert app.test_client().get("/").status_code == 200


def test_login_and_changes_reject_missing_csrf_token(app, client):
    anonymous = app.test_client()
    anonymous.get("/login")
    assert anonymous.post("/login", data={
        "username": "testadmin", "password": TEST_PASSWORD,
    }).status_code == 400
    assert client.post("/routers/MTN-LAGOS/edit", data={"name": "Changed"}).status_code == 400


def test_wrong_password_does_not_create_an_administrator_session(app):
    anonymous = app.test_client()
    anonymous.get("/login")
    with anonymous.session_transaction() as session:
        csrf = session["csrf_token"]
    response = anonymous.post("/login", data={
        "username": "testadmin", "password": "incorrect-test-password", "csrf_token": csrf,
    })
    assert response.status_code in (200, 401)
    assert anonymous.get("/").status_code == 302


def test_password_rotation_invalidates_existing_sessions(app, client):
    app.config["ADMIN_PASSWORD_HASH"] = generate_password_hash("rotated-test-password")
    assert client.get("/").status_code == 302


def test_router_command_delivery_requires_token_and_remains_locked(app):
    machine = app.test_client()
    assert machine.get("/router-config/R1").status_code == 503
    app.config["ROUTER_CONFIG_TOKEN"] = "test-only-router-token-32-characters-long"
    assert machine.get("/router-config/R1").status_code == 401
    response = machine.get("/router-config/R1", headers={
        "Authorization": "Bearer " + app.config["ROUTER_CONFIG_TOKEN"],
    })
    assert response.status_code == 423
    assert response.mimetype == "application/json"
    assert "configuration" not in response.get_json()


def test_local_admin_setup_preserves_environment_and_never_writes_plain_password(tmp_path):
    from dotenv import dotenv_values
    from werkzeug.security import check_password_hash
    from manage import configure_admin

    env_file = tmp_path / ".env"
    existing_key = "test-only-existing-secret-key-with-sufficient-length"
    env_file.write_text(
        "# Company local configuration\n"
        "ROUTER_R1_USERNAME='restricted-user'\n"
        "SDR_COMPANY_NAME='Example Company'\n"
        f"SDR_SECRET_KEY='{existing_key}'\n",
        encoding="utf-8",
    )
    password = "test-only-administrator-setup-password"
    configure_admin(env_file, "companyadmin", password)
    values = dotenv_values(env_file, interpolate=False)
    assert values["SDR_ADMIN_USERNAME"] == "companyadmin"
    assert check_password_hash(values["SDR_ADMIN_PASSWORD_HASH"], password)
    assert password not in env_file.read_text(encoding="utf-8")
    assert values["ROUTER_R1_USERNAME"] == "restricted-user"
    assert values["SDR_COMPANY_NAME"] == "Example Company"
    assert values["SDR_SECRET_KEY"] == existing_key
    assert "# Company local configuration" in env_file.read_text(encoding="utf-8")
    import os
    if os.name != "nt":
        assert env_file.stat().st_mode & 0o777 == 0o600


def test_router_inventory_forms_persist_real_settings_without_contacting_device(app, client, monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Form action contacted a device"))
    form = {
        "csrf_token": "test-only-csrf-token", "router_id": "R1", "name": "Company router",
        "ip_address": "10.20.0.1", "model": "CCR2116", "routeros_version": "7.21.4",
        "api_port": "8728", "ssh_port": "53722", "credential_ref": "ROUTER_R1",
    }
    storage = app.extensions["json_storage"]
    RouterService(storage, app.config).add_router(form)
    router = next(item for item in storage.read_json("routers.json") if item["router_id"] == "R1")
    assert router["connection_status"] == "untested"
    status = client.get("/api/system/status").get_json()
    assert status["router_count"] == 7
    assert status["readiness"] == "verification_required"
    form["name"] = "Updated company router"
    assert client.post("/routers/R1/edit", data=form).status_code == 302
    router = next(item for item in storage.read_json("routers.json") if item["router_id"] == "R1")
    assert router["name"] == "Updated company router"
    assert client.post("/routers/R1/delete", data={"csrf_token": form["csrf_token"]}).status_code == 302
    assert {router["router_id"] for router in storage.read_json("routers.json")} == SEEDED_ROUTER_IDS
    assert any(event["category"] == "routers" for event in storage.list_activity())


def test_router_inventory_api_uses_a_public_serializer(app, client):
    app.extensions["json_storage"].write_json("routers.json", [{
        "router_id": "R1", "name": "Company router", "ip_address": "10.20.0.1",
        "connection_status": "untested", "password": "test-only-legacy-password",
        "snmp_secret": "test-only-legacy-snmp-secret",
        "legacy_details": {"token": "test-only-nested-token"},
    }])
    response = client.get("/api/routers")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    payload = response.get_json()
    assert payload["routers"][0]["router_id"] == "R1"
    text = response.get_data(as_text=True)
    for secret in ("test-only-legacy-password", "test-only-legacy-snmp-secret", "test-only-nested-token"):
        assert secret not in text


def test_settings_survive_restart_and_startup_activity_is_not_duplicated(storage_dirs):
    first_app = configured_app(storage_dirs)
    store = StorageService(storage_dirs["DATA_DIR"], storage_dirs["OUTPUT_DIR"])
    settings = store.read_json("automation_settings.json")
    settings.update(monitoring_interval_seconds=90, averaging_window=7)
    store.write_json("automation_settings.json", settings)

    restarted = configured_app(storage_dirs)
    client = signed_in_client(restarted)
    status = client.get("/api/system/status").get_json()
    assert status["monitoring_interval_seconds"] == 90
    assert status["averaging_window"] == 7
    settings_html = client.get("/settings").get_data(as_text=True)
    assert "90 seconds" in settings_html
    assert "7 valid readings" in settings_html

    assert first_app.config["DATA_DIR"] == restarted.config["DATA_DIR"]
    events = store.list_activity()
    startup_events = [
        event
        for event in events
        if event["message"] == "System started."
    ]
    assert len(startup_events) == 1


def test_existing_simulation_settings_stay_in_simulation_without_losing_history(storage_dirs):
    storage = StorageService(storage_dirs["DATA_DIR"], storage_dirs["OUTPUT_DIR"])
    storage.initialize()
    legacy_settings = {
        **storage.read_json("automation_settings.json"),
        "mode": "simulation", "monitoring_interval_seconds": 90, "averaging_window": 7,
    }
    settings_path = Path(storage_dirs["DATA_DIR"]) / "automation_settings.json"
    settings_path.write_text(json.dumps(legacy_settings), encoding="utf-8")
    storage.append_activity("test", "Existing company history must survive restart.")
    storage.write_json("routers.json", [{"router_id": "LEGACY-R1", "name": "Existing company router"}])

    configured_app(storage_dirs)
    configured_app(storage_dirs)

    settings = storage.read_json("automation_settings.json")
    assert settings["mode"] == "simulation"
    assert settings["automation"] == "off"
    assert settings["routing_changes_enabled"] is False
    assert settings["monitoring_interval_seconds"] == 90
    assert settings["averaging_window"] == 7
    assert json.loads(settings_path.read_text())["mode"] == "simulation"
    assert storage.read_json("routers.json")[0]["router_id"] == "LEGACY-R1"
    events = storage.list_activity()
    assert any(event["message"] == "Existing company history must survive restart." for event in events)
    assert not any(event["message"] == "Routing changes disabled." for event in events)


def test_router_config_endpoint_does_not_deliver_unapproved_live_command(client, storage):
    command = {
        "schema_version": 1,
        "command_id": "cmd-phase-1-check",
        "router_id": "R1",
        "timestamp": "2026-11-18T12:00:00Z",
        "mode": "live",
        "action": "update_routing_configuration",
        "configuration": {"routing_cost": 5},
        "optimization_ref": "opt-1",
    }
    storage.write_router_config(command)

    response = client.get("/router-config/R1")
    assert response.status_code in (401, 423, 503)
    assert response.mimetype == "application/json"
    assert response.get_json() != command
    assert "configuration" not in response.get_json()
    missing = client.get("/router-config/UNKNOWN")
    assert missing.status_code in (401, 404, 423, 503)
    assert missing.mimetype == "application/json"
    assert "html" not in missing.get_data(as_text=True).lower()


def test_traffic_measurements_are_appended_to_date_segments(storage, storage_dirs):
    records = [
        {
            "router_id": "R1",
            "interface": "wan1",
            "timestamp": "2026-11-18T12:00:00Z",
            "tx_mbps": 12.5,
            "tx_octets": 10_000,
        },
        {
            "router_id": "R1",
            "interface": "wan1",
            "timestamp": "2026-11-18T12:01:00Z",
            "tx_mbps": 13.5,
            "tx_octets": 20_000,
        },
    ]
    storage.append_traffic(records[0])
    manifest = storage.read_json("traffic_history.json")
    assert manifest["storage"] == "segmented_jsonl"
    assert len(manifest["segments"]) == 1
    manifest_path = Path(storage_dirs["DATA_DIR"]) / "traffic_history.json"
    manifest_bytes = manifest_path.read_bytes()
    segment_file = manifest["segments"][0]["file"]
    segment_path = Path(storage_dirs["DATA_DIR"]) / segment_file
    first_append = segment_path.read_bytes()

    storage.append_traffic(records[1])
    assert segment_path.read_bytes().startswith(first_append)
    assert manifest_path.read_bytes() == manifest_bytes
    lines = [json.loads(line) for line in segment_path.read_text(encoding="utf-8").splitlines()]
    assert lines == records
    assert storage.list_traffic(limit=10) == records


def test_storage_rejects_path_traversal_and_invalid_traffic(storage, storage_dirs):
    before = Path(storage_dirs["DATA_DIR"], "routers.json").read_bytes()
    with pytest.raises((KeyError, ValueError)):
        storage.read_json("../outside.json")

    with pytest.raises((TypeError, ValueError)):
        storage.append_traffic(
            {
                "router_id": "R1",
                "interface": "wan1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tx_mbps": -1,
            }
        )
    assert Path(storage_dirs["DATA_DIR"], "routers.json").read_bytes() == before


def test_corrupt_storage_is_reported_without_resetting_it(client, storage_dirs):
    path = Path(storage_dirs["DATA_DIR"]) / "automation_settings.json"
    broken = '{"schema_version":1,"monitoring_interval_seconds":'
    path.write_text(broken, encoding="utf-8")

    response = client.get("/api/system/status")
    assert response.status_code == 503
    assert response.mimetype == "application/json"
    assert response.get_json()["storage"] == "unavailable"
    assert path.read_text(encoding="utf-8") == broken


def test_atomic_update_keeps_previous_valid_document_as_backup(storage, storage_dirs):
    path = Path(storage_dirs["DATA_DIR"]) / "automation_settings.json"
    original = path.read_bytes()
    updated = storage.update_json(
        "automation_settings.json",
        lambda current: {**current, "monitoring_interval_seconds": 120},
    )

    assert updated["monitoring_interval_seconds"] == 120
    assert storage.read_json("automation_settings.json") == updated
    assert path.with_suffix(".json.bak").read_bytes() == original
    current = path.read_bytes()

    with pytest.raises(ValueError):
        storage.update_json(
            "automation_settings.json",
            lambda settings: {**settings, "monitoring_interval_seconds": -1},
        )

    assert path.read_bytes() == current
    assert path.with_suffix(".json.bak").read_bytes() == original


def test_concurrent_activity_updates_do_not_lose_events(storage, storage_dirs):
    def append_event(index):
        writer = StorageService(storage_dirs["DATA_DIR"], storage_dirs["OUTPUT_DIR"])
        writer.append_activity("test", f"Concurrent event {index}")

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(append_event, range(20)))
    messages = [
        event["message"]
        for event in storage.list_activity()
        if event["category"] == "test"
    ]
    assert sorted(messages) == sorted(f"Concurrent event {index}" for index in range(20))


def test_failed_atomic_replacement_preserves_current_file(
    storage, storage_dirs, monkeypatch
):
    path = Path(storage_dirs["DATA_DIR"]) / "automation_settings.json"
    original = path.read_bytes()
    from services import json_storage

    real_replace = json_storage.os.replace

    def fail_main_replacement(source, destination):
        if Path(destination) == path:
            raise OSError("Simulated disk write failure")
        return real_replace(source, destination)

    monkeypatch.setattr(json_storage.os, "replace", fail_main_replacement)
    settings = storage.read_json("automation_settings.json")
    settings["monitoring_interval_seconds"] = 120
    with pytest.raises(StorageError):
        storage.write_json("automation_settings.json", settings)

    assert path.read_bytes() == original
    assert json.loads(original)["monitoring_interval_seconds"] == 60
    assert not list(path.parent.glob("*.tmp"))

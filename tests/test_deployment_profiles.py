"""Profile isolation is checked before any inventory or credential I/O."""
from pathlib import Path
import os

import pytest
from werkzeug.security import generate_password_hash

from config import load_config
from services.deployment_service import validate_deployment
from services.api_credentials_service import api_credentials


@pytest.fixture
def production(tmp_path):
    root = tmp_path / "production"
    root.mkdir(mode=0o700)
    return {"ENVIRONMENT": "production", "PROFILE_DIR": root,
        "CONFIG_ENV_FILE": root / ".env", "API_CREDENTIALS_ENV_FILE": root / "api.env",
        "CONTROLLER_CREDENTIALS_ENV_FILE": root / "controller.env",
        "DATA_DIR": root / "data", "OUTPUT_DIR": root / "output",
        "AUTH_ENABLED": True, "ADMIN_USERNAME": "operator",
        "ADMIN_PASSWORD_HASH": generate_password_hash("synthetic-only-test-passphrase"),
        "SECRET_KEY": "synthetic-session-key-for-isolated-tests",
        "SESSION_COOKIE_SECURE": True, "ALLOW_PLAINTEXT_API": False,
        "ROUTER_CA_FILE": None, "CONTROLLER_CA_FILE": None,
        "PRIVATE_BUNDLE_DIR": root / "private" / "router-bundles",
        "SIMULATION_MODE": True, "LIVE_ROUTING_ENABLED": False,
        "ADMIN_BASE_URL": "https://admin.example.test", "CONTROLLER_BASE_URL": "https://devices.example.test",
        "ROUTER_NETWORKS_EXPLICIT": True, "ROUTER_ALLOWED_NETWORKS": ["10.44.0.0/24"],
        "ADMIN_HOST": "127.0.0.1", "CONTROLLER_HOST": "127.0.0.1"}


def test_profile_loader_does_not_import_lab_environment_or_mutate_process(monkeypatch, tmp_path):
    root = tmp_path / "profile"
    root.mkdir(mode=0o700)
    env = root / ".env"
    env.write_text("SDR_COMPANY_NAME=Isolated network\nSDR_API_TIMEOUT_SECONDS=12\n")
    monkeypatch.setenv("SDR_ENV", "laboratory")
    monkeypatch.setenv("SDR_PROFILE_DIR", str(root))
    monkeypatch.delenv("SDR_ENV_FILE", raising=False)
    monkeypatch.delenv("SDR_COMPANY_NAME", raising=False)
    before = dict(os.environ)
    config = load_config()
    assert config["DATA_DIR"] == root / "data"
    assert config["API_CREDENTIALS_ENV_FILE"] == env
    assert config["COMPANY_NAME"] == "Isolated network"
    assert config["API_TIMEOUT_SECONDS"] == 12
    assert dict(os.environ) == before


def test_profile_cannot_switch_environment_or_reuse_unmarked_data(production):
    data = production["DATA_DIR"]
    data.mkdir()
    (data / "routers.json").write_text('[{"router_id":"LAB"}]')
    with pytest.raises(ValueError, match="unmarked"):
        validate_deployment(production)
    assert (data / "routers.json").read_text() == '[{"router_id":"LAB"}]'
    (data / "routers.json").unlink()
    validate_deployment(production)
    with pytest.raises(ValueError, match="another environment"):
        validate_deployment({**production, "ENVIRONMENT": "laboratory"})


@pytest.mark.parametrize("key,value", [("AUTH_ENABLED", False), ("SESSION_COOKIE_SECURE", False),
    ("ALLOW_PLAINTEXT_API", True), ("SIMULATION_MODE", False), ("LIVE_ROUTING_ENABLED", True),
    ("ADMIN_BASE_URL", "http://admin.example.test"), ("CONTROLLER_BASE_URL", "https://user:pass@example.test"),
    ("ROUTER_NETWORKS_EXPLICIT", False), ("ROUTER_ALLOWED_NETWORKS", ["0.0.0.0/0"]),
    ("ADMIN_HOST", "0.0.0.0"), ("SECRET_KEY", "short")])
def test_production_rejects_insecure_startup_before_storage(production, key, value):
    with pytest.raises(ValueError):
        validate_deployment({**production, key: value})
    assert not production["DATA_DIR"].exists()


def test_production_rejects_external_credentials_and_symlinks(production, tmp_path):
    with pytest.raises(ValueError, match="inside"):
        validate_deployment({**production, "API_CREDENTIALS_ENV_FILE": tmp_path / "lab.env"})
    production["DATA_DIR"].symlink_to(tmp_path / "old-lab")
    with pytest.raises(ValueError, match="symbolic"):
        validate_deployment(production)


def test_isolated_credentials_ignore_ambient_lab_values(production, monkeypatch):
    path = production["API_CREDENTIALS_ENV_FILE"]
    path.write_text("SHARED_USERNAME=production-reader\nSHARED_PASSWORD=synthetic-profile-only\n")
    path.chmod(0o600)
    monkeypatch.setenv("SHARED_USERNAME", "lab-account")
    monkeypatch.setenv("SHARED_PASSWORD", "synthetic-lab-only")
    assert api_credentials({"credential_ref": "SHARED"}, production) == ("production-reader", "synthetic-profile-only")


def test_production_requires_https_even_for_loopback(production):
    from app import create_app
    from device_app import create_device_app
    browser = create_app({**production, "TESTING": True})
    devices = create_device_app({**production, "TESTING": True})
    assert browser.test_client().get("/").status_code == 403
    assert browser.test_client().get("/", base_url=production["ADMIN_BASE_URL"]).status_code == 302
    assert devices.test_client().post("/api/controller/v2/poll", json={}).status_code == 403

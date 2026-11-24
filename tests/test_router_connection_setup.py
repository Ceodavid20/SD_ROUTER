"""Router onboarding shows the device endpoint instead of a registration form."""

from copy import deepcopy
from html.parser import HTMLParser

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from services.controller_connection_service import connection_details

POLL_PATH = "/api/controller/v2/poll"
SETUP_PATH = "/routers/connect"

class PageElements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.inputs = []
        self._link = None

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == "a":
            self._link = {"href": attributes.get("href"), "text": ""}
        elif tag == "form":
            self.forms.append(attributes)
        elif tag == "input":
            self.inputs.append(attributes)

    def handle_data(self, text):
        if self._link is not None:
            self._link["text"] += text

    def handle_endtag(self, tag):
        if tag == "a" and self._link is not None:
            self._link["text"] = " ".join(self._link["text"].split())
            self.links.append(self._link)
            self._link = None


@pytest.fixture
def config(tmp_path):
    return {
        "TESTING": True,
        "AUTH_ENABLED": False,
        "CONTROLLER_HOST": "127.0.0.1",
        "CONTROLLER_PORT": 8001,
        "CONTROLLER_BASE_URL": "",
        "ROUTER_POLL_INTERVAL": 60,
        "DATA_DIR": tmp_path / "data",
        "OUTPUT_DIR": tmp_path / "output",
    }


@pytest.fixture
def app(config):
    return create_app(config)


def elements(response):
    parser = PageElements()
    parser.feed(response.get_data(as_text=True))
    return parser


@pytest.mark.parametrize("path", ["/", "/routers"])
def test_add_router_link_opens_connection_setup_instead_of_a_form(app, path):
    response = app.test_client().get(path)
    assert response.status_code == 200
    links = [link for link in elements(response).links if link["text"] == "Add router"]
    assert links
    assert all(link["href"] == SETUP_PATH for link in links)


def test_router_page_supports_explicit_registration_and_retains_existing_router_actions(app):
    app.extensions["json_storage"].write_json("routers.json", [{"router_id": "EXISTING-R1", "name": "Existing router"}])
    response = app.test_client().get("/routers")
    page = elements(response)
    assert any(form.get("action") == "/routers/add" for form in page.forms)
    assert any(field.get("name") == "router_id" for field in page.inputs)
    actions = {form.get("action") for form in page.forms}
    assert "/routers/EXISTING-R1/edit" in actions
    assert "/routers/EXISTING-R1/delete" in actions
    assert "/routers/EXISTING-R1/test-api" in actions


@pytest.mark.parametrize("with_csrf", [False, True])
def test_explicit_registration_requires_csrf_and_keeps_monitoring_off(app, with_csrf):
    client = app.test_client()
    client.get("/routers")
    storage = app.extensions["json_storage"]
    before = deepcopy(storage.read_json("routers.json"))
    form = {"router_id": "REGISTERED-PHYSICAL", "name": "New physical router", "deployment_kind": "physical"}
    if with_csrf:
        client.get("/settings")
        with client.session_transaction() as session:
            form["csrf_token"] = session["csrf_token"]

    response = client.post("/routers/add", data=form)

    assert response.status_code == (302 if with_csrf else 400)
    after = storage.read_json("routers.json")
    if with_csrf:
        assert after[:-1] == before
        assert after[-1]["monitoring_enabled"] is False
        assert after[-1]["controller_auth_enabled"] is False
        assert after[-1]["deployment_kind"] == "physical"
    else:
        assert after == before


def test_connection_page_is_read_only_and_does_not_claim_router_reachability(app):
    storage = app.extensions["json_storage"]
    protected = ("routers.json", "routing_paths.json", "router_communication.json", "router_communication_v2.json", "router_config.json")
    before = {name: deepcopy(storage.read_json(name)) for name in protected}

    response = app.test_client().get(SETUP_PATH)
    page = response.get_data(as_text=True)
    parsed = elements(response)

    assert response.status_code == 200
    assert "Router connection" in page
    assert "http://127.0.0.1:8001" + POLL_PATH in page
    assert "POST" in page and "HMAC-SHA512" in page
    assert "/api/controller/v2/ack" in page
    assert "HMAC-SHA256" not in page
    assert "Local test endpoint" in page
    assert "loopback" in page.lower() or "this computer" in page.lower()
    assert not parsed.forms
    assert all(storage.read_json(name) == value for name, value in before.items())


def test_connection_url_ignores_browser_host_and_never_copies_secret_config(app):
    app.config.update({
        "ROUTER_CONFIG_TOKEN": "test-only-never-display-this-token",
        "SECRET_KEY": "test-only-never-display-this-session-key",
    })
    response = app.test_client().get(SETUP_PATH, base_url="http://browser-host.invalid:8765")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "http://127.0.0.1:8001" + POLL_PATH in text
    assert "http://browser-host.invalid:8765" + POLL_PATH not in text
    assert app.config["ROUTER_CONFIG_TOKEN"] not in text
    assert app.config["SECRET_KEY"] not in text


def test_configured_endpoint_comes_only_from_validated_controller_origin(app):
    app.config["CONTROLLER_BASE_URL"] = "https://controller.company.test:9443/"
    response = app.test_client().get(SETUP_PATH)
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "https://controller.company.test:9443" + POLL_PATH in page
    assert "Configured endpoint" in page


def test_connection_setup_page_obeys_existing_browser_authentication(config):
    app = create_app({
        **config, "AUTH_ENABLED": True,
        "SECRET_KEY": "test-only-session-key-with-sufficient-length",
        "ADMIN_USERNAME": "test-admin",
        "ADMIN_PASSWORD_HASH": generate_password_hash("test-only-admin-password"),
    })
    response = app.test_client().get(SETUP_PATH)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_local_endpoint_uses_device_listener_configuration_without_mutation():
    config = {
        "CONTROLLER_BASE_URL": "", "CONTROLLER_HOST": "127.0.0.1",
        "CONTROLLER_PORT": 9001, "ROUTER_POLL_INTERVAL": 90,
    }
    before = deepcopy(config)
    details = connection_details(config)
    assert details["endpoint_url"] == "http://127.0.0.1:9001" + POLL_PATH
    assert details["scope"] == "local"
    assert details["method"] == "POST"
    assert details["poll_path"] == POLL_PATH
    assert details["ack_path"] == "/api/controller/v2/ack"
    assert details["ack_endpoint_url"] == "http://127.0.0.1:9001/api/controller/v2/ack"
    assert details["protocol_version"] == "2.0"
    assert details["poll_interval"] == 90
    assert config == before


def test_ipv6_loopback_endpoint_is_bracketed():
    details = connection_details({
        "CONTROLLER_BASE_URL": "", "CONTROLLER_HOST": "::1",
        "CONTROLLER_PORT": 8001, "ROUTER_POLL_INTERVAL": 60,
    })
    assert details["endpoint_url"] == "http://[::1]:8001" + POLL_PATH
    assert details["scope"] == "local"


@pytest.mark.parametrize("url", [
    "javascript:alert(1)",
    "https://controller.company.test:invalid",
    "https://controller.company.test:65536",
    "https://controller.company.test?secret=test-only-not-for-html",
    "https://controller.company.test#test-only-not-for-html",
    "https://test-only-not-for-html:password@controller.company.test",
    "https://controller.company.test/prefix",
    "https:///missing-host",
    "https://bad host.invalid",
    "https://0.0.0.0",
    "https://[::]",
    "http://controller.company.test:8001",
])
def test_invalid_configured_origin_never_becomes_a_router_link(url):
    details = connection_details({
        "CONTROLLER_BASE_URL": url, "CONTROLLER_HOST": "127.0.0.1",
        "CONTROLLER_PORT": 8001, "ROUTER_POLL_INTERVAL": 60,
    })
    assert details["endpoint_url"] is None
    assert details["scope"] == "not_configured"
    assert details["configuration_error"]
    assert "test-only-not-for-html" not in str(details)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.15"])
def test_nonloopback_bind_address_is_not_advertised_as_a_verified_device_endpoint(host):
    details = connection_details({
        "CONTROLLER_BASE_URL": "", "CONTROLLER_HOST": host,
        "CONTROLLER_PORT": 8001, "ROUTER_POLL_INTERVAL": 60,
    })
    assert details["endpoint_url"] is None
    assert details["scope"] == "not_configured"

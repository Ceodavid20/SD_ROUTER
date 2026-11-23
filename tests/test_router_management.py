"""Real-device setup is tested without contacting a company router."""

import json
import ssl
from types import SimpleNamespace

import pytest

from services.json_storage import StorageService
from services.router_service import RouterService, RouterValidationError
from services.routeros_api import RouterAPIError, RouterOSReadOnlyClient, encode_length


@pytest.fixture
def inventory(tmp_path):
    storage = StorageService(tmp_path / "data", tmp_path / "output")
    storage.initialize()
    # Keep router-unit tests independent from the four company starter records.
    storage.write_json("routers.json", [])
    config = {
        "ROUTER_ALLOWED_NETWORKS": ["10.0.0.0/8"],
        "ALLOW_PLAINTEXT_API": False,
        "API_TIMEOUT_SECONDS": 3,
        "ROUTER_CA_FILE": None,
    }
    return RouterService(storage, config)


@pytest.fixture
def router_form():
    return {
        "router_id": "R1", "name": "Company egress",
        "ip_address": "10.20.0.1", "model": "CCR2116",
        "routeros_version": "7.21.4", "interface_name": "wan-uplink",
        "capacity_mbps": "100", "cost_per_gb": "2.5", "currency": "NGN",
        "api_port": "8728", "ssh_port": "53722", "credential_ref": "ROUTER_R1",
    }


def test_registration_stores_only_inventory_and_does_not_connect(inventory, router_form, monkeypatch):
    def unexpected_connection(*args, **kwargs):
        pytest.fail("Inventory registration must not open a network connection")

    monkeypatch.setattr("socket.create_connection", unexpected_connection)
    router_form.update(username="test-only-user", password="test-only-private-value")
    record = inventory.add_router(router_form)
    assert record["connection_status"] == "untested"
    assert record["monitoring_enabled"] is False
    assert record["api_port"] == 8728
    assert record["ssh_port"] == 53722
    assert record["credential_ref"] == "ROUTER_R1"
    stored = json.dumps(inventory.list_routers())
    assert "test-only-private-value" not in stored
    assert "test-only-user" not in stored
    with pytest.raises(RouterValidationError):
        inventory.add_router(router_form)


@pytest.mark.parametrize("address", ["not-an-ip", "127.0.0.1", "0.0.0.0", "224.0.0.1"])
def test_invalid_management_addresses_are_rejected(inventory, router_form, address):
    router_form["ip_address"] = address
    with pytest.raises(RouterValidationError):
        inventory.add_router(router_form)
    assert inventory.list_routers() == []


@pytest.mark.parametrize(("field", "value"), [
    ("api_port", "65536"), ("ssh_port", "0"), ("capacity_mbps", "-1"),
    ("cost_per_gb", "nan"), ("credential_ref", "../../secret"),
])
def test_invalid_router_parameters_cannot_reach_storage(inventory, router_form, field, value):
    router_form[field] = value
    with pytest.raises(RouterValidationError):
        inventory.add_router(router_form)
    assert inventory.list_routers() == []


def test_plaintext_api_is_blocked_before_any_connection(inventory, router_form, monkeypatch):
    inventory.add_router(router_form)
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Blocked request reached a socket"))
    result = inventory.test_api("R1")
    assert result["connection_status"] == "blocked"
    assert result["last_checked_at"]
    assert "Unencrypted" in result["last_error"]


def test_unapproved_destination_and_missing_credentials_are_blocked(inventory, router_form, monkeypatch):
    router_form.update(api_tls="on", ip_address="198.51.100.8")
    inventory.add_router(router_form)
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Blocked request reached a socket"))
    assert inventory.test_api("R1")["connection_status"] == "blocked"
    router_form["ip_address"] = "10.20.0.1"
    inventory.edit_router("R1", router_form)
    monkeypatch.delenv("ROUTER_R1_USERNAME", raising=False)
    monkeypatch.delenv("ROUTER_R1_PASSWORD", raising=False)
    assert inventory.test_api("R1")["connection_status"] == "blocked"


def test_only_successful_resource_response_marks_router_connected(inventory, router_form, monkeypatch):
    from services import router_service

    router_form["api_tls"] = "on"
    inventory.add_router(router_form)
    monkeypatch.setenv("ROUTER_R1_USERNAME", "restricted-test-user")
    monkeypatch.setenv("ROUTER_R1_PASSWORD", "test-only-credential")
    monkeypatch.setattr(router_service, "RouterOSReadOnlyClient", lambda *a, **k: SimpleNamespace(
        read_resource=lambda: {"version": "7.21.4", "board-name": "CCR2116"},
    ))
    result = inventory.test_api("R1")
    assert result["connection_status"] == "connected"
    assert result["detected_routeros_version"] == "7.21.4"
    assert "test-only-credential" not in json.dumps(inventory.list_routers())
    assert "test-only-credential" not in json.dumps(inventory.storage.list_activity())
    updated = inventory.edit_router("R1", router_form)
    assert updated["connection_status"] == "untested"
    assert updated["last_checked_at"] is None


def test_connection_failure_is_recorded_without_reporting_connected(inventory, router_form, monkeypatch):
    from services import router_service

    router_form["api_tls"] = "on"
    inventory.add_router(router_form)
    monkeypatch.setenv("ROUTER_R1_USERNAME", "restricted-test-user")
    monkeypatch.setenv("ROUTER_R1_PASSWORD", "test-only-credential")

    def failed_read():
        raise RouterAPIError("Router API request timed out.")

    monkeypatch.setattr(router_service, "RouterOSReadOnlyClient", lambda *a, **k: SimpleNamespace(read_resource=failed_read))
    result = inventory.test_api("R1")
    assert result["connection_status"] == "disconnected"
    assert "timed out" in result["last_error"]


@pytest.mark.parametrize(("length", "encoded"), [
    (0, "00"), (127, "7f"), (128, "8080"), (16383, "bfff"),
    (16384, "c04000"), (2097151, "dfffff"), (2097152, "e0200000"),
    (268435455, "efffffff"), (268435456, "f010000000"),
])
def test_routeros_length_framing_boundaries(length, encoded):
    assert encode_length(length) == bytes.fromhex(encoded)


class FakeSocket:
    def __init__(self, response):
        self.response = bytearray(response)
        self.sent = bytearray()
        self.closed = False

    def recv(self, size):
        # Deliberately fragment replies to exercise short TCP reads.
        count = min(size, 3, len(self.response))
        value = bytes(self.response[:count])
        del self.response[:count]
        return value

    def sendall(self, value):
        self.sent.extend(value)

    def settimeout(self, value):
        assert value > 0

    def close(self):
        self.closed = True


def sentence(*words):
    result = bytearray()
    for word in words:
        encoded = word.encode()
        result.extend(encode_length(len(encoded)))
        result.extend(encoded)
    return bytes(result) + b"\x00"


def test_native_api_login_and_read_use_only_allowed_commands(monkeypatch):
    reply = sentence("!done") + sentence("!re", "=version=7.21.4", "=board-name=CCR2116") + sentence("!done")
    connection = FakeSocket(reply)
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: connection)
    client = RouterOSReadOnlyClient("10.20.0.1", 8728, "test-user", "test-password", tls=False)
    assert client.read_resource() == {"version": "7.21.4", "board-name": "CCR2116"}
    assert connection.closed
    assert b"/system/resource/print" in connection.sent
    assert b"/login" in connection.sent
    with pytest.raises(RouterAPIError):
        client._talk(["/ip/route/set", "=distance=1"])


def test_refused_tcp_connection_has_specific_error_and_sends_no_login(monkeypatch):
    from services.routeros_api import RouterAPIError

    attempted = []

    def refused(address, *, timeout):
        attempted.append((address, timeout))
        raise ConnectionRefusedError("test-only refusal")

    monkeypatch.setattr("socket.create_connection", refused)
    client = RouterOSReadOnlyClient("10.20.0.1", 8728, "test-user", "test-password", tls=False)
    commands = []
    monkeypatch.setattr(client, "_talk", lambda words: commands.append(words))

    with pytest.raises(RouterAPIError, match="Router API connection refused on TCP port 8728\\."):
        client.read_resource()

    assert attempted and attempted[0][0] == ("10.20.0.1", 8728)
    assert commands == []


@pytest.mark.parametrize("error", [
    ssl.SSLError("test-only-private TLS details"),
    ConnectionResetError("test-only-private TLS details"),
    ConnectionAbortedError("test-only-private TLS details"),
])
def test_tls_handshake_failure_identifies_service_without_sending_credentials(monkeypatch, error):
    connection = FakeSocket(b"")
    attempts = []
    def connect(address, **kwargs):
        attempts.append(address)
        return connection
    def wrap(sock, *, server_hostname):
        assert sock is connection and server_hostname == "10.20.0.1"
        raise error
    monkeypatch.setattr("socket.create_connection", connect)
    monkeypatch.setattr("ssl.create_default_context", lambda **kwargs: SimpleNamespace(wrap_socket=wrap))
    client = RouterOSReadOnlyClient("10.20.0.1", 8728, "test-user", "test-password", tls=True)
    with pytest.raises(RouterAPIError, match="API-SSL handshake failed on TCP port 8728") as caught:
        client.read_resource()
    assert "api-ssl" in str(caught.value) and "certificate" in str(caught.value)
    assert "test-only-private" not in str(caught.value)
    assert connection.closed and connection.sent == b"" and client._socket is None
    assert attempts == [("10.20.0.1", 8728)]  # No plaintext retry.


def test_untrusted_certificate_is_reported_separately_and_sends_no_login(monkeypatch):
    connection = FakeSocket(b"")
    contexts = []
    def context(*, cafile):
        contexts.append(cafile)
        def wrap(sock, *, server_hostname):
            raise ssl.SSLCertVerificationError("test-only-private certificate details")
        return SimpleNamespace(wrap_socket=wrap)
    monkeypatch.setattr("socket.create_connection", lambda *args, **kwargs: connection)
    monkeypatch.setattr("ssl.create_default_context", context)
    client = RouterOSReadOnlyClient("10.20.0.1", 8729, "test-user", "test-password", ca_file="test-ca.pem")
    with pytest.raises(RouterAPIError, match="certificate verification failed") as caught:
        client.read_resource()
    assert contexts == ["test-ca.pem"]
    assert "management address" in str(caught.value) and "test-only-private" not in str(caught.value)
    assert connection.closed and connection.sent == b""


def test_missing_ca_file_identifies_controller_configuration_without_sending_login(monkeypatch):
    connection = FakeSocket(b"")
    def context(**kwargs):
        raise FileNotFoundError("test-only-private CA path")
    monkeypatch.setattr("socket.create_connection", lambda *args, **kwargs: connection)
    monkeypatch.setattr("ssl.create_default_context", context)
    client = RouterOSReadOnlyClient("10.20.0.1", 8729, "test-user", "test-password", ca_file="missing-test-ca.pem")
    with pytest.raises(RouterAPIError, match="SDR_ROUTER_CA_FILE") as caught:
        client.read_resource()
    assert "test-only-private" not in str(caught.value)
    assert connection.closed and connection.sent == b""


def test_device_error_does_not_echo_sensitive_device_text(monkeypatch):
    connection = FakeSocket(sentence("!trap", "=message=test-only-sensitive-device-text"))
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: connection)
    client = RouterOSReadOnlyClient("10.20.0.1", 8728, "test-user", "test-password", tls=False)
    with pytest.raises(RouterAPIError) as error:
        client.read_resource()
    assert "test-only-sensitive-device-text" not in str(error.value)
    assert connection.closed


def test_oversized_api_word_is_rejected_before_allocation(monkeypatch):
    connection = FakeSocket(encode_length(70000))
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: connection)
    client = RouterOSReadOnlyClient("10.20.0.1", 8728, "test-user", "test-password", tls=False)
    with pytest.raises(RouterAPIError, match="permitted size"):
        client.read_resource()
    assert connection.closed

def test_router_edit_preserves_monitoring_state(inventory, router_form):
    inventory.add_router(router_form)

    inventory.storage.update_json(
        "routers.json",
        lambda routers: [
            {**router, "monitoring_enabled": True}
            if router["router_id"] == "R1" else router
            for router in routers
        ],
    )

    updated = inventory.edit_router("R1", router_form)

    assert updated["monitoring_enabled"] is True

    stored = inventory.storage.read_json("routers.json")
    assert stored[0]["monitoring_enabled"] is True

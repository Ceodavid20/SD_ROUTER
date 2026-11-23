"""Prepare disabled client files with synthetic credentials; no router execution."""

import json
from pathlib import Path
import re

import pytest

from services.json_storage import StorageService
from services.traffic_setup_service import prepare_traffic_client, render_traffic_script


SECRET = "a" * 64


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Client preparation contacted a router"))


@pytest.fixture
def storage(tmp_path, monkeypatch):
    service = StorageService(tmp_path / "data", tmp_path / "output")
    service.initialize()
    service.write_json("routers.json", [{
        "router_id": "TEST-TX-R1", "controller_auth_ref": "TEST_TRAFFIC_SETUP",
        "controller_auth_enabled": True, "controller_auth_key_ids": ["PRIMARY"],
        "interface_name": "test-uplink", "monitoring_enabled": False,
    }])
    monkeypatch.setenv("TEST_TRAFFIC_SETUP_PRIMARY_SECRET", SECRET)
    return service


def test_prepared_bundle_is_disabled_private_and_leaves_operational_state_unchanged(storage, tmp_path):
    before = {path: path.read_bytes() for path in [*storage.data_dir.glob("*.json"), *storage.output_dir.glob("*.json")]}
    result = prepare_traffic_client(storage, "TEST-TX-R1", "PRIMARY", "https://controller.test", tmp_path / "client")
    assert result["enabled"] is False and SECRET not in json.dumps(result)
    assert {path: path.read_bytes() for path in before} == before
    directory = Path(result["output_dir"])
    script = (directory / "controller-traffic.rsc").read_text()
    assert ":local sdrTrafficEnabled false;" in script
    assert script.index("$sdrTrafficEnabled != true") < script.index("/interface/find")
    assert SECRET in script
    assert SECRET not in (directory / "README.txt").read_text()
    assert not re.search(r"__[A-Z_]+__", script)
    assert directory.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir())


def test_collector_reads_only_one_tx_property_with_verified_https_and_no_writes():
    script = render_traffic_script("TEST-TX-R1", "PRIMARY", SECRET, "https://controller.test", "test-uplink")
    assert '/interface/get $sdrInterfaceId value-name=tx-byte' in script
    assert script.count('/interface/get ') == 1
    assert script.count(':local sdrPath ') == 1
    assert '/interface/find where name=$sdrInterface' in script
    assert "rx" not in script.lower()
    assert "/api/controller/v2/traffic" in script
    assert "/api/controller/v2/poll" not in script and "/api/controller/v2/ack" not in script
    assert "check-certificate=yes" in script and "http-max-redirect-count=0" in script
    assert ":parse" not in script and ":execute" not in script
    assert not re.search(r"/(?:interface|routing|ip/route|system/scheduler)/.*\b(?:set|add|remove|reset-counters)\b", script)


def test_hmac_helper_is_identical_to_existing_poll_client():
    from services.controller_setup_service import render_routeros_script
    poll = render_routeros_script("TEST-TX-R1", "PRIMARY", SECRET, "https://controller.test")
    helper = poll.split("    # SDR_HMAC_BEGIN\n", 1)[1].split("    # SDR_HMAC_END", 1)[0].rstrip()
    traffic = render_traffic_script("TEST-TX-R1", "PRIMARY", SECRET, "https://controller.test", "test-uplink")
    assert helper in traffic


@pytest.mark.parametrize("interface", ['test-"quoted"', "test-$variable", "test-\\slash", "__SHARED_SECRET__"])
def test_interface_is_escaped_once_and_cannot_inject_code_or_expand_placeholders(interface):
    script = render_traffic_script("TEST-TX-R1", "PRIMARY", SECRET, "https://controller.test", interface)
    escaped = interface.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    assert ':local sdrInterface "' + escaped + '";' in script


@pytest.mark.parametrize("changes", [
    {"controller_auth_enabled": False}, {"controller_auth_key_ids": []},
    {"interface_name": ""}, {"interface_name": "bad\ninterface"},
])
def test_invalid_registration_is_rejected_before_creating_files(storage, tmp_path, changes):
    storage.update_json("routers.json", lambda rows: [{**rows[0], **changes}])
    with pytest.raises(ValueError):
        prepare_traffic_client(storage, "TEST-TX-R1", "PRIMARY", "https://controller.test", tmp_path / "client")
    assert not (tmp_path / "client").exists()


def test_missing_key_unknown_router_and_existing_bundle_are_preserved(storage, tmp_path, monkeypatch):
    with pytest.raises(ValueError):
        prepare_traffic_client(storage, "UNKNOWN", "PRIMARY", "https://controller.test", tmp_path / "client")
    monkeypatch.delenv("TEST_TRAFFIC_SETUP_PRIMARY_SECRET")
    with pytest.raises(ValueError):
        prepare_traffic_client(storage, "TEST-TX-R1", "PRIMARY", "https://controller.test", tmp_path / "client")
    monkeypatch.setenv("TEST_TRAFFIC_SETUP_PRIMARY_SECRET", SECRET)
    prepare_traffic_client(storage, "TEST-TX-R1", "PRIMARY", "https://controller.test", tmp_path / "client")
    original = (tmp_path / "client" / "controller-traffic.rsc").read_bytes()
    with pytest.raises(FileExistsError):
        prepare_traffic_client(storage, "TEST-TX-R1", "PRIMARY", "https://controller.test", tmp_path / "client")
    assert (tmp_path / "client" / "controller-traffic.rsc").read_bytes() == original

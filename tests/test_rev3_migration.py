"""Read-only capture, exact replay/history preservation and fail-closed artifacts."""
import hashlib
import json
from pathlib import Path
from datetime import datetime
from uuid import uuid4

import pytest

from services.json_storage import StorageService
from services.rev3_migration import MigrationError, prepare, verify, rehearse_restore


@pytest.fixture(autouse=True)
def no_router_access(monkeypatch):
    def forbidden(*a, **k):
        pytest.fail("Migration accessed a router or router credential")
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("services.api_credentials_service.api_credentials", forbidden)
    monkeypatch.setattr("services.api_credentials_service.controller_secret", forbidden)


@pytest.fixture
def source(tmp_path):
    tmp_path.chmod(0o700)
    config = {"ENVIRONMENT": "development", "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output",
              "SIMULATION_MODE": True, "LIVE_ROUTING_ENABLED": False}
    storage = StorageService(config["DATA_DIR"], config["OUTPUT_DIR"])
    storage.initialize()
    storage.write_json("routers.json", [{"router_id": "TEST-MIGRATION", "name": "Quotes ' \\ and Unicode Ω",
                                         "credential_ref": "TEST_API_REFERENCE"}])
    for name in ("router_communication.json", "router_communication_v2.json", "router_traffic_v2.json"):
        state = storage.read_json(name)
        state["seen_requests"].append({"router_id": "TEST-MIGRATION", "request_id": str(uuid4()),
                                       "expires_at": "2026-11-25T12:00:00Z"})
        storage.write_json(name, state)
    storage.append_traffic({"router_id": "TEST-MIGRATION", "interface": "test-tx", "tx_mbps": 0.25,
                            "timestamp": "2026-11-25T08:00:00Z", "tx_octets": 2**64 - 1})
    (tmp_path / ".env").write_text("SYNTHETIC_PASSWORD=must-not-be-copied\n")
    return config, storage, tmp_path


def fingerprints(config):
    return {str(p): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
            for key in ("DATA_DIR", "OUTPUT_DIR") for p in config[key].rglob("*") if p.is_file()}


def rewrite_manifest(root, change):
    path = root / "manifest.json"
    value = json.loads(path.read_text())
    change(value)
    path.write_text(json.dumps(value))


def test_capture_preserves_all_documents_segments_and_replays(source, monkeypatch):
    config, storage, root = source
    before = fingerprints(config)
    monkeypatch.setattr(StorageService, "initialize", lambda *a: pytest.fail("Migration initialized storage"))
    result = prepare(config, root / "bundle")
    assert fingerprints(config) == before
    assert result["counts"]["documents"] == len(StorageService.DEFAULTS)
    assert result["counts"]["traffic_records"] == 1
    assert result["counts"]["replay_records"] == 3
    assert result["runtime_cutover_authorized"] is False
    assert result["router_execution_authorized"] is False
    for row in result["files"]:
        original = root / row["name"]
        assert original.read_bytes() == (root / "bundle" / row["name"]).read_bytes()
    assert not (root / "bundle/.env").exists()
    assert "must-not-be-copied" not in (root / "bundle/mysql-import.sql").read_text()
    assert all(p.stat().st_mode & 0o077 == 0 for p in (root / "bundle").rglob("*"))
    sql = (root / "bundle/mysql-import.sql").read_text()
    assert "START TRANSACTION;" in sql and sql.endswith("COMMIT;\n")
    assert "Quotes '" not in sql and "Ω" not in sql


def test_isolated_restore_is_byte_identical_and_cannot_overwrite(source):
    config, _, root = source
    manifest = prepare(config, root / "bundle")
    before = fingerprints(config)
    result = rehearse_restore(config, root / "bundle", root / "restored")
    assert result["restored"] is True and result["runtime_cutover_authorized"] is False
    for row in manifest["files"]:
        assert (root / "bundle" / row["name"]).read_bytes() == (root / "restored" / row["name"]).read_bytes()
    assert fingerprints(config) == before
    with pytest.raises(MigrationError):
        rehearse_restore(config, root / "bundle", root / "restored")
    with pytest.raises(MigrationError):
        rehearse_restore(config, root / "bundle", root / "bundle/restored")


@pytest.mark.parametrize("damage", ["file", "sql", "missing", "traversal", "duplicate", "count", "activation", "unknown", "symlink"])
def test_tampered_or_incomplete_bundles_never_verify(source, damage):
    config, _, root = source
    bundle = root / "bundle"
    prepare(config, bundle)
    if damage == "file":
        (bundle / "data/routers.json").write_text('[]\n')
    elif damage == "sql":
        sql = bundle / "mysql-import.sql"
        sql.write_text("DROP DATABASE sdr;\n")
        rewrite_manifest(bundle, lambda m: m["artifacts"][1].update(bytes=sql.stat().st_size, sha256=hashlib.sha256(sql.read_bytes()).hexdigest()))
    elif damage == "missing":
        (bundle / "data/router_communication_v2.json").unlink()
    elif damage == "traversal":
        rewrite_manifest(bundle, lambda m: m["files"][0].update(name="../.env"))
    elif damage == "duplicate":
        rewrite_manifest(bundle, lambda m: m["files"].append(m["files"][0]))
    elif damage == "count":
        rewrite_manifest(bundle, lambda m: m["counts"].update(replay_records=0))
    elif damage == "activation":
        rewrite_manifest(bundle, lambda m: m.update(runtime_cutover_authorized=True))
    elif damage == "unknown":
        (bundle / "extra.json").write_text('{}')
    else:
        (bundle / "data/routers.json").unlink()
        (bundle / "data/routers.json").symlink_to(config["DATA_DIR"] / "routers.json")
    with pytest.raises(MigrationError):
        verify(bundle)


@pytest.mark.parametrize("damage", ["missing_lock", "symlink", "unreferenced", "truncated_history", "duplicate_json", "credentials"])
def test_bad_source_fails_without_recovery_or_data_loss(source, damage):
    config, storage, root = source
    data = config["DATA_DIR"]
    if damage == "missing_lock":
        (data / ".storage.lock").unlink()
    elif damage == "symlink":
        (data / "routers.json").unlink()
        (data / "routers.json").symlink_to(root / ".env")
    elif damage == "unreferenced":
        (data / "traffic_segments/traffic-2026-11-25-9999.jsonl").write_bytes(b"")
    elif damage == "truncated_history":
        path = next((data / "traffic_segments").iterdir())
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
    elif damage == "duplicate_json":
        (data / "routers.json").write_text('[{"router_id":"A","router_id":"B"}]')
    else:
        storage.write_json("routers.json", [{"router_id": "TEST-MIGRATION", "api_password": "synthetic-private-password"}])
    before = fingerprints(config)
    with pytest.raises(MigrationError) as error:
        prepare(config, root / "bundle")
    assert "synthetic-private-password" not in str(error.value)
    assert fingerprints(config) == before
    assert not (root / "bundle").exists()


def test_pending_history_transaction_is_not_recovered_by_migration(source):
    config, storage, root = source
    state = storage.read_json("router_traffic_v2.json")
    state["pending_reading"] = {"file": storage.read_json("traffic_history.json")["segments"][0]["file"], "offset": 0,
        "reading": {"protocol_version": "2.0", "router_id": "TEST-MIGRATION", "request_id": str(uuid4()),
                    "interface": "test-tx", "timestamp": "2026-11-25T08:00:00Z", "tx_octets": 1000,
                    "tx_mbps": 0.25, "interval_seconds": 60}}
    reading = state["pending_reading"]["reading"]
    state["routers"]["TEST-MIGRATION"] = {"interface": "test-tx", "generation": None,
        "timestamp": int(datetime.fromisoformat(reading["timestamp"].replace("Z", "+00:00")).timestamp()),
        "tx_octets": reading["tx_octets"], "last_received_at": reading["timestamp"],
        "tx_mbps": reading["tx_mbps"], "sample_state": "measured"}
    state["seen_requests"].append({"router_id": reading["router_id"], "request_id": reading["request_id"],
                                  "expires_at": "2026-11-25T12:00:00Z"})
    storage.write_json("router_traffic_v2.json", state)
    before = fingerprints(config)
    with pytest.raises(MigrationError, match="pending"):
        prepare(config, root / "bundle")
    assert fingerprints(config) == before


@pytest.mark.parametrize("target", ["data", "output", "data/backup"])
def test_destination_cannot_touch_active_storage(source, target):
    config, _, root = source
    before = fingerprints(config)
    with pytest.raises(MigrationError):
        prepare(config, root / target)
    assert fingerprints(config) == before


def test_failed_output_write_cleans_only_new_artifact(source, monkeypatch):
    config, _, root = source
    before = fingerprints(config)
    monkeypatch.setattr("services.rev3_migration._write", lambda *a: (_ for _ in ()).throw(OSError("synthetic-private")))
    with pytest.raises(MigrationError):
        prepare(config, root / "bundle")
    assert not (root / "bundle").exists()
    assert fingerprints(config) == before


def test_capture_refuses_existing_destination_and_unsafe_flags(source):
    config, _, root = source
    prepare(config, root / "bundle")
    before = (root / "bundle/manifest.json").read_bytes()
    with pytest.raises(MigrationError):
        prepare(config, root / "bundle")
    with pytest.raises(MigrationError):
        prepare({**config, "LIVE_ROUTING_ENABLED": True}, root / "unsafe")
    assert (root / "bundle/manifest.json").read_bytes() == before
    assert not (root / "unsafe").exists()


def test_cli_capture_does_not_initialize_or_expose_private_registry(source, monkeypatch, capsys):
    import manage
    import sys
    config, _, root = source
    before = fingerprints(config)
    monkeypatch.setattr("config.load_config", lambda: config)
    monkeypatch.setattr(StorageService, "initialize", lambda *a: pytest.fail("CLI initialized storage"))
    monkeypatch.setattr(sys, "argv", ["manage.py", "prepare-rev3-migration", "--output-dir", str(root / "cli-bundle")])
    manage.main()
    value = json.loads(capsys.readouterr().out)
    assert value["prepared"] is True and value["runtime_cutover_authorized"] is False
    assert "TEST_API_REFERENCE" not in json.dumps(value)
    assert fingerprints(config) == before

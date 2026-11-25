"""Stage 1 assessments must never acquire device access or mutate live state."""
from copy import deepcopy
import hashlib
import json
import sys

import pytest

from services.json_storage import StorageService
from services.path_config_service import PathConfigService
from services.rev3_readiness import (
    DECISIONS, ReadinessError, assess, format_report, load_register, report, validate_register,
)


@pytest.fixture(autouse=True)
def no_network_or_credentials(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Readiness assessment attempted device/credential access")
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("services.api_credentials_service.api_credentials", forbidden)
    monkeypatch.setattr("services.api_credentials_service.controller_secret", forbidden)


@pytest.fixture
def config(tmp_path):
    return {"ENVIRONMENT": "development", "DATA_DIR": tmp_path / "data",
            "OUTPUT_DIR": tmp_path / "output", "SIMULATION_MODE": True,
            "LIVE_ROUTING_ENABLED": False, "AUTH_ENABLED": False,
            "LIVE_SAMPLE_INTERVAL_SECONDS": 1, "SECRET_KEY": "synthetic-session-private"}


@pytest.fixture
def store(config):
    storage = StorageService(config["DATA_DIR"], config["OUTPUT_DIR"])
    storage.initialize()
    storage.write_json("routers.json", [
        {"router_id": "SYNTHETIC-AGG", "name": "Synthetic aggregation",
         "ip_address": "10.43.0.1", "credential_ref": "SYNTHETIC_PRIVATE_REF",
         "legacy_secret": "synthetic-registry-private"},
        {"router_id": "SYNTHETIC-PEER", "name": "Synthetic peer"},
    ])
    PathConfigService(storage).add_path({
        "aggregation_router_id": "SYNTHETIC-AGG", "carrier_router_id": "SYNTHETIC-PEER",
        "carrier": "Synthetic carrier", "aggregation_interface": "synthetic-tx",
        "carrier_interface": "synthetic-wan", "path_capacity_bps": "10000000",
    })
    storage.update_json("routing_paths.json", lambda value: {
        **value, "paths": [{**value["paths"][0], "live_sampling_enabled": True}],
    })
    return storage


def file_state(root):
    return {str(p.relative_to(root)): (p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
            for p in root.rglob("*") if p.is_file()}


def test_register_separates_approved_ospf_from_undecided_measurement():
    rows = {row["id"]: row for row in load_register()["decisions"]}
    assert rows["routing_mechanism"]["status"] == "confirmed"
    assert rows["routing_mechanism"]["selection"] == "ospf_interface_or_template_cost"
    assert rows["routing_mechanism"]["source"] == "user_confirmation"
    assert rows["measurement_method"]["status"] == "pending"
    assert rows["measurement_method"]["selection"] is None
    assert rows["confirmation_rule"]["status"] == "documented"


def test_existing_profile_is_unchanged_and_only_counts_are_exposed(config, store, monkeypatch):
    before = file_state(config["DATA_DIR"].parent)
    monkeypatch.setattr(StorageService, "initialize", lambda *a: pytest.fail("Initialized existing profile"))
    result = report(config)
    assert file_state(config["DATA_DIR"].parent) == before
    profile = result["current_profile"]
    assert profile["routers"] == 2 and profile["paths"] == 1
    assert profile["api_login_references_configured"] == 1
    assert profile["enabled_api_live_paths"] == 1
    assert profile["live_sampling_target_seconds"] == 1
    assert profile["decision_interval_seconds"] == 60
    assert result["required_corrections"][0]["status"] == "requires_replacement"
    for rendered in (json.dumps(result), format_report(result)):
        for private in ("10.43.0.1", "SYNTHETIC_PRIVATE_REF", "SYNTHETIC-AGG",
                        "synthetic-session-private", "synthetic-registry-private"):
            assert private not in rendered


def test_missing_profile_is_not_created(config, monkeypatch):
    monkeypatch.setattr(StorageService, "initialize", lambda *a: pytest.fail("Initialized missing profile"))
    result = report(config)
    assert result["current_profile"]["snapshot_status"] == "not_initialized"
    assert result["current_profile"]["routers"] == 0
    assert not config["DATA_DIR"].exists() and not config["OUTPUT_DIR"].exists()


def test_production_snapshot_cannot_read_outside_its_profile(config, tmp_path):
    isolated = {**config, "ENVIRONMENT": "production", "PROFILE_DIR": tmp_path / "production"}
    with pytest.raises(ValueError, match="inside"):
        report(isolated)
    assert not isolated["PROFILE_DIR"].exists()
    assert not config["DATA_DIR"].exists()


def test_snapshot_does_not_follow_a_symlinked_data_directory(config, tmp_path):
    actual = tmp_path / "actual-data"
    actual.mkdir()
    config["DATA_DIR"].symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic"):
        report(config)
    assert list(actual.iterdir()) == []


@pytest.mark.parametrize("damage", ["lock_missing", "lock_symlink", "bad_inventory", "bad_settings", "missing_paths"])
def test_unavailable_snapshot_fails_closed_without_repair(config, store, damage):
    root = config["DATA_DIR"]
    if damage.startswith("lock_"):
        lock = root / ".storage.lock"
        lock.unlink()
        if damage == "lock_symlink":
            lock.symlink_to(root / "routers.json")
    elif damage == "bad_inventory":
        (root / "routers.json").write_text("not valid JSON")
    elif damage == "bad_settings":
        (root / "automation_settings.json").write_text('{"secret":"synthetic-private-untrusted"}')
    else:
        (root / "routing_paths.json").unlink()
    before = file_state(root.parent)
    result = report(config)
    assert result["current_profile"]["snapshot_status"] == "consistent_snapshot_unavailable"
    assert result["production_ready"] is False
    assert "inventory_snapshot" in {b["id"] for b in result["planning_blockers"]}
    assert file_state(root.parent) == before


def test_all_planning_choices_still_cannot_authorize_execution(config, store):
    register = load_register()
    register["production_inputs_confirmed"] = True
    for row in register["decisions"]:
        row.update(status="confirmed", source="user_confirmation", recorded_on="2026-11-25",
                   selection=sorted(DECISIONS[row["id"]])[0])
    snapshot = {name: store.read_json(name) for name in (
        "routers.json", "routing_paths.json", "automation_settings.json")}
    result = assess(register, snapshot, config)
    assert result["planning_status"] == "inputs_recorded"
    assert result["planning_blockers"] == []
    assert result["production_ready"] is False
    assert result["router_execution_authorized"] is False
    assert result["controller_router_writes_permitted"] is False
    assert result["assessment_only"] is True
    register["production_inputs_confirmed"] = False
    assert assess(register, snapshot, config)["planning_status"] == "pending_inputs"


@pytest.mark.parametrize("key,value", [("SIMULATION_MODE", False), ("LIVE_ROUTING_ENABLED", True)])
def test_unsafe_global_flags_are_reported_without_changing_them(config, key, value):
    changed = {**config, key: value}
    result = report(changed)
    assert changed[key] is value
    assert "execution_locks" in {b["id"] for b in result["planning_blockers"]}
    assert result["router_execution_authorized"] is False


@pytest.mark.parametrize("damage", ["unknown_field", "unknown_decision", "duplicate_decision",
    "pending_selection", "invalid_choice", "false_document_provenance", "bad_date",
    "missing_decision", "not_planning", "boolean_schema", "bad_hash"])
def test_register_rejects_ambiguous_or_falsely_attributed_decisions(damage):
    register = load_register()
    row = register["decisions"][0]
    if damage == "unknown_field":
        register["password"] = "synthetic-private-unknown"
    elif damage == "unknown_decision":
        row["id"] = "synthetic-private-unknown"
    elif damage == "duplicate_decision":
        register["decisions"][1] = deepcopy(row)
    elif damage == "pending_selection":
        row["selection"] = "router_pushed_metrics"
    elif damage in ("invalid_choice", "false_document_provenance", "bad_date"):
        row.update(status="confirmed", source="user_confirmation", recorded_on="2026-11-25",
                   selection="router_pushed_metrics")
        if damage == "invalid_choice":
            row["selection"] = "synthetic-private-unknown"
        elif damage == "false_document_provenance":
            row.update(status="documented", source="official_plan")
        else:
            row["recorded_on"] = "2026-02-30"
    elif damage == "missing_decision":
        register["decisions"].pop()
    elif damage == "not_planning":
        register["planning_only"] = False
    elif damage == "boolean_schema":
        register["schema_version"] = True
    else:
        register["source"]["sha256"] = "synthetic-private-unknown"
    with pytest.raises(ReadinessError) as error:
        validate_register(register)
    assert "synthetic-private-unknown" not in str(error.value)


@pytest.mark.parametrize("content", ['{"secret":"synthetic-private-unknown"}',
    '{"schema_version":1,"schema_version":1}', '{"value":NaN}', '{"value":Infinity}',
    '["synthetic-private-unknown"]', 'invalid synthetic-private-unknown'])
def test_invalid_json_has_secret_free_errors(tmp_path, content):
    path = tmp_path / "register.json"
    path.write_text(content)
    with pytest.raises(ReadinessError) as error:
        load_register(path)
    assert "synthetic-private-unknown" not in str(error.value)


@pytest.mark.parametrize("kind", ["symlink", "oversized", "missing"])
def test_register_file_must_be_regular_and_bounded(tmp_path, kind):
    path = tmp_path / "register.json"
    if kind == "symlink":
        target = tmp_path / "target.json"
        target.write_text(json.dumps(load_register()))
        path.symlink_to(target)
    elif kind == "oversized":
        path.write_text(" " * (64 * 1024 + 1))
    with pytest.raises(ReadinessError):
        load_register(path)


def test_documented_requirement_does_not_imply_production_signoff(config):
    result = report(config)
    blockers = {item["id"] for item in result["planning_blockers"]}
    assert "confirmation_rule" in blockers
    assert "routing_mechanism" not in blockers
    assert "measurement_method" in blockers


@pytest.mark.parametrize("as_json", [False, True])
def test_cli_runs_before_profile_initialization(config, monkeypatch, capsys, as_json):
    import manage
    monkeypatch.setattr("config.load_config", lambda: config)
    monkeypatch.setattr(StorageService, "initialize", lambda *a: pytest.fail("CLI initialized storage"))
    monkeypatch.setattr("services.deployment_service.validate_deployment",
                        lambda *a, **k: pytest.fail("CLI invoked mutating startup validation"))
    monkeypatch.setattr(sys, "argv", ["manage.py", "rev3-readiness"] + (["--json"] if as_json else []))
    manage.main()
    captured = capsys.readouterr()
    assert captured.err == ""
    if as_json:
        assert json.loads(captured.out)["production_ready"] is False
    else:
        assert "routing_mechanism: confirmed" in captured.out
    assert "synthetic-session-private" not in captured.out
    assert not config["DATA_DIR"].exists() and not config["OUTPUT_DIR"].exists()


def test_cli_invalid_register_hides_private_values(config, tmp_path, monkeypatch, capsys):
    import manage
    path = tmp_path / "invalid.json"
    path.write_text('{"secret":"synthetic-private-cli-value"}')
    monkeypatch.setattr("config.load_config", lambda: config)
    monkeypatch.setattr(sys, "argv", ["manage.py", "rev3-readiness", "--decisions", str(path), "--json"])
    with pytest.raises(SystemExit) as error:
        manage.main()
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert "private details withheld" in captured.err
    assert "synthetic-private-cli-value" not in captured.err + captured.out
    assert not config["DATA_DIR"].exists()

"""Read-only Stage 1 planning assessment. This cannot authorize execution.

No device clients, credential lookup, writes, migrations or scheduler startup.
The decision register describes planning choices, never active routing policy.
"""
from datetime import date
import json
import os
from pathlib import Path
import re

from services.json_storage import StorageService, StorageError


class ReadinessError(ValueError):
    """An authored error which never echoes untrusted register contents."""


DECISIONS = {
    "measurement_method": {"router_pushed_metrics", "read_only_snmp"},
    "routing_mechanism": {"ospf_interface_or_template_cost"},
    "capacity_difference_basis": {"larger_capacity", "smaller_capacity", "mean_capacity"},
    "step_percentage_basis": {"normal_cost", "current_cost"},
    "rounding_rule": {"ceil_minimum_one", "nearest_minimum_one"},
    "confirmation_rule": {"two_consecutive_checks"},
    "database_engine": {"mysql", "postgresql"},
    "controller_outage_policy": {"hold_last", "normal_after_failures"},
}
DEFAULT_REGISTER = Path(__file__).resolve().parents[1] / "docs/vdt-rev3-decisions.json"
DOCUMENTED_SELECTIONS = {"confirmation_rule": "two_consecutive_checks"}


def _fields(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        raise ReadinessError("Invalid Rev3 decision register fields.")


def validate_register(register):
    _fields(register, "schema_version planning_only source production_inputs_confirmed decisions")
    if (type(register["schema_version"]) is not int or register["schema_version"] != 1
            or register["planning_only"] is not True or type(register["production_inputs_confirmed"]) is not bool):
        raise ReadinessError("The Rev3 register must remain planning-only.")
    _fields(register["source"], "title revision sha256")
    source = register["source"]
    if (source["title"] != "VDT SDR Implementation Plan (Plain Rev3)" or source["revision"] != "Plain Rev3"
            or not isinstance(source["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", source["sha256"])):
        raise ReadinessError("Invalid Rev3 requirements provenance.")
    rows = register["decisions"]
    if not isinstance(rows, list) or len(rows) != len(DECISIONS):
        raise ReadinessError("All Rev3 planning decisions must be listed once.")
    seen = set()
    for row in rows:
        _fields(row, "id status selection source recorded_on")
        identity = row["id"]
        if not isinstance(identity, str) or identity not in DECISIONS or identity in seen:
            raise ReadinessError("Unknown or duplicate Rev3 planning decision.")
        seen.add(identity)
        status = row["status"]
        if status not in ("pending", "documented", "confirmed"):
            raise ReadinessError("Invalid planning decision status.")
        if status == "pending":
            if row["selection"] is not None or row["recorded_on"] is not None or row["source"] != "pending":
                raise ReadinessError("Pending decisions cannot claim an approved selection.")
        else:
            if not isinstance(row["selection"], str) or row["selection"] not in DECISIONS[identity]:
                raise ReadinessError("Unsupported planning selection.")
            required_source = "user_confirmation" if status == "confirmed" else "official_plan"
            if row["source"] != required_source:
                raise ReadinessError("Decision confirmation must identify its source.")
            if status == "documented" and DOCUMENTED_SELECTIONS.get(identity) != row["selection"]:
                raise ReadinessError("This selection requires explicit confirmation; the plan leaves it open.")
            if not isinstance(row["recorded_on"], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", row["recorded_on"]):
                raise ReadinessError("Invalid planning confirmation date.")
            try:
                date.fromisoformat(row["recorded_on"])
            except ValueError as exc:
                raise ReadinessError("Invalid planning confirmation date.") from exc


def load_register(path=DEFAULT_REGISTER):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise ReadinessError("Use a regular bounded Rev3 decision register.")
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ReadinessError("Duplicate Rev3 decision register fields.")
            result[key] = value
        return result
    def invalid(_):
        raise ReadinessError("Non-finite register values are not allowed.")
    try:
        register = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=invalid)
        validate_register(register)
        return register
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ReadinessError("Cannot read a valid Rev3 decision register; private contents withheld.") from exc


def read_existing_snapshot(config):
    """Read an existing profile with a shared lock; never initialize or recover it."""
    from services.deployment_service import profile_path
    root = profile_path(config, config["DATA_DIR"])
    profile_path(config, config["OUTPUT_DIR"])
    empty = {"routers.json": [], "routing_paths.json": {"paths": []}, "automation_settings.json": {}}
    if not root.exists():
        return empty, "not_initialized"
    lock = root / ".storage.lock"
    if lock.is_symlink() or not lock.is_file() or os.name == "nt":
        return empty, "consistent_snapshot_unavailable"
    try:
        import fcntl
        storage = StorageService(root, config["OUTPUT_DIR"])
        with lock.open("rb") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            return {name: storage._read_unlocked(name) for name in empty}, "read_only_snapshot"
    except (OSError, StorageError):
        return empty, "consistent_snapshot_unavailable"


def assess(register, inputs, config, *, snapshot_status="read_only_snapshot"):
    validate_register(register)
    routers = inputs["routers.json"]
    paths = inputs["routing_paths.json"]["paths"]
    settings = inputs["automation_settings.json"]
    pending = [d["id"] for d in register["decisions"] if d["status"] == "pending"]
    blockers = [{"id": name, "reason": "Planning decision not yet confirmed."} for name in pending]
    blockers.extend({"id": row["id"], "reason": "Documented requirement; production sign-off still required."}
                    for row in register["decisions"] if row["status"] == "documented")
    if not register["production_inputs_confirmed"]:
        blockers.append({"id": "production_link_parameters", "reason": "Exact endpoints, OSPF resources, capacities, thresholds, cost bounds and probe paths need confirmation."})
    if snapshot_status != "read_only_snapshot":
        blockers.append({"id": "inventory_snapshot", "reason": "No initialized, consistent local profile was available for read-only inspection."})
    if config.get("SIMULATION_MODE") is not True or config.get("LIVE_ROUTING_ENABLED") is not False:
        blockers.append({"id": "execution_locks", "reason": "Keep simulation enabled and routing execution disabled."})
    api_references = sum(bool(row.get("credential_ref")) for row in routers)
    api_paths = sum(p.get("live_sampling_enabled") is True for p in paths)
    return {
        "stage": 1, "assessment_only": True, "planning_status": "pending_inputs" if blockers else "inputs_recorded",
        "production_ready": False, "router_execution_authorized": False, "controller_router_writes_permitted": False,
        "source": register["source"],
        "decisions": [{key: d[key] for key in ("id", "status", "selection")} for d in register["decisions"]],
        "planning_blockers": blockers,
        "current_profile": {"environment": config.get("ENVIRONMENT", "development"), "snapshot_status": snapshot_status,
            "routers": len(routers), "paths": len(paths), "api_login_references_configured": api_references,
            "enabled_api_live_paths": api_paths, "staff_login_enabled": config.get("AUTH_ENABLED") is True,
            "live_sampling_target_seconds": config.get("LIVE_SAMPLE_INTERVAL_SECONDS"),
            "decision_interval_seconds": settings.get("monitoring_interval_seconds")},
        "required_corrections": [
            {"id": "password_free_production_collection", "status": "requires_replacement" if api_references or api_paths else "requires_validation"},
            {"id": "three_metric_two_check_step_policy", "status": "not_implemented"},
            {"id": "test_manual_automatic_release_workflow", "status": "not_implemented"},
            {"id": "calculated_released_applied_costs", "status": "not_implemented"},
            {"id": "transactional_database_and_history_migration", "status": "staging_prepared_runtime_json"},
            {"id": "authorized_router_side_cost_application", "status": "not_implemented"},
            {"id": "four_page_named_staff_noc_dashboard", "status": "not_implemented"},
            {"id": "private_network_identity_and_source_restrictions", "status": "requires_validation"},
            {"id": "alerts_backup_restore_and_staged_acceptance", "status": "not_implemented"},
        ],
        "next_stage": "Stage 3: approved password-free measurement, normalized persistence and scheduled checks; runtime remains JSON until verified cutover.",
    }


def report(config, register_path=DEFAULT_REGISTER):
    register = load_register(register_path)
    inputs, status = read_existing_snapshot(config)
    return assess(register, inputs, config, snapshot_status=status)


def format_report(value):
    lines = ["VDT Rev3 — Stage 1 planning assessment", "Production readiness: NOT GRANTED; this assessment cannot authorize router execution."]
    for item in value["decisions"]:
        lines.append(f"{item['id']}: {item['status']}" + (f" ({item['selection']})" if item['selection'] else ""))
    profile = value["current_profile"]
    lines.append(f"Existing profile: {profile['routers']} routers, {profile['paths']} paths; {profile['snapshot_status']}.")
    lines.append(f"Router API login references configured: {profile['api_login_references_configured']}; these are incompatible with Rev3 production collection.")
    lines.extend("Pending: " + item["id"] + " — " + item["reason"] for item in value["planning_blockers"])
    lines.append("Assessment only. No credentials displayed, router contacted, profile initialized or settings changed.")
    return "\n".join(lines)

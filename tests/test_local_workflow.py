"""Local analysis/optimization tests: synthetic data, no router connections."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from itertools import product
import json
from uuid import uuid4

import pytest

from app import create_app
from device_app import create_device_app
from services.json_storage import StorageError, ValidationError
from services.path_config_service import PathConfigService
from services.router_service import RouterService
from services.routeros_protocol import ROUTEROS_TRAFFIC_PATH, sign_routeros_request
from services.traffic_service import TrafficService
from services.workflow_service import WorkflowService, allocate_parallel_paths


NOW = datetime.now(UTC).replace(microsecond=0)
SECRET = "synthetic-local-workflow-key-0123456789abcdef"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Workflow contacted a router"))


@pytest.fixture
def config(tmp_path):
    return {"TESTING": True, "AUTH_ENABLED": False, "SIMULATION_MODE": True,
            "LIVE_ROUTING_ENABLED": False, "ROUTER_RATE_LIMIT_ATTEMPTS": 200,
            "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output"}


@pytest.fixture
def setup(config, monkeypatch):
    app = create_device_app(config)
    storage = app.extensions["json_storage"]
    rows = [{"router_id": "SIM-AGG", "name": "Synthetic aggregation"}]
    for router_id, carrier, price in (("SIM-MTN", "MTN", 2), ("SIM-GLO", "GLO", 1)):
        monkeypatch.setenv(f"{router_id.replace('-', '_')}_PRIMARY_SECRET", SECRET)
        rows.append({
            "router_id": router_id, "name": router_id, "carrier": carrier,
            "interface_name": "synthetic-egress", "capacity_mbps": 100,
            "cost_per_gb": price, "currency": "NGN", "monitoring_enabled": True,
            "controller_auth_enabled": True, "controller_auth_ref": router_id.replace("-", "_"),
            "controller_auth_key_ids": ["PRIMARY"], "legacy_secret": "synthetic-private-registry-value",
        })
    storage.write_json("routers.json", rows)
    paths = PathConfigService(storage)
    for router_id, carrier in (("SIM-MTN", "MTN"), ("SIM-GLO", "GLO")):
        paths.add_path({"aggregation_router_id": "SIM-AGG", "carrier_router_id": router_id,
            "carrier": carrier, "aggregation_interface": "handoff-" + carrier.lower(),
            "carrier_interface": "synthetic-egress", "path_capacity_bps": "100000000",
            "route_role": "primary", "monitor_router_id": router_id})
    paths.save_congestion_policy({"utilization_limit_percent": "80", "minimum_hold_down_seconds": "0",
                                  "overload_policy": "prefer_lower_utilization"})
    workflow = WorkflowService(storage, app.config)
    workflow.save_settings({"optimization_objective": "minimize_cost", "averaging_window": "3",
                            "monitoring_interval_seconds": "10"})
    return app, storage, workflow


def sample(setup, router_id, at, counter):
    app, storage, _ = setup
    body = {"protocol_version": "2.0", "router_id": router_id, "request_id": str(uuid4()),
            "timestamp": int(at.timestamp()), "request_type": "traffic",
            "interface": "synthetic-egress", "tx_octets": counter}
    raw = json.dumps(body, separators=(",", ":")).encode()
    return TrafficService(storage, app.config).handle(raw, "PRIMARY",
        sign_routeros_request(SECRET, raw, "PRIMARY", ROUTEROS_TRAFFIC_PATH), "127.0.0.1", now=at)


def populate(setup, rates_a=(50, 55, 60, 65), rates_b=(50, 45, 40, 35)):
    for router_id, rates in (("SIM-MTN", rates_a), ("SIM-GLO", rates_b)):
        start = NOW - timedelta(seconds=len(rates) * 10)
        counter = 1_000_000
        sample(setup, router_id, start, counter)
        for index, rate in enumerate(rates, 1):
            counter += int(rate * 1_000_000 / 8 * 10)
            sample(setup, router_id, start + timedelta(seconds=index * 10), counter)


def change_router(storage, router_id, **changes):
    return storage.update_json("routers.json", lambda rows: [
        {**row, **changes} if row["router_id"] == router_id else row for row in rows])


def test_utilization_balancing_does_not_require_invented_carrier_prices(setup):
    populate(setup)
    app, storage, workflow = setup
    for router_id in ("SIM-MTN", "SIM-GLO"):
        change_router(storage, router_id, cost_per_gb=None, currency="")
    workflow.save_settings({"optimization_objective":"balance_utilization", "averaging_window":"3", "monitoring_interval_seconds":"10"})
    result = workflow.calculate(now=NOW)
    assert result["status"] == "ready"
    assert result["current_cost_per_hour"] is None and result["recommended_cost_per_hour"] is None
    assert result["estimated_savings_per_hour"] is None
    assert sum(row["recommended_mbps"] for row in result["allocations"]) == pytest.approx(100)
    assert result["action"] == "none" and result["routing_changes_enabled"] is False


def test_analysis_computes_full_window_previous_average_change_share_and_cost(setup):
    populate(setup)
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "ready"
    rows = {row["router_id"]: row for row in result["analysis"]}
    mtn = rows["SIM-MTN"]
    assert mtn["current_mbps"] == 65 and mtn["average_mbps"] == 60
    assert mtn["previous_average_mbps"] == 55
    assert mtn["change_percent"] == pytest.approx(100 * 5 / 55)
    assert mtn["utilization_percent"] == 60 and mtn["traffic_share_percent"] == 60
    assert mtn["observed_gb"] == pytest.approx(180 * 10 / 8000)
    assert mtn["cost_per_hour"] == 54
    assert result["current_cost_per_hour"] == 72
    assert result["recommended_cost_per_hour"] == 54
    assert result["estimated_savings_per_hour"] == 18
    assert result["mode"] == "dry_run" and result["action"] == "none"
    assert result["routing_changes_enabled"] is False


def test_cost_minimization_conserves_group_demand_and_respects_utilization_ceiling(setup):
    populate(setup)
    result = setup[2].calculate(now=NOW)
    targets = {row["carrier"]: row["recommended_mbps"] for row in result["allocations"]}
    assert targets == {"MTN": 20, "GLO": 80}
    assert sum(targets.values()) == 100
    assert result["groups"][0]["demand_mbps"] == 100
    assert all(0 <= row["recommended_mbps"] <= row["allowed_mbps"] for row in result["allocations"])


@pytest.mark.parametrize("objective", ["minimize_cost", "balance_utilization"])
def test_parallel_allocator_matches_independent_small_integer_cost_oracle(objective):
    paths = [{"path_id": str(index), "current_mbps": current, "allowed_mbps": cap, "cost_per_gb": price}
             for index, (current, cap, price) in enumerate(((2, 3, 5), (1, 4, 1), (2, 2, 3)))]
    result = allocate_parallel_paths(paths, objective)
    assert sum(result) == pytest.approx(5)
    assert all(0 <= value <= path["allowed_mbps"] for value, path in zip(result, paths))
    if objective == "minimize_cost":
        oracle = min(sum(value * path["cost_per_gb"] for value, path in zip(allocation, paths))
                     for allocation in product(range(4), range(5), range(3)) if sum(allocation) == 5)
        assert sum(value * path["cost_per_gb"] for value, path in zip(result, paths)) == oracle
    else:
        assert len({round(value / path["allowed_mbps"], 10) for value, path in zip(result, paths)}) == 1


def test_balance_policy_uses_capacity_proportions(setup):
    populate(setup)
    setup[2].save_settings({"optimization_objective": "balance_utilization", "averaging_window": "3",
                            "monitoring_interval_seconds": "10"})
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "ready"
    assert [row["recommended_mbps"] for row in result["allocations"]] == [50, 50]


def test_infeasible_demand_produces_no_partial_plan_or_silent_traffic_loss(setup):
    populate(setup, (100, 100, 100), (100, 100, 100))
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "infeasible"
    assert result["groups"][0]["demand_mbps"] == 200
    assert all(row["recommended_mbps"] is None for row in result["allocations"])
    assert result["recommended_cost_per_hour"] is None


def test_standby_is_excluded_from_available_capacity(setup):
    populate(setup)
    setup[1].update_json("routing_paths.json", lambda config: {**config, "paths": [
        {**path, "route_role": "standby"} if path["carrier"] == "GLO" else path for path in config["paths"]]})
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "infeasible"
    assert result["groups"][0]["available_mbps"] == 80


@pytest.mark.parametrize("changes,code", [
    ({"cost_per_gb": None}, "price_required"), ({"currency": "USD"}, "currency_mismatch"),
    ({"interface_name": "different-egress"}, "interface_mismatch"),
    ({"monitoring_enabled": False}, "readings_required"),
    ({"controller_auth_enabled": False}, "readings_required"),
])
def test_missing_or_changed_inputs_block_recommendations(setup, changes, code):
    populate(setup)
    change_router(setup[1], "SIM-MTN", **changes)
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "blocked"
    assert code in {issue["code"] for issue in result["issues"]}
    assert all(row["recommended_mbps"] is None for row in result["allocations"])


def test_measurement_source_is_explicit_and_must_match_one_endpoint(setup):
    setup[1].update_json("routing_paths.json", lambda config: {**config, "paths": [
        {key: value for key, value in path.items() if key != "monitor_router_id"} for path in config["paths"]]})
    populate(setup)
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "blocked"
    assert "measurement_required" in {issue["code"] for issue in result["issues"]}
    with pytest.raises(ValidationError):
        setup[1].update_json("routing_paths.json", lambda config: {**config, "paths": [
            {**path, "monitor_router_id": "OTHER-ROUTER"} for path in config["paths"]]})


def test_same_counter_cannot_supply_two_paths_or_be_double_counted(setup):
    populate(setup)
    setup[1].update_json("routing_paths.json", lambda config: {**config, "paths": [
        *config["paths"], {**config["paths"][0], "path_id": "SIM-DUPLICATE", "aggregation_interface": "other-handoff"}]})
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "blocked"
    assert "duplicate_measurement" in {issue["code"] for issue in result["issues"]}


def test_warmup_requires_full_window_and_stale_samples_cannot_produce_a_plan(setup):
    populate(setup, (60,), (40,))
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "blocked"
    assert {row["state"] for row in result["analysis"] if row["router_id"] != "SIM-AGG"} == {"warming_up"}
    result = setup[2].calculate(now=NOW + timedelta(seconds=181))
    assert {row["state"] for row in result["analysis"] if row["router_id"] != "SIM-AGG"} == {"stale"}
    assert all(row["recommended_mbps"] is None for row in result["allocations"])


def test_counter_reset_starts_new_average_window_without_mixing_history(setup):
    populate(setup)
    assert setup[2].calculate(now=NOW)["status"] == "ready"
    sample(setup, "SIM-MTN", NOW + timedelta(seconds=10), 0)
    sample(setup, "SIM-MTN", NOW + timedelta(seconds=20), 12_500_000)
    result = setup[2].calculate(now=NOW + timedelta(seconds=20))
    mtn = next(row for row in result["analysis"] if row["router_id"] == "SIM-MTN")
    assert mtn["sample_count"] == 1 and mtn["average_mbps"] is None
    assert result["status"] == "blocked"
    assert len(setup[1].list_traffic()) == 9


def test_zero_traffic_is_valid_and_previous_zero_has_no_percentage_change(setup):
    populate(setup, (0, 0, 0, 0), (0, 0, 0, 0))
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "ready" and result["recommended_cost_per_hour"] == 0
    assert all(row["recommended_mbps"] == 0 for row in result["allocations"])
    assert all(row["change_percent"] is None for row in result["analysis"])


def test_hold_down_withholds_new_recommendation_until_elapsed(setup):
    populate(setup)
    setup[1].update_json("routing_paths.json", lambda config: {**config, "congestion_policy": {
        **config["congestion_policy"], "minimum_hold_down_seconds": 120}})
    first = setup[2].calculate(now=NOW)
    counter = setup[1].read_json("router_traffic_v2.json")["routers"]["SIM-MTN"]["tx_octets"]
    sample(setup, "SIM-MTN", NOW + timedelta(seconds=10), counter + 12_500_000)
    held = setup[2].calculate(now=NOW + timedelta(seconds=10))
    assert first["status"] == "ready" and held["status"] == "hold_down"
    assert held["hold_until"] and all(row["recommended_mbps"] is None for row in held["allocations"])
    assert setup[2].calculate(now=NOW + timedelta(seconds=120))["status"] == "ready"


def test_duplicate_and_concurrent_calculation_does_not_duplicate_committed_history(setup):
    populate(setup)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: setup[2].calculate(now=NOW), range(4)))
    assert len({row["evaluation_id"] for row in results}) == 1
    assert len(setup[1].read_json("optimization_results.json")) == 1
    assert len(setup[1].read_json("averages.json")) == 3
    assert len(setup[1].read_json("routing_costs.json")) == 2


def test_interrupted_publication_does_not_expose_orphan_analysis_and_retry_recovers(setup, monkeypatch):
    populate(setup)
    original = setup[1]._write_unlocked
    def fail(name, value, **options):
        if name == "optimization_results.json":
            raise StorageError("Synthetic publication failure")
        return original(name, value, **options)
    with monkeypatch.context() as patch:
        patch.setattr(setup[1], "_write_unlocked", fail)
        with pytest.raises(StorageError):
            setup[2].calculate(now=NOW)
    assert setup[2].read_latest(now=NOW) is None
    assert setup[1].read_json("averages.json")
    setup[2].calculate(now=NOW)
    assert len(setup[1].read_json("averages.json")) == 3
    assert len(setup[1].read_json("routing_costs.json")) == 2


def test_current_result_is_invalidated_by_new_samples_settings_revoke_or_age(setup):
    populate(setup)
    setup[2].calculate(now=NOW)
    assert setup[2].read_latest(now=NOW)["is_current"] is True
    assert setup[2].read_latest(now=NOW + timedelta(seconds=181))["is_current"] is False
    change_router(setup[1], "SIM-MTN", controller_auth_enabled=False)
    assert setup[2].read_latest(now=NOW)["is_current"] is False


def test_workflow_writes_only_calculation_documents_and_preserves_all_routing_guards(setup):
    populate(setup)
    names = ("routers.json", "routing_paths.json", "automation_settings.json", "router_config.json",
             "router_communication.json", "router_communication_v2.json", "router_traffic_v2.json", "traffic_history.json")
    before = {name: setup[1].read_json(name) for name in names}
    setup[2].calculate(now=NOW)
    assert {name: setup[1].read_json(name) for name in names} == before
    assert setup[0].config["SIMULATION_MODE"] is True and setup[0].config["LIVE_ROUTING_ENABLED"] is False


def test_unknown_private_result_fields_are_rejected_and_legacy_records_are_preserved(setup):
    populate(setup)
    setup[1].write_json("optimization_results.json", [{"legacy_secret": "synthetic-hidden-legacy-result"}])
    result = setup[2].calculate(now=NOW)
    assert setup[1].read_json("optimization_results.json")[0]["legacy_secret"]
    with pytest.raises(ValidationError):
        setup[1].write_json("optimization_results.json", [{**result, "private_secret": SECRET}])
    assert SECRET not in json.dumps(result)
    assert "synthetic-private-registry-value" not in json.dumps(result)


def test_browser_calculation_requires_csrf_and_api_only_returns_public_committed_result(setup, config):
    populate(setup)
    browser = create_app(config)
    client = browser.test_client()
    assert client.post("/workflow/calculate").status_code == 400
    assert client.get("/api/workflow").get_json() == {"calculation": None}
    client.get("/settings")
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    assert client.post("/workflow/calculate", data={"csrf_token": csrf}).status_code == 302
    response = client.get("/api/workflow")
    assert response.status_code == 200 and response.get_json()["calculation"]["status"] == "ready"
    assert SECRET not in response.get_data(as_text=True)
    assert "synthetic-private-registry-value" not in response.get_data(as_text=True)


def test_invalid_workflow_settings_are_rejected_without_enabling_routing(setup):
    before = setup[1].read_json("automation_settings.json")
    for changes in ({"optimization_objective": "execute"}, {"averaging_window": "0"},
                    {"averaging_window": "1.5"}, {"monitoring_interval_seconds": "86401"}):
        from services.workflow_service import WorkflowError
        with pytest.raises(WorkflowError):
            setup[2].save_settings({"optimization_objective": "minimize_cost", "averaging_window": "3",
                                    "monitoring_interval_seconds": "10", **changes})
    assert setup[1].read_json("automation_settings.json") == before


def test_independent_aggregation_routers_never_transfer_demand_between_groups(setup):
    populate(setup)
    setup[1].update_json("routers.json", lambda rows: [*rows, {"router_id": "SIM-OTHER-AGG", "name": "Other aggregation"}])
    setup[1].update_json("routing_paths.json", lambda config: {**config, "paths": [
        {**path, "aggregation_router_id": "SIM-OTHER-AGG"} if path["carrier"] == "GLO" else path
        for path in config["paths"]]})
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "ready"
    assert {row["aggregation_router_id"]: row["demand_mbps"] for row in result["groups"]} == {"SIM-AGG": 60, "SIM-OTHER-AGG": 40}
    assert all(row["recommended_mbps"] == row["current_mbps"] for row in result["allocations"])


def test_new_series_after_disable_enable_cannot_reuse_old_average(setup):
    populate(setup)
    setup[2].calculate(now=NOW)
    service = RouterService(setup[1], setup[0].config)
    service.set_monitoring("SIM-MTN", False)
    service.set_monitoring("SIM-MTN", True)
    sample(setup, "SIM-MTN", NOW + timedelta(seconds=10), 1_000_000)
    sample(setup, "SIM-MTN", NOW + timedelta(seconds=20), 13_500_000)
    result = setup[2].calculate(now=NOW + timedelta(seconds=20))
    row = next(row for row in result["analysis"] if row["router_id"] == "SIM-MTN")
    assert row["sample_count"] == 1 and row["average_mbps"] is None


def test_results_and_cost_projections_survive_restart(setup, config):
    populate(setup)
    original = setup[2].calculate(now=NOW)
    restarted = create_device_app(config)
    current = WorkflowService(restarted.extensions["json_storage"], restarted.config).read_latest(now=NOW)
    assert current["evaluation_id"] == original["evaluation_id"] and current["is_current"] is True


@pytest.mark.parametrize("mutation", ["capacity", "demand", "mode", "unknown_field"])
def test_corrupt_ready_plan_is_rejected_before_persistence(setup, mutation):
    populate(setup)
    result = deepcopy(setup[2].calculate(now=NOW))
    if mutation == "capacity":
        result["allocations"][0]["recommended_mbps"] = 1000
    elif mutation == "demand":
        result["groups"][0]["demand_mbps"] = 1
    elif mutation == "mode":
        result["mode"] = "live"
    else:
        result["allocations"][0]["private_secret"] = SECRET
    with pytest.raises(ValidationError):
        setup[1].write_json("optimization_results.json", [result])


def test_settings_form_saves_objective_without_enabling_automation(setup, config):
    client = create_app(config).test_client()
    client.get("/settings")
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    data = {"optimization_objective": "balance_utilization", "averaging_window": "4", "monitoring_interval_seconds": "20"}
    assert client.post("/workflow/settings", data=data).status_code == 400
    assert client.post("/workflow/settings", data={**data, "csrf_token": csrf}).status_code == 302
    settings = setup[1].read_json("automation_settings.json")
    assert settings["optimization_objective"] == "balance_utilization" and settings["averaging_window"] == 4
    assert settings["automation"] == "off" and settings["routing_changes_enabled"] is False


def test_corrupt_calculation_returns_safe_json_and_is_not_reset(setup, config):
    client = create_app(config).test_client()
    path = setup[1].data_dir / "optimization_results.json"
    corrupt = [{"workflow_version": 1, "private_secret": "synthetic-corrupt-result"}]
    path.write_text(json.dumps(corrupt))
    response = client.get("/api/workflow")
    assert response.status_code == 503 and response.get_json() == {"error": "Calculation storage is unavailable."}
    assert "synthetic-corrupt-result" not in response.get_data(as_text=True)
    assert json.loads(path.read_text()) == corrupt


@pytest.mark.parametrize("api_state", ["untested", "blocked", "disconnected"])
def test_optional_api_diagnostic_cannot_block_fresh_authenticated_tx_analysis(setup, api_state):
    populate(setup)
    change_router(setup[1], "SIM-MTN", connection_status=api_state)
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "ready"
    assert "connection_unavailable" not in {item["code"] for item in result["issues"]}


def test_confirmed_8_and_4_gbps_links_balance_without_prices_and_conserve_demand(setup):
    populate(setup, (6000, 6000, 6000), (0, 0, 0))
    for router_id, capacity in (("SIM-MTN", 8000), ("SIM-GLO", 4000)):
        change_router(setup[1], router_id, capacity_mbps=capacity, capacity_confirmed=True,
                      cost_per_gb=None, currency="")
    setup[1].update_json("routing_paths.json", lambda routing: {**routing, "paths": [
        {**path, "path_capacity_bps": (8000 if path["carrier"] == "MTN" else 4000) * 1_000_000}
        for path in routing["paths"]]})
    setup[2].save_settings({"optimization_objective":"balance_utilization", "averaging_window":"3",
                            "monitoring_interval_seconds":"10"})
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "ready" and result["currency"] is None
    allocations = {r["carrier"]: r for r in result["allocations"]}
    assert allocations["MTN"]["recommended_mbps"] == pytest.approx(4000)
    assert allocations["GLO"]["recommended_mbps"] == pytest.approx(2000)
    assert sum(r["change_mbps"] for r in result["allocations"]) == pytest.approx(0)
    assert result["groups"][0]["available_mbps"] == 9600
    assert result["mode"] == "dry_run" and result["action"] == "none"
    assert result["routing_changes_enabled"] is False


def test_carrier_side_analysis_does_not_require_an_invented_aggregation_interface(setup):
    populate(setup)
    setup[1].update_json("routing_paths.json", lambda routing: {**routing, "paths": [
        {**path, "aggregation_interface":None, "configuration_status":"not_configured"}
        for path in routing["paths"]]})
    before = setup[1].read_json("routing_paths.json")
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "ready"
    assert all(r["interface"] == "synthetic-egress" for r in result["allocations"])
    assert setup[1].read_json("routing_paths.json") == before


def test_missing_carrier_measurement_interface_still_blocks_analysis(setup):
    populate(setup)
    setup[1].update_json("routing_paths.json", lambda routing: {**routing, "paths": [
        {**path, "carrier_interface":None, "configuration_status":"not_configured"}
        for path in routing["paths"]]})
    result = setup[2].calculate(now=NOW)
    assert result["status"] == "blocked"
    assert "path_incomplete" in {r["code"] for r in result["issues"]}


def test_carrier_recommendation_uses_selected_aggregation_side_counter(setup):
    populate(setup)
    setup[1].update_json("routers.json", lambda rows: [*rows, {
        "router_id":"NEW-CARRIER", "name":"Measured at aggregation", "carrier":"MTN",
        "capacity_mbps":100, "capacity_confirmed":True, "cost_per_gb":2, "currency":"NGN"}])
    setup[1].update_json("routing_paths.json", lambda routing: {**routing, "paths": [
        {**path, "aggregation_router_id":"SIM-MTN", **(
            {"carrier_router_id":"NEW-CARRIER", "aggregation_interface":"synthetic-egress"}
            if path["carrier"] == "MTN" else {})} for path in routing["paths"]]})
    preview = setup[2].preview(now=NOW)
    recommendation = next(row for row in preview["recommendations"] if row["router_id"] == "NEW-CARRIER")
    assert preview["status"] == "ready" and recommendation["status"] == "ready"
    assert recommendation["monitor_router_id"] == "SIM-MTN"
    assert recommendation["average_mbps"] == 60


def test_current_optimization_page_and_api_work_without_saving_a_snapshot(setup, config):
    populate(setup)
    storage = setup[1]
    before = {name:storage.read_json(name) for name in storage.DEFAULTS}
    client = create_app(config).test_client()
    response = client.get("/api/optimization")
    assert response.status_code == 200 and response.cache_control.no_store
    assert response.get_json()["calculation"]["status"] == "ready"
    page = client.get("/optimization").get_data(as_text=True)
    assert 'id="current-allocation"' in page and "Save calculation snapshot" in page
    assert 'data-endpoint="/api/optimization/live"' in page and 'http-equiv="refresh"' not in page
    assert SECRET not in page + response.get_data(as_text=True)
    assert {name:storage.read_json(name) for name in storage.DEFAULTS} == before


def test_optimization_does_not_round_small_actual_allocations_or_negative_changes_to_zero(setup, config):
    populate(setup, (0.0006, 0.0006, 0.0006), (0.0001, 0.0001, 0.0001))
    setup[2].save_settings({"optimization_objective":"balance_utilization", "averaging_window":"3",
                            "monitoring_interval_seconds":"10"})
    page = create_app(config).test_client().get("/optimization").get_data(as_text=True)
    assert "0.00035" in page and "-0.00025" in page
    assert "-0.000</td>" not in page


def test_current_optimization_api_keeps_browser_authentication_and_device_isolation(config):
    browser = create_app({**config, "AUTH_ENABLED":True, "ADMIN_USERNAME":"test-admin",
                          "ADMIN_PASSWORD_HASH":"synthetic-test-hash", "SECRET_KEY":"synthetic-session-key-for-optimization-test"})
    assert browser.test_client().get("/api/optimization").status_code == 401
    assert create_device_app(config).test_client().get("/api/optimization").status_code == 404


def test_legacy_objectives_respect_optimization_off_without_losing_measurements(setup,monkeypatch):
    from services.workflow_state import validate_workflow_result
    populate(setup)
    setup[2].set_optimization_enabled(False)
    monkeypatch.setattr('services.workflow_service.allocate_parallel_paths',lambda *a:pytest.fail('Legacy optimizer ran while off'))
    preview=setup[2].preview(now=NOW)
    assert preview['status']=='disabled' and not preview['allocations'] and not preview['recommendations']
    assert preview['analysis'] and any(r['current_mbps'] is not None for r in preview['analysis'])
    validate_workflow_result({k:v for k,v in preview.items() if k!='recommendations'})

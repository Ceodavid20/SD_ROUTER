"""Separate live TX and jitter plots share unchanged measured telemetry."""
from datetime import timedelta
from uuid import uuid4

import pytest

from app import create_app
from services.link_quality import DOCUMENT, _fingerprint
from services.optimization_graphs import live_view
from services.path_config_service import PathConfigService
from test_adaptive_routing import lab, populate, NOW


def add_quality(lab):
    lab[0].config["ROUTER_ALLOWED_NETWORKS"] = ["10.0.0.0/8"]
    storage = lab[1]
    paths = storage.read_json("routing_paths.json")["paths"]
    routers = {row["router_id"]: row for row in storage.read_json("routers.json")}
    for index, path in enumerate(paths):
        target = "10.8.0." + str(index+2)
        PathConfigService(storage).configure_jitter(path["path_id"], target, True, lab[0].config)
        path.update(jitter_target=target, jitter_enabled=True)
        series = str(uuid4())
        entry = {"fingerprint": _fingerprint(path, routers[path["aggregation_router_id"]], lab[0].config),
            "series_id": series, "next_probe_at": (NOW+timedelta(seconds=60)).isoformat().replace("+00:00", "Z"), "lease_id": None, "lease_until": None,
            "samples": [{"at": (NOW-timedelta(seconds=offset)).isoformat().replace("+00:00", "Z"),
                "series_id": series, "router_id": path["aggregation_router_id"], "interface": path["aggregation_interface"],
                "target": target, "status": "measured", "jitter_ms": jitter+index, "mean_rtt_ms": 4,
                "replies": 8, "probes_requested": 8, "adjacent_pairs": 7} for offset, jitter in ((10,1.234),(0,.456))]}
        storage.update_json(DOCUMENT, lambda state: {**state, "links": {**state["links"], path["path_id"]: entry}})


def test_separate_live_plots_contain_independent_tx_and_millisecond_jitter(lab):
    populate(lab)
    add_quality(lab)
    view = live_view(lab[1], lab[0].config, now=NOW)
    for index, series in enumerate(view["series"]):
        assert len(series["points"]) == 3
        assert "jitter_ms" not in series["points"][0]
        assert series["quality"]["current_jitter_ms"] == pytest.approx(.456+index)
        assert series["quality"]["points"][0]["jitter_ms"] == pytest.approx(1.234+index)
    client = create_app(lab[0].config).test_client()
    for url in ("/", "/optimization"):
        html = client.get(url).text
        assert html.count('id="tx-chart"') == 1
        assert html.count('id="jitter-chart"') == 1
        assert html.count('data-metric-panel=') == 2
        assert 'data-metric-panel="tx"' in html and 'data-metric-panel="jitter"' in html
        assert html.count('data-plot-range') == html.count('data-plot-follow') == 2
        assert 'data-jitter-toggle' not in html
    payload = client.get("/api/optimization/live").get_json()
    assert len(payload["series"][0]["quality"]["points"]) == 2


def test_missing_quality_is_unavailable_not_zero(lab):
    populate(lab)
    quality = live_view(lab[1], lab[0].config, now=NOW)["series"][0]["quality"]
    assert quality["state"] == "disabled" and quality["points"] == []
    assert quality["current_jitter_ms"] is None


def test_jitter_history_persists_without_changing_tx_series(lab):
    populate(lab)
    before = lab[1].list_traffic()
    add_quality(lab)
    restarted = create_app(lab[0].config)
    assert len(restarted.extensions["json_storage"].read_json(DOCUMENT)["links"]) == 2
    assert restarted.extensions["json_storage"].list_traffic() == before


def test_quality_page_has_explicit_csrf_protected_opt_in(lab):
    client = create_app(lab[0].config).test_client()
    html = client.get("/routing-paths").text
    assert 'name="jitter_target"' in html and 'name="jitter_enabled"' in html
    assert "Disabled" in html
    assert lab[0].test_client().get("/api/optimization/live").status_code == 404

"""The optional lab tool must use the controller's existing timestamp window."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest


@pytest.fixture
def tool(monkeypatch):
    path = Path(__file__).resolve().parents[1] / 'private/congestion-proof-20261124/run_proof.py'
    if not path.is_file():
        pytest.skip('Private optional lab tool is not installed in this checkout.')
    monkeypatch.setattr('socket.create_connection', lambda *a, **k: pytest.fail('Unexpected router contact'))
    spec = spec_from_file_location('optional_lab_congestion_preflight', path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('age,allowed', [(-31, False), (-30, True), (0, True), (37, True), (120, True), (121, False)])
def test_test_preflight_matches_existing_controller_freshness_window(tool, age, allowed):
    config = {'ROUTER_REQUEST_MAX_AGE_SECONDS': 120, 'ROUTER_CLOCK_SKEW_SECONDS': 30}
    assert tool.clock_ready(config, 1000-age, 1000) is allowed


def test_configured_clock_bounds_are_preserved(tool):
    config = {'ROUTER_REQUEST_MAX_AGE_SECONDS': 10, 'ROUTER_CLOCK_SKEW_SECONDS': 2}
    assert tool.clock_ready(config, 963, 1000) is False
    assert tool.clock_ready(config, 1003, 1000) is False


@pytest.mark.parametrize('field,value,reason', [('cpu_load', 71, 'CPU'), ('sessions', 1, 'another bandwidth test'),
    ('enabled', False, 'disabled'), ('authenticated', False, 'authentication'), ('epoch', 800, 'clock')])
def test_safety_failures_remain_blocked_with_actionable_safe_messages(tool, field, value, reason):
    item = {'cpu_load': 2, 'sessions': 0, 'enabled': True, 'authenticated': True, 'epoch': 1000}
    item[field] = value
    with pytest.raises(tool.LabTestError, match=reason):
        tool.validate_preflight('TEST-ROUTER', item, {}, 1000)

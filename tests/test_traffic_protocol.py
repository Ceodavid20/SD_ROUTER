"""Telemetry protocol tests use only synthetic keys and counters."""

import hashlib
import hmac
import json
from uuid import uuid4

import pytest

from services.router_protocol import ProtocolError
from services.routeros_protocol import ROUTEROS_TRAFFIC_PATH, sign_routeros_request
from services.traffic_protocol import parse_traffic_request


def payload(**changes):
    return {
        "protocol_version": "2.0", "router_id": "TEST-TX-R1",
        "request_id": str(uuid4()), "timestamp": 1795089600,
        "request_type": "traffic", "interface": "test-uplink", "tx_octets": 1000,
        **changes,
    }


def test_traffic_hmac_matches_independent_standard_construction():
    raw = json.dumps(payload(), separators=(",", ":")).encode()
    secret = "synthetic-traffic-test-key-0123456789"
    canonical = ("SDR-POLL-V2\nPOST\n/api/controller/v2/traffic\nPRIMARY\n"
                 + hashlib.sha512(raw).hexdigest()).encode("ascii")
    expected = hmac.new(secret.encode(), canonical, hashlib.sha512).hexdigest()
    assert sign_routeros_request(secret, raw, "PRIMARY", ROUTEROS_TRAFFIC_PATH) == expected
    assert sign_routeros_request(secret, raw, "PRIMARY") != expected


@pytest.mark.parametrize("counter", [0, 1, 2**64 - 1])
def test_cumulative_tx_accepts_exact_integer_counters(counter):
    body = payload(tx_octets=counter)
    assert parse_traffic_request(json.dumps(body).encode()) == body


@pytest.mark.parametrize("changes", [
    {"protocol_version": 2}, {"protocol_version": "1.0"}, {"request_type": "poll"},
    {"router_id": "../router"}, {"request_id": "invalid"},
    {"timestamp": True}, {"timestamp": 1.5}, {"timestamp": "1795089600"},
    {"timestamp": 0}, {"timestamp": 2**53},
    {"interface": ""}, {"interface": " uplink"}, {"interface": "uplink\n"},
    {"interface": ["ether1", "ether2"]}, {"interface": "x" * 129},
    {"interface": "bad\ud800"},
    {"tx_octets": True}, {"tx_octets": 1.0}, {"tx_octets": "1000"},
    {"tx_octets": -1}, {"tx_octets": 2**64},
    {"rx_octets": 12}, {"RX": 12}, {"interfaces": []}, {"configuration": {}},
])
def test_invalid_or_non_tx_payload_is_rejected(changes):
    with pytest.raises(ProtocolError):
        parse_traffic_request(json.dumps(payload(**changes)).encode())


@pytest.mark.parametrize("raw", [
    b"", b"[]", b"null", b"{", b"\xff", b" " * 8193,
    b'{"timestamp":NaN}', b'{"timestamp":Infinity}',
    b'{"interface":"a","interface":"a"}', b"[" * 1100 + b"]" * 1100,
])
def test_malformed_json_is_rejected(raw):
    with pytest.raises(ProtocolError):
        parse_traffic_request(raw)

def test_missing_field_is_rejected():
    body = payload()
    del body["tx_octets"]
    with pytest.raises(ProtocolError):
        parse_traffic_request(json.dumps(body).encode())

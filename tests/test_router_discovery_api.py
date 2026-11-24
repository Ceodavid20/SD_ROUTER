"""Native discovery framing, feature selection and output projection."""
import pytest
from services.routeros_api import RouterOSReadOnlyClient, RouterAPIError, encode_length


def sentence(*words):
    return b"".join(encode_length(len(word.encode())) + word.encode() for word in words) + b"\0"


class Socket:
    def __init__(self, data):
        self.data, self.sent, self.closed = bytearray(data), bytearray(), False
    def recv(self, count):
        count = min(3, count, len(self.data))
        chunk = bytes(self.data[:count]); del self.data[:count]
        return chunk
    def settimeout(self, value):
        assert value > 0
    def sendall(self, data):
        self.sent.extend(data)
    def close(self):
        self.closed = True


@pytest.mark.parametrize("version", ["6.49.18", "7.21.4", "8.0rc1"])
def test_readonly_discovery_selects_versioned_menus_and_drains_traps(monkeypatch, version):
    major = version[0]
    reply = sentence("!done")
    reply += sentence("!re", "=version=" + version, "=board-name=synthetic", "=architecture-name=arm64", "=password=must-not-return", "=rx-byte=123") + sentence("!done")
    for key in RouterOSReadOnlyClient.READS:
        if key in ("resource", "tx") or (key in ("tables", "ospf_templates") and major != "7") or (key == "ospf_interfaces_v6" and major != "6"):
            continue
        if key == "mangle":
            reply += sentence("!trap", "=message=synthetic-device-private-message") + sentence("!done")
        elif key == "interfaces":
            reply += sentence("!re", "=name=wan-custom", "=type=ether", "=rx-byte=111", "=source=must-not-return") + sentence("!done")
        else:
            reply += sentence("!done")
    reply += sentence("!re", "=name=wan-custom", "=tx-byte=123456", "=rx-byte=999") + sentence("!done")
    connection = Socket(reply)
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: connection)
    client = RouterOSReadOnlyClient("10.73.0.8", 9876, "synthetic-user", "synthetic-pass", tls=False)
    result = client.read_discovery(["wan-custom"])
    assert result["mangle"] == {"status": "unavailable", "rows": []}
    assert result["interfaces"]["rows"] == [{"name": "wan-custom", "type": "ether"}]
    assert result["tx"]["wan-custom"]["rows"] == [{"name": "wan-custom", "tx-byte": "123456"}]
    assert result["resource"]["rows"][0] == {"version": version, "board-name": "synthetic", "architecture-name": "arm64"}
    assert result["ospf_templates"]["status"] == ("observed" if major == "7" else "not_probed")
    assert result["ospf_interfaces_v6"]["status"] == ("observed" if major == "6" else "not_probed")
    assert b"rx-byte" not in connection.sent and connection.closed
    assert b"/set" not in connection.sent and b"/add" not in connection.sent


@pytest.mark.parametrize("words", [["/system/script/run", "=.id=*A"], ["/ip/route/set", "=distance=1"],
    ["/interface/print"], ["/interface/print", "=.proplist=name,rx-byte"],
    ["/system/resource/print", "=.proplist=board-name,version,uptime,cpu-load", "=file=exfiltration"],
    ["/interface/print", "=.proplist=.id,name,tx-byte"],
    ["/interface/print", "=.proplist=.id,name,tx-byte", "?name=wan\n=disabled=no"]])
def test_discovery_command_allowlist_rejects_writes_rx_and_unrestricted_reads(words):
    client = RouterOSReadOnlyClient("10.73.0.8", 9876, "test", "test", tls=False)
    with pytest.raises(RouterAPIError, match="allowlisted"):
        client._talk(words)

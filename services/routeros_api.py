"""Small, read-only RouterOS native API client.

Framing follows MikroTik's published API protocol. The only device commands
implemented are login and explicitly projected read-only print operations.
No routing or other configuration command can be submitted by a caller.
"""

from __future__ import annotations

import socket
import ssl
import time
from contextlib import contextmanager
from typing import Any


class RouterAPIError(Exception):
    """A safe, credential-free error suitable for an administrator."""


class RouterAPIMenuUnavailable(RouterAPIError):
    """A menu was rejected; support/permission cannot safely be inferred."""


def encode_length(value: int) -> bytes:
    """Encode a word byte count using RouterOS's variable-length prefix."""
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Invalid API word length.")
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return (value | 0x8000).to_bytes(2, "big")
    if value < 0x200000:
        return (value | 0xC00000).to_bytes(3, "big")
    if value < 0x10000000:
        return (value | 0xE0000000).to_bytes(4, "big")
    return b"\xf0" + value.to_bytes(4, "big")


class RouterOSReadOnlyClient:
    """Authenticate and fetch basic resource information from one router."""

    _MAX_WORD_BYTES = 64 * 1024
    _MAX_REPLY_BYTES = 1024 * 1024
    _MAX_SENTENCES = 128
    _MAX_WORDS = 256
    READS = {
        "resource": ("/system/resource/print", "board-name,version,architecture-name,uptime,cpu-load"),
        "interfaces": ("/interface/print", ".id,name,type,running,disabled"),
        "tables": ("/routing/table/print", ".id,name,fib,disabled"),
        "ospf_instances": ("/routing/ospf/instance/print", ".id,name,version,disabled,routing-table"),
        "ospf_areas": ("/routing/ospf/area/print", ".id,name,instance,area-id,disabled"),
        "ospf_templates": ("/routing/ospf/interface-template/print", ".id,interfaces,networks,area,cost,disabled"),
        "ospf_interfaces_v6": ("/routing/ospf/interface/print", ".id,interface,cost,network-type,passive,disabled"),
        "mangle": ("/ip/firewall/mangle/print", ".id,chain,action,disabled,connection-mark,new-connection-mark,routing-mark,new-routing-mark,per-connection-classifier,passthrough,in-interface,out-interface"),
        "routes": ("/ip/route/print", ".id,dst-address,gateway,distance,routing-table,routing-mark,disabled,dynamic,static"),
        "fasttrack": ("/ip/firewall/filter/print", ".id,chain,action,disabled,hw-offload,connection-mark"),
        "bridge_ports": ("/interface/bridge/port/print", ".id,interface,bridge,hw,hw-offload,disabled"),
        "switches": ("/interface/ethernet/switch/print", ".id,name,type,l3-hw-offloading"),
        "tx": ("/interface/print", ".id,name,tx-byte"),
    }

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        *,
        tls: bool = True,
        timeout: float = 3,
        ca_file: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self._username = username
        self._password = password
        self.tls = tls
        self.timeout = timeout
        self.ca_file = ca_file
        self._socket: Any = None
        self._deadline = 0.0
        self._received = 0

    def _remaining(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise RouterAPIError("Router API request timed out.")
        return remaining

    def _read_exact(self, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            self._socket.settimeout(self._remaining())
            chunk = self._socket.recv(count - len(chunks))
            if not chunk:
                raise RouterAPIError("Router closed the API connection before completing its reply.")
            chunks.extend(chunk)
            self._received += len(chunk)
            if self._received > self._MAX_REPLY_BYTES:
                raise RouterAPIError("Router API reply exceeded the permitted size.")
        return bytes(chunks)

    def _read_length(self) -> int:
        first = self._read_exact(1)[0]
        if first < 0x80:
            result = first
        elif first < 0xC0:
            result = ((first & 0x3F) << 8) | int.from_bytes(self._read_exact(1), "big")
        elif first < 0xE0:
            result = ((first & 0x1F) << 16) | int.from_bytes(self._read_exact(2), "big")
        elif first < 0xF0:
            result = ((first & 0x0F) << 24) | int.from_bytes(self._read_exact(3), "big")
        elif first == 0xF0:
            result = int.from_bytes(self._read_exact(4), "big")
        else:
            raise RouterAPIError("Router returned an unsupported API control byte.")
        if result > self._MAX_WORD_BYTES:
            raise RouterAPIError("Router API word exceeded the permitted size.")
        return result

    def _read_sentence(self) -> list[str]:
        sentence = []
        for _ in range(self._MAX_WORDS):
            length = self._read_length()
            if not length:
                return sentence
            try:
                sentence.append(self._read_exact(length).decode("utf-8"))
            except UnicodeError as exc:
                raise RouterAPIError("Router returned an invalid API text value.") from exc
        raise RouterAPIError("Router API sentence exceeded the permitted size.")

    def _talk(self, words: list[str]) -> list[dict[str, str]]:
        allowed = [(command, "=.proplist=" + fields) for key, (command, fields) in self.READS.items() if key != "tx"]
        allowed.append(("/system/resource/print", "=.proplist=board-name,version,uptime,cpu-load"))
        login = (len(words) == 3 and words[0] == "/login" and words[1].startswith("=name=")
                 and words[2].startswith("=password="))
        printing = len(words) == 2 and tuple(words) in allowed
        selected_tx = (len(words) == 3 and tuple(words[:2]) ==
                       (self.READS["tx"][0], "=.proplist=" + self.READS["tx"][1])
                       and words[2].startswith("?name=") and 0 < len(words[2][6:]) <= 128
                       and all(ord(c) >= 32 and ord(c) != 127 for c in words[2][6:]))
        if not (login or printing or selected_tx):
            raise RouterAPIError("Only allowlisted read-only discovery is supported.")
        fields = set(words[1].removeprefix("=.proplist=").split(",")) if not login else set()
        return self._exchange(words, fields)

    def _exchange(self, words, fields):
        """Bounded protocol framing after a caller's fixed command allowlist."""
        encoded = bytearray()
        for word in words:
            value = word.encode("utf-8")
            if len(value) > self._MAX_WORD_BYTES:
                raise RouterAPIError("API request word is too large.")
            encoded.extend(encode_length(len(value)))
            encoded.extend(value)
        encoded.append(0)
        self._socket.settimeout(self._remaining())
        self._socket.sendall(encoded)
        rows, trapped = [], False
        for _ in range(self._MAX_SENTENCES):
            sentence = self._read_sentence()
            if not sentence:
                continue
            attributes = {}
            for word in sentence[1:]:
                if word.startswith("=") and "=" in word[1:]:
                    key, value = word[1:].split("=", 1)
                    attributes[key] = value
            if sentence[0] == "!fatal":
                # Device-provided errors may echo arguments; do not expose them.
                raise RouterAPIError("Router rejected the API request. Check account permissions and credentials.")
            if sentence[0] == "!trap":
                # Drain through !done before another read on this connection.
                trapped = True
                continue
            if sentence[0] == "!done":
                if trapped:
                    raise RouterAPIMenuUnavailable("Read-only menu unavailable or not permitted.")
                if "ret" in attributes:
                    raise RouterAPIError("Legacy RouterOS API authentication is not supported.")
                return rows
            if sentence[0] == "!re":
                # The API may return extra fields despite .proplist. Project
                # immediately: secrets, RX and script sources never leave here.
                rows.append({key: value[:256] for key, value in attributes.items() if key in fields})
            elif sentence[0] != "!empty":
                raise RouterAPIError("Router returned an unexpected API reply.")
        raise RouterAPIError("Router API reply exceeded the permitted number of sentences.")

    def read_resource(self) -> dict[str, str]:
        """Use a verified connection to read the model, version, and uptime."""
        def read():
            rows = self._talk(["/system/resource/print", "=.proplist=board-name,version,uptime,cpu-load"])
            if len(rows) != 1 or not rows[0].get("version"):
                raise RouterAPIError("Router did not return the expected resource information.")
            return {key: value[:256] for key, value in rows[0].items()
                    if key in ("board-name", "version", "uptime", "cpu-load")}
        return self._read(read)

    def read_discovery(self, interfaces=()):
        """A bounded read-only snapshot. Rejected menus remain explicitly unknown."""
        from services.traffic_protocol import validate_interface
        if len(interfaces) > 16:
            raise RouterAPIError("Too many selected TX interfaces.")
        for name in interfaces:
            validate_interface(name)

        def read():
            result = {}
            def menu(key, suffix=()):
                command, fields = self.READS[key]
                try:
                    rows = self._talk([command, "=.proplist=" + fields, *suffix])
                except RouterAPIMenuUnavailable:
                    return {"status": "unavailable", "rows": []}
                return {"status": "observed", "rows": rows}

            result["resource"] = menu("resource")
            resources = result["resource"]["rows"]
            if len(resources) != 1 or not resources[0].get("version"):
                raise RouterAPIError("Router did not return discovery resource information.")
            version = resources[0]["version"].split(".", 1)[0]
            for key in self.READS:
                if key in ("resource", "tx"):
                    continue
                if ((key in ("tables", "ospf_templates") and version != "7")
                        or (key == "ospf_interfaces_v6" and version != "6")):
                    result[key] = {"status": "not_probed", "rows": []}
                else:
                    result[key] = menu(key)
            result["tx"] = {name: menu("tx", ("?name=" + name,)) for name in interfaces}
            return result
        return self._read(read)

    def _read(self, operation):
        """One verified, authenticated connection with a total byte/time budget."""
        with self._session():
            return operation()

    @contextmanager
    def _session(self):
        """Private transport lifetime; callers retain the fixed read allowlist."""
        connection = None
        self._deadline = time.monotonic() + self.timeout
        self._received = 0
        try:
            try:
                connection = socket.create_connection((self.host, self.port), timeout=self._remaining())
            except ConnectionRefusedError as exc:
                raise RouterAPIError(
                    f"Router API connection refused on TCP port {self.port}. "
                    "Check that the matching service is enabled and reachable from this computer."
                ) from exc
            if self.tls:
                try:
                    context = ssl.create_default_context(cafile=self.ca_file)
                except (OSError, ssl.SSLError) as exc:
                    raise RouterAPIError(
                        "The controller could not load trusted router CA certificates. "
                        "Check SDR_ROUTER_CA_FILE on this computer."
                    ) from exc
                connection.settimeout(self._remaining())
                try:
                    connection = context.wrap_socket(connection, server_hostname=self.host)
                except ssl.SSLCertVerificationError:
                    raise
                except (ssl.SSLError, ConnectionResetError, ConnectionAbortedError) as exc:
                    raise RouterAPIError(
                        f"Router API-SSL handshake failed on TCP port {self.port}. "
                        "In WinBox > IP > Services, confirm api-ssl is enabled on this port "
                        "with a certificate selected. The plain api service cannot accept TLS."
                    ) from exc
            self._socket = connection
            self._talk(["/login", "=name=" + self._username, "=password=" + self._password])
            yield self
        except ssl.SSLCertVerificationError as exc:
            raise RouterAPIError(
                "Router TLS certificate verification failed. Configure the trusted router CA "
                "and ensure the certificate covers the router management address."
            ) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise RouterAPIError("Router API request timed out.") from exc
        except (OSError, ssl.SSLError) as exc:
            raise RouterAPIError("Router API connection failed. Check the address, service, firewall, and TLS settings.") from exc
        finally:
            if connection is not None:
                connection.close()
            self._socket = None

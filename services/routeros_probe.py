"""Restricted active ICMP probes over the existing verified management channel.

No RX counters or configuration commands. An interface is always explicit.
"""
from ipaddress import ip_address
import re

from services.routeros_api import RouterAPIError, RouterOSReadOnlyClient
from services.traffic_protocol import validate_interface


def probe_address(value):
    if not isinstance(value, str) or not value or len(value) > 45 or "%" in value:
        raise ValueError("Enter a literal jitter target IPv4 or IPv6 address.")
    try:
        address = ip_address(value)
    except (ValueError, TypeError) as exc:
        raise ValueError("Enter a literal jitter target IPv4 or IPv6 address.") from exc
    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
        raise ValueError("Use a unicast jitter target reachable through the selected carrier interface.")
    return str(address)


def rtt_milliseconds(value):
    """Parse RouterOS duration text, never guess units for bare numbers."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Invalid RTT duration.")
    clock = re.fullmatch(r"(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?", value)
    if clock:
        hours, minutes, seconds, fraction = clock.groups()
        if int(minutes) >= 60 or int(seconds) >= 60:
            raise ValueError("Invalid RTT duration.")
        result = (int(hours) * 3600 + int(minutes) * 60 + int(seconds)) * 1000 + float("0." + (fraction or "0")) * 1000
    else:
        parts = list(re.finditer(r"(\d+(?:\.\d+)?)(ms|us|ns|s)", value))
        if not parts or "".join(part.group() for part in parts) != value:
            raise ValueError("Invalid RTT duration.")
        factors = {"s": 1000, "ms": 1, "us": .001, "ns": .000001}
        units = [part[2] for part in parts]
        if len(set(units)) != len(units) or units != sorted(units, key=lambda unit: -factors[unit]):
            raise ValueError("Invalid RTT duration.")
        result = sum(float(part[1]) * factors[part[2]] for part in parts)
    if not 0 <= result <= 60_000:
        raise ValueError("RTT duration is outside the supported range.")
    return result


class RouterOSProbeClient(RouterOSReadOnlyClient):
    READS = {**RouterOSReadOnlyClient.READS,
             "interface_addresses": ("/ip/address/print", "address,interface,disabled")}

    def _talk(self, words):
        if words and words[0] == "/ping":
            if (len(words) != 5 or not words[1].startswith("=address=")
                    or not words[2].startswith("=interface=") or words[3] != "=count=8"
                    or words[4] not in ("=interval=200ms", "=interval=50ms")):
                raise RouterAPIError("Only bounded interface-specific RTT probes are supported.")
            try:
                probe_address(words[1][9:])
                validate_interface(words[2][11:])
            except ValueError as exc:
                raise RouterAPIError("Invalid RTT probe settings.") from exc
            return self._exchange(words, {"seq", "time", "status"})
        return super()._talk(words)

    def ping(self, target, interface):
        target = probe_address(target)
        validate_interface(interface)
        rows = self._read(lambda: self._talk(["/ping", "=address=" + target,
            "=interface=" + interface, "=count=8", "=interval=200ms"]))
        return self.samples(rows)

    @staticmethod
    def samples(rows):
        # Return one slot per sent probe. Lost/invalid/missing replies remain
        # gaps, so they cannot fabricate zero jitter or bridge adjacent pairs.
        samples = [None] * 8
        seen = set()
        for row in rows:
            seq = row.get("seq", "")
            if not re.fullmatch(r"[0-7]", seq):
                continue
            index = int(seq)
            if index in seen:
                raise RouterAPIError("Router returned duplicate RTT probe replies.")
            seen.add(index)
            if row.get("status"):
                continue
            try:
                samples[index] = rtt_milliseconds(row.get("time"))
            except ValueError:
                continue
        if not seen:
            raise RouterAPIError("Router did not return individual RTT probe replies.")
        return samples

    def interface_addresses(self):
        command, fields = self.READS["interface_addresses"]
        return self._read(lambda: self._talk([command, "=.proplist=" + fields]))

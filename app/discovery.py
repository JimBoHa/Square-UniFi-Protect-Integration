"""LAN discovery of UniFi consoles via the Ubiquiti discovery protocol.

Ubiquiti devices answer a UDP probe (``01 00 00 00``) on port 10001 with a
TLV payload describing the device. Consoles on the same broadcast domain are
found automatically; consoles on routed VLANs (which often ignore broadcast
probes entirely) can still be identified with a unicast probe of a specific
address, which the settings UI uses as a "verify this IP" helper.

Verified against a real UNVR (Protect 7.1.87) and G6/UAP-Bridge accessories.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import time

DISCOVERY_PORT = 10001
DISCOVERY_PROBE = b"\x01\x00\x00\x00"

_TLV_HOSTNAME = 0x0B
_TLV_FRIENDLY_NAME = 0x06
_TLV_MODEL_SHORT = 0x0C
_TLV_MODEL_FULL = 0x14
_TLV_FIRMWARE = 0x03

# Model prefixes for UniFi OS consoles capable of running Protect, as opposed
# to accessories (cameras, bridges, APs) that also answer discovery.
_CONSOLE_MODEL_PREFIXES = (
    "UNVR",
    "UDM",
    "UDR",
    "UDW",
    "UCK",
    "UCG",
    "UX",
    "UNAS",
)


def parse_discovery_response(data: bytes, source_ip: str) -> dict | None:
    """Parse one TLV discovery response into a device description."""
    if len(data) < 8:
        return None
    if data[:2] != DISCOVERY_PROBE[:2]:
        return None
    declared_payload_length = struct.unpack(">H", data[2:4])[0]
    if declared_payload_length != len(data) - 4:
        return None
    device: dict = {"ip": source_ip}
    index = 4
    while index < len(data):
        if index + 3 > len(data):
            return None
        tlv_type = data[index]
        length = struct.unpack(">H", data[index + 1 : index + 3])[0]
        value = data[index + 3 : index + 3 + length]
        if len(value) != length:
            return None
        if tlv_type == _TLV_FRIENDLY_NAME:
            device["name"] = value.decode(errors="replace")
        elif tlv_type == _TLV_HOSTNAME:
            device.setdefault("name", value.decode(errors="replace"))
            device["hostname"] = value.decode(errors="replace")
        elif tlv_type == _TLV_MODEL_SHORT:
            device["model"] = value.decode(errors="replace")
        elif tlv_type == _TLV_MODEL_FULL:
            device.setdefault("model", value.decode(errors="replace"))
        elif tlv_type == _TLV_FIRMWARE:
            device["firmware"] = value.decode(errors="replace")
        index += 3 + length
    if "name" not in device and "model" not in device:
        return None
    device.setdefault("name", device.get("hostname", source_ip))
    device.setdefault("model", "")
    device["is_console"] = device["model"].upper().startswith(
        _CONSOLE_MODEL_PREFIXES
    )
    return device


def _local_networks() -> list[ipaddress.IPv4Network]:
    """Best-effort local IPv4 /24s, learned from a routed UDP socket."""
    networks = []
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("198.51.100.1", 9))  # no packets are sent
        local_ip = probe.getsockname()[0]
        networks.append(
            ipaddress.ip_network(f"{local_ip}/24", strict=False)
        )
    except OSError:
        pass
    finally:
        probe.close()
    return networks


def discover_consoles(
    timeout: float = 2.5,
    extra_hosts: tuple[str, ...] = (),
    sweep_local_subnet: bool = True,
) -> list[dict]:
    """Find UniFi devices; consoles sort first.

    Broadcast reaches devices that answer it; some UniFi OS consoles only
    answer unicast, so the local /24 is also swept with unicast probes, and
    ``extra_hosts`` lets the caller probe a specific (possibly routed)
    address directly.
    """
    timeout = max(0.5, min(float(timeout), 10.0))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.2)

    try:
        for _ in range(3):
            try:
                sock.sendto(DISCOVERY_PROBE, ("255.255.255.255", DISCOVERY_PORT))
            except OSError:
                break
        for host in extra_hosts:
            try:
                sock.sendto(DISCOVERY_PROBE, (host, DISCOVERY_PORT))
            except OSError:
                continue
        if sweep_local_subnet:
            for network in _local_networks():
                for address in network.hosts():
                    try:
                        sock.sendto(
                            DISCOVERY_PROBE, (str(address), DISCOVERY_PORT)
                        )
                    except OSError:
                        break

        devices: dict[str, dict] = {}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            parsed = parse_discovery_response(data, addr[0])
            if parsed:
                devices[addr[0]] = parsed
    finally:
        sock.close()

    return sorted(
        devices.values(),
        key=lambda d: (not d["is_console"], d["name"].lower()),
    )

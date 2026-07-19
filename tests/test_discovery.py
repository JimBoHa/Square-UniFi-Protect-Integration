"""Discovery protocol tests, including a real UNVR response fixture."""

import pytest

from app.discovery import discover_consoles, parse_discovery_response

# Captured verbatim from a UNVR (model UNVRAI4, Protect 7.1.87) answering the
# UDP discovery probe on port 10001.
REAL_UNVR_RESPONSE = bytes.fromhex(
    "010001b202000a8cede1ea2e600aff075b2f000a8cede1ea2e5f0aff075b0100068cede1ea2e5f3200368cede1ea2e5f000000007b2274797065223a2257414e222c226e616d65223a2265746830222c22706c7567676564223a66616c73657d3200368cede1ea2e600aff075b7b2274797065223a2257414e32222c226e616d65223a2265746831222c22706c7567676564223a747275657d300032386365646531656132653566306132353661303330616237306665343036613134643535382e69642e75692e6469726563740b000f554e56522d436f6173742d526f616406000f554e565220436f61737420526f61640c0007554e56524149340e0001010d0000030006352e312e31392000473843454445314541324535463030303030303030304132353641303330303030303030303041423730464534303030303030303036413134443535383a313436303438343831300a0004002621a7170001002b002439313064626437342d313138302d343766332d386436362d61303434666662356664623133002434333533663361622d303133652d333565392d613062362d3338396635333539306535360f000400001ba8"
)


def _response(*tlvs: bytes) -> bytes:
    payload = b"".join(tlvs)
    return b"\x01\x00" + len(payload).to_bytes(2, "big") + payload


def test_parse_real_unvr_response():
    device = parse_discovery_response(REAL_UNVR_RESPONSE, "10.255.7.91")
    assert device == {
        "ip": "10.255.7.91",
        "name": "UNVR Coast Road",
        "hostname": "UNVR-Coast-Road",
        "model": "UNVRAI4",
        "firmware": "5.1.19",
        "is_console": True,
    }

def test_parse_rejects_garbage():
    assert parse_discovery_response(b"", "10.0.0.1") is None
    assert parse_discovery_response(b"\x01\x00\x00\x00", "10.0.0.1") is None
    assert parse_discovery_response(b"\xff" * 40, "10.0.0.1") is None

def test_parse_accessory_is_not_console():
    payload = _response(
        bytes([0x0B, 0x00, 0x04]) + b"Gate",
        bytes([0x0C, 0x00, 0x09]) + b"UFP-UAP-B",
    )
    device = parse_discovery_response(payload, "10.0.0.9")
    assert device["is_console"] is False
    assert device["model"] == "UFP-UAP-B"

def test_truncated_tlv_does_not_crash():
    payload = _response(bytes([0x0B, 0x00, 0x40]) + b"short")
    assert parse_discovery_response(payload, "10.0.0.9") is None


def test_parse_rejects_wrong_protocol_header_and_declared_length():
    valid = _response(
        bytes([0x0B, 0x00, 0x04]) + b"UNVR",
        bytes([0x0C, 0x00, 0x04]) + b"UNVR",
    )
    assert parse_discovery_response(b"EV" + valid[2:], "10.0.0.9") is None
    assert parse_discovery_response(valid[:2] + b"\x00\x00" + valid[4:], "10.0.0.9") is None
    assert parse_discovery_response(valid[:-1], "10.0.0.9") is None

def test_discover_endpoint_requires_auth(client):
    assert client.post("/api/discover/protect", json={}).status_code == 401

def test_discover_endpoint_validates_host(authed, monkeypatch):
    monkeypatch.setattr(
        "app.discovery.discover_consoles", lambda extra_hosts=(): []
    )
    assert authed.post("/api/discover/protect", json={"host": "evil.com/path"}).status_code == 422

def test_discover_endpoint_passes_probe_host(authed, monkeypatch):
    captured = {}

    def fake_discover(extra_hosts=()):
        captured["extra"] = extra_hosts
        return [
            {
                "ip": "10.255.7.91",
                "name": "UNVR Coast Road",
                "model": "UNVRAI4",
                "is_console": True,
            }
        ]

    monkeypatch.setattr("app.discovery.discover_consoles", fake_discover)
    resp = authed.post("/api/discover/protect", json={"host": "10.255.7.91:443"})
    assert resp.status_code == 200
    assert captured["extra"] == ("10.255.7.91",)
    assert resp.json()[0]["name"] == "UNVR Coast Road"

def test_discovery_ui_wiring():
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "app" / "static"
    js = (static_dir / "app.js").read_text(encoding="utf-8")
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    assert 'id="protect-discover"' in html
    assert "/api/discover/protect" in js

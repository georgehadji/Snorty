"""Turn `tshark -T json -x` output into PacketView data. Pure; the output is untrusted."""

import json
from typing import Any

from snorty.packets.models import Layer, PacketView

MAX_PACKETS = 1000
MAX_LAYERS = 20
MAX_FIELDS = 60
MAX_DEPTH = 3
MAX_TEXT = 200
MAX_HEX_BYTES = 2048


class ParseError(ValueError):
    """The output was not the JSON shape tshark produces."""


def _text(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(_text(v) for v in value[:8])[:MAX_TEXT]
    return str(value)[:MAX_TEXT]


def _int(value: object) -> int:
    try:
        return int(str(value))
    except ValueError:
        return 0


def _flatten(node: dict[str, Any], depth: int, out: list[tuple[str, str]]) -> None:
    for key, value in node.items():
        if len(out) >= MAX_FIELDS:
            return
        if str(key).endswith("_raw"):
            continue
        if isinstance(value, dict):
            if depth < MAX_DEPTH:
                _flatten(value, depth + 1, out)
        else:
            out.append((str(key)[:80], _text(value)))


def _endpoints(layers: dict[str, Any]) -> tuple[str, str]:
    for proto in ("ip", "ipv6", "eth"):
        layer = layers.get(proto)
        if isinstance(layer, dict) and f"{proto}.src" in layer:
            return _text(layer[f"{proto}.src"]), _text(layer.get(f"{proto}.dst", ""))
    return "", ""


def _info(layers: dict[str, Any]) -> str:
    def get(proto: str, key: str) -> str:
        layer = layers.get(proto)
        return _text(layer[key]) if isinstance(layer, dict) and key in layer else ""

    if "dns" in layers and (name := get("dns", "dns.qry.name")):
        return f"DNS {name}"
    if "http" in layers:
        if method := get("http", "http.request.method"):
            return f"{method} {get('http', 'http.request.uri')}".strip()
        if code := get("http", "http.response.code"):
            return f"HTTP {code}"
    for proto in ("tcp", "udp"):
        if proto in layers:
            return f"{get(proto, f'{proto}.srcport')} \u2192 {get(proto, f'{proto}.dstport')}"
    if "icmp" in layers:
        return f"type {get('icmp', 'icmp.type')} code {get('icmp', 'icmp.code')}"
    return ""


def hexdump(hex_text: str) -> str:
    """The classic 16-bytes-per-row dump of a hex string, capped."""
    try:
        data = bytes.fromhex(hex_text)[:MAX_HEX_BYTES]
    except ValueError:
        return ""
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexes = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{i:04x}  {hexes:<47}  {text}")
    return "\n".join(rows)


def _packet(item: object) -> PacketView:
    try:
        layers = item["_source"]["layers"]  # type: ignore[index]
    except (KeyError, TypeError) as exc:
        raise ParseError("tshark output is missing the packet layers") from exc
    if not isinstance(layers, dict):
        raise ParseError("tshark output has an unexpected packet shape")
    frame = layers.get("frame")
    frame = frame if isinstance(frame, dict) else {}
    shown: list[Layer] = []
    for name, body in layers.items():
        if len(shown) >= MAX_LAYERS:
            break
        if str(name).endswith("_raw") or not isinstance(body, dict):
            continue
        fields: list[tuple[str, str]] = []
        _flatten(body, 1, fields)
        shown.append(Layer(str(name)[:40], tuple(fields)))
    protocols = _text(frame.get("frame.protocols", "")).split(":")
    raw = layers.get("frame_raw")
    src, dst = _endpoints(layers)
    return PacketView(
        number=_int(frame.get("frame.number")),
        time=_text(frame.get("frame.time_relative", "")),
        protocol=(protocols[-1] or "?").upper(),
        src=src,
        dst=dst,
        length=_int(frame.get("frame.len")),
        info=_info(layers),
        layers=tuple(shown),
        hexdump=hexdump(raw[0])
        if isinstance(raw, list) and raw and isinstance(raw[0], str)
        else "",
    )


def parse_packets(text: str) -> tuple[PacketView, ...]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ParseError("tshark did not return readable JSON") from exc
    if not isinstance(data, list):
        raise ParseError("tshark output is not a list of packets")
    return tuple(_packet(item) for item in data[:MAX_PACKETS])

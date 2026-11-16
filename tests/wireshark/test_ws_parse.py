import json

import pytest

from snorty.wireshark.parse import (
    MAX_FIELDS,
    MAX_HEX_BYTES,
    MAX_LAYERS,
    MAX_TEXT,
    ParseError,
    hexdump,
    parse_packets,
)

ICMP = {
    "_index": "packets-2026",
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "1",
                "frame.time_relative": "0.000000000",
                "frame.len": "74",
                "frame.protocols": "eth:ethertype:ip:icmp:data",
            },
            "eth": {"eth.src": "aa:bb:cc:dd:ee:01", "eth.dst": "aa:bb:cc:dd:ee:02"},
            "ip": {"ip.src": "192.168.10.1", "ip.dst": "192.168.10.230", "ip.ttl": "64"},
            "icmp": {"icmp.type": "8", "icmp.code": "0"},
            "frame_raw": ["4500003c", 0, 4, 0, 1],
        }
    },
}
TCP = {
    "_source": {
        "layers": {
            "frame": {"frame.number": "2", "frame.len": "60", "frame.protocols": "eth:ip:tcp"},
            "ip": {"ip.src": "10.0.0.5", "ip.dst": "10.0.0.9"},
            "tcp": {
                "tcp.srcport": "40000",
                "tcp.dstport": "80",
                "tcp.flags_tree": {"tcp.flags.syn": "1"},
            },
        }
    }
}


def test_a_packet_becomes_a_view_with_summary_columns() -> None:
    (p,) = parse_packets(json.dumps([ICMP]))
    assert (p.number, p.src, p.dst, p.length) == (1, "192.168.10.1", "192.168.10.230", 74)
    assert p.protocol == "DATA" and p.info == "type 8 code 0"
    assert [layer.name for layer in p.layers] == ["frame", "eth", "ip", "icmp"]
    assert ("ip.ttl", "64") in p.layers[2].fields
    assert p.hexdump.startswith("0000  45 00 00 3c")


def test_tcp_info_shows_ports_and_nested_fields_are_flattened() -> None:
    (p,) = parse_packets(json.dumps([TCP]))
    assert p.info == "40000 \u2192 80"
    assert ("tcp.flags.syn", "1") in p.layers[-1].fields


def test_missing_pieces_give_blanks_not_errors() -> None:
    (p,) = parse_packets(json.dumps([{"_source": {"layers": {}}}]))
    assert (p.number, p.src, p.protocol, p.info, p.hexdump) == (0, "", "?", "", "")


@pytest.mark.parametrize("text", ["", "not json", "{}", "[1]", "[{}]", '[{"_source": 5}]'])
def test_unexpected_shapes_raise_parse_error(text: str) -> None:
    with pytest.raises(ParseError):
        parse_packets(text)


def test_hostile_sizes_are_capped() -> None:
    wide = {f"f{i}": "x" * 5000 for i in range(500)}
    layers = {f"l{i}": dict(wide) for i in range(100)}
    layers["frame_raw"] = ["00" * 100_000]
    (p,) = parse_packets(json.dumps([{"_source": {"layers": layers}}]))
    assert len(p.layers) <= MAX_LAYERS
    assert all(len(layer.fields) <= MAX_FIELDS for layer in p.layers)
    assert all(len(v) <= MAX_TEXT for layer in p.layers for _, v in layer.fields)
    assert len(p.hexdump.splitlines()) == MAX_HEX_BYTES // 16


def test_deep_nesting_does_not_blow_the_stack() -> None:
    deep: dict = {}
    node = deep
    for _ in range(5000):
        node["n"] = {}
        node = node["n"]
    text = json.dumps([{"_source": {"layers": {"x": deep}}}])
    try:
        parse_packets(text)
    except ParseError:
        pass  # json itself may refuse the depth; either outcome is safe


def test_hexdump_formats_rows_and_survives_bad_input() -> None:
    assert hexdump("48656c6c6f") == "0000  " + "48 65 6c 6c 6f".ljust(47) + "  Hello"
    assert hexdump("zz") == ""
    assert hexdump("") == ""

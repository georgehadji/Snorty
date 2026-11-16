# ruff: noqa: E501
"""parse_summary: tshark's statistics text becomes a bounded Summary."""

from snorty.packets import Conversation, ProtocolRow
from snorty.wireshark.stats import MAX_PER_KIND, MAX_PROTOCOLS, parse_summary

# Captured from tshark 4.6.9 on a generated pcap (-q -z io,phs -z conv,tcp -z conv,udp -z conv,ip).
REAL = """\r
===================================================================\r
Protocol Hierarchy Statistics\r
Filter: \r
\r
frame                                    frames:3 bytes:229\r
  eth                                    frames:3 bytes:229\r
    ip                                   frames:3 bytes:229\r
      tcp                                frames:2 bytes:154\r
        http                             frames:1 bytes:81\r
      udp                                frames:1 bytes:75\r
        dns                              frames:1 bytes:75\r
===================================================================\r
================================================================================\r
IPv4 Conversations\r
Filter:<No Filter>\r
                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |\r
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |\r
10.0.0.5             <-> 10.0.0.9                   1 73 bytes        2 156 bytes       3 229 bytes     0.000000000         0.0020\r
================================================================================\r
================================================================================\r
TCP Conversations\r
Filter:<No Filter>\r
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |\r
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |\r
10.0.0.5:40000             <-> 10.0.0.9:80                      1 73 bytes        1 81 bytes        2 154 bytes     0.000000000         0.0010\r
================================================================================\r
"""


def conv_line(a: str, b: str, frames: int) -> str:
    return f"{a} <-> {b}   0 0 bytes   {frames} 31 kB   {frames} 31 kB   0.000000000   1.9990"


def test_real_output_gives_the_protocol_tree_and_conversations() -> None:
    s = parse_summary(REAL)
    assert s.protocols[0] == ProtocolRow("frame", 0, 3, 229)
    assert [(p.name, p.depth) for p in s.protocols] == [
        ("frame", 0),
        ("eth", 1),
        ("ip", 2),
        ("tcp", 3),
        ("http", 4),
        ("udp", 3),
        ("dns", 4),
    ]
    assert s.conversations == (
        Conversation("IPv4", "10.0.0.5", "10.0.0.9", 3, "229 bytes", "0.0020"),
        Conversation("TCP", "10.0.0.5:40000", "10.0.0.9:80", 2, "154 bytes", "0.0010"),
    )


def test_big_sizes_keep_the_tools_unit() -> None:
    s = parse_summary("UDP Conversations\n" + conv_line("10.0.0.7:1", "10.0.0.8:2", 2000))
    assert s.conversations[0].size == "31 kB" and s.conversations[0].frames == 2000


def test_empty_or_unrecognised_text_gives_an_empty_summary() -> None:
    for text in ("", "tshark: no such file", "\x00\xff garbage <-> \n" * 5):
        s = parse_summary(text)
        assert s.protocols == () and s.conversations == ()


def test_a_conversation_line_before_any_header_is_ignored() -> None:
    assert parse_summary(conv_line("1.1.1.1", "2.2.2.2", 1)).conversations == ()


def test_lists_are_capped_and_the_busiest_conversations_win() -> None:
    protos = "\n".join(f"p{i}  frames:1 bytes:1" for i in range(MAX_PROTOCOLS + 40))
    rows = "\n".join(conv_line(f"10.0.{i}.1:1", "10.0.0.2:2", i) for i in range(MAX_PER_KIND + 30))
    s = parse_summary(protos + "\nTCP Conversations\n" + rows)
    assert len(s.protocols) == MAX_PROTOCOLS
    assert len(s.conversations) == MAX_PER_KIND
    top = MAX_PER_KIND + 29
    assert s.conversations[0].frames == top and s.conversations[-1].frames == top - MAX_PER_KIND + 1


def test_long_names_and_addresses_are_cut() -> None:
    text = "x" * 500 + "  frames:1 bytes:1\nTCP Conversations\n" + conv_line("a" * 500, "b", 1)
    s = parse_summary(text)
    assert len(s.protocols[0].name) <= 40 and len(s.conversations[0].a) <= 64

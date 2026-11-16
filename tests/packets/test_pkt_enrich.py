"""packets.enrich: one line saying what a packet is for, from the names it carries."""

import pytest

from snorty.packets import PacketView, hint


def view(*hints: tuple[str, str]) -> PacketView:
    return PacketView(1, "0", "X", "a", "b", 60, "", (), "", hints)


DNS = ("dns.qry.name", "api.openai.com")
SNI = ("tls.handshake.extensions_server_name", "example.org")
HOST = ("http.host", "example.test")
METHOD = ("http.request.method", "GET")
URI = ("http.request.uri", "/a?b=1")


@pytest.mark.parametrize(
    ("hints", "expected"),
    [
        ((DNS,), "DNS lookup: api.openai.com"),
        ((SNI,), "TLS to example.org"),
        ((HOST, METHOD, URI), "GET example.test/a?b=1"),
        ((HOST,), "HTTP example.test"),
        ((HOST, URI), "HTTP example.test/a?b=1"),
        ((DNS, SNI, HOST), "DNS lookup: api.openai.com"),  # one line: the first that applies
        ((), None),
        ((METHOD, URI), None),  # a request line without a host names nothing
        ((("dns.qry.name", ""),), None),
    ],
)
def test_each_protocol_gives_its_line(
    hints: tuple[tuple[str, str], ...], expected: str | None
) -> None:
    assert hint(view(*hints)) == expected


def test_control_characters_from_the_network_are_not_passed_on() -> None:
    assert hint(view(("dns.qry.name", "a\x00b\x1b[31m.test"))) == "DNS lookup: a?b?[31m.test"

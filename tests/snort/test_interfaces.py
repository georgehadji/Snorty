import ipaddress
from pathlib import Path

import pytest

from snorty.snort.interfaces import find_local_ip, parse_interfaces, pick_interface
from snorty.snort.models import Interface

FIXTURE = (Path(__file__).parent.parent / "fixtures" / "snort_W.txt").read_text()


def test_parses_every_row_of_real_output() -> None:
    ifaces = parse_interfaces(FIXTURE)
    assert [i.index for i in ifaces] == list(range(1, 11))


def test_wifi_row_fields() -> None:
    wifi = next(i for i in parse_interfaces(FIXTURE) if i.index == 4)
    assert wifi == Interface(
        index=4,
        mac="48:45:E6:48:53:93",
        ip="192.168.10.230",
        device=r"\Device\NPF_{288C83B6-43F3-4D94-B6E5-09B97623D405}",
        description="MediaTek Wi-Fi 7 MT7925 Wireless LAN Card",
    )


def test_disabled_and_ipv6_loopback_have_no_ip() -> None:
    by_index = {i.index: i for i in parse_interfaces(FIXTURE)}
    assert by_index[1].ip is None  # "disabled"
    assert by_index[9].ip is None  # 0000:...:0000
    assert by_index[9].device == r"\Device\NPF_Loopback"


def test_garbage_gives_empty_list() -> None:
    assert parse_interfaces("") == []
    assert parse_interfaces("nothing useful\nhere") == []
    assert parse_interfaces("x\tonly\ttwo") == []


def test_pick_interface() -> None:
    ifaces = parse_interfaces(FIXTURE)
    picked = pick_interface(ifaces, "192.168.1.25")
    assert picked is not None and picked.description.startswith("Realtek")
    assert pick_interface(ifaces, "10.9.9.9") is None


def test_find_local_ip_is_ipv4_or_none() -> None:
    ip = find_local_ip()
    assert ip is None or isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)


def test_find_local_ip_without_route_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise OSError("network unreachable")

    monkeypatch.setattr("snorty.snort.interfaces.socket.socket", boom)
    assert find_local_ip() is None

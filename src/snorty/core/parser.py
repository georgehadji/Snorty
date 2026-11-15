import ipaddress
import re
import sys
from datetime import datetime, tzinfo
from pathlib import Path

from snorty.core.models import Alert

_FAST = re.compile(
    r"^(?P<ts>\S+)\s+\[\*\*\] \[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] "
    r"(?P<msg>.*?) \[\*\*\]"
    r"(?: \[Classification: (?P<cls>[^\]]*)\])?"
    r" \[Priority: (?P<prio>\d+)\] \{(?P<proto>[^}]+)\} (?P<src>\S+) -> (?P<dst>\S+)$"
)
# MM/DD-HH:MM:SS.ffffff, or MM/DD/YY-... when Snort runs with -y
_TS = re.compile(
    r"^(?P<mo>\d\d)/(?P<d>\d\d)(?:/(?P<y>\d\d))?-(?P<h>\d\d):(?P<mi>\d\d):(?P<s>\d\d)\.(?P<us>\d{6})$"
)


def parse_line(line: str, *, default_year: int, tz: tzinfo) -> Alert | None:
    """Parse one alert_fast line. Returns None for anything unrecognised.

    Lines without a year take `default_year`; the caller must pass the right one
    for old logs, since a log can span New Year.
    """
    text = line.rstrip("\r\n")
    m = _FAST.match(text)
    if m is None:
        return None
    ts = _parse_ts(m["ts"], default_year, tz)
    src = _split_endpoint(m["src"])
    dst = _split_endpoint(m["dst"])
    if ts is None or src is None or dst is None:
        return None
    return Alert(
        ts=ts,
        gid=int(m["gid"]),
        sid=int(m["sid"]),
        rev=int(m["rev"]),
        msg=m["msg"],
        classification=m["cls"],
        priority=int(m["prio"]),
        proto=m["proto"],
        src_ip=src[0],
        src_port=src[1],
        dst_ip=dst[0],
        dst_port=dst[1],
        raw=text,
    )


def _parse_ts(text: str, default_year: int, tz: tzinfo) -> datetime | None:
    m = _TS.match(text)
    if m is None:
        return None
    year = 2000 + int(m["y"]) if m["y"] else default_year
    try:
        return datetime(
            year, int(m["mo"]), int(m["d"]), int(m["h"]), int(m["mi"]), int(m["s"]),
            int(m["us"]), tzinfo=tz,
        )  # fmt: skip
    except ValueError:
        return None


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _split_endpoint(text: str) -> tuple[str, int | None] | None:
    """Split 'ip' or 'ip:port'. Snort writes IPv6 expanded, so 'a:b:...:h:443'
    has nine groups and the ninth is the port, not part of the address."""
    if _is_ip(text):
        return text, None
    ip, sep, port = text.rpartition(":")
    if not sep or not port.isdigit() or not 0 <= int(port) <= 65535 or not _is_ip(ip):
        return None
    return ip, int(port)


def main(argv: list[str]) -> int:
    """Check script: parse a file, print counts and the first failures.

    The only impure part of this module: the default year comes from the clock.
    """
    if len(argv) != 1:
        print("usage: python -m snorty.core.parser <alert_fast file>")
        return 2
    now = datetime.now().astimezone()
    tz = now.tzinfo
    assert tz is not None
    parsed = 0
    failed: list[str] = []
    for line in Path(argv[0]).read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        if parse_line(line, default_year=now.year, tz=tz) is None:
            failed.append(line)
        else:
            parsed += 1
    print(f"parsed={parsed} failed={len(failed)}")
    for line in failed[:5]:
        print(f"  FAILED: {line}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

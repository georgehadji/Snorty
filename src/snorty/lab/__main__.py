"""`python -m snorty.lab check|run|make-pcap`: try a Snort rule against a pcap, safely."""

import argparse
import asyncio
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from snorty.lab.lint import MAX_BYTES
from snorty.lab.models import LabJob, LabResult
from snorty.lab.pcapgen import build_pcap, make_frames
from snorty.lab.service import LabService
from snorty.snort import Runner, SnortPaths, SubprocessRunner


def _safe(text: str, stream: object) -> str:
    """Text that the console's encoding can show (rule messages are third-party text)."""
    enc = getattr(stream, "encoding", None) or "utf-8"
    return text.encode(enc, "replace").decode(enc)


def _out(text: str) -> None:
    print(_safe(text, sys.stdout))


def _err(text: str) -> None:
    print(_safe(text, sys.stderr), file=sys.stderr)


def _read_rules(path: Path) -> str:
    with path.open("rb") as f:
        return f.read(MAX_BYTES + 1).decode("utf-8", "replace")  # lint refuses anything longer


def _show(result: LabResult, *, checking: bool) -> None:
    for p in result.problems:
        _out(f"rule line {p.line}: {p.message}" if p.line else f"rules: {p.message}")
    if result.error:
        _err(f"error: {result.error}")
    if not result.ok:
        return
    if checking:
        _out(f"ok: {len(result.hits)} rule(s) load in Snort")
        return
    _out("Rule hits")
    _out(f"  {'SID':<10} {'Hits':>5}  Message")
    for h in result.hits:
        _out(f"  {h.sid:<10} {h.count:>5}  {h.msg}")
    _out(f"Matches ({len(result.matches)})")
    for a in result.matches:
        src = a.src_ip if a.src_port is None else f"{a.src_ip}:{a.src_port}"
        dst = a.dst_ip if a.dst_port is None else f"{a.dst_ip}:{a.dst_port}"
        _out(f"  {a.ts:%H:%M:%S}  {a.sid:<10} {a.msg}  {src} -> {dst}")


def _as_json(result: LabResult) -> str:
    return json.dumps(
        {
            "ok": result.ok,
            "problems": [{"line": p.line, "message": p.message} for p in result.problems],
            "error": result.error,
            "hits": [
                {"sid": h.sid, "msg": h.msg, "line": h.line, "count": h.count} for h in result.hits
            ],
            "matches": [
                {
                    "ts": a.ts.isoformat(),
                    "gid": a.gid,
                    "sid": a.sid,
                    "msg": a.msg,
                    "priority": a.priority,
                    "proto": a.proto,
                    "src_ip": a.src_ip,
                    "src_port": a.src_port,
                    "dst_ip": a.dst_ip,
                    "dst_port": a.dst_port,
                }
                for a in result.matches
            ],
        },
        indent=2,
    )


def _make_pcap(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.handshake and args.proto != "tcp":
        parser.error("--handshake only makes sense with --proto tcp")
    try:
        frames = make_frames(
            args.proto,
            args.src,
            args.sport,
            args.dst,
            args.dport,
            args.payload.encode("utf-8"),
            count=args.count,
            handshake=args.handshake,
        )
    except ValueError as exc:
        parser.error(str(exc))
    try:
        args.out.write_bytes(build_pcap(frames, start=time.time()))
    except OSError as exc:
        _err(f"could not write {args.out}: {exc}")
        return 1
    _out(f"wrote {len(frames)} packet(s) to {args.out}")
    return 0


def main(
    argv: list[str] | None = None,
    *,
    paths: SnortPaths | None = None,
    runner: Runner | None = None,
) -> int:
    parser = argparse.ArgumentParser(prog="python -m snorty.lab")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="do these rules load in Snort?")
    check.add_argument("rules", type=Path, help="file with your rules")

    run = sub.add_parser("run", help="run the rules against a pcap")
    run.add_argument("rules", type=Path, help="file with your rules")
    run.add_argument("pcap", type=Path)
    run.add_argument("--json", action="store_true", help="print the result as JSON")

    mk = sub.add_parser("make-pcap", help="build a small test pcap")
    mk.add_argument("--out", type=Path, required=True)
    mk.add_argument("--payload", required=True, help="text carried by each data packet")
    mk.add_argument("--proto", choices=("tcp", "udp"), default="tcp")
    mk.add_argument("--src", default="10.0.0.1")
    mk.add_argument("--sport", type=int, default=4444)
    mk.add_argument("--dst", default="10.0.0.2")
    mk.add_argument("--dport", type=int, default=80)
    mk.add_argument("--count", type=int, default=1)
    mk.add_argument("--handshake", action="store_true", help="TCP SYN, SYN-ACK, ACK first")
    args = parser.parse_args(argv)

    if args.command == "make-pcap":
        return _make_pcap(args, parser)

    try:
        rules_text = _read_rules(args.rules)
    except OSError as exc:
        _err(f"could not read {args.rules}: {exc}")
        return 1
    tz = datetime.now().astimezone().tzinfo or UTC
    service = LabService(paths or SnortPaths(), runner or SubprocessRunner(), tz=tz)
    if args.command == "check":
        result = asyncio.run(service.check(rules_text))
    else:
        result = asyncio.run(service.run(LabJob(rules_text, args.pcap)))
    if getattr(args, "json", False):
        _out(_as_json(result))
    else:
        _show(result, checking=args.command == "check")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""`python -m snorty.dashboard`: the local web dashboard, on 127.0.0.1 only."""

import argparse
import asyncio
import contextlib
import logging
import logging.handlers
import os
import sys
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI

from snorty.compose import Runtime, compose
from snorty.core.repository import AlertRepository
from snorty.dashboard import pcaps
from snorty.dashboard.app import build_app
from snorty.dashboard.config import ConfigError, DashConfig, default_data_dir, load_config
from snorty.dashboard.schedule import run_daily
from snorty.dashboard.security import new_token
from snorty.journal.ports import NoteStore, VaultNoteStore

HOST = "127.0.0.1"
LOG_NAME = "snorty.log"
log = logging.getLogger("snorty.dashboard")

Build = Callable[..., Runtime]
Serve = Callable[[FastAPI, str, int], Awaitable[None]]


async def serve_uvicorn(app: FastAPI, host: str, port: int) -> None:
    import uvicorn

    server = uvicorn.Server(
        uvicorn.Config(app, host=host, port=port, log_config=None, access_log=False)
    )
    await server.serve()


def setup_logging(data_dir: Path) -> logging.Handler:
    """A rotating log file in the data folder. Request lines and the token are never logged."""
    data_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        data_dir / LOG_NAME, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    return handler


def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m snorty.dashboard", description=__doc__)
    p.add_argument("--port", type=int, help="port on 127.0.0.1 (default 8765)")
    p.add_argument("--start-sensor", action="store_true", help="start the sensor at launch")
    p.add_argument("--no-notify", action="store_true", help="no toast notifications")
    p.add_argument("--no-journal", action="store_true", help="no daily Obsidian notes")
    p.add_argument("--vault", help="vault folder for notes, default $OBSIDIAN_VAULT_PATH")
    p.add_argument("--interface-ip", help="pin the capture interface by IP")
    p.add_argument(
        "--engine", choices=["snort", "suricata"], help="detection engine (default snort)"
    )
    p.add_argument("--data-dir", type=Path, help=r"default %%LOCALAPPDATA%%\Snorty")
    return p


def config_from(args: argparse.Namespace) -> DashConfig:
    overrides = {
        "port": args.port,
        "autostart_sensor": True if args.start_sensor else None,
        "notify": False if args.no_notify else None,
        "journal": False if args.no_journal else None,
        "vault": args.vault,
        "interface_ip": args.interface_ip,
        "engine": args.engine,
    }
    return load_config(args.data_dir or default_data_dir(), overrides)


def note_store(cfg: DashConfig) -> NoteStore | None:
    vault = cfg.vault or os.environ.get("OBSIDIAN_VAULT_PATH")
    return VaultNoteStore(vault) if cfg.journal and vault else None


async def prune_old(repo: AlertRepository, days: int, pcap_dir: Path | None = None) -> int:
    """Delete alerts, and recorded captures, older than `days` days (0 keeps all).

    A failure is logged, not raised. Returns the number of alerts removed.
    """
    if days <= 0:
        return 0
    if pcap_dir is not None:
        try:
            gone = await asyncio.to_thread(pcaps.prune_captures, pcap_dir, days)
        except Exception:
            log.exception("could not delete old captures")
        else:
            if gone:
                log.info("deleted %d captures older than %d days", gone, days)
    try:
        removed = await asyncio.to_thread(repo.prune, datetime.now(UTC) - timedelta(days=days))
    except Exception:
        log.exception("could not delete old alerts")
        return 0
    if removed:
        log.info("deleted %d alerts older than %d days", removed, days)
    return removed


async def run(
    cfg: DashConfig, *, build: Build = compose, serve: Serve = serve_uvicorn, host: str = HOST
) -> int:
    """Build the services, serve until stopped, then shut everything down. Returns the exit code."""
    if host != HOST:
        print(
            f"refusing to listen on {host}: the dashboard is local only ({HOST})", file=sys.stderr
        )
        return 2
    runtime = build(
        cfg.data_dir,
        interface_ip=cfg.interface_ip,
        notify=cfg.notify,
        journal_store=note_store(cfg),
        wireshark_dir=Path(cfg.wireshark_dir) if cfg.wireshark_dir else None,
        host_context=True,
        engine="suricata" if cfg.engine == "suricata" else "snort",
    )
    services = runtime.services
    app = build_app(services, token=new_token(), port=cfg.port)
    schedule = asyncio.create_task(
        run_daily(lambda: services.rules.update(), cfg.rules_update_at), name="rules-schedule"
    )
    prune = asyncio.create_task(
        run_daily(
            lambda: prune_old(services.repo, cfg.retention_days, services.pcap_dir),
            "03:30" if cfg.retention_days else "",
        ),
        name="alert-prune",
    )
    code = 0
    try:
        await prune_old(
            services.repo, cfg.retention_days, services.pcap_dir
        )  # the PC is often off at 03:30
        await runtime.start(sensor=cfg.autostart_sensor)
        print(f"Snorty dashboard: http://{HOST}:{cfg.port}/  (Ctrl+C to stop)", flush=True)
        await serve(app, host, cfg.port)
    except SystemExit as exc:  # uvicorn exits with 1 when it cannot bind the port
        code = exc.code if isinstance(exc.code, int) else 1
        print(f"could not serve on {HOST}:{cfg.port}; is the port in use?", file=sys.stderr)
    except Exception:
        log.exception("dashboard failed")
        print("dashboard failed; see snorty.log in the data folder", file=sys.stderr)
        code = 1
    finally:
        schedule.cancel()
        prune.cancel()
        await asyncio.gather(schedule, prune, return_exceptions=True)
        await runtime.stop()
        services.repo.close()
    return code


def main(
    argv: Sequence[str] | None = None, *, build: Build = compose, serve: Serve = serve_uvicorn
) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        cfg = config_from(args)
    except ConfigError as exc:
        print(f"snorty: {exc}", file=sys.stderr)
        return 2
    handler = setup_logging(cfg.data_dir)
    try:
        with contextlib.suppress(KeyboardInterrupt):
            return asyncio.run(run(cfg, build=build, serve=serve))
        return 0
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()


if __name__ == "__main__":
    raise SystemExit(main())

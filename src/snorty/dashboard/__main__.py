"""`python -m snorty.dashboard`: the local web dashboard, on 127.0.0.1 only."""

import argparse
import asyncio
import contextlib
import logging
import logging.handlers
import os
import socket
import sys
import time
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
from snorty.notify.ports import channel_notifier

HOST = "127.0.0.1"
LOG_NAME = "snorty.log"
STOP_NAME = "stop.request"  # `--stop` writes it; the running dashboard stops and deletes it
STOP_POLL = 1.0  # seconds between looks for the stop request
STOP_WAIT = 90.0  # how long `--stop` waits for the dashboard (and the sensor) to finish
CONTEXT_DAYS = 7  # connection and DNS context kept for alerts; about 70k connections a day
STOP_GRACE = 5  # an open browser tab keeps its live stream; cut it after this many seconds
log = logging.getLogger("snorty.dashboard")

Build = Callable[..., Runtime]
Serve = Callable[[FastAPI, str, int, asyncio.Event], Awaitable[None]]


class _StreamCutIsNotAnError(logging.Filter):
    """The grace limit cancels open live streams; that is a normal stop, not a crash."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.exc_info and isinstance(record.exc_info[1], asyncio.CancelledError):
            return False  # uvicorn's "Exception in ASGI application" for a cancelled stream
        if record.getMessage().endswith("timeout graceful shutdown exceeded"):
            record.levelno, record.levelname = logging.INFO, "INFO"
        return True


_STREAM_CUT = _StreamCutIsNotAnError()  # one instance: adding it again is a no-op


async def serve_uvicorn(
    app: FastAPI, host: str, port: int, stop: asyncio.Event, *, grace: int = STOP_GRACE
) -> None:
    """Serve until Ctrl+C or until `stop` is set; both end the same graceful way.

    Open requests get `grace` seconds to finish. Without that limit an open dashboard tab,
    whose live stream never ends, would keep the process waiting for ever.
    """
    import uvicorn

    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=host,
            port=port,
            log_config=None,
            access_log=False,
            timeout_graceful_shutdown=grace,
        )
    )

    async def exit_on_stop() -> None:
        await stop.wait()
        server.should_exit = True

    # Stays on after serve() returns: the cancelled streams log their error after that.
    logging.getLogger("uvicorn.error").addFilter(_STREAM_CUT)
    watcher = asyncio.create_task(exit_on_stop(), name="dashboard-stop")
    try:
        await server.serve()
    finally:
        watcher.cancel()


async def watch_stop_request(path: Path, stop: asyncio.Event, poll: float = STOP_POLL) -> None:
    while not path.exists():
        await asyncio.sleep(poll)
    log.info("stop requested")
    stop.set()


def _answers(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=2):
            return True
    except OSError:
        return False


def request_stop(
    cfg: DashConfig,
    *,
    answers: Callable[[int], bool] = _answers,
    wait: float = STOP_WAIT,
    poll: float = 0.5,
) -> int:
    """Ask the dashboard using `cfg.data_dir` to stop, and wait until it has finished."""
    if not answers(cfg.port):
        print(f"no Snorty dashboard is answering on {HOST}:{cfg.port}", file=sys.stderr)
        return 1
    path = cfg.data_dir / STOP_NAME
    path.touch()
    print("asked the dashboard to stop; waiting for it to finish...", flush=True)
    deadline = time.monotonic() + wait
    while path.exists():
        if time.monotonic() > deadline:
            print(f"the dashboard did not finish within {wait:.0f} s", file=sys.stderr)
            return 1
        time.sleep(poll)
    print("Snorty stopped.")
    return 0


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
        "--engine",
        choices=["snort", "suricata"],
        help="detection engine (default suricata when installed, else snort)",
    )
    p.add_argument("--data-dir", type=Path, help=r"default %%LOCALAPPDATA%%\Snorty")
    p.add_argument(
        "--stop",
        action="store_true",
        help="stop the running dashboard and its sensor cleanly, then exit",
    )
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
    """Delete alerts, and recorded captures, older than `days` days (0 keeps all). Connection
    and DNS context is always kept only CONTEXT_DAYS days.

    A failure is logged, not raised. Returns the number of alerts removed.
    """
    try:
        cutoff = datetime.now(UTC) - timedelta(days=CONTEXT_DAYS)
        await asyncio.to_thread(repo.prune_context, cutoff)
    except Exception:
        log.exception("could not delete old connection context")
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
        respond=cfg.respond,
        explain_model=cfg.explain_model,
        explain_language=cfg.explain_language,
        explain_audience=cfg.explain_audience,
        explain_prewarm=cfg.explain_prewarm,
        notifier=channel_notifier(cfg.channels) if cfg.channels else None,
        journal_store=note_store(cfg),
        wireshark_dir=Path(cfg.wireshark_dir) if cfg.wireshark_dir else None,
        host_context=True,
        engine="suricata" if cfg.engine == "suricata" else "snort",
    )
    services = runtime.services
    app = build_app(services, token=new_token(), port=cfg.port)
    stop_file = cfg.data_dir / STOP_NAME
    stop_file.unlink(missing_ok=True)  # left by a `--stop` that found nothing to stop
    stop = asyncio.Event()
    watch = asyncio.create_task(watch_stop_request(stop_file, stop), name="stop-request")
    schedule = asyncio.create_task(
        run_daily(lambda: services.rules.update(), cfg.rules_update_at), name="rules-schedule"
    )
    prune = asyncio.create_task(
        run_daily(
            lambda: prune_old(services.repo, cfg.retention_days, services.pcap_dir),
            "03:30",  # even with retention_days 0: the connection context is still pruned
        ),
        name="alert-prune",
    )
    code = 0
    try:
        await prune_old(
            services.repo, cfg.retention_days, services.pcap_dir
        )  # the PC is often off at 03:30
        await runtime.start(sensor=cfg.autostart_sensor)
        print(
            f"Snorty dashboard: http://{HOST}:{cfg.port}/  "
            "(Ctrl+C or `python -m snorty.dashboard --stop` to stop)",
            flush=True,
        )
        await serve(app, host, cfg.port, stop)
    except SystemExit as exc:  # uvicorn exits with 1 when it cannot bind the port
        code = exc.code if isinstance(exc.code, int) else 1
        print(f"could not serve on {HOST}:{cfg.port}; is the port in use?", file=sys.stderr)
    except Exception:
        log.exception("dashboard failed")
        print("dashboard failed; see snorty.log in the data folder", file=sys.stderr)
        code = 1
    finally:
        for task in (schedule, prune, watch):
            task.cancel()
        await asyncio.gather(schedule, prune, watch, return_exceptions=True)
        await runtime.stop()
        services.repo.close()
        stop_file.unlink(missing_ok=True)  # last: tells `--stop` that everything has finished
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
    if args.stop:
        return request_stop(cfg)
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

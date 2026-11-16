import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, tzinfo
from pathlib import Path

from snorty.core.bus import EventBus
from snorty.core.events import AlertRaised, SensorStateChanged
from snorty.core.models import Alert
from snorty.core.parser import parse_line
from snorty.core.repository import AlertRepository
from snorty.sensor.config import SensorConfig
from snorty.sensor.port import RunningSnort, SnortPort
from snorty.sensor.states import State, check_transition
from snorty.sensor.tail import TailState, read_new_lines
from snorty.snort.interfaces import pick_interface
from snorty.snort.models import Interface, SnortError

log = logging.getLogger("snorty.sensor")


@dataclass(frozen=True, slots=True)
class SensorStatus:
    state: State
    reason: str | None
    interface: Interface | None
    pid: int | None
    started_at: datetime | None
    alerts_seen: int
    last_alert_ts: datetime | None
    unparsed: int
    restarts: int
    last_error: str | None


def _read_pid(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def _write_pid(path: Path, pid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid))


def _remove_pid(path: Path) -> None:
    path.unlink(missing_ok=True)


class Sensor:
    """Keeps Snort running and turns its output into events.

    One supervisor task owns every state change. start() and stop() only signal it.
    """

    def __init__(
        self,
        config: SensorConfig,
        port: SnortPort,
        repo: AlertRepository,
        bus: EventBus,
        *,
        clock: Callable[[], float],
        sleep: Callable[[float], Awaitable[None]],
        tz: tzinfo,
        select_interface: Callable[[list[Interface]], Interface | None] | None = None,
        wall: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._port = port
        self._repo = repo
        self._bus = bus
        self._clock = clock
        self._sleep = sleep
        self._tz = tz
        self._select_interface = select_interface
        self._wall = wall or (lambda: datetime.now(tz))
        self._pid_path = config.paths.log_dir / "snorty-sensor.pid"
        self._alert_path = config.paths.log_dir / "alert.ids"
        self._tail = TailState()
        self._backlog_done = False
        self._ingest_task: asyncio.Task[None] | None = None

        self._state = State.STOPPED
        self._reason: str | None = None
        self._iface: Interface | None = None
        self._proc: RunningSnort | None = None
        self._started_at: datetime | None = None
        self._last_error: str | None = None
        self._restarts = 0
        self._alerts_seen = 0
        self._last_alert_ts: datetime | None = None
        self._unparsed = 0

        self._supervisor: asyncio.Task[None] | None = None
        self._stop_requested = asyncio.Event()
        self._settled = asyncio.Event()
        self._cmd_lock = asyncio.Lock()

    # --- public API -------------------------------------------------------------------

    @property
    def state(self) -> State:
        return self._state

    def status(self) -> SensorStatus:
        return SensorStatus(
            state=self._state,
            reason=self._reason,
            interface=self._iface,
            pid=self._proc.pid if self._proc is not None else None,
            started_at=self._started_at,
            alerts_seen=self._alerts_seen,
            last_alert_ts=self._last_alert_ts,
            unparsed=self._unparsed,
            restarts=self._restarts,
            last_error=self._last_error,
        )

    async def start(self) -> None:
        """Start Snort; returns once the sensor is RUNNING or FAILED. No-op if already active."""
        async with self._cmd_lock:
            if self._supervisor is not None and not self._supervisor.done():
                return
            self._stop_requested.clear()
            self._settled.clear()
            self._transition(State.STARTING, "start requested")
            self._supervisor = asyncio.create_task(self._run(), name="sensor-supervisor")
        await self._settled.wait()

    async def stop(self) -> None:
        """Stop Snort cleanly. No-op if already stopped."""
        async with self._cmd_lock:
            sup = self._supervisor
            if sup is None or sup.done():
                if self._state is State.FAILED:
                    self._transition(State.STOPPED, "stopped after failure")
                return
            self._stop_requested.set()
        await sup

    # --- state machine ----------------------------------------------------------------

    def _transition(self, new: State, reason: str | None) -> None:
        check_transition(self._state, new)
        old = self._state
        self._state, self._reason = new, reason
        log.info("sensor %s -> %s%s", old.name, new.name, f" ({reason})" if reason else "")
        self._bus.publish(SensorStateChanged(old.value, new.value, reason))
        if new in (State.RUNNING, State.FAILED, State.STOPPED):
            self._settled.set()

    # --- supervisor -------------------------------------------------------------------

    async def _run(self) -> None:
        try:
            failure = await self._start_once()
            if failure is not None:
                self._last_error = failure
                self._transition(State.FAILED, failure)
                return
            if self._stop_requested.is_set():
                await self._shutdown("stop requested")
                return
            self._transition(State.RUNNING, None)
            self._ingest_task = asyncio.create_task(self._ingest_loop(), name="sensor-ingest")
            await self._monitor()
        except Exception as e:  # keep the sensor object usable whatever goes wrong
            log.exception("sensor supervisor crashed")
            self._last_error = repr(e)
            await self._abort(f"internal error: {e!r}")

    async def _start_once(self) -> str | None:
        """Try to start Snort. Returns a failure reason, or None when it is up."""
        stale = await asyncio.to_thread(_read_pid, self._pid_path)
        if stale is not None and await self._port.is_snort_running(stale):
            return f"Snort already running (pid {stale})"
        chosen = await self._choose_interface()
        if isinstance(chosen, str):
            return chosen
        if not self._backlog_done:
            # Read what is already in alert.ids *before* Snort can add to it, so an alert
            # written right after startup is never mistaken for backlog.
            await self._poll_once()
            self._backlog_done = True
        try:
            proc = await self._port.start(chosen)
        except SnortError as e:
            return f"snort failed to start: {e}"
        self._iface, self._proc = chosen, proc
        self._started_at = self._wall()
        await asyncio.to_thread(_write_pid, self._pid_path, proc.pid)
        return None

    async def _choose_interface(self) -> Interface | str:
        interfaces = await self._port.list_interfaces()
        if self._select_interface is not None:
            return self._select_interface(interfaces) or "interface selector found no interface"
        ip = self._config.interface_ip or self._port.local_ip()
        if ip is None:
            return "no network route found"
        return pick_interface(interfaces, ip) or f"no interface has IP {ip}"

    async def _monitor(self) -> None:
        proc = self._proc
        assert proc is not None
        exited = asyncio.create_task(proc.wait())
        stopped = asyncio.create_task(self._stop_requested.wait())
        try:
            await asyncio.wait({exited, stopped}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (exited, stopped):
                t.cancel()
        if self._stop_requested.is_set():
            await self._shutdown("stop requested")
        else:
            await self._abort(f"snort exited unexpectedly (code {proc.returncode})")

    async def _shutdown(self, reason: str) -> None:
        self._transition(State.STOPPING, reason)
        proc = self._proc
        note: str | None = None
        if proc is not None:
            result = await self._port.stop(proc, self._config.stop_timeout)
            if result.how == "killed":
                note = "snort ignored Ctrl+Break and was killed"
            await self._stop_ingest()
        await self._release_process()
        self._transition(State.STOPPED, note)

    async def _abort(self, reason: str) -> None:
        """Leave a bad state: stop any process we own, then end in FAILED (or STOPPED)."""
        proc = self._proc
        if proc is not None and proc.returncode is None:
            try:
                await self._port.stop(proc, self._config.stop_timeout)
            except Exception:
                log.exception("could not stop snort while aborting")
        if proc is not None:
            await self._stop_ingest()
        await self._release_process()
        self._last_error = self._last_error or reason
        if self._state is State.RUNNING:
            self._transition(State.STARTING, reason)
        if self._state is State.STARTING:
            self._transition(State.FAILED, reason)
        elif self._state is State.STOPPING:
            self._transition(State.STOPPED, reason)

    async def _release_process(self) -> None:
        if self._proc is not None:
            await asyncio.to_thread(_remove_pid, self._pid_path)
        self._proc = None

    # --- ingest -----------------------------------------------------------------------

    async def _ingest_loop(self) -> None:
        while True:
            try:
                await self._poll_once()
            except Exception as e:  # a bad poll must not stop ingestion; it is retried
                log.exception("alert ingest failed; will retry")
                self._last_error = repr(e)
            await self._sleep(self._config.poll_interval)

    async def _stop_ingest(self) -> None:
        """Stop the ingest loop, then read whatever Snort wrote just before it stopped."""
        task, self._ingest_task = self._ingest_task, None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        try:
            await self._poll_once()
        except Exception as e:
            log.exception("final alert pass failed")
            self._last_error = repr(e)

    async def _poll_once(self) -> None:
        """Read new lines, store them, announce the new ones. The tail position only
        advances after a successful store, so a database error loses no lines."""
        result = await asyncio.to_thread(read_new_lines, self._alert_path, self._tail)
        if result.rotated:
            log.warning("alert file was rotated or truncated; reading it from the start")
        if result.lines:
            new, bad = await asyncio.to_thread(self._store_lines, result.lines, self._wall().year)
            self._unparsed += bad
            self._alerts_seen += len(new)
            if new:
                newest = max(a.ts for a in new)
                if self._last_alert_ts is None or newest > self._last_alert_ts:
                    self._last_alert_ts = newest
            if self._backlog_done or result.rotated:
                for alert in new:
                    self._bus.publish(AlertRaised(alert))
        self._tail = result.state

    def _store_lines(self, lines: list[str], year: int) -> tuple[list[Alert], int]:
        """Runs in a worker thread: parse and store. Returns (new alerts, unparsed count)."""
        alerts: list[Alert] = []
        bad = 0
        for text in lines:
            alert = parse_line(text, default_year=year, tz=self._tz)
            if alert is None:
                bad += 1
                log.warning("unparsed alert line: %.120s", text)
            else:
                alerts.append(alert)
        return self._repo.add_new(alerts), bad

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, tzinfo
from pathlib import Path
from typing import Literal

from snorty.core.bus import EventBus
from snorty.core.events import AlertRaised, SensorStateChanged
from snorty.core.models import Alert
from snorty.core.parser import parse_line
from snorty.core.repository import AlertRepository
from snorty.sensor.config import SensorConfig
from snorty.sensor.policy import backoff_delay, should_give_up
from snorty.sensor.port import RunningSnort, SnortPort
from snorty.sensor.states import State, check_transition
from snorty.sensor.tail import TailState, read_new_lines
from snorty.snort.interfaces import pick_interface
from snorty.snort.models import Interface, SnortError

log = logging.getLogger("snorty.sensor")

type StartOutcome = tuple[Literal["ok", "retry", "fatal"], str | None]
type MonitorEvent = Literal["stop", "restart", "network", "exited"]


@dataclass(frozen=True, slots=True)
class SensorStatus:
    state: State
    reason: str | None
    interface: Interface | None
    pid: int | None
    started_at: datetime | None
    alerts_seen: int  # new alerts stored since the sensor object was created (backlog + live)
    last_alert_ts: datetime | None
    unparsed: int
    restarts: int  # automatic or requested restarts of a running Snort
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

    One supervisor task owns every state change. start(), stop() and restart() only
    signal it.
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
        self._restart_requested = asyncio.Event()
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

    def _active(self) -> bool:
        return self._supervisor is not None and not self._supervisor.done()

    async def start(self) -> None:
        """Start Snort; returns once the sensor is RUNNING or FAILED. No-op if already active."""
        async with self._cmd_lock:
            if self._active():
                return
            self._stop_requested.clear()
            self._restart_requested.clear()
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

    async def restart(self) -> None:
        """Restart Snort; returns once the sensor is RUNNING or FAILED again."""
        async with self._cmd_lock:
            active = self._active()
            if active and self._state is State.RUNNING:
                self._settled.clear()
                self._restart_requested.set()
        if not active:
            await self.start()
        else:
            await self._settled.wait()

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
            await self._supervise()
        except Exception as e:  # keep the sensor object usable whatever goes wrong
            log.exception("sensor supervisor crashed")
            self._last_error = repr(e)
            await self._abort(f"internal error: {e!r}")

    async def _supervise(self) -> None:
        cfg = self._config
        failures = 0  # consecutive crashes and failed start attempts
        while True:
            kind, why = await self._start_once()
            if kind == "fatal":
                self._fail(why or "unknown failure")
                return
            if kind == "retry":
                failures += 1
                if should_give_up(failures, cfg.max_restarts):
                    self._fail(f"{why} (gave up after {failures} attempts)")
                    return
                delay = backoff_delay(failures)
                self._transition(
                    State.STARTING, f"{why}; retry {failures}/{cfg.max_restarts} in {delay:g}s"
                )
                if await self._wait_or_stop(delay):
                    await self._shutdown("stop requested")
                    return
                continue

            if self._stop_requested.is_set():  # stop arrived while Snort was starting
                await self._shutdown("stop requested")
                return
            self._transition(State.RUNNING, None)
            started = self._clock()
            self._ingest_task = asyncio.create_task(self._ingest_loop(), name="sensor-ingest")
            event, detail = await self._monitor()
            if event == "stop":
                await self._shutdown("stop requested")
                return

            self._restarts += 1
            if event == "exited":
                if self._clock() - started >= cfg.stable_after:
                    failures = 0
                failures += 1
                reason = detail
            else:  # a requested restart or a network change is not a failure
                failures = 0
                reason = detail
            giving_up = event == "exited" and should_give_up(failures, cfg.max_restarts)
            delay = backoff_delay(failures) if event == "exited" and not giving_up else 0.0
            if event == "exited" and not giving_up:
                reason = f"{reason}; restart {failures}/{cfg.max_restarts} in {delay:g}s"
            self._transition(State.STARTING, reason)
            await self._stop_process()
            if giving_up:
                self._fail(f"{detail} (gave up after {failures} failures)")
                return
            if delay and await self._wait_or_stop(delay):
                await self._shutdown("stop requested")
                return

    async def _start_once(self) -> StartOutcome:
        """Try to start Snort. 'fatal' means retrying cannot help; 'retry' is worth a backoff."""
        stale = await asyncio.to_thread(_read_pid, self._pid_path)
        if stale is not None and await self._port.is_snort_running(stale):
            return "fatal", f"Snort already running (pid {stale})"
        chosen = await self._choose_interface()
        if isinstance(chosen, str):
            return "fatal", chosen
        if not self._backlog_done:
            # Read what is already in alert.ids *before* Snort can add to it, so an alert
            # written right after startup is never mistaken for backlog.
            await self._poll_once()
            self._backlog_done = True
        try:
            proc = await self._port.start(chosen)
        except SnortError as e:
            self._last_error = f"snort failed to start: {e}"
            return "retry", self._last_error
        self._iface, self._proc = chosen, proc
        self._started_at = self._wall()
        await asyncio.to_thread(_write_pid, self._pid_path, proc.pid)
        return "ok", None

    async def _choose_interface(self) -> Interface | str:
        interfaces = await self._port.list_interfaces()
        if self._select_interface is not None:
            return self._select_interface(interfaces) or "interface selector found no interface"
        ip = self._config.interface_ip or self._port.local_ip()
        if ip is None:
            return "no network route found"
        return pick_interface(interfaces, ip) or f"no interface has IP {ip}"

    async def _monitor(self) -> tuple[MonitorEvent, str | None]:
        """Wait until Snort exits, the network changes, or stop/restart is requested."""
        proc = self._proc
        assert proc is not None
        tasks: dict[MonitorEvent, asyncio.Task[object]] = {
            "stop": asyncio.create_task(self._stop_requested.wait()),
            "restart": asyncio.create_task(self._restart_requested.wait()),
            "exited": asyncio.create_task(proc.wait()),
        }
        if self._config.interface_ip is None and self._select_interface is None:
            tasks["network"] = asyncio.create_task(self._watch_network())
        try:
            await asyncio.wait(set(tasks.values()), return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks.values():
                t.cancel()
            await asyncio.gather(*tasks.values(), return_exceptions=True)
        if self._stop_requested.is_set():
            return "stop", None
        if self._restart_requested.is_set():
            self._restart_requested.clear()
            return "restart", "restart requested"
        if "network" in tasks and tasks["network"].done() and not tasks["network"].cancelled():
            return "network", str(tasks["network"].result())
        return "exited", f"snort exited unexpectedly (code {proc.returncode})"

    async def _watch_network(self) -> str:
        """Returns once the PC's IP no longer matches the interface Snort is bound to."""
        bound = self._iface.ip if self._iface is not None else None
        while True:
            await self._sleep(self._config.network_check_interval)
            current = self._port.local_ip()
            if current is not None and bound is not None and current != bound:
                return f"network changed ({bound} -> {current})"

    async def _wait_or_stop(self, delay: float) -> bool:
        """Sleep `delay` seconds unless stop() arrives first. True if stop was requested."""
        sleeper = asyncio.ensure_future(self._sleep(delay))
        stopper = asyncio.create_task(self._stop_requested.wait())
        try:
            await asyncio.wait({sleeper, stopper}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            sleeper.cancel()
            stopper.cancel()
            await asyncio.gather(sleeper, stopper, return_exceptions=True)
        return self._stop_requested.is_set()

    def _fail(self, reason: str) -> None:
        self._last_error = reason
        self._transition(State.FAILED, reason)

    async def _stop_process(self) -> None:
        """Stop the Snort we own if it is still alive, drain its alerts, free the pid file."""
        proc = self._proc
        if proc is not None and proc.returncode is None:
            await self._port.stop(proc, self._config.stop_timeout)
        if proc is not None:
            await self._stop_ingest()
        await self._release_process()

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
        now = self._wall()
        for text in lines:
            alert = parse_line(text, default_year=year, tz=self._tz)
            if alert is not None and alert.ts > now + timedelta(days=1):
                # Snort writes no year: a December line read in January is from last year.
                alert = parse_line(text, default_year=year - 1, tz=self._tz)
            if alert is None:
                bad += 1
                log.warning("unparsed alert line: %.120s", text)
            else:
                alerts.append(alert)
        return self._repo.add_new(alerts), bad

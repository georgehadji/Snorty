"""Lab: record live traffic for a few seconds into the pcap folder, one capture at a time."""

import asyncio
import contextlib
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.dashboard import pcaps
from snorty.dashboard.jobs import Done, Errored, Idle, Job, Running
from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui
from snorty.dashboard.views import fmt_size
from snorty.packets import (
    CAPTURE_MAX_SECONDS,
    CAPTURE_MIN_SECONDS,
    Failed,
    Unavailable,
)
from snorty.sensor import State

EMPTY_CAPTURE = 24  # a pcap with only its header: the adapter saw nothing


@dataclass(frozen=True, slots=True)
class Captured:
    name: str
    size: int


@dataclass(slots=True)
class _Run:
    adapter: str = ""
    seconds: int = 0
    started: float = 0.0


CaptureResult = Captured | Failed


def _seconds(form: dict[str, str]) -> int:
    text = form.get("seconds", "")
    if text.isascii() and text.isdigit() and len(text) <= 3:
        value = int(text)
        if CAPTURE_MIN_SECONDS <= value <= CAPTURE_MAX_SECONDS:
            return value
    raise ValueError(
        f"capture time must be a whole number from {CAPTURE_MIN_SECONDS} to {CAPTURE_MAX_SECONDS}"
    )


def add_capture_routes(
    app: FastAPI,
    ui: Ui,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now().astimezone(),
    ticker: Callable[[], float] = time.monotonic,
) -> None:
    job: Job[CaptureResult] = Job()
    current = _Run()
    ui.cleanups.append(job.cancel)  # stopping the dashboard stops dumpcap

    async def capture(svc: Svc, device: str, seconds: int) -> CaptureResult:
        temp = await asyncio.to_thread(pcaps.capture_temp, svc.pcap_dir)
        try:
            result = await svc.packets.record(device, seconds, temp)
            if isinstance(result, Unavailable):
                return Failed(result.reason)
            if isinstance(result, Failed):
                return result
            if result.size <= EMPTY_CAPTURE:
                return Failed(f"No packets arrived in {seconds} s, so nothing was saved.")
            name = await asyncio.to_thread(pcaps.publish_capture, svc.pcap_dir, temp, clock())
            return Captured(name, result.size)
        finally:
            with contextlib.suppress(OSError):
                temp.unlink()  # already moved on success

    def fail(request: Request, text: str, status: int) -> HTMLResponse:
        return ui.page(request, "_capture_status.html", status=status, state="error", error=text)

    def running(request: Request, *, already: bool = False) -> HTMLResponse:
        left = max(0, math.ceil(current.seconds - (ticker() - current.started)))
        return ui.page(
            request,
            "_capture_status.html",
            state="running",
            already=already,
            adapter=current.adapter,
            left=left,
        )

    @app.post("/lab/capture", response_class=HTMLResponse)
    async def start(request: Request, svc: Svc) -> HTMLResponse:
        try:
            seconds = _seconds(await ui.form(request))
        except ValueError as exc:
            return fail(request, str(exc), 422)
        if job.running:
            return running(request, already=True)
        if not svc.packets.capabilities().record:
            return fail(
                request, "Wireshark (dumpcap) was not found, so nothing can be recorded.", 409
            )
        sensor = svc.sensor.status()  # its interface is the last one used, even once stopped
        adapter = sensor.interface if sensor.state is State.RUNNING else None
        if adapter is None:
            return fail(
                request, "Start the sensor first: Snorty records on the adapter Snort uses.", 409
            )
        current.adapter, current.seconds, current.started = (
            adapter.description,
            seconds,
            ticker(),
        )
        job.start(lambda: capture(svc, adapter.device, seconds))
        return running(request)

    @app.get("/lab/capture/status", response_class=HTMLResponse)
    async def status(request: Request, svc: Svc) -> HTMLResponse:
        match job.state:
            case Running():
                return running(request)
            case Errored(message=why):
                return fail(request, why, 200)
            case Idle():
                return ui.page(request, "_capture_status.html", state="idle")
            case Done(result=done):
                if isinstance(done, Failed):
                    return fail(request, done.message, 200)
                return ui.page(
                    request,
                    "_capture_status.html",
                    state="done",
                    saved=done.name,
                    size=fmt_size(done.size),
                    pcaps=pcaps.list_pcaps(svc.pcap_dir),
                    selected=done.name,
                    oob=True,
                )

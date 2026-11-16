"""Lab page: try rules against a pcap from data\\pcaps, without touching the live sensor."""

import asyncio

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.dashboard import pcaps, views
from snorty.dashboard.jobs import Job
from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui, read_body
from snorty.lab.lint import MAX_BYTES as RULES_MAX_BYTES
from snorty.lab.models import LabJob, LabResult

_PROTOS = ("tcp", "udp")


def _number(form: dict[str, str], key: str, label: str) -> int:
    text = form.get(key, "")
    if not (text.isascii() and text.isdigit() and len(text) <= 5):
        raise ValueError(f"{label} must be a whole number")
    return int(text)


def add_lab_routes(app: FastAPI, ui: Ui) -> None:
    job: Job[LabResult] = Job()
    ui.cleanups.append(job.cancel)

    def bad(request: Request, exc: ValueError) -> HTMLResponse:
        return ui.flash(request, views.Message(False, str(exc)), status=422)

    def running(request: Request, *, already: bool = False) -> HTMLResponse:
        return ui.page(request, "_lab_result.html", state="running", already=already)

    @app.get("/lab", response_class=HTMLResponse)
    async def lab_page(request: Request, svc: Svc) -> HTMLResponse:
        return ui.page(request, "lab.html", pcaps=pcaps.list_pcaps(svc.pcap_dir), selected="")

    async def start(request: Request, svc: Svc, *, run: bool) -> HTMLResponse:
        try:
            form = await ui.form(request)
            text = form.get("rules", "")
            if not text.strip():
                raise ValueError("type at least one rule")
            if len(text.encode()) > RULES_MAX_BYTES:
                raise ValueError("rules text is over 64 KB")
            lab_job = (
                LabJob(text, pcaps.pcap_path(svc.pcap_dir, form.get("pcap", ""))) if run else None
            )
        except ValueError as exc:
            return bad(request, exc)
        if lab_job is not None:
            started = job.start(lambda: svc.lab.run(lab_job))
        else:
            started = job.start(lambda: svc.lab.check(text))
        return running(request, already=not started)

    @app.post("/lab/check", response_class=HTMLResponse)
    async def check(request: Request, svc: Svc) -> HTMLResponse:
        return await start(request, svc, run=False)

    @app.post("/lab/run", response_class=HTMLResponse)
    async def run(request: Request, svc: Svc) -> HTMLResponse:
        return await start(request, svc, run=True)

    @app.get("/lab/status", response_class=HTMLResponse)
    async def status(request: Request, svc: Svc) -> HTMLResponse:
        if job.running:
            return running(request)
        if job.error:
            return ui.page(request, "_lab_result.html", state="error", error=job.error)
        if job.result is None:
            return ui.page(request, "_lab_result.html", state="idle")
        lab = views.lab_view(job.result, svc.tz)
        return ui.page(request, "_lab_result.html", state="done", lab=lab)

    def saved(request: Request, svc: Svc, name: str, what: str) -> HTMLResponse:
        msg = views.Message(True, f"{what} {name}.")
        return ui.flash(request, msg, pcaps=pcaps.list_pcaps(svc.pcap_dir), selected=name, oob=True)

    @app.post("/lab/pcaps", response_class=HTMLResponse)
    async def upload(request: Request, svc: Svc, name: str = "") -> HTMLResponse:
        try:
            data = await read_body(request, pcaps.MAX_PCAP_BYTES, "pcap is over 50 MB")
            await asyncio.to_thread(pcaps.save_pcap, svc.pcap_dir, name, data)  # up to 50 MB
        except ValueError as exc:
            return bad(request, exc)
        return saved(request, svc, name, "Uploaded")

    @app.post("/lab/pcaps/generate", response_class=HTMLResponse)
    async def generate(request: Request, svc: Svc) -> HTMLResponse:
        try:
            form = await ui.form(request)
            proto = form.get("proto", "")
            if proto not in _PROTOS:
                raise ValueError("protocol must be tcp or udp")
            name = await asyncio.to_thread(  # building a big pcap is CPU work: keep it off the loop
                pcaps.generate_pcap,
                svc.pcap_dir,
                form.get("name", ""),
                proto=proto,
                src=form.get("src", ""),
                sport=_number(form, "sport", "source port"),
                dst=form.get("dst", ""),
                dport=_number(form, "dport", "destination port"),
                payload=form.get("payload", ""),
                count=_number(form, "count", "packets"),
                handshake=form.get("handshake") == "on",
            )
        except ValueError as exc:
            return bad(request, exc)
        return saved(request, svc, name, "Generated")

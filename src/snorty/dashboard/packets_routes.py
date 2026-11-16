"""Packets: inspect a pcap, summarize it, and show or open the packet behind an alert."""

import asyncio

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response

from snorty.core.models import Alert
from snorty.dashboard import pcaps, views
from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui
from snorty.packets import AlertPacket, Failed, Launched, NotFound, Unavailable

PACKET_LIMIT = 200
MAX_ID = 2**63 - 1  # SQLite's largest row id


def add_packets_routes(app: FastAPI, ui: Ui) -> None:
    @app.get("/packets/pcap", response_class=HTMLResponse)
    async def inspect(request: Request, svc: Svc) -> HTMLResponse:
        try:
            path = pcaps.pcap_path(svc.pcap_dir, request.query_params.get("pcap", ""))
        except ValueError as exc:
            view = views.packets_view(Failed(str(exc)))
            return ui.page(request, "_packets.html", status=422, view=view)
        result = await svc.packets.decode(path, PACKET_LIMIT)
        return ui.page(request, "_packets.html", view=views.packets_view(result))

    @app.get("/packets/summary", response_class=HTMLResponse)
    async def summary(request: Request, svc: Svc) -> HTMLResponse:
        try:
            path = pcaps.pcap_path(svc.pcap_dir, request.query_params.get("pcap", ""))
        except ValueError as exc:
            view = views.summary_view(Failed(str(exc)))
            return ui.page(request, "_pcap_summary.html", status=422, view=view)
        result = await svc.packets.summarize(path)
        return ui.page(request, "_pcap_summary.html", view=views.summary_view(result))

    async def stored(svc: Svc, alert_id: int) -> Alert | None:
        if not 0 < alert_id <= MAX_ID:
            return None
        return await asyncio.to_thread(svc.repo.get, alert_id)

    @app.get("/alerts/{alert_id}/packet", response_class=HTMLResponse)
    async def alert_packet(request: Request, svc: Svc, alert_id: int) -> HTMLResponse:
        alert = await stored(svc, alert_id)
        if alert is None:
            gone = NotFound("This alert is no longer stored.")
            view = views.alert_packet_view(gone, alert_id, False)
            return ui.page(request, "_alert_packet.html", view=view)
        result = await svc.packets.alert_packet(alert)
        view = views.alert_packet_view(result, alert_id, svc.packets.capabilities().open)
        return ui.page(request, "_alert_packet.html", view=view)

    @app.get("/alerts/{alert_id}/packet.pcap")
    async def alert_pcap(svc: Svc, alert_id: int) -> Response:
        alert = await stored(svc, alert_id)
        if alert is None:
            return Response("No such alert.", status_code=404, media_type="text/plain")
        result = await svc.packets.alert_packet(alert)
        if not isinstance(result, AlertPacket):
            return Response("No packet for this alert.", status_code=404, media_type="text/plain")
        headers = {"Content-Disposition": f'attachment; filename="alert-{alert_id}.pcap"'}
        return Response(result.pcap, media_type="application/vnd.tcpdump.pcap", headers=headers)

    @app.post("/alerts/{alert_id}/open", response_class=HTMLResponse)
    async def open_alert(request: Request, svc: Svc, alert_id: int) -> HTMLResponse:
        alert = await stored(svc, alert_id)
        if alert is None:
            gone = views.Message(False, "This alert is no longer stored.")
            return ui.flash(request, gone, status=404)
        match await svc.packets.open_alert_packet(alert):
            case Launched():
                return ui.flash(request, views.Message(True, "Opened the packet in Wireshark."))
            case Unavailable(reason=why):
                return ui.flash(request, views.Message(False, why), status=409)
            case Failed(message=why):
                return ui.flash(request, views.Message(False, why), status=500)
            case _:
                return ui.flash(request, views.Message(False, "Could not open it."), status=500)

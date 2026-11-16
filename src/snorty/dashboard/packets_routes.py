"""Pcap inspection: decode the packets of a pcap in data\\pcaps with Wireshark's tshark."""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from snorty.dashboard import pcaps, views
from snorty.dashboard.services import Svc
from snorty.dashboard.ui import Ui
from snorty.packets import Failed

PACKET_LIMIT = 200


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

import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from snorty.rules import ports
from snorty.rules.ports import DownloadError, SnortValidator, UrllibDownloader
from snorty.snort.models import ConfigCheck, Interface, SnortPaths

BODY = b"x" * 50


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/ok":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(BODY)
        else:
            self.send_error(404)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    ).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


async def test_downloader_gets_bytes(base_url: str) -> None:
    assert await UrllibDownloader(allow_http=True).get(f"{base_url}/ok", 100) == BODY


async def test_downloader_rejects_oversize(base_url: str) -> None:
    with pytest.raises(DownloadError, match="larger than"):
        await UrllibDownloader(allow_http=True).get(f"{base_url}/ok", 10)


async def test_downloader_maps_http_errors(base_url: str) -> None:
    with pytest.raises(DownloadError):
        await UrllibDownloader(allow_http=True).get(f"{base_url}/missing", 100)


async def test_downloader_maps_network_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    with pytest.raises(DownloadError, match="refused"):
        await UrllibDownloader(allow_http=True).get("http://example.invalid/x", 100)


async def test_downloader_is_https_only_by_default(base_url: str) -> None:
    with pytest.raises(DownloadError, match="https"):
        await UrllibDownloader().get(f"{base_url}/ok", 100)


LOOP = Interface(9, "00", None, r"\Device\NPF_Loopback", "Loopback")
WIFI = Interface(4, "11", "192.168.10.230", r"\Device\NPF_{A}", "Wi-Fi")


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[Interface]:
    used: list[Interface] = []

    async def fake_check(
        paths: SnortPaths, iface: Interface, runner: object, *, conf: Path | None = None
    ) -> ConfigCheck:
        used.append(iface)
        return ConfigCheck(True, 5, ())

    monkeypatch.setattr(ports, "check_config", fake_check)
    return used


async def test_validator_prefers_loopback(
    monkeypatch: pytest.MonkeyPatch, calls: list[Interface]
) -> None:
    async def listing(paths: SnortPaths, runner: object) -> list[Interface]:
        return [WIFI, LOOP]

    monkeypatch.setattr(ports, "list_interfaces", listing)
    result = await SnortValidator(SnortPaths()).check(Path("x.conf"))
    assert result.ok and calls == [LOOP]


async def test_validator_falls_back_to_first_interface(
    monkeypatch: pytest.MonkeyPatch, calls: list[Interface]
) -> None:
    async def listing(paths: SnortPaths, runner: object) -> list[Interface]:
        return [WIFI]

    monkeypatch.setattr(ports, "list_interfaces", listing)
    await SnortValidator(SnortPaths()).check(Path("x.conf"))
    assert calls == [WIFI]


async def test_validator_without_interfaces_fails_cleanly(
    monkeypatch: pytest.MonkeyPatch, calls: list[Interface]
) -> None:
    async def listing(paths: SnortPaths, runner: object) -> list[Interface]:
        return []

    monkeypatch.setattr(ports, "list_interfaces", listing)
    result = await SnortValidator(SnortPaths()).check(Path("x.conf"))
    assert not result.ok and "no network interface" in result.errors[0]
    assert calls == []

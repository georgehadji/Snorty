"""What the rules service needs from the outside world, and the real implementations."""

import asyncio
import urllib.error
import urllib.request
from pathlib import Path
from typing import Protocol

from snorty.sensor.states import State
from snorty.snort.models import ConfigCheck, SnortPaths
from snorty.snort.runner import Runner, SubprocessRunner
from snorty.snort.service import check_config, list_interfaces
from snorty.suricata import SuricataPaths
from snorty.suricata import check_config as check_suricata


class DownloadError(Exception):
    pass


class Downloader(Protocol):
    async def get(self, url: str, max_bytes: int) -> bytes: ...


class Validator(Protocol):
    async def check(self, conf: Path) -> ConfigCheck: ...


class SensorControl(Protocol):
    @property
    def state(self) -> State: ...

    async def restart(self) -> None: ...


class UrllibDownloader:
    def __init__(self, *, allow_http: bool = False, timeout: float = 60.0) -> None:
        self._allow_http = allow_http
        self._timeout = timeout

    async def get(self, url: str, max_bytes: int) -> bytes:
        if not (url.startswith("https://") or (self._allow_http and url.startswith("http://"))):
            raise DownloadError(f"only https downloads are allowed: {url}")
        return await asyncio.to_thread(self._get, url, max_bytes)

    def _get(self, url: str, max_bytes: int) -> bytes:
        request = urllib.request.Request(url, headers={"User-Agent": "snorty-rules"})
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                data: bytes = resp.read(max_bytes + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise DownloadError(f"download failed: {e}") from e
        if len(data) > max_bytes:
            raise DownloadError(f"download is larger than {max_bytes} bytes")
        return data


class SnortValidator:
    """`snort -T` against any config file. -T needs an interface; any one will do."""

    def __init__(self, paths: SnortPaths, runner: Runner | None = None) -> None:
        self._paths = paths
        self._runner: Runner = runner or SubprocessRunner()

    async def check(self, conf: Path) -> ConfigCheck:
        interfaces = await list_interfaces(self._paths, self._runner)
        if not interfaces:
            return ConfigCheck(False, None, ("no network interface found for snort -T",))
        iface = next((i for i in interfaces if "Loopback" in i.device), interfaces[0])
        return await check_config(self._paths, iface, self._runner, conf=conf)


class SuricataValidator:
    """`suricata -T` against any config file."""

    def __init__(self, paths: SuricataPaths, runner: Runner | None = None) -> None:
        self._paths = paths
        self._runner: Runner = runner or SubprocessRunner()

    async def check(self, conf: Path) -> ConfigCheck:
        return await check_suricata(self._paths, self._runner, conf=conf)


def validator_for(paths: SnortPaths | SuricataPaths, runner: Runner | None = None) -> Validator:
    """The validator that matches the paths' engine."""
    if isinstance(paths, SuricataPaths):
        return SuricataValidator(paths, runner)
    return SnortValidator(paths, runner)

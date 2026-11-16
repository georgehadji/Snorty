"""Test doubles and a ready-made Snort directory for the rules service tests."""

import asyncio
import hashlib
import io
import os
import tarfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import RulesUpdated
from snorty.rules.config import RulesConfig
from snorty.rules.ports import DownloadError
from snorty.rules.service import RulesService
from snorty.sensor.states import State
from snorty.snort.models import ConfigCheck, SnortPaths

URL = "https://rules.test/emerging.rules.tar.gz"
NOW = datetime(2026, 11, 16, 4, 0, tzinfo=UTC)


def rule(sid: int) -> str:
    return f'alert tcp any any -> any any (msg:"rule {sid}"; sid:{sid};)\n'


def make_archive(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # noqa: S324


class FakeDownloader:
    def __init__(self, archive: bytes | Exception, md5_text: str | None = None) -> None:
        self.archive = archive
        self.md5_text = md5_text
        self.calls: list[str] = []

    async def get(self, url: str, max_bytes: int) -> bytes:
        self.calls.append(url)
        if url.endswith(".md5"):
            if self.md5_text is not None:
                return self.md5_text.encode()
            if isinstance(self.archive, Exception):
                raise self.archive
            return f"{md5(self.archive)}  emerging.rules.tar.gz\n".encode()
        if isinstance(self.archive, Exception):
            raise self.archive
        if len(self.archive) > max_bytes:
            raise DownloadError("too big")
        return self.archive


@dataclass
class FakeValidator:
    results: list[ConfigCheck] = field(default_factory=list)
    seen: list[str] = field(default_factory=list)  # text of each conf checked

    async def check(self, conf: Path) -> ConfigCheck:
        self.seen.append(conf.read_text(encoding="utf-8"))
        return self.results.pop(0) if self.results else ConfigCheck(True, 100, ())


class FakeSensor:
    def __init__(self, state: State = State.RUNNING) -> None:
        self._state = state
        self.restarts = 0
        self.results: list[State | None] = []  # per restart: end state, or None = hang forever

    @property
    def state(self) -> State:
        return self._state

    async def restart(self) -> None:
        self.restarts += 1
        result = self.results.pop(0) if self.results else State.RUNNING
        if result is None:
            await asyncio.Event().wait()
        else:
            self._state = result


class FlakyRename:
    """os.replace that fails on the given (1-based) call numbers."""

    def __init__(self, fail_on: set[int]) -> None:
        self.fail_on = fail_on
        self.calls = 0

    def __call__(self, src: Path, dst: Path) -> None:
        self.calls += 1
        if self.calls in self.fail_on:
            raise OSError(f"rename {self.calls} refused")
        os.replace(src, dst)


class Rig:
    def __init__(
        self,
        tmp_path: Path,
        archive: bytes | Exception | None = None,
        *,
        md5_text: str | None = None,
        rename: FlakyRename | None = None,
        **config: object,
    ) -> None:
        self.root = tmp_path / "snort"
        self.rules = self.root / "rules"
        self.etc = self.root / "etc"
        self.rules.mkdir(parents=True)
        self.etc.mkdir()
        (self.rules / "emerging-old.rules").write_text(rule(1) + rule(2) + rule(3) + rule(4))
        (self.rules / "local.rules").write_text("# mine\r\n" + rule(1000001))
        (self.rules / "white_list.rules").write_bytes(b"1.2.3.4\r\n")
        self.conf_text = (
            "ipvar HOME_NET [192.168.1.0/24]\r\n"
            f"var RULE_PATH {self.rules}\r\n"
            "include classification.config\r\n"
            "include threshold.conf\r\n"
        )
        (self.etc / "snort.conf").write_bytes(self.conf_text.encode())
        (self.etc / "threshold.conf").write_bytes(b"# thresholds\r\n")
        self.config = RulesConfig(
            paths=SnortPaths(
                exe=self.root / "bin" / "snort.exe",
                conf=self.etc / "snort.conf",
                log_dir=self.root / "log",
            ),
            rules_dir=self.rules,
            url=URL,
            **config,  # type: ignore[arg-type]
        )
        self.downloader = FakeDownloader(
            archive if archive is not None else self.good_archive(), md5_text
        )
        self.validator = FakeValidator()
        self.sensor = FakeSensor()
        self.bus = EventBus()
        self.sub: Subscription = self.bus.subscribe(maxsize=100)
        self.service = RulesService(
            self.config,
            self.downloader,
            self.validator,
            self.sensor,
            self.bus,
            clock=lambda: NOW,
            rename=rename or os.replace,
        )

    @staticmethod
    def good_archive() -> bytes:
        return make_archive(
            {
                "rules/emerging-old.rules": rule(1) + rule(2) + rule(5),
                "rules/emerging-a.rules": rule(10) + rule(11),
                "rules/local.rules": "# hostile overwrite\n",
                "rules/README.txt": "ignored",
            }
        )

    def snapshot(self) -> dict[str, bytes]:
        """Every file under the Snort root, for byte-identical comparisons."""
        return {
            str(p.relative_to(self.root)): p.read_bytes()
            for p in sorted(self.root.rglob("*"))
            if p.is_file()
        }

    def events(self) -> list[RulesUpdated]:
        out: list[RulesUpdated] = []
        while True:
            try:
                ev = self.sub._queue.get_nowait()
            except Exception:
                return out
            if isinstance(ev, RulesUpdated):
                out.append(ev)

"""The rules use cases: update the ruleset, mute rules, set HOME_NET.

Every operation edits a candidate, checks it with `snort -T`, and only then commits.
"""

import asyncio
import hashlib
import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from snorty.core.bus import EventBus
from snorty.core.events import RulesUpdated
from snorty.rules.archive import count_rules, extract_rules, parse_md5, sanity_ok
from snorty.rules.blocks import (
    MutedRule,
    apply_block,
    get_home_net,
    read_block,
    rewrite_include,
    rewrite_rule_path,
    set_home_net,
)
from snorty.rules.config import RulesConfig
from snorty.rules.ports import Downloader, SensorControl, Validator
from snorty.rules.state import RulesState, load_state, save_state
from snorty.sensor.states import State


@dataclass(frozen=True, slots=True)
class UpdateReport:
    outcome: Literal["updated", "up_to_date", "failed"]
    rule_count: int | None
    md5: str | None
    skipped: int
    detail: str


@dataclass(frozen=True, slots=True)
class EditReport:
    ok: bool
    changed: bool
    detail: str


def read_text(path: Path) -> str:
    """Lossless read that keeps line endings (the files are mostly ASCII, not always UTF-8)."""
    return path.read_bytes().decode("utf-8", "surrogateescape")


def write_text(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8", "surrogateescape"))


class RulesService:
    def __init__(
        self,
        config: RulesConfig,
        downloader: Downloader,
        validator: Validator,
        sensor: SensorControl,
        bus: EventBus,
        *,
        clock: Callable[[], datetime],
        rename: Callable[[Path, Path], object] = os.replace,
    ) -> None:
        self._config = config
        self._downloader = downloader
        self._validator = validator
        self._sensor = sensor
        self._bus = bus
        self._clock = clock
        self._rename = rename
        self._lock = asyncio.Lock()
        self._step = "download"  # which stage an exception came from; the lock serialises use

    async def update(self, *, force: bool = False) -> UpdateReport:
        """Update the ruleset. Never raises: a failure is a report, and the live rules are
        left exactly as they were."""
        async with self._lock:
            self._step = "download"
            try:
                return await self._update(force)
            except Exception as e:
                return await self._fail(f"{self._step}: {e}")

    async def _fail(self, detail: str) -> UpdateReport:
        await asyncio.to_thread(shutil.rmtree, self._new_dir, True)
        state = await asyncio.to_thread(load_state, self._config.state_path)
        self._bus.publish(RulesUpdated(False, state.rule_count or 0, detail))
        return UpdateReport("failed", state.rule_count, None, 0, detail)

    @property
    def _new_dir(self) -> Path:
        return self._config.rules_dir.with_name("rules.new")

    # --- update -----------------------------------------------------------------------

    async def _update(self, force: bool) -> UpdateReport:
        cfg = self._config
        self._step = "download"
        expected = parse_md5((await self._downloader.get(cfg.url + ".md5", 4096)).decode())
        state = await asyncio.to_thread(load_state, cfg.state_path)
        if not force and state.last_md5 == expected:
            return UpdateReport("up_to_date", state.rule_count, expected, 0, "already up to date")

        tarball = await self._downloader.get(cfg.url, cfg.max_download)
        if await asyncio.to_thread(lambda: hashlib.md5(tarball).hexdigest()) != expected:  # noqa: S324
            raise ValueError("md5 mismatch")

        self._step = "stage"
        new_dir = self._new_dir
        skipped, count = await asyncio.to_thread(self._stage, tarball, new_dir)

        self._step = "validate"
        stage_conf = cfg.paths.conf.with_name("snorty-stage.conf")
        text = rewrite_rule_path(read_text(cfg.paths.conf), str(new_dir))
        write_text(stage_conf, text)
        try:
            check = await self._validator.check(stage_conf)
        finally:
            stage_conf.unlink(missing_ok=True)
        if not check.ok:
            raise ValueError("; ".join(check.errors))

        self._step = "swap"
        await asyncio.to_thread(self._swap, new_dir)
        if self._sensor.state in (State.RUNNING, State.STARTING):
            self._step = "restart"
            if not await self._restart_ok():
                await self._roll_back()
                raise RuntimeError("sensor did not come back with the new rules; rolled back")

        saved = RulesState(expected, self._clock().isoformat(), count, "ok")
        await asyncio.to_thread(save_state, cfg.state_path, saved)
        detail = f"{count} rules"
        self._bus.publish(RulesUpdated(True, count, detail))
        return UpdateReport("updated", count, expected, skipped, detail)

    async def _restart_ok(self) -> bool:
        try:
            await asyncio.wait_for(self._sensor.restart(), self._config.health_timeout)
        except TimeoutError:
            return False
        return self._sensor.state is State.RUNNING

    async def _roll_back(self) -> None:
        live = self._config.rules_dir
        try:
            await asyncio.to_thread(self._unswap)
        except OSError as e:
            raise RuntimeError(
                f"rollback failed ({e}); the previous rules are in {live.with_name('rules.prev')}"
            ) from e
        await self._restart_ok()  # best effort: the old rules are back either way

    def _stage(self, tarball: bytes, new_dir: Path) -> tuple[int, int]:
        """Copy the live rules, overlay the archive's. Returns (skipped members, rule count)."""
        if new_dir.exists():
            shutil.rmtree(new_dir)
        shutil.copytree(self._config.rules_dir, new_dir)
        report = extract_rules(tarball, new_dir)
        if not report.written:
            raise ValueError("the archive contained no rules files")
        count = count_rules(new_dir)
        if not sanity_ok(count, count_rules(self._config.rules_dir), self._config.min_ratio):
            raise ValueError("new ruleset is much smaller than the current one")
        return report.skipped, count

    def _swap(self, new_dir: Path) -> None:
        live = self._config.rules_dir
        prev, tmp = live.with_name("rules.prev"), live.with_name("rules.swap")
        if prev.exists():
            shutil.rmtree(prev)
        self._rename(live, tmp)
        try:
            self._rename(new_dir, live)
        except OSError:
            self._rename(tmp, live)
            raise
        try:
            self._rename(tmp, prev)
        except OSError:
            self._rename(live, new_dir)
            self._rename(tmp, live)
            raise

    def _unswap(self) -> None:
        live = self._config.rules_dir
        self._rename(live, self._new_dir)
        self._rename(live.with_name("rules.prev"), live)

    # --- mute, unmute, HOME_NET -------------------------------------------------------

    async def status(self) -> RulesState:
        return await asyncio.to_thread(load_state, self._config.state_path)

    async def muted(self) -> list[MutedRule]:
        text = await asyncio.to_thread(read_text, self._config.threshold_conf)
        return read_block(text)

    async def mute(self, sid: int, note: str = "", *, restart: bool = True) -> EditReport:
        def edit(entries: list[MutedRule]) -> list[MutedRule]:
            return [e for e in entries if e.sid != sid] + [MutedRule(sid, note)]

        return await self._edit_threshold(edit, f"muted {sid}", restart)

    async def unmute(self, sid: int, *, restart: bool = True) -> EditReport:
        def edit(entries: list[MutedRule]) -> list[MutedRule]:
            return [e for e in entries if e.sid != sid]

        return await self._edit_threshold(edit, f"unmuted {sid}", restart)

    async def home_net(self) -> tuple[str, str]:
        """(current value in snort.conf, the value `set_home_net()` would write)."""
        text = await asyncio.to_thread(read_text, self._config.paths.conf)
        return get_home_net(text), self._config.home_net_default

    async def set_home_net(self, value: str | None = None, *, restart: bool = True) -> EditReport:
        conf = self._config.paths.conf
        new_value = value or self._config.home_net_default
        async with self._lock:
            try:
                old = await asyncio.to_thread(read_text, conf)
                new = set_home_net(old, new_value)
                return await self._commit(
                    conf, old, new, lambda _: new, f"HOME_NET {new_value}", restart
                )
            except Exception as e:
                return EditReport(False, False, str(e))

    async def _edit_threshold(
        self, edit: Callable[[list[MutedRule]], list[MutedRule]], done: str, restart: bool
    ) -> EditReport:
        target = self._config.threshold_conf
        async with self._lock:
            try:
                old = await asyncio.to_thread(read_text, target)
                new = apply_block(old, edit(read_block(old)))
                conf_text = await asyncio.to_thread(read_text, self._config.paths.conf)

                def stage_text(candidate: Path) -> str:
                    return rewrite_include(conf_text, "threshold.conf", str(candidate))

                return await self._commit(target, old, new, stage_text, done, restart)
            except Exception as e:
                return EditReport(False, False, str(e))

    async def _commit(
        self,
        target: Path,
        old: str,
        new: str,
        stage_text: Callable[[Path], str],
        done: str,
        restart: bool,
    ) -> EditReport:
        """Check `new` with snort -T through a temp conf, then replace `target` atomically."""
        if new == old:
            return EditReport(True, False, "no change")
        candidate = target.with_name("snorty-candidate" + target.suffix)
        stage_conf = self._config.paths.conf.with_name("snorty-stage.conf")
        try:
            write_text(candidate, new)
            write_text(stage_conf, stage_text(candidate))
            check = await self._validator.check(stage_conf)
        finally:
            candidate.unlink(missing_ok=True)
            stage_conf.unlink(missing_ok=True)
        if not check.ok:
            return EditReport(False, False, "; ".join(check.errors))
        await asyncio.to_thread(self._replace_file, target, new)
        if restart and self._sensor.state in (State.RUNNING, State.STARTING):
            if not await self._restart_ok():
                return EditReport(False, True, f"{done}, but the sensor did not come back running")
        return EditReport(True, True, done)

    @staticmethod
    def _replace_file(target: Path, text: str) -> None:
        backup = target.with_name(target.name + ".snorty.bak")
        if not backup.exists():
            shutil.copy2(target, backup)
        tmp = target.with_name(target.name + ".snorty.tmp")
        write_text(tmp, text)
        os.replace(tmp, target)

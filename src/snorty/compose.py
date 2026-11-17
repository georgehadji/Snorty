"""Builds the real Snorty services from paths and options (used by the dashboard)."""

import asyncio
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from snorty.attribution import AttributionService
from snorty.attribution.ports import ConnectionHistory, NoHistory
from snorty.core.bus import EventBus
from snorty.core.decoder import AlertDecoder, EveDecoder, FastDecoder
from snorty.core.localtz import LocalTimezone
from snorty.core.repository import AlertRepository
from snorty.enrich import EnrichService, ReverseDns, urllib_fetch
from snorty.explain import ExplainService, OllamaExplainer
from snorty.journal.ports import NoteStore
from snorty.journal.service import JournalConfig, JournalService
from snorty.lab.engines import LabEngine, SuricataLabEngine
from snorty.lab.service import LabService
from snorty.notify.ports import Notifier, WinotifyNotifier
from snorty.notify.service import NotifyService
from snorty.packets import NoDecoder, PacketService
from snorty.respond import BlockService
from snorty.rules.config import SURICATA_ET_URL, RulesConfig
from snorty.rules.find import find_rule
from snorty.rules.info import RuleInfo
from snorty.rules.ports import SnortValidator, SuricataValidator, UrllibDownloader, Validator
from snorty.rules.service import RulesService
from snorty.rules.suricata_home import prepare_suricata_home
from snorty.sensor import EnginePort, Sensor, SensorConfig, SnortAdapter
from snorty.sensor.port import SuricataAdapter
from snorty.services import Services
from snorty.snort import PERFMON_FILE, DropReader, Interface, SnortPaths, SubprocessRunner
from snorty.snort.interfaces import find_local_ip
from snorty.suricata import SuricataPaths
from snorty.triage import TriageService
from snorty.winevt import SysmonHistory, probe
from snorty.winfw import PowerShellFirewall
from snorty.winnet import WinConnectionLookup
from snorty.wireshark import DumpcapRecorder, TsharkDecoder, WiresharkViewer, find_tools

log = logging.getLogger("snorty")


@dataclass(slots=True)
class Runtime:
    """The built services plus the background pieces that need start and stop."""

    services: Services
    notify: NotifyService | None
    journal: JournalService | None
    triage: TriageService | None = None
    attribution: AttributionService | None = None
    enrich: EnrichService | None = None
    respond: BlockService | None = None
    explain: ExplainService | None = None

    async def start(self, *, sensor: bool = False) -> None:
        try:
            if self.notify:
                await self.notify.start()
            if self.journal:
                await self.journal.start()
            if self.triage:
                await self.triage.start()
            if self.attribution:
                await self.attribution.start()
            if self.enrich:
                await self.enrich.start()
            if self.respond:
                await self.respond.start()
            if self.explain:
                await self.explain.start()
            if sensor:
                await self.services.sensor.start()
        except BaseException:  # leave nothing half started
            await self.stop()
            raise

    async def stop(self) -> None:
        """Stop everything that was started; does not close the repository. A part that fails
        to stop does not keep the others running."""
        stops = [
            self.services.sensor.stop,
            *(
                p.stop
                for p in (
                    self.explain,
                    self.respond,
                    self.enrich,
                    self.attribution,
                    self.triage,
                    self.journal,
                )
                if p
            ),
            *([self.notify.stop] if self.notify else []),
        ]
        first: BaseException | None = None
        for i, stop in enumerate(stops):
            try:
                await (asyncio.shield(stop()) if i == 0 else stop())
            except BaseException as exc:  # keep stopping the rest, then re-raise the first
                first = first or exc
        if first is not None:
            raise first


def _connection_history() -> ConnectionHistory:
    """The Sysmon log when it can be read, else nothing (said once in the log)."""
    reason = probe()
    if reason is None:
        return SysmonHistory()
    log.info("past connections are not attributed: %s", reason)
    return NoHistory()


def compose(
    data_dir: Path,
    *,
    db_path: Path | None = None,
    interface_ip: str | None = None,
    notify: bool = False,
    notifier: Notifier | None = None,
    journal_store: NoteStore | None = None,
    paths: SnortPaths | None = None,
    select_interface: Callable[[list[Interface]], Interface | None] | None = None,
    wireshark_dir: Path | None = None,
    host_context: bool = False,
    engine: Literal["snort", "suricata"] = "snort",
    suricata_install: Path | None = None,
    respond: bool = False,
    explain_model: str = "",
    explain_language: str = "English",
    explain_audience: str = "home",
    explain_prewarm: bool = False,
) -> Runtime:
    """Wire every module together. The journal runs only when a note store is given. With
    `host_context` the PC's connection table and public data downloads are used for alerts
    (which program made the connection, where the remote address is, known-bad lists)."""
    data_dir.mkdir(parents=True, exist_ok=True)
    runner = SubprocessRunner()
    tz = LocalTimezone()
    adapter: EnginePort
    decoder: AlertDecoder | None = None
    validator: Validator
    lab_engine: LabEngine | None = None
    sensor_paths: SnortPaths | SuricataPaths
    if engine == "suricata":
        # Snorty edits its own copy of the config and rules, not the read-only install.
        install = suricata_install or SuricataPaths().exe.parent
        sensor_paths = prepare_suricata_home(install, data_dir / "suricata")
        rules_config = RulesConfig(
            paths=sensor_paths,
            engine="suricata",
            rules_dir=sensor_paths.conf.parent / "rules",
            url=SURICATA_ET_URL,
        )
        adapter, decoder = SuricataAdapter(sensor_paths, runner), EveDecoder()
        validator = SuricataValidator(sensor_paths, runner)
        lab_engine = SuricataLabEngine(sensor_paths, runner)
    else:
        paths = paths or SnortPaths()
        sensor_paths = paths
        decoder = FastDecoder(tz, DropReader(paths.log_dir / PERFMON_FILE))
        rules_config = RulesConfig(paths=paths)
        adapter, validator = SnortAdapter(paths), SnortValidator(paths)
    bus = EventBus()
    repo = AlertRepository(db_path or data_dir / "snorty.db")
    config = SensorConfig(paths=sensor_paths, interface_ip=interface_ip)
    sensor = Sensor(
        config,
        adapter,
        repo,
        bus,
        clock=time.monotonic,
        sleep=asyncio.sleep,
        tz=tz,
        select_interface=select_interface,
        decoder=decoder,
    )
    rules = RulesService(
        rules_config,
        UrllibDownloader(),
        validator,
        sensor,
        bus,
        clock=lambda: datetime.now().astimezone(),
    )
    try:  # a crash in the middle of a rules swap must not leave Snort without its rules
        rules.recover()
    except OSError:
        log.exception("could not repair an interrupted rules swap")
    lab = LabService(paths or SnortPaths(), runner, tz=tz, engine=lab_engine)
    toasts = NotifyService(bus, notifier or WinotifyNotifier()) if notify else None
    journal = (
        JournalService(bus, repo, journal_store, JournalConfig(tz=tz)) if journal_store else None
    )
    tools = find_tools(configured=wireshark_dir, env=os.environ)
    packets = PacketService(
        TsharkDecoder(tools.tshark) if tools.tshark else NoDecoder(),
        WiresharkViewer(tools.wireshark) if tools.wireshark else None,
        DumpcapRecorder(tools.dumpcap) if tools.dumpcap else None,
        snort_logs=sensor_paths.log_dir,
        scratch=data_dir / "opened",
    )
    blocker = BlockService(repo, PowerShellFirewall(runner)) if respond else None
    explainer = (
        ExplainService(
            repo,
            OllamaExplainer(explain_model, language=explain_language, audience=explain_audience),
            lambda sid: find_rule(rules_config.rules_dir, sid),
            bus=bus if explain_prewarm else None,
        )
        if explain_model
        else None
    )
    services = Services(
        sensor,
        rules,
        journal,
        toasts,
        lab,
        repo,
        bus,
        tz,
        data_dir,
        packets,
        respond=blocker,
        explain=explainer,
        engine=engine,
        rule_info=RuleInfo(lambda sid: find_rule(rules_config.rules_dir, sid)),
    )
    attribution = enrich = None
    if host_context:
        attribution = AttributionService(
            bus, repo, WinConnectionLookup(), find_local_ip, _connection_history()
        )
        enrich = EnrichService(
            bus, repo, data_dir / "enrich", fetch=urllib_fetch, rdns=ReverseDns()
        )
    return Runtime(
        services, toasts, journal, TriageService(bus, repo), attribution, enrich, blocker, explainer
    )

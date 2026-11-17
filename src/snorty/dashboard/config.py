"""Dashboard settings: defaults, an optional `snorty.toml`, then command-line overrides."""

import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from snorty.notify.ports import valid_channel_url
from snorty.suricata import SuricataPaths

CONFIG_NAME = "snorty.toml"
_TIME = re.compile(r"([01]\d|2[0-3]):[0-5]\d")
ENGINES = ("snort", "suricata")
_ENGINE_LINE = re.compile(r"^engine[ 	]*=.*$", re.M)
_FIRST_TABLE = re.compile(r"^\[", re.M)


class ConfigError(ValueError):
    """The config file or an override has a bad key or value."""


@dataclass(frozen=True, slots=True)
class DashConfig:
    data_dir: Path
    port: int = 8765
    interface_ip: str | None = None
    vault: str | None = None
    wireshark_dir: str | None = None  # folder holding tshark.exe; default: found automatically
    notify: bool = True
    respond: bool = True  # offer Block buttons that add Windows Firewall rules
    explain_model: str = ""  # an Ollama model that runs on this PC; empty switches explaining off
    journal: bool = True
    autostart_sensor: bool = False
    engine: str = "snort"  # "snort" or "suricata"; load_config picks Suricata when it is installed
    rules_update_at: str = "03:00"  # local "HH:MM"; empty string disables the daily update
    retention_days: int = 90  # alerts older than this are deleted; 0 keeps everything
    channels: tuple[Mapping[str, str], ...] = ()  # extra toast channels: {kind, url}


def default_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    return (Path(base) if base else Path.home()) / "Snorty"


def default_engine(suricata_exe: Path | None = None) -> str:
    """Suricata when it is installed, else Snort."""
    exe = suricata_exe or SuricataPaths().exe
    return "suricata" if exe.is_file() else "snort"


def _check_channels(value: object) -> tuple[Mapping[str, str], ...]:
    msg = 'channels must be a list of {kind = "webhook" or "ntfy", url = "http(s)://..."}'
    if not isinstance(value, list | tuple):
        raise ConfigError(msg)
    for c in value:
        if not isinstance(c, Mapping) or c.get("kind") not in ("webhook", "ntfy"):
            raise ConfigError(msg)
        if not valid_channel_url(c.get("url")):
            raise ConfigError("a channel url must be http or https")
    return tuple({"kind": c["kind"], "url": c["url"]} for c in value)


def _check(key: str, value: object) -> object:
    if key == "port":
        if type(value) is not int or not 0 < value < 65536:
            raise ConfigError("port must be a whole number from 1 to 65535")
    elif key in ("notify", "respond", "journal", "autostart_sensor"):
        if type(value) is not bool:
            raise ConfigError(f"{key} must be true or false")
    elif key == "retention_days":
        if type(value) is not int or not 0 <= value <= 36500:
            raise ConfigError("retention_days must be a whole number from 0 to 36500")
    elif key == "engine":
        if value not in ENGINES:
            raise ConfigError('engine must be "snort" or "suricata"')
    elif key == "channels":
        value = _check_channels(value)
    elif key in ("interface_ip", "vault", "wireshark_dir", "explain_model"):
        if not isinstance(value, str):
            raise ConfigError(f"{key} must be text")
    elif key == "rules_update_at":
        if not isinstance(value, str) or (value and not _TIME.fullmatch(value)):
            raise ConfigError('rules_update_at must be "HH:MM" (24 hours) or ""')
    else:
        raise ConfigError(f"unknown setting: {key}")
    return value


def load_config(data_dir: Path, overrides: Mapping[str, object] | None = None) -> DashConfig:
    """Defaults, then `<data_dir>/snorty.toml`, then overrides (None means not given)."""
    values: dict[str, object] = {}
    path = data_dir / CONFIG_NAME
    if path.is_file():
        try:
            values.update(tomllib.loads(path.read_text(encoding="utf-8")))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    values.update({k: v for k, v in (overrides or {}).items() if v is not None})
    values.setdefault("engine", default_engine())
    checked: dict[str, Any] = {k: _check(k, v) for k, v in values.items()}
    return replace(DashConfig(data_dir=data_dir), **checked)


def save_engine(data_dir: Path, engine: str) -> None:
    """Write `engine = "..."` into `<data_dir>/snorty.toml`, keeping the rest of the file. It takes
    effect the next time the dashboard starts."""
    if engine not in ENGINES:
        raise ConfigError('engine must be "snort" or "suricata"')
    path = data_dir / CONFIG_NAME
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    line = f'engine = "{engine}"'
    if _ENGINE_LINE.search(text):
        text = _ENGINE_LINE.sub(line, text, count=1)
    elif table := _FIRST_TABLE.search(text):  # a top-level key must come before any [table]
        text = f"{text[: table.start()]}{line}\n\n{text[table.start() :]}"
    else:
        text += ("" if not text or text.endswith("\n") else "\n") + line + "\n"
    data_dir.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".toml.tmp")
    tmp.write_text(text, encoding="utf-8", newline="")
    tmp.replace(path)

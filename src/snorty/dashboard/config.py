"""Dashboard settings: defaults, an optional `snorty.toml`, then command-line overrides."""

import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

CONFIG_NAME = "snorty.toml"
_TIME = re.compile(r"([01]\d|2[0-3]):[0-5]\d")


class ConfigError(ValueError):
    """The config file or an override has a bad key or value."""


@dataclass(frozen=True, slots=True)
class DashConfig:
    data_dir: Path
    port: int = 8765
    interface_ip: str | None = None
    vault: str | None = None
    notify: bool = True
    journal: bool = True
    autostart_sensor: bool = False
    rules_update_at: str = "03:00"  # local "HH:MM"; empty string disables the daily update


def default_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    return (Path(base) if base else Path.home()) / "Snorty"


def _check(key: str, value: object) -> object:
    if key == "port":
        if type(value) is not int or not 0 < value < 65536:
            raise ConfigError("port must be a whole number from 1 to 65535")
    elif key in ("notify", "journal", "autostart_sensor"):
        if type(value) is not bool:
            raise ConfigError(f"{key} must be true or false")
    elif key in ("interface_ip", "vault"):
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
    checked: dict[str, Any] = {k: _check(k, v) for k, v in values.items()}
    return replace(DashConfig(data_dir=data_dir), **checked)

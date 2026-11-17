from pathlib import Path

import pytest

from snorty.dashboard.config import ConfigError, DashConfig, default_data_dir, load_config


def write(tmp_path: Path, text: str) -> None:
    (tmp_path / "snorty.toml").write_text(text, encoding="utf-8")


def test_missing_file_gives_defaults(tmp_path: Path) -> None:
    cfg = load_config(tmp_path)
    assert cfg == DashConfig(data_dir=tmp_path)
    assert (cfg.port, cfg.rules_update_at, cfg.autostart_sensor) == (8765, "03:00", False)
    assert cfg.retention_days == 90


def test_file_values_are_read(tmp_path: Path) -> None:
    write(
        tmp_path,
        'port = 9000\nvault = "C:/v"\nnotify = false\nautostart_sensor = true\n'
        'rules_update_at = "04:30"\ninterface_ip = "10.0.0.5"\n',
    )
    cfg = load_config(tmp_path)
    assert cfg.port == 9000 and cfg.vault == "C:/v" and cfg.notify is False
    assert cfg.autostart_sensor is True and cfg.rules_update_at == "04:30"
    assert cfg.interface_ip == "10.0.0.5"


def test_overrides_win_and_none_is_ignored(tmp_path: Path) -> None:
    write(tmp_path, "port = 9000\nnotify = false\n")
    cfg = load_config(tmp_path, {"port": 9100, "notify": None, "vault": "X"})
    assert cfg.port == 9100 and cfg.notify is False and cfg.vault == "X"


def test_empty_update_time_disables_the_schedule(tmp_path: Path) -> None:
    write(tmp_path, 'rules_update_at = ""\n')
    assert load_config(tmp_path).rules_update_at == ""


@pytest.mark.parametrize(
    "text",
    [
        "bogus = 1",
        'port = "80"',
        "port = 0",
        "port = 70000",
        "port = true",
        "notify = 1",
        "retention_days = -1",
        'retention_days = "90"',
        "retention_days = true",
        'rules_update_at = "25:00"',
        'rules_update_at = "3am"',
        "rules_update_at = 3",
        "vault = 5",
        "this is not toml",
        "data_dir = 'x'",
    ],
)
def test_bad_files_raise_config_error(tmp_path: Path, text: str) -> None:
    write(tmp_path, text + "\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_a_bad_override_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path, {"port": 99999})


def test_default_data_dir_uses_localappdata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", "C:/Users/x/AppData/Local")
    assert default_data_dir() == Path("C:/Users/x/AppData/Local") / "Snorty"


def test_channels_come_from_the_toml_file(tmp_path: Path) -> None:
    (tmp_path / "snorty.toml").write_text(
        '[[channels]]\nkind = "ntfy"\nurl = "https://ntfy.sh/t"\n'
        '[[channels]]\nkind = "webhook"\nurl = "http://nas.lan/hook"\n'
    )
    cfg = load_config(tmp_path)
    assert [c["kind"] for c in cfg.channels] == ["ntfy", "webhook"]
    assert load_config(tmp_path / "none").channels == ()


@pytest.mark.parametrize(
    "bad",
    ['channels = "x"', 'channels = [{kind = "sms", url = "https://x/y"}]',
     'channels = [{kind = "ntfy", url = "file:///x"}]', 'channels = [{kind = "ntfy"}]'],
)  # fmt: skip
def test_bad_channels_are_refused(tmp_path: Path, bad: str) -> None:
    (tmp_path / "snorty.toml").write_text(bad + "\n")
    with pytest.raises(ConfigError, match="channel"):
        load_config(tmp_path)

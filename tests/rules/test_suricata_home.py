from pathlib import Path

import pytest

from snorty.compose import compose
from snorty.dashboard.config import ConfigError, load_config
from snorty.rules.suricata_home import prepare_suricata_home
from snorty.sensor.states import State

STOCK = (
    "default-log-dir: C:\\Program Files\\Suricata\\log\n"
    "default-rule-path: C:\\Program Files\\Suricata\\rules\\\n"
    "rule-files:\n"
    " - botcc.rules\n"
    " - decoder-events.rules\n"
    "classification-file: C:\\Program Files\\Suricata\\classification.config\n"
    "reference-config-file: C:\\Program Files\\Suricata\\reference.config\n"
)


def fake_install(root: Path) -> Path:
    install = root / "Suricata"
    (install / "rules").mkdir(parents=True)
    (install / "suricata.yaml").write_text(STOCK)
    (install / "classification.config").write_text("class")
    (install / "reference.config").write_text("ref")
    (install / "rules" / "decoder-events.rules").write_text(
        "alert ip any any -> any any (sid:1;)\n"
    )
    return install


def test_home_is_made_from_the_install_and_points_at_itself(tmp_path: Path) -> None:
    home = tmp_path / "data" / "suricata"
    paths = prepare_suricata_home(fake_install(tmp_path), home)

    assert paths.conf == home / "suricata.yaml" and paths.log_dir == home / "log"
    assert paths.exe == tmp_path / "Suricata" / "suricata.exe"
    text = paths.conf.read_text()
    assert f"default-rule-path: {home / 'rules'}" in text
    assert f"default-log-dir: {home / 'log'}" in text
    assert f"classification-file: {home / 'classification.config'}" in text
    assert f"threshold-file: {home / 'threshold.config'}" in text
    assert "Program Files" not in text
    assert (home / "rules" / "decoder-events.rules").read_text().startswith("alert")
    assert (home / "reference.config").read_text() == "ref"


def test_listed_rule_files_the_install_lacks_get_empty_placeholders(tmp_path: Path) -> None:
    home = tmp_path / "home"
    prepare_suricata_home(fake_install(tmp_path), home)
    assert (home / "rules" / "botcc.rules").read_text() == ""
    assert (home / "rules" / "decoder-events.rules").read_text() != ""


def test_an_existing_home_is_left_alone(tmp_path: Path) -> None:
    home = tmp_path / "home"
    install = fake_install(tmp_path)
    prepare_suricata_home(install, home)
    (home / "suricata.yaml").write_text("mine: true\n")
    (home / "rules" / "extra.rules").write_text("x")

    prepare_suricata_home(install, home)

    assert (home / "suricata.yaml").read_text() == "mine: true\n"
    assert (home / "rules" / "extra.rules").read_text() == "x"


async def test_compose_with_suricata_uses_the_owned_copy_and_eve_json(tmp_path: Path) -> None:
    install = fake_install(tmp_path)
    rt = compose(tmp_path / "data", engine="suricata", suricata_install=install)
    try:
        assert rt.services.sensor.state is State.STOPPED
        assert (tmp_path / "data" / "suricata" / "suricata.yaml").exists()
        assert rt.services.sensor._alert_path == tmp_path / "data" / "suricata" / "log" / "eve.json"
        await rt.start(sensor=False)
        await rt.stop()
    finally:
        rt.services.repo.close()


def test_engine_is_a_setting_with_two_values(tmp_path: Path) -> None:
    assert load_config(tmp_path).engine == "snort"
    assert load_config(tmp_path, {"engine": "suricata"}).engine == "suricata"
    with pytest.raises(ConfigError, match="engine"):
        load_config(tmp_path, {"engine": "bro"})

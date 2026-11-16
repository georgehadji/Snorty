from pathlib import Path

import pytest

from snorty.dashboard import autostart
from snorty.dashboard.autostart import SCRIPT_NAME, install, main, remove, script_text, status

PY = Path("C:/Program Files/My Env/Scripts/pythonw.exe")


def test_script_runs_the_dashboard_hidden_with_quoted_paths() -> None:
    text = script_text(PY, ["--port", "9000"])
    assert text.startswith('CreateObject("WScript.Shell").Run """')
    assert f'{PY}"" -m snorty.dashboard --port 9000", 0, False' in text
    assert text.endswith("\r\n")


def test_install_writes_one_file_and_status_reads_it(tmp_path: Path) -> None:
    assert status(tmp_path) is None
    target = install(tmp_path, PY, port=9001, start_sensor=True)
    assert target == tmp_path / SCRIPT_NAME
    line = status(tmp_path)
    assert line and "--port 9001" in line and "--start-sensor" in line
    assert [p.name for p in tmp_path.iterdir()] == [SCRIPT_NAME]


def test_install_twice_replaces_the_script(tmp_path: Path) -> None:
    install(tmp_path, PY, port=9001)
    install(tmp_path, PY)
    line = status(tmp_path)
    assert line and "--port" not in line and "--start-sensor" not in line


@pytest.mark.parametrize("port", [0, 70000, -1])
def test_bad_port_is_refused(tmp_path: Path, port: int) -> None:
    with pytest.raises(ValueError):
        install(tmp_path, PY, port=port)
    assert list(tmp_path.iterdir()) == []


def test_remove_deletes_only_our_file(tmp_path: Path) -> None:
    (tmp_path / "other.lnk").write_text("x")
    install(tmp_path, PY)
    assert remove(tmp_path) is True and remove(tmp_path) is False
    assert [p.name for p in tmp_path.iterdir()] == ["other.lnk"]


def test_pythonw_prefers_the_windowless_interpreter(tmp_path: Path) -> None:
    (tmp_path / "python.exe").write_text("")
    assert autostart.pythonw(tmp_path / "python.exe") == tmp_path / "python.exe"
    (tmp_path / "pythonw.exe").write_text("")
    assert autostart.pythonw(tmp_path / "python.exe") == tmp_path / "pythonw.exe"


def test_cli_install_status_remove(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["status"], folder=tmp_path) == 0
    assert "autostart off" in capsys.readouterr().out
    assert main(["install", "--port", "9100"], folder=tmp_path) == 0
    assert main(["status"], folder=tmp_path) == 0
    assert "--port 9100" in capsys.readouterr().out
    assert main(["remove"], folder=tmp_path) == 0
    assert "removed" in capsys.readouterr().out
    assert not (tmp_path / SCRIPT_NAME).exists()


def test_cli_reports_a_bad_port_with_exit_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["install", "--port", "0"], folder=tmp_path) == 1
    assert "port" in capsys.readouterr().err


def test_startup_dir_needs_appdata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APPDATA", raising=False)
    with pytest.raises(OSError):
        autostart.startup_dir()
    monkeypatch.setenv("APPDATA", "C:/Users/x/AppData/Roaming")
    assert autostart.startup_dir().name == "Startup"

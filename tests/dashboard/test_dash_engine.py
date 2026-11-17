import tomllib
from dataclasses import replace
from pathlib import Path

import pytest
from dash_fakes import make_services
from starlette.testclient import TestClient

from snorty.dashboard.app import build_app
from snorty.dashboard.config import ConfigError, save_engine

TOKEN = "t" * 64
PORT = 8765
POST = {"X-Snorty-Token": TOKEN}


def client(tmp_path: Path, engine: str = "snort") -> TestClient:
    services = replace(make_services(tmp_path), engine=engine)
    app = build_app(services, token=TOKEN, port=PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


def test_the_card_shows_the_running_and_the_saved_engine(tmp_path: Path) -> None:
    r = client(tmp_path).get("/engine")
    assert r.status_code == 200 and "Running now" in r.text and "Snort" in r.text
    assert "Saved." not in r.text


def test_choosing_saves_it_and_says_a_restart_applies_it(tmp_path: Path) -> None:
    c = client(tmp_path)
    r = c.post("/engine", headers=POST, content="engine=suricata")
    assert r.status_code == 200 and "start it again to switch to Suricata" in r.text
    assert tomllib.loads((tmp_path / "snorty.toml").read_text())["engine"] == "suricata"
    assert "Saved." in c.get("/engine").text


def test_an_unknown_engine_is_refused_and_the_post_needs_the_token(tmp_path: Path) -> None:
    c = client(tmp_path)
    assert c.post("/engine", headers=POST, content="engine=bogus").status_code == 422
    assert not (tmp_path / "snorty.toml").exists()
    assert c.post("/engine", content="engine=suricata").status_code in (401, 403)


def test_the_rest_of_the_file_is_kept_and_the_key_stays_top_level(tmp_path: Path) -> None:
    f = tmp_path / "snorty.toml"
    f.write_text('port = 9000\n\n[[channels]]\nkind = "ntfy"\nurl = "https://ntfy.sh/x"\n')
    save_engine(tmp_path, "suricata")
    data = tomllib.loads(f.read_text())
    assert data["engine"] == "suricata" and data["port"] == 9000
    assert data["channels"][0]["kind"] == "ntfy"
    save_engine(tmp_path, "snort")
    assert tomllib.loads(f.read_text())["engine"] == "snort"
    assert f.read_text().count("engine") == 1


def test_save_engine_refuses_other_values(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        save_engine(tmp_path, 'x"\nport = 1')

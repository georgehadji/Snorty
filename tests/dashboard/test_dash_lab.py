import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

import pytest
from dash_fakes import FakeLab, alert
from starlette.testclient import TestClient
from test_dash_routes import POST, make

from snorty.dashboard import pcaps, views
from snorty.lab.lint import Problem
from snorty.lab.models import LabJob, LabResult, RuleHit
from snorty.services import Services

FORM = {**POST, "Content-Type": "application/x-www-form-urlencoded"}
RULE = 'alert tcp any any -> any 80 (msg:"t"; content:"abc"; sid:1000001; rev:1;)'
PCAP = pcaps.build_pcap([])


def lab(s: Services) -> FakeLab:
    assert isinstance(s.lab, FakeLab)
    return s.lab


def post(c: TestClient, path: str, **fields: str):  # type: ignore[no-untyped-def]
    return c.post(path, content=urlencode(fields), headers=FORM)


def wait_done(c: TestClient) -> str:
    for _ in range(60):
        r = c.get("/lab/status")
        if 'hx-trigger="every' not in r.text:
            return r.text
        time.sleep(0.05)
    raise AssertionError("lab run never finished")


def put_pcap(s: Services, name: str = "a.pcap") -> None:
    s.pcap_dir.mkdir(parents=True, exist_ok=True)
    (s.pcap_dir / name).write_bytes(PCAP)


# --- pcaps module ---------------------------------------------------------------------------


def test_list_pcaps_shows_only_valid_names(tmp_path: Path) -> None:
    (tmp_path / "b.pcap").write_bytes(PCAP)
    (tmp_path / "a.pcap").write_bytes(PCAP)
    (tmp_path / "notes.txt").write_text("x")
    (tmp_path / "bad name.pcap").write_bytes(PCAP)
    (tmp_path / "dir.pcap").mkdir()
    assert pcaps.list_pcaps(tmp_path) == ["a.pcap", "b.pcap"]
    assert pcaps.list_pcaps(tmp_path / "missing") == []


@pytest.mark.parametrize("name", ["../x.pcap", "..\\x.pcap", "C:\\x.pcap", "x.txt", "", "con.pcap"])
def test_save_pcap_refuses_bad_names(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError):
        pcaps.save_pcap(tmp_path, name, PCAP)
    assert list(tmp_path.iterdir()) == []


def test_save_pcap_refuses_non_pcap_data_and_big_bodies(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a pcap"):
        pcaps.save_pcap(tmp_path, "a.pcap", b"hello world")
    with pytest.raises(ValueError, match="50 MB"):
        pcaps.save_pcap(tmp_path, "a.pcap", PCAP + bytes(pcaps.MAX_PCAP_BYTES))
    assert list(tmp_path.iterdir()) == []


def test_save_pcap_creates_the_folder_and_leaves_no_temp_file(tmp_path: Path) -> None:
    folder = tmp_path / "pcaps"
    assert pcaps.save_pcap(folder, "a.pcap", PCAP) == "a.pcap"
    assert [p.name for p in folder.iterdir()] == ["a.pcap"]


def test_pcap_path_only_returns_listed_plain_files(tmp_path: Path) -> None:
    (tmp_path / "a.pcap").write_bytes(PCAP)
    assert pcaps.pcap_path(tmp_path, "a.pcap") == tmp_path / "a.pcap"
    for bad in ("b.pcap", "../a.pcap", "a.txt"):
        with pytest.raises(ValueError):
            pcaps.pcap_path(tmp_path, bad)


def test_generate_pcap_writes_a_readable_file(tmp_path: Path) -> None:
    name = pcaps.generate_pcap(
        tmp_path, "g.pcap", proto="tcp", src="10.0.0.5", sport=1, dst="10.0.0.9", dport=80,
        payload="abc", count=2, handshake=True,
    )  # fmt: skip
    data = (tmp_path / name).read_bytes()
    assert data[:4] == b"\xd4\xc3\xb2\xa1" and len(data) > 24 + 5 * 16


# --- page -----------------------------------------------------------------------------------


def test_lab_page_lists_pcaps_by_name_only(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    put_pcap(s, "one.pcap")
    r = c.get("/lab")
    assert r.status_code == 200
    assert "one.pcap" in r.text and str(tmp_path) not in r.text
    assert 'hx-post="/lab/check"' in r.text and 'hx-post="/lab/run"' in r.text


def test_lab_page_with_no_pcaps_says_so(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    assert "No pcap files yet" in c.get("/lab").text


# --- check and run --------------------------------------------------------------------------


def test_check_calls_the_lab_once_and_shows_ok(tmp_path: Path) -> None:
    with make(tmp_path)[0] as c:
        r = post(c, "/lab/check", rules=RULE)
        assert r.status_code == 200 and "hx-get" in r.text
        assert "Rules are valid" in wait_done(c)
        assert lab(c.app.state.services).calls == [("check", RULE)]  # type: ignore[attr-defined]


def test_run_passes_the_named_pcap_and_shows_hits_and_matches(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    put_pcap(s)
    when = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    lab(s).result = LabResult(
        True,
        hits=(RuleHit(1000001, "t <b>x</b>", 1, 2), RuleHit(1000002, "idle", 2, 0)),
        matches=(alert(sid=1000001, ts=when),),
    )
    with c:
        post(c, "/lab/run", rules=RULE, pcap="a.pcap")
        html = wait_done(c)
    (name, job) = lab(s).calls[0]
    assert name == "run" and isinstance(job, LabJob)
    assert job.rules_text == RULE and job.pcap == s.pcap_dir / "a.pcap"
    assert "1000001" in html and "no match" in html and "&lt;b&gt;x&lt;/b&gt;" in html
    assert "<b>x" not in html and "Matches" in html


def test_a_problem_is_shown_with_its_rule_line(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    lab(s).result = LabResult(False, problems=(Problem(3, "unknown option"), Problem(0, "empty")))
    with c:
        post(c, "/lab/check", rules=RULE)
        html = wait_done(c)
    assert "rule line 3: unknown option" in html and "empty" in html


def test_a_lab_error_is_shown_escaped(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    lab(s).result = LabResult(False, error="snort <failed>")
    with c:
        post(c, "/lab/check", rules=RULE)
        assert "snort &lt;failed&gt;" in wait_done(c)


def test_unexpected_failure_hides_internals(tmp_path: Path) -> None:
    c, s = make(tmp_path)

    async def boom(rules_text: str) -> LabResult:
        raise RuntimeError("secret internals")

    lab(s).check = boom  # type: ignore[method-assign]
    with c:
        post(c, "/lab/check", rules=RULE)
        html = wait_done(c)
    assert "secret internals" not in html and "see the log" in html


@pytest.mark.parametrize(
    "fields",
    [
        {"rules": ""},
        {"rules": "   "},
        {"rules": "x" * (64 * 1024 + 1)},
    ],
)
def test_check_refuses_empty_and_oversize_text(tmp_path: Path, fields: dict[str, str]) -> None:
    c, s = make(tmp_path)
    r = post(c, "/lab/check", **fields)
    assert r.status_code == 422 and lab(s).calls == []


@pytest.mark.parametrize("pcap", ["", "missing.pcap", "../a.pcap", "C:\\a.pcap", "/etc/passwd"])
def test_run_refuses_unlisted_pcaps(tmp_path: Path, pcap: str) -> None:
    c, s = make(tmp_path)
    put_pcap(s)
    r = post(c, "/lab/run", rules=RULE, pcap=pcap)
    assert r.status_code == 422 and lab(s).calls == []


def test_lab_post_needs_the_token(tmp_path: Path) -> None:
    c, _ = make(tmp_path)
    r = c.post("/lab/check", content=urlencode({"rules": RULE}))
    assert r.status_code == 403


def test_a_second_run_while_busy_is_refused(tmp_path: Path) -> None:
    c, s = make(tmp_path)

    async def slow(rules_text: str) -> LabResult:
        import asyncio

        await asyncio.sleep(0.3)
        return LabResult(True)

    lab(s).check = slow  # type: ignore[method-assign]
    with c:
        post(c, "/lab/check", rules=RULE)
        again = post(c, "/lab/check", rules=RULE)
        assert "already going" in again.text
        wait_done(c)


# --- upload and generate --------------------------------------------------------------------


def test_upload_saves_the_file_and_selects_it(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    r = c.post("/lab/pcaps?name=up.pcap", content=PCAP, headers=POST)
    assert r.status_code == 200 and "Uploaded up.pcap" in r.text
    assert 'id="pcap-picker"' in r.text and "selected" in r.text
    assert (s.pcap_dir / "up.pcap").read_bytes() == PCAP


@pytest.mark.parametrize("name", ["../x.pcap", "x.txt", "", "a b.pcap"])
def test_upload_refuses_bad_names(tmp_path: Path, name: str) -> None:
    c, s = make(tmp_path)
    r = c.post("/lab/pcaps", params={"name": name}, content=PCAP, headers=POST)
    assert r.status_code == 422 and not s.pcap_dir.exists()


def test_upload_refuses_text_that_is_not_a_pcap(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    r = c.post("/lab/pcaps?name=x.pcap", content=b"not a pcap", headers=POST)
    assert r.status_code == 422 and "not a pcap" in r.text


def test_upload_over_50_mb_is_refused_while_reading(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    big = PCAP + bytes(pcaps.MAX_PCAP_BYTES)
    r = c.post("/lab/pcaps?name=big.pcap", content=big, headers=POST)
    assert r.status_code == 422 and "50 MB" in r.text
    assert not s.pcap_dir.exists() or list(s.pcap_dir.iterdir()) == []


GEN = {
    "name": "g.pcap", "proto": "tcp", "src": "10.0.0.5", "sport": "40000",
    "dst": "10.0.0.9", "dport": "80", "payload": "abc", "count": "2", "handshake": "on",
}  # fmt: skip


def test_generate_builds_a_pcap(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    r = post(c, "/lab/pcaps/generate", **GEN)
    assert r.status_code == 200 and "Generated g.pcap" in r.text
    assert (s.pcap_dir / "g.pcap").read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"


@pytest.mark.parametrize(
    "change",
    [
        {"name": "../g.pcap"},
        {"name": "g.txt"},
        {"proto": "icmp"},
        {"src": "not-an-ip"},
        {"src": "::1"},
        {"sport": "70000"},
        {"dport": "x"},
        {"count": "0"},
        {"count": "99999"},
        {"count": ""},
    ],
)
def test_generate_refuses_bad_fields(tmp_path: Path, change: dict[str, str]) -> None:
    c, s = make(tmp_path)
    r = post(c, "/lab/pcaps/generate", **{**GEN, **change})
    assert r.status_code == 422 and 'class="flash bad"' in r.text
    assert not s.pcap_dir.exists() or list(s.pcap_dir.iterdir()) == []


def test_a_flood_of_matches_shows_the_first_rows_and_the_true_total(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    put_pcap(s)
    n = views.MAX_LAB_ROWS + 100
    when = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    lab(s).result = LabResult(
        True,
        hits=(RuleHit(1000001, "t", 1, n),),
        matches=tuple(alert(sid=1000001, ts=when + timedelta(seconds=i)) for i in range(n)),
    )
    with c:
        post(c, "/lab/run", rules=RULE, pcap="a.pcap")
        html = wait_done(c)
    assert html.count('<tr class="p') == views.MAX_LAB_ROWS
    assert f"Showing the first {views.MAX_LAB_ROWS} of {n} matches" in html


def test_an_oversize_form_is_refused_while_reading_it(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    r = c.post("/lab/check", content=b"rules=" + b"x" * (300 * 1024), headers=FORM)
    assert r.status_code == 422 and "form is too large" in r.text and lab(s).calls == []


def test_a_run_asks_for_the_pcap_summary_and_a_check_does_not(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    put_pcap(s, "my-file.pcap")
    with c:
        post(c, "/lab/run", rules=RULE, pcap="my-file.pcap")
        assert 'hx-get="/packets/summary?pcap=my-file.pcap"' in wait_done(c)
        post(c, "/lab/check", rules=RULE)
        assert "/packets/summary" not in wait_done(c)

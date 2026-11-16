import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from snorty.dashboard.security import (
    SecurityMiddleware,
    host_allowed,
    new_token,
    origin_allowed,
    parse_form,
    token_ok,
    valid_home_net,
    valid_pcap_name,
    valid_priority,
    valid_range,
    valid_sid,
)

PORT = 8765
TOKEN = "t" * 64


# ---- validators ----


@pytest.mark.parametrize(
    "text,expected", [("1", 1), ("2000001", 2000001), ("2147483647", 2147483647)]
)
def test_valid_sid(text: str, expected: int) -> None:
    assert valid_sid(text) == expected


@pytest.mark.parametrize(
    "text", ["", "0", "-1", "1.5", "abc", " 1", "1 ", "2147483648", "١٢", "1" * 30]
)
def test_bad_sid(text: str) -> None:
    with pytest.raises(ValueError):
        valid_sid(text)


def test_priority_and_range() -> None:
    assert [valid_priority(t) for t in "123"] == [1, 2, 3]
    for bad in ("0", "4", "", "x", "1.0"):
        with pytest.raises(ValueError):
            valid_priority(bad)
    for good in ("1h", "24h", "7d", "all"):
        assert valid_range(good) == good
    for bad in ("", "1y", "ALL", "7d "):
        with pytest.raises(ValueError):
            valid_range(bad)


@pytest.mark.parametrize("name", ["a.pcap", "my-test_1.pcap", "x" * 59 + ".pcap"])
def test_good_pcap_names(name: str) -> None:
    assert valid_pcap_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        ".pcap",
        "a.txt",
        "a.PCAP.exe",
        "../a.pcap",
        "..\\a.pcap",
        "C:\\a.pcap",
        "/a.pcap",
        "a b.pcap",
        ".hidden.pcap",
        "a:stream.pcap",
        "x" * 60 + ".pcap",
        "a.pcap\n",
        "con.pcap",
        "nul.pcap",
    ],
)
def test_bad_pcap_names(name: str) -> None:
    with pytest.raises(ValueError):
        valid_pcap_name(name)


def test_parse_form() -> None:
    assert parse_form(b"a=1&b=hello+world&c=%C3%A9&d=") == {
        "a": "1",
        "b": "hello world",
        "c": "é",
        "d": "",
    }
    assert parse_form(b"") == {}


def test_parse_form_refuses_duplicates_bad_utf8_and_big_bodies() -> None:
    with pytest.raises(ValueError):
        parse_form(b"a=1&a=2")
    with pytest.raises(ValueError):
        parse_form(b"a=%FF")
    with pytest.raises(ValueError):
        parse_form(b"a=" + b"x" * 300_000)
    assert parse_form(b"a=" + b"x" * 1000, max_bytes=2000) == {"a": "x" * 1000}
    with pytest.raises(ValueError):
        parse_form(b"a=" + b"x" * 1000, max_bytes=500)


# ---- host, origin, token ----


def test_host_allowed() -> None:
    assert host_allowed("127.0.0.1:8765", PORT)
    assert host_allowed("localhost:8765", PORT)
    assert host_allowed("LOCALHOST:8765", PORT)
    for bad in (None, "", "127.0.0.1", "127.0.0.1:80", "evil.com:8765", "127.0.0.1.evil.com:8765"):
        assert not host_allowed(bad, PORT)


def test_origin_allowed() -> None:
    host = "127.0.0.1:8765"
    assert origin_allowed(None, host)
    assert origin_allowed("http://127.0.0.1:8765", host)
    for bad in ("null", "http://evil.com", "https://127.0.0.1:8765", "http://127.0.0.1:1"):
        assert not origin_allowed(bad, host)


def test_token_ok_and_new_token() -> None:
    assert token_ok(TOKEN, TOKEN)
    assert not token_ok(None, TOKEN)
    assert not token_ok("", TOKEN)
    assert not token_ok(TOKEN + "x", TOKEN)
    assert not token_ok("é", TOKEN)
    a, b = new_token(), new_token()
    assert a != b and len(a) == 64 and int(a, 16) >= 0


# ---- middleware ----


async def echo(request: Request) -> PlainTextResponse:
    return PlainTextResponse(f"{request.method} ok")


def make_client() -> TestClient:
    app = Starlette(
        routes=[
            Route("/healthz", echo, methods=["GET", "POST"]),
            Route("/x", echo, methods=["GET", "POST", "PUT", "DELETE"]),
        ]
    )
    return TestClient(
        SecurityMiddleware(app, token=TOKEN, port=PORT), base_url=f"http://127.0.0.1:{PORT}"
    )


def assert_headers(r) -> None:  # type: ignore[no-untyped-def]
    assert r.headers["content-security-policy"] == "default-src 'self'; frame-ancestors 'none'"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_get_passes_without_a_token_and_has_security_headers() -> None:
    with make_client() as c:
        r = c.get("/x")
        assert r.status_code == 200 and r.text == "GET ok"
        assert_headers(r)


def test_headers_also_on_errors() -> None:
    with make_client() as c:
        assert_headers(c.get("/missing"))


def test_localhost_host_is_allowed() -> None:
    with make_client() as c:
        assert c.get("/x", headers={"host": f"localhost:{PORT}"}).status_code == 200


@pytest.mark.parametrize(
    "host", ["evil.com", f"evil.com:{PORT}", "127.0.0.1:1", f"127.0.0.1.evil.com:{PORT}"]
)
def test_foreign_host_gets_400_even_on_healthz(host: str) -> None:
    with make_client() as c:
        for path in ("/x", "/healthz"):
            r = c.get(path, headers={"host": host})
            assert r.status_code == 400
            assert_headers(r)


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_non_get_without_token_gets_403_and_does_not_reach_the_app(method: str) -> None:
    with make_client() as c:
        r = c.request(method, "/x")
        assert r.status_code == 403 and "ok" not in r.text
        assert_headers(r)


def test_non_get_with_wrong_token_gets_403() -> None:
    with make_client() as c:
        assert c.post("/x", headers={"X-Snorty-Token": "nope"}).status_code == 403


def test_post_with_token_passes() -> None:
    with make_client() as c:
        r = c.post("/x", headers={"X-Snorty-Token": TOKEN})
        assert r.status_code == 200 and r.text == "POST ok"


def test_post_with_token_and_matching_origin_passes() -> None:
    with make_client() as c:
        h = {"X-Snorty-Token": TOKEN, "Origin": f"http://127.0.0.1:{PORT}"}
        assert c.post("/x", headers=h).status_code == 200


@pytest.mark.parametrize("origin", ["http://evil.com", "null", f"http://localhost:{PORT}"])
def test_post_with_foreign_origin_gets_403(origin: str) -> None:
    with make_client() as c:
        r = c.post("/x", headers={"X-Snorty-Token": TOKEN, "Origin": origin})
        assert r.status_code == 403


def test_token_in_the_query_string_does_not_count() -> None:
    with make_client() as c:
        assert c.post(f"/x?token={TOKEN}").status_code == 403


def test_post_to_healthz_still_needs_the_token() -> None:
    with make_client() as c:
        assert c.post("/healthz").status_code == 403


@pytest.mark.parametrize(
    "text",
    ["any", "[10.0.0.0/8,192.168.0.0/16]", "$EXTERNAL_NET", "![10.0.0.0/8]", "fe80::/10", " any "],
)
def test_good_home_net(text: str) -> None:
    assert valid_home_net(text) == text.strip()


@pytest.mark.parametrize(
    "text", ["", "   ", "any\ninclude /x", "a\ry", "a;b", "x" * 201, "$(calc)", "any #c", "é"]
)
def test_bad_home_net(text: str) -> None:
    with pytest.raises(ValueError):
        valid_home_net(text)

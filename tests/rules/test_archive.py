import io
import tarfile
from pathlib import Path

import pytest

from snorty.rules.archive import count_rules, extract_rules, parse_md5, safe_members, sanity_ok

MD5 = "0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize(
    "text",
    [
        MD5,
        f"{MD5}\n",
        f"{MD5}  emerging.rules.tar.gz\n",
        f"MD5 (emerging.rules.tar.gz) = {MD5}\r\n",
    ],
)
def test_parse_md5_accepts_common_forms(text: str) -> None:
    assert parse_md5(text) == MD5


def test_parse_md5_lowercases_and_rejects_garbage() -> None:
    assert parse_md5(MD5.upper()) == MD5
    for bad in ("", "<html>404</html>", MD5[:-1]):
        with pytest.raises(ValueError):
            parse_md5(bad)


def test_safe_members_filters_names() -> None:
    names = [
        "rules/emerging-info.rules",
        "emerging-dos.rules",
        "rules\\emerging-win.rules",
        "../evil.rules",
        "rules/../../evil.rules",
        "/abs.rules",
        "C:\\x.rules",
        "c:/x.rules",
        "rules/local.rules",
        "rules/White_List.rules",
        "rules/threatview_CS_c2.rules",
        "rules/README.txt",
        "rules/",
    ]
    assert safe_members(names) == [
        "rules/emerging-info.rules",
        "emerging-dos.rules",
        "rules\\emerging-win.rules",
    ]


def make_tar(members: list[tuple[str, bytes | str]]) -> bytes:
    """Members are (name, content); a str content means a symlink to that target."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in members:
            info = tarfile.TarInfo(name)
            if isinstance(content, str):
                info.type = tarfile.SYMTYPE
                info.linkname = content
                tf.addfile(info)
            else:
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


RULE = b'alert tcp any any -> any any (msg:"x"; sid:1;)\n'


def test_extract_flattens_nested_and_counts_skipped(tmp_path: Path) -> None:
    dest = tmp_path / "stage"
    dest.mkdir()
    data = make_tar(
        [
            ("rules/emerging-a.rules", RULE),
            ("emerging-b.rules", RULE * 2),
            ("rules/local.rules", b"overwrite attempt"),
            ("../escape.rules", RULE),
            ("rules/link.rules", "/etc/passwd"),
            ("rules/notes.txt", b"hi"),
        ]
    )
    report = extract_rules(data, dest)
    assert sorted(report.written) == ["emerging-a.rules", "emerging-b.rules"]
    assert report.skipped == 4
    assert sorted(p.name for p in dest.iterdir()) == ["emerging-a.rules", "emerging-b.rules"]
    assert not (tmp_path / "escape.rules").exists()
    assert (dest / "emerging-b.rules").read_bytes() == RULE * 2


def test_extract_skips_oversize_member(tmp_path: Path) -> None:
    report = extract_rules(make_tar([("big.rules", b"x" * 100)]), tmp_path, max_member=10)
    assert report.written == () and report.skipped == 1


def test_extract_rejects_non_tar(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        extract_rules(b"this is not a tarball", tmp_path)


def test_count_rules_counts_only_rule_lines(tmp_path: Path) -> None:
    (tmp_path / "a.rules").write_text(
        "# comment\n\nalert tcp any any -> any any (sid:1;)\n"
        "  drop udp any any -> any any (sid:2;)\n#alert tcp any any -> any any (sid:3;)\n"
        "alertness is not a rule\npass ip any any -> any any (sid:4;)\n"
    )
    (tmp_path / "b.rules").write_text("log tcp any any -> any any (sid:5;)\r\n")
    (tmp_path / "ignored.txt").write_text("alert tcp any any -> any any (sid:6;)\n")
    assert count_rules(tmp_path) == 4


def test_sanity_ok() -> None:
    assert sanity_ok(60, 100)
    assert sanity_ok(50, 100)
    assert not sanity_ok(49, 100)
    assert sanity_ok(0, 0)
    assert not sanity_ok(0, 10)

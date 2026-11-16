from pathlib import Path

from snorty.wireshark import find_tools


def finder(existing: set[str], on_path: str | None = None):
    return {
        "is_file": lambda p: str(p).replace("\\", "/") in existing,
        "which": lambda name: on_path,
    }


def test_a_configured_folder_wins() -> None:
    tools = find_tools(
        configured=Path("D:/ws"),
        env={"ProgramFiles": "C:/Program Files"},
        **finder({"D:/ws/tshark.exe", "C:/Program Files/Wireshark/tshark.exe"}),
    )
    assert str(tools.tshark).replace("\\", "/") == "D:/ws/tshark.exe"


def test_program_files_is_checked_before_path() -> None:
    tools = find_tools(
        env={"ProgramFiles": "C:/Program Files"},
        **finder({"C:/Program Files/Wireshark/tshark.exe"}, on_path="E:/bin/tshark.exe"),
    )
    assert str(tools.tshark).replace("\\", "/") == "C:/Program Files/Wireshark/tshark.exe"


def test_the_environment_variable_is_used() -> None:
    tools = find_tools(env={"SNORTY_WIRESHARK_DIR": "F:/w"}, **finder({"F:/w/tshark.exe"}))
    assert str(tools.tshark).replace("\\", "/") == "F:/w/tshark.exe"


def test_path_is_the_last_resort_and_nothing_found_is_none() -> None:
    assert find_tools(env={}, **finder(set(), on_path="E:/bin/tshark.exe")).tshark == Path(
        "E:/bin/tshark.exe"
    )
    assert find_tools(env={}, **finder(set())).tshark is None


def test_the_window_program_is_found_beside_tshark_and_may_be_missing() -> None:
    both = find_tools(
        env={"ProgramFiles": "C:/Program Files"},
        **finder(
            {"C:/Program Files/Wireshark/tshark.exe", "C:/Program Files/Wireshark/Wireshark.exe"}
        ),
    )
    assert str(both.wireshark).replace("\\", "/") == "C:/Program Files/Wireshark/Wireshark.exe"
    cli_only = find_tools(
        env={"ProgramFiles": "C:/Program Files"},
        **finder({"C:/Program Files/Wireshark/tshark.exe"}),
    )
    assert cli_only.tshark is not None and cli_only.wireshark is None
    on_path = find_tools(env={}, **finder({"E:/bin/Wireshark.exe"}, on_path="E:/bin/tshark.exe"))
    assert str(on_path.wireshark).replace("\\", "/") == "E:/bin/Wireshark.exe"

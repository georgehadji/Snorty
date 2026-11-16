import sys

import pytest

from snorty.wireshark.runner import ToolError, run_bounded

PY = sys.executable


async def test_collects_output_and_exit_code() -> None:
    out = await run_bounded(
        [PY, "-c", "import sys; print('hi'); sys.stderr.write('warn'); sys.exit(3)"],
        timeout=10,
        max_bytes=1000,
    )
    assert (out.returncode, out.stdout.strip(), out.stderr, out.truncated) == (
        3,
        b"hi",
        "warn",
        False,
    )


async def test_output_over_the_cap_stops_the_tool() -> None:
    out = await run_bounded(
        [PY, "-c", "import sys\nwhile True: sys.stdout.write('x' * 10000); sys.stdout.flush()"],
        timeout=10,
        max_bytes=50_000,
    )
    assert out.truncated and len(out.stdout) == 50_000


async def test_a_slow_tool_is_killed_at_the_timeout() -> None:
    with pytest.raises(ToolError, match="longer than"):
        await run_bounded([PY, "-c", "import time; time.sleep(30)"], timeout=0.5, max_bytes=100)


async def test_a_missing_program_is_a_tool_error() -> None:
    with pytest.raises(ToolError, match="cannot start"):
        await run_bounded(["definitely-not-a-real-program-xyz"], timeout=2, max_bytes=100)


async def test_a_noisy_stderr_does_not_hang_the_tool() -> None:
    out = await run_bounded(
        [PY, "-c", "import sys; sys.stderr.write('e' * 1_000_000)"], timeout=10, max_bytes=100
    )
    assert out.returncode == 0 and len(out.stderr) == 4096

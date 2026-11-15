import sys

import pytest

from snorty.snort.models import SnortError
from snorty.snort.runner import SubprocessRunner

run = SubprocessRunner()


async def test_captures_output_and_returncode() -> None:
    code = "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"
    result = await run([sys.executable, "-c", code], timeout=10)
    assert result.returncode == 3
    assert result.stdout.strip() == "out"
    assert result.stderr.strip() == "err"


async def test_undecodable_bytes_are_replaced() -> None:
    code = "import sys; sys.stdout.buffer.write(b'a\\xffb')"
    result = await run([sys.executable, "-c", code], timeout=10)
    assert result.stdout == "a\ufffdb"


async def test_timeout_kills_child_and_raises() -> None:
    with pytest.raises(SnortError, match="timeout"):
        await run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)


async def test_missing_executable_raises_snort_error() -> None:
    with pytest.raises(SnortError, match="cannot start"):
        await run([r"C:\definitely\not\here.exe"], timeout=5)

import asyncio

from snorty.dashboard.jobs import Job


async def test_start_runs_the_work_and_keeps_the_result() -> None:
    job: Job[int] = Job()
    assert not job.running and job.result is None and job.error is None

    async def work() -> int:
        await asyncio.sleep(0.01)
        return 7

    assert job.start(work) is True
    assert job.running
    await job.wait()
    assert not job.running and job.result == 7 and job.error is None


async def test_a_second_start_while_running_does_nothing() -> None:
    job: Job[int] = Job()
    calls = 0

    async def work() -> int:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.02)
        return calls

    assert job.start(work) is True
    assert job.start(work) is False
    await job.wait()
    assert calls == 1 and job.result == 1


async def test_it_can_run_again_after_finishing_and_clears_the_old_result() -> None:
    job: Job[str] = Job()

    async def first() -> str:
        return "first"

    async def second() -> str:
        await asyncio.sleep(0.02)
        return "second"

    job.start(first)
    await job.wait()
    assert job.result == "first"
    assert job.start(second) is True
    assert job.result is None
    await job.wait()
    assert job.result == "second"


async def test_an_exception_becomes_an_error_message_not_a_crash() -> None:
    job: Job[int] = Job()

    async def boom() -> int:
        raise RuntimeError("secret details")

    job.start(boom)
    await job.wait()
    assert job.result is None and job.error and "secret details" not in job.error
    assert not job.running


async def test_cancel_stops_a_running_job_and_is_safe_when_idle() -> None:
    job: Job[int] = Job()
    await job.cancel()  # idle: nothing to do
    started = asyncio.Event()

    async def hang() -> int:
        started.set()
        await asyncio.sleep(60)
        return 1

    job.start(hang)
    await started.wait()
    await job.cancel()
    assert not job.running and job.result is None

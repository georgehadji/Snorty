from datetime import UTC, datetime, timedelta, timezone

from snorty.core.localtz import LocalTimezone
from snorty.core.parser import parse_line

TZ = LocalTimezone()
LINE = "{} [**] [1:1000002:1] t [**] [Priority: 1] {{TCP}} 10.0.0.1:1 -> 10.0.0.2:80"


def test_matches_the_os_for_every_half_hour_of_two_years() -> None:
    """The property: the offset on each date is the one the OS reports, DST included."""
    start = datetime(2025, 1, 1, tzinfo=UTC)
    for i in range(0, 2 * 366 * 48):
        utc = start + timedelta(minutes=30 * i)
        ours, os_view = utc.astimezone(TZ), utc.astimezone()
        assert ours.utcoffset() == os_view.utcoffset(), utc
        assert ours.replace(tzinfo=None) == os_view.replace(tzinfo=None), utc
        assert ours.astimezone(UTC) == utc, utc


def test_a_wall_clock_time_gets_the_offset_of_its_own_date() -> None:
    summer = datetime(2026, 7, 1, 12, 0, tzinfo=TZ)
    winter = datetime(2026, 1, 15, 12, 0, tzinfo=TZ)
    assert summer.utcoffset() == datetime(2026, 7, 1, 12, 0).astimezone().utcoffset()
    assert winter.utcoffset() == datetime(2026, 1, 15, 12, 0).astimezone().utcoffset()


def test_snort_lines_from_either_half_of_the_year_are_read_with_their_own_offset() -> None:
    for stamp in ("07/01-12:00:00.000001", "01/15-12:00:00.000001"):
        alert = parse_line(LINE.format(stamp), default_year=2026, tz=TZ)
        assert alert is not None
        expected = datetime(2026, int(stamp[:2]), int(stamp[3:5]), 12, 0, 0, 1).astimezone()
        assert alert.ts.astimezone(UTC) == expected.astimezone(UTC)


def test_the_fixed_offset_it_replaces_disagrees_with_the_os_when_the_zone_has_dst() -> None:
    fixed = datetime.now().astimezone().tzinfo
    assert isinstance(fixed, timezone)  # the old way: one offset for every date
    ours = {m: datetime(2026, m, 1, 12, tzinfo=TZ).utcoffset() for m in (1, 7)}
    if ours[1] != ours[7]:  # this PC's zone observes DST
        old = {m: datetime(2026, m, 1, 12, tzinfo=fixed).utcoffset() for m in (1, 7)}
        assert old != ours


def test_dates_the_os_clock_cannot_handle_fall_back_to_the_current_offset() -> None:
    assert datetime(1900, 1, 1, tzinfo=TZ).utcoffset() == datetime.now().astimezone().utcoffset()
    assert datetime(1900, 1, 1, tzinfo=UTC).astimezone(TZ).year == 1900


def test_no_name_and_no_dst_amount_are_reported() -> None:
    now = datetime(2026, 7, 1, tzinfo=TZ)
    assert now.tzname() is None and now.dst() is None

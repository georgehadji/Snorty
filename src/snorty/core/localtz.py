"""The PC's local time zone with its daylight-saving rules.

`datetime.now().astimezone().tzinfo` is one fixed UTC offset: wrong for any date on the other
side of a DST change, such as old lines in Snort's alert file or a dashboard left running
through the change. This class asks the OS for the offset of each date instead.
"""

from datetime import UTC, datetime, timedelta, tzinfo


def _now_offset() -> timedelta:
    return datetime.now().astimezone().utcoffset() or timedelta(0)


class LocalTimezone(tzinfo):
    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        if dt is None:
            return None
        try:
            return dt.replace(tzinfo=None).astimezone().utcoffset()
        except (OverflowError, ValueError, OSError):  # a date the OS clock cannot handle
            return _now_offset()

    def dst(self, dt: datetime | None) -> timedelta | None:
        return None

    def tzname(self, dt: datetime | None) -> str | None:
        return None

    def fromutc(self, dt: datetime) -> datetime:
        try:
            local = dt.replace(tzinfo=UTC).astimezone()
        except (OverflowError, ValueError, OSError):
            return dt + _now_offset()
        wall = local.replace(tzinfo=None)
        # astimezone() leaves fold at 0 in the repeated autumn hour; recover it.
        fold = int(wall.astimezone().utcoffset() != local.utcoffset())
        return wall.replace(tzinfo=self, fold=fold)

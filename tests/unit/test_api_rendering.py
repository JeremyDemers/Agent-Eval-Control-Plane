from datetime import datetime, timedelta, timezone

from aecontrol.api import _utc_timestamp


def test_dashboard_timestamps_are_converted_before_being_labeled_utc() -> None:
    local_time = datetime(2026, 7, 13, 14, 30, tzinfo=timezone(-timedelta(hours=4)))

    assert _utc_timestamp(local_time) == "2026-07-13 18:30:00 UTC"

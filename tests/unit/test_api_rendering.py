from datetime import UTC, datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from aecontrol.api import _efficacy_window, _utc_timestamp


def test_dashboard_timestamps_are_converted_before_being_labeled_utc() -> None:
    local_time = datetime(2026, 7, 13, 14, 30, tzinfo=timezone(-timedelta(hours=4)))

    assert _utc_timestamp(local_time) == "2026-07-13 18:30:00 UTC"


def test_efficacy_window_requires_ordered_aware_bounded_timestamps() -> None:
    end = datetime(2026, 7, 13, tzinfo=UTC)
    start, resolved_end = _efficacy_window(None, end)
    assert resolved_end == end
    assert start == end - timedelta(days=30)

    with pytest.raises(HTTPException, match="timezone"):
        _efficacy_window(
            datetime(2026, 7, 1, tzinfo=UTC).replace(tzinfo=None),
            datetime(2026, 7, 2, tzinfo=UTC).replace(tzinfo=None),
        )
    with pytest.raises(HTTPException, match="before"):
        _efficacy_window(end, end)
    with pytest.raises(HTTPException, match="366 days"):
        _efficacy_window(end - timedelta(days=367), end)

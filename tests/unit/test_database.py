from __future__ import annotations

import pytest

from aecontrol.database import (
    DatabaseRuntimeConfiguration,
    database_configuration_from_environment,
)


def test_database_configuration_defaults_to_direct_connections() -> None:
    configuration = database_configuration_from_environment({})

    assert configuration.pooling_enabled is False
    assert configuration.pool_min_size == 0
    assert configuration.pool_max_size == 0
    assert configuration.migration_lock_timeout_seconds == 30


def test_database_configuration_parses_bounded_pool() -> None:
    configuration = database_configuration_from_environment(
        {
            "AECONTROL_DATABASE_POOL_MIN_SIZE": "2",
            "AECONTROL_DATABASE_POOL_MAX_SIZE": "8",
            "AECONTROL_DATABASE_POOL_TIMEOUT_SECONDS": "2.5",
            "AECONTROL_DATABASE_POOL_MAX_WAITING": "40",
            "AECONTROL_DATABASE_MIGRATION_LOCK_TIMEOUT_SECONDS": "12",
        }
    )

    assert configuration.pooling_enabled is True
    assert configuration.pool_min_size == 2
    assert configuration.pool_max_size == 8
    assert configuration.pool_timeout_seconds == 2.5
    assert configuration.pool_max_waiting == 40
    assert configuration.migration_lock_timeout_seconds == 12


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"pool_min_size": 1}, "minimum must be zero"),
        ({"pool_min_size": 0, "pool_max_size": 1}, "1 <= min <= max"),
        ({"pool_timeout_seconds": 0}, "pool timeout"),
        ({"pool_max_waiting": -1}, "maximum waiting"),
        ({"migration_lock_timeout_seconds": 301}, "migration lock"),
    ],
)
def test_database_configuration_rejects_unsafe_bounds(
    arguments: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        DatabaseRuntimeConfiguration(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "environment",
    [
        {"AECONTROL_DATABASE_POOL_MAX_SIZE": "many"},
        {"AECONTROL_DATABASE_POOL_TIMEOUT_SECONDS": "soon"},
    ],
)
def test_database_configuration_rejects_invalid_numbers(
    environment: dict[str, str],
) -> None:
    with pytest.raises(ValueError, match="must be"):
        database_configuration_from_environment(environment)

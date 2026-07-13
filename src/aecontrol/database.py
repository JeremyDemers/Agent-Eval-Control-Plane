from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class DatabaseRuntimeConfiguration:
    pool_min_size: int = 0
    pool_max_size: int = 0
    pool_timeout_seconds: float = 5.0
    pool_max_waiting: int = 20
    migration_lock_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.pool_max_size == 0:
            if self.pool_min_size != 0:
                raise ValueError("database pool minimum must be zero when pooling is disabled")
        elif not 1 <= self.pool_min_size <= self.pool_max_size <= 100:
            raise ValueError("database pool sizes must satisfy 1 <= min <= max <= 100")
        if not 0.1 <= self.pool_timeout_seconds <= 60:
            raise ValueError("database pool timeout must be between 0.1 and 60 seconds")
        if not 0 <= self.pool_max_waiting <= 10_000:
            raise ValueError("database pool maximum waiting requests must be between 0 and 10000")
        if not 0.1 <= self.migration_lock_timeout_seconds <= 300:
            raise ValueError("database migration lock timeout must be between 0.1 and 300 seconds")

    @property
    def pooling_enabled(self) -> bool:
        return self.pool_max_size > 0


@dataclass(frozen=True)
class DatabasePoolSnapshot:
    minimum: int
    maximum: int
    size: int
    available: int
    waiting: int


def database_configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> DatabaseRuntimeConfiguration:
    env = environment if environment is not None else os.environ
    maximum = _integer(env, "AECONTROL_DATABASE_POOL_MAX_SIZE", 0)
    minimum_default = 1 if maximum > 0 else 0
    return DatabaseRuntimeConfiguration(
        pool_min_size=_integer(env, "AECONTROL_DATABASE_POOL_MIN_SIZE", minimum_default),
        pool_max_size=maximum,
        pool_timeout_seconds=_floating(env, "AECONTROL_DATABASE_POOL_TIMEOUT_SECONDS", 5.0),
        pool_max_waiting=_integer(env, "AECONTROL_DATABASE_POOL_MAX_WAITING", 20),
        migration_lock_timeout_seconds=_floating(
            env,
            "AECONTROL_DATABASE_MIGRATION_LOCK_TIMEOUT_SECONDS",
            30.0,
        ),
    )


def _integer(environment: Mapping[str, str], name: str, default: int) -> int:
    value = environment.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error


def _floating(environment: Mapping[str, str], name: str, default: float) -> float:
    value = environment.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a number") from error

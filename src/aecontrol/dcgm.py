from __future__ import annotations

import base64
import math
import os
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from prometheus_client.parser import text_string_to_metric_families

from aecontrol.models import GpuDevice, normalize_mig_profile

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
DCGM_METRICS = {
    "DCGM_FI_DEV_FB_USED",
    "DCGM_FI_DEV_FB_FREE",
    "DCGM_FI_DEV_GPU_UTIL",
    "DCGM_FI_PROF_GR_ENGINE_ACTIVE",
    "DCGM_FI_DEV_GPU_TEMP",
    "DCGM_FI_DEV_POWER_USAGE",
}


class DcgmExporterError(RuntimeError):
    """Raised when configured DCGM telemetry cannot be used safely."""


@dataclass(frozen=True)
class DcgmExporterConfiguration:
    enabled: bool
    endpoint: str | None = field(default=None, repr=False)
    endpoint_host: str | None = None
    timeout_seconds: float = 1.0
    pod_name: str | None = None


@dataclass
class _DcgmSample:
    uuid: str
    mig_profile: str | None
    gpu_instance_id: str | None
    pod_name: str | None
    values: dict[str, float] = field(default_factory=dict)


def dcgm_configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> DcgmExporterConfiguration:
    env = environment if environment is not None else os.environ
    endpoint = env.get("AECONTROL_DCGM_EXPORTER_URL", "").strip()
    if not endpoint:
        return DcgmExporterConfiguration(enabled=False)

    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("AECONTROL_DCGM_EXPORTER_URL must be an absolute HTTP(S) URL")
    if parsed.fragment:
        raise ValueError("AECONTROL_DCGM_EXPORTER_URL must not contain a fragment")
    try:
        timeout = float(env.get("AECONTROL_DCGM_TIMEOUT_SECONDS", "1"))
    except ValueError as error:
        raise ValueError("AECONTROL_DCGM_TIMEOUT_SECONDS must be a number") from error
    if not 0.1 <= timeout <= 10:
        raise ValueError("AECONTROL_DCGM_TIMEOUT_SECONDS must be between 0.1 and 10 seconds")

    pod_name = env.get("AECONTROL_DCGM_POD_NAME", socket.gethostname()).strip() or None
    return DcgmExporterConfiguration(
        enabled=True,
        endpoint=endpoint,
        endpoint_host=parsed.hostname,
        timeout_seconds=timeout,
        pod_name=pod_name,
    )


def enrich_gpus_from_dcgm(
    gpus: Sequence[GpuDevice],
    configuration: DcgmExporterConfiguration,
) -> list[GpuDevice]:
    if not configuration.enabled:
        return list(gpus)
    try:
        exposition = _fetch_metrics(configuration)
        samples = parse_dcgm_metrics(exposition)
    except DcgmExporterError:
        return [_without_live_telemetry(gpu) for gpu in gpus]

    enriched: list[GpuDevice] = []
    for gpu in gpus:
        sample = _match_sample(gpu, samples, configuration.pod_name)
        if sample is None:
            enriched.append(_without_live_telemetry(gpu))
            continue
        values = sample.values
        memory_used = _valid_memory(values.get("DCGM_FI_DEV_FB_USED"))
        if memory_used is None:
            free = _valid_memory(values.get("DCGM_FI_DEV_FB_FREE"))
            memory_used = None if free is None else max(0, gpu.memory_total_mb - round(free))
        utilization = _valid_range(values.get("DCGM_FI_DEV_GPU_UTIL"), 0, 100)
        if utilization is None:
            engine_active = _valid_range(values.get("DCGM_FI_PROF_GR_ENGINE_ACTIVE"), 0, 1)
            utilization = None if engine_active is None else engine_active * 100
        payload = gpu.model_dump()
        payload.update(
            memory_used_mb=None if memory_used is None else round(memory_used),
            utilization_percent=utilization,
            temperature_celsius=_valid_range(values.get("DCGM_FI_DEV_GPU_TEMP"), -100, 300),
            power_draw_watts=_valid_range(values.get("DCGM_FI_DEV_POWER_USAGE"), 0, 100_000),
            telemetry_source="dcgm-exporter",
        )
        enriched.append(GpuDevice.model_validate(payload))
    return enriched


def parse_dcgm_metrics(exposition: str) -> list[_DcgmSample]:
    samples: dict[tuple[str, str | None, str | None, str | None], _DcgmSample] = {}
    recognized = 0
    try:
        families = text_string_to_metric_families(exposition)
        for family in families:
            for metric in family.samples:
                if metric.name not in DCGM_METRICS:
                    continue
                recognized += 1
                labels = {key.lower(): value for key, value in metric.labels.items()}
                uuid = labels.get("uuid", "").strip()
                if not uuid:
                    continue
                profile_value = labels.get("gpu_i_profile")
                profile = normalize_mig_profile(profile_value) if profile_value else None
                pod_name = labels.get("pod") or labels.get("pod_name")
                key = (uuid, profile, labels.get("gpu_i_id"), pod_name)
                sample = samples.setdefault(
                    key,
                    _DcgmSample(uuid, profile, labels.get("gpu_i_id"), pod_name),
                )
                value = float(metric.value)
                if not math.isfinite(value):
                    continue
                previous = sample.values.get(metric.name)
                if previous is not None and previous != value:
                    raise DcgmExporterError(f"conflicting {metric.name} values for one DCGM entity")
                sample.values[metric.name] = value
    except DcgmExporterError:
        raise
    except (TypeError, ValueError) as error:
        raise DcgmExporterError("invalid Prometheus exposition from DCGM Exporter") from error
    if recognized == 0:
        raise DcgmExporterError("DCGM Exporter response contains no supported metrics")
    return list(samples.values())


def _fetch_metrics(configuration: DcgmExporterConfiguration) -> str:
    if configuration.endpoint is None:
        raise DcgmExporterError("DCGM Exporter endpoint is not configured")
    parsed = urlsplit(configuration.endpoint)
    host = parsed.hostname or ""
    netloc = f"[{host}]" if ":" in host else host
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    endpoint = urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, ""))
    headers = {"Accept": "text/plain", "User-Agent": "aecontrol-dcgm/1"}
    if parsed.username is not None:
        credentials = f"{parsed.username}:{parsed.password or ''}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(credentials).decode()
    request = Request(endpoint, headers=headers)  # noqa: S310 - scheme validated at configuration
    try:
        with urlopen(  # noqa: S310 - scheme validated at configuration
            request, timeout=configuration.timeout_seconds
        ) as response:
            payload = cast(bytes, response.read(MAX_RESPONSE_BYTES + 1))
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        raise DcgmExporterError("DCGM Exporter scrape failed") from error
    if len(payload) > MAX_RESPONSE_BYTES:
        raise DcgmExporterError("DCGM Exporter response exceeds 2 MiB")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DcgmExporterError("DCGM Exporter response is not UTF-8") from error


def _match_sample(
    gpu: GpuDevice,
    samples: Sequence[_DcgmSample],
    pod_name: str | None,
) -> _DcgmSample | None:
    profile_matches = [
        sample
        for sample in samples
        if sample.mig_profile == gpu.mig_profile and sample.uuid.casefold() == gpu.uuid.casefold()
    ]
    if len(profile_matches) == 1:
        return profile_matches[0]
    if gpu.mig_profile is None or pod_name is None:
        return None
    pod_matches = [
        sample
        for sample in samples
        if sample.mig_profile == gpu.mig_profile and sample.pod_name == pod_name
    ]
    return pod_matches[0] if len(pod_matches) == 1 else None


def _without_live_telemetry(gpu: GpuDevice) -> GpuDevice:
    payload = gpu.model_dump()
    payload.update(
        memory_used_mb=None,
        utilization_percent=None,
        temperature_celsius=None,
        power_draw_watts=None,
        telemetry_source="unavailable",
    )
    return GpuDevice.model_validate(payload)


def _valid_memory(value: float | None) -> float | None:
    return _valid_range(value, 0, float(2**53))


def _valid_range(value: float | None, minimum: float, maximum: float) -> float | None:
    if value is None or not math.isfinite(value) or not minimum <= value <= maximum:
        return None
    return value

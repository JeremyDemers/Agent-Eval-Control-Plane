from __future__ import annotations

import base64
from urllib.error import URLError

import pytest

from aecontrol import dcgm
from aecontrol.dcgm import (
    DcgmExporterConfiguration,
    DcgmExporterError,
    dcgm_configuration_from_environment,
    enrich_gpus_from_dcgm,
    parse_dcgm_metrics,
)
from aecontrol.models import GpuDevice


def _gpu(*, uuid: str = "GPU-test", mig_profile: str | None = None) -> GpuDevice:
    return GpuDevice(
        index=0,
        uuid=uuid,
        name="NVIDIA H100 80GB HBM3",
        memory_total_mb=81920,
        memory_used_mb=12,
        utilization_percent=1,
        temperature_celsius=30,
        power_draw_watts=40,
        compute_capability="9.0",
        mig_profile=mig_profile,
        telemetry_source="nvidia-smi",
    )


def _config(*, pod_name: str | None = "worker-pod") -> DcgmExporterConfiguration:
    return DcgmExporterConfiguration(
        enabled=True,
        endpoint="http://dcgm.example:9400/metrics",
        endpoint_host="dcgm.example",
        pod_name=pod_name,
    )


def test_dcgm_configuration_is_optional_bounded_and_sanitized() -> None:
    assert dcgm_configuration_from_environment({}).enabled is False

    config = dcgm_configuration_from_environment(
        {
            "AECONTROL_DCGM_EXPORTER_URL": "https://user:secret@dcgm.example:9400/metrics",
            "AECONTROL_DCGM_TIMEOUT_SECONDS": "2.5",
            "AECONTROL_DCGM_POD_NAME": "gpu-worker-1",
        }
    )

    assert config.endpoint_host == "dcgm.example"
    assert config.timeout_seconds == 2.5
    assert config.pod_name == "gpu-worker-1"
    assert "secret" not in repr(config)
    with pytest.raises(ValueError, match="absolute HTTP"):
        dcgm_configuration_from_environment({"AECONTROL_DCGM_EXPORTER_URL": "dcgm:9400"})
    with pytest.raises(ValueError, match=r"between 0\.1 and 10"):
        dcgm_configuration_from_environment(
            {
                "AECONTROL_DCGM_EXPORTER_URL": "http://dcgm:9400/metrics",
                "AECONTROL_DCGM_TIMEOUT_SECONDS": "30",
            }
        )


def test_full_gpu_metrics_replace_nvidia_smi_live_values(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    exposition = """
# TYPE DCGM_FI_DEV_FB_USED gauge
DCGM_FI_DEV_FB_USED{gpu="0",UUID="GPU-test"} 4096
DCGM_FI_DEV_GPU_UTIL{gpu="0",UUID="GPU-test"} 72
DCGM_FI_DEV_GPU_TEMP{gpu="0",UUID="GPU-test"} 66
DCGM_FI_DEV_POWER_USAGE{gpu="0",UUID="GPU-test"} 321.5
"""
    monkeypatch.setattr(dcgm, "_fetch_metrics", lambda _configuration: exposition)

    result = enrich_gpus_from_dcgm([_gpu()], _config())

    assert result[0].memory_used_mb == 4096
    assert result[0].utilization_percent == 72
    assert result[0].temperature_celsius == 66
    assert result[0].power_draw_watts == 321.5
    assert result[0].telemetry_source == "dcgm-exporter"


def test_mig_metrics_match_exact_workload_and_use_profiler_utilization(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    exposition = """
DCGM_FI_DEV_FB_FREE{UUID="GPU-parent",GPU_I_PROFILE="3g.40gb",GPU_I_ID="7",pod="worker-pod"} 32768
DCGM_FI_PROF_GR_ENGINE_ACTIVE{UUID="GPU-parent",GPU_I_PROFILE="3g.40gb",GPU_I_ID="7",pod="worker-pod"} 0.625
DCGM_FI_DEV_FB_USED{UUID="GPU-other",GPU_I_PROFILE="3g.40gb",GPU_I_ID="8",pod="other-pod"} 9999
"""
    monkeypatch.setattr(dcgm, "_fetch_metrics", lambda _configuration: exposition)

    result = enrich_gpus_from_dcgm([_gpu(uuid="MIG-device-uuid", mig_profile="3g.40gb")], _config())

    assert result[0].memory_used_mb == 49152
    assert result[0].utilization_percent == 62.5
    assert result[0].telemetry_source == "dcgm-exporter"


def test_unavailable_ambiguous_or_invalid_scrapes_fail_live_telemetry_closed(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    def fail(_configuration: object) -> str:
        raise DcgmExporterError("offline")

    monkeypatch.setattr(dcgm, "_fetch_metrics", fail)
    unavailable = enrich_gpus_from_dcgm([_gpu()], _config())[0]
    assert unavailable.memory_used_mb is None
    assert unavailable.utilization_percent is None
    assert unavailable.telemetry_source == "unavailable"

    ambiguous = """
DCGM_FI_DEV_FB_USED{UUID="GPU-a",GPU_I_PROFILE="3g.40gb",GPU_I_ID="1",pod="worker-pod"} 1
DCGM_FI_DEV_FB_USED{UUID="GPU-b",GPU_I_PROFILE="3g.40gb",GPU_I_ID="2",pod="worker-pod"} 2
"""
    monkeypatch.setattr(dcgm, "_fetch_metrics", lambda _configuration: ambiguous)
    result = enrich_gpus_from_dcgm([_gpu(uuid="MIG-device", mig_profile="3g.40gb")], _config())[0]
    assert result.telemetry_source == "unavailable"

    monkeypatch.setattr(dcgm, "_fetch_metrics", lambda _configuration: "not prometheus")
    assert enrich_gpus_from_dcgm([_gpu()], _config())[0].memory_used_mb is None


def test_parser_rejects_conflicts_and_ignores_non_finite_values() -> None:
    with pytest.raises(DcgmExporterError, match="conflicting"):
        parse_dcgm_metrics(
            'DCGM_FI_DEV_GPU_UTIL{UUID="GPU-test"} 10\nDCGM_FI_DEV_GPU_UTIL{UUID="GPU-test"} 20\n'
        )

    samples = parse_dcgm_metrics(
        'DCGM_FI_DEV_GPU_UTIL{UUID="GPU-test"} NaN\nDCGM_FI_DEV_FB_USED{UUID="GPU-test"} 100\n'
    )
    assert "DCGM_FI_DEV_GPU_UTIL" not in samples[0].values
    assert samples[0].values["DCGM_FI_DEV_FB_USED"] == 100


def test_fetch_is_bounded_and_forwards_basic_auth_without_credentials_in_url(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    class Response:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_args):  # type: ignore[no-untyped-def]
            return None

        def read(self, amount: int) -> bytes:
            captured["amount"] = amount
            return b'DCGM_FI_DEV_GPU_UTIL{UUID="GPU-test"} 1\n'

    def open_request(request, timeout):  # type: ignore[no-untyped-def]
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(dcgm, "urlopen", open_request)
    config = DcgmExporterConfiguration(
        enabled=True,
        endpoint="https://user:secret@dcgm.example:9400/metrics",
        endpoint_host="dcgm.example",
        timeout_seconds=2,
    )

    assert "GPU-test" in dcgm._fetch_metrics(config)
    assert captured["url"] == "https://dcgm.example:9400/metrics"
    assert captured["authorization"] == "Basic " + base64.b64encode(b"user:secret").decode()
    assert captured["timeout"] == 2
    assert captured["amount"] == dcgm.MAX_RESPONSE_BYTES + 1

    monkeypatch.setattr(
        dcgm, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(URLError("offline"))
    )
    with pytest.raises(DcgmExporterError, match="scrape failed"):
        dcgm._fetch_metrics(config)

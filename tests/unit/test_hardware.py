from __future__ import annotations

import shutil
import subprocess
from unittest.mock import Mock

import pytest

from aecontrol.hardware import detect_nvidia_gpus, detect_worker_capabilities
from aecontrol.models import Accelerator


def test_nvidia_gpu_output_is_normalized(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    result = Mock(
        returncode=0,
        stdout=(
            "0, GPU-test, NVIDIA RTX 5000 Ada Generation Laptop GPU, "
            "16376, 512, 42, 61, 47.25, 8.9\n"
        ),
    )
    monkeypatch.setattr(shutil, "which", Mock(return_value="/usr/bin/nvidia-smi"))
    monkeypatch.setattr(subprocess, "run", Mock(return_value=result))

    devices = detect_nvidia_gpus()

    assert devices[0].memory_total_mb == 16376
    assert devices[0].memory_used_mb == 512
    assert devices[0].utilization_percent == 42
    assert devices[0].temperature_celsius == 61
    assert devices[0].power_draw_watts == 47.25
    assert devices[0].uuid == "GPU-test"
    assert devices[0].compute_capability == "8.9"


def test_missing_nvidia_smi_falls_back_to_cpu(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(shutil, "which", Mock(return_value=None))

    capabilities = detect_worker_capabilities({"pool": "test"})

    assert capabilities.accelerators == [Accelerator.CPU]
    assert capabilities.labels == {"pool": "test"}


def test_configured_mig_profile_is_applied_to_visible_devices(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    result = Mock(
        returncode=0,
        stdout="0, MIG-test, NVIDIA H100 80GB HBM3, 40960, 0, 0, 35, 50, 9.0\n",
    )
    monkeypatch.setenv("AECONTROL_MIG_PROFILE", " 1C.3G.40GB ")
    monkeypatch.setattr(shutil, "which", Mock(return_value="/usr/bin/nvidia-smi"))
    monkeypatch.setattr(subprocess, "run", Mock(return_value=result))

    capabilities = detect_worker_capabilities()

    assert capabilities.gpus[0].mig_profile == "1c.3g.40gb"
    assert Accelerator.CUDA in capabilities.accelerators


def test_configured_dcgm_exporter_enriches_detected_devices(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    result = Mock(
        returncode=0,
        stdout="0, GPU-test, NVIDIA H100, 81920, 1, 2, 3, 4, 9.0\n",
    )
    monkeypatch.setenv("AECONTROL_DCGM_EXPORTER_URL", "http://dcgm:9400/metrics")
    monkeypatch.setattr(shutil, "which", Mock(return_value="/usr/bin/nvidia-smi"))
    monkeypatch.setattr(subprocess, "run", Mock(return_value=result))
    monkeypatch.setattr(
        "aecontrol.dcgm._fetch_metrics",
        lambda _configuration: 'DCGM_FI_DEV_GPU_UTIL{UUID="GPU-test"} 88\n',
    )

    capabilities = detect_worker_capabilities()

    assert capabilities.gpus[0].utilization_percent == 88
    assert capabilities.gpus[0].telemetry_source == "dcgm-exporter"


def test_invalid_configured_mig_profile_fails_closed(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("AECONTROL_MIG_PROFILE", "forty-gigabytes")
    monkeypatch.setattr(shutil, "which", Mock(return_value=None))

    with pytest.raises(ValueError, match="invalid NVIDIA MIG profile"):
        detect_worker_capabilities()


def test_failed_or_malformed_gpu_queries_are_ignored(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(shutil, "which", Mock(return_value="/usr/bin/nvidia-smi"))
    monkeypatch.setattr(subprocess, "run", Mock(return_value=Mock(returncode=1, stdout="")))
    assert detect_nvidia_gpus() == []

    malformed = Mock(returncode=0, stdout="bad row\n0, uuid, GPU, invalid, 1, 2, 3, 4, 9.0\n")
    monkeypatch.setattr(subprocess, "run", Mock(return_value=malformed))
    assert detect_nvidia_gpus() == []

    no_power = Mock(returncode=0, stdout="0, uuid, GPU, 100, 10, 20, 30, [N/A], 9.0\n")
    monkeypatch.setattr(subprocess, "run", Mock(return_value=no_power))
    assert detect_nvidia_gpus()[0].power_draw_watts is None

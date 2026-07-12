from __future__ import annotations

import shutil
import subprocess
from unittest.mock import Mock

from aecontrol.hardware import detect_nvidia_gpus, detect_worker_capabilities
from aecontrol.models import Accelerator


def test_nvidia_gpu_output_is_normalized(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    result = Mock(
        returncode=0,
        stdout="NVIDIA RTX 5000 Ada Generation Laptop GPU, 16376, 8.9\n",
    )
    monkeypatch.setattr(shutil, "which", Mock(return_value="/usr/bin/nvidia-smi"))
    monkeypatch.setattr(subprocess, "run", Mock(return_value=result))

    devices = detect_nvidia_gpus()

    assert devices[0].memory_total_mb == 16376
    assert devices[0].compute_capability == "8.9"


def test_missing_nvidia_smi_falls_back_to_cpu(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(shutil, "which", Mock(return_value=None))

    capabilities = detect_worker_capabilities({"pool": "test"})

    assert capabilities.accelerators == [Accelerator.CPU]
    assert capabilities.labels == {"pool": "test"}


def test_failed_or_malformed_gpu_queries_are_ignored(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(shutil, "which", Mock(return_value="/usr/bin/nvidia-smi"))
    monkeypatch.setattr(subprocess, "run", Mock(return_value=Mock(returncode=1, stdout="")))
    assert detect_nvidia_gpus() == []

    malformed = Mock(returncode=0, stdout="bad row\nGPU, not-a-number, 9.0\n")
    monkeypatch.setattr(subprocess, "run", Mock(return_value=malformed))
    assert detect_nvidia_gpus() == []

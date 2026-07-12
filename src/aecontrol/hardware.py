from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess

from aecontrol.models import Accelerator, GpuDevice, WorkerCapabilities


def detect_worker_capabilities(labels: dict[str, str] | None = None) -> WorkerCapabilities:
    gpus = detect_nvidia_gpus()
    accelerators = [Accelerator.CPU]
    if gpus:
        accelerators.append(Accelerator.CUDA)
    return WorkerCapabilities(
        hostname=socket.gethostname(),
        operating_system=platform.system().lower(),
        architecture=platform.machine(),
        cpu_count=os.cpu_count() or 1,
        accelerators=accelerators,
        gpus=gpus,
        labels=labels or {},
    )


def detect_nvidia_gpus() -> list[GpuDevice]:
    executable = shutil.which("nvidia-smi")
    if executable is None:
        return []
    try:
        result = subprocess.run(
            [
                executable,
                "--query-gpu=name,memory.total,compute_cap",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=2,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []

    devices: list[GpuDevice] = []
    for line in result.stdout.splitlines():
        fields = [field.strip() for field in line.split(",")]
        if len(fields) != 3:
            continue
        try:
            devices.append(
                GpuDevice(
                    name=fields[0],
                    memory_total_mb=int(fields[1]),
                    compute_capability=fields[2],
                )
            )
        except ValueError:
            continue
    return devices

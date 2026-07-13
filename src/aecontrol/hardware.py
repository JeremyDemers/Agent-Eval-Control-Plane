from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess

from aecontrol.dcgm import dcgm_configuration_from_environment, enrich_gpus_from_dcgm
from aecontrol.models import Accelerator, GpuDevice, WorkerCapabilities, normalize_mig_profile


def detect_worker_capabilities(labels: dict[str, str] | None = None) -> WorkerCapabilities:
    gpus = detect_nvidia_gpus()
    mig_profile = os.getenv("AECONTROL_MIG_PROFILE")
    if mig_profile is not None:
        mig_profile = normalize_mig_profile(mig_profile)
        gpus = [
            GpuDevice.model_validate({**gpu.model_dump(), "mig_profile": mig_profile})
            for gpu in gpus
        ]
    gpus = enrich_gpus_from_dcgm(gpus, dcgm_configuration_from_environment())
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
                "--query-gpu=index,uuid,name,memory.total,memory.used,utilization.gpu,temperature.gpu,power.draw,compute_cap",
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
        if len(fields) != 9:
            continue
        try:
            devices.append(
                GpuDevice(
                    index=int(fields[0]),
                    uuid=fields[1],
                    name=fields[2],
                    memory_total_mb=int(fields[3]),
                    memory_used_mb=int(fields[4]),
                    utilization_percent=float(fields[5]),
                    temperature_celsius=float(fields[6]),
                    power_draw_watts=_optional_float(fields[7]),
                    compute_capability=fields[8],
                    telemetry_source="nvidia-smi",
                )
            )
        except ValueError:
            continue
    return devices


def _optional_float(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None

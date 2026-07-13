import pytest
from pydantic import ValidationError

from aecontrol.models import Accelerator, EvaluationJob, GpuDevice


def test_mig_profiles_are_normalized_and_require_cuda() -> None:
    job = EvaluationJob(
        suite_path="suite.yaml",
        agent_version="nim/model",
        required_accelerator=Accelerator.CUDA,
        required_mig_profile=" 1C.3G.40GB ",
    )
    device = GpuDevice(
        name="H100 MIG",
        memory_total_mb=40960,
        compute_capability="9.0",
        mig_profile="3G.40GB",
    )

    assert job.required_mig_profile == "1c.3g.40gb"
    assert device.mig_profile == "3g.40gb"

    with pytest.raises(ValidationError, match="require the cuda accelerator"):
        EvaluationJob(
            suite_path="suite.yaml",
            agent_version="baseline",
            required_mig_profile="1g.10gb",
        )


@pytest.mark.parametrize("profile", ["", "40gb", "0g.10gb", "1g.0gb", "mig-3g.40gb"])
def test_invalid_mig_profiles_are_rejected(profile: str) -> None:
    with pytest.raises(ValidationError, match="invalid NVIDIA MIG profile"):
        GpuDevice(
            name="H100 MIG",
            memory_total_mb=40960,
            compute_capability="9.0",
            mig_profile=profile,
        )

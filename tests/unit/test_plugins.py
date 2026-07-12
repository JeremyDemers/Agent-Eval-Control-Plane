import pytest

from aecontrol.agents import get_coding_agent, list_agent_versions
from aecontrol.plugins import PluginRegistry


def test_registry_detects_collisions() -> None:
    registry: PluginRegistry[object] = PluginRegistry()
    item = object()
    registry.register("x", item)

    with pytest.raises(ValueError, match="already registered"):
        registry.register("x", object())


def test_registry_lists_names() -> None:
    registry: PluginRegistry[object] = PluginRegistry()
    registry.register("b", object())
    registry.register("a", object())

    assert registry.list() == ["a", "b"]


def test_agent_versions_are_explicit() -> None:
    versions = {version.version for version in list_agent_versions()}

    assert versions == {"baseline", "candidate_fixed", "candidate_regressed"}
    assert get_coding_agent("candidate_regressed").version.description

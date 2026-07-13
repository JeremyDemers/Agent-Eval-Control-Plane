# Plugin Development

Plugins implement typed runtime or evaluator protocols and may be registered in-process or discovered
through Python entry points. Plugins must not perform network calls at import time and should provide
clear names, deterministic behavior, and contract tests.

`EvaluationEngine(runtime=...)` accepts any `RuntimeAdapter`. `LangGraphRuntimeAdapter` is the
reference external-framework implementation: it uses builders for graph input and per-run config,
captures the framework's stable streaming contract, and returns ordinary `AgentOutput` evidence.
See [`langgraph.md`](langgraph.md) for a complete example.

# Plugin Development

Plugins implement typed runtime or evaluator protocols and may be registered in-process or discovered
through Python entry points. Plugins must not perform network calls at import time and should provide
clear names, deterministic behavior, and contract tests.

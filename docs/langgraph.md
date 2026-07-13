# LangGraph Runtime Interoperability

AgentEval can execute a trusted compiled LangGraph as an evaluation runtime. The integration uses
LangGraph's unified v2 stream format and requests `tasks`, `updates`, `values`, `messages`, and
`custom` modes with subgraph streaming enabled. It does not require LangGraph for the base package.

```bash
uv sync --extra langgraph
make langgraph-demo
```

The demo builds a two-node planning and coding graph, runs four dataset slices through the existing
resource-limited sandbox, and evaluates the resulting graph and tool trajectory. It is deterministic
and requires no hosted model credentials.

## Runtime Contract

Construct the graph in trusted application code and inject the adapter into the engine:

```python
from aecontrol import EvaluationEngine, LangGraphRuntimeAdapter

runtime = LangGraphRuntimeAdapter(
    compiled_graph,
    graph_name="support_agent",
    input_builder=lambda request: {
        "messages": [message.model_dump() for message in request.messages],
        "case": request.variables["case"],
    },
    config_builder=lambda request: {
        "configurable": {"thread_id": request.case_id},
    },
)
run = await EvaluationEngine(runtime=runtime).run(suite, "langgraph/support-v3")
```

The compiled object must expose LangGraph's asynchronous `astream` method. Each execution receives a
fresh input and optional config; applications using checkpointers should provide a unique thread ID.
The compiled graph and any checkpointer must support the suite's configured concurrency.

The final root `values` state maps these keys into `AgentOutput`:

| State key | Type | Default |
| --- | --- | --- |
| `final_response` | string or message mapping | `None` |
| `patch` | string | empty |
| `modified_files` | list of strings | empty |
| `public_test_output` | string | `not provided` |
| `hidden_test_output` | string | `not provided` |
| `status` | `passed`, `failed`, or `error` | `passed` |
| `tool_calls` | list of name/arguments mappings | empty |
| `tool_results` | list of name/ok/output mappings | empty |

`LangGraphOutputMapping` remaps these names when an existing graph uses a different state schema.
Mapped tool activity is emitted as standard trajectory steps, so expected/forbidden-tool evaluators
work without LangGraph-specific logic. Node start/finish/error events remain distinct `graph_node`
steps; updates and custom events use `graph_event`. The browser run detail shows ordered node names
alongside tool activity.

## Evidence Boundaries

State and task payload capture is disabled by default. Trajectories retain node names, phases,
namespaces, trigger metadata, changed key names, model message content, and mapped final evidence.
Set `LangGraphCaptureOptions(capture_payloads=True)` only when complete node input, result, update, and
custom payloads are required. Keys named `api_key`, `authorization`, `password`, `secret`, or `token`
are redacted recursively; applications can replace the redaction set.

The adapter rejects an individual stream event above 1 MB, a run above 10 MB of stream data, or a run
above 10,000 events by default. All limits are configurable within hard validation bounds. Graph exceptions, invalid v2 parts,
interrupts before final output, missing root state, mapping errors, and limit violations become
`ExecutionStatus.ERROR` evidence with the observed trajectory retained. They do not escape the
runtime and terminate a durable worker lease.

Redaction is defense in depth, not a data-loss-prevention system. Model message content, mapped final
responses, patches, and test output are evaluation evidence and may be sensitive. Do not place
credentials in graph state, and apply the same database and artifact-access controls used for native
runs.

The adapter targets the official LangGraph v2 unified stream introduced in LangGraph 1.1. See the
[streaming contract](https://docs.langchain.com/oss/python/langgraph/streaming) and
[Graph API](https://docs.langchain.com/oss/python/langgraph/graph-api).

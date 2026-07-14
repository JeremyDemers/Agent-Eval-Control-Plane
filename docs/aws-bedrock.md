# Amazon Bedrock Runtime

Agent versions prefixed with `bedrock/` use the Amazon Bedrock Converse API. The adapter supplies a
single `coding_repair` tool with a JSON Schema input, explicitly selects that tool, and accepts exactly
one matching tool result. It records the model ID, AWS region, prompt SHA-256, token usage, latency,
stop reason, and request ID without recording credentials, profile names, prompts, or AWS error text.

## Local use

Authentication uses the standard Boto3 credential provider chain. Prefer short-lived AWS SSO or role
credentials; the application does not define environment variables for access-key material.

```bash
export AECONTROL_BEDROCK_REGION=us-east-1
export AECONTROL_BEDROCK_PROFILE=portfolio
uv run aecontrol bedrock doctor
uv run aecontrol bedrock models
uv run aecontrol run --suite examples/suites/ollama_smoke.yaml \
  --agent-version bedrock/replace-with-converse-tool-capable-model-id \
  --output reports/bedrock.json
```

`AECONTROL_BEDROCK_TIMEOUT_SECONDS` defaults to 120 and accepts 1-300 seconds. Region resolution uses
`AECONTROL_BEDROCK_REGION`, then `AWS_REGION`, then `AWS_DEFAULT_REGION`, and finally `us-east-1`.
The optional `AECONTROL_BEDROCK_PROFILE` selects a named local SDK profile and is never persisted.

## Durable placement

Queued `bedrock/` jobs automatically require `runtime=aws-bedrock`. Advertise that label only from
workers with Bedrock access:

```bash
uv run aecontrol worker --label runtime=aws-bedrock
```

The `deploy/overlays/aws-bedrock` Kustomize overlay adds a dedicated CPU worker and EKS service
account. Replace its IRSA role annotation and attach a policy based on
`iam-policy.example.json`. The example permits text-model discovery and invocation of one explicit
foundation-model ARN; it does not grant model administration, streaming, Agents, knowledge-base,
S3, or Secrets Manager access. The pod receives AWS web identity from EKS and contains no static AWS
access key.

```bash
kubectl kustomize deploy/overlays/aws-bedrock | kubectl apply -f -
```

For an inference profile, provisioned model, or cross-region model ID, replace the IAM resource with
the exact corresponding ARN or ARNs. Converse authorization is governed by `bedrock:InvokeModel`.

## Contract and limits

Converse provides one request shape across message-capable Bedrock models, but forced tool choice is
model-dependent. Choose a model that supports Converse tool use and test it in the target region.
Provider failures become per-case error artifacts with sanitized messages; they do not fall back to a
different model or provider. CI uses injected Boto3 transport doubles, so it verifies request,
response, error, metadata, and scheduling contracts without cloud credentials or inference charges.

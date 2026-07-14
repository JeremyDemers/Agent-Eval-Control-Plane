# Vault Transit Remote Signing

AgentEval can delegate every new evidence and ledger-checkpoint signature to a version-pinned
HashiCorp Vault Transit Ed25519 key. The API and workers retain only a short-lived Vault credential
and public verification keys; the Ed25519 private key is never returned to or loaded by AgentEval.
Vault documents Transit as a cryptography service and supports Ed25519 signing and verification in
its [Transit engine](https://developer.hashicorp.com/vault/docs/secrets/transit).

## Provision The Key

Enable Transit once and create a non-exportable Ed25519 key through an operator channel:

```bash
vault secrets enable transit
vault write transit/keys/agent-evidence \
  type=ed25519 exportable=false allow_plaintext_backup=false
```

The [Transit HTTP API](https://developer.hashicorp.com/vault/api-docs/secret/transit) returns public
keys by version when the key is read. Convert the selected version's PEM public key to the raw 32-byte
base64 value expected by AgentEval:

```bash
vault read -format=json transit/keys/agent-evidence \
  | jq -r '.data.keys["1"].public_key' > /tmp/agent-evidence-v1.pem
PUBLIC_KEY="$(uv run python - /tmp/agent-evidence-v1.pem <<'PY'
import base64
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

key = serialization.load_pem_public_key(Path(sys.argv[1]).read_bytes())
if not isinstance(key, Ed25519PublicKey):
    raise SystemExit("Vault Transit key is not Ed25519")
print(base64.b64encode(key.public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)).decode())
PY
)"
```

Grant the workload token only signing authority. It does not need key read, rotation, export, backup,
verification, or administrative capabilities:

```hcl
path "transit/sign/agent-evidence" {
  capabilities = ["update"]
}
```

## Configure AgentEval

Bind the envelope key ID to one explicit Vault key version and publish its public key locally:

```bash
export AECONTROL_ARTIFACT_SIGNING_KEY_ID=vault-evidence-v1
export AECONTROL_ARTIFACT_SIGNING_ALGORITHM=ed25519
export AECONTROL_ARTIFACT_ED25519_PUBLIC_KEYS="{\"vault-evidence-v1\":\"$PUBLIC_KEY\"}"
export AECONTROL_ARTIFACT_VAULT_ADDR=https://vault.example
export AECONTROL_ARTIFACT_VAULT_TOKEN_FILE=/var/run/secrets/vault/token
export AECONTROL_ARTIFACT_VAULT_MOUNT=transit
export AECONTROL_ARTIFACT_VAULT_KEY=agent-evidence
export AECONTROL_ARTIFACT_VAULT_KEY_VERSION=1
export AECONTROL_ARTIFACT_VAULT_TIMEOUT_SECONDS=5
```

`AECONTROL_ARTIFACT_VAULT_TOKEN` is available for local testing, but exactly one token source is
required and a renewable workload token file is preferred. `AECONTROL_ARTIFACT_VAULT_NAMESPACE` is
optional for Vault Enterprise namespaces. Non-loopback addresses require HTTPS; normal system CA
verification applies. `aecontrol doctor` reports only the Vault host, mount, and pinned key version.

The signer sends the exact domain-separated AgentEval message as base64 input and sets `key_version`.
It accepts only a bounded JSON response containing a 64-byte signature prefixed with the matching
`vault:vN:` version. AgentEval removes the Vault prefix and stores ordinary base64 Ed25519, preserving
the existing envelope and public-only audit path.

## Rotation And Failure Behavior

1. Rotate the Vault key and retrieve the new version's public key.
2. Add a new AgentEval envelope key ID and public key without removing historical public keys.
3. Deploy the new Vault key version and envelope key ID together to every signer.
4. Run `aecontrol store verify` before retiring the previous workload configuration.

Explicit version pinning prevents Vault auto-rotation from silently signing under a public key that
does not match the stored envelope ID. AgentEval rejects a response carrying any other Vault version.

Vault HTTP failures, timeouts, oversized or malformed responses, and invalid signatures fail evidence
writes before their PostgreSQL transaction commits. The API returns a sanitized HTTP 503 and does not
expose Vault response bodies, tokens, URLs, or exception text. Existing evidence reads and audits use
the configured public keys and remain independent of Vault availability.

The Kubernetes `vault-transit` overlay removes the local private-key environment variable and mounts
an externally managed token Secret read-only. The example token Secret is intentionally excluded from
Kustomize. Prefer Vault Kubernetes auth plus an agent/CSI integration that refreshes this Secret or
token file; patch the Vault address, CA trust, key, and version for the environment before applying it.

Vault's documentation notes that Ed25519 is not certified in Vault FIPS 140-3 mode. Deployments with a
FIPS requirement must select a certified signature algorithm and corresponding future AgentEval
envelope adapter rather than enabling this Ed25519 integration.

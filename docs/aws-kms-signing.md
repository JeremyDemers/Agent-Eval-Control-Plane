# AWS KMS Remote Signing

AgentEval can delegate every new evidence and ledger-checkpoint signature to a non-exportable AWS
KMS Ed25519 key. API and worker processes receive short-lived AWS workload credentials and public
verification keys; private signing material never enters a pod, process, Secret, or PostgreSQL.

AWS KMS supports `ECC_NIST_EDWARDS25519` keys for signing and verification. AgentEval fixes the
operation to `ED25519_SHA_512` with `MessageType=RAW`, which produces the same 64-byte Ed25519
signature envelope used by local and Vault signers. Stored evidence therefore remains portable and
verifiable without AWS availability or credentials.

## Provision The Key

Create one asymmetric signing key and retain its immutable key ARN. Aliases are deliberately rejected
because retargeting an alias could silently change the private key behind an envelope key ID.

```bash
KEY_ARN="$(aws kms create-key \
  --key-spec ECC_NIST_EDWARDS25519 \
  --key-usage SIGN_VERIFY \
  --description 'AgentEval evidence signing' \
  --query KeyMetadata.Arn --output text)"

aws kms get-public-key --key-id "$KEY_ARN" --query PublicKey --output text \
  | base64 --decode > /tmp/aecontrol-kms-public.der

PUBLIC_KEY="$(uv run python - /tmp/aecontrol-kms-public.der <<'PY'
import base64
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

key = serialization.load_der_public_key(Path(sys.argv[1]).read_bytes())
if not isinstance(key, Ed25519PublicKey):
    raise SystemExit("AWS KMS key is not Ed25519")
print(base64.b64encode(key.public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)).decode())
PY
)"
```

[`GetPublicKey`](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html) returns
DER-encoded X.509 SubjectPublicKeyInfo. Run that provisioning step through an operator identity;
runtime signers need only `kms:Sign` on the exact key ARN. Pin the algorithm in IAM as well:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "SignAgentEvalEvidenceOnly",
    "Effect": "Allow",
    "Action": "kms:Sign",
    "Resource": "arn:aws:kms:us-east-2:123456789012:key/REPLACE_WITH_KEY_ID",
    "Condition": {
      "StringEquals": {"kms:SigningAlgorithm": "ED25519_SHA_512"}
    }
  }]
}
```

## Configure AgentEval

Bind one logical envelope key ID to the KMS key and its raw public key:

```bash
export AECONTROL_ARTIFACT_SIGNING_KEY_ID=aws-kms-evidence-2026-07
export AECONTROL_ARTIFACT_SIGNING_ALGORITHM=ed25519
export AECONTROL_ARTIFACT_ED25519_PUBLIC_KEYS="{\"aws-kms-evidence-2026-07\":\"$PUBLIC_KEY\"}"
export AECONTROL_ARTIFACT_AWS_KMS_KEY_ARN="$KEY_ARN"
export AECONTROL_ARTIFACT_AWS_KMS_TIMEOUT_SECONDS=5
unset AECONTROL_ARTIFACT_ED25519_PRIVATE_KEYS
```

The SDK derives the region from the key ARN and uses its standard credential provider chain. Prefer
EKS Pod Identity or IRSA, EC2 instance profiles, or an equivalent short-lived workload identity;
never inject static AWS access keys. `aecontrol doctor` reports only the region and a truncated
SHA-256 fingerprint of the ARN.

Each request is bounded to 4096 bytes and uses bounded standard SDK retries plus equal connect/read
timeouts. AgentEval accepts only a response carrying the exact configured key ARN, fixed signing
algorithm, and 64-byte signature. It then verifies that signature locally against the configured
public key before committing evidence. Transport errors, authorization failures, malformed responses,
identity mismatches, and verification failures roll back the write and return a sanitized HTTP 503.
Existing reads and audits remain independent of KMS.

## Kubernetes And Rotation

`deploy/overlays/aws-kms` removes private-key injection from every API/worker pod and binds an
IRSA-ready ServiceAccount. Replace its role ARN, KMS key ARN, logical key ID, and public-key Secret
before applying it:

```bash
kubectl apply -k deploy/overlays/aws-kms
kubectl -n aecontrol rollout status deployment/api
uv run aecontrol doctor
uv run aecontrol store verify
```

For the scheduled checkpoint publisher, apply the same KMS variables and workload identity to its
ServiceAccount and delete `AECONTROL_ARTIFACT_ED25519_PRIVATE_KEYS`. Its role needs both the exact
`kms:Sign` permission above and the independently scoped S3 Object Lock permissions.

Rotate by creating a new KMS key, exporting its public key through the operator channel, adding a new
logical envelope key ID to the public map, and deploying the new ARN and key ID together. Run the
integrity audit before disabling the old key. Keep every historical public key for the full evidence
retention period; old signatures remain valid even after the old KMS key is disabled or deleted.

The workload identity can request signatures for attacker-chosen AgentEval envelopes while a pod is
compromised. IAM scope, KMS key policy, CloudTrail monitoring, credential lifetime, egress controls,
and rapid role revocation remain required controls. KMS protects key extraction; it does not make a
compromised authorized signer trustworthy.

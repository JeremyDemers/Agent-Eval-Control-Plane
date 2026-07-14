# Google Cloud KMS and Cloud HSM Signing

AgentEval can sign new evidence with a version-pinned Google Cloud KMS `EC_SIGN_ED25519` key while
continuing to verify all signatures locally from configured public keys. The active private key is
never available to the application. A key version can use `SOFTWARE`, `HSM`, `HSM_SINGLE_TENANT`, or
an external protection level; the expected level is pinned in configuration and checked on every
response.

## Signing contract

Set the normal Ed25519 envelope configuration and the full immutable CryptoKeyVersion resource name:

```bash
export AECONTROL_ARTIFACT_SIGNING_KEY_ID=gcp-hsm-2026-07
export AECONTROL_ARTIFACT_SIGNING_ALGORITHM=ed25519
export AECONTROL_ARTIFACT_ED25519_PUBLIC_KEYS='{"gcp-hsm-2026-07":"BASE64_RAW_32_BYTE_PUBLIC_KEY"}'
export AECONTROL_ARTIFACT_GCP_KMS_KEY_VERSION=projects/PROJECT/locations/us-central1/keyRings/evidence/cryptoKeys/artifact-signing/cryptoKeyVersions/1
export AECONTROL_ARTIFACT_GCP_KMS_PROTECTION_LEVEL=HSM
uv run aecontrol doctor
```

The signer submits the canonical artifact message as raw `data`, which is required by
`EC_SIGN_ED25519`. Every request includes `data_crc32c`. A response is accepted only when Cloud KMS
confirms that checksum, returns the exact configured key-version name and protection level, returns a
64-byte signature, and supplies a matching `signature_crc32c`. Integrity failures retry at most three
times by default; API, authentication, identity, algorithm, and shape failures fail closed without
provider diagnostics entering persisted evidence. The `ArtifactKeyring` then verifies the signature
again using the configured Ed25519 public key before any database commit.

Optional controls:

- `AECONTROL_ARTIFACT_GCP_KMS_TIMEOUT_SECONDS`: RPC timeout from 0.1 to 30 seconds; default `5`.
- `AECONTROL_ARTIFACT_GCP_KMS_INTEGRITY_ATTEMPTS`: checksum attempts from 1 to 5; default `3`.
- `AECONTROL_ARTIFACT_GCP_KMS_PROTECTION_LEVEL`: expected `SOFTWARE`, `HSM`,
  `HSM_SINGLE_TENANT`, `EXTERNAL`, or `EXTERNAL_VPC`; default `HSM`.

Vault Transit, AWS KMS, Google Cloud KMS, and a local active private key are mutually exclusive.
Historical public keys remain configured during rotation. Create and activate a new Cloud KMS key
version, export its raw Ed25519 public key into the verifier map under a new application key ID, update
the full version resource, and restart every signer. Existing evidence remains verifiable offline.

## GKE Workload Identity

`deploy/overlays/gcp-kms` removes local private keys and assigns API and worker pods to the dedicated
`aecontrol-gcp-kms-signer` Kubernetes service account. It uses direct Workload Identity Federation for
GKE, so no Google service-account key file or `GOOGLE_APPLICATION_CREDENTIALS` Secret is present.

Create the custom role and bind the GKE principal only on the target CryptoKey:

```bash
gcloud iam roles create aecontrolKmsSigner --project=PROJECT_ID \
  --file=deploy/overlays/gcp-kms/custom-role.example.yaml

gcloud kms keys add-iam-policy-binding artifact-signing \
  --project=PROJECT_ID --location=us-central1 --keyring=evidence \
  --role=projects/PROJECT_ID/roles/aecontrolKmsSigner \
  --member='principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/PROJECT_ID.svc.id.goog/subject/ns/aecontrol/sa/aecontrol-gcp-kms-signer'

kubectl apply -k deploy/overlays/gcp-kms
```

Replace the project, location, key ring, key, key version, public key, and image promotion values.
Enable Workload Identity Federation for GKE on the cluster and node pool before rollout. The example
custom role contains only `cloudkms.cryptoKeyVersions.useToSign`; it cannot create, rotate, disable,
destroy, export, encrypt with, or decrypt with keys.

## Trust boundary

Cloud KMS or Cloud HSM protects key extraction, not signing intent. A compromised API or worker can
request signatures from every key its principal may use. Restrict IAM on the individual CryptoKey,
separate signing from key administration, retain Cloud Audit Logs, alert on unexpected signing volume,
and use organization policy where required. A compromised database administrator can alter evidence
rows but cannot create a valid signature without invoking the remote key.

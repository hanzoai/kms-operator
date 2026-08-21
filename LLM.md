# Hanzo Kms Operator

## Overview
Go module: `github.com/hanzoai/kms-operator`.

Reconciles `KMSSecret` and `KMSPushSecret` CRDs (`kms.hanzo.ai/v1`)
against the canonical luxfi/kms surface (`~/work/hanzo/kms` cmd/kmsd at
`kms.hanzo.svc.cluster.local`).

## Tech Stack
- **Language**: Go 1.26.3
- **Controller framework**: sigs.k8s.io/controller-runtime v0.23.x
- **KMS dep**: `github.com/luxfi/kms@v1.9.11` (transitively pulls
  `pkg/zapclient` for ZAP transport)

## Build & Run
```bash
GOWORK=off go build ./...
GOWORK=off go test ./...
```

(`GOWORK=off` because this module is not a member of the parent
`~/work/hanzo/go.work` use-list — it ships as a leaf module.)

## Transport (v0.3.0+) — HTTP vs ZAP

The reconciler talks to KMS over either of:

- **HTTP** (default): `http(s)://…` host. `clientId`/`clientSecret` from
  the CR's `universalAuth.credentialsRef` → bearer JWT via IAM. Used for
  every CR that doesn't opt into ZAP.
- **ZAP** (opt-in per CR via `spec.hostAPI`):
  - `zap://host:port` — direct address (typically
    `zap://kms.hanzo.svc.cluster.local:9999`).
  - `zap+mdns://_kms._tcp` — mDNS discovery (single peer wins).

The factory `util.BuildTransport(host, ca, ua)` picks the impl by
scheme. Both reconcilers (`KMSSecret`, `KMSPushSecret`) call it at
`getResourceVariables` time.

### ZAP auth — important divergence

ZAP does NOT consume IAM bearer tokens. The kmsd ZAP server
(`luxfi/kms/pkg/zapserver/auth.go`) authorises by peer NodeID + ACL:

```
# KMS_ZAP_ACL file format (per luxfi/kms):
nodeId,pathPrefix,role
kms-operator-canonical,,admin
```

To enable ZAP in production:

1. Set `KMS_OPERATOR_ZAP_NODE_ID=<unique-id>` on the operator Deployment.
2. Add `<unique-id>,<path-prefix>,admin` (or `read`) to the KMS ACL file
   referenced by `KMS_ZAP_ACL` on kmsd.
3. Set `spec.hostAPI: zap://kms.hanzo.svc.cluster.local:9999` on the
   target CR.

`clientId`/`clientSecret` from the CR's `universalAuth.credentialsRef`
are accepted but **ignored** on the ZAP path — the call still works
because `Login()` returns a synthetic `zap:<nodeID>` token kept in the
existing token cache.

## Structure
```
kms-operator/
  Dockerfile                 # alpine builder (incl. git for VCS resolution)
  Makefile
  PROJECT
  README.md
  api/v1/              # KMSSecret + KMSPushSecret CRD types
  bin/
  config/
  controllers/
    kmssecret/               # read-side reconciler
    kmspushsecret/           # write-side reconciler
  frontend/                  # static (unused on the wire)
  go.mod
  go.sum
  hack/
  kubectl-install/
  main.go
  packages/
    api/                     # global host / CA / UA config
    constants/
    controllerhelpers/
    controllerutil/
    crypto/
    generator/               # password/token generator output for push
    kmsapi/                  # HTTP transport + Transport interface (v0.3.0+)
      transport.go           # ← interface seam
      client.go              # HTTP impl
    kmszap/                  # ZAP transport (v0.3.0+) — wraps luxfi/kms/pkg/zapclient
      client.go
    model/
    template/                # go-template for managed Secret/CM
    util/
      auth.go                # HandleUniversalAuth (token cache, NUL filter)
      models.go              # ResourceVariables (KMSClient: Transport)
      secrets.go             # GetPlainTextSecretsViaMachineIdentity
      transport.go           # BuildTransport factory (v0.3.0+)
```

## Key Files
- `packages/kmsapi/transport.go` — `Transport` interface (`Login`,
  `LoginCached`, `GetSecret`, `CreateSecret`, `UpdateSecret`,
  `DeleteSecret`, `InvalidateToken`) + `IsZAPHost`.
- `packages/kmsapi/client.go` — HTTP implementation (default).
- `packages/kmszap/client.go` — ZAP implementation (opt-in).
- `packages/util/transport.go` — `BuildTransport(host, ca, ua)`
  factory: picks HTTP vs ZAP by scheme.
- `controllers/{kmssecret,kmspushsecret}_helper.go` — call
  `util.BuildTransport` at `getResourceVariables`; pass the Transport
  to the reconcile pipeline.

## Consensus-authority reconciler (v0.3.1+)

`internal/bootstrap/` owns the `kms-consensus-authority` Secret that
the kmsd loads via `KMS_CONSENSUS_FILE`. The package is a
controller-runtime `Runnable` registered alongside the CR reconcilers
and gated by leader election.

Responsibilities:

  1. **Bootstrap** — on Start, ensure `kms-operator-mnemonic` Secret
     exists in the target namespace (default `hanzo`). Generate a
     fresh 24-word BIP-39 phrase if absent (or load from
     `KMS_OPERATOR_MNEMONIC` env). Derive the operator's NodeID via
     the byte-for-byte port of `luxfi/keys.NewServiceIdentity`
     (`service_identity.go`). Write the initial
     `kms-consensus-authority` Secret with that NodeID as the sole
     operator + the current luxd validator set.

  2. **Per-service identity** — each `KMSSecret` CR reconcile calls
     `EnsureServiceIdentity(ref, servicePath)`. If the mnemonic
     Secret is missing the operator generates + persists one, then
     derives the NodeID and stamps the canonical path back onto the
     Secret as an annotation (`kms-operator.lux.network/service-path`)
     so the periodic reconcile can re-derive without consulting the
     CR.

  3. **TTL reconcile** — every `KMS_CONSENSUS_TTL` (default 30s):
       a. Re-derive the operator NodeID (cached after first call).
       b. List every Secret in `KMS_MNEMONIC_NAMESPACE` carrying
          label `app.kubernetes.io/component=service-mnemonic` and
          derive each one's NodeID under its stamped service path.
       c. Pull `platform.getCurrentValidators` from `LUXD_RPC_URL`.
       d. Compose a canonical snapshot
          `{"validators": [...], "operators": [...]}` and `Update`
          the authority Secret only when the canonical bytes differ.

Fail-closed: any luxd unreachable / HTTP error leaves the authority
Secret untouched. The kmsd continues honouring the prior snapshot
until the next successful tick.

Mnemonic discipline: the BIP-39 phrase NEVER appears in CR status, in
operator logs, or in any non-Secret resource. Only the source category
(`secret` / `env` / `generate`) and the derived NodeID surface.

Determinism contract: `service_identity_test.go` pins NodeIDs derived
locally against vectors produced by `luxfi/keys.NewServiceIdentity` at
v1.0.10. Treat any failure as an emergency — drift would silently
revoke every consumer's KMS access.

### Env vars

| Var | Default | Meaning |
|-----|---------|---------|
| `KMS_AUTHORITY_NAMESPACE` | `hanzo` | Namespace of the authority Secret + per-service mnemonic Secrets. |
| `KMS_AUTHORITY_SECRET` | `kms-consensus-authority` | Authority Secret name. |
| `KMS_MNEMONIC_NAMESPACE` | `$KMS_AUTHORITY_NAMESPACE` | Namespace scanned for `app.kubernetes.io/component=service-mnemonic` Secrets. |
| `KMS_OPERATOR_MNEMONIC_SECRET` | `kms-operator-mnemonic` | Operator's own mnemonic Secret name. |
| `KMS_OPERATOR_MNEMONIC` | _unset_ | Optional bootstrap env carrying a pre-existing operator mnemonic. Honoured only on first-boot when the Secret is absent. |
| `KMS_OPERATOR_SERVICE_PATH` | `hanzo/kms-operator` | Canonical service path for the operator's own derivation. |
| `LUXD_RPC_URL` | `http://luxd-headless.lux-mainnet.svc.cluster.local:9650` | luxd Platform Chain RPC base. The hanzo cluster routes this at `https://api.lux.network` in production. |
| `KMS_CONSENSUS_TTL` | `30s` | Cadence of the periodic luxd-validator-set refresh. |

### CRD additions (v0.3.1+)

`KMSSecretSpec` and `KMSPushSecretSpec` gain two optional fields:

  - `spec.servicePath` — canonical service path for the consumer's
    NodeID derivation. Empty → `hanzo/<crname>`.
  - `spec.mnemonicSecretRef` — `KubeSecretReference` to an existing
    mnemonic Secret. Empty → `<crname>-mnemonic` in
    `KMS_MNEMONIC_NAMESPACE`.

Backward compatible: omitting both fields falls back to the
auto-derived defaults so existing CRs continue working without edit.

## Releases

- `v0.1.0` (2026-03)  initial port to canonical /v1/kms/* surface.
- `v0.2.0` (2026-04)  hardening: control-byte filter, fail-closed on
                      empty fetch, token cache, same-ns credentialsRef.
- `v0.3.0` (2026-05)  ZAP transport alongside HTTP.
- `v0.3.1` (2026-05)  kms-consensus-authority reconciler. Closes the
                      operator-side bootstrap left open by the
                      consensus-native-identity agent.
- `v0.4.0` (2026-07)  per-service WRITE path-scopes in the authority
                      snapshot (task #53). Also fixes two pre-existing
                      build blockers: Dockerfile now `COPY internal/`,
                      and flags the stale-vendor drift (see below).

## Path-scope activation (task #53) — state + open model gap

The kms-consensus-authority snapshot now carries an optional least-privilege
`scopes` overlay (`AuthorityScopes{validators,operators}`, NodeID→prefix).
The kmsd consumer (luxfi/kms `cmd/kms/consensus.go`, from
`feat/v1-sdk-secrets-plane`) parses it into `NewScopedAuthorityProvider` and
confines each bound NodeID to its granted subtree; absent scopes → flat +
a boot WARN. End-to-end scoped-deny is proven through `verifyAndAuthorize`
(luxfi/kms `pkg/zapserver/path_scope_e2e_test.go`).

**What the operator emits now:** `scopes.operators` = each service NodeID
confined to its OWN subtree (`deriveServiceScope` = the canonical service
path), the kms-operator itself unconfined. `scopes.validators` = **flat**
(the luxd L1 consensus set has no per-node secret subtree).

**Open model gap — DO NOT guess the read boundary:**
1. The enveloped `/v1/sdk` ZAP plane is **OFF in prod**: the live kmsd
   (`ghcr.io/luxfi/kms:1.11.8`, universe `infra/k8s/kms/deployment.yaml`)
   mounts **no** `KMS_CONSENSUS_FILE` and no `kms-consensus-authority`
   Secret. All secret access is the legacy HTTP `/v1/kms/orgs/{org}/secrets`
   path (IAM JWT, org-scoped by `owner`). So path-scope is defense-in-depth
   readiness, **not** a live blast-radius reduction yet.
2. zapserver requires **validator (read) membership for ALL ops**; services
   are placed in `operators` (write) **only** → a service can neither read
   nor write via the plane today, so the operator write-scope is inert until
   the plane is activated AND services are added to the read authority.
   Confining a compromised SERVICE key's READS (the task's actual goal)
   needs services to become **scoped members of the READ (validator)
   authority** — an authority-placement decision (recommended:
   operators ⊆ validators, each scoped to its own subtree; luxd L1 either
   unconfined readers or dropped). **Left for CTO confirmation.**

**Activation checklist (all gated):** (a) merge the /v1/sdk plane PR +
this operator PR; (b) re-sync stale vendor (`go mod vendor` on a networked
runner — x/{sys,term,text,tools} pinned newer in go.mod than vendored);
(c) confirm the read-authority placement + emit `scopes.validators`;
(d) mount `KMS_CONSENSUS_FILE=/etc/kms/consensus-authority.json` (the
`kms-consensus-authority` Secret) into the kmsd Deployment;
(e) semver tag → operator CR.

## Binary secret convention: `*.b64` (v0.4.2)

KMS values are JSON strings and the transport fails closed on control
bytes, so raw binary material (a 32-byte BLS signer key) cannot ride the
wire verbatim. Convention, enforced in ONE place
(`packages/util/secrets.go` fetch layer, pinned by
`TestB64KeysDecodeOnProjection`): a KMS secret named `X.b64` holds the
base64 of the raw bytes; on projection the operator strips the suffix and
decodes, so the managed k8s Secret carries key `X` with the exact bytes
its consumers expect (luxd startup scripts stay untouched). Invalid
base64 fails the whole reconcile (no partial/garbage projection). First
consumer: `luxd-staking` sync CRs in `luxfi/universe`
`k8s/lux-k8s/kms-secrets.yaml` (org `lux`, envs mainnet/testnet/devnet,
path `/staking`, keys `staker-N.crt`, `staker-N.key`,
`signer-N.key.b64`). Server-side path note: values must be written with
`path: "staking"` (NO leading slash) — the store keys (path, name)
literally and the operator's NormaliseScopePath strips slashes, so a
value written under `/staking` is only reachable as `%2Fstaking` and the
operator will 404 on it.

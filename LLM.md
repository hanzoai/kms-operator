# LLM.md - Hanzo Kms Operator

## Overview
Go module: `github.com/hanzoai/kms-operator`.

Reconciles `KMSSecret` and `KMSPushSecret` CRDs (`secrets.lux.network/v1alpha1`)
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
  api/v1alpha1/              # KMSSecret + KMSPushSecret CRD types
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

## Releases

- `v0.1.0` (2026-03)  initial port to canonical /v1/kms/* surface.
- `v0.2.0` (2026-04)  hardening: control-byte filter, fail-closed on
                      empty fetch, token cache, same-ns credentialsRef.
- `v0.3.0` (2026-05)  ZAP transport alongside HTTP.

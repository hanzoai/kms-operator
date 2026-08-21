# syntax=docker/dockerfile:1

# Build the manager binary
FROM golang:1.26.5-alpine AS builder
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -g 65532 -S nonroot && adduser -u 65532 -S nonroot -G nonroot

WORKDIR /workspace

# Dependencies resolve from the module proxy. This used to copy a 74 MB vendor
# tree on the grounds that github.com/luxfi/kms was private and a build without
# it would need a PAT. That repository is public — proxy.golang.org serves it and
# an unauthenticated clone succeeds — so the tree bought nothing.
COPY go.mod go.mod
COPY go.sum go.sum
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY controllers/ controllers/
COPY packages/ packages/
# internal/bootstrap holds the kms-consensus-authority reconciler that
# main.go imports; without it the build fails "package … is not in std".
COPY internal/ internal/

# go.sum is the integrity check the tree stood in for: a module whose hash does
# not match is refused, whichever way it arrived.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -a -o manager main.go

# Scratch runtime — static binary + CA certs + tzdata + nonroot user.
FROM scratch
WORKDIR /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]

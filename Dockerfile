# syntax=docker/dockerfile:1

# Build the manager binary
FROM golang:1.26.4-alpine AS builder
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -g 65532 -S nonroot && adduser -u 65532 -S nonroot -G nonroot

WORKDIR /workspace

# Copy the Go Modules manifests + vendor tree. Vendoring is required
# because github.com/luxfi/kms is private — without vendor we'd need a
# GitHub PAT in the build context to authenticate `go mod download`.
COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/

# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY controllers/ controllers/
COPY packages/ packages/
COPY internal/ internal/

# Build off the vendored deps; -mod=vendor short-circuits the module
# resolver so no network calls are made during build.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -mod=vendor -a -o manager main.go

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

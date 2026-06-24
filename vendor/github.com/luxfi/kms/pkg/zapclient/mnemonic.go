// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// mnemonic.go — one canonical way for every Lux-derived service
// (luxd, netrunner, lux/cli, and any descending L1's bootstrap) to
// load a BIP-39 mnemonic.
//
// Precedence (highest first):
//
//   1. MNEMONIC env var — local dev + CI test seam. Validated as
//      BIP-39 before use.
//   2. Native ZAP from KMS at (addr, env, path). The path may
//      include a directory portion (e.g. "/staking/0/master"); the
//      split-on-last-slash convention mirrors the staking-key layout
//      callers already use.
//
// No file mount, no projected volume, no HTTP-bearer-token fallback.
// Three historical failure modes collapse into one ZAP read.
//
// Tests substitute the package-level dial function for a fake — same
// seam pattern callers use for their own ZAP wiring.

package zapclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	bip39 "github.com/luxfi/go-bip39"
)

// MnemonicReader is the minimum surface LoadMnemonicFromKMS needs.
// The real *Client satisfies it; tests substitute fakes.
type MnemonicReader interface {
	GetAt(ctx context.Context, path, name, env string) (string, error)
	Close()
}

// dialMnemonic is the production seam.
var dialMnemonic = func(ctx context.Context, addr string) (MnemonicReader, error) {
	c, err := Dial(ctx, addr, "")
	if err != nil {
		return nil, err
	}
	return c, nil
}

// LoadMnemonic returns the BIP-39 mnemonic from the canonical source.
// MNEMONIC env wins when set; otherwise dials KMS over native ZAP at
// `addr` and reads the secret at `path` under `env`.
//
//	addr  KMS host:port (e.g. "kms.hanzo.svc:9999")
//	env   KMS env scope ("mainnet" | "testnet" | "devnet")
//	path  KMS secret path (e.g. "/mnemonic" or "/foo/master")
//
// Caller is responsible for keeping the returned string on the
// goroutine stack and overwriting / dropping it once derivation is
// done. See the threat model in callers (network-bootstrap, luxd,
// etc.) for the full handling contract.
func LoadMnemonic(ctx context.Context, addr, env, path string) (string, error) {
	if e := strings.TrimSpace(os.Getenv("MNEMONIC")); e != "" {
		if !bip39.IsMnemonicValid(e) {
			return "", errors.New("MNEMONIC env is not a valid BIP-39 phrase")
		}
		return e, nil
	}
	return LoadMnemonicFromKMS(ctx, addr, env, path)
}

// LoadMnemonicFromKMS is the production-only path (skips the MNEMONIC
// env-var check). Useful when a caller wants to force the KMS read
// regardless of ambient env — e.g., a regression test pinning the
// production code path.
func LoadMnemonicFromKMS(ctx context.Context, addr, env, path string) (string, error) {
	if addr == "" {
		return "", errors.New("zapclient.LoadMnemonic: KMS addr is required")
	}
	if env == "" {
		return "", errors.New("zapclient.LoadMnemonic: KMS env is required")
	}
	if path == "" {
		return "", errors.New("zapclient.LoadMnemonic: KMS path is required")
	}

	c, err := dialMnemonic(ctx, addr)
	if err != nil {
		return "", fmt.Errorf("dial KMS %s: %w", addr, err)
	}
	defer c.Close()

	dir, name := SplitSecretPath(path)
	v, err := c.GetAt(ctx, dir, name, env)
	if err != nil {
		return "", fmt.Errorf("read mnemonic (path=%q name=%q env=%q): %w",
			dir, name, env, err)
	}
	m := strings.TrimSpace(v)
	if m == "" {
		return "", fmt.Errorf("mnemonic at %q is empty", path)
	}
	if !bip39.IsMnemonicValid(m) {
		return "", errors.New("mnemonic from KMS is not a valid BIP-39 phrase")
	}
	return m, nil
}

// SplitSecretPath turns "/foo/bar/baz" into ("/foo/bar/", "baz"). When
// there is no '/' or only a leading one, the directory is "" and the
// whole remainder is the name (e.g., "/mnemonic" → ("", "mnemonic")).
//
// Exported so other helpers in callers can address secrets with the
// same convention zapclient uses internally — one and only one
// addressing scheme across every secret class (mnemonic, staking
// keys, gas-payer keys, future relayer keys, …).
func SplitSecretPath(full string) (dir, name string) {
	full = strings.TrimSpace(full)
	full = strings.TrimPrefix(full, "/")
	i := strings.LastIndex(full, "/")
	if i < 0 {
		return "", full
	}
	return "/" + full[:i+1], full[i+1:]
}

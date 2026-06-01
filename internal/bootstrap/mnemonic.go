// Copyright (C) 2026, Hanzo Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// mnemonic.go — generate / load / persist the BIP-39 mnemonic Secrets
// that drive service identity. One Secret per service, key `mnemonic`,
// owned by the kms-operator (so deleting the operator namespace does
// not cascade-delete service identities — Secrets are deliberately not
// owner-referenced to the operator pod).
//
// Source order on load:
//
//  1. Existing Kubernetes Secret (data.mnemonic) — most common.
//  2. Optional fallback env (operator's own mnemonic only): KMS_OPERATOR_MNEMONIC.
//  3. Generate a fresh 24-word BIP-39 phrase (256 bits entropy) and
//     persist into the Secret.
//
// The mnemonic NEVER appears in operator logs. Only the source category
// ("secret", "env", or "generate") and the resulting NodeID surface.

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	bip39 "github.com/luxfi/go-bip39"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// MnemonicKey is the canonical Secret data key holding the BIP-39
// phrase. Single value, no template, no override — one and only one
// way to store a mnemonic in this operator's surface area.
const MnemonicKey = "mnemonic"

// EntropyBits is the BIP-39 entropy size for generated mnemonics.
// 256 bits → 24 words. Fixed; the operator does not expose a knob.
const EntropyBits = 256

// MnemonicSource identifies where the mnemonic came from. Useful for
// audit logs (without leaking the mnemonic itself).
type MnemonicSource string

const (
	// SourceSecret means the mnemonic was loaded from an existing
	// Kubernetes Secret.
	SourceSecret MnemonicSource = "secret"
	// SourceEnv means the mnemonic was sourced from the
	// KMS_OPERATOR_MNEMONIC env var (operator only).
	SourceEnv MnemonicSource = "env"
	// SourceGenerate means the operator generated a fresh BIP-39
	// phrase on first reconcile.
	SourceGenerate MnemonicSource = "generate"
)

// MnemonicRef points at a Kubernetes Secret holding a BIP-39 mnemonic.
type MnemonicRef struct {
	Namespace string
	Name      string
}

// LoadOrCreateMnemonic returns the mnemonic stored at the given ref,
// generating a fresh phrase and persisting it when the Secret does not
// exist. `envFallback` is the optional env-derived mnemonic used only
// when the Secret is missing AND a non-empty env value is provided
// (intended for the operator's own bootstrap; per-service callers pass
// an empty string).
//
// Returns (mnemonic, source, error). The caller MUST treat the
// mnemonic as sensitive and avoid logging it.
func LoadOrCreateMnemonic(
	ctx context.Context,
	c client.Client,
	ref MnemonicRef,
	envFallback string,
) (string, MnemonicSource, error) {

	var sec corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &sec)
	if err == nil {
		// Existing Secret. The mnemonic MUST live under data.mnemonic;
		// any other layout is a misconfigured cluster and we refuse to
		// silently invent one.
		raw, ok := sec.Data[MnemonicKey]
		if !ok || len(raw) == 0 {
			return "", "", fmt.Errorf("secret %s/%s exists but has no %q data key", ref.Namespace, ref.Name, MnemonicKey)
		}
		mnemonic := strings.TrimSpace(string(raw))
		if !bip39.IsMnemonicValid(mnemonic) {
			return "", "", fmt.Errorf("secret %s/%s holds an invalid BIP-39 mnemonic", ref.Namespace, ref.Name)
		}
		return mnemonic, SourceSecret, nil
	}
	if !k8serrors.IsNotFound(err) {
		return "", "", fmt.Errorf("get mnemonic secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}

	// Secret absent — fall back to env (operator only) or generate.
	var mnemonic string
	var src MnemonicSource
	if envFallback != "" {
		env := strings.TrimSpace(envFallback)
		if !bip39.IsMnemonicValid(env) {
			return "", "", errors.New("KMS_OPERATOR_MNEMONIC env is set but holds an invalid BIP-39 mnemonic")
		}
		mnemonic = env
		src = SourceEnv
	} else {
		ent, err := bip39.NewEntropy(EntropyBits)
		if err != nil {
			return "", "", fmt.Errorf("generate entropy: %w", err)
		}
		fresh, err := bip39.NewMnemonic(ent)
		if err != nil {
			return "", "", fmt.Errorf("generate mnemonic: %w", err)
		}
		mnemonic = fresh
		src = SourceGenerate
	}

	if err := persistMnemonic(ctx, c, ref, mnemonic, src); err != nil {
		return "", "", err
	}
	return mnemonic, src, nil
}

// persistMnemonic creates the mnemonic Secret. Annotates with the
// source category so operators can audit (without leaking the value).
func persistMnemonic(ctx context.Context, c client.Client, ref MnemonicRef, mnemonic string, src MnemonicSource) error {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ref.Namespace,
			Name:      ref.Name,
			Labels: map[string]string{
				"app.kubernetes.io/name":       ref.Name,
				"app.kubernetes.io/managed-by": "kms-operator",
				"app.kubernetes.io/component":  "service-mnemonic",
			},
			Annotations: map[string]string{
				"kms-operator.lux.network/mnemonic-source": string(src),
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{MnemonicKey: []byte(mnemonic)},
	}
	if err := c.Create(ctx, sec); err != nil {
		if k8serrors.IsAlreadyExists(err) {
			// Race: a peer operator pod created the Secret between
			// our Get and Create. Re-fetch and use whatever it holds.
			var existing corev1.Secret
			if gerr := c.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &existing); gerr != nil {
				return fmt.Errorf("race-recovery get mnemonic secret %s/%s: %w", ref.Namespace, ref.Name, gerr)
			}
			return nil
		}
		return fmt.Errorf("persist mnemonic secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	return nil
}

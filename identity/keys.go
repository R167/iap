package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
)

// KeySource returns the issuer's public key for a kid.
type KeySource interface {
	Key(ctx context.Context, kid string) (ed25519.PublicKey, error)
}

// ErrUnknownKey is returned for a kid the key source does not hold.
var ErrUnknownKey = errors.New("unknown key")

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	D   string `json:"d"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type keySet map[string]ed25519.PublicKey

// parseJWKS accepts only public Ed25519 signing keys, each with a distinct
// kid. Any other key fails the whole document rather than being skipped.
func parseJWKS(doc []byte) (keySet, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(doc, &set); err != nil {
		return nil, fmt.Errorf("JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("JWKS: no keys")
	}
	keys := keySet{}
	for _, k := range set.Keys {
		switch {
		case k.Kid == "":
			return nil, errors.New("JWKS: a key has no kid")
		case k.D != "":
			return nil, fmt.Errorf("JWKS: key %q is a private key", k.Kid)
		case k.Kty != "OKP" || k.Crv != "Ed25519":
			return nil, fmt.Errorf("JWKS: key %q: want kty OKP, crv Ed25519", k.Kid)
		case k.Alg != "" && k.Alg != "EdDSA":
			return nil, fmt.Errorf("JWKS: key %q: alg %q, want EdDSA", k.Kid, k.Alg)
		case k.Use != "" && k.Use != "sig":
			return nil, fmt.Errorf("JWKS: key %q: use %q, want sig", k.Kid, k.Use)
		case keys[k.Kid] != nil:
			return nil, fmt.Errorf("JWKS: kid %q appears twice", k.Kid)
		}
		x, err := base64.RawURLEncoding.Strict().DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("JWKS: key %q: x is not a base64url Ed25519 public key", k.Kid)
		}
		keys[k.Kid] = ed25519.PublicKey(x)
	}
	return keys, nil
}

func (s keySet) lookup(kid string) (ed25519.PublicKey, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownKey, kid)
}

// StaticJWKS is a key source fixed from a JWKS document, such as one pinned
// in configuration or built by a test. A key rotation means a new document.
func StaticJWKS(doc []byte) (KeySource, error) {
	keys, err := parseJWKS(doc)
	if err != nil {
		return nil, err
	}
	return staticSource(keys), nil
}

type staticSource keySet

func (s staticSource) Key(_ context.Context, kid string) (ed25519.PublicKey, error) {
	return keySet(s).lookup(kid)
}

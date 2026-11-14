package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"maps"
	"strings"
	"testing"
	"time"
)

const (
	testIssuer = "https://access.example.com"
	testHost   = "app.example.com"
)

var testNow = time.Date(2030, 1, 2, 12, 0, 0, 0, time.UTC)

type testKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

// newTestKey derives kid the way the issuer does: the first 16 hex of
// sha256(public key).
func newTestKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	return testKey{priv: priv, pub: pub, kid: hex.EncodeToString(sum[:])[:16]}
}

func (k testKey) jwk() map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64.EncodeToString(k.pub), "kid": k.kid, "alg": "EdDSA", "use": "sig"}
}

func jwks(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(b)
}

// signRaw signs payload under header with k.
func (k testKey) signRaw(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	in := mustJSON(t, header) + "." + mustJSON(t, payload)
	return in + "." + b64.EncodeToString(ed25519.Sign(k.priv, []byte(in)))
}

func (k testKey) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	return k.signRaw(t, map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": k.kid}, claims)
}

// idClaims are the claims the issuer mints for sub, a canonical principal.
func idClaims(sub string) map[string]any {
	kind, value, _ := strings.Cut(sub, ":")
	c := map[string]any{
		"iss":            testIssuer,
		"sub":            sub,
		"aud":            []string{"https://" + testHost},
		"iat":            testNow.Unix(),
		"exp":            testNow.Add(5 * time.Minute).Unix(),
		"jti":            "0123456789abcdef",
		"principal_type": kind,
	}
	switch kind {
	case KindUser:
		c["email"] = value
	case KindAgent:
		if segs := strings.Split(value, ":"); segs[0] == AgentUser && len(segs) > 1 {
			c["owner"] = "user:" + segs[1]
		}
	}
	return c
}

// with returns a copy of c with each key set, or deleted when its value is
// nil.
func with(c map[string]any, kv ...any) map[string]any {
	out := maps.Clone(c)
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(out, kv[i].(string))
		} else {
			out[kv[i].(string)] = kv[i+1]
		}
	}
	return out
}

func newTestVerifier(t *testing.T, k testKey) *Verifier {
	t.Helper()
	keys, err := StaticJWKS(jwks(t, k.jwk()))
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(keys, testIssuer, testHost)
	v.Now = func() time.Time { return testNow }
	return v
}

func TestVerify(t *testing.T) {
	k := newTestKey(t)
	v := newTestVerifier(t, k)
	ctx := context.Background()

	const agent = "agent:user:alice@example.com:laptop:cli:s1"
	for sub, want := range map[string]Identity{
		"user:alice@example.com":   {Principal: "user:alice@example.com", Kind: KindUser, Email: "alice@example.com"},
		"sa:build/runner":          {Principal: "sa:build/runner", Kind: KindSA},
		agent:                      {Principal: agent, Kind: KindAgent, AgentType: AgentUser, Owner: "user:alice@example.com"},
		"agent:k8s:prod:assistant": {Principal: "agent:k8s:prod:assistant", Kind: KindAgent, AgentType: AgentK8s},
	} {
		got, err := v.Verify(ctx, k.mint(t, idClaims(sub)))
		if err != nil || got != want {
			t.Errorf("%s: got %+v, %v; want %+v", sub, got, err, want)
		}
	}

	ok := map[string]map[string]any{
		"within leeway": with(idClaims("user:alice@example.com"), "exp", testNow.Add(-20*time.Second).Unix(), "iat", testNow.Add(20*time.Second).Unix()),
		"aud string":    with(idClaims("user:alice@example.com"), "aud", "https://"+testHost),
		"aud among":     with(idClaims("user:alice@example.com"), "aud", []string{"https://other.example.com", "https://" + testHost}),
		"fractional":    with(idClaims("user:alice@example.com"), "exp", float64(testNow.Unix())+0.5),
		"nbf in leeway": with(idClaims("user:alice@example.com"), "nbf", testNow.Add(20*time.Second).Unix()),
	}
	for name, c := range ok {
		if _, err := v.Verify(ctx, k.mint(t, c)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	user := idClaims("user:alice@example.com")
	payload := mustJSON(t, user)
	other := newTestKey(t)
	other.kid = k.kid // same kid, different key
	bad := map[string]string{
		"bad signature":     other.mint(t, user),
		"wrong aud":         k.mint(t, with(user, "aud", []string{"https://other.example.com"})),
		"no aud":            k.mint(t, with(user, "aud", nil)),
		"wrong iss":         k.mint(t, with(user, "iss", "https://evil.example.net")),
		"expired":           k.mint(t, with(user, "exp", testNow.Add(-31*time.Second).Unix())),
		"iat in the future": k.mint(t, with(user, "iat", testNow.Add(time.Minute).Unix())),
		"nbf in the future": k.mint(t, with(user, "nbf", testNow.Add(time.Minute).Unix())),
		"no exp":            k.mint(t, with(user, "exp", nil)),
		"no iat":            k.mint(t, with(user, "iat", nil)),
		"exp a string":      k.mint(t, with(user, "exp", "2099-01-01")),
		"huge iat":          k.mint(t, with(user, "iat", 1e300)),
		"huge exp":          k.mint(t, with(user, "exp", 1e300)),
		"huge nbf":          k.mint(t, with(user, "nbf", 1e19)),
		"negative iat":      k.mint(t, with(user, "iat", -1)),
		"unknown kid":       k.signRaw(t, map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": "ffffffffffffffff"}, user),
		"no kid":            k.signRaw(t, map[string]any{"alg": "EdDSA", "typ": "JWT"}, user),
		"wrong typ":         k.signRaw(t, map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": k.kid}, user),
		"crit":              k.signRaw(t, map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": k.kid, "crit": []string{"exp"}}, user),
		"alg none":          mustJSON(t, map[string]any{"alg": "none", "typ": "JWT", "kid": k.kid}) + "." + payload + ".",
		"alg HS256":         k.signRaw(t, map[string]any{"alg": "HS256", "typ": "JWT", "kid": k.kid}, user),
		"garbage":           "not.a.jwt",
		"two parts":         mustJSON(t, map[string]any{"alg": "EdDSA"}) + "." + payload,
		"padded":            k.mint(t, user) + "=",
		"pattern sub":       k.mint(t, with(idClaims("sa:build/runner"), "sub", "sa:build/*")),
		"user wildcard":     k.mint(t, with(user, "sub", "user:*@example.com")),
		"non-canonical sub": k.mint(t, with(user, "sub", "user:Alice@example.com")),
		"uppercase sub":     k.mint(t, idClaims("user:Alice@example.com")),
		"invalid email":     k.mint(t, idClaims("user:alice")),
		"type mismatch":     k.mint(t, with(idClaims("sa:build/runner"), "principal_type", "user")),
		"user as agent":     k.mint(t, with(user, "principal_type", "agent")),
		"email mismatch":    k.mint(t, with(user, "email", "bob@example.com")),
		"email case":        k.mint(t, with(user, "email", "Alice@example.com")),
		"user no email":     k.mint(t, with(user, "email", nil)),
		"sa with an email":  k.mint(t, with(idClaims("sa:build/runner"), "email", "alice@example.com")),
		"user with owner":   k.mint(t, with(user, "owner", "user:alice@example.com")),
		"bad sa":            k.mint(t, idClaims("sa:no-slash")),
		"agent owner lies":  k.mint(t, with(idClaims(agent), "owner", "user:bob@example.com")),
		"agent no owner":    k.mint(t, with(idClaims(agent), "owner", nil)),
		"k8s with an owner": k.mint(t, with(idClaims("agent:k8s:prod:assistant"), "owner", "user:alice@example.com")),
		"short agent":       k.mint(t, idClaims("agent:user:alice@example.com:laptop:cli")),
		"long agent":        k.mint(t, idClaims("agent:user:alice@example.com:laptop:cli:s1:x")),
		"bad agent segment": k.mint(t, idClaims("agent:user:alice@example.com:laptop:-cli:s1")),
		"empty agent seg":   k.mint(t, idClaims("agent:user:alice@example.com:laptop::s1")),
		"agent pattern":     k.mint(t, idClaims("agent:user:alice@example.com:*")),
		"untyped agent":     k.mint(t, idClaims("agent:alice@example.com:laptop:cli:s1")),
		"agent:test":        k.mint(t, idClaims("agent:test:this-is-a-test")),
		"unknown agent":     k.mint(t, idClaims("agent:foo:prod:assistant")),
		"group":             k.mint(t, idClaims("group:admins")),
		"gh":                k.mint(t, idClaims("gh:org/team")),
		"unknown kind":      k.mint(t, idClaims("x:y")),
		"no kind":           k.mint(t, with(user, "sub", "alice@example.com")),
	}
	// A payload with a member twice, which encoding/json/v2 refuses.
	dup := `{"iss":"` + testIssuer + `","sub":"user:alice@example.com","sub":"user:bob@example.com"}`
	in := mustJSON(t, map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": k.kid}) + "." + b64.EncodeToString([]byte(dup))
	bad["duplicate claim"] = in + "." + b64.EncodeToString(ed25519.Sign(k.priv, []byte(in)))

	for name, raw := range bad {
		t.Run(name, func(t *testing.T) {
			if id, err := v.Verify(ctx, raw); err == nil {
				t.Fatalf("accepted as %+v", id)
			}
		})
	}
}

func TestStaticJWKS(t *testing.T) {
	k := newTestKey(t)
	if _, err := StaticJWKS(jwks(t, k.jwk(), newTestKey(t).jwk())); err != nil {
		t.Errorf("two keys: %v", err)
	}
	priv := with(k.jwk(), "d", b64.EncodeToString(k.priv.Seed()))
	for name, doc := range map[string][]byte{
		"garbage":     []byte("{"),
		"empty":       []byte(`{"keys":[]}`),
		"no keys":     []byte(`{}`),
		"no kid":      jwks(t, with(k.jwk(), "kid", nil)),
		"private key": jwks(t, priv),
		"wrong alg":   jwks(t, with(k.jwk(), "alg", "RS256")),
		"wrong kty":   jwks(t, with(k.jwk(), "kty", "RSA")),
		"wrong crv":   jwks(t, with(k.jwk(), "crv", "X25519")),
		"enc key":     jwks(t, with(k.jwk(), "use", "enc")),
		"short x":     jwks(t, with(k.jwk(), "x", b64.EncodeToString(k.pub[:31]))),
		"bad x":       jwks(t, with(k.jwk(), "x", "!!!")),
		"kid twice":   jwks(t, k.jwk(), with(newTestKey(t).jwk(), "kid", k.kid)),
	} {
		if _, err := StaticJWKS(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParsePrincipal(t *testing.T) {
	for _, s := range []string{"user:alice@example.com", "sa:ns/name.with.dots", "agent:user:alice@example.com:m:p:s", "agent:k8s:prod:assistant"} {
		if _, err := ParsePrincipal(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"", "user", "user:", ":x", "User:alice@example.com", "user:a b@example.com", "sa:ns/", "sa:/name", "agent:k8s:prod", "agent:test:x"} {
		if id, err := ParsePrincipal(s); err == nil {
			t.Errorf("%q: accepted as %+v", s, id)
		}
	}
}

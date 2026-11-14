package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// Header is the request header that carries the identity JWT.
const Header = "X-IAP-Identity"

// Leeway is the clock skew allowed on exp, iat and nbf.
const Leeway = 30 * time.Second

// Verifier checks identity tokens issued by Issuer for one host.
type Verifier struct {
	keys   KeySource
	issuer string
	host   string

	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// NewVerifier returns a Verifier for tokens Issuer (the iss claim, e.g.
// https://access.example.com) minted for host (aud https://<host>).
func NewVerifier(keys KeySource, issuer, host string) *Verifier {
	return &Verifier{keys: keys, issuer: issuer, host: host}
}

// Host is the host tokens are verified for.
func (v *Verifier) Host() string { return v.host }

type header struct {
	Alg  string   `json:"alg"`
	Typ  string   `json:"typ"`
	Kid  string   `json:"kid"`
	Crit []string `json:"crit"`
}

type claims struct {
	Iss           string         `json:"iss"`
	Sub           string         `json:"sub"`
	Aud           jsontext.Value `json:"aud"`
	Exp           *float64       `json:"exp"`
	Iat           *float64       `json:"iat"`
	Nbf           *float64       `json:"nbf"`
	PrincipalType string         `json:"principal_type"`
	Email         string         `json:"email"`
	Owner         string         `json:"owner"`
}

var b64 = base64.RawURLEncoding.Strict()

// Verify checks raw, the X-IAP-Identity header's value, and returns its
// principal. Anything short of a fully valid token for this host is an
// error.
//
// The audience check is what keeps a backend, which receives its visitors'
// genuine tokens for its own host, from replaying one to another host.
func (v *Verifier) Verify(ctx context.Context, raw string) (Identity, error) {
	id, err := v.verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("identity: %w", err)
	}
	return id, nil
}

func (v *Verifier) verify(ctx context.Context, raw string) (Identity, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Identity{}, errors.New("not a compact JWS")
	}
	hb, err1 := b64.DecodeString(parts[0])
	pb, err2 := b64.DecodeString(parts[1])
	sig, err3 := b64.DecodeString(parts[2])
	if err := errors.Join(err1, err2, err3); err != nil {
		return Identity{}, fmt.Errorf("not a compact JWS: %w", err)
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Identity{}, fmt.Errorf("header: %w", err)
	}
	switch {
	case h.Alg != "EdDSA":
		return Identity{}, fmt.Errorf("alg %q, want EdDSA", h.Alg)
	case h.Typ != "JWT":
		return Identity{}, fmt.Errorf("typ %q, want JWT", h.Typ)
	case h.Kid == "":
		return Identity{}, errors.New("no kid")
	case h.Crit != nil:
		return Identity{}, errors.New("crit header is not supported")
	}
	key, err := v.keys.Key(ctx, h.Kid)
	if err != nil {
		return Identity{}, err
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return Identity{}, errors.New("bad signature")
	}

	var c claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return Identity{}, fmt.Errorf("claims: %w", err)
	}
	if c.Iss != v.issuer {
		return Identity{}, fmt.Errorf("iss %q, want %q", c.Iss, v.issuer)
	}
	if !audienceHas(c.Aud, "https://"+v.host) {
		return Identity{}, fmt.Errorf("aud does not name https://%s", v.host)
	}
	if c.Exp == nil || c.Iat == nil {
		return Identity{}, errors.New("missing exp or iat")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	exp, ok1 := numericDate(c.Exp)
	iat, ok2 := numericDate(c.Iat)
	nbf, ok3 := numericDate(c.Nbf)
	switch {
	case !ok1 || !ok2 || !ok3:
		return Identity{}, errors.New("exp, iat or nbf out of range")
	case now.Add(-Leeway).After(exp):
		return Identity{}, errors.New("expired")
	case now.Add(Leeway).Before(iat):
		return Identity{}, errors.New("issued in the future")
	case c.Nbf != nil && now.Add(Leeway).Before(nbf):
		return Identity{}, errors.New("not valid yet")
	}

	id, err := ParsePrincipal(c.Sub)
	if err != nil {
		return Identity{}, fmt.Errorf("sub: %w", err)
	}
	if c.PrincipalType != id.Kind {
		return Identity{}, errors.New("principal_type does not match sub")
	}
	if c.Email != id.Email {
		return Identity{}, errors.New("email does not match sub")
	}
	if c.Owner != id.Owner {
		return Identity{}, errors.New("owner does not match sub")
	}
	return id, nil
}

// audienceHas reports whether aud, a string or an array of strings, holds
// want.
func audienceHas(aud jsontext.Value, want string) bool {
	var one string
	if json.Unmarshal(aud, &one) == nil {
		return one == want
	}
	var many []string
	return json.Unmarshal(aud, &many) == nil && slices.Contains(many, want)
}

// maxNumericDate is far beyond any real token (about the year 5138) and far
// below where a float64 to int64 conversion stops being exact on every
// platform.
const maxNumericDate = 1e11

// numericDate converts a JWT NumericDate, refusing a negative, non-finite or
// absurdly large one. A nil date converts to the zero time.
func numericDate(f *float64) (time.Time, bool) {
	if f == nil {
		return time.Time{}, true
	}
	if math.IsNaN(*f) || *f < 0 || *f > maxNumericDate {
		return time.Time{}, false
	}
	sec, frac := math.Modf(*f)
	return time.Unix(int64(sec), int64(frac*1e9)), true
}

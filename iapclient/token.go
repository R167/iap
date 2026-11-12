package iapclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// minRemaining: a cached access token is reused only while more than this
// is left of it.
const minRemaining = time.Minute

// TokenSource mints access tokens for one session of the saved registration
// (principal agent:user:<email>:<machine>:<program>:<session>), one per exact
// host, and caches each in memory until shortly before it expires. No access
// token is ever written to disk. Safe for concurrent use; mints are
// serialised, across processes too (refreshGrant).
type TokenSource struct {
	c       *Client
	session string

	mu    sync.Mutex
	cache map[string]Token
}

// TokenSource returns a source for session, which must match SegmentPattern.
func (c *Client) TokenSource(session string) (*TokenSource, error) {
	if !ValidSegment(session) {
		return nil, fmt.Errorf("session %q must match %s", session, SegmentPattern)
	}
	if _, err := c.account(); err != nil {
		return nil, err
	}
	return &TokenSource{c: c, session: session, cache: map[string]Token{}}, nil
}

// Token returns an access token for exactly host (lowercase, no port), from
// the cache or freshly minted. A host outside AllowedSuffixes is refused
// before anything is sent.
func (ts *TokenSource) Token(ctx context.Context, host string) (Token, error) {
	host = strings.ToLower(host)
	if sfx := ts.c.AllowedSuffixes(); !hostAllowed(host, sfx) {
		return Token{}, &HostNotAllowedError{URL: "https://" + host, Suffixes: sfx, https: true}
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	now := ts.c.cfg.Now()
	if t, ok := ts.cache[host]; ok && now.Add(minRemaining).Before(t.Expiry) {
		return t, nil
	}
	delete(ts.cache, host)
	account, err := ts.c.account()
	if err != nil {
		return Token{}, err
	}
	tr, err := ts.refreshGrant(ctx, account, host)
	if err != nil {
		return Token{}, err
	}
	if tr.AccessToken == "" || strings.ContainsAny(tr.AccessToken, "\r\n \t") {
		return Token{}, errors.New("token endpoint returned no usable access token")
	}
	t := Token{Value: NewSecret(tr.AccessToken), Host: host, Principal: tr.Principal}
	if tr.ExpiresIn > 0 {
		t.Expiry = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
		ts.cache[host] = t
	}
	return t, nil
}

// FederatedToken returns a federated token for exactly audience: a relying
// party outside the issuer's domain that fixes its own audience string (for
// Tailscale, api.tailscale.com/<client id>). The issuer mints one only when
// its policy lists that audience for this agent, and the token is never a
// credential at the issuer's own hosts. It is the caller's to hand to that
// relying party's own exchange, never to send as Proxy-Authorization. Not
// cached: each call mints.
func (ts *TokenSource) FederatedToken(ctx context.Context, audience string) (Token, error) {
	if audience == "" || strings.ContainsAny(audience, "\r\n \t?#@") {
		return Token{}, fmt.Errorf("audience %q: want [https://]<host>[/<path>]", audience)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	now := ts.c.cfg.Now()
	account, err := ts.c.account()
	if err != nil {
		return Token{}, err
	}
	tr, err := ts.refreshGrant(ctx, account, audience)
	if err != nil {
		return Token{}, err
	}
	if tr.AccessToken == "" || strings.ContainsAny(tr.AccessToken, "\r\n \t") {
		return Token{}, errors.New("token endpoint returned no usable token")
	}
	t := Token{Value: NewSecret(tr.AccessToken), Principal: tr.Principal}
	if tr.ExpiresIn > 0 {
		t.Expiry = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return t, nil
}

// refreshGrant posts a refresh_token grant for audience with the stored
// credential, holding the registration's lock (Client.lockRegistration) from
// reading the credential until any rotated one is saved. Processes sharing a
// registration take turns: each reads the credential the last one saved, and
// none presents one another has rotated away. The credential is read from
// the store every time, never cached, for the same reason.
//
// The request asks for rotation (rotate=1). When the answer carries a new
// refresh credential (on a 200 or a 403), it is saved to the store before
// anything else; if saving fails, the answer is not used. The issuer keeps
// the old credential good until the new one is first presented, so a crash
// or a failed save in between loses nothing: the next grant rotates again.
func (ts *TokenSource) refreshGrant(ctx context.Context, account, audience string) (tokenResponse, error) {
	unlock, err := ts.c.lockRegistration(ctx, account)
	if err != nil {
		return tokenResponse{}, err
	}
	defer unlock()
	refresh, err := ts.c.cfg.Store.Load(ctx, account)
	if err != nil {
		return tokenResponse{}, err
	}
	tr, err := ts.c.tokenRequest(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh.Reveal()},
		"session":       {ts.session},
		"audience":      {audience},
		"rotate":        {"1"},
	})
	if tr.RefreshToken != "" {
		if serr := ts.c.saveRotated(ctx, account, tr); serr != nil {
			return tokenResponse{}, serr
		}
	}
	return tr, err
}

// saveRotated stores the rotated refresh credential in tr, then records the
// registration's new expiry in the state file. Only the credential matters:
// a state file that can't be written leaves a stale expiry in `status`.
func (c *Client) saveRotated(ctx context.Context, account string, tr tokenResponse) error {
	if !strings.HasPrefix(tr.RefreshToken, "iapr_") || strings.ContainsAny(tr.RefreshToken, "\r\n \t") {
		return errors.New("the issuer rotated the refresh credential but sent an unusable one; the stored one still works for now")
	}
	if err := c.cfg.Store.Save(ctx, account, NewSecret(tr.RefreshToken)); err != nil {
		return fmt.Errorf("the issuer rotated the refresh credential, but the %s store refused the new one (the stored one still works for now): %w", c.cfg.Store.Name(), err)
	}
	if exp, err := time.Parse(time.RFC3339, tr.RegistrationExpiresAt); err == nil {
		_ = updateStateExpiry(c.cfg.Dir, programOf(account), account, exp)
	}
	return nil
}

// Transport is an http.RoundTripper that adds `Proxy-Authorization: Bearer
// <token>` to a request only when it is https to a host under the client's
// AllowedSuffixes, with a token minted for exactly that host. It removes any
// Proxy-Authorization the caller set, so no other credential rides along,
// and it adds none on a redirect hop whose host differs from the first
// request's (an issuer-protected host cannot send the client's credential
// elsewhere, even to another allowed host). Other requests pass through
// without the header.
type Transport struct {
	Source *TokenSource
	// Base carries the request; nil means http.DefaultTransport.
	Base http.RoundTripper
}

func (t *Transport) base() http.RoundTripper {
	if t.Base == nil {
		return http.DefaultTransport
	}
	return t.Base
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Header.Del("Proxy-Authorization")
	host, ok := requestHost(req.URL, t.Source.c.AllowedSuffixes())
	if ok && !crossHostRedirect(req) {
		tok, err := t.Source.Token(req.Context(), host)
		if err != nil {
			if req.Body != nil {
				req.Body.Close()
			}
			return nil, err
		}
		out.Header.Set("Proxy-Authorization", "Bearer "+tok.Value.Reveal())
	}
	return t.base().RoundTrip(out)
}

// crossHostRedirect reports whether req is a redirect hop to a host other
// than the one the chain started at.
func crossHostRedirect(req *http.Request) bool {
	first := req
	for first.Response != nil && first.Response.Request != nil {
		first = first.Response.Request
	}
	return first != req && !strings.EqualFold(first.URL.Hostname(), req.URL.Hostname())
}

// HTTPClient returns an *http.Client for session whose Transport adds the
// credential (see Transport) over http.DefaultTransport.
func (c *Client) HTTPClient(session string) (*http.Client, error) {
	ts, err := c.TokenSource(session)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: &Transport{Source: ts}}, nil
}

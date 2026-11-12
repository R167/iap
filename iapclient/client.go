package iapclient

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/R167/iap/internal/jsoncompat"
)

// Config configures a Client.
type Config struct {
	// Issuer is the token issuer, https://<host> with nothing after it.
	// Required; no default is built in.
	Issuer string
	// Dir holds the non-secret state file (StatePath). Default:
	// os.UserConfigDir()/iap.
	Dir string
	// Store keeps the refresh credential. Required (see OpenStore).
	Store Store
	// Program is the program segment whose registration the client uses, and
	// the one Login registers by default ("cli" if empty). Each program has
	// its own registration and stored credential (StateFile).
	Program string
	// HTTPClient talks to the issuer. Default: 30s timeout, no redirects.
	HTTPClient *http.Client
	// Now is the clock; default time.Now.
	Now func() time.Time
	// LegacyIssuer is the issuer a saved state without an issuer field
	// belongs to (written before the field existed: the tool's built-in
	// default). Empty: such a state belongs to no issuer, and its credential
	// is never sent anywhere.
	LegacyIssuer string
}

var (
	// ErrNotLoggedIn: no registration is saved.
	ErrNotLoggedIn = errors.New("not logged in")
	// ErrInvalidGrant: the issuer refused the refresh credential or login code.
	ErrInvalidGrant = errors.New("invalid_grant: the registration was revoked or expired, or the code was used")
	// ErrRefreshReused: the issuer saw a refresh credential it had already
	// rotated away presented after its grace window (a copy of the credential
	// in use somewhere else) and revoked the registration. It wraps
	// ErrInvalidGrant.
	ErrRefreshReused = fmt.Errorf("%w (here: a refresh credential already rotated away was presented again, so the issuer revoked the registration; log in again, and if no other copy of this machine's credential should exist, treat it as leaked)", ErrInvalidGrant)
)

// IssuerMismatchError: the saved registration belongs to another issuer, so
// its refresh credential is not sent to this one.
type IssuerMismatchError struct{ Saved, Configured string }

func (e *IssuerMismatchError) Error() string {
	return fmt.Sprintf("the saved registration belongs to %s, not %s: log in against %s first", e.Saved, e.Configured, e.Configured)
}

// HostNotAllowedError: the URL is not https, or its host is not under a
// domain the issuer mints for.
type HostNotAllowedError struct {
	URL      string
	Suffixes []string
	https    bool
}

func (e *HostNotAllowedError) Error() string {
	if !e.https {
		return fmt.Sprintf("%q: want an https:// URL", e.URL)
	}
	return fmt.Sprintf("%q: the host must be under %s", e.URL, displaySuffixes(e.Suffixes))
}

// ForbiddenError: the issuer will not mint for this principal on this host,
// because no grant covers it. Ask the issuer's admin for one. For a federated
// audience (Audience set, Host empty), the issuer's policy entry for that
// audience does not list the agent, or its owner may not reach the entry's
// host.
type ForbiddenError struct{ Principal, Host, Audience, Issuer string }

func (e *ForbiddenError) Error() string {
	if e.Audience != "" {
		return fmt.Sprintf("%s may not get a token for audience %s: the issuer's entry for it must list %s, and its owner must reach that host", e.Principal, e.Audience, PatternOf(e.Principal))
	}
	return fmt.Sprintf("%s may not reach %s: grant it (or %s) on %s/", e.Principal, e.Host, PatternOf(e.Principal), e.Issuer)
}

// PatternOf maps agent:user:<e>:<m>:<p>:<s> to its registration pattern
// agent:user:<e>:<m>:<p>:*.
func PatternOf(principal string) string {
	if i := strings.LastIndex(principal, ":"); i > 0 {
		return principal[:i] + ":*"
	}
	return principal
}

// Client mints host-bound access tokens from a saved registration.
type Client struct {
	cfg   Config
	state State
}

// New validates cfg and loads the saved state. Being logged out is not an
// error here; it is reported when a credential is needed.
func New(cfg Config) (*Client, error) {
	iss, err := ParseIssuer(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	cfg.Issuer = iss
	if cfg.Store == nil {
		return nil, errors.New("iapclient: Config.Store is required (see OpenStore)")
	}
	if cfg.Dir == "" {
		if cfg.Dir, err = DefaultDir(); err != nil {
			return nil, err
		}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	// Never follow a redirect from the issuer: the form carries a credential.
	hc := *cfg.HTTPClient
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.HTTPClient = &hc
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Program == "" {
		cfg.Program = "cli"
	}
	if !ValidSegment(cfg.Program) {
		return nil, fmt.Errorf("program %q must match %s", cfg.Program, SegmentPattern)
	}
	st, err := LoadState(cfg.Dir, cfg.Program)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, state: st}, nil
}

// Issuer is the configured issuer, normalised.
func (c *Client) Issuer() string { return c.cfg.Issuer }

// Program is the program segment whose registration the client uses (after
// a Login, the one it registered).
func (c *Client) Program() string { return c.cfg.Program }

// Store is the configured store.
func (c *Client) Store() Store { return c.cfg.Store }

// State is the saved registration.
func (c *Client) State() State { return c.state }

// AllowedSuffixes are the domains tokens may be minted for and sent to: the
// issuer's own domain, plus those it advertised at login (when the saved
// registration is this issuer's). An advertised suffix that contains the
// issuer's domain (".example.com" for ".iap.example.com") would widen it to hosts
// the issuer never vouched for, and one under it adds nothing, so both are
// dropped.
func (c *Client) AllowedSuffixes() []string {
	own := issuerDomain(c.cfg.Issuer)
	out := []string{own}
	if c.registrationIssuer() == c.cfg.Issuer {
		for _, s := range c.state.AudienceSuffixes {
			n := normalizeSuffix(s)
			if n == "" || strings.HasSuffix(own, n) || strings.HasSuffix(n, own) || slices.Contains(out, n) {
				continue
			}
			out = append(out, n)
		}
	}
	return out
}

// CheckURL validates raw (https, no userinfo, a plain host under
// AllowedSuffixes) and returns its lowercase host.
func (c *Client) CheckURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	sfx := c.AllowedSuffixes()
	if err != nil || u.Scheme != "https" || u.User != nil {
		return "", &HostNotAllowedError{URL: raw, Suffixes: sfx}
	}
	host, ok := requestHost(u, sfx)
	if !ok {
		return "", &HostNotAllowedError{URL: raw, Suffixes: sfx, https: true}
	}
	return host, nil
}

// registrationIssuer is the saved registration's issuer. A registration
// saved without one predates the field and belongs to Config.LegacyIssuer
// only, never to whatever issuer is configured now: a credential goes only to
// the issuer it came from.
func (c *Client) registrationIssuer() string {
	if c.state.Issuer == "" {
		if iss, err := ParseIssuer(c.cfg.LegacyIssuer); err == nil {
			return iss
		}
		return "(unknown issuer: the saved state names none)"
	}
	if iss, err := ParseIssuer(c.state.Issuer); err == nil {
		return iss
	}
	return c.state.Issuer
}

// account returns the saved registration's account, or why there is none
// usable with this issuer.
func (c *Client) account() (string, error) {
	if c.state.Account == "" {
		return "", ErrNotLoggedIn
	}
	if iss := c.registrationIssuer(); iss != c.cfg.Issuer {
		return "", &IssuerMismatchError{Saved: iss, Configured: c.cfg.Issuer}
	}
	return c.state.Account, nil
}

// lockRegistration takes the lock that serialises everything reading or
// writing account's stored credential, in this process and every other one
// using this Dir: Dir/locks/<program>.lock (flock; a no-op where there is
// none). Held from reading the credential to saving its replacement.
func (c *Client) lockRegistration(ctx context.Context, account string) (func(), error) {
	return lockFile(ctx, filepath.Join(c.cfg.Dir, "locks", programOf(account)+".lock"))
}

// maxLockWait bounds how long a process waits for another to finish with a
// registration's credential (one token request, at most the HTTP client's
// timeout, plus a store write).
const maxLockWait = 2 * time.Minute

// --- token endpoint ---

// tokenResponse is POST /api/agent/token's JSON (either grant).
type tokenResponse struct {
	RefreshToken     string   `json:"refresh_token"`
	AccessToken      string   `json:"access_token"`
	ExpiresIn        int      `json:"expires_in"`
	ExpiresAt        string   `json:"expires_at"`
	Principal        string   `json:"principal"`
	Host             string   `json:"host"`
	Audience         string   `json:"audience"`
	AudienceSuffixes []string `json:"external_audience_suffixes"`
	// RegistrationExpiresAt: with a rotated RefreshToken, the registration's
	// new expiry.
	RegistrationExpiresAt string `json:"registration_expires_at"`
	Error                 string `json:"error"`
	Reason                string `json:"reason"`
	Description           string `json:"error_description"`
}

// tokenRequest posts a form to the token endpoint. Errors carry the issuer's
// error code, never a credential or the response body. On an error answer the
// parsed body is returned too: a 403 can carry a rotated refresh credential,
// which the caller must still save.
func (c *Client) tokenRequest(ctx context.Context, form url.Values) (tokenResponse, error) {
	var tr tokenResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Issuer+"/api/agent/token", strings.NewReader(form.Encode()))
	if err != nil {
		return tr, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return tr, &transientError{err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return tr, &transientError{err}
	}
	transient := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	// jsoncompat.Read: the issuer is a v1 encoder; decode what v1 decoded.
	if err := json.Unmarshal(body, &tr, jsoncompat.Read); err != nil {
		err := fmt.Errorf("token endpoint: HTTP %d, not JSON (is %s reachable?)", resp.StatusCode, c.cfg.Issuer)
		if transient {
			return tokenResponse{}, &transientError{err}
		}
		return tokenResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		if transient && tr.Error != "invalid_grant" {
			return tokenResponse{}, &transientError{fmt.Errorf("token endpoint: HTTP %d %s", resp.StatusCode, safeText(tr.Error))}
		}
		switch {
		case tr.Error == "forbidden":
			return tokenResponse{RefreshToken: tr.RefreshToken, RegistrationExpiresAt: tr.RegistrationExpiresAt},
				&ForbiddenError{Principal: tr.Principal, Host: tr.Host, Audience: tr.Audience, Issuer: c.cfg.Issuer}
		case tr.Error == "invalid_grant" && tr.Reason == "reused":
			return tokenResponse{}, ErrRefreshReused
		case tr.Error == "invalid_grant":
			return tokenResponse{}, ErrInvalidGrant
		case tr.Error != "":
			return tokenResponse{}, fmt.Errorf("token endpoint: HTTP %d %s %s", resp.StatusCode, safeText(tr.Error), safeText(tr.Description))
		default:
			return tokenResponse{}, fmt.Errorf("token endpoint: HTTP %d", resp.StatusCode)
		}
	}
	return tr, nil
}

// transientError: the token endpoint could not be reached, or answered 429
// or 5xx. The request may be retried.
type transientError struct{ err error }

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

// safeText keeps an issuer-supplied error string printable and short.
func safeText(s string) string {
	b := []byte(s)
	if len(b) > 200 {
		b = b[:200]
	}
	for i, ch := range b {
		if ch < 0x20 || ch > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}

// --- status / logout ---

// Status describes the registration without any secret.
type Status struct {
	Issuer           string
	Account          string // "" when logged out
	ExpiresAt        time.Time
	Expired          bool
	AudienceSuffixes []string
	Store            string // store name
	Location         string // where the credential lives in that store
	Present          bool   // the store holds a credential for Account
	StoreErr         error  // the store could not be asked
	Mismatch         error  // *IssuerMismatchError when the registration is another issuer's
}

// Status reports the registration and whether its credential is stored,
// without reading it into the output.
func (c *Client) Status(ctx context.Context) Status {
	s := Status{
		Issuer:           c.registrationIssuer(),
		Account:          c.state.Account,
		ExpiresAt:        c.state.ExpiresAt,
		AudienceSuffixes: c.AllowedSuffixes()[1:],
		Store:            c.cfg.Store.Name(),
	}
	if s.Account == "" {
		return s
	}
	if _, err := c.account(); err != nil {
		s.Mismatch = err
	}
	s.Expired = c.cfg.Now().After(s.ExpiresAt)
	s.Location = c.cfg.Store.Location(s.Account)
	s.Present, s.StoreErr = c.cfg.Store.Exists(ctx, s.Account)
	return s
}

// Logout deletes the stored credential and forgets the registration. The
// registration itself stays valid at the issuer until revoked there.
func (c *Client) Logout(ctx context.Context) (account string, err error) {
	account = c.state.Account
	if account == "" {
		return "", ErrNotLoggedIn
	}
	unlock, err := c.lockRegistration(ctx, account)
	if err != nil {
		return account, err
	}
	defer unlock()
	if ok, _ := c.cfg.Store.Exists(ctx, account); ok {
		if err := c.cfg.Store.Delete(ctx, account); err != nil {
			return account, err
		}
	}
	// The issuer and store stay as the program's defaults for its next login.
	c.state.Account, c.state.ExpiresAt = "", time.Time{}
	return account, SaveState(c.cfg.Dir, c.cfg.Program, c.state)
}

package iapclient

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testIssuer  = "https://access.example.test"
	testRefresh = "iapr_refresh-SECRET-value"
	testAccount = "agent:user:alice@example.com:box:cli"
)

// memStore is an in-memory Store.
type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (*memStore) Name() string             { return "mem" }
func (*memStore) Location(a string) string { return "mem/" + a }
func (s *memStore) Save(_ context.Context, a string, c Secret) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[a] = c.Reveal()
	return nil
}
func (s *memStore) Load(_ context.Context, a string) (Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[a]
	if !ok {
		return Secret{}, ErrNoCredential
	}
	return NewSecret(v), nil
}
func (s *memStore) Exists(_ context.Context, a string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[a]
	return ok, nil
}
func (s *memStore) Delete(_ context.Context, a string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, a)
	return nil
}

// handlerTransport serves every request from h in-process, recording them.
type handlerTransport struct {
	h    http.Handler
	mu   sync.Mutex
	reqs []*http.Request
}

func (t *handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.reqs = append(t.reqs, r)
	t.mu.Unlock()
	w := httptest.NewRecorder()
	t.h.ServeHTTP(w, r)
	resp := w.Result()
	resp.Request = r
	return resp, nil
}

// fakeIssuer answers POST /api/agent/token like iap-authz: refresh grants mint
// "at-<host>-<n>"; hosts in forbidden get 403; anything else under
// .example.test or advertised is fine.
type fakeIssuer struct {
	mu        sync.Mutex
	mints     map[string]int
	forbidden map[string]bool
	suffixes  []string
	expiresIn int
	invalid   bool
}

func (f *fakeIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/api/agent/token" || r.Host != "access.example.test" {
		http.Error(w, "nope", http.StatusNotFound)
		return
	}
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		if r.PostFormValue("code") != "the-code" || r.PostFormValue("code_verifier") == "" {
			w.WriteHeader(400)
			_ = json.MarshalWrite(w, map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.MarshalWrite(w, map[string]any{
			"refresh_token": testRefresh, "principal": testAccount + ":*",
			"expires_at": "2030-01-02T03:04:05Z", "external_audience_suffixes": f.suffixes,
		})
	case "refresh_token":
		host, session := r.PostFormValue("audience"), r.PostFormValue("session")
		if f.invalid || r.PostFormValue("refresh_token") != testRefresh {
			w.WriteHeader(400)
			_ = json.MarshalWrite(w, map[string]string{"error": "invalid_grant"})
			return
		}
		p := testAccount + ":" + session
		if f.forbidden[host] {
			w.WriteHeader(403)
			key := "host"
			if strings.Contains(host, "/") {
				key = "audience" // a federated audience entry, as iap-authz names it
			}
			_ = json.MarshalWrite(w, map[string]string{"error": "forbidden", "principal": p, key: host})
			return
		}
		if f.mints == nil {
			f.mints = map[string]int{}
		}
		f.mints[host]++
		_ = json.MarshalWrite(w, map[string]any{
			"access_token": fmt.Sprintf("at-%s-%d", host, f.mints[host]), "token_type": "Bearer",
			"expires_in": f.expiresIn, "principal": p,
		})
	}
}

func (f *fakeIssuer) count(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mints[host]
}

// loggedIn returns a client logged in to testIssuer with the refresh
// credential in a memStore, talking to f.
func loggedIn(t *testing.T, f *fakeIssuer, st State) (*Client, *memStore, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	if st.Account == "" {
		st.Account = testAccount
	}
	if st.Issuer == "" {
		st.Issuer = testIssuer
	}
	if err := SaveState(dir, "cli", st); err != nil {
		t.Fatal(err)
	}
	store := &memStore{m: map[string]string{testAccount: testRefresh}}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	c, err := New(Config{
		Issuer: testIssuer, Dir: dir, Store: store,
		HTTPClient: &http.Client{Transport: &handlerTransport{h: f}},
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, store, &now
}

func TestSecretNeverPrints(t *testing.T) {
	s := NewSecret("tok-SECRET")
	tok := Token{Value: s, Host: "a.example.test", Principal: "p"}
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "s", s, "tok", tok)
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "s", s, "tok", tok)
	for _, out := range []string{
		fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s %q %x %X %d", s, s, s, s, s, s, s, s),
		fmt.Sprintf("%v %+v %#v %s", tok, tok, tok, &tok), s.String(), s.GoString(), logged.String(),
	} {
		if strings.Contains(out, "SECRET") || strings.Contains(out, "544543") /* hex of "SEC" */ {
			t.Errorf("secret printed: %s", out)
		}
	}
	if b, err := json.Marshal(tok); err == nil {
		t.Errorf("token marshalled to JSON: %s", b)
	}
	if s.Reveal() != "tok-SECRET" {
		t.Error("Reveal lost the value")
	}
}

func TestParseIssuer(t *testing.T) {
	for in, want := range map[string]string{
		"https://access.corp.example.org": "https://access.corp.example.org",
		"https://Access.Example.COM/":     "https://access.example.com",
		"https://login.corp.example.org":  "https://login.corp.example.org",
	} {
		if got, err := ParseIssuer(in); err != nil || got != want {
			t.Errorf("ParseIssuer(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{
		"", "http://access.example.com", "https://example.com", "https://access.example.com:8443",
		"https://access.example.com/x", "https://u@access.example.com", "https://access.example.com?x=1",
		"https://access.example.com#f", "https://10.0.0.1", "https://acc_ess.example.com", "access.example.com",
	} {
		if _, err := ParseIssuer(bad); err == nil {
			t.Errorf("ParseIssuer(%q) accepted", bad)
		}
	}
	if d := issuerDomain("https://access.corp.example.org"); d != ".corp.example.org" {
		t.Errorf("issuerDomain = %q", d)
	}
}

func TestCheckURL(t *testing.T) {
	// ".test" and "example.test" contain the issuer's domain, ".a.example.test"
	// is under it: none of them is an extra suffix.
	c, _, _ := loggedIn(t, &fakeIssuer{}, State{AudienceSuffixes: []string{"other.org", ".Second.Example.net", "bogus", ".x..y", ".test", "example.test", ".a.example.test", ".com"}})
	if got := c.AllowedSuffixes(); !slices.Equal(got, []string{".example.test", ".other.org", ".second.example.net"}) {
		t.Fatalf("AllowedSuffixes = %q", got)
	}
	for in, want := range map[string]string{
		"https://Grafana.example.test:443/api?x=1": "grafana.example.test",
		"https://app.other.org/":                   "app.other.org",
		"https://a.b.second.example.net/x":         "a.b.second.example.net",
	} {
		if h, err := c.CheckURL(in); err != nil || h != want {
			t.Errorf("CheckURL(%q) = %q, %v", in, h, err)
		}
	}
	for _, bad := range []string{
		"http://grafana.example.test/", "grafana.example.test", "https://u:p@grafana.example.test/", "https:///x",
		"https://example.test/", "https://other.org/", "https://grafana.example.test.evil.com/", "https://evilexample.test/",
		"https://evil-other.org/", "https://{a,b}.example.test/", "https://1.2.3.4/", "https://bogus/",
	} {
		if _, err := c.CheckURL(bad); err == nil {
			t.Errorf("CheckURL(%q) accepted", bad)
		}
	}
	// Advertised suffixes belong to the issuer that advertised them.
	c.cfg.Issuer = "https://login.elsewhere.test"
	if _, err := c.CheckURL("https://app.other.org/"); err == nil {
		t.Error("another issuer's advertised suffix was used")
	}
}

func TestTokenSourceCachesPerHost(t *testing.T) {
	f := &fakeIssuer{expiresIn: 3600}
	c, _, now := loggedIn(t, f, State{})
	ts, err := c.TokenSource("work")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a1, err := ts.Token(ctx, "A.example.test")
	if err != nil || a1.Value.Reveal() != "at-a.example.test-1" || a1.Host != "a.example.test" || a1.Principal != testAccount+":work" {
		t.Fatalf("first token = %+v, %v", a1, err)
	}
	if a2, _ := ts.Token(ctx, "a.example.test"); a2.Value.Reveal() != a1.Value.Reveal() || f.count("a.example.test") != 1 {
		t.Errorf("not cached: %d mints", f.count("a.example.test"))
	}
	if b, _ := ts.Token(ctx, "b.example.test"); b.Value.Reveal() != "at-b.example.test-1" {
		t.Errorf("b = %v", b.Value.Reveal())
	}
	*now = now.Add(59 * time.Minute) // under a minute left: mint again
	if a3, _ := ts.Token(ctx, "a.example.test"); a3.Value.Reveal() != "at-a.example.test-2" {
		t.Errorf("expired token reused: %s", a3.Value.Reveal())
	}
	if _, err := ts.Token(ctx, "evil.com"); err == nil || f.count("evil.com") != 0 {
		t.Error("minted for a host outside the allowed suffixes")
	}
	if _, err := c.TokenSource("Bad:*"); err == nil {
		t.Error("bad session accepted")
	}
}

func TestTokenErrorsCarryNoSecrets(t *testing.T) {
	f := &fakeIssuer{expiresIn: 3600, forbidden: map[string]bool{"no.example.test": true}}
	c, _, _ := loggedIn(t, f, State{})
	ts, _ := c.TokenSource("s")
	_, err := ts.Token(context.Background(), "no.example.test")
	var fe *ForbiddenError
	if !errors.As(err, &fe) || fe.Host != "no.example.test" || fe.Principal != testAccount+":s" {
		t.Fatalf("forbidden = %v", err)
	}
	if want := testAccount + ":*"; !strings.Contains(err.Error(), want) {
		t.Errorf("forbidden error %q does not name the pattern %q", err, want)
	}
	f.invalid = true
	_, err = ts.Token(context.Background(), "yes.example.test")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("invalid = %v", err)
	}
	for _, e := range []error{fe, err} {
		if s := fmt.Sprintf("%v %+v", e, e); strings.Contains(s, "SECRET") || strings.Contains(s, "at-") {
			t.Errorf("error leaks a credential: %s", s)
		}
	}
}

func TestIssuerMismatchRefusesCredential(t *testing.T) {
	f := &fakeIssuer{expiresIn: 3600}
	c, _, _ := loggedIn(t, f, State{Issuer: "https://access.other.test"})
	var me *IssuerMismatchError
	if _, err := c.TokenSource("s"); !errors.As(err, &me) {
		t.Fatalf("TokenSource = %v, want an issuer mismatch", err)
	}
	if st := c.Status(context.Background()); st.Mismatch == nil {
		t.Error("Status hides the mismatch")
	}
}

// recordingBase answers 200, or a redirect for paths /to/<host>/<path>.
type recordingBase struct {
	mu   sync.Mutex
	seen []string // "host proxy-authorization"
}

func (b *recordingBase) RoundTrip(r *http.Request) (*http.Response, error) {
	b.mu.Lock()
	b.seen = append(b.seen, r.URL.Scheme+"://"+r.URL.Host+" "+r.Header.Get("Proxy-Authorization"))
	b.mu.Unlock()
	w := httptest.NewRecorder()
	if rest, ok := strings.CutPrefix(r.URL.Path, "/to/"); ok {
		host, path, _ := strings.Cut(rest, "/")
		http.Redirect(w, r, "https://"+host+"/"+path, http.StatusFound)
	} else {
		_, _ = io.WriteString(w, "ok")
	}
	resp := w.Result()
	resp.Request = r
	return resp, nil
}

func TestTransport(t *testing.T) {
	f := &fakeIssuer{expiresIn: 3600}
	c, _, _ := loggedIn(t, f, State{AudienceSuffixes: []string{".other.org"}})
	ts, _ := c.TokenSource("s")
	base := &recordingBase{}
	hc := &http.Client{Transport: &Transport{Source: ts, Base: base}}

	get := func(u string, hdr string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		if hdr != "" {
			req.Header.Set("Proxy-Authorization", hdr)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		resp.Body.Close()
	}
	get("https://a.example.test/x", "")
	get("http://a.example.test/x", "")             // not https: nothing
	get("https://evil.com/x", "Bearer caller-set") // not allowed: nothing, and the caller's header goes
	get("https://app.other.org/", "")              // an advertised suffix
	get("https://a.example.test/to/b.example.test/p", "")
	get("https://a.example.test/to/a.example.test/p", "")
	// Go itself copies a caller's Proxy-Authorization to a subdomain on
	// redirect; the transport strips it.
	get("https://evil.com/to/sub.evil.com/p", "Bearer caller-set")

	want := []string{
		"https://a.example.test Bearer at-a.example.test-1",
		"http://a.example.test ",
		"https://evil.com ",
		"https://app.other.org Bearer at-app.other.org-1",
		"https://a.example.test Bearer at-a.example.test-1",
		"https://b.example.test ", // cross-host redirect: no token
		"https://a.example.test Bearer at-a.example.test-1",
		"https://a.example.test Bearer at-a.example.test-1", // same-host redirect keeps it
		"https://evil.com ",
		"https://sub.evil.com ",
	}
	if !slices.Equal(base.seen, want) {
		t.Errorf("seen:\n%s\nwant:\n%s", strings.Join(base.seen, "\n"), strings.Join(want, "\n"))
	}
	if f.count("b.example.test") != 0 || f.count("evil.com") != 0 {
		t.Error("minted for a host that was not requested directly")
	}

	// A refused mint fails the request instead of sending it bare.
	f.forbidden = map[string]bool{"no.example.test": true}
	if _, err := hc.Get("https://no.example.test/"); !errors.As(err, new(*ForbiddenError)) {
		t.Errorf("forbidden request = %v", err)
	}
}

func TestLoginStoresCredentialAndSuffixes(t *testing.T) {
	f := &fakeIssuer{suffixes: []string{"second.example", "not a host"}}
	dir := t.TempDir()
	store := &memStore{}
	c, err := New(Config{Issuer: testIssuer, Dir: dir, Store: store, HTTPClient: &http.Client{Transport: &handlerTransport{h: f}}})
	if err != nil {
		t.Fatal(err)
	}
	var prompt bytes.Buffer
	browser := func(ctx context.Context, raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		q := u.Query()
		if u.Host != "access.example.test" || u.Path != "/agents/authorize" || q.Get("machine") != "box" || q.Get("program") != "cli" || q.Get("code_challenge_method") != "S256" {
			return fmt.Errorf("bad consent URL %s", raw)
		}
		go func() {
			resp, err := http.Get("http://127.0.0.1:" + q.Get("port") + "/callback?code=the-code&state=" + url.QueryEscape(q.Get("state")))
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
	reg, err := c.Login(context.Background(), LoginOptions{Machine: "box", OpenBrowser: browser, Prompt: &prompt, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if reg.Account != testAccount || !slices.Equal(reg.AudienceSuffixes, []string{".second.example"}) || reg.ExpiresAt.Year() != 2030 {
		t.Errorf("registration = %+v", reg)
	}
	if store.m[testAccount] != testRefresh {
		t.Error("refresh credential not stored")
	}
	st, _ := LoadState(dir, "cli")
	if st.Issuer != testIssuer || st.Account != testAccount || st.Store != "mem" || !slices.Equal(st.AudienceSuffixes, []string{".second.example"}) {
		t.Errorf("state = %+v", st)
	}
	b, _ := os.ReadFile(StatePath(dir))
	if strings.Contains(string(b)+prompt.String()+fmt.Sprintf("%+v", reg), "SECRET") {
		t.Error("refresh credential in the state file, prompt or registration")
	}
	if _, err := c.CheckURL("https://app.second.example/"); err != nil {
		t.Errorf("advertised suffix not allowed after login: %v", err)
	}
}

func TestLoadStateAcceptsWireName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(StatePath(dir), []byte(`{"server":"`+testIssuer+`","account":"`+testAccount+`","external_audience_suffixes":[".second.example"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := LoadState(dir, "cli"); err != nil || !slices.Equal(st.AudienceSuffixes, []string{".second.example"}) {
		t.Errorf("LoadState = %+v, %v", st, err)
	}
}

func TestLoginHeadlessPrintsForwardingHint(t *testing.T) {
	c, err := New(Config{Issuer: testIssuer, Dir: t.TempDir(), Store: &memStore{}})
	if err != nil {
		t.Fatal(err)
	}
	var prompt bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = c.Login(ctx, LoginOptions{Machine: "box", Port: 18765, Prompt: &prompt})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Login = %v", err)
	}
	if !strings.Contains(prompt.String(), "ssh -L 18765:127.0.0.1:18765") || !strings.Contains(prompt.String(), "port=18765") {
		t.Errorf("prompt = %s", prompt.String())
	}
}

func TestCallbackHandler(t *testing.T) {
	out := make(chan callbackResult, 1)
	h := callbackHandler("the-state", out)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=c&state=other", nil))
	if w.Code != http.StatusBadRequest || len(out) != 0 {
		t.Fatalf("state mismatch = %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?code=c&state=the-state", nil))
	if res := <-out; w.Code != http.StatusOK || res.code != "c" || res.err != nil {
		t.Fatalf("callback = %d %+v", w.Code, res)
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&state=the-state", nil))
	if res := <-out; res.err == nil {
		t.Fatal("cancel not reported")
	}
}

func TestSanitizeSegment(t *testing.T) {
	for in, want := range map[string]string{
		"Someones-MacBook-Pro":  "someones-macbook-pro",
		"my mac":                "my-mac",
		"-x":                    "x",
		"":                      "",
		"__":                    "",
		strings.Repeat("a", 70): strings.Repeat("a", 63),
	} {
		if got := SanitizeSegment(in); got != want {
			t.Errorf("SanitizeSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLogout(t *testing.T) {
	c, store, _ := loggedIn(t, &fakeIssuer{}, State{})
	if acct, err := c.Logout(context.Background()); err != nil || acct != testAccount {
		t.Fatalf("Logout = %q, %v", acct, err)
	}
	if len(store.m) != 0 || c.State().Account != "" {
		t.Error("credential or account kept")
	}
	if _, err := c.Logout(context.Background()); !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("second Logout = %v", err)
	}
}

func TestKeychainStoreCmdKeepsSecretOffArgv(t *testing.T) {
	const acct, secret = "agent:user:alice@example.com:mac:claude", "iapr_abcDEF123-_xyz"
	cmd, err := KeychainStore{}.storeCmd(context.Background(), acct, NewSecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cmd.Args, []string{"security", "-i"}) {
		t.Fatalf("argv = %q", cmd.Args)
	}
	b, _ := io.ReadAll(cmd.Stdin)
	if string(b) != "add-generic-password -U -s iap-authz -a "+acct+" -w "+secret+"\n" {
		t.Errorf("stdin = %q", b)
	}
	for _, bad := range []string{`iapr_x" -A`, "iapr_x\nadd", "iapr x", ""} {
		if _, err := (KeychainStore{}).storeCmd(context.Background(), acct, NewSecret(bad)); err == nil {
			t.Errorf("secret %q accepted", bad)
		}
	}
}

// fakeSecretTool writes a secret-tool stand-in that keeps one item in a file,
// or, with headless set, fails like secret-tool without a D-Bus session.
func fakeSecretTool(t *testing.T, headless bool) (SecretServiceStore, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	dir := t.TempDir()
	item := filepath.Join(dir, "item")
	argv := filepath.Join(dir, "argv")
	script := `#!/bin/sh
echo "$@" >> '` + argv + `'
`
	if headless {
		script += "echo 'Cannot autolaunch D-Bus without X11 $DISPLAY' >&2; exit 1\n"
	} else {
		script += `case "$1" in
store) cat > '` + item + `' ;;
lookup) [ -f '` + item + `' ] || exit 1; cat '` + item + `' ;;
clear) rm -f '` + item + `' ;;
esac
`
	}
	bin := filepath.Join(dir, "secret-tool")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return SecretServiceStore{Command: bin}, argv
}

func TestSecretServiceStore(t *testing.T) {
	ctx := context.Background()
	s, argv := fakeSecretTool(t, false)
	if ok, err := s.Exists(ctx, testAccount); ok || err != nil {
		t.Fatalf("Exists before save = %v, %v", ok, err)
	}
	if _, err := s.Load(ctx, testAccount); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("Load before save = %v", err)
	}
	if err := s.Save(ctx, testAccount, NewSecret(testRefresh)); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Load(ctx, testAccount); err != nil || got.Reveal() != testRefresh {
		t.Fatalf("Load = %v", err)
	}
	if err := s.Delete(ctx, testAccount); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Exists(ctx, testAccount); ok {
		t.Error("item survived Delete")
	}
	b, _ := os.ReadFile(argv)
	if strings.Contains(string(b), "SECRET") {
		t.Errorf("credential on secret-tool's argv: %s", b)
	}
	if !strings.Contains(string(b), "store --label=iap refresh credential ("+testAccount+") service iap-authz account "+testAccount) {
		t.Errorf("argv = %s", b)
	}

	h, _ := fakeSecretTool(t, true)
	for _, err := range []error{h.Save(ctx, testAccount, NewSecret(testRefresh)), func() error { _, err := h.Load(ctx, testAccount); return err }()} {
		if !errors.Is(err, ErrSecretServiceUnavailable) || !strings.Contains(err.Error(), "file store") || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("headless error = %v", err)
		}
	}
}

func TestFileStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits")
	}
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "iap")
	s := FileStore{Dir: dir}
	if ok, err := s.Exists(ctx, testAccount); ok || err != nil {
		t.Fatalf("Exists on nothing = %v, %v", ok, err)
	}
	if err := s.Save(ctx, testAccount, NewSecret(testRefresh)); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "other", NewSecret("x")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Load(ctx, testAccount); err != nil || got.Reveal() != testRefresh {
		t.Fatalf("Load = %v", err)
	}
	for p, want := range map[string]os.FileMode{dir: 0o700, s.Location(""): 0o600} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v, %v", p, fi.Mode(), err)
		}
	}
	if err := s.Delete(ctx, testAccount); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, testAccount); !errors.Is(err, ErrNoCredential) || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("Load after Delete = %v", err)
	}

	// Looser permissions, and symlinks, are refused.
	_ = os.Chmod(s.Location(""), 0o644)
	if _, err := s.Load(ctx, "other"); err == nil || !strings.Contains(err.Error(), "looser") {
		t.Errorf("0644 file = %v", err)
	}
	_ = os.Chmod(s.Location(""), 0o600)
	_ = os.Chmod(dir, 0o755)
	if err := s.Save(ctx, "other", NewSecret("y")); err == nil {
		t.Error("0755 directory accepted")
	}
	_ = os.Chmod(dir, 0o700)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileStore{Dir: link}).Load(ctx, "other"); err == nil {
		t.Error("symlinked directory accepted")
	}
}

func TestOpenStore(t *testing.T) {
	if _, err := OpenStore("vault"); err == nil {
		t.Error("unknown store accepted")
	}
	t.Setenv("XDG_STATE_HOME", "/xdg/state")
	if s, err := OpenStore(StoreFile); err != nil || s.Location("") != "/xdg/state/iap/credentials.json" {
		t.Errorf("file store = %v, %v", s, err)
	}
	if runtime.GOOS == "linux" {
		t.Setenv("PATH", t.TempDir())
		if _, err := OpenStore(StoreAuto); !errors.Is(err, ErrNoKeyring) {
			t.Errorf("auto without secret-tool = %v (must not fall back to a file)", err)
		}
	}
}

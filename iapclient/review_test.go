package iapclient

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// failingStore is a memStore whose Save fails after `okSaves` successes.
type failingStore struct {
	memStore
	mu      sync.Mutex
	okSaves int
	saves   int
}

func (f *failingStore) Save(ctx context.Context, a string, c Secret) error {
	f.mu.Lock()
	f.saves++
	n := f.saves
	f.mu.Unlock()
	if n > f.okSaves {
		return errors.New("keyring locked")
	}
	return f.memStore.Save(ctx, a, c)
}

// lyingStore says every item is absent, whatever was saved: a locked
// Keychain answers "not found" the same way.
type lyingStore struct{ memStore }

func (*lyingStore) Exists(context.Context, string) (bool, error) { return false, nil }

func TestCheckStoreWritesAndDeletes(t *testing.T) {
	ctx := context.Background()
	m := &memStore{}
	if err := CheckStore(ctx, m); err != nil {
		t.Fatalf("working store: %v", err)
	}
	if len(m.m) != 0 {
		t.Errorf("probe item left behind: %v", m.m)
	}
	if err := CheckStore(ctx, &failingStore{}); err == nil {
		t.Error("a store that can't save passed")
	}
	if err := CheckStore(ctx, &lyingStore{}); err == nil {
		t.Error("a store that loses what it saved passed")
	}
}

// The store check runs before the consent URL is printed: nobody approves a
// login whose credential could not be kept.
func TestLoginChecksStoreBeforeURL(t *testing.T) {
	for _, headless := range []bool{false, true} {
		c, err := New(Config{Issuer: testIssuer, Dir: t.TempDir(), Store: &failingStore{}})
		if err != nil {
			t.Fatal(err)
		}
		var prompt bytes.Buffer
		read := func() (string, error) { t.Error("code read despite a broken store"); return "", nil }
		_, err = c.Login(context.Background(), LoginOptions{Machine: "box", Headless: headless, ReadCode: read, Prompt: &prompt, Timeout: time.Second})
		if err == nil || strings.Contains(prompt.String(), "/agents/authorize") {
			t.Errorf("headless=%v: err %v, prompt %q", headless, err, prompt.String())
		}
	}
}

// If the store fails after the code is spent, the error says exactly where
// that leaves the person, and carries no secret.
func TestLoginCredentialLost(t *testing.T) {
	p := &pkceIssuer{}
	store := &failingStore{okSaves: 1} // the probe works, the real save fails
	c, err := New(Config{Issuer: testIssuer, Dir: t.TempDir(), Store: store, HTTPClient: &http.Client{Transport: &handlerTransport{h: p}}})
	if err != nil {
		t.Fatal(err)
	}
	var prompt bytes.Buffer
	_, err = c.Login(context.Background(), LoginOptions{Machine: "box", Headless: true, Prompt: &prompt, Timeout: 5 * time.Second,
		ReadCode: func() (string, error) {
			return p.approve(consentURL(t, prompt.String()).Query().Get("code_challenge")), nil
		}})
	var lost *CredentialLostError
	if !errors.As(err, &lost) {
		t.Fatalf("Login = %v", err)
	}
	msg := err.Error()
	for _, want := range []string{testAccount + ":*", "credential is lost", "revoke it", testIssuer + "/#agents", "keyring locked"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error lacks %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, testRefresh) {
		t.Error("the refresh credential is in the error")
	}
	if st := c.State(); st.Account != "" {
		t.Errorf("state saved for a lost credential: %+v", st)
	}
}

// flakyIssuer fails the first `fail` token requests with status, then
// behaves as pkceIssuer.
type flakyIssuer struct {
	pkceIssuer
	mu     sync.Mutex
	fail   int
	status int
	calls  int
}

func (f *flakyIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls++
	failing := f.calls <= f.fail
	f.mu.Unlock()
	if failing {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_ = json.MarshalWrite(w, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	f.pkceIssuer.ServeHTTP(w, r)
}

// A 429/5xx on the exchange is retried within the code's lifetime instead of
// throwing a valid code away; invalid_grant is final at once.
func TestLoginRetriesTransientExchange(t *testing.T) {
	prev := exchangeRetryDelays
	exchangeRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { exchangeRetryDelays = prev })
	for _, c := range []struct {
		fail, status int
		ok           bool
		calls        int
	}{
		{2, http.StatusServiceUnavailable, true, 3},
		{1, http.StatusTooManyRequests, true, 2},
		{9, http.StatusBadGateway, false, 4}, // gives up after the schedule
		{1, http.StatusBadRequest, false, 1}, // not transient
	} {
		f := &flakyIssuer{fail: c.fail, status: c.status}
		cl, err := New(Config{Issuer: testIssuer, Dir: t.TempDir(), Store: &memStore{}, HTTPClient: &http.Client{Transport: &handlerTransport{h: f}}})
		if err != nil {
			t.Fatal(err)
		}
		var prompt bytes.Buffer
		_, err = cl.Login(context.Background(), LoginOptions{Machine: "box", Headless: true, Prompt: &prompt, Timeout: 5 * time.Second,
			ReadCode: func() (string, error) {
				return f.approve(consentURL(t, prompt.String()).Query().Get("code_challenge")), nil
			}})
		if (err == nil) != c.ok || f.calls != c.calls {
			t.Errorf("%d x %d: err %v after %d calls", c.fail, c.status, err, f.calls)
		}
	}
}

// Advertised suffixes that AllowedSuffixes drops are warned about, and the
// registration reports only what is actually allowed.
func TestLoginWarnsDroppedSuffixes(t *testing.T) {
	f := &fakeIssuer{suffixes: []string{"second.example", ".test", "example.test", "not a host"}}
	c, err := New(Config{Issuer: testIssuer, Dir: t.TempDir(), Store: &memStore{}, HTTPClient: &http.Client{Transport: &handlerTransport{h: f}}})
	if err != nil {
		t.Fatal(err)
	}
	var prompt bytes.Buffer
	reg, err := c.Login(context.Background(), LoginOptions{Machine: "box", Prompt: &prompt, Timeout: 5 * time.Second,
		OpenBrowser: func(_ context.Context, raw string) error {
			go loopbackCallback(t, raw)
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(reg.AudienceSuffixes, []string{".second.example"}) {
		t.Errorf("registration suffixes = %q", reg.AudienceSuffixes)
	}
	for _, dropped := range []string{`".test"`, `"example.test"`, `"not a host"`} {
		if !strings.Contains(prompt.String(), "ignoring the issuer's audience suffix "+dropped) {
			t.Errorf("no warning for %s:\n%s", dropped, prompt.String())
		}
	}
	if strings.Contains(prompt.String(), `"second.example"`) {
		t.Error("warned about an allowed suffix")
	}
}

// loopbackCallback plays the browser for a loopback login with code the-code.
func loopbackCallback(t *testing.T, raw string) {
	u := consentURL(t, raw)
	q := u.Query()
	resp, err := http.Get("http://127.0.0.1:" + q.Get("port") + "/callback?code=the-code&state=" + q.Get("state"))
	if err == nil {
		resp.Body.Close()
	}
}

// A suffix without a leading dot still matches on a label boundary only.
func TestSuffixLabelBoundary(t *testing.T) {
	c, _, _ := loggedIn(t, &fakeIssuer{}, State{AudienceSuffixes: []string{"example.com"}})
	if _, err := c.CheckURL("https://app.example.com/"); err != nil {
		t.Errorf("app.example.com: %v", err)
	}
	for _, bad := range []string{"https://evilexample.com/", "https://example.com/", "https://app.example.com.evil.org/"} {
		if _, err := c.CheckURL(bad); err == nil {
			t.Errorf("%s accepted under example.com", bad)
		}
	}
}

// A state without an issuer belongs to Config.LegacyIssuer only; with none
// set it belongs to no issuer. Its credential is never sent elsewhere.
func TestLegacyStateIssuer(t *testing.T) {
	for _, c := range []struct {
		legacy string
		ok     bool
	}{{testIssuer, true}, {"https://access.other.test", false}, {"", false}} {
		dir := t.TempDir()
		if err := SaveState(dir, "cli", State{Account: testAccount}); err != nil {
			t.Fatal(err)
		}
		cl, err := New(Config{Issuer: testIssuer, Dir: dir, Store: &memStore{m: map[string]string{testAccount: testRefresh}}, LegacyIssuer: c.legacy})
		if err != nil {
			t.Fatal(err)
		}
		_, err = cl.TokenSource("s")
		if mismatch := errors.As(err, new(*IssuerMismatchError)); mismatch == c.ok {
			t.Errorf("legacy issuer %q: TokenSource = %v", c.legacy, err)
		}
	}
}

// StoreFallback is recorded in the state, so the next login retries the
// keyring.
func TestLoginRecordsStoreFallback(t *testing.T) {
	f := &fakeIssuer{}
	dir := t.TempDir()
	c, err := New(Config{Issuer: testIssuer, Dir: dir, Store: &memStore{}, HTTPClient: &http.Client{Transport: &handlerTransport{h: f}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Login(context.Background(), LoginOptions{Machine: "box", Prompt: &bytes.Buffer{}, Timeout: 5 * time.Second, StoreFallback: true,
		OpenBrowser: func(_ context.Context, raw string) error { go loopbackCallback(t, raw); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := LoadState(dir, "cli"); !st.StoreFallback || st.Store != "mem" {
		t.Errorf("state = %+v", st)
	}
}

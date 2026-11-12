package iapclient

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// rotatingIssuer answers refresh grants like iap-authz with rotation, but
// stricter: it rotates on every rotate=1 grant, and the grace a rotated-away
// credential gets ends the moment its successor is first presented, not
// minutes later. strict drops the grace entirely (any rotated-away
// credential revokes), which only a client that never races itself survives.
type rotatingIssuer struct {
	strict    bool
	forbidden map[string]bool

	mu       sync.Mutex
	n        int
	current  string
	used     bool            // current has been presented
	open     map[string]bool // rotated away, successor never presented
	dead     map[string]bool // rotated away, grace over
	revoked  bool
	rotation int
	exp      time.Time
}

func newRotatingIssuer(strict bool) *rotatingIssuer {
	return &rotatingIssuer{strict: strict, current: testRefresh, used: true, open: map[string]bool{}, dead: map[string]bool{},
		exp: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (f *rotatingIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	refuse := func(body map[string]string) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.MarshalWrite(w, body)
	}
	tok := r.PostFormValue("refresh_token")
	switch {
	case f.revoked:
		refuse(map[string]string{"error": "invalid_grant"})
		return
	case tok == f.current:
		if !f.used {
			f.used = true
			for k := range f.open {
				delete(f.open, k)
				f.dead[k] = true
			}
		}
	case f.open[tok] && !f.strict:
		// In its grace: accepted; rotates again only if the successor was
		// never presented (it always wasn't, while open is non-empty).
	case f.open[tok] || f.dead[tok]:
		f.revoked = true
		refuse(map[string]string{"error": "invalid_grant", "reason": "reused"})
		return
	default:
		refuse(map[string]string{"error": "invalid_grant"})
		return
	}
	body := map[string]any{}
	if r.PostFormValue("rotate") == "1" {
		f.open[f.current] = true
		f.n++
		f.current = fmt.Sprintf("iapr_rotated-%d", f.n)
		f.used = false
		f.rotation++
		f.exp = f.exp.Add(time.Hour)
		body["refresh_token"] = f.current
		body["registration_expires_at"] = f.exp.Format(time.RFC3339)
	}
	host := r.PostFormValue("audience")
	if f.forbidden[host] {
		w.WriteHeader(http.StatusForbidden)
		body["error"], body["principal"], body["host"] = "forbidden", testAccount+":s", host
		_ = json.MarshalWrite(w, body)
		return
	}
	body["access_token"], body["token_type"], body["expires_in"] = "at-"+host, "Bearer", 3600
	_ = json.MarshalWrite(w, body)
}

func (f *rotatingIssuer) state() (current string, revoked bool, exp time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current, f.revoked, f.exp
}

// rotatingClient is a client of f logged in with testRefresh in store, with
// its state in dir.
func rotatingClient(t *testing.T, f http.Handler, dir string, store Store) *Client {
	t.Helper()
	c, err := New(Config{Issuer: testIssuer, Dir: dir, Store: store, HTTPClient: &http.Client{Transport: &handlerTransport{h: f}}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func loginState(t *testing.T, dir string) {
	t.Helper()
	if err := SaveState(dir, "cli", State{Issuer: testIssuer, Account: testAccount, ExpiresAt: time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
}

// TestRotationSavedBeforeUse: a rotated credential is in the store before
// the access token is returned, and the state file has the new expiry.
func TestRotationSavedBeforeUse(t *testing.T) {
	f := newRotatingIssuer(true)
	dir := t.TempDir()
	loginState(t, dir)
	store := &memStore{m: map[string]string{testAccount: testRefresh}}
	ts, err := rotatingClient(t, f, dir, store).TokenSource("s")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if _, err := ts.Token(context.Background(), fmt.Sprintf("h%d.example.test", i)); err != nil {
			t.Fatalf("token %d: %v", i, err)
		}
	}
	cur, revoked, exp := f.state()
	if revoked || store.m[testAccount] != cur || cur == testRefresh {
		t.Fatalf("stored %q, issuer current %q, revoked %v", store.m[testAccount], cur, revoked)
	}
	if st, err := LoadState(dir, "cli"); err != nil || !st.ExpiresAt.Equal(exp) {
		t.Errorf("state expiry = %v, %v; want %v", st.ExpiresAt, err, exp)
	}
}

// TestRotationOnForbidden: a 403 that carries a rotated credential still
// saves it.
func TestRotationOnForbidden(t *testing.T) {
	f := newRotatingIssuer(true)
	f.forbidden = map[string]bool{"no.example.test": true}
	dir := t.TempDir()
	loginState(t, dir)
	store := &memStore{m: map[string]string{testAccount: testRefresh}}
	ts, _ := rotatingClient(t, f, dir, store).TokenSource("s")
	var fe *ForbiddenError
	if _, err := ts.Token(context.Background(), "no.example.test"); !errors.As(err, &fe) {
		t.Fatalf("forbidden host: %v", err)
	}
	if cur, _, _ := f.state(); store.m[testAccount] != cur {
		t.Fatalf("rotated credential from a 403 not saved: %q vs %q", store.m[testAccount], cur)
	}
	if _, err := ts.Token(context.Background(), "ok.example.test"); err != nil {
		t.Fatalf("after the 403: %v", err)
	}
}

// TestRotationConcurrentClients: several clients (as several processes
// would: separate Clients, one Dir, one file store) minting at once, each
// mint rotating, against an issuer with no grace at all. The registration
// lock means none ever presents a credential another rotated away.
func TestRotationConcurrentClients(t *testing.T) {
	f := newRotatingIssuer(true)
	dir := t.TempDir()
	loginState(t, dir)
	store := FileStore{Dir: t.TempDir() + "/state"}
	if err := store.Save(context.Background(), testAccount, NewSecret(testRefresh)); err != nil {
		t.Fatal(err)
	}
	const clients, mints = 6, 8
	var wg sync.WaitGroup
	errs := make(chan error, clients*mints)
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ts, err := rotatingClient(t, f, dir, store).TokenSource(fmt.Sprintf("s%d", i))
			if err != nil {
				errs <- err
				return
			}
			for j := range mints {
				if _, err := ts.Token(context.Background(), fmt.Sprintf("c%d-%d.example.test", i, j)); err != nil {
					errs <- fmt.Errorf("client %d mint %d: %w", i, j, err)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	cur, revoked, _ := f.state()
	got, err := store.Load(context.Background(), testAccount)
	if revoked || err != nil || got.Reveal() != cur || f.rotation != clients*mints {
		t.Errorf("revoked %v, stored current %v (%v), rotations %d", revoked, got.Reveal() == cur, err, f.rotation)
	}
}

// TestRotationCrashBeforeSave: the new credential is lost between the
// issuer's answer and the store (here, the save fails; a crash is the same).
// The token is not used, the old credential stays stored, and the next grant
// presents it, inside its grace, and gets another new one.
func TestRotationCrashBeforeSave(t *testing.T) {
	f := newRotatingIssuer(false)
	dir := t.TempDir()
	loginState(t, dir)
	store := &failingStore{memStore: memStore{m: map[string]string{testAccount: testRefresh}}, okSaves: 0}
	ts, _ := rotatingClient(t, f, dir, store).TokenSource("s")
	_, err := ts.Token(context.Background(), "a.example.test")
	if err == nil || !strings.Contains(err.Error(), "refused the new one") {
		t.Fatalf("failed save: %v", err)
	}
	if store.m[testAccount] != testRefresh {
		t.Fatalf("store changed: %q", store.m[testAccount])
	}
	store.mu.Lock()
	store.okSaves = 100
	store.mu.Unlock()
	if _, err := ts.Token(context.Background(), "a.example.test"); err != nil {
		t.Fatalf("after the lost credential: %v", err)
	}
	if cur, revoked, _ := f.state(); revoked || store.m[testAccount] != cur {
		t.Errorf("recovered: stored %q, current %q, revoked %v", store.m[testAccount], cur, revoked)
	}
}

// TestRefreshReusedError: the issuer's reuse answer is ErrRefreshReused, which
// is also ErrInvalidGrant.
func TestRefreshReusedError(t *testing.T) {
	f := newRotatingIssuer(true)
	f.dead[testRefresh] = true
	f.current = "iapr_other"
	dir := t.TempDir()
	loginState(t, dir)
	ts, _ := rotatingClient(t, f, dir, &memStore{m: map[string]string{testAccount: testRefresh}}).TokenSource("s")
	_, err := ts.Token(context.Background(), "a.example.test")
	if !errors.Is(err, ErrRefreshReused) || !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("reused credential: %v", err)
	}
	if strings.Contains(err.Error(), testRefresh) {
		t.Error("error carries the credential")
	}
}

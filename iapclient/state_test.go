package iapclient

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// The state file reads the layout of the CLI before iapclient (one
// registration per program, one top-level server, the Tailscale client ID)
// and the single-registration layout, and writing one program keeps the
// others and the client ID.
func TestStateFileLayouts(t *testing.T) {
	const claude = "agent:user:alice@example.com:box:claude"
	dir := t.TempDir()
	perProgram := `{"server":"https://access.other.test","registrations":{"claude":{"account":"` + claude + `","expires_at":"2030-01-02T03:04:05Z"}},` +
		`"account":"` + testAccount + `","expires_at":"2030-01-02T03:04:05Z","tailscale_client_id":"Tclient1"}`
	if err := os.WriteFile(StatePath(dir), []byte(perProgram), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := LoadStateFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Registrations["claude"]; got.Account != claude || got.Issuer != "https://access.other.test" || got.ExpiresAt.Year() != 2030 {
		t.Errorf("claude = %+v", got)
	}
	if got := f.Registrations["cli"]; got.Account != testAccount || got.Issuer != "https://access.other.test" {
		t.Errorf("folded single registration = %+v", got)
	}
	if f.TailscaleClientID != "Tclient1" {
		t.Errorf("client id = %q", f.TailscaleClientID)
	}

	if err := SaveState(dir, "cli", State{Issuer: testIssuer, Account: testAccount, Store: "file"}); err != nil {
		t.Fatal(err)
	}
	f, err = LoadStateFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f.Registrations["claude"].Account != claude || f.Registrations["cli"].Store != "file" || f.TailscaleClientID != "Tclient1" {
		t.Errorf("after SaveState: %+v", f)
	}
	b, _ := os.ReadFile(StatePath(dir))
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	if _, ok := top["account"]; ok {
		t.Errorf("top-level single registration written back:\n%s", b)
	}
}

// Each program is its own registration: a client for one never uses, and a
// logout never touches, another program's.
func TestProgramsAreSeparate(t *testing.T) {
	c, store, _ := loggedIn(t, &fakeIssuer{}, State{})
	dir := c.cfg.Dir
	if err := SaveState(dir, "claude", State{Issuer: testIssuer, Account: "agent:user:alice@example.com:box:claude", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	store.m["agent:user:alice@example.com:box:claude"] = "iapr_other"
	other, err := New(Config{Issuer: testIssuer, Dir: dir, Store: store, Program: "claude"})
	if err != nil {
		t.Fatal(err)
	}
	if other.State().Account != "agent:user:alice@example.com:box:claude" || c.State().Account != testAccount {
		t.Fatalf("states: %+v / %+v", other.State(), c.State())
	}
	if _, err := c.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, _ := LoadState(dir, "claude"); st.Account == "" {
		t.Error("logging out cli forgot claude")
	}
	if _, ok := store.m["agent:user:alice@example.com:box:claude"]; !ok {
		t.Error("logging out cli deleted claude's credential")
	}
	if none, err := New(Config{Issuer: testIssuer, Dir: dir, Store: store, Program: "other"}); err != nil {
		t.Fatal(err)
	} else if _, err := none.TokenSource("s1"); !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("unregistered program: %v", err)
	}
}

// A federated audience is minted as asked, never cached, and a refusal names
// the audience rather than a host.
func TestFederatedToken(t *testing.T) {
	const aud = "api.example.com/Client-ID1"
	f := &fakeIssuer{expiresIn: 900}
	c, _, _ := loggedIn(t, f, State{})
	ts, err := c.TokenSource("s1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 1; i <= 2; i++ {
		tok, err := ts.FederatedToken(ctx, aud)
		if err != nil {
			t.Fatal(err)
		}
		if tok.Value.Reveal() != "at-"+aud+"-"+string(rune('0'+i)) || tok.Host != "" || tok.Expiry.IsZero() {
			t.Errorf("mint %d = %+v", i, tok)
		}
	}
	for _, bad := range []string{"", "a b", "x?y", "bob@example.com/a", "x\n"} {
		if _, err := ts.FederatedToken(ctx, bad); err == nil {
			t.Errorf("audience %q accepted", bad)
		}
	}
	f.forbidden = map[string]bool{aud: true}
	_, err = ts.FederatedToken(ctx, aud)
	var fe *ForbiddenError
	if !errors.As(err, &fe) || fe.Audience != aud || fe.Host != "" || !strings.Contains(err.Error(), "audience "+aud) {
		t.Errorf("forbidden = %v", err)
	}
	// The source's per-host tokens are untouched by federated mints.
	if got := f.count(aud); got != 2 {
		t.Errorf("mints = %d", got)
	}
}

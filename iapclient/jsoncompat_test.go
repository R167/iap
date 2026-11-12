package iapclient

import (
	"context"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// Files and responses below are literal encoding/json (v1) output, or input
// v1 accepted. This package encodes with encoding/json/v2; these tests pin
// that existing installs and v1 peers keep working. See CLAUDE.md, "JSON".

const claudeAcct = "agent:user:alice@example.com:box:claude"

// v1StateFile is json.MarshalIndent(f, "", "  ") by a v1 build, for the
// StateFile in v1StateFileValue. It has HTML characters and U+2028, which v1
// escapes.
const v1StateFile = `{
  "registrations": {
    "claude": {
      "account": "agent:user:a\u003cb\u003e\u0026c@example.com:box:claude\u2028",
      "expires_at": "2030-01-02T03:04:05.000006Z"
    },
    "cli": {
      "server": "https://access.example.com",
      "account": "agent:user:alice@example.com:box:cli",
      "expires_at": "2030-01-02T03:04:05.000006Z",
      "audience_suffixes": [
        ".example.net"
      ],
      "store": "file",
      "store_fallback": true
    }
  },
  "tailscale_client_id": "Tclient1"
}
`

func v1StateFileValue() StateFile {
	exp := time.Date(2030, 1, 2, 3, 4, 5, 6000, time.UTC)
	return StateFile{Registrations: map[string]State{
		"cli": {Issuer: "https://access.example.com", Account: "agent:user:alice@example.com:box:cli", ExpiresAt: exp,
			AudienceSuffixes: []string{".example.net"}, Store: "file", StoreFallback: true},
		"claude": {Account: "agent:user:a<b>&c@example.com:box:claude\u2028", ExpiresAt: exp},
	}, TailscaleClientID: "Tclient1"}
}

func writeState(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(StatePath(dir), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func loadState(t *testing.T, content string) StateFile {
	t.Helper()
	f, err := LoadStateFile(writeState(t, content))
	if err != nil {
		t.Fatalf("LoadStateFile(%s): %v", content, err)
	}
	return f
}

func equalState(a, b State) bool {
	return a.Issuer == b.Issuer && a.Account == b.Account && a.ExpiresAt.Equal(b.ExpiresAt) &&
		slices.Equal(a.AudienceSuffixes, b.AudienceSuffixes) && a.Store == b.Store && a.StoreFallback == b.StoreFallback
}

// config.json reads what v1 wrote, and is written back byte for byte as v1
// wrote it (sorted keys, two-space indent, v1's escaping, false omitted).
func TestStateFileV1Bytes(t *testing.T) {
	want := v1StateFileValue()
	got := loadState(t, v1StateFile)
	if len(got.Registrations) != 2 || got.TailscaleClientID != want.TailscaleClientID {
		t.Fatalf("loaded %+v", got)
	}
	for p, s := range want.Registrations {
		if !equalState(got.Registrations[p], s) {
			t.Errorf("%s = %+v, want %+v", p, got.Registrations[p], s)
		}
	}

	dir := t.TempDir()
	if err := SaveStateFile(dir, want); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(StatePath(dir))
	if string(b) != v1StateFile {
		t.Errorf("written:\n%s\nv1 wrote:\n%s", b, v1StateFile)
	}
	// A v1 decoder reads it back (an older iap sharing the config dir).
	var v1 StateFile
	if err := jsonv1.Unmarshal(b, &v1); err != nil || !equalState(v1.Registrations["cli"], want.Registrations["cli"]) {
		t.Errorf("v1 decode: %v %+v", err, v1)
	}

	// An empty file is still "{}", and a false StoreFallback still omitted.
	if err := SaveStateFile(dir, StateFile{}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(StatePath(dir)); string(b) != "{}\n" {
		t.Errorf("empty state written as %q", b)
	}
	if b, err := json.Marshal(State{Account: "a"}); err != nil || string(b) != `{"account":"a","expires_at":"0001-01-01T00:00:00Z"}` {
		t.Errorf("State{Account} = %s, %v", b, err)
	}
}

// Input v1 accepted that v2's defaults would reject or misread: null for a
// slice or map, names in another case, a repeated name (last wins), invalid
// UTF-8 (U+FFFD), and unknown members.
func TestStateFileV1Leniency(t *testing.T) {
	f := loadState(t, `{"registrations":{"cli":{"account":"`+testAccount+`","expires_at":"2030-01-02T03:04:05Z","audience_suffixes":null,"unknown":1}},"tailscale_client_id":null}`)
	if s := f.Registrations["cli"]; s.Account != testAccount || s.AudienceSuffixes != nil {
		t.Errorf("null slice: %+v", s)
	}
	if f := loadState(t, `{"registrations":null}`); len(f.Registrations) != 0 {
		t.Errorf("null map: %+v", f)
	}

	f = loadState(t, `{"Registrations":{"cli":{"SERVER":"https://access.example.com","Account":"`+testAccount+`","Expires_At":"2030-01-02T03:04:05Z","Audience_Suffixes":[".example.net"],"STORE":"file","Store_Fallback":true}},"Tailscale_Client_ID":"T1"}`)
	want := State{Issuer: "https://access.example.com", Account: testAccount, ExpiresAt: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		AudienceSuffixes: []string{".example.net"}, Store: "file", StoreFallback: true}
	if !equalState(f.Registrations["cli"], want) || f.TailscaleClientID != "T1" {
		t.Errorf("mixed case: %+v", f)
	}

	f = loadState(t, `{"registrations":{"cli":{"account":"old","account":"`+testAccount+`"}},"tailscale_client_id":"a","tailscale_client_id":"b"}`)
	if f.Registrations["cli"].Account != testAccount || f.TailscaleClientID != "b" {
		t.Errorf("duplicate names: %+v", f)
	}

	f = loadState(t, "{\"registrations\":{\"cli\":{\"account\":\""+testAccount+"\",\"store\":\"fi\xffle\"}}}")
	if got := f.Registrations["cli"].Store; got != "fi\uFFFDle" {
		t.Errorf("invalid UTF-8: %q", got)
	}
}

// Each older layout of config.json still loads.
func TestStateFileLegacyLayouts(t *testing.T) {
	exp := "2030-01-02T03:04:05Z"
	// One registration at the top level, from before per-program entries.
	f := loadState(t, `{"server":"https://access.other.test","account":"`+testAccount+`","expires_at":"`+exp+`","audience_suffixes":[".example.net"],"store":"keychain"}`)
	if s := f.Registrations["cli"]; s.Account != testAccount || s.Issuer != "https://access.other.test" ||
		!slices.Equal(s.AudienceSuffixes, []string{".example.net"}) || s.Store != "keychain" || len(f.Registrations) != 1 {
		t.Errorf("single registration: %+v", f)
	}
	// The issuer's wire name for the suffixes, at top level and per program.
	f = loadState(t, `{"account":"`+testAccount+`","external_audience_suffixes":null,"registrations":{"claude":{"account":"`+claudeAcct+`","external_audience_suffixes":[".example.org"]}}}`)
	if s := f.Registrations["claude"]; !slices.Equal(s.AudienceSuffixes, []string{".example.org"}) {
		t.Errorf("wire suffixes: %+v", s)
	}
	if s := f.Registrations["cli"]; s.Account != testAccount || s.AudienceSuffixes != nil {
		t.Errorf("wire suffixes null: %+v", s)
	}
	// audience_suffixes wins over the wire name when both are set.
	f = loadState(t, `{"registrations":{"cli":{"account":"`+testAccount+`","audience_suffixes":[".a.test"],"external_audience_suffixes":[".b.test"]}}}`)
	if s := f.Registrations["cli"]; !slices.Equal(s.AudienceSuffixes, []string{".a.test"}) {
		t.Errorf("both names: %+v", s)
	}
	// Per-program layout with a top-level server: the issuer of every entry
	// naming none; an entry's own issuer is kept; a top-level registration
	// does not replace its program's entry.
	f = loadState(t, `{"server":"https://access.other.test","account":"agent:user:alice@example.com:box:cli","expires_at":"`+exp+`",`+
		`"registrations":{"cli":{"account":"agent:user:bob@example.com:box:cli"},"claude":{"server":"https://access.example.com","account":"`+claudeAcct+`"}}}`)
	if s := f.Registrations["cli"]; s.Account != "agent:user:bob@example.com:box:cli" || s.Issuer != "https://access.other.test" {
		t.Errorf("cli: %+v", s)
	}
	if s := f.Registrations["claude"]; s.Issuer != "https://access.example.com" {
		t.Errorf("claude: %+v", s)
	}
}

// State.UnmarshalJSON (the v1 method) still decodes for callers on v1, with
// v1's leniency.
func TestStateUnmarshalJSONV1Caller(t *testing.T) {
	var s State
	if err := jsonv1.Unmarshal([]byte(`{"Account":"a","account":"b","external_audience_suffixes":[".x.test"]}`), &s); err != nil {
		t.Fatal(err)
	}
	if s.Account != "b" || !slices.Equal(s.AudienceSuffixes, []string{".x.test"}) {
		t.Errorf("%+v", s)
	}
}

// v1CredentialsFile is json.MarshalIndent(m, "", "  ") by a v1 build.
const v1CredentialsFile = `{
  "a": "iapr_\u003c\u0026\u003e",
  "m": "",
  "z": "iapr_z"
}
`

// credentials.json reads what v1 wrote and is written back as v1 wrote it.
func TestFileStoreV1Bytes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte(v1CredentialsFile), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := FileStore{Dir: dir}
	ctx := context.Background()
	if s, err := fs.Load(ctx, "a"); err != nil || s.Reveal() != "iapr_<&>" {
		t.Fatalf("Load a: %v", err)
	}
	// Rewrite with the same content: Save then restore "z".
	if err := fs.Save(ctx, "z", NewSecret("iapr_z")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != v1CredentialsFile {
		t.Errorf("written:\n%s\nv1 wrote:\n%s", b, v1CredentialsFile)
	}
	if err := fs.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Delete(ctx, "m"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Delete(ctx, "z"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "{}\n" {
		t.Errorf("emptied file = %q", b)
	}

	// Leniency: a repeated name (last wins), invalid UTF-8, and a null file
	// (v1 left the map empty).
	for content, want := range map[string]string{
		`{"a":"iapr_old","a":"iapr_new"}`: "iapr_new",
		"{\"a\":\"iapr_\xff\"}":           "iapr_\uFFFD",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if s, err := fs.Load(ctx, "a"); err != nil || s.Reveal() != want {
			t.Errorf("%q: %v", content, err)
		}
	}
	if err := os.WriteFile(path, []byte("null"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := fs.Exists(ctx, "a"); err != nil || ok {
		t.Errorf("null file: %v %v", ok, err)
	}
}

// The token endpoint is a v1 server: null for the suffixes, members this
// client does not know, and an error body all decode as before.
func TestTokenResponseFromV1Issuer(t *testing.T) {
	var body string
	var status int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := &Client{cfg: Config{Issuer: srv.URL, HTTPClient: srv.Client()}}
	ctx := context.Background()

	status, body = 200, `{"access_token":"at","expires_in":900,"expires_at":"2030-01-02T03:04:05Z","principal":"p","host":"h","audience":"",`+
		`"external_audience_suffixes":null,"refresh_token":"","registration_expires_at":"","error":"","reason":"","error_description":"","new_field":{"x":[1]}}`
	tr, err := c.tokenRequest(ctx, url.Values{})
	if err != nil || tr.AccessToken != "at" || tr.ExpiresIn != 900 || tr.AudienceSuffixes != nil || tr.Principal != "p" {
		t.Errorf("ok response: %+v %v", tr, err)
	}
	status, body = 200, `{"access_token":"at","external_audience_suffixes":[".example.net"]}`
	if tr, err := c.tokenRequest(ctx, url.Values{}); err != nil || !slices.Equal(tr.AudienceSuffixes, []string{".example.net"}) {
		t.Errorf("suffixes: %+v %v", tr, err)
	}
	status, body = 400, `{"error":"invalid_grant","reason":"reused","error_description":"x"}`
	if _, err := c.tokenRequest(ctx, url.Values{}); err != ErrRefreshReused {
		t.Errorf("reused: %v", err)
	}
	status, body = 403, `{"error":"forbidden","principal":"p","host":"h","refresh_token":"iapr_r","registration_expires_at":"2030-01-02T03:04:05Z"}`
	tr, err = c.tokenRequest(ctx, url.Values{})
	if fe, ok := err.(*ForbiddenError); !ok || fe.Principal != "p" || tr.RefreshToken != "iapr_r" {
		t.Errorf("forbidden: %+v %v", tr, err)
	}
	status, body = 400, `{"error":"bad_request","error_description":"no grant_type"}`
	if _, err := c.tokenRequest(ctx, url.Values{}); err == nil || err.Error() != "token endpoint: HTTP 400 bad_request no grant_type" {
		t.Errorf("other error: %v", err)
	}
}

// Secret refuses every JSON route, in v2 and v1, directly, by pointer, in a
// struct, a slice, as a map value and as a map key, and with the
// compatibility options in force.
func TestSecretRefusesJSONV2(t *testing.T) {
	s := NewSecret("tok-SECRET")
	tok := Token{Value: s, Host: "h"}
	type wrapper struct {
		S Secret `json:"s,omitempty"`
	}
	for name, v := range map[string]any{
		"value": s, "pointer": &s, "token": tok, "token pointer": &tok, "struct": wrapper{S: s},
		"slice": []Secret{s}, "map value": map[string]Secret{"k": s}, "map key": map[Secret]string{s: "v"},
	} {
		if b, err := json.Marshal(v); err == nil {
			t.Errorf("v2 %s marshalled: %s", name, b)
		}
		if b, err := json.Marshal(v, json.Deterministic(true), json.FormatNilSliceAsNull(true)); err == nil {
			t.Errorf("v2 %s marshalled with options: %s", name, b)
		}
		if b, err := jsonv1.Marshal(v); err == nil {
			t.Errorf("v1 %s marshalled: %s", name, b)
		}
	}
	// The zero Secret refuses too.
	if b, err := json.Marshal(Secret{}); err == nil {
		t.Errorf("zero secret marshalled: %s", b)
	}
	if b, err := s.AppendText(nil); err == nil || b != nil {
		t.Errorf("AppendText = %q, %v", b, err)
	}
	if b, err := s.AppendBinary(nil); err == nil || b != nil {
		t.Errorf("AppendBinary = %q, %v", b, err)
	}
}

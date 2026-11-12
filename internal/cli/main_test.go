package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/R167/iap/iapclient"
)

const host = "app.iap.r167.dev"

func TestCheckCurlArgsRefuses(t *testing.T) {
	for name, args := range map[string][]string{
		"second URL":                    {"https://evil.example.com/"},
		"second URL, same host":         {"-s", "https://app.iap.r167.dev/other"},
		"bare word":                     {"x"},
		"--":                            {"--", "https://evil.example.com/"},
		"--next":                        {"--next"},
		"-:":                            {"-:"},
		"--resolve":                     {"--resolve", "app.iap.r167.dev:443:1.2.3.4"},
		"--connect-to":                  {"--connect-to", "::evil:443"},
		"-k":                            {"-k"},
		"-sk":                           {"-sk"},
		"--insecure":                    {"--insecure"},
		"--cacert":                      {"--cacert", "ca.pem"},
		"--capath":                      {"--capath", "/tmp"},
		"-x":                            {"-x", "http://proxy:8080"},
		"--proxy":                       {"--proxy=http://proxy:8080"},
		"--preproxy":                    {"--preproxy", "socks5://p"},
		"--proxy-header":                {"--proxy-header", "X: y"},
		"--proxytunnel":                 {"--proxytunnel"},
		"--unix-socket":                 {"--unix-socket", "/tmp/s"},
		"--abstract-unix-socket":        {"--abstract-unix-socket", "s"},
		"--interface":                   {"--interface", "en0"},
		"--dns-servers":                 {"--dns-servers", "1.1.1.1"},
		"-L":                            {"-L"},
		"-sL":                           {"-sL"},
		"--location":                    {"--location"},
		"--location-trusted":            {"--location-trusted"},
		"-K":                            {"-K", "cfg"},
		"--config":                      {"--config=cfg"},
		"-v":                            {"-v"},
		"-sv":                           {"-sv"},
		"--verbose":                     {"--verbose"},
		"--trace":                       {"--trace", "f"},
		"--trace-ascii":                 {"--trace-ascii=f"},
		"--trace-time":                  {"--trace-time"},
		"--libcurl":                     {"--libcurl", "out.c"},
		"--url":                         {"--url", "https://evil.example.com/"},
		"abbreviation":                  {"--sil"},
		"-H Proxy-Authorization":        {"-H", "Proxy-Authorization: Bearer x"},
		"-H authorization, joined":      {"-HAuthorization: Basic x"},
		"--header=Host":                 {"--header=host: evil.example.com"},
		"-H empty Host;":                {"-H", "Host;"},
		"-H from a file":                {"-H", "@headers.txt"},
		"--header from a file":          {"--header", "@/dev/fd/3"},
		"-H with a line break":          {"-H", "X-A: 1\r\nProxy-Authorization: x"},
		"value option with no value":    {"-X"},
		"flag option given a value":     {"--silent=yes"},
		"joined value after a flag":     {"-sHAuthorization: x"},
		"refused option after a value":  {"-o", "out", "-v"},
		"refused option in a value pos": {"-d", "x", "-k"},
	} {
		if _, err := checkCurlArgs(args); err == nil {
			t.Errorf("%s: checkCurlArgs(%q) allowed", name, args)
		}
	}
}

func TestCheckCurlArgsAllows(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-s", "-S", "-f", "-i", "-X", "POST", "-H", "Accept: application/json", "-H", "Content-Type: application/json"},
		{"-sSf", "-XPOST", "-d", `{"k":"v"}`, "-o", "out.json", "--compressed", "-w", "%{http_code}\n"},
		{"--max-time", "10", "--connect-timeout=5", "--data-raw", "-v", "--json", `{"a":1}`, "-G", "--data-urlencode", "q=x y"},
		{"-A", "iap-cli", "-e", "https://x/", "--retry", "2", "-b", "a=b", "-r", "0-99", "-O", "-I", "--fail-with-body"},
		{"-F", "file=@report.pdf", "--data-binary", "@body.bin", "--header=X-Trace: 1", "-HX-Joined: yes"},
	} {
		if _, err := checkCurlArgs(args); err != nil {
			t.Errorf("checkCurlArgs(%q): %v", args, err)
		}
	}
}

// curl itself rejects --opt=value, so it is handed over as two arguments;
// every other form passes through unchanged.
func TestCheckCurlArgsNormalises(t *testing.T) {
	got, err := checkCurlArgs([]string{"-sS", "--max-time=5", "--header=X-A: 1", "-HX-B: 2", "-X", "POST", "--compressed", "-d", "x=1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-sS", "--max-time", "5", "--header", "X-A: 1", "-HX-B: 2", "-X", "POST", "--compressed", "-d", "x=1"}
	if !slices.Equal(got, want) {
		t.Errorf("checkCurlArgs = %q, want %q", got, want)
	}
}

func TestCurlCommandPassesTokenOnAPipe(t *testing.T) {
	const token = "eyJ.secret-token.sig"
	cmd, cleanup, err := curlCommand(context.Background(), "Proxy-Authorization", iapclient.NewSecret(token), "https://"+host+"/api", []string{"-s", "-X", "POST"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, a := range cmd.Args {
		if strings.Contains(a, token) {
			t.Fatalf("token on argv: %q", cmd.Args)
		}
	}
	for _, e := range cmd.Env {
		if strings.Contains(e, token) {
			t.Fatal("token in the environment")
		}
	}
	want := []string{"curl", "-q", "-H", "@/dev/fd/3", "https://" + host + "/api", "-s", "-X", "POST"}
	if !slices.Equal(cmd.Args, want) {
		t.Errorf("argv = %q, want %q", cmd.Args, want)
	}
	if len(cmd.ExtraFiles) != 1 {
		t.Fatalf("ExtraFiles = %d, want 1 (fd 3)", len(cmd.ExtraFiles))
	}
	b, err := io.ReadAll(cmd.ExtraFiles[0])
	if err != nil || string(b) != "Proxy-Authorization: Bearer "+token+"\n" {
		t.Errorf("pipe = %q, %v", b, err)
	}
	if _, _, err := curlCommand(context.Background(), "Proxy-Authorization", iapclient.NewSecret("a\nb"), "https://"+host+"/", nil); err == nil {
		t.Error("a token with a line break was accepted")
	}
}

// TestCurlCommandRealCurl proves -H @/dev/fd/3 delivers the header through
// the real curl binary.
func TestCurlCommandRealCurl(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Proxy-Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	cmd, cleanup, err := curlCommand(context.Background(), "Proxy-Authorization", iapclient.NewSecret("tok123"), srv.URL+"/x", []string{"-s", "--noproxy", "*"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("curl: %v: %s", err, out.String())
	}
	if got != "Bearer tok123" || out.String() != "ok" {
		t.Errorf("server saw %q, curl printed %q", got, out.String())
	}
}

func TestSplitCurlArgs(t *testing.T) {
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	f, rest, err := splitCurlArgs([]string{"--session", "work", "https://" + host + "/", "-s"})
	if err != nil || f.session != "work" || !slices.Equal(rest, []string{"https://" + host + "/", "-s"}) {
		t.Errorf("--session: %q %q %v", f.session, rest, err)
	}
	if f, _, _ := splitCurlArgs([]string{"https://" + host + "/"}); f.session != "cli" {
		t.Errorf("default session = %q", f.session)
	}
	t.Setenv("CLAUDE_CODE_SESSION_ID", "0F8E6A1C-2B3D-4E5F-8A9B-0C1D2E3F4A5B")
	if f, _, _ := splitCurlArgs([]string{"--session=work", "https://" + host + "/"}); f.session != "0f8e6a1c-2b3d-4e5f-8a9b-0c1d2e3f4a5b" {
		t.Errorf("Claude session = %q", f.session)
	}
	for _, bad := range [][]string{{}, {"--session", "x"}, {"-v", "https://" + host + "/"}} {
		if _, _, err := splitCurlArgs(bad); err == nil {
			t.Errorf("splitCurlArgs(%q) accepted", bad)
		}
	}
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	if _, _, err := splitCurlArgs([]string{"--session", "Bad:*", "https://" + host + "/"}); err == nil {
		t.Error("bad session accepted")
	}
}

// isolate points the config and state directories at a temp dir and resets
// the root flags.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	flagIssuer, flagStore = "", ""
	t.Cleanup(func() { flagIssuer, flagStore = "", "" })
	dir, err := iapclient.DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// The saved issuer and store are used unless flagged; a flagged issuer must be
// a plain https host; the refresh credential is never sent to an issuer other
// than the one it was registered with.
func TestClientResolution(t *testing.T) {
	dir := isolate(t)
	const acct = "agent:user:alice@example.com:box:cli"
	if err := iapclient.SaveState(dir, "cli", iapclient.State{Issuer: defaultIssuer, Account: acct, Store: iapclient.StoreFile}); err != nil {
		t.Fatal(err)
	}
	s, err := loadSession()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.client("cli")
	if err != nil || c.Issuer() != defaultIssuer || c.Store().Name() != iapclient.StoreFile {
		t.Fatalf("client = %v, %v", c, err)
	}
	if _, err := c.CheckURL("https://App.iap.r167.dev/api"); err != nil {
		t.Errorf("default issuer's domain refused: %v", err)
	}
	for bad, msg := range map[string]string{
		"https://app.iap.r167.dev.evil.com/": `"https://app.iap.r167.dev.evil.com/": the host must be under iap.r167.dev`,
		"http://app.iap.r167.dev/":           `"http://app.iap.r167.dev/": want an https:// URL`,
	} {
		if _, err := c.CheckURL(bad); err == nil || err.Error() != msg {
			t.Errorf("CheckURL(%q) = %v, want %q", bad, err, msg)
		}
	}
	for _, f := range []string{"http://access.iap.r167.dev", "https://access.iap.r167.dev:8443", "https://access.iap.r167.dev/x", "https://u@access.iap.r167.dev"} {
		flagIssuer = f
		if _, err := s.client("cli"); err == nil {
			t.Errorf("--issuer %q accepted", f)
		}
	}
	flagIssuer = "https://access.iap.r167.dev.evil.com"
	c, err = s.client("cli")
	if err != nil {
		t.Fatal(err)
	}
	var mismatch *iapclient.IssuerMismatchError
	if _, err := c.TokenSource("cli"); !errors.As(err, &mismatch) {
		t.Errorf("credential offered to another issuer: %v", err)
	}
	flagIssuer, flagStore = "", "vault"
	if _, err := s.client("cli"); err == nil {
		t.Error("unknown --store accepted")
	}
}

// A host outside .iap.r167.dev is a target only under a suffix the server
// named at login (external_audience_suffixes), and only a well-formed one
// that does not widen the issuer's own domain. The config may hold the
// server's wire name, as the pre-iapclient CLI wrote it.
func TestCheckURLExternal(t *testing.T) {
	dir := isolate(t)
	const acct = "agent:user:alice@example.com:box:cli"
	cfg := `{"server":"` + defaultIssuer + `","account":"` + acct + `","store":"file",` +
		`"external_audience_suffixes":[".iap.Example.net",".com","example.org.",".r167.dev",".x.iap.r167.dev"]}`
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(iapclient.StatePath(dir), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := loadSession()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.client("cli")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.AllowedSuffixes(); !slices.Equal(got, []string{".iap.r167.dev", ".iap.example.net"}) {
		t.Errorf("AllowedSuffixes = %q", got)
	}
	if h, err := c.CheckURL("https://App.iap.Example.net/x"); err != nil || h != "app.iap.example.net" {
		t.Errorf("external = %q, %v", h, err)
	}
	if h, err := c.CheckURL("https://app.iap.r167.dev/"); err != nil || h != host {
		t.Errorf("local with external = %q, %v", h, err)
	}
	for _, bad := range []string{
		"http://app.iap.example.net/", "https://iap.example.net/", "https://eviliap.example.net/",
		"https://app.iap.example.net.evil.org/", "https://u@app.iap.example.net/", "https://app.example.com/",
		"https://x.r167.dev/",
	} {
		if _, err := c.CheckURL(bad); err == nil {
			t.Errorf("CheckURL(%q) accepted", bad)
		}
	}
}

func TestStatusOutput(t *testing.T) {
	dir := isolate(t)
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	var out bytes.Buffer
	if err := runStatus(context.Background(), &out); err != nil || !strings.HasPrefix(out.String(), "not logged in (") {
		t.Fatalf("logged out status = %q, %v", out.String(), err)
	}
	exp := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := iapclient.SaveState(dir, "cli", iapclient.State{Issuer: defaultIssuer, Account: "agent:user:alice@example.com:box:cli", ExpiresAt: exp, Store: iapclient.StoreFile}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runStatus(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	want := []string{
		"registration: agent:user:alice@example.com:box:cli:* (used here)",
		"server:       https://access.iap.r167.dev",
		"expires:      " + exp.Local().Format(time.RFC3339),
		"status:       expired (",
		"file:         " + filepath.Join(os.Getenv("XDG_STATE_HOME"), "iap", "credentials.json") + " MISSING (",
		"",
		"revoke:       on the access page",
	}
	if len(lines) != len(want) {
		t.Fatalf("status:\n%s", out.String())
	}
	for i := range want {
		if !strings.HasPrefix(lines[i], want[i]) {
			t.Errorf("line %d = %q, want prefix %q", i, lines[i], want[i])
		}
	}
}

func TestSplitCurlArgsClientID(t *testing.T) {
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	f, rest, err := splitCurlArgs([]string{"--client-id", "Abc1CNTRL-x2", "https://api.tailscale.com/api/v2/tailnet/-/dns/nameservers", "-s"})
	if err != nil || f.clientID != "Abc1CNTRL-x2" || len(rest) != 2 {
		t.Errorf("--client-id: %+v %q %v", f, rest, err)
	}
	if f, _, err := splitCurlArgs([]string{"--client-id=Abc", "https://api.tailscale.com/"}); err != nil || f.clientID != "Abc" {
		t.Errorf("--client-id=: %+v %v", f, err)
	}
	for _, bad := range []string{"a/b", "a b", "a:b"} {
		if _, _, err := splitCurlArgs([]string{"--client-id=" + bad, "https://api.tailscale.com/"}); err == nil {
			t.Errorf("client id %q accepted", bad)
		}
	}
}

func TestSplitCurlArgsProgram(t *testing.T) {
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	if f, _, err := splitCurlArgs([]string{"https://" + host + "/"}); err != nil || f.program != "cli" {
		t.Errorf("terminal default = %+v %v", f, err)
	}
	t.Setenv("CLAUDE_CODE_SESSION_ID", "abc")
	if f, _, err := splitCurlArgs([]string{"https://" + host + "/"}); err != nil || f.program != "claude" {
		t.Errorf("Claude default = %+v %v", f, err)
	}
	if f, _, err := splitCurlArgs([]string{"--program", "cli", "https://" + host + "/"}); err != nil || f.program != "cli" {
		t.Errorf("--program = %+v %v", f, err)
	}
	if _, _, err := splitCurlArgs([]string{"--program=Bad:*", "https://" + host + "/"}); err == nil {
		t.Error("bad program accepted")
	}
}

func TestTailscaleTarget(t *testing.T) {
	if h, err := tailscaleTarget("https://api.tailscale.com/api/v2/tailnet/-/dns/nameservers"); err != nil || h != "api.tailscale.com" {
		t.Errorf("ok URL: %q %v", h, err)
	}
	for _, bad := range []string{"http://api.tailscale.com/", "https://api.tailscale.com:8443/", "https://u@api.tailscale.com/", "https://evil.com/api.tailscale.com", "https://api.tailscale.com.evil.com/"} {
		if _, err := tailscaleTarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTailscaleExchange(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.PostForm
		if r.PostForm.Get("jwt") == "bad" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"message":"invalid jwt"}`)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"tskey-api-x","token_type":"Bearer","expires_in":3600}`)
	}))
	defer srv.Close()
	tok, err := tailscaleExchange(context.Background(), srv.URL, "cid", iapclient.NewSecret("the.jwt.sig"))
	if err != nil || tok.Reveal() != "tskey-api-x" || got.Get("client_id") != "cid" || got.Get("jwt") != "the.jwt.sig" {
		t.Errorf("exchange = %v, form %v", err, got)
	}
	_, err = tailscaleExchange(context.Background(), srv.URL, "cid", iapclient.NewSecret("bad"))
	if err == nil || !strings.Contains(err.Error(), "invalid jwt") {
		t.Errorf("refusal = %v", err)
	}
}

// The config written by the CLI before iapclient (one registration per
// program, a top-level server, the saved Tailscale client ID) is read as is:
// each program's registration with that server as its issuer, and the
// client ID still offered to curl. A login of one program keeps the others.
func TestPerProgramConfig(t *testing.T) {
	dir := isolate(t)
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	old := `{"server":"` + defaultIssuer + `","registrations":{` +
		`"claude":{"account":"agent:user:alice@example.com:mac:claude","expires_at":"2030-01-02T03:04:05Z"},` +
		`"cli":{"account":"agent:user:alice@example.com:mac:cli","expires_at":"2030-01-02T03:04:05Z"}},` +
		`"tailscale_client_id":"Tclient1"}`
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(iapclient.StatePath(dir), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	flagStore = iapclient.StoreFile
	s, err := loadSession()
	if err != nil {
		t.Fatal(err)
	}
	if s.file.TailscaleClientID != "Tclient1" {
		t.Errorf("client id = %q", s.file.TailscaleClientID)
	}
	for _, p := range []string{"claude", "cli"} {
		c, err := s.client(p)
		if err != nil {
			t.Fatal(err)
		}
		if c.State().Account != "agent:user:alice@example.com:mac:"+p || c.Issuer() != defaultIssuer {
			t.Errorf("%s: %+v at %s", p, c.State(), c.Issuer())
		}
		if _, err := c.TokenSource("s1"); err != nil {
			t.Errorf("%s: %v (its credential would go to the wrong issuer?)", p, err)
		}
	}
	var out bytes.Buffer
	if err := runStatus(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"agent:user:alice@example.com:mac:claude:*\n", "agent:user:alice@example.com:mac:cli:* (used here)\n", "client id Tclient1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, out.String())
		}
	}
	if err := iapclient.SaveState(dir, "cli", iapclient.State{Issuer: defaultIssuer, Account: "agent:user:alice@example.com:mac2:cli"}); err != nil {
		t.Fatal(err)
	}
	f, err := iapclient.LoadStateFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f.Registrations["claude"].Account != "agent:user:alice@example.com:mac:claude" || f.TailscaleClientID != "Tclient1" {
		t.Errorf("after a cli login: %+v", f)
	}
}

// An issuer that advertises .tailscale.com never gets api.tailscale.com
// treated as one of its hosts: the Tailscale path (federated token, exchanged)
// wins, and a near miss on that host is refused outright.
func TestCurlTargetTailscaleFirst(t *testing.T) {
	dir := isolate(t)
	cfg := `{"server":"` + defaultIssuer + `","account":"agent:user:alice@example.com:box:cli","store":"file",` +
		`"external_audience_suffixes":[".tailscale.com"]}`
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(iapclient.StatePath(dir), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := loadSession()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.client("cli")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CheckURL("https://api.tailscale.com/x"); err != nil {
		t.Fatalf("setup: the advertised suffix is not allowed: %v", err)
	}
	if h, ts, err := curlTarget(c, "https://API.tailscale.com/api/v2/x"); err != nil || !ts || h != "api.tailscale.com" {
		t.Errorf("tailscale = %q, %v, %v", h, ts, err)
	}
	for _, bad := range []string{"https://api.tailscale.com:443/x", "https://u@api.tailscale.com/x"} {
		if h, ts, err := curlTarget(c, bad); err == nil {
			t.Errorf("%s: accepted as %q (tailscale %v)", bad, h, ts)
		}
	}
	if h, ts, err := curlTarget(c, "https://login.tailscale.com/x"); err != nil || ts || h != "login.tailscale.com" {
		t.Errorf("other advertised host = %q, %v, %v", h, ts, err)
	}
}

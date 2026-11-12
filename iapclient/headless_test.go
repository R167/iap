package iapclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// pkceIssuer is the issuer side of a headless login: approve hands out a
// code bound to a challenge, and the token endpoint spends it once, only with
// the matching verifier (a wrong verifier burns it, as iap-authz does).
type pkceIssuer struct {
	mu        sync.Mutex
	codes     map[string]string // code -> challenge; deleted when tried
	verifiers []string          // every verifier the endpoint received
	principal string            // the registration it answers with; default testAccount:*
}

func (p *pkceIssuer) approve(challenge string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.codes == nil {
		p.codes = map[string]string{}
	}
	code := fmt.Sprintf("%043d", len(p.codes)+1)
	code = "code_" + code[5:]
	p.codes[code] = challenge
	return code
}

func (p *pkceIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	code, verifier := r.PostFormValue("code"), r.PostFormValue("code_verifier")
	p.verifiers = append(p.verifiers, verifier)
	challenge, ok := p.codes[code]
	delete(p.codes, code)
	sum := sha256.Sum256([]byte(verifier))
	if r.PostFormValue("grant_type") != "authorization_code" || !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	principal := p.principal
	if principal == "" {
		principal = testAccount + ":*"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"refresh_token": testRefresh, "principal": principal, "expires_at": "2030-01-02T03:04:05Z",
	})
}

var promptURLRE = regexp.MustCompile(`https://\S+`)

// consentURL is the URL a headless login printed.
func consentURL(t *testing.T, prompt string) *url.URL {
	t.Helper()
	m := promptURLRE.FindString(prompt)
	u, err := url.Parse(m)
	if m == "" || err != nil {
		t.Fatalf("no URL in prompt:\n%s", prompt)
	}
	return u
}

func headlessClient(t *testing.T, p *pkceIssuer) (*Client, *memStore, string) {
	t.Helper()
	dir := t.TempDir()
	store := &memStore{}
	c, err := New(Config{Issuer: testIssuer, Dir: dir, Store: store, HTTPClient: &http.Client{Transport: &handlerTransport{h: p}}})
	if err != nil {
		t.Fatal(err)
	}
	return c, store, dir
}

func TestRequestCheckVector(t *testing.T) {
	// The RFC 7636 appendix B verifier's challenge; iap-authz's
	// TestRequestCheckVector pins the same value.
	if got := RequestCheck("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"); got != "MOAE-TRCS" {
		t.Errorf("RequestCheck = %q", got)
	}
}

// A headless login prints a consent URL with no redirect target, tells the
// person what the page must show, reads the code from ReadCode, and spends it
// with the verifier only this process holds. Neither the code nor the
// verifier nor the credential is ever printed.
func TestLoginHeadless(t *testing.T) {
	p := &pkceIssuer{}
	c, store, dir := headlessClient(t, p)
	var prompt bytes.Buffer
	var code string
	read := 0
	readCode := func() (string, error) {
		read++
		if read == 1 {
			return "  not a code\n", nil // malformed: asked again, not consumed
		}
		u := consentURL(t, prompt.String())
		q := u.Query()
		if u.Host != "access.example.test" || u.Path != "/agents/authorize" || q.Get("mode") != "headless" ||
			q.Has("port") || q.Has("state") || q.Get("machine") != "box" || q.Get("program") != "cli" ||
			q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 {
			t.Errorf("consent URL = %s", u)
		}
		if want := "mix-up check " + RequestCheck(q.Get("code_challenge")); !strings.Contains(prompt.String(), want) {
			t.Errorf("prompt does not show %q:\n%s", want, prompt.String())
		}
		code = p.approve(q.Get("code_challenge"))
		return " " + code + "\r\n", nil // whitespace from a paste is trimmed
	}
	reg, err := c.Login(context.Background(), LoginOptions{Machine: "box", Program: "cli", Headless: true, ReadCode: readCode, Prompt: &prompt, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("Login: %v\n%s", err, prompt.String())
	}
	if read != 2 || !strings.Contains(prompt.String(), "not a login code") {
		t.Errorf("malformed paste not asked again (reads %d):\n%s", read, prompt.String())
	}
	if reg.Account != testAccount || store.m[testAccount] != testRefresh {
		t.Errorf("registration %+v, store %v", reg, store.m)
	}
	if st, _ := LoadState(dir, "cli"); st.Account != testAccount || st.Issuer != testIssuer {
		t.Errorf("state = %+v", st)
	}
	b, _ := os.ReadFile(StatePath(dir))
	out := prompt.String() + string(b) + fmt.Sprintf("%+v", reg)
	for _, secret := range append([]string{code, testRefresh, "not a code"}, p.verifiers...) {
		if strings.Contains(out, secret) {
			t.Errorf("%q printed or saved:\n%s", secret, out)
		}
	}
}

// The code alone is useless: another process (another verifier) spending it
// is refused, the code is gone afterwards, and the error carries neither.
func TestLoginHeadlessCodeNeedsThisVerifier(t *testing.T) {
	p := &pkceIssuer{}
	victim, _, _ := headlessClient(t, p)
	attacker, attackerStore, _ := headlessClient(t, p)

	var vPrompt bytes.Buffer
	stolen := make(chan string, 1)
	victimDone := make(chan error, 1)
	go func() {
		_, err := victim.Login(context.Background(), LoginOptions{Machine: "box", Headless: true, Prompt: &vPrompt, Timeout: 5 * time.Second,
			ReadCode: func() (string, error) {
				code := p.approve(consentURL(t, vPrompt.String()).Query().Get("code_challenge"))
				stolen <- code
				<-time.After(200 * time.Millisecond) // the attacker pastes it first
				return code, nil
			}})
		victimDone <- err
	}()
	code := <-stolen
	var aPrompt bytes.Buffer
	_, err := attacker.Login(context.Background(), LoginOptions{Machine: "box", Headless: true, Prompt: &aPrompt, Timeout: 5 * time.Second,
		ReadCode: func() (string, error) { return code, nil }})
	if !errors.Is(err, ErrInvalidGrant) || len(attackerStore.m) != 0 {
		t.Fatalf("stolen code with another verifier = %v, store %v", err, attackerStore.m)
	}
	if strings.Contains(err.Error(), code) || strings.Contains(aPrompt.String(), code) {
		t.Errorf("the code was printed: %v\n%s", err, aPrompt.String())
	}
	// The attacker's try burned it, as the issuer does.
	if err := <-victimDone; !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("victim after the code was burned = %v", err)
	}
}

func TestLoginHeadlessRefusals(t *testing.T) {
	c, _, _ := headlessClient(t, &pkceIssuer{})
	if _, err := c.Login(context.Background(), LoginOptions{Machine: "box", Headless: true, Port: 18765, Prompt: &bytes.Buffer{}}); err == nil {
		t.Error("headless login with a port accepted")
	}
	// Three malformed pastes end the login without echoing any of them.
	var prompt bytes.Buffer
	_, err := c.Login(context.Background(), LoginOptions{Machine: "box", Headless: true, Prompt: &prompt,
		ReadCode: func() (string, error) { return "garbage-paste-SECRETISH", nil }})
	if err == nil || strings.Contains(err.Error()+prompt.String(), "SECRETISH") {
		t.Errorf("malformed pastes = %v\n%s", err, prompt.String())
	}
	// Closed stdin is an error, not a hang.
	if _, err := c.Login(context.Background(), LoginOptions{Machine: "box", Headless: true, Prompt: &bytes.Buffer{},
		ReadCode: func() (string, error) { return "", errors.New("no input") }}); err == nil {
		t.Error("read error ignored")
	}
	// Nobody pastes: the login times out.
	block := make(chan struct{})
	defer close(block)
	_, err = c.Login(context.Background(), LoginOptions{Machine: "box", Headless: true, Prompt: &bytes.Buffer{}, Timeout: 100 * time.Millisecond,
		ReadCode: func() (string, error) { <-block; return "", nil }})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("no paste = %v", err)
	}
}

// The issuer answering with another program's registration than the one
// asked for fails the login: filing it under the returned name would replace
// that program's credential.
func TestLoginProgramMismatch(t *testing.T) {
	p := &pkceIssuer{principal: "agent:user:alice@example.com:box:claude:*"}
	c, store, dir := headlessClient(t, p)
	var prompt bytes.Buffer
	_, err := c.Login(context.Background(), LoginOptions{Machine: "box", Program: "cli", Headless: true, Prompt: &prompt, Timeout: 5 * time.Second,
		ReadCode: func() (string, error) {
			return p.approve(consentURL(t, prompt.String()).Query().Get("code_challenge")), nil
		}})
	if err == nil || !strings.Contains(err.Error(), `program "claude", not "cli"`) {
		t.Fatalf("Login = %v", err)
	}
	if strings.Contains(err.Error(), testRefresh) {
		t.Error("the refresh credential is in the error")
	}
	for acct := range store.m {
		if acct != "agent:user:store-check" {
			t.Errorf("credential saved under %s", acct)
		}
	}
	for _, prog := range []string{"cli", "claude"} {
		if st, _ := LoadState(dir, prog); st.Account != "" {
			t.Errorf("state saved for %s: %+v", prog, st)
		}
	}
}

package iapclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultLoginTimeout bounds the wait for the browser consent.
const DefaultLoginTimeout = 5 * time.Minute

// DefaultHeadlessTimeout bounds a headless login, which waits for a person
// to sign in on another device and paste the code back.
const DefaultHeadlessTimeout = 10 * time.Minute

// LoginOptions configures Login.
type LoginOptions struct {
	Machine string // default DefaultMachine()
	Program string // default Config.Program, else "cli"
	// Port is the loopback callback port; 0 picks a free one. Fix it (1024–
	// 65535) to forward it over SSH from another machine's browser.
	Port int
	// OpenBrowser opens the consent URL; nil prints it only. OpenURL is the
	// platform default. Not used by a headless login.
	OpenBrowser func(ctx context.Context, url string) error
	// Prompt receives the consent URL and instructions (default os.Stderr).
	Prompt  io.Writer
	Timeout time.Duration // default DefaultLoginTimeout, or DefaultHeadlessTimeout

	// Headless logs in without a loopback listener or a browser on this
	// machine: the person opens the printed URL on any device, approves, and
	// the issuer shows a one-time code to paste back here. The issuer accepts
	// the code only with the PKCE verifier, which never leaves this process.
	Headless bool
	// ReadCode reads the pasted code (headless only). Default: one line from
	// os.Stdin, with terminal echo off (stty) while reading when stdin is a
	// terminal, restored however Login returns. Login never prints or logs
	// what it reads. A caller that wants echo restored on SIGINT too must
	// handle the signal itself (the iap CLI does).
	ReadCode func() (string, error)
	// StoreFallback records that Config.Store was chosen only because no OS
	// keyring worked (State.StoreFallback), so the next login tries the
	// keyring again instead of treating the store as the person's choice.
	StoreFallback bool
	// SaveFallback is called when Config.Store refuses the refresh credential
	// after the code exchange, while the credential is still in memory, with
	// the store's name and error (never a secret). A non-nil Store it returns
	// is tried instead; on success the login proceeds with that store,
	// recorded as a fallback (State.StoreFallback). nil keeps the
	// CredentialLostError.
	SaveFallback func(store string, err error) Store
}

// loginCodeRE is the issuer's login code: base64url of 32 random bytes.
var loginCodeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// RequestCheck is the mix-up check the issuer's headless consent page shows
// for a PKCE challenge (two logins at once, the wrong tab): base32 of the
// first five bytes of sha256("iap login request\x00" || challenge), as
// XXXX-XXXX. It is derived from the public challenge, so anyone holding the
// link can quote it: it never proves a link is yours, and authorizes nothing.
func RequestCheck(challenge string) string {
	sum := sha256.Sum256([]byte("iap login request\x00" + challenge))
	s := base32.StdEncoding.EncodeToString(sum[:5])
	return s[:4] + "-" + s[4:]
}

// Registration is the result of a Login.
type Registration struct {
	Issuer           string
	Account          string // the principal pattern, without the trailing ":*"
	ExpiresAt        time.Time
	AudienceSuffixes []string
	Store            string
	Location         string
}

// DefaultMachine is the short hostname, sanitised, else "mac" on macOS and
// "host" elsewhere.
func DefaultMachine() string {
	h, _ := os.Hostname()
	h, _, _ = strings.Cut(h, ".")
	if m := SanitizeSegment(h); m != "" {
		return m
	}
	if runtime.GOOS == "darwin" {
		return "mac"
	}
	return "host"
}

// OpenURL opens u in the desktop browser: `open` on macOS, `xdg-open`
// elsewhere. It fails on a machine with no display.
func OpenURL(ctx context.Context, u string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.CommandContext(ctx, "open", u).Run()
	case "windows":
		return exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", u).Run()
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return errors.New("no display")
	}
	return exec.CommandContext(ctx, "xdg-open", u).Run()
}

// HasDisplay reports whether OpenURL can plausibly open a browser the user
// sees: not over SSH on macOS, and only with a display elsewhere.
func HasDisplay() bool {
	switch runtime.GOOS {
	case "darwin":
		return os.Getenv("SSH_CONNECTION") == ""
	case "windows":
		return true
	}
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

// randomB64 returns base64url(n random bytes), unpadded.
func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Login registers this machine and program with the issuer: it listens on
// 127.0.0.1:<port>, sends a browser to the issuer's consent page with a PKCE
// S256 challenge and a random state, receives a one-time code on /callback,
// trades it (with the verifier) for the refresh credential, stores that in
// the Store and saves the state. A person must approve in the browser; the
// issuer decides who may. With opts.Headless the code comes from the person
// instead (see LoginOptions.Headless); everything after it is the same.
func (c *Client) Login(ctx context.Context, opts LoginOptions) (Registration, error) {
	machine, program := opts.Machine, opts.Program
	if machine == "" {
		machine = DefaultMachine()
	}
	if program == "" {
		program = c.cfg.Program
	}
	if program == "" {
		program = "cli"
	}
	if !ValidSegment(machine) || !ValidSegment(program) {
		return Registration{}, fmt.Errorf("machine and program must match %s", SegmentPattern)
	}
	if opts.Port != 0 && (opts.Port < 1024 || opts.Port > 65535) {
		return Registration{}, errors.New("port must be 1024–65535")
	}
	prompt := opts.Prompt
	if prompt == nil {
		prompt = os.Stderr
	}
	if opts.Headless && opts.Port != 0 {
		return Registration{}, errors.New("a headless login has no callback port")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultLoginTimeout
		if opts.Headless {
			timeout = DefaultHeadlessTimeout
		}
	}
	// A store that fails only after the code is spent would lose the
	// credential, so ask it first.
	if err := CheckStore(ctx, c.cfg.Store); err != nil {
		return Registration{}, err
	}
	// The verifier never leaves this process until it goes, with the code, to
	// the token endpoint: whoever sees the code (on a screen, in a clipboard)
	// cannot spend it without it.
	verifier, err := randomB64(32)
	if err != nil {
		return Registration{}, err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{
		"machine":               {machine},
		"program":               {program},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	var code Secret
	if opts.Headless {
		code, err = c.headlessCode(ctx, q, opts, prompt, timeout)
	} else {
		code, err = c.loopbackCode(ctx, q, opts, prompt, timeout)
	}
	if err != nil {
		return Registration{}, err
	}
	tr, err := c.exchangeCode(ctx, code, verifier, prompt)
	if opts.Headless && errors.Is(err, ErrInvalidGrant) {
		return Registration{}, fmt.Errorf("the issuer refused the code (mistyped, already tried, older than its few minutes, or from another login): %w", err)
	}
	if err != nil {
		return Registration{}, err
	}
	if !strings.HasPrefix(tr.RefreshToken, "iapr_") || tr.Principal == "" {
		return Registration{}, errors.New("token endpoint returned no refresh credential")
	}
	// The issuer names the registration by its pattern, agent:user:<e>:<m>:<p>:*;
	// the store's account is the prefix without the "*".
	account := strings.TrimSuffix(tr.Principal, ":*")
	exp, _ := time.Parse(time.RFC3339, tr.ExpiresAt)
	// The credential is filed under its program, so a registration for
	// another program than the one asked for would replace that program's
	// login. Refuse it; the registration stays unusable at the issuer.
	if got := programOf(account); got != program {
		return Registration{}, fmt.Errorf("the issuer registered %s, for program %q, not %q as requested; nothing was saved. Revoke it in the Agents section of %s/#agents",
			safeText(tr.Principal), safeText(got), program, c.cfg.Issuer)
	}
	storeFallback := opts.StoreFallback
	// A token request from another process holds this lock while it may
	// save a rotated credential for the same account: wait, so it can't
	// overwrite this login's.
	unlock, err := c.lockRegistration(ctx, account)
	if err != nil {
		return Registration{}, &CredentialLostError{Principal: tr.Principal, Issuer: c.cfg.Issuer, ExpiresAt: exp, Store: c.cfg.Store.Name(), Err: err}
	}
	defer unlock()
	if err := c.cfg.Store.Save(ctx, account, NewSecret(tr.RefreshToken)); err != nil {
		lost := &CredentialLostError{Principal: tr.Principal, Issuer: c.cfg.Issuer, ExpiresAt: exp, Store: c.cfg.Store.Name(), Err: err}
		// The credential is still in memory: one chance to keep it elsewhere.
		var alt Store
		if opts.SaveFallback != nil {
			alt = opts.SaveFallback(c.cfg.Store.Name(), err)
		}
		if alt == nil {
			return Registration{}, lost
		}
		if aerr := alt.Save(ctx, account, NewSecret(tr.RefreshToken)); aerr != nil {
			lost.Err = fmt.Errorf("%v; then the %s store: %w", err, alt.Name(), aerr)
			return Registration{}, lost
		}
		c.cfg.Store, storeFallback = alt, true
	}
	var advertised []string
	for _, s := range tr.AudienceSuffixes {
		if n := normalizeSuffix(s); n != "" {
			advertised = append(advertised, n)
		}
	}
	c.state = State{Issuer: c.cfg.Issuer, Account: account, ExpiresAt: exp, AudienceSuffixes: advertised,
		Store: c.cfg.Store.Name(), StoreFallback: storeFallback}
	// Only what AllowedSuffixes keeps is ever used; say what is dropped.
	allowed := c.AllowedSuffixes()[1:]
	for _, s := range tr.AudienceSuffixes {
		if n := normalizeSuffix(s); n == "" || !slices.Contains(allowed, n) {
			fmt.Fprintf(prompt, "ignoring the issuer's audience suffix %q (not a domain, or it overlaps the issuer's own)\n", safeText(s))
		}
	}
	// Saved under the program the issuer registered (the account's last
	// segment); other programs' registrations stay. The client now uses this
	// registration.
	c.cfg.Program = programOf(account)
	if err := SaveState(c.cfg.Dir, c.cfg.Program, c.state); err != nil {
		return Registration{}, err
	}
	return Registration{
		Issuer: c.cfg.Issuer, Account: account, ExpiresAt: exp, AudienceSuffixes: allowed,
		Store: c.cfg.Store.Name(), Location: c.cfg.Store.Location(account),
	}, nil
}

// CredentialLostError: the issuer registered the agent and handed over its
// refresh credential, but the store refused it, so the credential is gone.
// The registration exists at the issuer (and can't be used by anyone) until
// it expires or is revoked.
type CredentialLostError struct {
	Principal string
	Issuer    string
	ExpiresAt time.Time
	Store     string
	Err       error
}

func (e *CredentialLostError) Error() string {
	return fmt.Sprintf("registered %s at %s, but the %s store refused its refresh credential (%v), so the credential is lost. "+
		"The registration stays on the issuer until %s, unusable; revoke it in the Agents section of %s/#agents, "+
		"fix the store (or choose another with --store) and log in again",
		e.Principal, e.Issuer, e.Store, e.Err, e.ExpiresAt.UTC().Format("2006-01-02"), e.Issuer)
}

func (e *CredentialLostError) Unwrap() error { return e.Err }

// exchangeRetryDelays are the waits between exchange attempts: a transient
// failure (network, 429, 5xx) must not discard a code that is still valid,
// and the whole schedule stays well inside the shortest code lifetime (60s).
var exchangeRetryDelays = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// exchangeCode trades the login code for the refresh credential, retrying
// transient failures. invalid_grant and any other answer from the issuer end
// it at once: the code is spent or wrong.
func (c *Client) exchangeCode(ctx context.Context, code Secret, verifier string, prompt io.Writer) (tokenResponse, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code.Reveal()}, "code_verifier": {verifier}}
	for attempt := 0; ; attempt++ {
		tr, err := c.tokenRequest(ctx, form)
		var te *transientError
		if err == nil || !errors.As(err, &te) || attempt == len(exchangeRetryDelays) {
			return tr, err
		}
		fmt.Fprintf(prompt, "token endpoint: %v; retrying\n", err)
		select {
		case <-time.After(exchangeRetryDelays[attempt]):
		case <-ctx.Done():
			return tokenResponse{}, ctx.Err()
		}
	}
}

// loopbackCode listens on 127.0.0.1, sends the browser to the consent page
// with that port and a random state, and returns the code the issuer
// redirects back with.
func (c *Client) loopbackCode(ctx context.Context, q url.Values, opts LoginOptions, prompt io.Writer, timeout time.Duration) (Secret, error) {
	state, err := randomB64(16)
	if err != nil {
		return Secret{}, err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", opts.Port))
	if err != nil {
		return Secret{}, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	codes := make(chan callbackResult, 1)
	srv := &http.Server{Handler: callbackHandler(state, codes), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	q.Set("port", fmt.Sprint(port))
	q.Set("state", state)
	authURL := c.cfg.Issuer + "/agents/authorize?" + q.Encode()
	if opts.OpenBrowser != nil {
		fmt.Fprintf(prompt, "Opening the consent page (waiting up to %s):\n  %s\n", timeout, authURL)
		if err := opts.OpenBrowser(ctx, authURL); err != nil {
			fmt.Fprintln(prompt, "Could not open a browser; open the URL above yourself.")
		}
	} else {
		fmt.Fprintf(prompt, "Open this URL in a browser (waiting up to %s):\n  %s\n", timeout, authURL)
		fmt.Fprintf(prompt, "The page redirects that browser to http://127.0.0.1:%d/callback, so it must run on this machine,\n"+
			"or forward the port first: ssh -L %d:127.0.0.1:%d <this machine>\n"+
			"(or log in with --headless and paste a code instead)\n", port, port, port)
	}

	var res callbackResult
	select {
	case res = <-codes:
	case <-time.After(timeout):
		return Secret{}, errors.New("timed out waiting for the browser")
	case <-ctx.Done():
		return Secret{}, ctx.Err()
	}
	if res.err != nil {
		return Secret{}, res.err
	}
	return NewSecret(res.code), nil
}

// maxCodeAttempts bounds how often a malformed paste is asked again. A
// well-formed but wrong code is never retried: the issuer burns it.
const maxCodeAttempts = 3

// headlessCode prints the consent URL (mode=headless: no port, no state, so
// the issuer redirects nowhere) and reads the code the person copies from
// the issuer's page. Nothing it reads is printed back.
func (c *Client) headlessCode(ctx context.Context, q url.Values, opts LoginOptions, prompt io.Writer, timeout time.Duration) (Secret, error) {
	q.Set("mode", "headless")
	authURL := c.cfg.Issuer + "/agents/authorize?" + q.Encode()
	readCode := opts.ReadCode
	if readCode == nil {
		read, restore, err := NoEchoStdin()
		if err != nil {
			return Secret{}, err
		}
		defer restore()
		readCode = read
	}
	fmt.Fprintf(prompt, "Open this URL on any device and sign in (waiting up to %s):\n  %s\n\n", timeout, authURL)
	fmt.Fprintf(prompt, "The page should show machine %s, program %s and mix-up check %s.\n",
		q.Get("machine"), q.Get("program"), RequestCheck(q.Get("code_challenge")))
	fmt.Fprintln(prompt, "If it does, click Register and paste the one-time code it shows (the input is not shown).")

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for attempt := 1; ; attempt++ {
		fmt.Fprint(prompt, "Paste the code and press Enter: ")
		type line struct {
			s   string
			err error
		}
		lines := make(chan line, 1)
		// A blocked read can't be cancelled; on timeout the goroutine is left
		// to the process's exit.
		go func() { s, err := readCode(); lines <- line{s, err} }()
		var l line
		select {
		case l = <-lines:
		case <-deadline.C:
			fmt.Fprintln(prompt)
			return Secret{}, errors.New("timed out waiting for the code")
		case <-ctx.Done():
			fmt.Fprintln(prompt)
			return Secret{}, ctx.Err()
		}
		if l.err != nil {
			return Secret{}, fmt.Errorf("reading the code: %w", l.err)
		}
		code := strings.TrimSpace(l.s)
		if loginCodeRE.MatchString(code) {
			return NewSecret(code), nil
		}
		if attempt == maxCodeAttempts {
			return Secret{}, errors.New("that is not a login code (43 letters, digits, - and _); start the login again")
		}
		fmt.Fprintln(prompt, "That is not a login code (43 letters, digits, - and _). Paste it again.")
	}
}

// NoEchoStdin returns a reader of one stdin line and a restore func. When
// stdin is a terminal it turns echo off with stty (saving the state with
// `stty -g`) and restore puts the saved state back; restore is idempotent and
// safe to call from another goroutine while read is blocked. When stdin is
// not a terminal (a pipe, a file, /dev/null), read is StdinLine and restore
// does nothing.
func NoEchoStdin() (read func() (string, error), restore func(), err error) {
	saved, err := stty("-g")
	if err != nil {
		return StdinLine, func() {}, nil // not a terminal
	}
	if _, err := stty("-echo"); err != nil {
		return nil, nil, fmt.Errorf("could not turn terminal echo off: %w", err)
	}
	var once sync.Once
	restore = func() { once.Do(func() { _, _ = stty(saved) }) }
	read = func() (string, error) {
		s, err := StdinLine()
		fmt.Fprintln(os.Stderr) // the newline the hidden input swallowed
		return s, err
	}
	return read, restore, nil
}

// stty runs stty on stdin's terminal.
func stty(args ...string) (string, error) {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// StdinLine reads one line from os.Stdin, byte by byte so nothing past the
// newline is consumed.
func StdinLine() (string, error) {
	var b strings.Builder
	buf := make([]byte, 1)
	for b.Len() < 1024 {
		n, err := os.Stdin.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				return b.String(), nil
			}
			b.WriteByte(buf[0])
		}
		if err == io.EOF {
			if b.Len() > 0 {
				return b.String(), nil
			}
			return "", errors.New("no input (stdin closed); run the login in a terminal")
		}
		if err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

type callbackResult struct {
	code string
	err  error
}

// callbackHandler receives the one-time code on /callback, checking state.
func callbackHandler(state string, out chan<- callbackResult) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		res := callbackResult{code: q.Get("code")}
		if e := q.Get("error"); e != "" {
			res = callbackResult{err: fmt.Errorf("login refused in the browser (%s)", safeText(e))}
		} else if res.code == "" {
			res = callbackResult{err: errors.New("callback without a code")}
		}
		select {
		case out <- res:
		default: // a second callback: the first one decides
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if res.err != nil {
			fmt.Fprintln(w, "Login cancelled. You can close this tab.")
			return
		}
		fmt.Fprintln(w, "Login complete. You can close this tab.")
	})
	return mux
}

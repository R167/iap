// Package cli is the iap command: it gives a local CLI or an AI coding agent
// short-lived, host-bound credentials for hosts behind an iap-authz
// identity-aware proxy (default issuer https://access.iap.r167.dev).
// Main runs it; cmd/iap and the module root are thin package main shims.
//
//	login   register agent:user:<you>:<machine>:<program> through the browser
//	        (loopback + PKCE); the refresh credential goes to the OS keyring.
//	        One registration per program (claude under Claude Code, else cli)
//	curl    run curl with a freshly minted access token, passed on a pipe;
//	        https://api.tailscale.com via a federated token and Tailscale's
//	        token exchange
//	expose  publish 127.0.0.1:<port> at https://<name>.<domain> through the
//	        tunnel service behind the IAP (./expose)
//	status  show every program's registration (no secrets)
//	logout  delete one program's stored credential
//
// No subcommand prints a token or the refresh credential. The library under
// it is github.com/R167/iap/iapclient; the tunnel client is
// github.com/R167/iap/expose.
package cli

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/R167/iap/iapclient"
	"github.com/R167/iap/internal/jsoncompat"
)

const defaultIssuer = "https://access.iap.r167.dev"

var (
	flagIssuer string
	flagStore  string
)

// Version is the release version, stamped at build time with
// -ldflags "-X github.com/R167/iap/internal/cli.Version=v1.2.3". Unstamped, it
// is the module version from the build info (go install ...@v1.2.3), else
// "dev".
var Version = "dev"

// version resolves Version as described there.
func version() string {
	if Version != "dev" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return Version
}

// Main runs the iap command with os.Args and returns the process exit status:
// 0 on success, the status of curl or of an expose -- command when it fails,
// else 1. Callers pass it to os.Exit. The headless login's code prompt may
// itself exit with 130 or 143 on SIGINT or SIGTERM, after restoring the
// terminal.
func Main() int {
	rootCmd.Version = version()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", withHint(err))
		var exit exitCode
		if errors.As(err, &exit) {
			return int(exit)
		}
		return 1
	}
	return 0
}

var rootCmd = &cobra.Command{
	Use:           "iap",
	Short:         "Agent credentials for hosts behind an iap-authz proxy (login, curl, expose, status, logout)",
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error once
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagIssuer, "issuer", "", "token issuer URL (default: the saved one, else "+defaultIssuer+")")
	pf.StringVar(&flagIssuer, "server", "", "same as --issuer")
	_ = pf.MarkHidden("server")
	pf.StringVar(&flagStore, "store", "", "where the refresh credential lives: auto (Keychain on macOS, secret-tool on Linux), keychain, secret-service, or file (opt-in, for headless machines); default: the one used at login, else auto")
	rootCmd.AddCommand(loginCmd, curlCmd, statusCmd, logoutCmd)
	rootCmd.SetVersionTemplate("iap {{.Version}}\n")
}

// cmdName is how to invoke this tool, for hints: `go run <main package>` when
// it runs from a go run build, else `iap`.
func cmdName() string {
	if exe, err := os.Executable(); err == nil && strings.Contains(filepath.ToSlash(exe), "/go-build") {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Path != "" {
			return "go run " + bi.Path
		}
	}
	return "iap"
}

// withHint adds what to do next to the library's errors.
func withHint(err error) error {
	var lost *iapclient.CredentialLostError
	switch {
	case errors.As(err, &lost) && lost.Store != iapclient.StoreFile:
		return fmt.Errorf("%w. Re-running with --store file avoids it: `%s login --store file`", err, cmdName())
	case errors.Is(err, iapclient.ErrNotLoggedIn):
		return fmt.Errorf("not logged in: run `%s login`", cmdName())
	case errors.Is(err, iapclient.ErrInvalidGrant), errors.Is(err, iapclient.ErrNoCredential):
		return fmt.Errorf("%w; run `%s login`", err, cmdName())
	case errors.Is(err, iapclient.ErrNoKeyring), errors.Is(err, iapclient.ErrSecretServiceUnavailable):
		return fmt.Errorf("%w (--store file)", err)
	}
	return err
}

// session holds what every subcommand resolves first: the state file, with
// one registration per program.
type session struct {
	dir  string
	file iapclient.StateFile
}

func loadSession() (session, error) {
	dir, err := iapclient.DefaultDir()
	if err != nil {
		return session{}, err
	}
	f, err := iapclient.LoadStateFile(dir)
	return session{dir: dir, file: f}, err
}

// state is program's saved registration (empty when there is none).
func (s session) state(program string) iapclient.State { return s.file.Registrations[program] }

// client builds the library client for program's registration: --issuer,
// else the registration's issuer, else the default; --store, else the store
// used at its login, else auto.
func (s session) client(program string) (*iapclient.Client, error) {
	name := flagStore
	if name == "" {
		name = s.state(program).Store
	}
	return s.clientWithStore(program, name)
}

// autoStoreName is what an unset store means: auto (tests pin it).
var autoStoreName = iapclient.StoreAuto

func (s session) clientWithStore(program, name string) (*iapclient.Client, error) {
	if name == "" {
		name = autoStoreName
	}
	issuer := defaultIssuer
	switch {
	case flagIssuer != "":
		issuer = flagIssuer
	case s.state(program).Issuer != "":
		issuer = s.state(program).Issuer
	}
	store, err := iapclient.OpenStore(name)
	if err != nil {
		return nil, err
	}
	// A state without an issuer was written by the CLI before it recorded one,
	// which only ever talked to the default issuer.
	return iapclient.New(iapclient.Config{Issuer: issuer, Dir: s.dir, Store: store, Program: program, LegacyIssuer: defaultIssuer})
}

// programFlag resolves a --program value: the flag, else claude under Claude
// Code, else cli.
func programFlag(flag string) (string, error) {
	if flag == "" {
		return defaultProgram(), nil
	}
	if !iapclient.ValidSegment(flag) {
		return "", fmt.Errorf("program %q must match %s", flag, iapclient.SegmentPattern)
	}
	return flag, nil
}

// exitCode carries curl's exit status out through cobra.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func defaultProgram() string {
	if os.Getenv("CLAUDE_CODE_SESSION_ID") != "" {
		return "claude"
	}
	return "cli"
}

// storeLabel and storeNoun name a store in output.
func storeLabel(name string) string {
	switch name {
	case iapclient.StoreKeychain:
		return "Keychain"
	case iapclient.StoreSecretService:
		return "Secret Service"
	}
	return "file"
}

func storeNoun(name string) string {
	if name == iapclient.StoreFile {
		return "the stored credential"
	}
	return "the " + storeLabel(name) + " item"
}

// --- login ---

var (
	loginMachine   string
	loginProgram   string
	loginPort      int
	loginNoBrowser bool
	loginHeadless  bool
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Register this machine/program in the browser and store the credential in the OS keyring",
	Long: `Registers agent:user:<you>:<machine>:<program> with the issuer: a person approves it on
the issuer's consent page in a browser, which then redirects to this command on
http://127.0.0.1:<port>/callback.

On a machine with no browser (SSH, a headless server), use --headless: open the
printed URL on any device (a phone, a laptop), sign in, check that the page
shows this machine, program and mix-up check, click Register, and paste the
one-time code the page shows at the "Paste the code and press Enter:" prompt.
The code is read from stdin: on a terminal with echo off (restored on Ctrl-C
and on timeout), else one piped line; never from the command line. It works
once, for 5 minutes, and only together with a secret this process holds.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error { return runLogin(cmd.Context(), cmd.OutOrStdout()) },
}

func init() {
	loginCmd.Flags().StringVar(&loginMachine, "machine", "", "machine segment (default: short hostname)")
	loginCmd.Flags().StringVar(&loginProgram, "program", "", "program segment (default: claude under Claude Code, else cli)")
	loginCmd.Flags().IntVar(&loginPort, "port", 0, "loopback callback port, 1024-65535 (default: a free one)")
	loginCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false, "print the consent URL instead of opening a browser (default when there is no display)")
	loginCmd.Flags().BoolVar(&loginHeadless, "headless", false, "approve on any device and paste the code the page shows (no browser or callback on this machine)")
	loginCmd.MarkFlagsMutuallyExclusive("headless", "port")
	loginCmd.MarkFlagsMutuallyExclusive("headless", "no-browser")
}

func runLogin(ctx context.Context, out io.Writer) error {
	s, err := loadSession()
	if err != nil {
		return err
	}
	program, err := programFlag(loginProgram)
	if err != nil {
		return err
	}
	c, fallback, err := s.loginClient(ctx, program, loginHeadless, os.Stderr)
	if err != nil {
		return err
	}
	opts := iapclient.LoginOptions{Machine: loginMachine, Program: program, Port: loginPort, Prompt: os.Stderr, StoreFallback: fallback}
	if fs, err := iapclient.OpenStore(iapclient.StoreFile); err == nil {
		opts.SaveFallback = offerFileStore(iapclient.StdinLine, term.IsTerminal(int(os.Stdin.Fd())), os.Stderr, fs)
	}
	switch {
	case loginHeadless:
		read, done := terminalCodeReader(int(os.Stdin.Fd()), os.Stderr, os.Exit)
		defer done()
		opts.Headless, opts.ReadCode = true, read
	case !loginNoBrowser && iapclient.HasDisplay():
		opts.OpenBrowser = iapclient.OpenURL
	}
	reg, err := c.Login(ctx, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Registered %s:* until %s (%s: %s).\n", reg.Account, reg.ExpiresAt.Local().Format("2006-01-02"), storeLabel(reg.Store), reg.Location)
	if len(reg.AudienceSuffixes) > 0 {
		fmt.Fprintf(out, "The issuer also mints for hosts under: %s\n", trimDots(reg.AudienceSuffixes))
	}
	fmt.Fprintf(out, "Hosts still need a grant for %s:* on %s/.\n", reg.Account, reg.Issuer)
	return nil
}

// loginClient picks the store program's login saves to: --store; else the
// store of that program's last login, unless that was a fallback
// (State.StoreFallback), which never becomes the choice: the keyring is tried
// again. A headless login without --store whose keyring is unreachable
// (ErrNoKeyring, ErrSecretServiceUnavailable) falls back to the file store,
// says so on notice every time, and reports fallback so the state records it
// as one. Any other store error stops the login.
func (s session) loginClient(ctx context.Context, program string, headless bool, notice io.Writer) (_ *iapclient.Client, fallback bool, _ error) {
	name := flagStore
	if st := s.state(program); name == "" && !st.StoreFallback {
		name = st.Store
	}
	c, err := s.clientWithStore(program, name)
	if !headless || flagStore != "" || name == iapclient.StoreFile {
		return c, false, err
	}
	if err == nil {
		err = iapclient.CheckStore(ctx, c.Store())
	}
	if err == nil || !errors.Is(err, iapclient.ErrNoKeyring) && !errors.Is(err, iapclient.ErrSecretServiceUnavailable) {
		return c, false, err
	}
	fc, ferr := s.clientWithStore(program, iapclient.StoreFile)
	if ferr != nil {
		return nil, false, ferr
	}
	fmt.Fprintf(notice, "No OS keyring is usable here (%v).\nThis login stores the refresh credential in the file store, %s (mode 0600); the next login tries the keyring again.\nPass --store secret-service to require the keyring, or --store file to make the file your choice.\n\n",
		err, fc.Store().Location(""))
	return fc, true, nil
}

// offerFileStore is the login's SaveFallback: when the chosen store refuses
// the refresh credential after the exchange, it says what failed and, on an
// interactive terminal, asks whether to save to the file store instead. Yes
// returns file (the login records it as a fallback); no, anything else, or no
// terminal returns nil, and the login ends with CredentialLostError.
func offerFileStore(readLine func() (string, error), interactive bool, out io.Writer, file iapclient.Store) func(string, error) iapclient.Store {
	return func(store string, err error) iapclient.Store {
		fmt.Fprintf(out, "The %s store refused the refresh credential: %v\n", store, err)
		if !interactive || store == file.Name() {
			return nil
		}
		fmt.Fprintf(out, "Save it to %s (mode 0600) instead? [y/N] ", file.Location(""))
		answer, rerr := readLine()
		if rerr != nil {
			fmt.Fprintln(out)
			return nil
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
			return file
		}
		return nil
	}
}

// terminalCodeReader returns the headless login's code reader for stdin fd
// and a done func the caller defers. On a terminal it reads with echo off
// (term.ReadPassword) and guarantees echo comes back: done restores the
// state saved before reading (a timeout leaves ReadPassword blocked with echo
// off, and the process then exits), and SIGINT/SIGTERM restore it before
// exiting via exit. Off a terminal it reads one line (a pipe). Never argv.
func terminalCodeReader(fd int, errOut io.Writer, exit func(int)) (read func() (string, error), done func()) {
	if !term.IsTerminal(fd) {
		return iapclient.StdinLine, func() {}
	}
	saved, err := term.GetState(fd)
	if err != nil {
		return func() (string, error) { return "", fmt.Errorf("reading the terminal state: %w", err) }, func() {}
	}
	var once sync.Once
	restore := func() { once.Do(func() { _ = term.Restore(fd, saved) }) }
	sigs := make(chan os.Signal, 1)
	stop := make(chan struct{})
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-sigs:
			restore()
			fmt.Fprintln(errOut)
			code := 130
			if sig == syscall.SIGTERM {
				code = 143
			}
			exit(code)
		case <-stop:
		}
	}()
	read = func() (string, error) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(errOut) // the newline the hidden input swallowed
		return string(b), err
	}
	done = func() {
		signal.Stop(sigs)
		close(stop)
		restore()
	}
	return read, done
}

func trimDots(suffixes []string) string {
	out := make([]string, len(suffixes))
	for i, s := range suffixes {
		out[i] = strings.TrimPrefix(s, ".")
	}
	return strings.Join(out, ", ")
}

// --- curl ---

var curlCmd = &cobra.Command{
	Use:   "curl [--session <s>] [--program <p>] [--client-id <id>] <https-url> [curl args...]",
	Short: "Run curl against one protected host (or api.tailscale.com) with a fresh token (passed on fd 3, never argv)",
	Long: `Mints a 1h access token for agent:user:<you>:<machine>:<program>:<session> bound to the
URL's host and runs the real curl with it as Proxy-Authorization, read from an
inherited pipe (-H @/dev/fd/3). Session: $CLAUDE_CODE_SESSION_ID, else --session,
else "cli". Registration: the one for --program, else "claude" under Claude Code,
else "cli" (one login per program). The URL must be https on a host under the
issuer's domain (or one it advertised at login), or api.tailscale.com (below),
and come first; only allowlisted curl options follow (run with --help for the
list). ~/.curlrc is not read (-q).

https://api.tailscale.com/...: gets a federated token for the audience
api.tailscale.com/<client id> (an audiences: entry in the issuer's policy),
trades it at Tailscale's token exchange for an API token under that trust
credential, and sends that as Authorization. --client-id is the trust
credential's client ID; the last one given is saved.`,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		f, rest, err := splitCurlArgs(args)
		if err != nil {
			return err
		}
		return runCurl(cmd.Context(), f, rest[0], rest[1:])
	},
}

// curlFlags are this tool's own flags before the URL.
type curlFlags struct {
	session  string
	program  string // which registration: --program, else claude under Claude Code, else cli
	clientID string // Tailscale trust credential client ID; "" = the saved one
}

// tailscaleClientIDRE is the shape of a Tailscale client ID.
var tailscaleClientIDRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

// splitCurlArgs takes our own leading --session, --program and --client-id
// (cobra flag parsing is off so curl's flags pass through) and returns them,
// then url + curl args. The root's --issuer/--store go before `curl`.
func splitCurlArgs(args []string) (curlFlags, []string, error) {
	usage := fmt.Errorf("usage: %s curl [--session <s>] [--program <p>] [--client-id <id>] <https-url> [curl args...]", cmdName())
	var f curlFlags
	flagSession, flagProgram := "", ""
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch {
		case args[0] == "--session" && len(args) > 1:
			flagSession, args = args[1], args[2:]
		case strings.HasPrefix(args[0], "--session="):
			flagSession, args = strings.TrimPrefix(args[0], "--session="), args[1:]
		case args[0] == "--program" && len(args) > 1:
			flagProgram, args = args[1], args[2:]
		case strings.HasPrefix(args[0], "--program="):
			flagProgram, args = strings.TrimPrefix(args[0], "--program="), args[1:]
		case args[0] == "--client-id" && len(args) > 1:
			f.clientID, args = args[1], args[2:]
		case strings.HasPrefix(args[0], "--client-id="):
			f.clientID, args = strings.TrimPrefix(args[0], "--client-id="), args[1:]
		case args[0] == "-h" || args[0] == "--help":
			return f, nil, fmt.Errorf("%s\n%s", usage, curlOptionsHelp())
		default:
			return f, nil, usage // curl options go after the URL
		}
	}
	if len(args) == 0 {
		return f, nil, usage
	}
	program, err := programFlag(flagProgram)
	if err != nil {
		return f, nil, err
	}
	f.program = program
	if f.clientID != "" && !tailscaleClientIDRE.MatchString(f.clientID) {
		return f, nil, fmt.Errorf("client id %q must match %s", f.clientID, tailscaleClientIDRE)
	}
	f.session = "cli"
	if id := os.Getenv("CLAUDE_CODE_SESSION_ID"); id != "" {
		f.session = strings.ToLower(id)
	} else if flagSession != "" {
		f.session = flagSession
	}
	if !iapclient.ValidSegment(f.session) {
		return f, nil, fmt.Errorf("session %q must match %s", f.session, iapclient.SegmentPattern)
	}
	return f, args, nil
}

// curlCommand builds the curl process: the header (header: Bearer token)
// travels on a pipe the child inherits as fd 3 and reads with -H @/dev/fd/3,
// so the token is in no argv, no environment and no file. The returned
// cleanup closes our end.
func curlCommand(ctx context.Context, header string, token iapclient.Secret, rawURL string, args []string) (*exec.Cmd, func(), error) {
	if strings.ContainsAny(token.Reveal(), "\r\n") {
		return nil, nil, errors.New("token contains a line break")
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	// A token is well under the pipe buffer, so writing before curl starts
	// cannot block.
	_, werr := io.WriteString(w, header+": Bearer "+token.Reveal()+"\n")
	cerr := w.Close()
	if err := errors.Join(werr, cerr); err != nil {
		r.Close()
		return nil, nil, err
	}
	// -q must come first: it stops curl reading ~/.curlrc, which could turn on
	// verbose output.
	argv := append([]string{"-q", "-H", "@/dev/fd/3", rawURL}, args...)
	cmd := exec.CommandContext(ctx, "curl", argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{r}
	return cmd, func() { r.Close() }, nil
}

// tailscaleAPIHost is the one relying party outside the issuer's domains
// that curl reaches, with a federated token traded at its token exchange.
const tailscaleAPIHost = "api.tailscale.com"

// tailscaleTokenExchangeURL is a var so tests can point it at a fake.
var tailscaleTokenExchangeURL = "https://" + tailscaleAPIHost + "/api/v2/oauth/token-exchange"

func runCurl(ctx context.Context, f curlFlags, rawURL string, args []string) error {
	s, err := loadSession()
	if err != nil {
		return err
	}
	c, err := s.client(f.program)
	if err != nil {
		return err
	}
	host, tailscale, err := curlTarget(c, rawURL)
	if err != nil {
		return err
	}
	if f.clientID != "" && !tailscale {
		return errors.New("--client-id is only for https://" + tailscaleAPIHost + " URLs")
	}
	args, err = checkCurlArgs(args)
	if err != nil {
		return err
	}
	if c.State().Account == "" {
		return fmt.Errorf("no %s registration: run `%s login --program %s`", f.program, cmdName(), f.program)
	}
	ts, err := c.TokenSource(f.session)
	if err != nil {
		return err
	}
	header, token := "Proxy-Authorization", iapclient.Secret{}
	if tailscale {
		if token, err = tailscaleToken(ctx, s, ts, f.clientID); err != nil {
			return err
		}
		header = "Authorization"
	} else {
		tok, err := ts.Token(ctx, host)
		if err != nil {
			return err
		}
		token = tok.Value
	}
	cmd, cleanup, err := curlCommand(ctx, header, token, rawURL, args)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitCode(ee.ExitCode())
		}
		return err
	}
	return nil
}

// tailscaleToken returns a Tailscale API token: the federated token for
// audience api.tailscale.com/<client id>, traded at Tailscale's exchange.
// clientID "" is the saved one; a new one is saved.
func tailscaleToken(ctx context.Context, s session, ts *iapclient.TokenSource, clientID string) (iapclient.Secret, error) {
	if clientID == "" {
		clientID = s.file.TailscaleClientID
	}
	if clientID == "" {
		return iapclient.Secret{}, errors.New("--client-id <trust credential client ID> is required for " + tailscaleAPIHost + " (saved after the first use)")
	}
	if clientID != s.file.TailscaleClientID {
		f, err := iapclient.LoadStateFile(s.dir)
		if err != nil {
			return iapclient.Secret{}, err
		}
		f.TailscaleClientID = clientID
		if err := iapclient.SaveStateFile(s.dir, f); err != nil {
			return iapclient.Secret{}, err
		}
	}
	jwt, err := ts.FederatedToken(ctx, tailscaleAPIHost+"/"+clientID)
	if err != nil {
		return iapclient.Secret{}, err
	}
	return tailscaleExchange(ctx, tailscaleTokenExchangeURL, clientID, jwt.Value)
}

// tailscaleTarget validates an https://api.tailscale.com URL (no userinfo,
// no port) and returns its host.
// curlTarget picks the token for rawURL. The Tailscale API comes first and
// never falls through to the issuer's suffixes: an issuer that advertised
// .tailscale.com must never get an agent token sent there as
// Proxy-Authorization.
func curlTarget(c *iapclient.Client, rawURL string) (host string, tailscale bool, err error) {
	if _, err := tailscaleTarget(rawURL); err == nil {
		return tailscaleAPIHost, true, nil
	}
	if u, err := url.Parse(rawURL); err == nil && strings.EqualFold(u.Hostname(), tailscaleAPIHost) {
		return "", false, fmt.Errorf("%q: want https://%s/... (no port or userinfo)", rawURL, tailscaleAPIHost)
	}
	host, err = c.CheckURL(rawURL)
	return host, false, err
}

func tailscaleTarget(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || strings.ToLower(u.Hostname()) != tailscaleAPIHost {
		return "", fmt.Errorf("%q: want https://%s/...", raw, tailscaleAPIHost)
	}
	return tailscaleAPIHost, nil
}

// tailscaleExchange trades a federated token for a Tailscale API access token
// under the trust credential clientID. Errors carry the HTTP status and
// Tailscale's error fields, never a token.
func tailscaleExchange(ctx context.Context, endpoint, clientID string, jwt iapclient.Secret) (iapclient.Secret, error) {
	form := url.Values{"client_id": {clientID}, "jwt": {jwt.Reveal()}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return iapclient.Secret{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return iapclient.Secret{}, fmt.Errorf("tailscale token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return iapclient.Secret{}, err
	}
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Message     string `json:"message"`
	}
	jerr := json.Unmarshal(body, &out, jsoncompat.Read) // as lenient as v1 was
	if resp.StatusCode != http.StatusOK || jerr != nil || out.AccessToken == "" {
		return iapclient.Secret{}, fmt.Errorf("tailscale token exchange: HTTP %d %s %s %s", resp.StatusCode, out.Error, out.Description, out.Message)
	}
	return iapclient.NewSecret(out.AccessToken), nil
}

// --- status / logout ---

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show each program's registration and whether its stored credential exists (no secrets)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runStatus(cmd.Context(), cmd.OutOrStdout())
	},
}

func runStatus(ctx context.Context, out io.Writer) error {
	s, err := loadSession()
	if err != nil {
		return err
	}
	var programs []string
	for p, st := range s.file.Registrations {
		if st.Account != "" {
			programs = append(programs, p)
		}
	}
	if len(programs) == 0 {
		fmt.Fprintf(out, "not logged in (%s login)\n", cmdName())
		return nil
	}
	slices.Sort(programs)
	for i, p := range programs {
		if i > 0 {
			fmt.Fprintln(out)
		}
		if err := programStatus(ctx, out, s, p); err != nil {
			return err
		}
	}
	if s.file.TailscaleClientID != "" {
		fmt.Fprintf(out, "\ntailscale:    client id %s (curl https://%s/...)\n", s.file.TailscaleClientID, tailscaleAPIHost)
	}
	fmt.Fprintln(out, "\nrevoke:       on the access page (\"Your agents\")")
	return nil
}

// programStatus prints one program's registration.
func programStatus(ctx context.Context, out io.Writer, s session, program string) error {
	c, err := s.client(program)
	if err != nil {
		return err
	}
	st := c.Status(ctx)
	here := ""
	if program == defaultProgram() {
		here = " (used here)"
	}
	fmt.Fprintf(out, "registration: %s:*%s\nserver:       %s\nexpires:      %s\n", st.Account, here, st.Issuer, st.ExpiresAt.Local().Format(time.RFC3339))
	if st.Mismatch != nil {
		fmt.Fprintf(out, "issuer:       %v\n", st.Mismatch)
	}
	if len(st.AudienceSuffixes) > 0 {
		fmt.Fprintf(out, "also mints:   %s\n", trimDots(st.AudienceSuffixes))
	}
	relogin := fmt.Sprintf("%s login --program %s", cmdName(), program)
	if st.Expired {
		fmt.Fprintf(out, "status:       expired (%s)\n", relogin)
	}
	label := strings.ToLower(storeLabel(st.Store)) + ":"
	switch {
	case st.StoreErr != nil:
		fmt.Fprintf(out, "%-14s%s unknown: %v\n", label, st.Location, withHint(st.StoreErr))
	case st.Present:
		fmt.Fprintf(out, "%-14s%s present\n", label, st.Location)
	default:
		fmt.Fprintf(out, "%-14s%s MISSING (%s)\n", label, st.Location, relogin)
	}
	if s.state(program).StoreFallback {
		fmt.Fprintln(out, "note:         file store used because no OS keyring worked at login; the next login tries the keyring again")
	}
	return nil
}

var logoutProgram string

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Delete one program's stored credential and forget its registration (revoke it on the access page)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		s, err := loadSession()
		if err != nil {
			return err
		}
		program, err := programFlag(logoutProgram)
		if err != nil {
			return err
		}
		if s.state(program).Account == "" {
			fmt.Fprintf(cmd.OutOrStdout(), "no %s registration\n", program)
			return nil
		}
		c, err := s.client(program)
		if err != nil {
			return err
		}
		acct, err := c.Logout(cmd.Context())
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s for %s. The registration stays valid until revoked on %s/#agents.\n", storeNoun(c.Store().Name()), acct, c.Issuer())
		return nil
	},
}

func init() {
	logoutCmd.Flags().StringVar(&logoutProgram, "program", "", "which registration (default: claude under Claude Code, else cli)")
}

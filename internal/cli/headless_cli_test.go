package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/R167/iap/iapclient"
)

// Off a terminal the code is one line of stdin at a time, never argv.
func TestTerminalCodeReaderPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = prev; r.Close() })
	if _, err := io.WriteString(w, "first-line\nsecond\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	read, done := terminalCodeReader(int(r.Fd()), io.Discard, func(int) { t.Fatal("exit called") })
	defer done()
	for _, want := range []string{"first-line", "second"} {
		if got, err := read(); err != nil || got != want {
			t.Errorf("read = %q, %v; want %q", got, err, want)
		}
	}
	if _, err := read(); err == nil {
		t.Error("closed stdin read as a code")
	}
	if loginCmd.Flags().Lookup("code") != nil {
		t.Error("login takes the code on argv")
	}
}

// --headless excludes the loopback flags.
func TestHeadlessFlags(t *testing.T) {
	for _, args := range [][]string{{"login", "--headless", "--port", "18765"}, {"login", "--headless", "--no-browser"}} {
		isolate(t)
		rootCmd.SetArgs(args)
		rootCmd.SetOut(io.Discard)
		rootCmd.SetErr(io.Discard)
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "none of the others can be") {
			t.Errorf("%v = %v", args, err)
		}
		for _, f := range []string{"headless", "no-browser", "port"} {
			_ = loginCmd.Flags().Set(f, loginCmd.Flags().Lookup(f).DefValue)
			loginCmd.Flags().Lookup(f).Changed = false
		}
	}
}

// ptyReader starts terminalCodeReader on a fresh pty's terminal end, drains
// the controller (what the person would see) and waits until echo is off.
type ptyReader struct {
	t        *testing.T
	ctl, tty *os.File
	read     func() (string, error)
	done     func()
	exits    chan int
	mu       sync.Mutex
	shown    bytes.Buffer
}

func newPTYReader(t *testing.T) *ptyReader {
	ctl, tty := openPTY(t)
	p := &ptyReader{t: t, ctl: ctl, tty: tty, exits: make(chan int, 1)}
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := ctl.Read(buf)
			p.mu.Lock()
			p.shown.Write(buf[:n])
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	if !echoOn(t, int(tty.Fd())) {
		t.Fatal("a new pty does not echo")
	}
	p.read, p.done = terminalCodeReader(int(tty.Fd()), io.Discard, func(code int) { p.exits <- code })
	return p
}

// startRead runs read in the background and waits for echo to go off.
func (p *ptyReader) startRead() chan string {
	got := make(chan string, 1)
	go func() {
		s, err := p.read()
		if err != nil {
			s = "error: " + err.Error()
		}
		got <- s
	}()
	for i := 0; echoOn(p.t, int(p.tty.Fd())); i++ {
		if i == 200 {
			p.t.Fatal("echo never went off")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return got
}

func (p *ptyReader) shownText() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.shown.String()
}

// On a terminal the code is read with echo off: it never shows, and echo is
// back afterwards.
func TestTerminalCodeReaderEchoOff(t *testing.T) {
	p := newPTYReader(t)
	defer p.done()
	got := p.startRead()
	if _, err := io.WriteString(p.ctl, "pasted-SECRET-code\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s != "pasted-SECRET-code" {
			t.Errorf("read = %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read never returned")
	}
	time.Sleep(50 * time.Millisecond) // let the drain catch up
	if strings.Contains(p.shownText(), "SECRET") {
		t.Errorf("the code was echoed: %q", p.shownText())
	}
	if !echoOn(t, int(p.tty.Fd())) {
		t.Error("echo not back on after reading")
	}
}

// A timeout abandons the blocked read with echo off; done (deferred by
// runLogin) must put it back.
func TestTerminalCodeReaderRestoresOnTimeout(t *testing.T) {
	p := newPTYReader(t)
	got := p.startRead()
	p.done()
	if !echoOn(t, int(p.tty.Fd())) {
		t.Error("echo still off after done")
	}
	_, _ = io.WriteString(p.ctl, "\n") // release the abandoned read
	<-got
}

// Ctrl-C (SIGINT) at the prompt restores echo before exiting 130.
func TestTerminalCodeReaderRestoresOnSignal(t *testing.T) {
	p := newPTYReader(t)
	defer p.done()
	got := p.startRead()
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-p.exits:
		if code != 130 {
			t.Errorf("exit code = %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGINT not handled")
	}
	if !echoOn(t, int(p.tty.Fd())) {
		t.Error("echo still off after SIGINT")
	}
	_, _ = io.WriteString(p.ctl, "\n")
	<-got
}

// fakeSecretTool installs a secret-tool on PATH. working: a reachable
// keyring that stores one item in a file; otherwise every call fails as an
// unreachable D-Bus does.
func fakeSecretTool(t *testing.T, bin string, working bool) {
	t.Helper()
	item := filepath.Join(bin, "item")
	script := `#!/bin/sh
echo 'Cannot autolaunch D-Bus without X11 $DISPLAY' >&2
exit 1
`
	if working {
		script = `#!/bin/sh
case "$1" in
store) /bin/cat > ` + item + `;;
lookup) [ -f ` + item + ` ] || exit 1; /bin/cat ` + item + `;;
clear) /bin/rm -f ` + item + `;;
esac
`
	}
	if err := os.WriteFile(filepath.Join(bin, "secret-tool"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

// login --headless without --store keeps a keyring that works, and falls
// back to the file store, out loud, only when the keyring is unreachable.
// The fallback is never the saved choice: the next login tries the keyring
// again and says so again if it still has to fall back.
func TestHeadlessStoreChoice(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	ctx := context.Background()
	// "auto" is the Secret Service here whatever the test machine is, so
	// nothing touches a real Keychain.
	autoStoreName = iapclient.StoreSecretService
	t.Cleanup(func() { autoStoreName = iapclient.StoreAuto })
	for _, c := range []struct {
		working  bool
		saved    iapclient.State
		want     string
		fallback bool
	}{
		{true, iapclient.State{Store: iapclient.StoreSecretService}, iapclient.StoreSecretService, false},
		{false, iapclient.State{Store: iapclient.StoreSecretService}, iapclient.StoreFile, true},
		// A previous fallback: the keyring is tried again, and used now it works...
		{true, iapclient.State{Store: iapclient.StoreFile, StoreFallback: true}, iapclient.StoreSecretService, false},
		// ...or the fallback happens, and is announced, again.
		{false, iapclient.State{Store: iapclient.StoreFile, StoreFallback: true}, iapclient.StoreFile, true},
	} {
		dir := isolate(t)
		if err := iapclient.SaveState(dir, "cli", c.saved); err != nil {
			t.Fatal(err)
		}
		fakeSecretTool(t, bin, c.working)
		s, err := loadSession()
		if err != nil {
			t.Fatal(err)
		}
		var notice bytes.Buffer
		cl, fallback, err := s.loginClient(ctx, "cli", true, &notice)
		if err != nil || cl.Store().Name() != c.want || fallback != c.fallback || (notice.Len() > 0) != c.fallback {
			t.Errorf("%+v: store = %v, fallback %v, %v, notice %q", c, cl, fallback, err, notice.String())
			continue
		}
		if c.fallback && (!strings.Contains(notice.String(), "credentials.json") || !strings.Contains(notice.String(), "next login tries the keyring again")) {
			t.Errorf("notice: %s", notice.String())
		}
	}

	// --store file is a choice: no probe, no notice, no fallback flag.
	isolate(t)
	fakeSecretTool(t, bin, false)
	flagStore = iapclient.StoreFile
	s, _ := loadSession()
	var notice bytes.Buffer
	if cl, fallback, err := s.loginClient(ctx, "cli", true, &notice); err != nil || fallback || notice.Len() > 0 || cl.Store().Name() != iapclient.StoreFile {
		t.Errorf("--store file = %v, %v, %v, %q", cl, fallback, err, notice.String())
	}
	flagStore = ""

	// A saved file store with a loose directory fails the store check that
	// Login runs before printing the URL; it is never swapped for another.
	dir := isolate(t)
	if err := iapclient.SaveState(dir, "cli", iapclient.State{Store: iapclient.StoreFile}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(os.Getenv("XDG_STATE_HOME"), "iap"), 0o755); err != nil {
		t.Fatal(err)
	}
	s, _ = loadSession()
	cl, fallback, err := s.loginClient(ctx, "cli", true, io.Discard)
	if err != nil || fallback || cl.Store().Name() != iapclient.StoreFile {
		t.Fatalf("saved file store = %v, %v, %v", cl, fallback, err)
	}
	if err := iapclient.CheckStore(ctx, cl.Store()); err == nil {
		t.Error("file store with a 0755 directory passed the check")
	}
}

// A state without an issuer (written before the field existed) belongs to
// the default issuer only: its credential is never offered to another.
func TestLegacyStateBelongsToDefaultIssuer(t *testing.T) {
	dir := isolate(t)
	if err := iapclient.SaveState(dir, "cli", iapclient.State{Account: "agent:user:alice@example.com:box:cli", Store: iapclient.StoreFile}); err != nil {
		t.Fatal(err)
	}
	s, _ := loadSession()
	c, err := s.client("cli")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.TokenSource("cli"); err != nil && errors.As(err, new(*iapclient.IssuerMismatchError)) {
		t.Errorf("default issuer refused its own legacy state: %v", err)
	}
	flagIssuer = "https://access.other.example.org"
	c, err = s.client("cli")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.TokenSource("cli"); !errors.As(err, new(*iapclient.IssuerMismatchError)) {
		t.Errorf("legacy credential offered to %s: %v", flagIssuer, err)
	}
}

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/R167/iap/expose"
	"github.com/R167/iap/iapclient"
)

func TestParseReserve(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"":    0,
		"7d":  7 * 24 * time.Hour,
		"30d": 30 * 24 * time.Hour,
		"36h": 36 * time.Hour,
		"90m": 90 * time.Minute,
	} {
		if got, err := parseReserve(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"31d", "721h", "-1h", "xd", "soon", "106751991167301d", "9223372036854775807d"} {
		if _, err := parseReserve(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// tokensErr fails every mint with err.
type tokensErr struct{ err error }

func (t tokensErr) Token(context.Context, string) (iapclient.Token, error) {
	return iapclient.Token{}, t.err
}

func testExposeOptions(err error) expose.Options {
	return expose.Options{
		Name: "app", Domain: "iap.example.com", Backend: "127.0.0.1:1",
		Tokens: tokensErr{err}, MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
	}
}

// The command's exit status is the CLI's, and the tunnel stops with it.
func TestExposeCommandExitStatus(t *testing.T) {
	err := exposeWithCommand(context.Background(), testExposeOptions(errors.New("transient")), []string{"sh", "-c", "exit 3"}, &bytes.Buffer{})
	var code exitCode
	if !errors.As(err, &code) || code != 3 {
		t.Fatalf("got %v", err)
	}
}

// A final tunnel error stops the command.
func TestExposeTunnelEndsCommand(t *testing.T) {
	var out bytes.Buffer
	start := time.Now()
	err := exposeWithCommand(context.Background(), testExposeOptions(iapclient.ErrInvalidGrant), []string{"sleep", "30"}, &out)
	var code exitCode
	if !errors.As(err, &code) || code != 1 || time.Since(start) > 10*time.Second {
		t.Fatalf("got %v after %s", err, time.Since(start))
	}
	if !bytes.Contains(out.Bytes(), []byte("stopping sleep")) {
		t.Fatalf("output %q", out.String())
	}
}

// tokensAfterFile fails with err once file exists (the command has started
// what it starts).
type tokensAfterFile struct {
	file string
	err  error
}

func (t tokensAfterFile) Token(ctx context.Context, _ string) (iapclient.Token, error) {
	for {
		if b, err := os.ReadFile(t.file); err == nil && len(b) > 0 && b[len(b)-1] == '\n' {
			return iapclient.Token{}, t.err
		}
		select {
		case <-ctx.Done():
			return iapclient.Token{}, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// gone waits for pid to stop existing (it is reparented and reaped once
// killed).
func gone(t *testing.T, pid int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("pid %d outlived the command", pid)
}

func grandchildPid(t *testing.T, file string) int {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

// What the command started (a dev server's own children) is stopped with
// it: the command runs in its own process group and the group is signalled.
func TestExposeStopsGrandchildren(t *testing.T) {
	dir := t.TempDir()
	// The tunnel fails for good: the whole group is stopped.
	f1 := filepath.Join(dir, "a")
	opts := testExposeOptions(nil)
	opts.Tokens = tokensAfterFile{file: f1, err: iapclient.ErrInvalidGrant}
	err := exposeWithCommand(context.Background(), opts,
		[]string{"sh", "-c", "sleep 30 & echo $! > " + f1 + "; wait"}, &bytes.Buffer{})
	var code exitCode
	if !errors.As(err, &code) || code != 1 {
		t.Fatalf("got %v", err)
	}
	gone(t, grandchildPid(t, f1))

	// The command exits on its own and leaves a child behind.
	f2 := filepath.Join(dir, "b")
	err = exposeWithCommand(context.Background(), testExposeOptions(errors.New("transient")),
		[]string{"sh", "-c", "sleep 30 & echo $! > " + f2 + "; exit 3"}, &bytes.Buffer{})
	if !errors.As(err, &code) || code != 3 {
		t.Fatalf("got %v", err)
	}
	gone(t, grandchildPid(t, f2))
}

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/R167/iap/expose"
	"github.com/R167/iap/iapclient"
)

var (
	exposePort    int
	exposeReserve string
	exposeTake    bool
	exposePublic  bool
	exposeDomain  string
	exposeProgram string
	exposeSession string
)

var exposeCmd = &cobra.Command{
	Use:   "expose <name> --port <port> [--public] [--reserve <dur>] [--take] [-- <command> [args...]]",
	Short: "Publish 127.0.0.1:<port> at https://<name>.<domain> through the IAP's tunnel service",
	Long: `Opens a tunnel to https://tunnel.<domain> with an agent token for that host and
publishes 127.0.0.1:<port> at https://<name>.<domain> while it runs. Every visitor
still passes the IAP. HTTP, streaming responses and WebSockets are forwarded.

<domain> is --domain, else $IAP_EXPOSE_DOMAIN, else the one domain the issuer
advertised at login (e.g. iap.example.com).

The name is released about a minute after this process exits, unless --reserve
keeps it for that long after the last disconnect (at most 30d; "7d", "36h").
Running without --reserve drops an earlier reservation of the name. Your own
registration (this machine and program) always gets its name back, live or
not: a second process, or this one after a restart, supersedes the old
connection. A name held by another of your registrations moves here only with
--take; a name another person holds never does.

--public publishes at https://<name>.<public domain> (a domain the service
chooses) instead: no IAP in front of visitors, so the program's own login is
the only gate. The service allows it only for the names and principals its
public-page list names (default deny); the connection itself still goes
through the IAP with this registration's token.

With -- <command>, runs the command in its own process group and exits with
its status when it exits, releasing the name. On a terminal it gets the
terminal (Ctrl-C reaches it directly); SIGINT, SIGTERM and SIGHUP sent to this
process go to the whole group.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		var command []string
		if at := cmd.ArgsLenAtDash(); at >= 0 {
			if at != 1 {
				return errors.New("usage: expose <name> --port <port> [flags] [-- <command> [args...]]")
			}
			command = args[1:]
		} else if len(args) > 1 {
			return errors.New("put the command after --: expose <name> --port <port> -- <command> [args...]")
		}
		return runExpose(cmd.Context(), name, command)
	},
}

func init() {
	f := exposeCmd.Flags()
	f.IntVar(&exposePort, "port", 0, "local port to publish (127.0.0.1:<port>); required")
	f.StringVar(&exposeReserve, "reserve", "", `keep the name this long after the last disconnect ("7d", "36h"; max 30d)`)
	f.BoolVar(&exposeTake, "take", false, "move the name here from another of your registrations")
	f.BoolVar(&exposePublic, "public", false, "publish at <name>.<public domain>, without the IAP (only names the service's public-page list allows you)")
	f.StringVar(&exposeDomain, "domain", "", "the tunnel service's domain (default: $IAP_EXPOSE_DOMAIN, else the one the issuer advertised)")
	f.StringVar(&exposeProgram, "program", "", "which registration (default: claude under Claude Code, else cli)")
	f.StringVar(&exposeSession, "session", "", "session segment when not under Claude Code (default cli)")
	_ = exposeCmd.MarkFlagRequired("port")
	rootCmd.AddCommand(exposeCmd)
}

// parseReserve parses a Go duration or a whole number of days ("7d").
func parseReserve(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	var d time.Duration
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("--reserve %q: want a duration like 7d or 36h", s)
		}
		// Bound before multiplying: a huge day count would overflow.
		if days < 0 || days > expose.MaxReserve/(24*60*60) {
			return 0, fmt.Errorf("--reserve %q: at most 30d", s)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("--reserve %q: want a duration like 7d or 36h", s)
		}
	}
	if d < 0 || d > time.Duration(expose.MaxReserve)*time.Second {
		return 0, fmt.Errorf("--reserve %q: at most 30d", s)
	}
	return d.Truncate(time.Second), nil
}

// exposeDomainFor picks the tunnel domain: the flag, the environment, or the
// single domain the issuer advertised.
func exposeDomainFor(c *iapclient.Client) (string, error) {
	d := exposeDomain
	if d == "" {
		d = os.Getenv("IAP_EXPOSE_DOMAIN")
	}
	if d == "" {
		adv := c.AllowedSuffixes()[1:]
		if len(adv) != 1 {
			return "", fmt.Errorf("pass --domain: the issuer advertised %d domains (%s)", len(adv), strings.Join(adv, ", "))
		}
		d = adv[0]
	}
	return strings.TrimPrefix(strings.ToLower(d), "."), nil
}

func exposeSessionName() (string, error) {
	s := "cli"
	if id := os.Getenv("CLAUDE_CODE_SESSION_ID"); id != "" {
		s = strings.ToLower(id)
	} else if exposeSession != "" {
		s = exposeSession
	}
	if !iapclient.ValidSegment(s) {
		return "", fmt.Errorf("session %q must match %s", s, iapclient.SegmentPattern)
	}
	return s, nil
}

func runExpose(ctx context.Context, name string, command []string) error {
	if exposePort < 1 || exposePort > 65535 {
		return fmt.Errorf("--port %d: want 1-65535", exposePort)
	}
	reserve, err := parseReserve(exposeReserve)
	if err != nil {
		return err
	}
	program, err := programFlag(exposeProgram)
	if err != nil {
		return err
	}
	session, err := exposeSessionName()
	if err != nil {
		return err
	}
	s, err := loadSession()
	if err != nil {
		return err
	}
	c, err := s.client(program)
	if err != nil {
		return err
	}
	if c.State().Account == "" {
		return fmt.Errorf("no %s registration: run `%s login --program %s`", program, cmdName(), program)
	}
	domain, err := exposeDomainFor(c)
	if err != nil {
		return err
	}
	if _, err := c.CheckURL("https://tunnel." + domain + "/"); err != nil {
		return err
	}
	ts, err := c.TokenSource(session)
	if err != nil {
		return err
	}
	opts := expose.Options{
		Name:    name,
		Domain:  domain,
		Backend: "127.0.0.1:" + strconv.Itoa(exposePort),
		Reserve: reserve,
		Take:    exposeTake,
		Public:  exposePublic,
		Tokens:  ts,
		Log:     os.Stderr,
	}
	if len(command) == 0 {
		ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		defer stop()
		return exposeError(expose.Run(ctx, opts))
	}
	return exposeWithCommand(ctx, opts, command, os.Stderr)
}

// exposeWithCommand runs command beside the tunnel. The tunnel ends when the
// command exits; the command is stopped (SIGTERM, then SIGKILL after 10 s)
// when the tunnel ends for good.
//
// The command runs in its own process group, and every signal goes to the
// whole group, so what it starts dies with it (`npm run dev` runs node, which
// runs esbuild). On a terminal where this process is in the foreground, that
// group is made the terminal's foreground group: Ctrl-C and terminal reads
// reach the command as if it ran alone, and the terminal is handed back when
// it exits.
func exposeWithCommand(ctx context.Context, opts expose.Options, command []string, errOut io.Writer) error {
	child := exec.Command(command[0], command[1:]...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	fg := inForeground()
	if fg {
		// Ctty is a descriptor in the child: its stdin, the terminal.
		child.SysProcAttr.Foreground, child.SysProcAttr.Ctty = true, 0
	}
	if err := child.Start(); err != nil {
		return err
	}
	group := -child.Process.Pid // the child leads its own group
	signalGroup := func(sig syscall.Signal) { _ = syscall.Kill(group, sig) }
	exited := make(chan error, 1)
	go func() {
		err := child.Wait()
		if fg {
			reclaimTerminal()
		}
		// Whatever the command left running in its group goes with it.
		signalGroup(syscall.SIGTERM)
		exited <- err
	}()

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	tctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tunnelDone := make(chan error, 1)
	go func() { tunnelDone <- expose.Run(tctx, opts) }()

	for {
		select {
		case sig := <-sigs:
			signalGroup(sig.(syscall.Signal))
		case err := <-exited:
			cancel()
			<-tunnelDone
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return exitCode(ee.ExitCode())
			}
			return err
		case err := <-tunnelDone:
			// Run returns nil only when ctx ends.
			if err == nil {
				err = ctx.Err()
			}
			fmt.Fprintf(errOut, "iap expose: %v; stopping %s\n", exposeError(err), command[0])
			signalGroup(syscall.SIGTERM)
			select {
			case <-exited:
			case <-time.After(10 * time.Second):
				signalGroup(syscall.SIGKILL)
				<-exited
			}
			return exitCode(1)
		}
	}
}

// inForeground reports whether stdin is a terminal whose foreground process
// group is this process's own (not run with &, not under a pipe-only parent).
func inForeground() bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}
	pgrp, err := unix.IoctlGetInt(int(os.Stdin.Fd()), unix.TIOCGPGRP)
	return err == nil && pgrp == unix.Getpgrp()
}

// reclaimTerminal makes this process's group the terminal's foreground group
// again. A background group changing it gets SIGTTOU unless it is ignored.
func reclaimTerminal() {
	signal.Ignore(syscall.SIGTTOU)
	defer signal.Reset(syscall.SIGTTOU)
	_ = unix.IoctlSetPointerInt(int(os.Stdin.Fd()), unix.TIOCSPGRP, unix.Getpgrp())
}

// exposeError adds what to do next to a final tunnel error.
func exposeError(err error) error {
	var ref *expose.Refusal
	if errors.As(err, &ref) {
		return fmt.Errorf("refused (%s): %s", ref.Code, ref.Message)
	}
	return err
}

package iapclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ErrSecretServiceUnavailable: secret-tool ran but could not reach an unlocked
// Secret Service (typically a headless machine with no D-Bus session or no
// keyring daemon).
var ErrSecretServiceUnavailable = errors.New("the Secret Service (desktop keyring) is not reachable")

// SecretServiceStore keeps the credential in the freedesktop Secret Service
// (GNOME Keyring, KWallet, KeePassXC) through libsecret's secret-tool, with
// the attributes service=Service (default "iap-authz") and account=<the
// registration principal>. The credential goes to secret-tool on stdin and
// comes back on stdout, never on argv.
type SecretServiceStore struct {
	Service string
	// Command is the secret-tool binary; default "secret-tool" from PATH.
	Command string
}

func (s SecretServiceStore) service() string {
	if s.Service == "" {
		return DefaultService
	}
	return s.Service
}

func (s SecretServiceStore) command() string {
	if s.Command == "" {
		return "secret-tool"
	}
	return s.Command
}

func (SecretServiceStore) Name() string { return StoreSecretService }

func (s SecretServiceStore) Location(account string) string {
	return "service=" + s.service() + " account=" + account
}

func (s SecretServiceStore) attrs(account string) []string {
	return []string{"service", s.service(), "account", account}
}

// storeCmd builds the secret-tool process that stores cred.
func (s SecretServiceStore) storeCmd(ctx context.Context, account string, cred Secret) *exec.Cmd {
	args := append([]string{"store", "--label=iap refresh credential (" + account + ")"}, s.attrs(account)...)
	cmd := exec.CommandContext(ctx, s.command(), args...)
	cmd.Stdin = strings.NewReader(cred.Reveal())
	return cmd
}

// run runs cmd, returning stdout. A failure with stderr output is the
// Secret Service being unreachable or locked; a failure with none is "no such
// item" (secret-tool lookup exits 1 silently).
func (s SecretServiceStore) run(cmd *exec.Cmd, cred Secret) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}
	msg := strings.TrimSpace(stderr.String())
	if !cred.IsZero() {
		msg = strings.ReplaceAll(msg, cred.Reveal(), redacted)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return nil, fmt.Errorf("%s: %w", s.command(), err)
	}
	if msg == "" {
		return nil, ErrNoCredential
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return nil, fmt.Errorf("%w (%s: %s); on a headless machine, opt in to the file store instead", ErrSecretServiceUnavailable, s.command(), msg)
}

func (s SecretServiceStore) Save(ctx context.Context, account string, cred Secret) error {
	if _, err := s.run(s.storeCmd(ctx, account, cred), cred); err != nil {
		if errors.Is(err, ErrNoCredential) {
			return fmt.Errorf("%s store failed without a message", s.command())
		}
		return err
	}
	if ok, err := s.Exists(ctx, account); !ok {
		return fmt.Errorf("%s did not store the item: %v", s.command(), err)
	}
	return nil
}

func (s SecretServiceStore) Load(ctx context.Context, account string) (Secret, error) {
	out, err := s.run(exec.CommandContext(ctx, s.command(), append([]string{"lookup"}, s.attrs(account)...)...), Secret{})
	if errors.Is(err, ErrNoCredential) {
		return Secret{}, fmt.Errorf("%w: no Secret Service item %s", ErrNoCredential, s.Location(account))
	}
	if err != nil {
		return Secret{}, err
	}
	v := strings.TrimRight(string(out), "\r\n")
	if v == "" {
		return Secret{}, fmt.Errorf("%w: empty Secret Service item %s", ErrNoCredential, s.Location(account))
	}
	return NewSecret(v), nil
}

// Exists looks the item up and discards the value.
func (s SecretServiceStore) Exists(ctx context.Context, account string) (bool, error) {
	_, err := s.Load(ctx, account)
	if errors.Is(err, ErrNoCredential) {
		return false, nil
	}
	return err == nil, err
}

func (s SecretServiceStore) Delete(ctx context.Context, account string) error {
	_, err := s.run(exec.CommandContext(ctx, s.command(), append([]string{"clear"}, s.attrs(account)...)...), Secret{})
	if errors.Is(err, ErrNoCredential) {
		return nil
	}
	return err
}

package iapclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// KeychainStore keeps the credential in the macOS login Keychain as a
// generic password, service Service (default "iap-authz"), account = the
// registration principal. It drives /usr/bin/security; writes go through
// `security -i` reading the command from stdin, so the credential is never on
// any process's argv.
type KeychainStore struct {
	Service string
}

func (k KeychainStore) service() string {
	if k.Service == "" {
		return DefaultService
	}
	return k.Service
}

func (KeychainStore) Name() string { return StoreKeychain }

func (k KeychainStore) Location(account string) string { return k.service() + " / " + account }

// securityArgRE bounds what goes into a `security -i` command line: the
// registration principal and the refresh credential never need quoting.
var securityArgRE = regexp.MustCompile(`^[A-Za-z0-9@._:+-]{1,256}$`)

// addScript is the `security -i` input that stores secret.
func (k KeychainStore) addScript(account, secret string) (string, error) {
	if !securityArgRE.MatchString(account) || !securityArgRE.MatchString(secret) || !securityArgRE.MatchString(k.service()) {
		return "", errors.New("keychain: account or credential has unexpected characters")
	}
	return fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n", k.service(), account, secret), nil
}

// storeCmd builds the `security -i` process that stores secret.
func (k KeychainStore) storeCmd(ctx context.Context, account string, cred Secret) (*exec.Cmd, error) {
	script, err := k.addScript(account, cred.Reveal())
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "security", "-i")
	cmd.Stdin = strings.NewReader(script)
	return cmd, nil
}

// Save writes the credential, then checks it is there (`security -i` can exit
// 0 after a failed command).
func (k KeychainStore) Save(ctx context.Context, account string, cred Secret) error {
	cmd, err := k.storeCmd(ctx, account, cred)
	if err != nil {
		return err
	}
	out, err := cmd.CombinedOutput()
	clean := strings.ReplaceAll(string(out), cred.Reveal(), redacted)
	if err != nil {
		return fmt.Errorf("security -i: %v: %s", err, clean)
	}
	if ok, _ := k.Exists(ctx, account); !ok {
		return fmt.Errorf("security -i did not store the item: %s", clean)
	}
	return nil
}

// Load reads the credential into memory with `security ... -w`.
func (k KeychainStore) Load(ctx context.Context, account string) (Secret, error) {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "security", "find-generic-password", "-s", k.service(), "-a", account, "-w")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return Secret{}, fmt.Errorf("%w: no Keychain item %s: %v", ErrNoCredential, k.Location(account), err)
	}
	return NewSecret(strings.TrimRight(string(out), "\r\n")), nil
}

// Exists checks for the item without reading the credential.
func (k KeychainStore) Exists(ctx context.Context, account string) (bool, error) {
	err := exec.CommandContext(ctx, "security", "find-generic-password", "-s", k.service(), "-a", account).Run()
	if err == nil {
		return true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return false, nil
	}
	return false, err
}

func (k KeychainStore) Delete(ctx context.Context, account string) error {
	out, err := exec.CommandContext(ctx, "security", "delete-generic-password", "-s", k.service(), "-a", account).CombinedOutput()
	if err != nil {
		return fmt.Errorf("security delete-generic-password: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

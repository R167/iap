package iapclient

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
)

// Store keeps the refresh credential, keyed by the registration principal
// (agent:user:<email>:<machine>:<program>). Access tokens are never stored.
// No method returns or prints the credential except Load.
type Store interface {
	// Name is the store's kind: "keychain", "secret-service" or "file".
	Name() string
	// Location says where account's credential lives, for status output.
	Location(account string) string
	Save(ctx context.Context, account string, cred Secret) error
	// Load returns ErrNoCredential (wrapped) when there is no credential.
	Load(ctx context.Context, account string) (Secret, error)
	Exists(ctx context.Context, account string) (bool, error)
	Delete(ctx context.Context, account string) error
}

// Store names accepted by OpenStore.
const (
	StoreAuto          = "auto"
	StoreKeychain      = "keychain"
	StoreSecretService = "secret-service"
	StoreFile          = "file"
)

// DefaultService names the Keychain / Secret Service items this package writes.
const DefaultService = "iap-authz"

var (
	// ErrNoCredential: the store has no credential for the account.
	ErrNoCredential = errors.New("no stored credential")
	// ErrNoKeyring: auto selection found no OS keyring. The file store is
	// never chosen in its place; the caller must opt in to it.
	ErrNoKeyring = errors.New("no OS keyring available")
)

// storeProbeAccount is an account no registration has; CheckStore asks for it.
const storeProbeAccount = "agent:user:store-check"

// CheckStore proves store can keep a credential the way Login will: it saves
// a random throwaway value under a probe account, checks it is there, and
// deletes it. Asking alone is not enough (the Keychain answers "not found"
// for a locked keychain, and a locked Secret Service can answer lookups).
// No real credential is touched. Login calls it before the person approves
// anything.
func CheckStore(ctx context.Context, store Store) error {
	v, err := randomB64(32)
	if err != nil {
		return err
	}
	if err := store.Save(ctx, storeProbeAccount, NewSecret("probe-"+v)); err != nil {
		return fmt.Errorf("the %s store can't save a credential: %w", store.Name(), err)
	}
	ok, err := store.Exists(ctx, storeProbeAccount)
	if err == nil && !ok {
		err = errors.New("a saved test item was not found again")
	}
	if derr := store.Delete(ctx, storeProbeAccount); err == nil && derr != nil {
		err = derr
	}
	if err != nil {
		return fmt.Errorf("the %s store does not work: %w", store.Name(), err)
	}
	return nil
}

// OpenStore returns the named store with its default settings. "auto" (or
// "") is the Keychain on macOS and the Secret Service (secret-tool) on
// Linux and the BSDs; it never falls back to the file store.
func OpenStore(name string) (Store, error) {
	switch name {
	case "", StoreAuto:
		switch runtime.GOOS {
		case "darwin":
			return KeychainStore{}, nil
		case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
			if _, err := exec.LookPath("secret-tool"); err != nil {
				return nil, fmt.Errorf("%w: secret-tool is not installed (Debian/Ubuntu: apt install libsecret-tools; Fedora: dnf install libsecret); on a headless machine, opt in to the file store instead", ErrNoKeyring)
			}
			return SecretServiceStore{}, nil
		default:
			return nil, fmt.Errorf("%w on %s; opt in to the file store instead", ErrNoKeyring, runtime.GOOS)
		}
	case StoreKeychain:
		return KeychainStore{}, nil
	case StoreSecretService:
		return SecretServiceStore{}, nil
	case StoreFile:
		dir, err := DefaultFileStoreDir()
		if err != nil {
			return nil, err
		}
		return FileStore{Dir: dir}, nil
	}
	return nil, fmt.Errorf("unknown store %q (want auto, keychain, secret-service or file)", name)
}

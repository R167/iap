package iapclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// FileStore keeps credentials in Dir/credentials.json (a JSON object,
// account → credential), mode 0600 in a 0700 directory. It is for machines
// with no keyring and must be chosen explicitly: anyone who can read the file
// as you (or read your disk) holds the credential. It refuses to read or
// write when the directory or file is a symlink, or is readable, writable or
// executable by group or others. It does not work on Windows, whose
// permission bits it cannot check.
type FileStore struct {
	Dir string
}

const credentialsFile = "credentials.json"

// maxCredentialsFile bounds what Load reads.
const maxCredentialsFile = 1 << 20

// DefaultFileStoreDir is $XDG_STATE_HOME/iap, else ~/.local/state/iap.
func DefaultFileStoreDir() (string, error) {
	if d := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "iap"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "iap"), nil
}

func (FileStore) Name() string { return StoreFile }

func (f FileStore) path() string { return filepath.Join(f.Dir, credentialsFile) }

func (f FileStore) Location(string) string { return f.path() }

// checkPerm refuses a symlink, the wrong type, or any group/other bit.
func checkPerm(path string, wantDir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("file store: %s is a symlink; refusing it", path)
	case wantDir && !fi.IsDir(), !wantDir && !fi.Mode().IsRegular():
		return fmt.Errorf("file store: %s is not a regular %s", path, map[bool]string{true: "directory", false: "file"}[wantDir])
	case fi.Mode().Perm()&0o077 != 0:
		want := map[bool]string{true: "700", false: "600"}[wantDir]
		return fmt.Errorf("file store: %s has mode %04o, looser than %s; refusing it (chmod %s %s)", path, fi.Mode().Perm(), want, want, path)
	}
	return nil
}

// read returns the stored map; a missing file is an empty map.
func (f FileStore) read() (map[string]string, error) {
	if f.Dir == "" {
		return nil, errors.New("file store: no directory")
	}
	if err := checkPerm(f.Dir, true); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	if err := checkPerm(f.path(), false); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	fh, err := os.Open(f.path())
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, maxCredentialsFile))
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		// The decoder's message could quote file content; give none of it.
		return nil, fmt.Errorf("file store: %s is not a JSON object of credentials", f.path())
	}
	return m, nil
}

// write replaces the file atomically (writeFileAtomic: temp file in the same
// directory, synced, renamed, directory synced), creating the directory 0700
// if needed. A rotated credential is saved this way, so a crash mid-save
// leaves the old credential or the new one, never neither.
func (f FileStore) write(m map[string]string) error {
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	if err := checkPerm(f.Dir, true); err != nil {
		return err
	}
	if err := checkPerm(f.path(), false); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(f.path(), append(b, '\n'))
}

func (f FileStore) Save(_ context.Context, account string, cred Secret) error {
	m, err := f.read()
	if err != nil {
		return err
	}
	m[account] = cred.Reveal()
	return f.write(m)
}

func (f FileStore) Load(_ context.Context, account string) (Secret, error) {
	m, err := f.read()
	if err != nil {
		return Secret{}, err
	}
	v, ok := m[account]
	if !ok || v == "" {
		return Secret{}, fmt.Errorf("%w: no entry for %s in %s", ErrNoCredential, account, f.path())
	}
	return NewSecret(v), nil
}

func (f FileStore) Exists(_ context.Context, account string) (bool, error) {
	m, err := f.read()
	if err != nil {
		return false, err
	}
	return m[account] != "", nil
}

func (f FileStore) Delete(_ context.Context, account string) error {
	m, err := f.read()
	if err != nil {
		return err
	}
	if _, ok := m[account]; !ok {
		return nil
	}
	delete(m, account)
	return f.write(m)
}

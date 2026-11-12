package iapclient

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// State is the non-secret record of one program's registration, kept in
// Dir/config.json (StateFile). It holds nothing secret.
type State struct {
	Issuer    string    `json:"server,omitempty"`
	Account   string    `json:"account"` // registration principal, the store's key
	ExpiresAt time.Time `json:"expires_at"`
	// AudienceSuffixes are the extra domains (".example.org") the issuer said
	// at login it may mint tokens for, beyond its own domain.
	AudienceSuffixes []string `json:"audience_suffixes,omitempty"`
	// Store is the store the credential was saved in ("" = auto).
	Store string `json:"store,omitempty"`
	// StoreFallback: Store was used only because no OS keyring worked at
	// login, not chosen. Commands still read the credential from it; the next
	// login tries the keyring again.
	// omitzero, not omitempty: v2's omitempty would still write false.
	StoreFallback bool `json:"store_fallback,omitzero"`
}

// UnmarshalJSONFrom also accepts the issuer's wire name for the suffixes
// (external_audience_suffixes), as another writer may store it. The whole
// State is replaced, not merged into.
func (s *State) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	type plain State // State without its methods, so json decodes it natively
	var v struct {
		P    plain    `json:",embed"`
		Wire []string `json:"external_audience_suffixes"`
	}
	if err := json.UnmarshalDecode(dec, &v); err != nil {
		return err
	}
	*s = State(v.P)
	if len(s.AudienceSuffixes) == 0 {
		s.AudienceSuffixes = v.Wire
	}
	return nil
}

// UnmarshalJSON is UnmarshalJSONFrom for callers on encoding/json (v1).
func (s *State) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, s)
}

// StateFile is Dir/config.json: one registration per program segment (claude
// under Claude Code, cli in a terminal, …), each with its own stored
// credential, so logging in for one program leaves the others alone.
type StateFile struct {
	Registrations map[string]State `json:"registrations,omitempty"`
	// TailscaleClientID is the iap CLI's last --client-id for
	// api.tailscale.com: a Tailscale trust credential's client ID, an
	// identifier, not a secret. iapclient only keeps it.
	TailscaleClientID string `json:"tailscale_client_id,omitempty"`
}

// DefaultDir is os.UserConfigDir()/iap.
func DefaultDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "iap"), nil
}

// StatePath is the state file in dir.
func StatePath(dir string) string { return filepath.Join(dir, "config.json") }

// programOf returns the program segment of a registration account
// (agent:user:<email>:<machine>:<program>).
func programOf(account string) string {
	return account[strings.LastIndex(account, ":")+1:]
}

// LoadStateFile reads dir's state file; a missing file is empty. Older
// layouts are folded in: a top-level "server" is the issuer of every
// registration that names none (the one-registration-per-program layout
// before per-registration issuers), and a top-level single registration
// (account, expires_at, …) becomes its program's entry unless that program
// already has one.
func LoadStateFile(dir string) (StateFile, error) {
	var f StateFile
	b, err := os.ReadFile(StatePath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	// The same object read twice: as the file, and as the top-level fields of
	// the older layouts.
	var legacy State
	if err := json.Unmarshal(b, &f); err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &legacy); err != nil {
		return f, err
	}
	for p, s := range f.Registrations {
		if s.Issuer == "" {
			s.Issuer = legacy.Issuer
			f.Registrations[p] = s
		}
	}
	if legacy.Account != "" {
		if f.Registrations == nil {
			f.Registrations = map[string]State{}
		}
		if _, ok := f.Registrations[programOf(legacy.Account)]; !ok {
			f.Registrations[programOf(legacy.Account)] = legacy
		}
	}
	return f, nil
}

// SaveStateFile writes f to dir (0600 in a 0700 directory), atomically: a
// temp file in dir, synced, then renamed over the old one, so a reader never
// sees half a file.
func SaveStateFile(dir string, f StateFile) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(f, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	return writeFileAtomic(StatePath(dir), append(b, '\n'))
}

// writeFileAtomic replaces path with b (mode 0600) by writing a temp file in
// its directory, syncing it, renaming it over path, and syncing the
// directory, so after a crash path holds the old content or the new, whole.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*") // created 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	_, werr := tmp.Write(b)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // best effort: not every filesystem syncs a directory
		d.Close()
	}
	return nil
}

// updateStateExpiry records exp as the expiry of program's registration in
// dir, if that registration is still account (a login in between replaced
// it otherwise). The caller holds the registration's lock.
func updateStateExpiry(dir, program, account string, exp time.Time) error {
	f, err := LoadStateFile(dir)
	if err != nil {
		return err
	}
	st, ok := f.Registrations[program]
	if !ok || st.Account != account || st.ExpiresAt.Equal(exp) {
		return nil
	}
	st.ExpiresAt = exp
	f.Registrations[program] = st
	return SaveStateFile(dir, f)
}

// LoadState reads program's registration from dir; none is an empty State.
func LoadState(dir, program string) (State, error) {
	f, err := LoadStateFile(dir)
	return f.Registrations[program], err
}

// SaveState records s as program's registration in dir, keeping the others.
func SaveState(dir, program string, s State) error {
	f, err := LoadStateFile(dir)
	if err != nil {
		return err
	}
	if f.Registrations == nil {
		f.Registrations = map[string]State{}
	}
	f.Registrations[program] = s
	return SaveStateFile(dir, f)
}

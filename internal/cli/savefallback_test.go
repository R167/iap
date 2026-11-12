package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/R167/iap/iapclient"
)

// After the exchange, a store that refuses the credential is reported, and
// on a terminal the file store is offered: yes saves there, no or no
// terminal keeps CredentialLostError, which then names --store file.
func TestOfferFileStore(t *testing.T) {
	isolate(t)
	file, err := iapclient.OpenStore(iapclient.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("keyring locked")
	for _, c := range []struct {
		name        string
		interactive bool
		answer      string
		want        bool
		asked       bool
	}{
		{"yes", true, "y\n", true, true},
		{"Yes", true, " Yes ", true, true},
		{"no", true, "n", false, true},
		{"enter", true, "", false, true},
		{"non-interactive", false, "y", false, false},
	} {
		var out bytes.Buffer
		read := func() (string, error) {
			if !c.interactive {
				t.Errorf("%s: read stdin without a terminal", c.name)
			}
			return c.answer, nil
		}
		got := offerFileStore(read, c.interactive, &out, file)(iapclient.StoreSecretService, refused)
		if (got != nil) != c.want || (got != nil && got.Name() != iapclient.StoreFile) {
			t.Errorf("%s: store = %v", c.name, got)
		}
		if !strings.Contains(out.String(), "The secret-service store refused the refresh credential: keyring locked") {
			t.Errorf("%s: failure not reported: %q", c.name, out.String())
		}
		if asked := strings.Contains(out.String(), "credentials.json (mode 0600) instead? [y/N]"); asked != c.asked {
			t.Errorf("%s: asked = %v: %q", c.name, asked, out.String())
		}
	}
	// A failing file store is never offered the file store again.
	if got := offerFileStore(func() (string, error) { return "y", nil }, true, io.Discard, file)(iapclient.StoreFile, refused); got != nil {
		t.Error("offered the file store after the file store failed")
	}
	lost := &iapclient.CredentialLostError{Principal: "agent:user:alice@example.com:box:cli:*", Issuer: defaultIssuer, Store: iapclient.StoreSecretService, Err: iapclient.ErrSecretServiceUnavailable}
	if msg := withHint(lost).Error(); !strings.Contains(msg, "credential is lost") || !strings.Contains(msg, "--store file") {
		t.Errorf("hint = %s", msg)
	}
}

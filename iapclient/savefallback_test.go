package iapclient

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// SaveFallback gets one chance at the credential still in memory: a store
// it returns is used and recorded as a fallback; nil keeps the loss.
func TestLoginSaveFallback(t *testing.T) {
	for _, offer := range []bool{true, false} {
		p := &pkceIssuer{}
		dir := t.TempDir()
		alt := &memStore{}
		c, err := New(Config{Issuer: testIssuer, Dir: dir, Store: &failingStore{okSaves: 1}, HTTPClient: &http.Client{Transport: &handlerTransport{h: p}}})
		if err != nil {
			t.Fatal(err)
		}
		var prompt bytes.Buffer
		var gotStore string
		var gotErr error
		reg, err := c.Login(context.Background(), LoginOptions{Machine: "box", Headless: true, Prompt: &prompt, Timeout: 5 * time.Second,
			ReadCode: func() (string, error) {
				return p.approve(consentURL(t, prompt.String()).Query().Get("code_challenge")), nil
			},
			SaveFallback: func(store string, err error) Store {
				gotStore, gotErr = store, err
				if offer {
					return alt
				}
				return nil
			}})
		if gotStore != "mem" || gotErr == nil || strings.Contains(gotErr.Error(), testRefresh) {
			t.Errorf("offer=%v: SaveFallback(%q, %v)", offer, gotStore, gotErr)
		}
		if !offer {
			if !errors.As(err, new(*CredentialLostError)) {
				t.Errorf("declined: %v", err)
			}
			continue
		}
		if err != nil || alt.m[testAccount] != testRefresh || reg.Store != "mem" || reg.Location != "mem/"+testAccount {
			t.Fatalf("accepted: %+v, %v", reg, err)
		}
		if st, _ := LoadState(dir, "cli"); !st.StoreFallback || st.Account != testAccount {
			t.Errorf("state = %+v", st)
		}
	}
}

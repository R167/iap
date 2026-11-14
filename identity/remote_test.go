package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// jwksServer serves the current document and counts fetches.
type jwksServer struct {
	*httptest.Server
	doc     atomic.Value // []byte
	status  atomic.Int32
	fetches atomic.Int32
	block   chan struct{} // when non-nil, each request waits for it
}

func newJWKSServer(t *testing.T, doc []byte) *jwksServer {
	t.Helper()
	s := &jwksServer{}
	s.doc.Store(doc)
	s.status.Store(http.StatusOK)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.fetches.Add(1)
		if s.block != nil {
			select {
			case <-s.block:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(int(s.status.Load()))
		w.Write(s.doc.Load().([]byte))
	}))
	t.Cleanup(s.Close)
	return s
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// newRemote returns a RemoteJWKS on srv whose fetch results arrive on the
// returned channel.
func newRemote(srv *jwksServer, c *clock) (*RemoteJWKS, chan error) {
	results := make(chan error, 16)
	return &RemoteJWKS{
		URL:     srv.URL,
		Client:  srv.Client(),
		Now:     c.Now,
		OnFetch: func(err error) { results <- err },
	}, results
}

func TestRemoteJWKS(t *testing.T) {
	ctx := context.Background()
	k1, k2 := newTestKey(t), newTestKey(t)
	srv := newJWKSServer(t, jwks(t, k1.jwk()))
	c := &clock{now: testNow}
	src, results := newRemote(srv, c)
	fetches := func() int { return int(srv.fetches.Load()) }

	if _, err := src.Key(ctx, k1.kid); err != nil || fetches() != 1 {
		t.Fatalf("first use: %v, %d fetches", err, fetches())
	}
	if err := <-results; err != nil {
		t.Fatalf("OnFetch: %v", err)
	}
	if _, err := src.Key(ctx, k1.kid); err != nil || fetches() != 1 {
		t.Fatalf("cached: %v, %d fetches", err, fetches())
	}

	// A new kid within MinInterval of the last fetch is refused without a fetch.
	srv.doc.Store(jwks(t, k1.jwk(), k2.jwk()))
	if _, err := src.Key(ctx, k2.kid); !errors.Is(err, ErrUnknownKey) || fetches() != 1 {
		t.Fatalf("new kid within MinInterval: %v, %d fetches", err, fetches())
	}
	// After it, the unknown kid triggers one fetch, and the caller waits for it.
	c.advance(DefaultMinInterval)
	if _, err := src.Key(ctx, k2.kid); err != nil || fetches() != 2 {
		t.Fatalf("new kid after MinInterval: %v, %d fetches", err, fetches())
	}
	<-results

	// A flood of made-up kids costs no fetch within MinInterval.
	for range 50 {
		if _, err := src.Key(ctx, newTestKey(t).kid); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("made-up kid: %v", err)
		}
	}
	if fetches() != 2 {
		t.Fatalf("made-up kids fetched: %d fetches, want 2", fetches())
	}

	// Past TTL a known kid answers at once from the old set and starts a
	// refresh; once it lands, a retired key stops verifying.
	srv.doc.Store(jwks(t, k2.jwk()))
	c.advance(DefaultTTL)
	if _, err := src.Key(ctx, k1.kid); err != nil {
		t.Fatalf("known kid past TTL: %v", err)
	}
	if err := <-results; err != nil {
		t.Fatalf("background refresh: %v", err)
	}
	if _, err := src.Key(ctx, k1.kid); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("retired key after refresh: %v", err)
	}

	// A failed refresh keeps the last good set.
	srv.status.Store(http.StatusInternalServerError)
	c.advance(DefaultTTL)
	if _, err := src.Key(ctx, k2.kid); err != nil {
		t.Fatalf("known kid while the refresh fails: %v", err)
	}
	if err := <-results; err == nil {
		t.Fatal("OnFetch got no error for a 500")
	}
	if _, err := src.Key(ctx, k2.kid); err != nil {
		t.Fatalf("last good set dropped after a failed refresh: %v", err)
	}
}

func TestRemoteJWKSNeverLoaded(t *testing.T) {
	ctx := context.Background()
	k := newTestKey(t)
	srv := newJWKSServer(t, []byte("down"))
	srv.status.Store(http.StatusServiceUnavailable)
	c := &clock{now: testNow}
	src, results := newRemote(srv, c)

	if _, err := src.Key(ctx, k.kid); !errors.Is(err, ErrNoKeys) || !strings.Contains(err.Error(), "503") {
		t.Fatalf("first use against a failing issuer: %v", err)
	}
	<-results
	// Within MinInterval: still ErrNoKeys with the cause, no new fetch.
	if _, err := src.Key(ctx, k.kid); !errors.Is(err, ErrNoKeys) || !strings.Contains(err.Error(), "503") || srv.fetches.Load() != 1 {
		t.Fatalf("retry within MinInterval: %v, %d fetches", err, srv.fetches.Load())
	}
	// The issuer recovers: the next fetch after MinInterval loads the set.
	srv.status.Store(http.StatusOK)
	srv.doc.Store(jwks(t, k.jwk()))
	c.advance(DefaultMinInterval)
	if _, err := src.Key(ctx, k.kid); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

// A hung issuer never blocks a caller past its context or a fetch past
// FetchTimeout.
func TestRemoteJWKSSlowIssuer(t *testing.T) {
	k := newTestKey(t)
	srv := newJWKSServer(t, jwks(t, k.jwk()))
	srv.block = make(chan struct{})
	t.Cleanup(func() { close(srv.block) })
	c := &clock{now: testNow}
	src, results := newRemote(srv, c)
	src.FetchTimeout = 200 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := src.Key(ctx, k.kid); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller deadline: %v", err)
	}
	select {
	case err := <-results:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("fetch ended with %v, want its timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fetch outlived FetchTimeout")
	}
	if _, err := src.Key(context.Background(), k.kid); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("after a timed-out fetch: %v", err)
	}
}

func TestRemoteJWKSRefresh(t *testing.T) {
	k := newTestKey(t)
	srv := newJWKSServer(t, jwks(t, k.jwk()))
	src, _ := newRemote(srv, &clock{now: testNow})
	if err := src.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Key(context.Background(), k.kid); err != nil || srv.fetches.Load() != 1 {
		t.Fatalf("after Refresh: %v, %d fetches", err, srv.fetches.Load())
	}
}

// Concurrent callers share one fetch.
func TestRemoteJWKSConcurrent(t *testing.T) {
	k := newTestKey(t)
	srv := newJWKSServer(t, jwks(t, k.jwk()))
	src := &RemoteJWKS{URL: srv.URL, Client: srv.Client()}
	v := NewVerifier(src, testIssuer, testHost)
	v.Now = func() time.Time { return testNow }
	raw := k.mint(t, idClaims("user:alice@example.com"))
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := v.Verify(context.Background(), raw); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := srv.fetches.Load(); n != 1 {
		t.Errorf("%d fetches, want 1", n)
	}
}

func TestRemoteJWKSRefusesBadDocuments(t *testing.T) {
	k := newTestKey(t)
	for name, doc := range map[string][]byte{
		"not json":  []byte("<html>"),
		"too large": []byte(`{"keys":[],"pad":"` + strings.Repeat("x", maxJWKSSize) + `"}`),
		"private":   jwks(t, with(k.jwk(), "d", b64.EncodeToString(k.priv.Seed()))),
	} {
		srv := newJWKSServer(t, doc)
		src := &RemoteJWKS{URL: srv.URL, Client: srv.Client()}
		if _, err := src.Key(context.Background(), k.kid); !errors.Is(err, ErrNoKeys) {
			t.Errorf("%s: %v, want ErrNoKeys", name, err)
		}
	}
}

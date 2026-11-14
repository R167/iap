package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ErrNoKeys is returned while a RemoteJWKS has never loaded a key set. It
// wraps the last fetch's error, if any.
var ErrNoKeys = errors.New("no JWKS loaded")

// Defaults for the zero fields of RemoteJWKS.
const (
	DefaultTTL          = time.Hour
	DefaultMinInterval  = 30 * time.Second
	DefaultFetchTimeout = 10 * time.Second
)

// maxJWKSSize bounds the JWKS response body.
const maxJWKSSize = 1 << 20

// RemoteJWKS is a key source that fetches the issuer's JWKS document from
// URL, typically https://<issuer>/.well-known/jwks.json.
//
// It fetches on first use and keeps the set for TTL, then refreshes it in
// the background while still answering from it. A token naming a kid the set
// does not hold triggers a fetch, but fetches never start more often than
// once per MinInterval, so a flood of made-up kids cannot hammer the issuer.
// A failed fetch keeps the last good set. Until a set has loaded, Key returns
// ErrNoKeys. Set the fields before the first Key call and leave them alone
// after.
type RemoteJWKS struct {
	URL          string
	Client       *http.Client  // nil: http.DefaultClient
	TTL          time.Duration // zero: DefaultTTL
	MinInterval  time.Duration // zero: DefaultMinInterval
	FetchTimeout time.Duration // zero: DefaultFetchTimeout; bounds each fetch
	// OnFetch, if set, is called after every fetch with its error (nil on
	// success), for logging or metrics, on the goroutine that fetched.
	OnFetch func(err error)
	Now     func() time.Time // nil: time.Now

	mu        sync.Mutex
	keys      keySet
	fetched   time.Time     // when keys loaded
	attempted time.Time     // when the last fetch started
	lastErr   error         // the last fetch's error
	inflight  chan struct{} // closed when the running fetch ends
}

func (r *RemoteJWKS) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Key returns the key for kid, fetching the set when it has none, when kid is
// unknown, or when the set is older than TTL, within the MinInterval bound.
// A caller that needs a fetch waits for it until ctx ends.
func (r *RemoteJWKS) Key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	r.mu.Lock()
	now := r.now()
	canFetch := r.inflight == nil && (r.attempted.IsZero() || now.Sub(r.attempted) >= orDefault(r.MinInterval, DefaultMinInterval))
	if r.keys != nil {
		k, err := r.keys.lookup(kid)
		if err == nil {
			if canFetch && now.Sub(r.fetched) >= orDefault(r.TTL, DefaultTTL) {
				r.startFetch(now)
			}
			r.mu.Unlock()
			return k, nil
		}
		if !canFetch && r.inflight == nil {
			r.mu.Unlock()
			return nil, err
		}
	} else if !canFetch && r.inflight == nil {
		err := r.noKeysLocked()
		r.mu.Unlock()
		return nil, err
	}
	done := r.inflight
	if done == nil {
		done = r.startFetch(now)
	}
	r.mu.Unlock()

	select {
	case <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keys == nil {
		return nil, r.noKeysLocked()
	}
	return r.keys.lookup(kid)
}

// Refresh fetches the set now, or waits for a fetch already running, and
// returns its error. Calling it in a goroutine at start-up loads the keys
// before the first request; Key works without it.
func (r *RemoteJWKS) Refresh(ctx context.Context) error {
	r.mu.Lock()
	done := r.inflight
	if done == nil {
		done = r.startFetch(r.now())
	}
	r.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

func (r *RemoteJWKS) noKeysLocked() error {
	if r.lastErr != nil {
		return fmt.Errorf("%w: %w", ErrNoKeys, r.lastErr)
	}
	return ErrNoKeys
}

// startFetch starts a fetch that outlives the request that triggered it,
// bounded by FetchTimeout. r.mu is held.
func (r *RemoteJWKS) startFetch(now time.Time) chan struct{} {
	done := make(chan struct{})
	r.inflight, r.attempted = done, now
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), orDefault(r.FetchTimeout, DefaultFetchTimeout))
		keys, err := r.fetch(ctx)
		cancel()
		r.mu.Lock()
		if err == nil {
			r.keys, r.fetched = keys, r.now()
		}
		r.lastErr = err
		r.inflight = nil
		close(done)
		r.mu.Unlock()
		if r.OnFetch != nil {
			r.OnFetch(err)
		}
	}()
	return done
}

func (r *RemoteJWKS) fetch(ctx context.Context) (keySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("JWKS: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS: %s: %s", r.URL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSSize+1))
	if err != nil {
		return nil, fmt.Errorf("JWKS: %w", err)
	}
	if len(body) > maxJWKSSize {
		return nil, fmt.Errorf("JWKS: %s: response over %d bytes", r.URL, maxJWKSSize)
	}
	return parseJWKS(body)
}

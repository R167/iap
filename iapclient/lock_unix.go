//go:build unix

package iapclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// lockFile takes an exclusive flock(2) on path (created 0600, its directory
// 0700), waiting until it is free, ctx ends, or maxLockWait passes. flock
// locks belong to the open file, so two opens conflict even within one
// process: goroutines and processes are serialised alike. The lock is
// released by the returned func, or by the kernel when the process exits, so
// a crashed holder never leaves it stuck.
func lockFile(ctx context.Context, path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(maxLockWait)
	delay := 5 * time.Millisecond
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("another iap process has held %s for over %s", path, maxLockWait)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("waiting for %s: %w", path, ctx.Err())
		case <-time.After(delay):
		}
		delay = min(delay*2, 100*time.Millisecond)
	}
}

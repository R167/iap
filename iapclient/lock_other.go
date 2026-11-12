//go:build !unix

package iapclient

import "context"

// lockFile is a no-op where there is no flock(2) (no store here works on
// those systems anyway). The issuer's grace window still covers two
// processes rotating one registration at once.
func lockFile(context.Context, string) (func(), error) { return func() {}, nil }

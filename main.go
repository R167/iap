// Command iap gets short-lived, host-bound credentials for hosts behind an
// iap-authz identity-aware proxy. See github.com/R167/iap for the guide.
package main

import (
	"os"

	"github.com/R167/iap/internal/cli"
)

func main() { os.Exit(cli.Main()) }

package iapclient_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/R167/iap/iapclient"
)

// Calling a protected host from Go, after `iap login` on this machine.
func Example() {
	store, err := iapclient.OpenStore(iapclient.StoreAuto) // or StoreFile, chosen explicitly
	if err != nil {
		log.Fatal(err)
	}
	client, err := iapclient.New(iapclient.Config{
		Issuer: "https://access.example.com", // your issuer
		Store:  store,
	})
	if err != nil {
		log.Fatal(err)
	}
	// The session names this run; tokens are minted per (session, host).
	hc, err := client.HTTPClient("nightly-report")
	if err != nil {
		log.Fatal(err) // e.g. not logged in
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://app.example.com/api/status", nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := hc.Do(req) // a *iapclient.ForbiddenError when no grant covers you
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(resp.Status, len(body))
}

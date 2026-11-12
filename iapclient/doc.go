// Package iapclient lets a program act as an agent:user principal against an
// identity-aware proxy whose issuer mints short-lived, host-bound access
// tokens (iap-authz's agent tokens).
//
// A person registers a machine and program once in the browser (Client.Login:
// loopback redirect + PKCE). The issuer returns a refresh credential, valid
// about 30 days, which goes into a Store (macOS Keychain, the Secret Service
// through secret-tool, or an explicitly chosen 0600 file). From then on a
// TokenSource mints an access token for one session on one exact host, and a
// Transport sends it as `Proxy-Authorization: Bearer <token>`.
//
// Invariants this package enforces:
//   - tokens are minted for and sent to https URLs only, on hosts under the
//     issuer's own domain or a domain it advertised at login;
//   - a token is minted for exactly the request's host and sent only there,
//     never on a redirect to another host;
//   - access tokens live in memory only; the refresh credential lives only in
//     the Store;
//   - neither appears in an error, a String/fmt/slog rendering (Secret), a
//     process argv (stores use stdin), or stdout.
//
// The package imports only the standard library.
package iapclient

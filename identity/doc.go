// Package identity verifies the X-IAP-Identity header an iap-authz
// identity-aware proxy attaches to every request it allows: an EdDSA JWT
// naming the caller's principal, bound to one host.
//
// A backend builds one Verifier for its own host with a key source, usually
// RemoteJWKS on the issuer's JWKS URL, or StaticJWKS on a fixed document, and
// calls Verify on each request. Verify returns only a canonical, concrete
// principal of a type this package knows: user:, sa:, agent:user and
// agent:k8s. Which of those a backend accepts is the backend's own decision.
//
// The package imports only the standard library.
package identity

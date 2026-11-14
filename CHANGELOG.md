# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-11-14

### Added

- `identity` package, for services behind the proxy: verifies the signed
  `X-IAP-Identity` header and returns the caller's principal. Keys come from a
  fixed JWKS document (`StaticJWKS`) or are fetched and cached from a URL
  (`RemoteJWKS`). Standard library only.

## [0.1.1] - 2026-11-11

### Changed

- JSON encoding uses plain `encoding/json/v2` defaults. Files and wire messages
  written by earlier versions still load.

### Fixed

- A `credentials.json` holding `null` is read as empty instead of panicking
  when a credential is saved over it.

## [0.1.0] - 2026-11-11

### Added

- `iap` command: `login` (browser or `--headless`), `curl`, `expose`, `status`
  and `logout`.
- `iapclient` package: an `*http.Client` that authenticates to hosts behind the
  proxy on its own.
- `expose` package: the tunnel client behind `iap expose`, and its wire
  protocol.
- Release binaries for Linux and macOS (amd64, arm64) with `SHA256SUMS` and
  signed build-provenance attestations.

[unreleased]: https://github.com/R167/iap/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/R167/iap/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/R167/iap/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/R167/iap/releases/tag/v0.1.0

# iap

Client side of an iap-authz identity-aware proxy: a CLI and two Go packages that get a local program or AI agent short-lived, host-bound tokens as `agent:user:<email>:<machine>:<program>:<session>`. `README.md` is the user guide; this file is for working on the code. The issuer (iap-authz) and the tunnel server (iap-tunnel) live in a private repository; nothing server-side belongs here.

## Layout

| Path | What | Rules |
|---|---|---|
| `iapclient/` | The library: issuer config, credential stores (Keychain via `security`, Secret Service via `secret-tool`, file), loopback and headless login, token cache, `Transport`, refresh rotation under a file lock | **Standard library only.** No third-party import, ever; consumers rely on it. Exported API is public: additive changes only. |
| `expose/` | Tunnel client (`Run`) and the wire protocol (`proto.go`) | Imported by the private iap-tunnel server; see "Wire protocol". Depends on `github.com/coder/websocket` and `github.com/hashicorp/yamux`. |
| `internal/cli/` | The `iap` command (cobra): `main.go` (root, login, curl, status, logout), `curlargs.go` (curl option allowlist), `expose.go` | `Main() int` is the whole program; it returns the exit status. |
| `cmd/iap/main.go`, `main.go` | Identical `package main` shims: `os.Exit(cli.Main())` | Both exist so `go install github.com/R167/iap@latest` and `.../cmd/iap@latest` each produce `iap`. Keep them identical and logic-free. |

macOS and Linux only (`internal/cli` uses process groups, `TIOCSPGRP`, `flock`). Windows is unsupported: there is no keyring backend and the file store cannot check permissions.

## Invariants

- **Nothing prints a token, a refresh credential (`iapr_…`) or a pasted login code.** Not stdout, not errors, not logs, not argv. Secrets travel as `iapclient.Secret` (redacts under every `fmt` verb and `slog`, refuses JSON) and reach child processes on stdin or an inherited pipe (`curl -H @/dev/fd/3`). There is deliberately no `token` subcommand; don't add one.
- **Tokens go only to `https://` hosts under the issuer's domain or a suffix it advertised** (`Client.CheckURL`, `AllowedSuffixes`), and never across a redirect to another host. The refresh credential goes only to the issuer it was registered with (`IssuerMismatchError`). The Tailscale path (`api.tailscale.com`) is decided before the suffix check, so an issuer advertising `.tailscale.com` can never receive a token there as `Proxy-Authorization`.
- **`curlargs.go` is an allowlist.** Anything that prints headers, changes the destination host, disables TLS checks or reads headers from a file stays refused. `-q` stays the first curl argument (no `~/.curlrc`).
- **Store fallback is never silent.** Only `login --headless` without `--store` falls back from an unreachable keyring to the file store, announced every time and recorded as `store_fallback`, not as the choice.
- **Refresh rotation:** every refresh grant sends `rotate=1` under an exclusive `flock` on `<Dir>/locks/<program>.lock`, re-reads the credential from the store each time, and saves a rotated credential before using the access token. `TestRotationCrashBeforeSave` and friends in `iapclient/rotation_test.go` pin this.
- The built-in default issuer is `https://access.iap.r167.dev` (`internal/cli/main.go`, `defaultIssuer`); a `config.json` without an issuer belongs to it only.

## Wire protocol (`expose/proto.go`)

The iap-tunnel server imports `github.com/R167/iap/expose` for these definitions, so they are a contract with deployed servers and with every released client.

- Exported identifiers in `expose` keep their names, types and meanings. Document every exported symbol.
- Changes are additive and optional on both sides: a new query parameter, header, control-message field or close code must be ignored by an old peer and must not be required from one. An old client must keep working against a new server and the reverse.
- Never renumber or reuse a close code, `Refusal.Code` string, query key or header name. Retire one by leaving it defined and unused.
- A breaking change needs a new endpoint path (`/v2/connect`), with the server serving both until old clients are gone.
- Land a protocol change here first, tag a release, then bump the server to that version.
- **The peer may encode and decode with `encoding/json` (v1) or `encoding/json/v2`**, and either side may move between them independently. Every message must decode the same under both; `expose/proto_test.go` checks that a v1 decoder reads `MarshalLine` output and that `readControl`/`refusalFrom` read what a v1 server writes. See "JSON".

## JSON

All code uses `encoding/json/v2` (and `encoding/json/jsontext`) with its default options: `json.Marshal`/`Unmarshal`/`MarshalWrite`/`UnmarshalRead`, and `jsontext.WithIndent("  ")` for `config.json` and `credentials.json`. No `encoding/json` import outside tests, no third-party JSON module.

- **v1 peers are fine without compatibility options.** Everything decoded here is written by our own code with exact field tags (the issuer's token responses, the tunnel server's control messages, `config.json` and `credentials.json` from older releases) or is a standard OAuth response with exact lowercase names (`api.tailscale.com`'s token exchange), so v1's leniency (case-insensitive names, duplicate names, invalid UTF-8) guards against input that never occurs; unknown members and `null` decode the same under both versions. Output need not match v1's bytes: v1 decodes `[]` and `null` alike, and key order and HTML escaping don't change meaning.
- **Tag `omitzero`, not `omitempty`, on a number or bool field that should be dropped at zero.** v2's `omitempty` only drops what encodes as `null`, `""`, `[]` or `{}`, so it writes `0` and `false`. `omitempty` stays right for strings, slices and maps. v1 honours `omitzero` too.
- `null` into a map leaves it nil; initialize after decoding if you write to it (`FileStore.read`).
- `time.Duration` has no v2 default (marshalling one fails); give it an explicit format or keep it out of JSON types.
- Custom decoding: implement `UnmarshalJSONFrom` and decode inner values with `json.UnmarshalDecode(dec, …)` so the caller's options apply (`State`). An exported type that had `UnmarshalJSON` keeps it (public API), delegating to `json.Unmarshal`. To decode a type's plain fields from inside its own method, use a method-less local type in a named field tagged `json:",embed"` (v2 ignores an unknown option such as `inline` silently).
- `Secret` refuses every marshalling interface either version or an `encoding.*Appender` user tries first (`MarshalJSONTo`, `MarshalJSON`, `AppendText`, `MarshalText`, `AppendBinary`, `MarshalBinary`); `TestSecretRefusesJSONV2` covers v1 and v2, nested, as map keys and values. Keep every one when adding another.
- v1 compatibility tests (`iapclient/jsonv1_test.go`, `expose/proto_test.go`) use literal v1 output, or import `encoding/json` as `jsonv1` as the other side; that is the only place v1 appears.

## Develop and test

```bash
go vet ./...
go test -race ./...
gofmt -l .           # must print nothing (CI checks it)
go run ./cmd/iap --help
go run -ldflags "-X github.com/R167/iap/internal/cli.Version=v0.0.0-test" ./cmd/iap --version
```

- Tests use example names only (`alice@example.com`, `app.iap.r167.dev` for the default issuer's domain, `*.example.com`/`.net`/`.test`). This repository is public: no real email addresses, hostnames, IPs or tailnet names in code, tests or docs.
- Tests never touch the real keyring or config: `isolate(t)` (`internal/cli/main_test.go`) points `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` at a temp dir and resets the root flags; tests save state with `Store: iapclient.StoreFile` (or a fake `Store`) and pin `autoStoreName` when they exercise the auto default. Keep it that way for new tests.
- PTY tests (`pty_*_test.go`) skip when no pty is available. `TestCurlCommandRealCurl` skips without `curl`.
- The `expose` package's end-to-end tests need the tunnel server and run in the server's repository; here it has unit tests only (`proto_test.go`, decoding with a v1 peer). Unit-testable additions to `expose` should get tests here.
- CI (`.github/workflows/ci.yml`) runs gofmt, vet and race tests on ubuntu-latest and macos-latest.

## Release

1. Merge to `master` with CI green.
2. Tag and push: `git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0` (semver; a protocol or exported-API break needs a new major version and a `/vN` module path).
3. `.github/workflows/release.yml` vets, tests, builds `iap_{linux,darwin}_{amd64,arm64}` with `CGO_ENABLED=0 -trimpath -ldflags "-s -w -X .../internal/cli.Version=<tag>"`, writes `SHA256SUMS`, attests build provenance for each binary, and creates the GitHub release with `gh`.

Third-party actions are pinned to full commit SHAs with a `# vX.Y.Z` comment. To bump one, resolve the tag (`gh api repos/<owner>/<repo>/git/ref/tags/<tag>`; if `object.type` is `tag`, follow it to the commit) and update both.

`Version` falls back to the module version from the build info (`go install ...@v0.2.0`), else `dev`.

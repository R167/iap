# iap

[![ci](https://github.com/R167/iap/actions/workflows/ci.yml/badge.svg)](https://github.com/R167/iap/actions/workflows/ci.yml)

`iap` lets a program on your computer, or an AI coding agent working for you, call web services that sit behind an identity-aware proxy (IAP) run with [iap-authz](#how-it-works). You approve the computer once in a browser. After that, every request gets a short-lived token that works for exactly one host, and the tool sends it for you. Nothing in it ever prints a token.

It comes in three parts:

- **`iap`**, a command-line tool: `iap login`, `iap curl`, `iap expose`, `iap status`, `iap logout`.
- **`iapclient`** (`github.com/R167/iap/iapclient`), a Go package with the same logic, for programs that want an `*http.Client` that authenticates on its own. It depends only on the standard library.
- **`expose`** (`github.com/R167/iap/expose`), the tunnel client behind `iap expose`, and the wire protocol the tunnel service speaks.

macOS and Linux are supported; Windows is not.

Examples on this page use `access.example.com` as the issuer and `app.example.com` as a protected host. Replace them with the names the person who runs your proxy gives you.

## How it works

Three parties are involved:

| Party | What it is | Example |
|---|---|---|
| **Issuer** | The service that registers your computer and hands out tokens. It also hosts the admin page where access is granted and revoked. | `https://access.example.com` |
| **Protected host** | A website or API behind the proxy. The proxy checks every request's token before the request reaches it. | `https://app.example.com` |
| **You** | A person with an account at the issuer, plus a program or agent acting for you. | `agent:user:you@example.com:laptop:claude:<session>` |

**Registration (once per computer and program; it lasts while it is used, and expires after 30 days without use).** `iap login` opens the issuer's consent page in your browser. You sign in there as yourself and click Register. The issuer then gives `iap` a **refresh credential**, a long random string beginning `iapr_`. It identifies this registration: you, this machine name, this program name. `iap` stores it in your operating system's keyring and nowhere else. On a machine with no browser, `iap login --headless` prints the consent URL for you to open on any other device, and you paste a one-time code from the page back into the terminal instead.

**Per request.** `iap` sends the refresh credential to the issuer and asks for an **access token** for one host and one session. For a host in the issuer's own domain, it answers only if a grant there covers this agent. For a host in another domain the issuer serves, it answers for any active registration, and that domain decides each request. The token:

- works for that one host name only, and is refused anywhere else;
- expires after at most 1 hour;
- names you, the machine, the program and the session, so the service's logs show which agent did what;
- is never written to disk. `iap curl` mints a new one for each call. The Go library keeps it in memory until about a minute before it expires.

Anyone who can sign in to the issuer may register their own agents: the registration takes the email you are signed in with, and nobody can register an agent for someone else.

**Access comes from grants.** A registration reaches a host only where a grant covers it; someone with admin rights at the issuer grants that per host (a grant that already covers your pattern applies at once). An agent also never gets more access than its owner has: if your own access to a host is removed, your agents lose it at once.

**Revoking.** The issuer's page lists your own registrations ("Your agents"; an admin sees everyone's under Agents). Revoking one there stops all of its tokens for the issuer's own hosts within a second; a token already minted for another domain keeps working there until it expires (at most 15 minutes). `iap logout` deletes only the local copy of the refresh credential.

**Which hosts.** Tokens are only ever minted for, and sent to, `https://` hosts under the issuer's own domain (for `https://access.example.com`, anything under `example.com`), plus any further domains the issuer lists when you log in. `iap status` shows them.

## Install

`iap curl` needs `curl` on your `PATH`.

**Release binary.** Each [release](https://github.com/R167/iap/releases) has static binaries named `iap_<os>_<arch>` for `linux_amd64`, `linux_arm64`, `darwin_arm64` and `darwin_amd64`, a `SHA256SUMS` file, and a signed build-provenance attestation for each binary.

```bash
VERSION=v0.1.0   # the release you want
curl -fsSLO https://github.com/R167/iap/releases/download/$VERSION/iap_linux_amd64
curl -fsSLO https://github.com/R167/iap/releases/download/$VERSION/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS      # macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
gh attestation verify iap_linux_amd64 --repo R167/iap   # optional: proves GitHub Actions built it from this repo
install -m 0755 iap_linux_amd64 ~/.local/bin/iap
```

On macOS, a binary downloaded with a browser is quarantined; one fetched with `curl` is not.

**From source** (Go 1.27 or later). Either path installs a binary named `iap`:

```bash
go install github.com/R167/iap@latest
go install github.com/R167/iap/cmd/iap@latest
```

`iap --version` prints the release version (`dev` for a build from an untagged checkout).

Where the refresh credential is kept:

| System | Default store | Needs |
|---|---|---|
| macOS | the login Keychain (service `iap-authz`) | nothing |
| Linux desktop | the Secret Service (GNOME Keyring, KWallet, KeePassXC) via `secret-tool` | `secret-tool` (Debian/Ubuntu: `apt install libsecret-tools`; Fedora: `dnf install libsecret`) and a logged-in desktop session |
| Linux server, no desktop | the Secret Service if one answers; with `login --headless`, otherwise the file store | `--store file` at a non-headless login |

`iap` never quietly switches from a keyring to a file. A plain `iap login` that finds no usable keyring stops and says so. `iap login --headless` without `--store` uses the keyring when it works and otherwise the file store, and says so before it prints the consent URL, every time it does. That fallback is not remembered as your choice: later commands read the credential from the file, and the next login tries the keyring again. Pass `--store file` to make the file your choice, or `--store secret-service` to make the login stop instead. Every login first saves and deletes a test item in its store, so a store that can't keep the credential fails before you approve anything. If saving still fails after you approved, `iap` says which store failed and why and, on a terminal, offers to save the credential to the file store instead (`[y/N]`; a yes is remembered as a fallback, like the headless one). Otherwise it tells you the registration exists but its credential is lost, where to revoke it, and that `--store file` avoids it.

**The file store** (`--store file`) keeps the credential in `$XDG_STATE_HOME/iap/credentials.json` (default `~/.local/state/iap/credentials.json`). The file is mode 0600 inside a 0700 directory. `iap` refuses to use it if either is a symlink, or if the permissions let anyone else read it. Anyone who can read files as your user, or who can read the disk, can read the credential, so use it only where there is no keyring. The store chosen at login is remembered, so later commands need no flag.

## Use

The issuer defaults to the one compiled into the tool (`https://access.iap.r167.dev`). To use a different one, pass `--issuer https://access.example.com` to `login`. Later commands remember it. An issuer must be `https://<host>` with at least three labels and no port or path; its domain is its host minus the first label.

### login

```bash
iap login                                # opens the consent page in your browser
iap login --machine laptop --program claude
iap login --headless                     # no browser here: approve on another device, paste a code
```

The machine name defaults to the computer's short hostname. The program name defaults to `claude` inside Claude Code, otherwise `cli`. Both must be lowercase letters, digits, `.`, `_` or `-`. Each program is its own registration with its own stored credential: logging in as `claude` leaves the `cli` registration alone, and `iap curl --program <p>` / `iap logout --program <p>` pick one.

When you click Register, the issuer sends your browser to `http://127.0.0.1:<port>/callback` on the same computer. That is how the credential reaches `iap`. It has to finish within 5 minutes.

**On a computer without a browser** (a server you reach over SSH, a headless box an agent runs on), use `--headless`. Nothing has to reach the server from your browser: the page shows a code and you carry it across by copy and paste.

#### First login on a headless machine

1. In a terminal on that machine (your own SSH session, not the agent's tool call: the command waits for you to type), run:

   ```bash
   iap login --headless --program claude
   ```

   It prints a URL, plus the machine, program and a **mix-up check** such as `MOAE-TRCS`, then waits at `Paste the code and press Enter:`. If the machine has no usable keyring, it first says that the credential will go to the file store.
2. Open the URL on any device: your laptop, your phone. Sign in as yourself if asked.
3. Check the page: it names the account you are signed in as, the machine, the program and the same mix-up check as the terminal. If any of them is wrong, or you did not just start a login, click Cancel. The mix-up check only catches a mix-up between two logins: anyone holding a link can quote it, so it does not prove a link is yours.
4. Click Register. The page shows a one-time code.
5. Copy the code and paste it at the terminal prompt. The input is not shown. `iap` trades the code for the refresh credential and prints `Registered agent:user:you@example.com:<machine>:claude:* until …`.

The code works once, for 5 minutes, and the issuer accepts it only together with a secret that the waiting `iap` process generated and never shows. Paste it only into the terminal where you started the login; anyone who asks you to send it to them is attacking you. A mistyped paste that is not code-shaped is asked for again; a wrong or reused code ends the login, and you start again. A brief network error or busy issuer during the exchange is retried. The whole login waits up to 10 minutes; Ctrl-C or a timeout at the prompt leaves your terminal as it was. The code can also be piped on stdin instead of typed.

The older alternative still works when you want no copy and paste: forward the callback port from the computer you are sitting at (`ssh -L 18080:127.0.0.1:18080 server`, then on the server `iap login --no-browser --port 18080`) and open the printed URL in your laptop's browser. Without a display, `--no-browser` is the default.

### curl

```bash
iap curl https://app.example.com/api/status -sS
iap curl --session nightly https://app.example.com/api/report -X POST --json '{"week": 41}'
```

The URL comes first, then curl options. `iap` mints a token for the URL's host and runs your system's `curl` with the token in a `Proxy-Authorization` header. The header reaches curl through an inherited pipe, never as a command-line argument, so other processes cannot see it. The exit status is curl's.

Only a fixed list of curl options is accepted (`iap curl --help` prints it). Options that would print headers (`-v`, `--trace`), send the request to another host (a second URL, `-L`, `--resolve`, proxies) or turn off certificate checks (`-k`) are refused. `-H` cannot set `Authorization`, `Proxy-Authorization` or `Host`. `~/.curlrc` is not read.

The session names this run. It defaults to `$CLAUDE_CODE_SESSION_ID` inside Claude Code, otherwise `--session`, otherwise `cli`. Global flags (`--issuer`, `--store`) go before `curl`.

### expose

```bash
iap expose myapp --port 5173                         # https://myapp.<domain> -> 127.0.0.1:5173 while this runs
iap expose myapp --port 5173 --reserve 7d -- npm run dev   # run the server too; keep the name 7 days after the last disconnect
iap expose myapp --port 5173 --take                  # move the name here from another of your machines or programs
iap expose demo --port 3000 --public                 # https://demo.<public domain>, no proxy in front of visitors (allowed names only)
```

Publishes a server on your machine's loopback at `https://<name>.<domain>` through a tunnel service behind the same proxy, for proxies that run one (the iap-tunnel service, deployed next to iap-authz). Every visitor still passes the proxy and needs access to the page's host. Only `127.0.0.1:<port>` is reachable through it, never another address. Ordinary requests, streamed responses and WebSockets all work. The page's server receives the public `Host`, `X-Forwarded-Host` and `X-Forwarded-Proto: https`; a dev server that checks `Host` (Vite's `server.allowedHosts`) must allow the domain.

`<domain>` is `--domain`, else `$IAP_EXPOSE_DOMAIN`, else the one extra domain the issuer advertised at login. `iap` holds a WebSocket open to `https://tunnel.<domain>` with an access token for that host (at most 15 minutes for a domain outside the issuer's), and replaces the connection with a fresh token before each one expires, without dropping requests. It prints the URL once the page is live, and reconnects with backoff when the connection drops.

**Names.** One lowercase DNS label, starting with a letter. A few are reserved (`access`, `tunnel`, `www`, …), and a name the proxy's route registrar holds is refused. A name belongs to your registration (you, this machine, this program) and to you:

- Without `--reserve`, it is released about a minute after `iap expose` exits or loses its connection.
- `--reserve <d>` (`7d`, `36h`; at most `30d`) keeps it for that long after the last disconnect; visitors meanwhile see "reserved and offline". Every connection renews it; it does not depend on when your registration expires. Running without `--reserve` drops an earlier reservation.
- Your own registration always gets the name back without `--take`, even while the service still counts an old connection live (the machine restarted): the new `iap expose` supersedes the old one, which stops ("superseded").
- Another of your machines or programs gets the name only with `--take`, which closes the current holder ("taken by …"). Someone else's name is never yours, `--take` or not.
- At most 50 names per person, live and reserved together, public ones included.

**`--public`** publishes at `https://<name>.<public domain>` instead (the service chooses the domain), and visitors do not pass the proxy: anyone can reach the page, so the program's own login is the only gate. The tunnel itself still goes to `https://tunnel.<domain>` through the proxy with your token. The service allows it only for the names and agents its operator lists (default deny; `public_not_allowed` otherwise). Public names are separate from proxy-protected ones (`foo.<domain>` and `foo.<public domain>` are two names); the rules above apply to each. The page gets no identity headers: anything a visitor sends that the proxy would vouch for is removed.

**With `-- <command>`**, `iap` runs the command in its own process group beside the tunnel and exits with its status when it exits, which releases the name. On a terminal the command gets the terminal, so Ctrl-C reaches it directly; `SIGINT`, `SIGTERM` and `SIGHUP` sent to `iap` go to the command's whole group, so what it started (a dev server's own children) stops too. If the name is lost for good (taken, superseded, refused, the registration revoked), `iap` stops the group (SIGTERM, then SIGKILL after 10 s) and exits 1.

Errors name the reason: `name_taken` (with the holder when it is yours, so you can decide on `--take`), `reserved_name`, `invalid_name`, `quota_exceeded`, `principal_not_allowed`, `public_not_allowed`, or the proxy refusing the tunnel host (your agent needs a grant on `tunnel.<domain>`). A redirect on the connect means the proxy did not accept the token and sent `iap` to its sign-in page. `rate_limited` (too many connects or open connections) and `unavailable` are retried.

The tunnel client is the Go package `github.com/R167/iap/expose` (`expose.Run`); unlike `iapclient` it depends on `github.com/coder/websocket` and `github.com/hashicorp/yamux`.

### curl to the Tailscale API

```bash
iap curl --client-id <trust credential client id> https://api.tailscale.com/api/v2/tailnet/-/devices -sS
```

`https://api.tailscale.com/...` is the one URL outside the issuer's domains that `iap curl` accepts. `iap` asks the issuer for a federated token with the audience `api.tailscale.com/<client id>` (the issuer's policy must list that audience for this agent), trades it at Tailscale's token exchange for a Tailscale API token under that trust credential, and passes the result to curl as `Authorization: Bearer` on the same pipe. Neither token is printed. In the Tailscale admin console, the trust credential's issuer is the issuer's federation endpoint, its subject the agent pattern (for example `agent:user:you@example.com:laptop:claude:*`), and its audience `api.tailscale.com/<client id>`. The client ID is an identifier, not a secret; the last one given is saved, so later calls can leave `--client-id` out.

### status and logout

```bash
iap status    # each program's registration, issuer, expiry, extra domains, whether the stored credential exists
iap logout    # deletes this program's stored credential (--program for another); revoke the registration on the issuer's page
```

## Using the library from Go

```bash
go get github.com/R167/iap/iapclient
```

```go
import "github.com/R167/iap/iapclient"
```

The package depends only on the Go standard library. A complete example that compiles is [`iapclient/example_test.go`](iapclient/example_test.go). In outline:

```go
store, _ := iapclient.OpenStore(iapclient.StoreAuto)          // or StoreFile, chosen explicitly
c, _ := iapclient.New(iapclient.Config{Issuer: "https://access.example.com", Store: store})
hc, _ := c.HTTPClient("my-session")                          // fails when not logged in
resp, err := hc.Get("https://app.example.com/api/status")    // *iapclient.ForbiddenError without a grant
```

- `Client.Login` runs the browser registration. `LoginOptions.OpenBrowser` set to `nil` prints the URL instead of opening a browser, and `Port` fixes the callback port. `Headless: true` runs the paste-a-code login instead; `ReadCode` supplies the pasted line (default `NoEchoStdin`: one line of stdin, with echo off via `stty` on a terminal, restored however `Login` returns; restoring on Ctrl-C is the caller's job). `RequestCheck(challenge)` is the mix-up check the page shows. `CheckStore` saves, finds and deletes a throwaway item; `Login` runs it before anything is approved, and returns `*CredentialLostError` if the real save still fails afterwards. `StoreFallback` records that the store was a fallback, not a choice (`State.StoreFallback`). `Config.LegacyIssuer` names the issuer a state file without an issuer belongs to; empty means none. Transient token-endpoint failures during the code exchange are retried.
- `Client.TokenSource(session).Token(ctx, host)` returns a `Token`. Its `Value` is a `Secret`, which prints as `<redacted>` with every `fmt` verb and in `slog`, and refuses JSON marshalling. `Secret.Reveal()` is the only way to the raw value.
- `Transport` is an `http.RoundTripper`. It adds the header only to `https` requests whose host is allowed, mints a token for exactly that host, removes any `Proxy-Authorization` the caller set, and adds nothing when a redirect leads to a different host. Requests to other hosts pass through without the header.
- Errors: `ErrNotLoggedIn`, `ErrInvalidGrant` (registration revoked or expired), `*ForbiddenError` (no grant; names the principal and host), `*HostNotAllowedError`, `*IssuerMismatchError` (the saved registration belongs to another issuer, so its credential is not sent), `ErrNoKeyring`, `ErrSecretServiceUnavailable`.

## Instructions for an AI coding agent

Paste this into your agent's instruction file (`CLAUDE.md`, `AGENTS.md` or similar), with your own issuer and hosts filled in:

```markdown
## Reaching services behind the identity-aware proxy

- Hosts under <example.com> (and the extra domains `iap status` lists) need a
  credential. Call them only with `iap curl <https-url> [curl options]`. Never
  plain curl, and never by copying a token anywhere.
- Never try to print, read, export or decode a token or the refresh credential
  (`iap` has no command that shows one, on purpose). Do not read the keyring or
  ~/.local/state/iap/. If a token ever appears in your output, tell the human so
  they can revoke the registration.
- `iap curl --help` lists the curl options allowed. Do not try to get around a
  refused option.
- If `iap` says "not logged in", "invalid_grant" or that the registration expired:
  stop and ask the human to run `iap login` (on a machine without a browser,
  `iap login --headless` in their own terminal there). You cannot do it; it needs
  them in a browser. Never ask them to paste the login code to you.
- "<principal> may not reach <host>" (HTTP 403 from the issuer): this agent has
  no grant for that host. Stop and ask the human to request access for the
  principal or pattern named in the message. Do not retry with other sessions or
  hosts.
- HTTP 401 from the host itself: the token was refused (revoked registration,
  clock skew). Run `iap status` and report it to the human.
- "the host must be under ...": that host is not served by this issuer. Do not
  look for another way to reach it.
```

## Refresh rotation and lifetimes

| What | Lifetime |
|---|---|
| Access token, issuer's own domain | at most 1 hour; `iap curl` mints one per call, the library caches it until about a minute before expiry |
| Access token, another domain the issuer advertised | at most 15 minutes |
| Login code (loopback callback) | 60 seconds, once |
| Login code (`--headless`, pasted) | 5 minutes, once |
| Registration | 30 days after its last rotation |

Every refresh asks the issuer to rotate the refresh credential. Once the stored credential is a day old, the issuer answers with a new one and pushes the registration's expiry 30 days out, so a machine that keeps using its registration (a long-running `iap expose`, say) never needs a new login. The new credential is saved to the store before the access token is used; if the save fails, the old credential stays, and the issuer keeps accepting it until the new one is first presented.

Processes that share a registration take turns: each refresh holds an exclusive lock on `<config dir>/iap/locks/<program>.lock` from reading the credential to saving its replacement, and re-reads the credential from the store every time. If the issuer ever sees a credential it already rotated away, it revokes the registration (`ErrRefreshReused`): two copies of the credential exist. Give each machine its own login rather than copying one.

## Troubleshooting

| Message | Meaning | Fix |
|---|---|---|
| `not logged in` | No registration saved on this computer. | `iap login` |
| `invalid_grant: the registration was revoked or expired` | The refresh credential no longer works. A registration expires after 30 days without use and can be revoked. If the message says a rotated-away credential was presented again, the issuer revoked it because a second copy of the credential was in use. | `iap login` again |
| `status: expired` in `iap status` | Same, seen from the saved expiry date. | `iap login` |
| `... may not reach app.example.com: grant it (or agent:user:...:*) on https://access.example.com/` | You are registered, but nothing grants this agent access to that host. | Ask the issuer's admin to grant the pattern shown (all sessions of this machine and program) on that host. Your own account also needs access to the host. |
| `"https://x.other.com/": the host must be under example.com` | That host is not under a domain this issuer mints tokens for. | Use the right issuer (`--issuer`), or ask whether the issuer should serve that domain. |
| `the saved registration belongs to https://A, not https://B` | `--issuer` names a different issuer than the one you logged in to. The credential is not sent to B. | Drop `--issuer`, or `iap --issuer https://B login`. |
| `no OS keyring available: secret-tool is not installed` | Linux without `secret-tool`. | Install `libsecret-tools`, or log in with `--store file` on a machine without a desktop. |
| `the Secret Service (desktop keyring) is not reachable` | `secret-tool` is present but there is no unlocked keyring, for example over SSH with no desktop session. | Log in from a desktop session, unlock the keyring, or use `--store file`. |
| `file store: ... looser than 600` | Someone else could read the credential file. | Run the `chmod` shown, after checking why the mode changed. |
| `timed out waiting for the browser` | The consent page never redirected back to this computer. | Finish within 5 minutes. On a remote machine, use `iap login --headless`. |
| `the issuer refused the code (...)` | The pasted code was wrong, already tried, older than 5 minutes, or belongs to another login. | `iap login --headless` again; paste the new code within 5 minutes. |
| `registered ... but the ... store refused its refresh credential (...), so the credential is lost` | You approved, but the store failed after its test passed. | Revoke the named registration on the access page, fix the store (or pick one with `--store`) and log in again. |
| `the saved registration belongs to (unknown issuer: ...)` | Library use: a state file without an issuer and no `Config.LegacyIssuer`. (The `iap` CLI treats such a file as the built-in default issuer's.) | Log in again against the issuer you want. |
| `invalid_grant` mentioning a reused credential | The issuer saw a rotated-away refresh credential again and revoked the registration. | `iap login`; if no second copy should exist, treat the credential as leaked. |
| `timed out waiting for the code` | Nothing was pasted within 10 minutes. | Start again. |
| `no input (stdin closed); run the login in a terminal` | `--headless` ran without a terminal to read from (for example inside an agent's tool call). | Run it yourself in a terminal on that machine. |
| `a headless login takes no port or state` (on the consent page) | The URL was edited, or mixes the two login kinds. | Start again and open the URL exactly as printed. |
| HTTP 401 from the host with `error="invalid_token"` | The proxy refused the token: the registration was revoked, or a clock is far off. | `iap status`, check the system clock, `iap login` if needed. |

## Security notes

- **What a leaked access token allows:** requests to one host, as this agent, for at most an hour. **What a leaked refresh credential allows:** minting tokens for every host the registration is granted, until it is revoked or goes 30 days unused. `iap` replaces the credential with a new one about once a day of use; if a leaked copy and yours are both used after that, the issuer revokes the registration. If you suspect either has leaked, revoke the registration on the issuer's page and log in again.
- Nothing in `iap` prints a token or the refresh credential: not on stdout, in errors, in logs, or in a process's command line. The credential is passed to `security` and `secret-tool` on stdin, and to `curl` through a pipe.
- `iap` has no `token` subcommand, on purpose.
- Treat any token that does appear in an AI agent's transcript as leaked. Transcripts are stored and replayed.
- Tokens go only to `https://` URLs whose host is under an allowed domain. The token for one host is never sent to another, including after a redirect.
- `iap` never follows a redirect from the issuer, since its requests carry the credential.
- The non-secret state (per program: issuer, registration name, expiry, allowed domains, store) is in your user config directory as `iap/config.json` (`~/.config` on Linux, `~/Library/Application Support` on macOS). Whoever can change that file can point `iap` at another issuer, so keep your home directory to yourself.
- The login callback listens only on `127.0.0.1`, and checks a random `state` value. The code it receives works once, within 60 seconds, and only together with a secret that never leaves `iap` (PKCE).
- A headless login has no callback at all: the issuer recognises it as its own mode and never redirects. The code it shows is not the credential. It works once, within 5 minutes, and only with the PKCE secret of the `iap` process that printed the URL; a wrong attempt destroys it. `iap` reads it from the terminal with echo off and never prints, logs or saves it. The page names the signed-in account, machine and program so that you can spot a login you did not start: a link someone sends you would register an agent in your name, and with the code they could use it, so the code goes only into your own terminal and never to anyone who asks for it.
- A saved registration's credential is only ever sent to the issuer it came from. A `config.json` written before `iap` recorded the issuer belongs to the built-in default issuer only.
- Copying a registration's credential to a second machine gets the registration revoked at the next rotation. Log in on each machine instead.
- Windows is not supported: the file store cannot check permissions there, and there is no Windows keyring backend.

## License

MIT; see [LICENSE](LICENSE).

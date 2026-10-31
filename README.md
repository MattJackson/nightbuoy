[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/MattJackson)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CI](https://github.com/MattJackson/nightbuoy/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/MattJackson/nightbuoy/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.98-blue.svg)](#development)

# NightBuoy

A portable encrypted forum. Run a temporary local client, point it at a storage URL, unlock your identity or private forum key, and retrieve verified encrypted history from remote backends. Every frontend can be stopped while the forum data remains on its backends. The same client can stay online for convenience.

**Status: development software under adversarial review.** No absolute anonymity, Byzantine finality or professional security certification is claimed. [ARCHITECTURE.md](ARCHITECTURE.md) is the master design; [docs/AUDIT.md](docs/AUDIT.md) records findings, fixes and validation limits.

## Try the portable client

Prerequisites: Rust 1.98+, Node 26 and the Rust WebAssembly target for the legacy archive verifier.

```sh
npm ci
rustup target add wasm32-unknown-unknown
npm run dev:up
```

Open **http://localhost:8080**. This is a loopback-only local interface; remote connections require HTTPS or Tor. There is no local setup token, SQLite database, validator network or required data volume in portable mode.

Enter a GitHub/Forgejo repository URL or an S3-compatible root, optionally enter a private forum access key, then choose Join. NightBuoy infers the provider settings and asks for your scoped provider credentials when needed. It asks before creating a forum in a confirmed-empty location. The repository branch or bucket must already exist. Save your encrypted identity recovery file; connection exports are optional advanced backups. Backend transactions, membership/governance metadata, append certificates, snapshots and heads are authenticated encrypted binary objects. Provider accounts, URL paths, object sizes/counts and traffic timing remain observable.

On another computer, launch NightBuoy, enter the same storage URL, provide provider access if required, then import and unlock your encrypted identity. An authorized identity discovers its forum key without a connection file. A private `nb2:` access key permits current-epoch reading and pins the forum/branch; it does not grant membership or provider write permission. Provider permission and forum membership are separate. Never share an owner's unrestricted token with members. Provider credentials stay in companion memory and must be entered again after restarting; private profile/kit credential persistence is not implemented.

`npm run dev:status` reports the launcher. `npm run dev:down` stops it and retains remote history. Pending posts exist only in the tab's memory: export them from Account before closing or signing out. Private `.nbp` exports encrypt routing and metadata as well as content, and require the owning identity to import. The launcher writes only its explicitly chosen development PID/log files under ignored `.dev/`; the companion does not create application state files.

Use **Switch forum** to return to the storage URL form. It drops that session's provider credentials, keys, cache and identity from the client/companion without modifying remote data. Export pending posts first; the interface asks before discarding drafts. Sign-out and authentication expiry also clear unsaved plaintext editor state.

## Portable executable and read-only media

```sh
npm run build
cargo build --release --locked
./target/release/nightbuoy portable
```

Build the web assets **before** the executable to embed them. Copy the executable and your portable files to read-only media; the installed binary can run from another working directory without writing there. The browser and operating system can retain traces independently. Keep the identity file and passphrase separate.

Running the executable without a command opens the local graphical interface in your system browser. `portable` keeps the companion in the foreground without opening a browser. The terminal client uses the same verified history and encrypted storage:

```sh
nightbuoy cli -f https://github.com/owner/repository --prompt-key
nightbuoy cli -f https://forge.example/owner/repository -i recovery.json --provider-token-file token.txt
nightbuoy identity create recovery.json
nightbuoy cli --help
```

`-k KEY` is also supported, but exposes the key in process arguments; prefer hidden prompting or `--key-file`. Identity passphrases are prompted with hidden input. For S3 use `--provider-credentials-file` with a private JSON file containing `access_key` and `secret_key`. The terminal supports selection, reading, new boards/topics/replies, refresh and retained pending retries. After an unconfirmed submission, Ctrl+D twice in its draft consults verified history and permits explicit review/resubmission using the same object ID. Use `e` (or Ctrl+E while drafting) to save private pending submissions; `--pending-file` imports them with the owning identity. `p` retries, `v` reviews and `d` explicitly discards a saved pending copy. Queues are limited to 100 unique submissions and 16 MiB. `identity create NEW_FILE` creates a recovery file; `--export-identity NEW_FILE` saves an updated encrypted checkpoint after the terminal closes. Exports preserve existing files. `--print` explicitly emits decrypted content to standard output.

The opaque format deliberately rejects old plaintext-metadata storage at the same location. Use an explicitly selected new directory and preserved-history migration; it cannot make earlier Git commits secret retroactively. Existing user data is never silently rewritten.

The default Docker target and `compose.yaml` run one portable client, with a read-only root filesystem and no database volume. The personal Compose example uses host networking and binds host loopback; on macOS/Windows prefer the native launcher unless Docker host networking is explicitly supported/enabled.

Watch topics, see unread counts and receive a private sign-in summary of missed replies and mentions. Reading state is encrypted for your identity and saved to the original backend when your provider permissions allow it. Account exports/restores private `.nbs` backups for independent copies or sessions without write permission. The terminal supports `w` to watch, `m` to mark a thread read, `a` to mark all read, `b` to export a backup and `R` to reload saved state; `--reading-state-file` and `--export-reading-state` exchange backups with the browser. Reading state is separate from forum archive copies.

Posts support formatted text, preview, code, quotes, spoilers and emoji insertion. Links and external images require an explicit click. Administrators and moderators can lock threads; the terminal uses `l` on a selected topic. Existing communities can explicitly enable current moderation tools from Account. Edits and removals append signed records; recipients retaining old keys/history can still read earlier versions.

## Backups, availability and recovery

Account → Add / update a private encrypted backup copies verified history to another backend using independently owned credentials. Save the updated connection file. Copies are point-in-time: updating a primary does not automatically update offline backups. The UI reports whether the **current exact checkpoint** has been copied. Private copies need no administrator registry or approval.

A configured compatible replica can serve reads when the primary is unavailable, invalid or rolled back. Writes still require the selected active backend's conditional update; replicas are not votes and do not elect a new writer. A lagging replica cannot satisfy a newer pinned checkpoint.

To recover onto another backend: export a verified archive, connect a fresh local client to a **different empty namespace**, choose Join / restore, verify the old community fingerprint, explicitly select a separate branch and import a surviving identity. Recovery rotates future keys, resets administrator roles and preserves prior history. It cannot overwrite the original namespace. Other members must explicitly select the new branch; branches never merge.

For membership, a new user downloads a signed request and sends it to an administrator through a chosen channel. The administrator imports it from Account and grants encrypted key access. There is no required always-on admission inbox. Revocation protects future messages after rotation; it cannot erase keys or plaintext already copied.

## Optional always-on hosting and Tor

The same executable can run persistently behind HTTPS or a Tor v3 onion service. Set `NIGHTBUOY_PUBLIC_URL`, `NIGHTBUOY_LISTEN` and `NIGHTBUOY_CONNECTION_FILE` to an operator-approved public connection containing community, branch and checkpoint pins. Hosted mode restricts destinations to that profile and does not let the first visitor initialize operator storage. Each session supplies its own scoped provider access; an operator-credential write relay is not implemented.

Set `NIGHTBUOY_SOCKS_PROXY=socks5h://127.0.0.1:9050` to route provider traffic and remote DNS through Tor. Repository and S3 transports disable redirects and ambient proxy settings. Onion providers require the explicit proxy. HTTPS/Tor protect transport; providers and endpoint peers may still identify accounts or observe timing. Hosted JavaScript and its delivery host remain part of the trust boundary.

OEM installs contain only NightBuoy and five local palettes. Apply optional public branding after installation with `NIGHTBUOY_BRANDING_DIR`; branding changes assets/metadata, not signed forum data. [docs/LEGACY_OPERATIONS.md](docs/LEGACY_OPERATIONS.md) covers existing SQLite/CometBFT deployments, which remain intact and require explicit migration. `npm run dev:legacy:status` inspects the retained local network.

## Development and verification

The **Package rehearsal** Actions workflow builds on native Linux, macOS and Windows runners for x86-64 and ARM64. Its downloadable artifacts contain portable archives, macOS app/DMG/PKG files, Windows per-user installers, and Linux DEB/RPM/pacman packages. `build.json` records the source commit, target and signing status; `SHA256SUMS` covers that run's outputs. This workflow creates test artifacts without publishing releases or stores. Linux GNU packages currently require glibc 2.39 or newer. macOS bundles are ad-hoc signed and unnotarized; Windows packages are unsigned. Check actual job results before treating a platform as verified.

`nightbuoy check-transports` initializes both provider TLS stacks without network access or credentials. A successful check confirms usable TLS client configuration, including platform certificate roots needed by S3; it does not test provider permissions or connectivity.

For a local native package rehearsal, build embedded assets first, run `cargo build --release --locked --target YOUR_RUST_TARGET --features desktop-launcher`, then `node scripts/package-native.mjs YOUR_RUST_TARGET` and `node scripts/verify-packages.mjs YOUR_RUST_TARGET`. Output goes to ignored `dist/TARGET/`. The verifier extracts Linux/macOS payloads into temporary directories; on Windows it installs/uninstalls with a unique test registration and no shortcuts. Windows ZIPs pair the graphical `nightbuoy.exe` with the console `nightbuoy.com`.

**Static Linux rehearsal** additionally targets x86-64, ARM64 and ARMv7 musl archives, verifies there is no dynamic ELF interpreter, and runs the extracted client (using QEMU for cross-built ARM). Native runner results establish support; these recipes remain provisional until their jobs pass. The same workflow now includes x86-64/ARM64 AppImage, sideloaded Flatpak/Snap and scratch container recipes using the exact checksummed static archive. Their build/install/runtime jobs must pass before those formats are considered verified; no stores or registries are written. Installation rehearsals run only on disposable Actions runners and refuse existing NightBuoy Flatpak/Snap installations.

```sh
npm run check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
npm run test:crypto
npm run build
npm run test:portable
npx playwright install chromium
npx playwright test --config playwright.portable.config.ts
npm test
```

Portable provider fixtures exercise real HTTP/SDK conditional requests, concurrent writers, corruption, authentication, raw ciphertext inspection, revocation/discovery rotation, cold historical-key backup updates, zero-frontend restart, read-only working directories, replica fallback and isolated recovery branches. Native interoperability and a pseudo-terminal test verify recovery keys, decryption and rendering; browser tests exercise root-only joining, repeated private-key reads and encrypted recovery. A separate opt-in live GitHub check also creates and removes a temporary branch with synthetic encrypted data; see the audit ledger. These tests do not certify every hosted provider's ACLs, retention or conditional-write implementation. Legacy integration tests retain encryption, moderation, revocation and consensus regressions. This pilot caps a complete archive at 64 MiB; full snapshot retention currently grows with history and needs provider capacity monitoring.

Licensed under [MIT](LICENSE). See [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), [Code of Conduct](CODE_OF_CONDUCT.md) and [third-party notices](THIRD_PARTY_NOTICES.md).

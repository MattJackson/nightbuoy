[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/MattJackson)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CI](https://github.com/MattJackson/nightbuoy/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/MattJackson/nightbuoy/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.98-blue.svg)](#development)

# NightBuoy

An encrypted community forum with portable member identities, independently hosted frontends and replicated storage. The community should survive its original website.

**Status: executable security prototype under review. Not yet ready to deploy for real users.**

[ARCHITECTURE.md](ARCHITECTURE.md) is the single master document for the product vision, trust/privacy model, protocol, implementation status and release acceptance criteria. Superseded kickoff/design/deployment drafts have been removed. Independent review findings and remediation evidence are recorded separately in [docs/AUDIT.md](docs/AUDIT.md).

The reference implementation uses Rust/Axum/SQLite, Svelte/TypeScript, browser encryption and a shared native/WebAssembly consensus-proof verifier. CometBFT orders confirmed contributions; independent archive backends preserve ciphertext and do not gain consensus votes. Reading requires authenticated key access. Private read-only deployments require no administrator registration; two-way publication requires approval of a pseudonymous backend key.

## Run the HTTPS development network

With Docker running (Docker Desktop or Colima), from this checkout:

```sh
npm ci
npm run dev:up
npm run dev:certificate
npm run dev:token
```

Open **https://localhost:8443**. The test network uses a private development CA: explicitly trust `.dev/caddy-root.crt` in your test browser before signing in. The scripts do not install a system trust root. Use the displayed bootstrap token, choose key-only enrollment for this local test, create a long unique passphrase, and save the downloaded encrypted recovery file. The token is an operator secret; do not share it.

Alternate frontends are https://node1.localhost:8443, https://node2.localhost:8443 and https://node3.localhost:8443. Import your recovery file to sign into the same community there. All four validators run on your machine: this tests the protocol, not independent ownership or production resilience. Only the HTTPS ingress is published, bound to loopback; consensus RPC and ABCI remain internal.

`npm run dev:status` shows containers. `npm run dev:down` stops them while retaining volumes, identities and data. Never delete validator volumes to repair a running network. `npm run test:compose` exercises a separate disposable HTTPS network on port 9443 after building the image; it creates synthetic test keys under ignored `.dev/`. Initial image builds compile pinned Rust, Go and WebAssembly dependencies and can take several minutes.

This is a deployable **development environment**, not a production deployment profile. Production recovery, Tor acceptance, independent re-review and the other release gates in the master document remain open.

## Development

Prerequisites: Rust 1.98 or newer, the `wasm32-unknown-unknown` target, Node 26, Go, and Chromium for Playwright. Dependencies and consensus-tool versions are pinned by the lockfiles/build scripts.

```sh
npm ci
rustup target add wasm32-unknown-unknown
npm run check
cargo test --locked
npx playwright install chromium
npm test
```

The proof build installs the pinned wasm-bindgen CLI in local `.tools/` if needed. Browser tests build a pinned CometBFT binary locally and run isolated loopback test instances, including four validators. No public service or real forge credentials are created by these tests. `NIGHTBUOY_WASM_BINDGEN` and `NIGHTBUOY_COMET` may select matching preinstalled tool binaries.

Production recovery/deployment, live-provider checks and independent re-review remain in progress. See the master document for limitations; there is no published image or deployed site. Licensed under [MIT](LICENSE). See [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), [Code of Conduct](CODE_OF_CONDUCT.md) and [third-party notices](THIRD_PARTY_NOTICES.md).

# Legacy deployment operations

Compatibility runbook for existing SQLite/CometBFT forums. The current portable architecture is in [ARCHITECTURE.md](../ARCHITECTURE.md); these commands do not describe the default client. Preserve existing volumes and signing state. Build the `legacy` Docker target, use `compose.legacy.yaml` for the old local network, and use `npm run dev:legacy:up` / `dev:legacy:down` / `dev:legacy:status`.

## Operator deployment

`compose.production.yaml` supplies narrowly exposed HTTPS and Tor profiles. Build the application image from the reviewed source revision; it is not a published or security-certified release. Keep `operator/` outside version control. The examples contain placeholders, not credentials.

For a new consensus network, each independently owned validator generates its own keys:

```sh
docker build --target legacy -t nightbuoy:dev .
node scripts/operator.mjs init --dir operator
```

Exchange **only** `operator/public/validator.json`. One participant assembles the shared genesis from at least four independently generated descriptors:

```sh
node scripts/operator.mjs assemble --dir operator --output shared-genesis.json validator-a.json validator-b.json validator-c.json validator-d.json
```

Every participant independently checks the printed genesis fingerprint, validator membership and private peer routes. Each installs the identical shared genesis on their own host:

```sh
node scripts/operator.mjs install --dir operator --genesis shared-genesis.json --origin https://forum.example.org --peers NODE_ID@PRIVATE_TUNNEL_ADDRESS:26656
cp examples/deployment.env operator/deployment.env
```

Edit `operator/deployment.env` with the hostname, image and authenticated private tunnel/VPN bind address. Use a full comma-separated set of reachable peers as appropriate. RPC/ABCI stay on loopback. Peer exchange is disabled; private peer routes stay operator-local. CometBFT peer connections are separate from the application's SOCKS configuration and reveal network addresses to their endpoints. Tor user access does not make validator routing anonymous.

For HTTPS, point the chosen hostname at your ingress and permit inbound TCP 443 (UDP 443 is optional HTTP/3). The Caddy profile uses ACME TLS-ALPN validation; it publishes no cleartext HTTP application endpoint and requires no port 80 redirect:

```sh
docker compose -f compose.production.yaml --env-file operator/deployment.env --profile validator --profile https up -d
docker compose -f compose.production.yaml --env-file operator/deployment.env exec -T app cat /data/app/bootstrap-token
```

Open the configured HTTPS origin, use the one-use operator token, choose enrollment/history policies and create your portable identity. Key-only enrollment is the privacy default. Save the encrypted member recovery file and a separate encrypted community archive. The setup token is no longer printed to service logs.

An additional frontend can run a **non-voting full node** on an existing network: initialize new local keys, install the existing shared genesis with `--non-voting`, and connect its CometBFT process to surviving private peers. It replays the existing network; it does not create a new community or gain validator votes. Reading requires no publisher approval. An administrator approves only the frontend's publication key before it can publish signed member events, and can revoke that key later. Normal full-node catch-up requires surviving consensus peers with the needed blocks; complete validator loss uses explicit branch recovery instead.

Forge enrollment is optional. When enabled, configure GitHub/Forgejo providers in `operator/public/providers.json` using `client_secret_file` paths under `/run/secrets/`, and keep those credential files in `operator/secrets/`, readable only by the service/operator. Register the exact callback `https://YOUR_HOST/auth/PROVIDER_ID/callback`. The automated suite exercises the OAuth protocol against a local issuer fixture; external account configuration is operator-specific. Likewise, `operator/public/replicas.json` contains only destination settings and paths to operator-owned credentials. A directory example is:

```json
[{"id":"local-owner-label","kind":"directory","directory":"/archives/independent","mode":"push","consent":true}]
```

Mount that destination into the service explicitly. GitHub, Forgejo and S3 adapters exist; verify your provider's actual permissions, limits and failure behavior before depending on it. Archive copies do not gain consensus votes. Credentials that can delete every owner's copy defeat independent durability.

### Private read-only copy

Create `operator/public/` and `operator/secrets/`, copy a verified encrypted archive to `operator/public/archive.json`, set `operator/public/replicas.json` to `[]`, and copy `examples/application.readonly.env` to `operator/application.env`. Set its own HTTPS origin and copy/edit the deployment environment. Start the HTTPS profile **without** the validator profile. No forge account, administrator registration or publisher approval is involved. Import your member recovery file to read. The service checks portable signatures and consensus proofs, rejects writes, and keeps its sessions local. An explicit reset branch still requires an explicit client branch choice.

A configured pull-only archive destination can keep this private copy current. Pulls never replace a live consensus application's state. A stale seed file cannot roll a newer compatible local copy backward; conflicting branches fail closed.

### Tor onion frontend

Build the Tor sidecar and generate its persistent service identity without network access:

```sh
docker build -t nightbuoy-tor:dev -f docker/Dockerfile.tor .
docker compose -f compose.production.yaml --env-file operator/deployment.env run --rm tor-init
```

Set `NIGHTBUOY_PUBLIC_URL` in `operator/application.env` to the printed `http://V3_ADDRESS.onion` origin and set `NIGHTBUOY_SOCKS_PROXY=socks5h://127.0.0.1:9050`. Start `--profile tor` with the appropriate role (`--profile validator` for a validator/full node, omitted for a read-only copy). Do not start the HTTPS profile on an onion-only deployment. Onion origins require an explicit SOCKS proxy; application HTTP/storage clients fail closed if it is unavailable. CometBFT peer routing remains a separate operator responsibility.

Use Tor Browser with JavaScript and WebAssembly enabled. Tor provides authenticated encrypted transport to the onion service; this is not cleartext HTTP to an internet IP. Protect the `onion` volume: replacing it changes the onion identity. The sidecar exposes neither a public SOCKS port nor a public application HTTP port. See the [Tor Project's onion-service guide](https://community.torproject.org/onion-services/setup/).

`npm run test:tor` runs a disposable production-profile read-only onion service and a separate Tor client, then verifies key sign-in and content decryption using Firefox with its onion secure-context preference. Run `npm test` first to generate synthetic encrypted fixtures and `npx playwright install firefox` first. This is an actual Tor transport test, not a Tor Browser fingerprinting/anonymity certification. It removes its test containers and volumes afterward.

### Recovery, upgrades and backups

If quorum survives, reconnect a replacement frontend/full node to the same network. Preserve each validator's private key **and** signing state together; never clone a running validator identity or delete/reset its signing state. Back up member recovery files independently from encrypted forum archives. Operator credentials and sessions are not in community exports.

If the validator network is lost or the community deliberately leaves it, initialize **fresh keys and a distinct chain** using the procedure above. At its unconfigured frontend choose Join / restore, provide the trusted community fingerprint and a consensus-confirmed archive, select a separate branch, import a surviving active member's recovery file, and specify any exclusions. The new network verifies the old checkpoint proof and the member-signed reset, rotates future keys, resets former administrator roles and confirms the seed through its own consensus. Old history remains in the archive. It never overwrites the old network, reuses its signing state, merges branches or silently follows a reset. Other clients must explicitly choose the new branch before decrypting it.

Retain an independent archive before upgrades. Build/tag the new image from a reviewed revision and update one validator at a time, checking its health/catch-up and quorum before continuing. `docker compose ... down` preserves named volumes; do not use `down --volumes` on a real deployment. SQLite commits the archive and consensus checkpoint atomically. Directory archive writes are synchronized before rename/readback confirmation. Production capacity remains a bounded 64 MiB archive pilot, not an unlimited-history claim. Repeated full snapshots consume substantial storage; monitor every destination's retention independently.


## Appearance and post-install branding

NightBuoy is the only OEM brand. The built-in Light, Dark, Midnight, Paper and High Contrast palettes are selected in the header and saved in that browser. A fresh install defaults to NightBuoy Light. These choices do not change community permissions, encryption keys, signed history or other readers' preferences.

The theme palettes live in `web/src/themes.css`; shared layout stays in `web/src/style.css`. Organization branding is a **separate post-install bundle**, containing `branding.json`, an optional CSS file and local logo/favicon files. No customer assets or alternative brands are included in the OEM image, installer or theme chooser.

A bundle's manifest supplies `name`, `home`, `tagline`, `links`, `logo`, `favicon` and `css`. Image/CSS entries are filenames inside that public bundle directory; navigation supports site-relative paths or HTTPS. Scripts, remote assets, path traversal and symlink assets are not supported. Keep credentials and private files out of this directory. The server serves only the declared public assets.

For an existing operator deployment, set `NIGHTBUOY_BRANDING_PACKAGE` to the absolute path of the separate bundle and add `-f compose.branding.yaml` after `-f compose.production.yaml` in its usual Compose command. Recreate the application container. The core image stays identical, and removing the overlay restores NightBuoy. For a direct installation, set `NIGHTBUOY_BRANDING_DIR` to the bundle directory and restart. Branding never replaces the OEM first-install screen.

`node scripts/reinstall-dev.mjs` starts a fresh local installer while preserving the previous project's volumes and signing state. It creates a distinct network rather than resetting or reusing old validator identities. The active project selector and retained-project list are local, ignored files under `.dev/`. Run `npm run dev:token` for the new instance's one-use token.

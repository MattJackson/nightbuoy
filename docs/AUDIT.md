# Independent architecture and code review

Date: 2026-10-30. Reviewer: independent read-only review agent, separate from the implementation agent. This is not professional security certification. Findings describe the pre-remediation snapshot; original line references can move as fixes are applied.

## Initial disposition

**Block deployment.** The master architecture accurately distinguishes the vision from an unfinished prototype, but the code contained confirmed security and correctness flaws. Review covered ARCHITECTURE.md, Rust model/API/storage/consensus/proof code, browser crypto/protocol/UI, replication and tests. The reviewer ran three bounded, in-memory Node reproductions without editing sources or starting/stopping shared processes.

## Confirmed findings

### F1 — High: browser consensus trust downgrade

Original locations: `web/src/lib/protocol.ts:37,56`; native invariant: `crates/server/src/model.rs:83`.

Browser policy replay accepted removing/replacing `policy.consensus`, then decided whether to verify a proof from that altered policy. An administrator could append an unconfirmed downgrade to a pinned community. The native implementation rejected the same transition. Reproduction accepted a signed downgrade with `proofPresent:false` and `consensus:null`.

Required fix: identical native/browser trust-transition rules; regression tests for removal and replacement.

### F2 — High: hostile member content can disable history loading

Original locations: `model.rs:111–112`, `web/src/App.svelte:35–37,128`, `web/src/lib/protocol.ts:46`.

A structurally valid signed event can contain an invalid GCM tag. Non-decrypting validators cannot authenticate that payload, but the browser decrypted all historical events in one uncaught loop. One admitted ordinary member could prevent fresh clients from loading the entire forum, even after tombstoning the offending record. Reviewer reproduction passed archive verification then threw `OperationError` during decryption.

Valid ciphertext with malformed body/title/attachments types could also crash rendering/search. Accepted advisory timestamps could exceed JavaScript Date's valid range and crash `toISOString()`.

Required fix: per-record isolation, decrypted schema validation, safe date bounds/rendering, signed evidence retention and moderation without decrypting the malformed record.

### F3 — High: consensus capacity/proof deadlock

Original locations: `consensus.rs:49,53,32`; `store.rs:17`.

ABCI acceptance/commit bypassed the 64 MiB limit enforced by Store::save. Proof attachment used Store::save, so a confirmed archive exceeding that size could permanently prevent portable proof publication and leave sync returning 503. The path was confirmed by inspection; a full capacity attack was not run by the reviewer.

Required fix: deterministic aggregate limits before consensus inclusion, with reserved proof/export space and boundary tests.

### F4 — High: archive pulls mutate live consensus state

Original locations: `replication.rs:45–48`; contrast `api.rs:82`; consistency check `consensus.rs:13`.

Pull/both replication advanced application state with catch_up/store.save even on a live consensus node. Consensus height/app hash stayed at the old checkpoint. A valid future archive could therefore cause inconsistent execution or restart failure.

Required fix: live consensus catch-up must use coordinated CometBFT synchronization; archive replacement requires explicit offline recovery.

### F5 — High when Tor privacy is expected: S3 proxy bypass

Original locations: `replication.rs:22,25,37`; proxy configuration `main.rs:24–26`.

S3 used an independent object_store HTTP client without the configured NIGHTBUOY_SOCKS_PROXY. It could connect directly and expose the operator's network address. Configuration also accepted HTTP onion endpoints that the production S3 builder rejected rather than supporting through Tor.

Required fix: identical explicit routing policy for every SDK, or fail closed for unsupported combinations. Network/DNS path tests are required before claiming Tor privacy.

### F6 — Medium: unauthenticated recovery checkpoint

Original locations: `web/src/lib/crypto.ts:14–15`; `App.svelte:34,42`.

Vault encryption authenticated the community and public identity but omitted its anti-rollback checkpoint. Modifying the checkpoint to an empty string still unlocked the original identity without knowing the passphrase. This weakens recovery on a fresh origin with no existing pin.

Required fix: versioned authenticated recovery metadata and an explicit, authenticated checkpoint-update operation.

### F7 — Medium: authentication expiry does not lock plaintext

Original locations: `App.svelte:26,33–40,74–76`.

A 401 from /api/me threw into a general error handler without clearing the existing verified view, plaintext or keys. Explicit logout and a successful revoked/pending response followed different clearing paths.

Required fix: centralized client locking on authentication failure/expiry, including races with in-flight loads.

### F8 — Confirmed recovery defects and unfinished production workflow

Original locations: `App.svelte:56–58`; `protocol.ts:30–35`; `model.rs:65,71–76`; `api.rs:60`.

The reset builder used the latest transaction tip where the previous governance checkpoint was required, omitted the old-checkpoint proof and omitted replacement validator trust. The browser did not verify the checkpoint proof or apply the native trust transition. A checkpoint ending in a post therefore failed even in the development reset path. Production live restore was intentionally blocked; a complete offline consensus recovery procedure was not supplied.

Required fix: an end-to-end recovery artifact/workflow with verified old checkpoint, explicitly selected new trust, separate branch identity, retained ancestry, key rotation and client selection. Test checkpoints ending in controls and posts.

## Conditional exposures

- **Genesis takeover if consensus RPC is exposed:** consensus genesis admission lacked a bootstrap authorization or expected-community pin. An attacker reaching submission before setup could initialize the network. Private RPC/ABCI exposure must be enforced and tested, not merely documented.
- **TLS depends on actual ingress:** a public HTTPS URL setting does not add TLS to the HTTP listener. Broad listening without protected ingress can expose plaintext. Deployment boundaries must enforce the transport policy.
- **Static validator trust and freshness:** valid old signatures do not prove freshness. Compromise of sufficient retained validator keys can defeat clients without a recent independent checkpoint. Concrete rotation/checkpoint procedures remain necessary.

## Architecture assessment

The master correctly separates archive copies from validators, explains quorum assumptions, preserves permanent forks, rejects founder immunity and separates backend-key approval from infrastructure ownership. Its metadata, malicious-client, lost-key and surviving-copy limitations are appropriately explicit.

Remaining product/release requirements include permissionless read-only deployment acceptance tests; anonymous capability requests/control proofs/private routing; durable encrypted pending submissions; full production restore; trusted client distribution/cross-origin pins; live forge/storage and failure/scale tests; and packaged HTTPS/Tor deployment/recovery procedures.

Document corrections requested: do not claim a SQLite outbox queue already exists; explicitly list session-expiry locking as a gap until fixed.

## Verification limits

The reviewer inspected the selected Tendermint verifier methods and found validator-hash, header/commit binding and quorum-signature checks present. This does not prove the whole proof system correct. Four local processes demonstrate behavior, not independent ownership, Tor privacy or production security.

## Remediation ledger

These are implementation-agent verification results, not independent closure. The requested follow-up independent review was rejected by the review system's security filter, including a static-only attempt. It was not retried further. The original findings remain above; production deployment remains blocked.

| Finding | Remediation and evidence | Independent status |
| --- | --- | --- |
| F1 | Browser enforces immutable consensus trust in ordinary policy updates; crypto tests reject removal/replacement. | Re-review outstanding |
| F2 | Per-record decryption isolation, validated decrypted schemas, bounded timestamps and safe date rendering; crypto and native regressions pass. Bad signed evidence remains available for moderation. | Re-review outstanding |
| F3 | Deterministic aggregate capacity checks before mutation with 256 KiB proof reserve; native test fills the real 64 MiB boundary and confirms rejection without state change. | Re-review outstanding |
| F4 | Pull/both replication rejects live consensus mode before remote reads/state changes; native regression passes. | Re-review outstanding |
| F5 | S3 transport has explicit SOCKS support and proxy configuration; mock SOCKS test verifies destination hostname is routed through the proxy. Full Tor network acceptance remains open. | Re-review outstanding |
| F6 | Vault v2 authenticates checkpoint/community/device metadata. Tests reject metadata tampering and wrong passphrases, and validate checkpoint refresh. UI refresh first verifies the existing passphrase. | Re-review outstanding |
| F7 | Centralized 401 locking clears keys/plaintext/view, guards in-flight results; browser regression simulates expired authentication. | Re-review outstanding |
| F8 | Builder uses authority checkpoint and includes old proof/new trust; browser verifies trust transition. Fresh-network consensus recovery now verifies the old checkpoint, requires a distinct new chain and confirms the seed through the new network. A browser test stops all old validators, rejects a member-signed seed carrying forged checkpoint signatures, restores history, posts on the new branch and requires explicit selection on an independent read-only copy. Direct database reset is restricted to tests. | Re-review outstanding |

The four-validator browser test now covers simultaneous posts, original-node failure, quorum loss, encrypted pending storage through reload and successful retry without duplicate confirmation. The pending queue is browser IndexedDB, not SQLite. The packaged Docker environment was built and exercised over HTTPS using a pinned private development CA, two frontend origins and a three-signature consensus commit. These local checks do not establish Tor anonymity, independent validator ownership or production readiness.

Configuration restricts consensus RPC and ABCI bindings to loopback. Compose publishes only loopback HTTPS ingress and keeps each validator's persistent secrets in its own volume. Consensus itself still assumes a trusted private setup channel; operator exposure of RPC remains dangerous. Validator trust rotation/freshness, complete production recovery, permissionless deployment acceptance, live external providers and client-distribution trust remain release gates.

Dependency checks on 2026-10-30: cargo audit found no known vulnerability advisories, but reported the transitive unmaintained `paste` advisory RUSTSEC-2024-0436. npm audit reported two low-severity build-tool advisories in deepmerge/the Svelte Vite plugin with no published fix. These results are a dated observation, not an assurance against future advisories.


## Additional implementation verification

Production recovery is a new-network consensus transaction, not a direct replacement of a live SQLite application. The request requires the new frontend's one-use bootstrap token and trusted community fingerprint; all validators independently verify the seed. The normal transaction path rejects resets and an initialized network rejects a recovery seed. Bootstrap tokens are read from a protected file and are no longer printed in service logs. Authenticated mutations check authorization before allocating/parsing archive-sized JSON, and identity endpoints have smaller body limits.

The dedicated read-only mode does not require consensus participation or publisher registration and rejects enrollment/publication/control changes. Its browser test signs in with a portable identity, verifies the exact copied archive and decrypts the recovered history without changing the source network. A 50-destination filesystem test deletes one destination and verifies every surviving independent archive. This establishes local adapter behavior, not independent ownership, geographical redundancy or network-scale performance.

The Tor acceptance script builds the Tor image, creates a v3 service identity with networking disabled, starts an onion-only read-only frontend and a separate Tor client, then performs authenticated browser decryption over Tor. The automated browser is Firefox with the onion secure-context preference; it does not establish Tor Browser fingerprinting resistance. Onion application origins require explicit socks5h routing. Consensus peer traffic is separately configured and is not covered by the application's SOCKS setting. The initial S3 SOCKS-path regression remains in the native suite.

The production Compose profile keeps application HTTP/RPC/ABCI unexposed, supports HTTPS on 443 without HTTP redirects, and keeps operator-owned validator/config/credential material separate. The operator tooling validates public descriptors and protects existing signing state; code and deployment changes here have not received follow-up independent review. Further external provider acceptance, trusted client distribution, validator operational review and independent security review are required before making strong security/anonymity claims.

The production-profile acceptance script provisions separate validator and non-voting node keys using the operator CLI, installs the identical shared genesis, performs enrollment over pinned-CA HTTPS, catches up the full node, approves only its publisher key and confirms a new encrypted post through it. The validator count stays unchanged. The isolated packaging test deliberately uses one validator; four-validator agreement/failure behavior is covered separately. Live ACME issuance and a real operator's external provider credentials require deployment-specific verification.

## Portable architecture review — 2026-10-30

The sections above preserve the historical review of the legacy SQLite/CometBFT implementation. The approved default is now the RAM-only portable companion described in ARCHITECTURE.md. A fresh independent reviewer inspected this new scope in repeated static review cycles; the implementation agent supplied runtime regressions. This is not a professional security audit, a proof of perfection or production approval.

| Portable finding | Correction and regression evidence |
| --- | --- |
| A1 — High: ordinary member reset could replace active head | Ordinary preparation rejects reconstitute. Recovery requires a distinct empty backend/namespace; branch/head-pinned connections and source history remain intact. Provider fixtures and browser recovery exercise both paths. |
| A2 — High: imported connection could redirect existing form credentials | Exact endpoint/repository/bucket/namespace displayed for explicit review. Any descriptor change clears credentials and consent; malformed connection files are rejected before rendering. Credentials are session-only, never silently reused from saved/imported data. Browser regression covers secret clearing and reviewed reconnect. This does not authenticate a provider account for a user who manually trusts an impostor endpoint. |
| A3 — High: portable trust could be stripped or skipped on return to legacy ordering | Portable ordering cannot be removed or changed into legacy consensus. Native and browser tests reject these transitions; certificates must cover complete inventory. Legacy → portable migration retains an old verified consensus anchor; reverse migration is unsupported. |
| A4 — High: unauthenticated/global session exhaustion and busy-session eviction | Busy sessions remain registered; bootstrap requires same-origin POST and a custom header, cookies reuse live sessions, unreserved attempts can be evicted. Only verified active members reserve capacity, capped atomically at two per member/community, including identity switching. Expiry is eight hours; total capacity is 32. Native quota regression and provider session tests cover the reported bypasses. This is bounded admission, not DDoS protection. |
| A5 — Major: backups could not serve independent reads | Read transports are separate from signed write authority. Every fallback candidate passes community/branch/head/prefix checks; stale/unrelated sources do not prevent trying later sources. Writes never fail over automatically. Provider tests cover primary outage and rollback with a surviving replica. |
| A6 — Medium: expired portable sessions returned 400 and retained visible keys | Authentication/expiry returns 401; middleware rejects expired sessions before parsing bodies. Browser's shared 401 handler clears keys/plaintext. Native expiry and retained browser locking regressions cover this boundary. |
| A7 — Medium: SDK S3 redirects/privacy path differed from repository HTTP | Custom S3 connector disables redirects and ambient proxies, requires explicit socks5h remote DNS when selected, and retains conditional writes. All three adapter fixtures verify no redirect reaches a second server; native SOCKS hostname regression passes. Full portable Tor Browser anonymity is not established. |
| A8 — High: copy flag remained true after newer posts | Copy status is bound to the exact signed head and compared with current verified head. Fixture regression copies A, publishes B and checks status becomes false. Copies remain point-in-time until explicitly updated. |
| A9 — Recovery UI used the wrong pin store | Portable explicit branch choice updates the in-memory pin; recovery re-encrypts the authenticated identity checkpoint and exports the new connection. Browser recovery and cold sign-in pass. |
| A10 — High: public reverse proxy on loopback bypassed hosted allowlist | Personal mode requires both loopback listener and loopback advertised origin. A public HTTPS/onion origin requires an operator-approved community/branch/head-pinned connection even behind a loopback ingress. Test transport is restricted to personal mode. Startup rejection regression covers this configuration. |

Runtime evidence includes real HTTP/SDK conditional headers against bounded provider fixtures; simultaneous writers with exactly one accepted head; accepted writes whose acknowledgement is lost and idempotent retry; zero-frontend cold restart; no application-owned files in an empty read-only working directory; corruption/rollback rejection; compatible replica fallback; explicit branch separation; no plaintext/provider credentials in stored objects or public exports; credential review and identity import in Chromium. Native and browser replay both retain member authorization, epoch grants, encrypted content and old-history verification.

Portable protocol confirmation means successful conditional storage publication followed by verified readback. A member-signed certificate alone does not prove provider acceptance, global freshness or Byzantine finality. The initial implementation stores a full archive snapshot on every append and caps archives at 64 MiB; cumulative storage overhead is substantial. Hosted JavaScript delivery is trusted. Member metadata, provider accounts and timing can remain identifying. Revocation cannot erase copied plaintext or old keys.

Release gates remain: live deployment-specific provider ACL/conditional-write/retention acceptance; complete legacy-consensus-to-portable migration acceptance across real provider failures; private credential-kit and optional operator relay design if those features are shipped; trusted executable/client distribution and broader professional security review. Automatic background replication and multi-primary writes are not implemented. The portable development environment is suitable for synthetic testing; production security approval is withheld.

Final independent portable static cycle: the reviewer confirmed the identity-switch quota predicate, public-ingress classification and portable trust-transition fixes against the current files, and reported **no concrete unresolved high or critical issue within that reviewed scope**. The reviewer did not independently rerun runtime tests; this is bounded finding closure, not a production approval.

Live GitHub acceptance also passed using a temporary branch with synthetic encrypted data: community creation, posting, simultaneous conditional updates with exactly one winner, loser retry and independent browser-protocol verification. The temporary branch was deleted afterward. The opt-in reproduction is `node --experimental-strip-types scripts/live-github-acceptance.mjs --allow-temporary-branch OWNER REPOSITORY`. It uses the local gh credential in memory and never writes it into remote objects or public exports. This validates one account/repository configuration, not every provider/ACL configuration. Live Forgejo/S3 deployment acceptance remains open.

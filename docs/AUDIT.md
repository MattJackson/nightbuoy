# Independent architecture and code review

## File selection during sign-in/loading

CI exposed a pending-import race: verified posts render before sign-in finishes its last private-state read, and the previous operation guard silently ignored file selection while busy. Imports now capture the File immediately, wait for the current operation, recheck identity/root/branch and execute serially. Pending imports recheck identity/branch after decryption and storage awaits. The same queue covers reading backups, membership requests, archive catch-up and both identity recovery inputs. Background refresh preserves user notices. A deterministic browser regression blocks the final sign-in read, selects a pending file, releases the read and verifies import/publication. Four portable and five legacy browser checks pass, along with zero-diagnostic Svelte checks. Independent static review identified the remaining branch-recovery input; that input now uses the same queue.

## Sideload packaging review in progress

AppImage, Flatpak, Snap and scratch-container recipes reuse the same-run checksummed static binary and verify its source commit. The planned matrix uses native x86-64/ARM64 runners; definitions are not runtime evidence. Rehearsals require disposable Actions runners, refuse installed NightBuoy Flatpak/Snap packages, restrict runtime environment variables, and independently attempt owned-resource cleanup. Container cleanup tracks its daemon-owned name rather than relying only on a killed Docker CLI. The scratch image includes platform CA roots and their copyright notice. A non-network `check-transports` command now initializes both provider TLS stacks in package smoke checks; UI-only testing previously missed absent S3 roots.

Independent review found the missing CA bundle, daemon container cleanup, skipped cleanup after a failure, and environment inheritance. These are corrected for the next review/runtime cycle. Full third-party license/source bundling, graphical desktop-opening checks and broader package trust/signing acceptance remain separate release gates. The AppImage runtime and tool downloads are checksum-pinned; moving upstream continuous assets may require deliberate pin updates and fail closed if changed.

## Git attribution and read-capability backup follow-up

GitHub and Forgejo writes explicitly set both Git author and committer to `NightBuoy <storage@nightbuoy.invalid>`, avoiding provider defaults that publish the authenticated account name/email. This does not conceal provider authentication/activity, signatures, logs, sizes or timing, and does not rewrite earlier commits. Provider fixtures assert both fields on every repository write. The opt-in live GitHub rehearsal verified every newly generated commit on its isolated synthetic branch, along with large-object cold reads and the CAS race; the temporary branch was removed.

Authenticated readers with verified unlocked data can now export encrypted archives, query their own backup status and copy unchanged encrypted history without active forum membership. Previously these operations incorrectly reused the posting membership gate. Destination write credentials, hosted operator destination allowlists, conditional updates, ancestry validation and original signed write authority remain required/preserved. The root/capability acceptance check verifies guest copying and cold recovery, unchanged primary objects, refused posting and refused operations after logout. Backup destinations remain session-private and do not add an administrator-visible registry.

## Watched topics, unread state and catch-up follow-up

Browser and terminal clients now share a bounded branch-bound private reading-state schema and an independent common projection vector. Ledger positions determine unread/catch-up; author clocks do not. Current deleted, unreadable and self-authored posts are excluded, as are posts already read before returning. Private-state requests bind the expected forum, branch and member so delayed requests cannot write into a newly selected session. Backups remain owner-encrypted and are not included in ordinary forum copies.

Review findings corrected: Account/search/hidden-tab refresh could mark unseen replies read; reading-state 401 handlers could retain plaintext; native pending saves could appear clean after undo/restore; and revocation could block local private backup export. Read advancement now requires a displayed visible topic, matching-context 401s lock the client, pending/imported state requires reconciliation, and local backup ownership is separate from remote membership authorization. Explicit quit/sign-out/switch/reload warns about unsaved private state. Rejected native reloads preserve the prior version/state atomically.

Executed checks pass: 31 Rust workspace tests, strict all-feature Clippy, 17 crypto/private/projection tests, six native/provider checks, four portable browser checks and five legacy browser checks. Actual pseudo-terminal acceptance imports/re-exports a GUI `.nbs` backup and performs a native watch with browser-decryptable output. Browser checks restore watches and missed replies/mentions after reload, retain unread replies while Account is open, and lock plaintext on private read/write expiry. Final independent static review closed the concrete findings in this feature scope.

## Hosted ingress admission follow-up

Separate read-only review confirmed that the former global 132 MiB body limit allowed unauthenticated bootstrapped sessions to buffer large bodies before endpoint authorization, with unbounded concurrent requests per cookie. Middleware now checks authentication, membership, recovery eligibility and operation limits before collecting bodies, including router-decoded path aliases. Per-session permits (four), separate global normal/post/recovery pools (32/8/2), declared and streamed byte limits, and collection deadlines bound admitted processing. Recovery-sized input is restricted to authenticated empty personal companions. Disconnect preserves the session permit pool.

Seven portable unit tests pass, including bodies that must never be polled, permit exhaustion/release, declared/streamed limits, large authenticated input and recovery eligibility. Four browser checks and all provider/native scenarios pass; the full 3 MiB GitHub attachment originally passed prepare, publication and cold/fork replay. Routine checks now isolate full-size admission/validation at prepare instead of multiplying that payload through every subsequent debug replay; separate live tests retain large-object publication/cold-read coverage. Owner-private writes exercise a near-capacity frame. Strict all-feature Clippy passes. Final independent static review closed the reported allocation gap within this scope. These bounds do not establish general network denial-of-service resistance.

Native package rehearsal 41166615828 and static Linux rehearsal 41166615849 passed at commit 6d5a9f6. Rehearsals 41167738965 and 41167738987 also passed for the later owner-private primitive milestone 684bded. These cover Linux/macOS/Windows x86-64/ARM64 and static Linux x86-64/ARM64/ARMv7; later commits still require their own checks. Remaining formats/signing/production gates apply.

## Owner-private mutable objects follow-up

Private-state locators derive from the member signing secret with a separate HMAC domain and purpose/community binding; native/browser interoperability has an independent browser-generated public test vector. Objects occupy a distinct opaque keyspace, use padded owner-private frames and a 256 KiB bound, and never append forum history. Routes enforce POST/CSRF, current membership and original backend identity. Conditional updates reject stale versions, accept retries of the exact confirmed candidate and verify readback after ambiguous acknowledgments. Clients remain responsible for decrypting/schema/branch checks. These objects are a primitive; watched/unread interfaces and owner backup handling are not implemented yet.

Independent review caught fallback membership being used for a private write despite an original-backend ID check. Writes now require primary-only refresh. Regressions leave the primary private path writable while disabling its forum head and providing a current replica; writes fail without changing private bytes. All six portable/native checks pass across GitHub, Forgejo and S3, including private CAS conflict, missing/oversized/invalid paths, unauthorized membership, lost-ack exact retry, cold persistence and unchanged forum order. Crypto/private tests, browser/native locator interoperability and strict all-feature Clippy pass. Final read-only review found no further concrete issue in this scope.

## Static Linux rehearsal recipes

The musl matrix targets x86-64, ARM64 and ARMv7. Cross tool/download hashes and container digests are pinned; the artifact check rejects a dynamic ELF interpreter, compares the extracted binary and executes the embedded UI/API smoke check. Only fixed QEMU executable names are accepted as test wrappers. Static inspection found no concrete issue, actionlint and JavaScript syntax checks pass, and the unchanged native smoke behavior passes locally. Cross-build/runtime results are still pending; definitions are not evidence of successful platform support.

## Session switching and editor cleanup follow-up

Explicit Switch forum resets the companion to an empty session while preserving its original expiry, CSRF token and operator pin. It drops remote transports/credentials, cached history, metadata keys, discovery, authentication, admissions and prepared writes. Hosted destination restrictions remain on the application. The browser clears identity, both fingerprint sources, draft/search/attachment/recovery state and returns to the URL form. A pending/draft discard requires confirmation. Logout/401 also clear unsaved plaintext editors. The session mode is copied into reactive component state after bootstrap so header actions update correctly.

Validation passed three portable session tests, four portable browser checks, a further switch with a stale URL fingerprint and an unaffiliated recovery identity, five legacy browser checks (including 401 draft clearing), all-feature Clippy and zero-diagnostic Svelte checks. Independent review identified the retained URL fingerprint; clearing it and the restore fingerprint input resolves that finding. No forensic erasure claim is made.

## Native package rehearsal follow-up

CI run 41165825737 passed Linux x86-64/ARM64 and macOS ARM64 package/runtime checks. Both Windows executables compiled; installer compilation required `UsePreviousLanguage=no` with the isolated dynamic application ID. That setting is corrected for the next rehearsal. Intel macOS was still building at this checkpoint. CI run 41165825866 passed the full application suite at commit 0ce22ad. These observations do not establish results for later commits.

The first native matrix builds x86-64/ARM64 Linux, macOS and Windows, with embedded web assets from the same workflow run. Package manifests enumerate only outputs created in that invocation, preventing stale packages from being labeled with a newer commit. The verifier checks checksums and expected application versions and executes packaged binaries against embedded UI assets and the ephemeral API. Linux DEB/RPM/pacman payloads are extracted rather than system-installed; RPM stripping is disabled to preserve the tested binary identity. macOS ZIP, PKG payload and mounted read-only DMG are inspected and executed. Windows installer rehearsal uses a random, separate Inno application registration and suppresses shortcuts, then uninstalls that registration.

Independent static review identified and prompted fixes for shared Windows uninstall registration/shortcuts, stale artifact inclusion and RPM stripping. Local Apple Silicon release build, package creation, all macOS payload round-trips and the stale-output regression pass. All-feature Clippy and workflow actionlint pass. Native CI results and further formats are pending; unsigned/ad-hoc packages do not establish trusted distribution or notarization.

## Formatted posts and versioned moderation follow-up

The browser now renders a bounded escaped formatting tree with preview, emoji insertion, safe explicit links and no automatic external media. Unit tests cover hostile markup/URLs, parser budgets, numbered lists and selection boundaries; browser tests inspect both rendered behavior and the original encrypted source. Independent review caught a selection-prefix boundary bug and lost ordered-list starting numbers; both are corrected.

Signed `content_version: 1` enables thread locking and live-parent requirements. Native and browser replay preserve older accepted history, enforce the signed upgrade boundary, reject downgrades, restrict moderators to thread controls and retain ordinary authorized removals. Review caught missing publisher gating and reply/edit actions beneath a removed board; shared ancestor checks now govern both validation and UI. Native tests cover authorization, lock/unlock, history compatibility, removed ancestors and forbidden downgrade.

A browser regression also exposed session bootstrap replacing a busy connected session with an empty session. Bootstrap now waits for the existing session after releasing the registry lock. A focused native test holds the session mutex and verifies no replacement cookie, CSRF value or registry entry is created. Browser suites use separate artifact directories so concurrent validation cannot delete another suite's traces.

Milestone validation passed: 27 Rust tests, strict Clippy, Svelte checks with zero diagnostics, 13 text/protocol/crypto/private tests, six native/provider tests, four portable browser checks and five retained legacy browser checks. The independent reviewer rechecked the removed-parent and busy-bootstrap fixes and found no further concrete correctness or permission issues in these changes. The review was read-only and did not independently rerun runtime tests. Remaining release gates elsewhere in this document still apply.

## GitHub large-object read follow-up

GitHub omits inline content for objects above 1 MiB. The old fallback fetched raw content from the mutable branch after observing its SHA, which could pair newer bytes with an older conditional-write version. The fallback now validates the SHA and fetches the immutable blob from the configured API origin using the same redirect-disabled authenticated client. It ignores provider-supplied download URLs. A regression serves different bytes from the changed branch and checks the original >1 MiB blob/version pairing and refusal of a path-traversal SHA. Strict Clippy passes.

The opt-in live GitHub script now uses opaque format v2 and publishes only synthetic data on a temporary branch. Executed acceptance passed encrypted creation, a 900 KiB attachment producing >1 MiB stored objects, a cold-session read, simultaneous conditional publication with exactly one winner, loser retry and independent browser verification/decryption. The temporary branch was removed; the default branch was not modified. This is one repository/account acceptance, not a general provider availability or retention guarantee. API behavior is documented in [GitHub Contents](https://docs.github.com/en/rest/repos/contents#get-repository-content) and [Git blobs](https://docs.github.com/en/rest/git/blobs#get-a-blob).

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

## Opaque storage and native client review cycle (working tree, 2026-10-30)

This cycle reviews the new format rather than treating the earlier portable audit as approval. The independently requested read-only reviewer examined discovery authentication, native/browser crypto, history/branch pins, credential binding and failure state. It did not independently execute the runtime suite and identified no additional concrete critical/high issue in its final inspected snapshot. That finite static finding is not production approval or a proof of recipient anonymity.

Findings and remediation in this cycle:

- Unsigned discovery replacement by an ordinary writer: discovery point and recipient slots now originate in signed governance state and must exactly match it. Provider fixtures attempt and reject an ordinary post carrying substituted grants.
- Repeated metadata-history entries and cold backup update gaps: deduplicate the bounded in-memory key history and accept bounded historical metadata keys derived locally from a surviving identity. Cold rotation/backup tests exercise the latter.
- Cold copied-root authority adoption: adopt the signed primary while retaining the actual read location. Credentials may rebind only when every transport coordinate matches; a copied backend cannot inherit write authority or redirect credentials to the original endpoint.
- **High, native rejected-source key state:** candidate discovery keys previously replaced retained keys before branch/prefix validation. They now commit only after validation. A native HTTP regression supplies a valid alternate forum with attacker-chosen epoch keys, rejects it, and proves a subsequent export still uses the retained forum's key.
- Native ambiguous publication retry: retain the exact signed pending event and intent across separate invocations; changed drafts cannot silently overwrite an unconfirmed submission. TUI offers retry and warns before ordinary quit. A separate independent reliability review found that a governance update made retained signatures stale; explicit local discard/review now consults the verified head and keeps the draft object ID when it is resubmitted. The HTTP regression covers this transition. Native encrypted pending export/import remains release work.
- Native decrypted schema bounds: align titles, bodies, board order and inline attachment count/size/encoding checks with browser limits. Each malformed event remains isolated.
- Native S3 credentials: wire private credential-file input through root resolution rather than claiming repository-token-only input supports private S3. The S3 fixture executes the CLI with a private credential file and verifies decrypted output. Actual provider ACL/installation acceptance remains a separate gate.
- Browser real-interface regression found a Svelte-proxy cloning failure before publication; use a plain JSON member projection and show the pending failure reason. Root-only browser creation, cold identity login and encrypted recovery now pass.
- Private read capabilities need their own key allocation when installed into the current epoch-key map; refreshing must not clear the capability through an alias to an old cache entry. A repeated GUI refresh test covers this path.
- Browser/native recovery discovery consistency: require the public and private discovery-key fields to be present together, and check their public-key match. An authenticated synthetic vault missing the private discovery key is rejected during unlock.

Executed evidence is recorded alongside tests in `tests/portable.test.ts`, `tests/browser-portable/forum.spec.ts`, `sealed_storage.rs`, `client_crypto.rs` and `client.rs`. The public synthetic recovery fixture is explicitly a test identity and must never be used for real data.

Open release work includes new chat/presence and content-interaction protocols/interfaces, bounded blob storage and retention, full preserved-history legacy migration acceptance, provider acceptance, platform package/install verification and signing gates. The running dev environment remains the earlier committed portable build until the replacement is validated; real legacy data/signing state has not been migrated or reset by this cycle.

## Native identities and private pending recovery follow-up

The independent read-only reviewer examined native identity creation/recovery, browser PKCS8 compatibility, member-private export framing, purpose/forum/owner binding, pending queues and export-file preservation. It found no new concrete high/critical issue in that inspected scope, and reported two correctness gaps that were subsequently fixed: aggregate queue growth could exceed export capacity, and native imports counted duplicates before deduplication. Both clients now enforce 100 unique submissions/16 MiB before queue mutation; the native regression imports the same 60-item file twice without consuming additional capacity. Invalid mixed batches do not partially mutate the queue. A GUI action can also export an individual saved submission. A subsequent queue review found a draft could adopt a different queued item's object ID after an error; existing draft IDs are now preserved and unrelated confirmations cannot clear the draft. The reviewer confirmed closure, and an actual TUI A/B queue sequence independently verifies the original object ID and payload after resubmission.

The browser validates signed routing/context and decrypted payloads before accepting a pending file. Native saved submissions retain an independently wrapped content key for private recovery/review after an epoch change. Pending data and metadata are encrypted under a separate identity-owned key; possession of the shared forum epoch key is insufficient. Native identity creation emits the same authenticated recovery format the browser can unlock. Private exports never overwrite existing files and require a regular file target. The terminal exposes saved-draft review, exact retry, explicit local discard, private export/import and authenticated checkpoint export.

Executed evidence includes hidden-prompt native identity creation followed by browser unlock/signing/RSA checks; browser-to-native padded private-frame decryption; actual TUI import and re-export followed by browser decryption; wrong identity/forum/purpose and tamper rejection; aggregate-size/count limits and idempotent batch import; and a browser test that closes the originating browser, imports the identity and private pending file in a fresh context, then confirms the original submission. Platform-specific package/install/ACL evidence and the remaining messaging/interaction/migration gates are still open.

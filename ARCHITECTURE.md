# NightBuoy master architecture

Updated: 2026-10-30. This is the single architecture source of truth. It supersedes the former database/validator-first default. Requirements below describe the approved portable design; the implementation matrix separates working code from work in progress. NightBuoy is pre-release software, not a professionally certified anonymity or security system.

## 1. Product and ownership

NightBuoy is a portable encrypted forum client. **No permanent frontend or local database is required. The durable forum lives in encrypted data on independently owned storage backends.** A client can run temporarily on a computer or from read-only media, expose a private local browser UI, connect to a forum, verify/decrypt history and submit signed encrypted changes. Closing every frontend must not destroy remotely confirmed forum data.

The same application can remain running as a personal service or be hosted behind HTTPS/Tor for other people. Always-on instances provide convenience, optional replication work and optional authenticated write relaying. They do not acquire community ownership, administrator immunity or extra votes by remaining online. Backends themselves must remain reachable for remote reads/writes. A physically disconnected client can read only data it already has; unsent changes require an encrypted export or explicitly chosen writable outbox to survive exit.

The OEM product is NightBuoy only. Its five local palettes are Light, Dark, Midnight, Paper and High Contrast. Optional organization branding is a separate post-install public-assets bundle. Customer branding never belongs in the OEM installer or core image, and never changes signed forum data or permissions.

## 2. Experience

1. Launch NightBuoy. A personal launcher binds its UI to loopback, normally localhost:8080.
2. Open an existing forum connection file, or choose storage backends to create a new forum.
3. Import an encrypted identity/portable kit and unlock it locally. New members create an identity and request membership.
4. Fetch encrypted objects from reachable backends; verify fingerprints, signatures, membership history and the selected branch before decrypting.
5. Encrypt/sign posts on the user's device and publish through the selected branch's active write backend.
6. See remote confirmation and replica availability as separate states. Export pending work before closing an ephemeral session.

A read-only USB can carry the executable, web assets, a public connection file and an encrypted identity. Read-only application media does not prevent remote posting. Browser and operating-system traces are separate from application persistence; a no-database mode is not a forensic no-trace guarantee.

User-facing flows must explain connection, sign-in, access requests, additional devices, backups and restoration without requiring knowledge of SQLite, consensus engines, publication receipts or object-store APIs. Requirements that disable an action must be visible beside the affected fields.

## 3. Components and durable state

| Component | Responsibility | Persistence |
| --- | --- | --- |
| Browser UI | Identity unlocking, encryption/decryption, signatures, local search and forum interaction | RAM by default in portable mode; explicit encrypted exports/remember options |
| Rust companion | Serve local/hosted UI, provider transports, protocol validation, conditional publication and copying | Transient sessions and bounded caches; no required data directory or SQLite database |
| Storage backends | Preserve encrypted immutable objects and branch discovery heads | Durable remote storage, independently owned |
| Optional worker/host | Copy verified objects, provide availability and authenticated provider access | Optional; never the only durable copy by design |
| Connection file | Locate a community/branch and known backends; carry trust/checkpoint information | User-owned portable file; public export contains no credentials |
| Encrypted identity/kit | Member keys and optionally that user's private backend access | User-owned authenticated encrypted file; never shared as a forum connection file |

Remote data includes signed genesis, member/admin changes, encrypted posts/attachments, encrypted key grants, signed append certificates and verification material. Sessions, provider-account mappings, private member keys, passphrases and plaintext search indexes are never replicated as forum objects.

Application-owned caches are replaceable projections. Losing a cache must not lose remotely confirmed history. The existing SQLite server and CometBFT network are legacy compatibility/test paths, not the new default. Existing databases/validator signing state must not be reset or silently relabeled as portable storage.

## 4. Identity, permissions and keys

A member has a portable signing key and a separate encryption/wrapping key. The current primitives remain browser P-256 signatures, RSA-OAEP-3072 key wrapping, AES-256-GCM content encryption and Argon2id-protected encrypted recovery files. Native validation and browser validation must agree on protocol rules and encodings. Do not invent a cryptographic primitive or use application hash links as a substitute for authentication.

Public identity is pseudonymous and normally unique per community. Forge account enrollment is optional; portable key possession must support ordinary sign-in without the original domain, OAuth issuer or original frontend. Passkeys are not a mandatory identity dependency. A hosted client distributing malicious JavaScript can steal unlocked secrets; trusted client distribution and user choice of frontend remain part of the threat model. A local executable/embedded client can remove dependency on a mutable remote frontend, but does not protect against a compromised host.

Members require admission and encrypted grants before decrypting content. Administrator approval and history-sharing are explicit community choices. Administrators are peers; the founder has no permanent owner status. A revocation advances the encryption epoch and grants future keys only to remaining active identities. Copied plaintext and previously issued keys cannot be erased retroactively. Session expiry/logout must lock plaintext and discard in-memory key references; forensic secure erasure is not promised.

## 5. Remote object log and confirmation

Storage is an adapter interface: bounded read, immutable object creation and conditional head replacement. Initial providers are GitHub, Forgejo, S3-compatible storage and a directory adapter for explicit local/offline copies and tests. More providers may be added without changing forum permissions or encryption. A backend unable to provide the required conditional-write semantics is a replica/read source, not an active write backend.

A connection identifies a storage namespace, not a local database path. Namespace objects are content-addressed. A branch head points to a signed append certificate, which links the previous certificate and one immutable signed forum transaction. The certificate binds community, branch, active storage identity, sequence, previous object, transaction digest and signing member. Genesis establishes the root. Verification replays the complete authenticated ancestry and current permissions; a hash, discovery pointer or HTTP success alone does not establish valid history.

For each branch, exactly one explicitly selected backend provides the active conditional head operation. Concurrent writers read its current head, construct/validate a candidate, sign its exact parent binding and conditionally advance the head. A losing writer refreshes and retries; governance/epoch/revision changes may require a newly encrypted or reauthorized candidate. Ordinary simultaneous posts should not create user-visible branches.

A contribution is remotely stored only after its immutable objects and conditional head publication have succeeded and the accepted head/history has been verified. Copy confirmation is tracked separately per known destination. Failed/ambiguous writes remain pending until refreshed; retries must be idempotent and must never falsely report confirmation. No locally committed SQLite row substitutes for a remote acknowledgement.

The initial implementation also stores a complete certified archive snapshot at every confirmed append to make cold retrieval straightforward. Immutable transaction/header objects are separately retained. This has quadratic cumulative snapshot storage cost and a 64 MiB complete-archive cap; incremental packing/checkpoint compaction is future work. A confirmed snapshot is verified in full, not trusted because it came from a provider.

## 6. Trust tradeoff and failures

**This portable model does not claim Byzantine quorum finality.** A selected provider's correct conditional-write behavior serializes ordinary concurrent writes. Member-signed parent links prevent storage from inventing member actions or silently rearranging an already signed path. A malicious provider can censor, withhold, roll back or present different legitimate signed proposals to different readers. Pinned checkpoints and comparisons with independent copies detect incompatible histories when the evidence becomes available; a fresh client with an old checkpoint cannot prove global freshness from signatures alone.

There is no automatic primary election based on replica count. If the write backend is unavailable, existing copies can support reading, while new contributions remain pending. Explicitly choosing another writable backend/branch requires a verified checkpoint, appropriate surviving identity, a signed transition, future-key rotation and informed client selection. The original branch stays intact. Deliberate branches never merge automatically.

A compatible prefix is lag, not a fork. Unknown/unreachable participants are not votes. Invalid signatures are invalid data, not another valid branch. Observation counts describe reachable known sources; they do not prove independent ownership or legitimacy. Private read-only copies are not globally counted.

## 7. Backend identities, access and privacy

Forum membership and storage-provider permission are separate. Member keys authorize forum actions. Provider credentials authorize transport to a particular repository/bucket/namespace. A forum connection file must never contain a shared master storage token, member private keys or an OAuth secret.

The current portable implementation accepts provider access for the session only. Explicit private profiles and credentials authenticated inside an encrypted portable kit are planned extensions. Secrets are bound to the exact backend identity/location so tampering with a connection cannot redirect an existing credential to another destination. Future optional hosted write relays must retain their operator credentials privately, verify member authorization and exact signed candidates before publication, and expose no arbitrary storage-write/delete endpoint. A permanent relay must not be required when a user has suitable direct provider permissions.

Granting forum membership does not magically grant GitHub/S3 permissions. The UI must explain whether a member uses their own scoped backend access or an optional authorized relay. It must not give ordinary members an owner's unrestricted token. Independent owner credentials are essential: a credential that can erase every copy defeats the durability model. Provider ACLs/version retention and append/conditional-write capabilities need real acceptance tests.

Approved writable backends are represented by opaque identities/capabilities in signed governance. Physical routes, account labels, credentials, replication destinations and private read-only inventory remain operator/profile-local. A direct requester necessarily learns the endpoint it contacts; Git repository owner names can identify an account. Anonymity against the provider or endpoint peer is not guaranteed. Pseudonymous storage accounts, Tor and optional relays can reduce particular exposures; they do not create absolute anonymity.

Any person can copy verified encrypted data or run a read-only client without administrator registration, approval or notification. New two-way write authority needs explicit administrator approval. Installing a frontend alone grants none.

## 8. Replication and recovery

Replication copies encrypted immutable transactions/certificates and only advances a destination head along a verified compatible history. Read back and verify stored bytes. Never overwrite a conflicting branch or silently replace another community. Interrupted copies can be retried; missing bytes cannot be recreated from their hashes. Backend-specific quotas and failure behavior must be visible to the owner without publishing private connection details to forum administrators.

Any online client or optional worker can perform authorized replication. Providers do not synchronize merely because a connection lists them. Adding a backend performs capability/access checks and initial copy; removing one connection cannot delete independently owned copies. The UI must show local session/cache state, active remote write status, verified available copies, lag/conflict and pending work distinctly.

With every frontend stopped, start a new client, import the connection and encrypted identity, retrieve surviving objects, verify and resume. A read-only/offline backup preserves only the checkpoint it received. Recovery from an unavailable/rogue write provider creates an explicit new branch as described above. Legacy consensus archives require a verified old quorum certificate and an explicit member-signed migration boundary; no ordinary policy update may downgrade their trust scheme.

## 9. Transport, local launch and hosted mode

A personal launcher binds only to loopback. Localhost UI transport is a private local-process exception to the prohibition on clear public HTTP. Remote provider traffic and public hosted frontends require HTTPS or authenticated Tor v3 transport. A non-loopback cleartext application listener must not be advertised as secure. Hosted deployments may use a private internal listener behind protected ingress.

All applicable outbound HTTP/storage SDKs must honor the selected SOCKS/Tor path or fail closed; proxying one library does not proxy another. Redirects and remote assets must not bypass the privacy path. The portable path has no CometBFT peer network to expose accidentally. The UI includes no analytics or externally loaded branding assets.

Companion APIs require exact Host/Origin handling, CSRF protection and bounded input. Hosted sessions isolate identities, connections and credentials. The pilot caps one companion at 32 sessions for eight hours and at two reserved active sessions per verified member; arbitrary key proofs do not reserve capacity. It is not DDoS protection or a large public hosting capacity claim. Arbitrary backend configuration must not become a public SSRF/open-proxy interface: hosted deployments use operator-approved connection endpoints; unrestricted connection entry belongs to the personal loopback launcher. Private APIs never expose plaintext keys or raw provider credentials.

## 10. Packaging and compatibility

Default packaging is one lightweight client/companion process plus embedded/static web assets, with no mandatory database volume or four-node network. A read-only-media build carries the executable/assets and user-supplied portable files. Always-on/public hosting is optional. OEM branding stays NightBuoy; separate post-install branding supplies only validated public metadata/CSS/images and does not fork application code.

Preserve the existing forum and its signing state during implementation. Legacy mode remains explicitly identifiable and can read/export old archives. Migration is opt-in and must retain the old verified history, identity, grants and attachments, while recording the change in trust/ordering model. No automatic schema rewrite, volume deletion, root replacement or silent downgrade is allowed.

## 11. Implementation and acceptance matrix

This matrix is deliberately conservative while the portable refactor is in progress.

| Area | Evidence/status at architecture transition |
| --- | --- |
| Encryption, portable identity, epoch grants, revocation | Existing implementation and regression suite; retain and extend |
| Forum CRUD, attachments, moderation and search | Existing reference UI; preserve behavior |
| Five OEM palettes, separate post-install branding | Implemented and browser-tested; OEM source/runtime checked for customer-brand references |
| Passphrase validation feedback | Inline minimum/mismatch/missing setup requirement feedback; browser regression |
| Legacy consensus/server compatibility | Existing tested SQLite/CometBFT implementation; no longer the intended default |
| Remote append certificates and conditional publication | Implemented in native/browser replay and GitHub/Forgejo/S3 conditional adapters; HTTP/SDK fixture races tested; live GitHub synthetic branch race passed and branch removed |
| No-database transient launcher and isolated sessions | Implemented; RAM-only session state, no Store::open; cold restart/read-only working directory tested |
| Backend-first creation/opening and connection files | Implemented; destination review, secret clearing, branch/head pins and credential-free export |
| Private kit/provider access and membership handoff | Session-only provider access; separate encrypted identity + public connection; signed membership request export/import. Combined private credential kits and operator relays remain unimplemented |
| Remote replication and provider capabilities | Explicit private backup copy/readback; exact copied checkpoint; compatible replica fallback. No automatic background sync/election; live provider ACL/retention acceptance remains open |
| Zero-frontend recovery | Provider fixture tests stop every companion and cold-start in empty read-only working directories; history remains available remotely |
| Read-only-media launch | Executable embeds assets built before Rust; tests launch from read-only empty working directories and assert no state files |
| Legacy migration | Explicit reset with old quorum-proven anchor; code present, full cross-mode acceptance is still required. Portable → legacy ordering is forbidden |
| Security assurance | Fresh independent portable static audit and iterative remediation; evidence and remaining gates in docs/AUDIT.md; no professional certification |

Required checks include two concurrent clients posting through real conditional writes; stale/malformed/unauthorized inputs; revoked-member attempts; connection/credential redirection; rollback/fork detection; corrupt/missing objects; interrupted writes and duplicate retries; loss of the primary with explicit recovery; all frontends stopped then cold restart; read-only execution; and no plaintext/private-key/credential leakage into remote objects, logs or public exports. Provider integration and failure tests supplement protocol/unit/browser tests.

Audit cycles must fix and regression-test critical/high findings, repeat adversarial checks and record evidence/remaining limits in docs/AUDIT.md. No finite test suite or agent review proves perfection, absolute anonymity or absence of unknown vulnerabilities. Production security claims require evidence appropriate to their scope.

## 12. Supporting references

Provider conditional operations: [GitHub Contents API](https://docs.github.com/en/rest/repos/contents#create-or-update-file-contents), [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html), [Forgejo API](https://forgejo.org/docs/latest/user/api-usage/). Each adapter must verify the actual supported semantics; interchangeable storage does not imply interchangeable consistency guarantees.

Cryptography and transport: [Argon2/RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html), [secure contexts](https://www.w3.org/TR/secure-contexts/), [Tor onion services](https://community.torproject.org/onion-services/setup/). Legacy agreement uses the established CometBFT implementation; its old guarantees must not be claimed for the new provider-CAS branch model.

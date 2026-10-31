# NightBuoy master architecture

Updated: 2026-10-30. This is the single architecture source of truth. It supersedes the former database/validator-first default. Requirements below describe the approved portable design; the implementation matrix separates working code from work in progress. NightBuoy is pre-release software, not a professionally certified anonymity or security system.

## 1. Product and ownership

NightBuoy is a portable encrypted forum client. **No permanent frontend or local database is required. The durable forum lives in encrypted data on independently owned storage backends.** A client can run temporarily on a computer or from read-only media, expose a private local browser UI, connect to a forum, verify/decrypt history and submit signed encrypted changes. Closing every frontend must not destroy remotely confirmed forum data.

The same application can remain running as a personal service or be hosted behind HTTPS/Tor for other people. Always-on instances provide convenience, optional replication work and optional authenticated write relaying. They do not acquire community ownership, administrator immunity or extra votes by remaining online. Backends themselves must remain reachable for remote reads/writes. A physically disconnected client can read only data it already has; unsent changes require an encrypted export or explicitly chosen writable outbox to survive exit.

The OEM product is NightBuoy only. Its five local palettes are Light, Dark, Midnight, Paper and High Contrast. Optional organization branding is a separate post-install public-assets bundle. Customer branding never belongs in the OEM installer or core image, and never changes signed forum data or permissions.

## 2. Experience

1. Launch NightBuoy: the default graphical interface opens locally. `nightbuoy cli -f STORAGE_ROOT -k ACCESS_KEY` opens the terminal interface; hidden prompting and key files avoid command-line secret exposure.
2. Use one basic connection form: storage directory/repository URL, optional access key, Join. Infer provider, repository/bucket, branch and path. Credentials are requested only when required; provider permission remains separate from forum key possession.
3. Open and verify an existing encrypted forum, using the authorized identity/key. If the chosen storage location is confirmed empty, explicitly confirm creation. Authentication failures, missing provider permissions and network failures never mean "empty".
4. Decrypt forum data and metadata locally, verify fingerprints/signatures/membership/branch, then display only authorized forums. No public forum-name catalog or compulsory connection-file step.
5. Encrypt/sign posts or private conversations on the user's device, then publish conditionally to remote storage. Display remote confirmation separately from backup freshness.
6. Presence is invisible by default and opt-in for authorized forum members. Encrypted 1:1/group conversations use participant-only keys and rotate when membership changes.
7. Export pending work before ending an ephemeral session. Address/checkpoint bundles remain optional advanced backups; they never contain provider credentials or decryption keys in their public form.

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

### Required opaque storage revision (implementation in progress)

The earlier portable JSON format encrypts message payloads but exposes protocol metadata. It does **not** meet the user's clarified requirement and must not be advertised as zero plaintext or silently made public. Preserve old installations and use a distinct, explicitly versioned opaque format for new storage; previously published Git history cannot be retroactively made secret.

No forum name, member identifier/public key, role, membership graph, conversation participants, timestamp, object type, thread hierarchy, control action, signed checkpoint or backend inventory may be readable in backend objects. Encrypt complete transaction records, certificates, snapshots and head payloads with AES-256-GCM, with purpose-bound authenticated data and size padding. Address immutable blobs by ciphertext hashes, using opaque directory/object names. Binary transport framing, randomized anonymous key envelopes, byte counts and conditional provider versions are protocol mechanics, not plaintext forum records.

Derive a separate metadata key from the current random content epoch key with a fixed HMAC-SHA-256 domain separator. The browser retains content epoch keys and private identity keys; a trusted local Rust companion may receive only the derived metadata key in RAM for authenticated protocol validation. Hosted companions are consequently trusted with unlocked metadata, as their delivered JavaScript was already trusted with identity/content access; do not claim otherwise. New epoch grants exclude revoked identities and metadata encryption advances with the epoch. Old ciphertext/keys remain readable by prior holders.

Bootstrap key envelopes contain only randomized recipient ciphertexts, no public recipient identifiers. Authorized identity keys or an explicitly supplied metadata capability unlock the head. Never put decryption material in public connection exports. Bind accepted heads to the exact signed archive and preserve checkpoint/branch rollback checks after decryption. Private identity exports must carry any remembered forum capability inside authenticated encryption. Discovery grants are bound by the signed genesis or an authorized membership/key control. Ordinary posts preserve that authenticated grant revision. Pseudorandom cover slots remain stable across that revision and its replicas, preventing intersections from separating cover from real slots. A changed opaque discovery point can reveal a grant revision occurred; no recipient identifier is public. This is not traffic-flow confidentiality.

The normal UI is root URL plus authorized key/identity; there is no public list of forum names. Multiple forums can share a backend in separate opaque directories. Sharing/copying public ciphertext grants neither decryption nor signing authority. Repository owners/providers still know hosting-account identity, repository URLs, object counts, byte lengths and upload/access timing. Public forks can reveal relationships between copies. "Nobody knows anything" is not an achievable transport guarantee; no plaintext forum content or metadata in stored objects is the enforceable target.



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

Linux, Windows and macOS must have standalone binaries and appropriate direct installers/packages. The GUI is the default; the CLI entry opens a keyboard-driven TUI backed by the same protocol/crypto/permission core. Adapt established non-store release patterns from the user's existing project without copying customer branding. Planned artifacts include macOS application/archive, DMG/PKG; Windows portable archive and installer; Linux binary archives, DEB/RPM, Arch package, AppImage, sideloadable Flatpak/Snap; container images and package-manager metadata where supported. No app-store publishing, store credentials or store enrollment. Only claim a platform/package works when its build/install smoke has actually passed; missing signing/notarization credentials must be recorded rather than faked.



Default packaging is one lightweight client/companion process plus embedded/static web assets, with no mandatory database volume or four-node network. A read-only-media build carries the executable/assets and user-supplied portable files. Always-on/public hosting is optional. OEM branding stays NightBuoy; separate post-install branding supplies only validated public metadata/CSS/images and does not fork application code.

Preserve the existing forum and its signing state during implementation. Legacy mode remains explicitly identifiable and can read/export old archives. Migration is opt-in and must retain the old verified history, identity, grants and attachments, while recording the change in trust/ordering model. No automatic schema rewrite, volume deletion, root replacement or silent downgrade is allowed.

## 11. Implementation and acceptance matrix

This matrix describes the first portable release. The newly approved opaque-metadata format, root/key basic form, shared GUI/TUI, presence/chat and cross-platform package matrix are in progress and supersede earlier convenience/privacy assumptions. Existing passing tests do not establish these new features.

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

## 12. Forum interaction and content retention

The browser supports bounded formatted text with preview: emphasis, headings, lists, quotes, fenced/inline code, spoilers and emoji insertion. It renders an escaped element tree, never author-supplied HTML. Explicit links permit HTTPS and valid Tor v3 onion HTTP destinations; external images become links and are never automatically fetched. Parser budgets bound formatting work and preserve overflow as plain text. Reactions, pins and reports remain release work.

New communities sign `content_version: 1` into their policy. An administrator can explicitly upgrade an existing community with a signed policy control; replay preserves accepted older records and rejects subsequent downgrades. Under this version, a signed thread control lets an active administrator or moderator lock/unlock a live topic. Moderators gain no other administrator controls. Locked threads reject ordinary-member replies and edits, while moderators may continue managing them; authorized removals remain available. New posts and edits require live ancestors, including a reply's parent board. Both native and browser verification enforce these rules, and the interfaces disable unavailable actions. Older histories without the version keep their prior replay rules until upgraded. A newly selected recovery branch may explicitly adopt the current version.

Post edits append signed revisions; removal appends a signed tombstone rather than rewriting authenticated ancestry. Normal views show the current revision or removal. The encrypted original can remain readable to someone with retained keys/history. A signing identity authenticates an action; it does not prove the real-world person behind it. Permanent auditability and guaranteed erasure of the same content cannot both be promised. Exact revision-display policy remains configurable/design work; chain integrity must not depend on hiding old revisions.

Attachments must become independently encrypted blobs outside permanent post snapshots before managed retention is offered. Administrators may set per-file, count and total upload limits, and optionally expire managed attachments after a chosen number of days (default: never). Expired references show an unavailable/expired state. Cleanup cannot guarantee deletion from provider version history, independent replicas or recipients' saved copies. Current inline attachments do not yet meet this retention design.

Persistent private messages and incognito conversations are distinct modes, chosen visibly at creation. Both use participant-only encryption; forum administrators gain no special decryption privilege. Membership changes rotate chat keys. Incognito bodies/keys must stay outside permanent forum history, with transient local history cleared when leaving. Other participants can retain copies; closing one window cannot erase another person's device. Persistent PMs intentionally retain encrypted history. Presence remains opt-in and invisible by default; a historical storage provider is unsuitable for a promise that activity leaves no trace.

The intended chat implementation reuses signed, context-bound random epoch-key envelopes and padded anonymous ECDH discovery rather than persisting a shared MLS sender ratchet. An isolated OpenMLS 0.9.2 native/WASM evaluation passed basic encryption/removal checks, but avoiding cloned/rolled-back sender state across portable clients would require additional fencing and crash recovery. Persistent PM history deliberately remains recoverable with retained identity keys; forward secrecy and recovery from a compromised long-term identity are not claimed. Incognito discovery uses session-ephemeral keys that never enter identity exports, caches or backups. Invitation bindings must cover community/branch/checkpoint, chat ID/mode, exact ephemeral key, recipient, nonce and expiry, with live challenge/acknowledgment. Every message and roster/key change needs participant authorization and a signature; shared AES possession alone is insufficient. Apply forum eligibility checks on receive as well as send, retain exact packets through ambiguous publication, and inherit the documented provider freshness/fork limits. These are implementation/acceptance requirements, not a claim that chat is already shipped.

Watched/read state and notification summaries are private member data, never a plaintext backend catalog or an administrator analytics feed. The implemented owner-private state is bound to community and branch, tracks up to 1,000 topics, and uses signed ledger positions rather than author clocks. Browser read cursors advance only while the topic is displayed in a visible tab; the terminal uses explicit mark-thread/all-read actions. Catch-up excludes already-read, deleted, unavailable and self-authored posts. Exact encrypted state packets survive ambiguous writes and CAS conflicts; conflicts require reload or explicit backup restore rather than silent replacement. Private `.nbs` backups interoperate between browser and terminal, and cached owner data remains exportable after revocation. PM catch-up awaits the messaging implementation. Login catch-up is computed after verified decryption and must distinguish the first visit from a known prior checkpoint. A disposable session cannot remember the previous visit without an explicitly retained encrypted state, identity export or private remote state. Email, push services and external notification accounts are outside the approved minimal feature scope.

## 13. Current opaque/native implementation evidence

Native packaging rehearsal now targets Linux, macOS and Windows on x86-64 and ARM64, using the corresponding native runners. Outputs include source/signing manifests and checksums, portable archives and native installer formats. Verification executes extracted/installed binaries and checks their embedded assets/API without creating forum state. Windows tests use a unique uninstall registration and suppress shortcuts to protect existing installs. macOS bundles are ad-hoc signed, not notarized. Static Linux and remaining sideload formats, broader install/signing acceptance and complete release qualification remain open; workflow definitions alone do not establish platform support.

The working tree now contains versioned padded binary frames, authenticated anonymous discovery, signed grant revisions, metadata rotation, encrypted archive exports, URL inference with repository/branch permission probes, S3 empty-location confirmation, same-location-only signed identity adoption, a native shared client and Ratatui terminal interface. Default portable GUI launch opens the validated local origin in the OS browser; explicit `portable` remains headless. CLI supports hidden access-key/passphrase prompts and private credential files. Native identity creation and private pending export/import now work across GUI/TUI. Chat/presence, reactions, attachment retention, legacy migration and remaining distribution formats remain release work; this is not a completion claim.

Current executed checks include raw provider-byte inspection and CAS/rollback/restart fixtures for GitHub, Forgejo and S3; browser URL-only creation/cold identity sign-in/encrypted export/fork recovery; browser-to-native identity/ECDH/HKDF/RSA/content interoperability; frame prefix/grant/context tampering; stable cover-slot sets across posts; and transactional native rejection of an alternate forum. Expanded revocation, cold historical-key backup, private access-key refresh and actual pseudo-terminal checks pass. `docs/AUDIT.md` records the bounded independent review and outstanding gates.

### Member-owned exports and pending recovery

Bounded mutable private objects provide a foundation for member preferences outside the forum chain. Their locators are HMAC-SHA256 of the owning signing secret and an exact domain/purpose/community context; a separate opaque subdirectory prevents writes from replacing chain objects. Frames use the existing owner-private version-3 encryption and are capped at 256 KiB. Both reads and writes require active membership through the app; writes additionally require current primary-only membership verification and the user's provider permission. Updates use conditional versions, exact-candidate retry and readback. Clients must authenticate/decrypt and validate their schemas/branch bindings; the companion cannot validate plaintext inside a private frame. Browser and terminal clients now use this primitive for watched topics, unread cursors and login catch-up. Automatic private-state replication is not implemented. Forum copies exclude these member-owned objects unless explicitly copied by their owner. Provider writers can corrupt/delete stored files; encryption protects confidentiality and authentication, not availability against a storage owner.

`nightbuoy identity create NEW_FILE` generates a P-256 signing identity, a separate P-256 discovery key and an AWS-LC RSA-OAEP-3072 wrapping key. Hidden passphrase prompts protect the browser-compatible Argon2id/AES-GCM recovery envelope. Native public-key conversion inspects only SDK-generated public DER; private RSA arithmetic/parsing stays in AWS-LC. `identity inspect FILE` unlocks and prints public identity/checkpoint information. `--export-identity NEW_FILE` saves a current authenticated checkpoint on exit. Exports create new regular files, use mode 0600 on Unix and preserve existing files/symlinks. Windows file ACL/install behavior remains a platform acceptance gate.

Private pending files use a separate binary version-3 frame, with no owner, community, timestamps, routing or content outside ciphertext. A per-identity HMAC-SHA256 derivation over the signing secret and the exact JSON context `["nightbuoy-private-v1", purpose, community]` supplies an AES-256-GCM key; that context is also authenticated. Other forum members and shared epoch keys cannot open these exports. Payloads retain the bounded padded JSON framing used by the opaque serializer. These private files require the owning recovery identity, not merely a forum reading capability.

Both clients verify pending signatures, owner/forum/routing bindings, wrapped content keys and decrypted content before queueing. Queues are capped at 100 unique submissions and 16 MiB so every accepted queue remains exportable. Duplicate imports do not consume capacity. GUI export/import and TUI `e`/Ctrl+E plus `--pending-file` preserve submissions across exit. TUI `p` retries the exact signature, `v` reviews a saved draft, and explicit discard consults verified history before resubmission using the same object ID. Existing readers' saved copies remain outside application control.

## 14. Supporting references

Provider conditional operations: [GitHub Contents API](https://docs.github.com/en/rest/repos/contents#create-or-update-file-contents), [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html), [Forgejo API](https://forgejo.org/docs/latest/user/api-usage/). Each adapter must verify the actual supported semantics; interchangeable storage does not imply interchangeable consistency guarantees.

Cryptography and transport: [Argon2/RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html), [secure contexts](https://www.w3.org/TR/secure-contexts/), [Tor onion services](https://community.torproject.org/onion-services/setup/). Legacy agreement uses the established CometBFT implementation; its old guarantees must not be claimed for the new provider-CAS branch model.

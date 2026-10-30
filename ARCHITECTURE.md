# NightBuoy: master architecture and product vision

Updated: 2026-10-30. This is the single architecture source of truth. Normative requirements describe the intended product; the implementation matrix identifies what exists and what remains. The implementation is a security prototype under independent agent review, not a production release or professionally audited security system. Completion requires a usable deployment with real enrollment, authenticated reading, posting and independently recoverable encrypted history.

## 1. The community survives its website

NightBuoy is a standalone, open-source community forum. A community is identified by signed records and a cryptographic fingerprint, not its first domain, original operator, forge account, database or vendor. If `abc.com` disappears, participants should be able to resume the community at another HTTPS address or a Tor onion service, sign in again, unlock their keys, read surviving discussions and attachments, and continue posting without contacting `abc.com`.

Independent ownership matters as much as copying. The target is dozens of independently owned archive backends, potentially fifty or more. One administrator or storage operator must not possess credentials capable of erasing every copy. Removing a destination from one deployment's configuration stops that deployment's transfers; it never commands another owner to destroy retained history. Encryption keys and recovery material are separate from archive copies.

“No loss” is a durability statement with prerequisites. The latest confirmed records, attachments, membership/key envelopes and verification material must have reached a surviving copy. A hash cannot reconstruct missing bytes. A user's unsent draft cannot be recovered from someone else's archive. The application must distinguish a local draft, a pending submission, a consensus-confirmed post and a confirmed independent archive copy.

freemkv is the first customer configuration, not a protocol special case. Its forum uses freemkv's local logo assets, navigation, typography, teal palette and light/dark styling. Other communities choose their own branding, domains and compatible frontends.

## 2. Security, privacy and user experience

All discussion reading requires sign-in and authorized decryption keys. Public visitors may see the application shell, public branding and a deliberately public community label. Board names/descriptions, topic titles, post bodies, replies, attachments and search results must not appear in the public HTML, URLs, logs, exports or storage-provider plaintext.

The forum should feel familiar: ordered boards, topics, replies, quoting, revisions, search, attachments, moderation and clear publication states. Deep links use opaque identifiers. Search operates over the member's decrypted local view. The reference client must work on mobile, support keyboard navigation, escape untrusted text and avoid fetching third-party fonts, avatars, analytics or remotely embedded post content.

Privacy is required at every layer, but the product must name its boundaries:

- Members use independent, random cryptographic identities per community and pseudonyms unrelated to a forge username or email. Reusing one community's identity in another is not the default.
- Identity mapping, where forge enrollment is configured, is separately encrypted and excluded from replicated community archives. Being a moderator or ordinary community administrator must not automatically expose forge identities or infrastructure credentials.
- The login handler necessarily observes the forge identity during that enrollment. A forge provider may correlate its own account and authorization activity. Local encryption cannot undo that observation.
- A direct network connection exposes some addressing information to the receiving operator. Tor/appropriate relays are necessary when the real host or client address must be hidden from that peer. Omitting fields from an admin panel is not network anonymity.
- Stable community public keys, opaque object relationships, roles, sizes, epochs, ordering and timing/access patterns are verification metadata in the current protocol. They can correlate activity even though names and content are encrypted. Further metadata minimization is a requirement, not an implemented anonymity guarantee.
- A reader can retain plaintext and old keys. Revocation cannot erase screenshots or previously acquired information. A malicious frontend, browser extension, endpoint compromise or untrusted recovery tool can steal keys or plaintext.

Anyone may distribute a compatible frontend. This does not make arbitrary frontend code safe to receive private keys. Members need a trusted client distribution and independently verifiable community fingerprints/checkpoints. A replacement domain's TLS certificate proves that domain's control, not that its JavaScript is trustworthy. Signed/reproducible client distribution and a usable trust-pinning workflow remain release gates.

## 3. Independent roles and trust boundaries

| Role | Responsibility | What it does not acquire automatically |
| --- | --- | --- |
| Member | Hold community identity keys; decrypt granted epochs; sign authorized contributions | Other members' forge identities or administrator authority |
| Moderator | Moderate content under community policy | Forge mappings, backend credentials or permanent ownership |
| Administrator | Sign admission, roles, key grants, publisher approvals and policy changes | Ownership of independently operated servers/copies or immunity from revocation |
| Frontend | Present a verified, authorized client view | Publication authority, membership or decryption keys merely by hosting |
| Approved publisher | Deliver member-signed candidate changes under an approved backend key | Permission to impersonate users or grant itself roles |
| Validator | Participate in agreement on valid ordered transactions under the selected branch's validator trust | Content decryption, membership or more power because it runs extra archive copies |
| Archive backend | Preserve/serve opaque encrypted history and required verification/key-envelope data | Publication authority, votes, membership or plaintext keys |
| Local operator | Configure its own process, credentials, storage and routing | Global control over every community participant |

These roles may coexist on one machine, but their authority must remain separate. An S3 bucket is storage, not an identity provider. A forge repository may be storage while a distinct OAuth integration handles enrollment. Storage authorization does not configure an OAuth application or its callback.

## 4. Permissionless read-only participation

Anyone can create a read-only frontend or backend without community-administrator approval. Such deployments must not register themselves in a community-wide inventory, trigger administrator notifications or attach a permanent owner/member identity merely to copy or serve ciphertext.

A private pull backup need not announce its existence. Its owner keeps source/destination credentials and routing configuration locally. A read-only frontend still requires the normal member authentication and key-unlock path to render plaintext. Neither serving public application assets nor possessing an encrypted archive permits plaintext reading.

No protocol can guarantee that a publicly advertised website or observed connection is undiscoverable. The guarantee is no mandatory administrator registration/inventory and no automatic disclosure through community administration APIs. A server performing an explicitly configured push necessarily knows its own destination; this operator-local fact must not become a global administrator directory.

Recovery and public verification must not depend on a list containing every private copy. Dashboard counts refer only to known, reachable, voluntarily advertised participants. They never represent a complete worldwide inventory.

## 5. Two-way approval without connection disclosure

Publication requires explicit community approval of a pseudonymous backend signing key. Approval applies to capabilities, not to the owner's real identity, forum membership or physical infrastructure.

| Community administrators may see | Kept local to the backend owner or necessary routing peers |
| --- | --- |
| Random backend label and public-key fingerprint | Real identity, forge account or mandatory association with a member |
| Requested capabilities and approval/revocation state | Repository/bucket coordinates and internal paths |
| Proof of key possession and protocol compatibility | Tokens, passwords, OAuth secrets and private keys |
| Verified history/checkpoint and bounded health status | Private IP addresses, local configuration and unrelated private backups |

Administrators may approve or revoke a publisher's ability to submit candidates. They cannot remotely delete its retained history or confiscate its storage. Member signatures and current permissions remain mandatory for each accepted transaction.

Transport addresses are a separate routing concern. A connecting peer needs some route, such as an onion address or relay handle, but those routes need not be replicated as part of the administrator approval record. Direct HTTPS cannot hide the destination from the operator connecting to it. Tor/outbound relay support is needed when revealing that address is unacceptable. Approval records must never contain credentials.

Publisher approval is separate from validator membership. Adding fifty encrypted backups grants no additional consensus votes. The current implementation has publisher key approval and a fixed validator set; the full anonymous capability-request, proof-of-control and private routing workflow remains unfinished.

## 6. Portable identity, sign-in and keys

### 6.1 Member-held identity

A member's portable identity contains separate signing and wrapping keypairs. The prototype uses Web Crypto ECDSA P-256/SHA-256 for member signatures and RSA-OAEP 3072/SHA-256 to wrap group epoch keys. The public identity fingerprint is SHA-256 of the uncompressed signing public key. User-facing pseudonyms derive from that random per-community fingerprint, never a guessable forge username or email.

The browser encrypts private key material in a local vault with AES-256-GCM. A unique long passphrase derives the wrapping key through Argon2id with 64 MiB memory, three iterations and four lanes. A downloaded encrypted recovery file carries the portable vault and authenticated recovery metadata. The passphrase and private keys must never reach a service, forge, archive or log. The implementation must authenticate the community, public keys and recovery checkpoint against vault tampering.

Sign-in is a one-use, expiring challenge scoped to the community and deployment origin, signed by the member key. Sessions are local to a deployment and do not define community identity. Moving to a new domain may require sign-in and recovery import; it must not require the old domain or its session cookies.

Passkeys and OTP are not the identity foundation. They may become optional local protections where compatible with portability and the threat model. Neither a forge login nor an OTP can recreate a lost encryption private key. Hardware-backed distinct-device credentials, individual device revocation and encrypted device-to-device enrollment remain future work; the prototype recovery file copies one identity's keypairs across devices.

### 6.2 Forge enrollment policy

The administrator chooses whether joining requires an approved forge account or permits a key-only identity. The prototype supports GitHub and Forgejo OAuth enrollment using state bound to an HttpOnly cookie, one-use expiring state, PKCE S256 and fixed callbacks. Normal existing-member recovery/sign-in uses portable key possession, so a forge outage need not disable an already enrolled identity.

Forge identity uses the configured issuer instance and immutable account ID, not matching usernames or email. Account linking must never occur by matching those mutable values. OAuth credentials stay operator-local. The current implementation does not fetch forge avatars or use forge account names in posts. Private mappings use a keyed index and separate AES-GCM encryption under an operator-local identity key; archive exports omit mappings, sessions and OAuth secrets.

### 6.3 Admission, history and revocation

Setup asks the administrator to choose automatic versus approved membership, existing-history access and identity requirements. Automatic admission is not hidden key escrow: an unlocked authorized administrator client must grant keys. It must be clear when admission awaits such a client.

Discussion content uses AES-256-GCM epoch keys with fresh 96-bit IVs. Encrypted payload authentication binds the routing/event fields as additional authenticated data. An administrator wraps epoch keys to each authorized identity's public wrapping key. The service and storage providers do not receive plaintext group keys.

When a member is revoked, the same accepted control operation advances the epoch and supplies grants only to remaining active identities. Future posts require that current epoch and current authority state. Removing an administrator follows the same rule; the founder has no permanent owner privilege. The selected branch retains at least one administrator during ordinary administration. A separate explicit recovery branch can reset authority using a surviving active member identity at a retained checkpoint.

Historical keys and copied content cannot be revoked retroactively. An isolated host may not have learned a revocation, so it must not independently confirm new posts without agreement. Client logout/session expiry must lock the visible view and clear in-memory keys/plaintext; encrypted local recovery material may remain. Forensic secure erasure is not promised.

## 7. One agreed history during normal operation

Hash links, signatures, replication and agreement have distinct jobs:

- Hashes detect changed bytes and identify records.
- Signatures prove key possession and permit authorization checks.
- Replication copies complete accepted data and repairs gaps.
- Consensus orders concurrent valid transactions and determines confirmation.

Hash linking alone does not keep disconnected independent writers on one history. Ordinary simultaneous posting must not require human branch arbitration. NightBuoy therefore uses an established consensus engine rather than inventing a new voting protocol or treating storage replicas as voters.

The prototype integrates **CometBFT 0.38.26** through ABCI++, using the compatible Rust Tendermint types/verifier at 0.41.0. A smaller explicitly trusted validator group orders transactions; approved publishers submit member-signed candidates. A post references the current governance checkpoint so two ordinary posts can be ordered without requiring the author to sign the other post's eventual position. The consensus block history commits the ordered application state.

With four equally weighted, independently operated validators, more than two-thirds voting power means at least three must confirm a block. Safety assumes less than one-third Byzantine voting power; confirmation also needs sufficient reachable honest validators and suitable network progress. Four processes on one machine test behavior but do not provide independent ownership or protection against that machine's loss. More backup buckets do not improve a validator quorum.

When confirmation is unavailable, the client must preserve an encrypted pending submission and label it pending. It must never show an unavailable quorum as a successful confirmed post. Receiving an RPC response alone is not sufficient portable evidence. The validator key set/chain ID must be bound to community trust, and a verified commit must bind the exact exported application state. Both native services and browser clients must verify this proof. A policy update must never silently remove or replace validator trust.

The prototype's fixed validator set requires an explicit branch reset to change trust. Safe ongoing validator reconfiguration is not implemented. Confirmation guarantees do not mean every archive has copied the post at that instant. Reads must expose checkpoint/freshness limitations rather than imply global completeness.

## 8. Deliberate permanent forks and explicit reset

A lagging copy that contains a verified prefix is not a fork. Missing peers are unknown, not votes. Invalid signatures or altered objects are invalid data, not a competing legitimate branch. An incompatible signed history or an explicit authority reset is a branch decision.

Participants may deliberately retain or resume an earlier valid checkpoint after a rogue administrator changes permissions, removes members or disconnects storage. Forks are permanent. There is no merge, longest-chain rule or automatic “most backends wins.” Selecting A, Z or creating B must explicitly choose a starting checkpoint and preserve unselected archives.

A new branch must be bound to a distinct branch fingerprint and clearly explain changed administrator, publisher, validator and key-epoch state. A surviving member may reconstitute a branch only from a checkpoint where their identity was active. The new branch must cryptographically verify the selected old checkpoint, retain its ancestry, rotate future keys and require explicit client trust selection. It must not make an ordinary member an administrator on the old branch or be silently followed as normal catch-up.

Administrator notifications should show the last common checkpoint, verified conflicting records, relevant content/permission differences available to that reader, known participant observations, last-seen times and missing data. Example: “12 reachable known participants report A; 6 report Z; 32 configured participants are unreachable/unknown.” These are observations, not proof of legitimacy or independent ownership. Notification deduplication and a full branch comparison/reset workflow are not yet implemented.

An administrator's choice affects participants choosing that branch. No single administrator can force all independent deployments or users to follow it. A signed action can still be socially malicious while valid under the selected branch's permission rules; consensus does not decide whether an administrator's intention is good.

## 9. Data and protocol contract in the prototype

The community genesis is a compact, signed UTF-8 JSON array:

```text
["nightbuoy-genesis", 1, creatorPublicIdentity, initialPolicy,
 initialPublisherPublicKey, encryptedEpochKeyGrants]
```

Its exact body bytes hash to the community fingerprint. Initial policy includes validator trust when consensus is configured. JSON arrays have fixed field order; object keys in member-signed bodies are recursively sorted; signatures cover exact compact bytes. This is a constrained prototype encoding, not a claim of implementing every JCS numeric edge case.

Control bodies have this form:

```text
["nightbuoy-control", 1, community, previousAuthorityCheckpoint,
 actorIdentity, nonce, operation, parameters]
```

Content event bodies have this form:

```text
[1, community, authorIdentity, authorityCheckpoint, epoch,
 kind, objectId, parentId, previousRevision, advisoryCreatedTime,
 iv, ciphertext]
```

The first ten content fields form AES-GCM additional authenticated data. Body SHA-256 identifies the transaction. Publisher receipts use Ed25519 and cover a domain-separated community/event identifier. UUID object IDs remain stable across frontend addresses. Wall-clock timestamps are advisory and cannot establish authority or ordering.

Archives contain signed genesis, control records, publication records, their consensus-selected order and a portable commit proof. The application-state digest uses recursively sorted JSON object keys over the core archive and excludes the proof to avoid circular hashing. Member signatures, publisher approval, role rules, current epoch, parent type, revision predecessor and limits are replayed before acceptance. Duplicate delivery does not create duplicate posts or revive a removed object. Stale same-object revisions require an explicit reload/reconciliation.

Malformed ciphertext cannot always be detected by a non-decrypting validator. The authorized client must isolate decryption/schema failures per record, retain the signed evidence, keep other discussions usable and offer moderation of the bad record. One corrupt historical payload must not disable all future reads.

The native consensus-proof verifier is compiled to WebAssembly for the reference browser client. This reduces duplicated proof-verification logic; it does not by itself establish correctness or remove client-distribution trust. Browser authorization and archive parsing still require independent consistency tests against native behavior.

## 10. Replication and durable storage

Adapters separate identity, storage, transport and presentation. The current storage families are directory, GitHub, Forgejo and S3-compatible object storage. Adapters preserve the same portable encrypted records, independent of Git commit IDs, native issue numbers, provider timestamps or S3 ETags.

The current prototype writes complete immutable archive snapshots at content-addressed paths and a mutable discovery pointer. The pointer is a hint; hashes, signatures, permission replay and confirmation proofs establish validity. Snapshots include encrypted attachments and key envelopes. Operators must not place private vaults, identity mappings, sessions, provider credentials or plaintext indexes in them.

Configured destinations are bounded, asynchronous and checked by write/readback. The prototype limits a service to 128 configured destinations with eight concurrent transfers. A `consent` declaration and successful scoped access/readback are operator-local checks, not a globally published backup enrollment record. Private pull mirrors remain outside that configuration and community inventory.

A divergent remote history must be retained/reported and never combined with the selected history. Unknown/missing/stale records trigger retry or repair, not fabricated acceptance. Revoking a publisher does not invalidate authentic previously accepted archives held by it. Credentials must grant only the destination access needed by its owner; one shared all-replica deletion credential is forbidden.

Local SQLite currently stores accepted application state, consensus progress and sessions. The browser keeps pending signed ciphertext and a self-wrapped content key in IndexedDB before sending; it supports retry, draft review and encrypted export. The server does not claim a SQLite outbox. Private browsing or cleared browser storage can destroy unexported pending work. Application state and consensus checkpoint must commit atomically and be crash-recoverable. Rebuildable projections differ from secrets and unreplicated work. Aggregate archive limits must be enforced before consensus admission; accepting data that cannot be proofed/exported afterward is a correctness failure.

Whole-archive snapshots, repeated replay and full-history client decryption are pilot limitations. Incremental content-addressed object exchange, bounded local projections, efficient attachment objects, inventory reconciliation at scale and server-side delivery queues remain engineering work. A prototype cap is not a claim of unlimited forum capacity.

## 11. Deployment and transport

Public user access must use trusted HTTPS or an authenticated Tor v3 onion service. Plain clearnet HTTP is rejected. HTTPS IP endpoints are allowed with a certificate the client trusts. An onion service may use an `http://…onion` URL while Tor supplies authenticated encrypted transport; this is distinct from clear HTTP to an internet IP. Loopback HTTP exists only in explicitly restricted automated test mode or private local process transport, not as a public deployment mode.

The target default is Docker packaging for the Rust service, built Svelte client and required local consensus integration, with explicit persistent volumes and operator-owned credentials. Independently hosted frontend/non-voting service deployments must remain possible. Ingress, Tor routing and consensus RPC/ABCI interfaces need separate exposure rules. Internal consensus RPC and ABCI must not be exposed to arbitrary internet clients. Validator signing state must never be reset/reused in a way that causes double-signing.

Fresh deployment presents Create community or Join/restore. A local one-use bootstrap token protects first administration. Setup chooses public origin, community policies, supported enrollment issuers, branding, storage and recovery settings. Restoring an existing live network differs from starting an explicitly selected new branch after all validators are lost. Neither operation may silently overwrite live consensus state.

For Tor deployments, every applicable outbound client must honor the chosen proxy/routing policy or fail closed. A proxy on one HTTP client does not cover another SDK's independent client. No DNS, redirect, asset or storage transfer should silently bypass the configured privacy path.

Standalone domains, subdomains, path mounts, embedding, headless use and replaceable frontends are product goals. The current reference implementation serves one origin at `/`; path mounts, cross-origin/embedded integration and installable script-free skin packages are not implemented. The two built-in skins are not a complete skin-package API.

## 12. Implementation and release gates

| Area | Current evidence/status |
| --- | --- |
| Browser encryption and portable encrypted vault | Implemented; authenticated recovery metadata, per-record malformed-content isolation and session-expiry locking have regression checks; independent re-review outstanding |
| Boards/topics/replies/revisions/search/attachments/moderation | Implemented reference UI; bounded pilot behavior |
| Forge OAuth enrollment | Implemented GitHub/Forgejo flow; local protocol fixture covers PKCE/state, not a live-provider credential smoke test |
| Admission/history and peer admin revocation | Implemented; admission/history/revocation browser tests pass, including founder revocation |
| Original-host-loss recovery | Development-mode independent-archive restore/read/attachment/reply test passed |
| Normal concurrent posts | Four-node CometBFT browser test passed with one agreed order and continued posting after original node shutdown |
| Consensus proof | Native/WASM verifier implemented; browser trust-downgrade regressions pass; independent re-review outstanding |
| Permissionless private read-only participation | No global read-only registry exists; end-to-end anonymous frontend/backup workflow and privacy boundaries need further acceptance tests |
| Anonymous two-way approval | Publisher key approval exists; complete capability requests/control proofs/private routing UX unfinished |
| Archive adapters | Implemented; external live-provider compatibility/failure/scale tests unfinished |
| Deliberate branch recovery | Core control and development restore paths exist; full consensus-backed restore/reset, comparison, notifications and anti-rollback UX unfinished |
| Durable pending outbox | Encrypted IndexedDB outbox tested across quorum loss, page reload and successful retry |
| HTTPS/Tor/Docker packaging | Docker HTTPS test network built and exercised with two origins and quorum proof; SOCKS routing unit test passes; end-to-end Tor and production packaging unfinished |
| Security review | Initial independent agent audit completed; remediation evidence in docs/AUDIT.md; follow-up review blocked by review system, no professional certification |
| License | MIT, selected by the project owner; standard repository/community documents follow the existing MIT repositories |

Deployment readiness requires all of the following, not merely a green build:

1. Real supported forge enrollment where enabled, portable key sign-in and correct topic return paths.
2. No content/identity/private-key leakage through HTML, logs, caches, exported records, filenames or third-party requests.
3. Concurrency tests proving one confirmed order across independent services, validator failure tests, quorum-loss pending behavior and durable crash/restart recovery.
4. Removal tests proving no future key grants to revoked members/admins, including stale/replayed attempts.
5. A fresh deployment at another HTTPS origin or onion address recovering complete history/attachments from an independent archive and member-held keys, with the original host absent.
6. Explicit permanent branch/reset tests preserving old history and requiring informed client trust selection; no automatic merge or replica-count voting.
7. Read-only participation without admin registration/inventory, and minimal-information two-way approval with credentials/routing privacy enforced at API boundaries.
8. Docker/HTTPS/Tor deployment artifacts validated against actual builds, with narrowly exposed interfaces, safe permissions and documented upgrade/recovery behavior.
9. Independent findings triaged and regression-tested; unresolved critical issues block release, and material remaining limitations are stated plainly.

## 13. Implementation map and supporting evidence

- `crates/server/src/model.rs`: signed community state, permissions, epochs, content validation, replay and branch rules.
- `crates/server/src/consensus.rs`: CometBFT ABCI application, proposal validation, atomic acceptance and proof retrieval.
- `crates/proof/src/lib.rs`: native/browser consensus commit verifier.
- `crates/server/src/api.rs`: setup, challenge authentication, OAuth, sessions, authorization and HTTP security boundaries.
- `crates/server/src/store.rs`: SQLite durability, local secrets and private identity mappings.
- `crates/server/src/replication.rs`: encrypted archive adapters and operator-local transfer status.
- `web/src/lib/crypto.ts`: member keys, encrypted vaults, epoch grants and content encryption.
- `web/src/lib/protocol.ts`: browser authorization/history verification and WASM proof checks.
- `web/src/App.svelte`: reference forum, setup, keys, administration and recovery UI.
- `crates/server/tests/security.rs`, `tests/browser/forum.spec.ts`: executable security/behavior checks; test success is evidence within their coverage, not a general security proof.

Protocol research and library documentation: [MLS/RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), [Argon2/RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html), [Scuttlebutt](https://ssbc.github.io/scuttlebutt-protocol-guide/), [Briar](https://briarproject.org/how-it-works/), [Peergos](https://github.com/Peergos/Peergos), [CometBFT consensus specification](https://github.com/cometbft/cometbft/blob/v0.38.26/spec/consensus/consensus.md), [ABCI application requirements](https://github.com/cometbft/cometbft/blob/v0.38.26/spec/abci/abci%2B%2B_app_requirements.md), [GitHub OAuth](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps), [Forgejo OAuth](https://forgejo.org/docs/latest/user/authentication/oauth2-provider/), [Tor onion services](https://community.torproject.org/onion-services/overview/index.html). These inform the design; they do not constitute an endorsement or audit of NightBuoy.

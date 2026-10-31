# NightBuoy — resume kickoff

## Paused by the user

The user explicitly requested a convenient pause, a kickoff for the next session, stopped subagents, and cleanup of owned obsolete targets/worktrees/temp files. The goal was cleared before pausing; `get_goal` returns null. The project is **not complete**. Do not resume feature work until the user resumes it, and do not silently expand the agreed scope.

Read `ARCHITECTURE.md` for the master design and `docs/AUDIT.md` for bounded review findings/evidence. Hindsight searches/list/read calls are required by the environment; the seven pages were empty/stale placeholders during this session, so code, tests and live CI supplied the actual status.

## Saved code and green evidence

Repository: `MattJackson/nightbuoy`, branch `dev`. Latest application source milestone: **88f06b80c2fe97562b75c231f134be475162d1fa**. Presence is in `e9bcc2f`; the following commit fixes the Snap rehearsal's systemd user session.

All three workflows passed at exactly that milestone:

- [Full CI — 41174641148](https://github.com/MattJackson/nightbuoy/actions/runs/41174641148).
- [Native packages — 41174641150](https://github.com/MattJackson/nightbuoy/actions/runs/41174641150): Linux/macOS/Windows on x86-64 and ARM64, native archives/installers and payload/runtime checks.
- [Static Linux and sideloads — 41174641305](https://github.com/MattJackson/nightbuoy/actions/runs/41174641305): musl x86-64/ARM64/ARMv7; native x86-64/ARM64 AppImage, Flatpak, Snap and scratch-container rehearsals. Downloadable artifacts/checksums are attached to the runs, with 14-day retention.

Local checks at the presence milestone passed 36 Rust workspace tests, strict all-feature Clippy, zero Svelte diagnostics, 19 crypto/private/projection tests, focused provider epoch-admission checks and five portable browser tests. Full CI also ran the legacy/browser/provider suites. Workflows verify the embedded UI and portable API, not every desktop/browser launcher integration or supported historical OS version. macOS is ad-hoc signed/unnotarized; Windows and sideload artifacts are unsigned. No stores, tags or registry releases were published.

## Implemented

- Opaque v2 backend objects: padded authenticated encrypted metadata/content, ciphertext addressing, anonymous ECDH discovery, signed grant revisions and revocation rotation, pinned branches/checkpoints, encrypted exports. A metadata-capable companion is trusted with unlocked metadata; delivered application code remains a trust boundary.
- Basic storage-root URL plus optional key, provider inference and permission probes, confirmed-empty creation, private `nb2` read capabilities, no compulsory connection file, independent copies and explicit fork recovery.
- Default browser GUI, headless portable mode, native CLI/TUI, hidden key/passphrase prompts and private credential files. No mandatory SQLite for portable mode.
- Safe formatting/preview/emoji insertion, signed versioned thread locks and existing post edits/tombstones. Historical ciphertext remains recoverable to retained key holders. External media is never automatically fetched.
- Owner-private CAS objects; watched/unread/catch-up state and interoperable `.nbs` private backups. PM catch-up awaits messaging.
- Session/bootstrap/switching/401 cleanup fixes; pre-body ingress authorization, per-operation byte budgets and per-session/global permits. Provider writes use generic Git author/committer fields. Live GitHub large-object/CAS/attribution rehearsal passed on a temporary synthetic branch, which was removed.
- Read-capability holders can copy/export verified encrypted history without membership approval. This does not grant posting rights, destination credentials or write authority; private destination inventory is not an admin registry.
- Opt-in presence in GUI/TUI. Invisible by default, with no presence I/O until refresh/opt-in. A current-key-encrypted bounded pool contains signed forum/branch/epoch/governance/member/session/ephemeral-point hints. GUI and actual PTY terminal interoperate. Epoch admission, stale completions, revocation/expiry filtering and opt-out were reviewed. A 90-second sender lifetime plus 30-second future-clock tolerance can yield two observer-side minutes. This is recent activity, not proof someone is online; all current forum-key holders can decrypt it and providers can retain history.
- Native/static/sideload packaging, exact-commit/checksum binding, bounded owned cleanup and a non-network `check-transports` command. Scratch includes S3's required platform CA roots. Snap CI requires a real systemd user bus, not bare `dbus-run-session`.

## Next work: messaging, still unfinished

There is **no shipped PM/incognito implementation**. An initial, untested browser envelope helper is preserved as `docs/drafts/anonymous.ts.txt`, outside compiled production source. It was moved out of `web/src/lib` at pause. It needs review/cleanup before use: unused imports and a redundant cover-seed derivation remain. Do not describe this draft as a completed transport/protocol.

Continue the already approved participant-only 1:1/group GUI/TUI chat requirement. The chosen approach reuses existing random AES epoch keys, P-256 signatures and anonymous ECDH envelopes, rather than a shared persisted MLS sender ratchet. An isolated OpenMLS evaluation passed basic native/WASM checks but was removed after state cloning/fencing complexity was assessed. Do not restart that evaluation without a concrete reason.

Current proposed implementation (bounds are implementation proposals, not shipped behavior):

1. Context-bound signed linked packets, immutable packet before conditional encrypted head, a signed head certificate binding inventory/key commitments/roster/discovery, pinned accepted history, no merge. Participant-only metadata keys; forum administrators gain no special chat decryption privilege.
2. Small bounded groups, initially at most eight. A fixed initial roster with departure/revocation handling is the minimal proposal; adding people can start another conversation. Keep the implementation within the approved lean feature scope.
3. Persistent PM capabilities/pins in owner-encrypted private state; portable backups/checkpoints and missed-PM summaries. Persistent identity keys may recover PM history, so do not claim forward secrecy or post-compromise recovery.
4. Incognito uses live proposal/accept with a fresh **per-conversation** ephemeral recipient key. Bind exact forum/branch/checkpoint/room/mode/roster/recipient/session nonce/key/proposal hash/expiry. Final group keys must target accepted per-room ephemeral keys, never long-term identity or general presence keys. Incognito secrets/history stay in RAM, outside ordinary forum history, exports and caches. Leaving also retires the general presence/invitation ephemeral key so retained proposals cannot reopen local incognito metadata. Other participants can retain copies.
5. A bounded unlabeled binary invitation collection was proposed to avoid stranding offline PM invitations when forum metadata keys rotate. Existing v2 anonymous encrypted boxes expose only crypto framing/counts/points/ciphertexts, with no participant labels/content/forum names/timestamps/modes in plaintext. Each decrypted signed invitation authenticates its exact context and intended recipient. A format4 collection would need explicit bounded validation in private-object transport; it is **not implemented**. Private transport currently accepts only format3.

### Independent design findings that MUST be resolved

The independent reviewer stopped at pause after identifying these gates; the messaging design is not approved as implemented:

- **A departing participant must not generate the successor key.** Otherwise it still knows that key. Commit a signed departure, block further messages pending rekey, and require an eligible remaining participant to generate/commit a fresh epoch. Handle the last participant/closed room explicitly.
- **Distinguish ambiguous publication from definitive CAS conflict.** Keep exact packets/heads for ambiguous outcomes and readback. After a real competing winner, the old signed predecessor/sequence cannot be appended: rebase/resign against the new predecessor, preserve a logical message ID, and detect an already accepted logical message. Never silently merge divergent confirmed branches.
- **Enforce fixed-size arithmetic before decrypting.** A v2 box with eight slots and one padded 4096-byte body is 4674 bytes. Forty-eight boxes total 224352 bytes plus a three-byte collection header, fitting the 256 KiB private-object bound. A second 4096-byte block does not fit this count budget. Cap invitation plaintext at 4092 bytes, or deliberately lower the box count.

Known provider freshness/in-flight rotation limitations must remain explicit. Expected-epoch checks prevent already-refreshed companions from accepting obsolete client state, but cannot make independent remote object writes globally atomic with forum rotation. Apply eligibility on receive as well as send and use the selected primary's conditional semantics.

## Remaining approved release work

- Complete/audit/test messaging and PM notifications in both interfaces.
- Separate encrypted attachment blobs from immutable inline post snapshots; admin per-file/count/total limits, optional age purge default never, safe internal image handling and accurate provider-history/copy retention limits.
- Remaining explicitly approved lean interactions: reactions, pins and reports. Watches/unread/locks/formatting are already implemented; avoid unrelated forum features.
- Explicit preserved-history legacy-to-opaque migration and discovery-key upgrades for old identities. Existing portable reconstitution/legacy-anchor code is a foundation, not full migration acceptance. Never silently rewrite/reset the real old installation.
- Full third-party license/source bundles beyond the current generic notices, graphical launcher coverage and any remaining distribution/production gates. Packaging runs above are green; do not redo the recipes from scratch.
- Final independent bounded audits, real acceptance, current dev preview/artifacts, owned cleanup, commits/push and green CI. Stop when the agreed goal is actually complete; do not claim perfection/absolute anonymity or grow the scope.

## Preserve these environments and data

- Personal client `http://localhost:8080`: PID 30595 at pause, `.dev/bin/nightbuoy portable`, an older build. Preserve its active session/pending work; never broadly kill processes named NightBuoy.
- Separate preview `http://localhost:8081`: PID 89457 at pause, `.dev/preview/nightbuoy portable`, also older than current source. It has **not** been refreshed to the presence milestone. Verify PID/command again before any future replacement.
- Real legacy HTTPS installation at `https://localhost:8443` and its four-validator data/signing state remain intact. Preserve `.dev/project`, retained project records, certificate/volume overrides and Docker data. `scripts/compose.mjs` / Colima are the working Docker route; do not prune volumes or signing state.
- `MattJackson/nightbuoy-forum` is **private**, default branch `main`. It may hold real legacy/v1 data. Never publish or erase it, or mutate main for tests. Live provider acceptance must use disposable synthetic branches and clean them up. Keep credentials in subprocess memory, never logs, argv or handoff files.
- OEM stays NightBuoy-only; optional post-install branding remains separate. Never add the user's disallowed deployment-domain sentence.
- Other projects have active processes on this machine. Do not kill their tests/browsers or prune their worktrees/caches.

## Cleanup at pause

Removed the disposable 9.4 GiB repository `target/`, stale 67 MiB `dist/`, completed `test-results/`, 134 owned `/tmp/nightbuoy*` files and eight inactive NightBuoy test directories under the macOS temp root. No stale linked worktrees existed: `git worktree list` showed only the main `dev` checkout. Preserve `.dev` runtimes, certificates, project/connection files, synthetic Tor fixture and current `.tools` executables; shared dependency caches and `node_modules` are intentional. `.dev/cleanup-summary.json` records the cleanup locally.

Local Rust binaries/tests need rebuilding on resume (`cargo build --locked`; `npm run build` for current embedded assets). The green CI artifacts remain the current package evidence. The kickoff/draft commit is documentation-only and may skip CI; use source milestone 88f06b8 above for the completed application checks.

Both subagents were interrupted; no agent work should continue while paused. Resume from this checkpoint, not from a fresh redesign.

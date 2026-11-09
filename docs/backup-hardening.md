<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Encrypted backup and hardening

The owner authorized backup/hardening application code and offline tests on 2026-11-09 UTC. OTA, flashing, real-device operations and unverified switch writes remain excluded. This work does not prove recovery on hardware.

## Backup contract

`keys.export {passphrase, lock?}` returns an encrypted backup; `keys.import {passphrase, backup}` restores it. Both require owner authentication and the board button over HTTPS; USB retains the existing physical-presence rule. Web requests use jobs; USB keeps its inline reply contract. Passphrases are 12 to 128 UTF-8 bytes and never enter logs, events or audit metadata.

Use a versioned `LKB2` binary envelope: magic, version, KDF identifier, PBKDF2-HMAC-SHA256 iteration count (100,000), 16-byte random salt and 12-byte random nonce. Authenticate the complete header as AES-256-GCM additional data; use a 16-byte tag. Reject unknown versions/KDFs and unexpected iteration counts before deriving a key. Reuse the existing PBKDF2 implementation and PSA cryptography; add no dependency. Derivation yields periodically to the scheduler.

Encode fields explicitly, not as raw C++ structs. Preserve each lock's identity, protocol and keys, confirmed admin-passcode copy/provenance and any pending replacement, labels (including managed flags and weekly schedules), and optional seed table. Exclude board credentials, Wi-Fi/MQTT configuration, audit history and monitoring cursors. Validate counts, lengths, flags, UTF-8 text, MAC uniqueness, protocol data and nested records before any storage mutation. Clear transient plaintext and key material on success and failure.

Bound plaintext to 8 KiB, accepting up to eight locks when they fit. Refuse oversized exports with an instruction to export individual locks; never truncate or silently omit data. A maximum-size single-lock fixture must fit. Bound the authenticated RPC body and serial line to 16 KiB; buffers grow on demand rather than reserving that space permanently. Authenticate before allowing the larger HTTP body; unauthenticated login retains its smaller limit. Transfer parsed job parameters instead of duplicating them, release the raw request before starting the job, and release encoded input before allocating decoded records. Prefer a single owned binary buffer for authenticated decryption; PSA permits overlapping input/output buffers, but plaintext is unusable until authentication succeeds. Check allocation failures and test buffer lifetimes; runtime heap remains unproven. Increase the browser backup timeout to cover button confirmation and derivation.

Also bound export serialization and queued WebSocket bytes. Release binary/JSON representations as soon as their serialized replacement owns the data, and reject work that cannot meet the allocation budget. Test maximum import/export payloads against an explicit allocation budget; queue limits by message count alone are insufficient for large results.

Wrong passwords, damaged blobs, duplicate identities, existing locks, insufficient capacity or failed validation change no stored lock. Existing locks are reported and never overwritten, including persisted identities whose records are unreadable and absent from the in-memory lock list. Preflight the whole import and the NVS reserve. Persist a journal of new identities before writing their records, labels and seeds; publish the import only after every write succeeds. On error or reboot, remove only the journaled new identities, retain the journal if cleanup fails, and refuse lock initialization until recovery succeeds. Serialize imports with other lock mutations. Export refuses unreadable source records and marks the selected locks backed up only after encryption succeeds; return an error if this state cannot be persisted.

## Hardening contract

`lock.harden {lock, dryRun?}` previews or runs an ordered plan: time synchronization, unmanaged-passcode removal, admin-passcode handling, reset-button handling. Preview is read-only and reports opaque passcode IDs and counts, never codes. Its serialized read path bypasses automatic catch-up, clock writes and metadata persistence; authentication and read commands alone are allowed. Execution requires a backup since pairing and the board button over HTTPS, and rechecks current lock state after confirmation. Managed passcodes and confirmed or pending admin passcodes are never deleted.

Record admin-passcode provenance explicitly for newly paired locks and successful owner changes. Preserve owner-selected codes. Preserve legacy codes whose provenance is unknown, report that uncertainty and direct the owner to the existing admin-passcode control; do not guess provenance from code length. Rotate only a code known to be generated at pairing. Avoid collisions with listed passcodes, persist confirmation accurately and never overwrite a confirmed old copy before the lock accepts the replacement. New codes do not appear in progress events; the existing button-gated admin-passcode view remains available.

Before any admin-code write, persist the candidate separately from the confirmed old copy. A timeout or reboot retains both and marks the outcome unresolved; no automatic retry or further rotation occurs. Authenticated readback may confirm the candidate or the old code, then atomically persist that verdict before removing the pending entry. If readback is unavailable, fails, or reports a third code, retain the pending state and refuse automatic rotation. Backup/import preserves this state. Confirmed refusal may clear the candidate; failed cleanup remains visible and blocks further rotation.

Report each step and stop further mutations on an actual failure. Reset-button writes are always skipped as unverified in this version; `hardened` stays false while a required step is skipped or failed. Return explicit completion state and step results. The UI must display partial completion and never infer success from the presence of a result object.

Persist backed-up, hardened, reset-button-off and provenance flags without reinterpreting existing flags. Guard local forget and board factory reset while any affected lock is recorded with its reset button off. No force bypass is introduced. Pairing clears lifecycle flags. Imported recovery status must accurately reflect the authenticated backup and the current restore.

## Offline evidence

- Host format tests cover full records, labels/seeds, maximum size, truncation, duplicate locks, invalid fields, unsupported headers and exact wire bytes.
- Crypto tests use known AES-256-GCM/PBKDF2 vectors and an independent reference, with wrong passwords and header/ciphertext/tag changes refused. Reuse existing test/vendor code without adding dependencies.
- Import tests exercise preflight, persisted-but-unreadable conflicts, capacity, failure at every write boundary, restart recovery and cleanup failure through a deterministic in-memory storage backend. Transport tests verify early authentication, bounded allocations and request ownership through a queued job.
- Hardening tests cover preview without catch-up writes, managed/admin preservation, provenance, partial failure, backup prerequisites and zero switch writes. Admin-code tests cover lost acknowledgements, reboot, pending candidates and failed reconciliation/persistence.
- Browser tests cover preview/confirmation, partial completion, export/import errors, longer job deadlines and honest state after failures.
- Both target builds, native tests, browser tests and source checks must pass. No HIL or device command runs in this pass.

## Remaining acceptance

Runtime heap during derivation/import, physical-button behavior and a two-board restore remain unverified until separate hardware work is authorized. Full reset-button hardening additionally needs the switch-layout proof in issue #20. OTA and its hardware checks are deferred beyond v1.0.0.

The buffer-overlap contract follows the [PSA API conventions](https://arm-software.github.io/psa-api/crypto/1.2/overview/conventions.html#overlap-between-parameters).

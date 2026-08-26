# Installer state schema

The installer writes metadata only.  Managed and backup bytes never appear in
`manifest.json` or `journal.json`.

Manifests remain schema version 2. Journal schema version 3 is the current
write format; schema-v2 journals remain readable. Every journal operation
contains `expected_before_evidence` and `expected_after_evidence`; each is
either `null` or an object with exactly `device`, `inode`, `size`, `nlink`,
`mode`, and `sha256`.

Schema-v3 operations with a transaction backup also contain
`backup_identity_evidence`, captured when the backup is created and bound by
the original transaction commitment. Recovery compares this identity before
entering cleanup, so a same-content inode replacement or added hardlink cannot
be adopted as new evidence.

Every schema-v3 transaction pre-creates three private, single-link, fixed-size
commitment anchors per participant: one retained base-root slot and two
alternating progress slots. The transaction digest commits the ordered
structural projection of every anchor: device, inode, size, link count, and
mode. The base anchor is sealed with a canonical base-root payload; both
progress anchors initially contain the same sequence-zero progress payload.
Every journal stores the complete six-field evidence for all
`3 * participant_count` anchors in
`cleanup_commitment_evidence`, including before cleanup. Replacing an original
commitment marker with a same-content inode and rewriting the journal therefore
changes the transaction digest and is rejected.

Before an operation status or newly observed target identity is written to the
journal, the installer writes the next canonical progress payload into the
inactive progress slot and synchronizes its directory. The payload binds the
transaction/base commitment, participant and target, a monotonic sequence, all
operation statuses, and every full `expected_before_evidence` and
`expected_after_evidence` value. The other slot retains the preceding journal
state, and every journal replacement refreshes the complete stored identity of
both progress slots. Recovery requires at least one canonical progress root
whose complete observed identity equals the journal evidence. A mismatched
inactive slot is treated as an interrupted write only when it is torn or its
strict envelope binds an exact one-step transition derived from the current
journal and descriptor-relative target evidence. This preserves recovery after
a short slot write or a crash after the new root but before the journal
replacement. When that exact ahead transition is present, recovery materializes
the derived next journal state in memory before it classifies target state or
starts rollback; the next journal write persists it before another filesystem
mutation. Arbitrary forged-ahead digests remain rejected. Rewriting only a
pending journal's target identity, operation status, or recorded anchor digest
is rejected.

Before cleanup removes any transaction backup, the journal is atomically
rewritten with `rollback_status` set to `cleanup`. In this phase every backup
operation also contains `cleanup_backup_evidence` with the exact six-field
identity captured before deletion. The journal contains one canonical
`cleanup_participant_digests` entry per transaction participant; each
domain-separated participant digest binds the transaction metadata, full
`expected_before_evidence` and `expected_after_evidence`, final operation
state, full backup identities, and the precommitted anchor structures. A
canonical cleanup-root payload independently binds the original transaction
digest, ordered participant digests, their group digest, participant order,
and ordered anchor structures. Its expected SHA-256 is derived from that
payload rather than fed recursively into the participant digest.

Cleanup retains the base-root slot and newest valid progress slot unchanged. It
rewrites the inactive or older progress slot with the cleanup root and
synchronizes the containing backup directories before writing any cleanup
journal. A short or interrupted cleanup-root write can be repaired only while
the retained base root, latest progress root, and all precommitted structural
identities remain valid. Once any cleanup journal exists, exactly one progress
slot must match the canonical cleanup-root bytes and the other must match the
latest progress record; all three anchors must match their full stored
identities exactly. Staging never adopts a changed root by recomputing its
evidence. All participant
journals are rewritten with the final full anchor evidence before the first
backup or journal unlink. Same-content anchor replacement, hardlinks, mixed
participant roots, and partially rewritten marker-evidence tuples remain
fail-closed.
Recovery may treat a missing backup as an already completed unlink only in a
valid v3 cleanup journal; any present backup must still match the stored
identity exactly. A partial participant-journal set is accepted only when all
surviving journals agree on the cleanup transaction, participant set, final
operation state, per-participant digests, and the base, progress, and cleanup
records.

These roots provide crash evidence and detect malformed state, incomplete
crash-boundary writes, inode replacement, hardlinks, and uncoordinated
journal/anchor
tampering. They are not an append-only trust service: a same-UID actor that can
coordinate rewriting a journal, the affected target or backup state, and the
mutable progress or cleanup anchors needed for an accepted crash-boundary
state can construct a new self-consistent local history without rewriting every
anchor. Preventing that stronger attack requires an external key, TPM,
privileged service, or other trust boundary outside the selected homes; the
project intentionally has none. Rewrites that do not form a complete accepted
crash-boundary state remain fail-closed.

Cross-home cleanup unlinks participants sequentially and is resumable rather
than atomic. A surviving cleanup journal can prove the participant set and let
recovery finish the group. If every journal is absent, no local trusted fact
distinguishes completed cleanup from coordinated same-UID deletion; recovery
does not interpret or remove unproved orphan anchors.

Schema version 1 is legacy.  A completed v1 manifest can be migrated only by
the explicit migration path, which re-reads each descriptor-relative managed
path and proves its stored hash and mode.  A pending v1 journal is diagnostic
only and requires manual recovery; it is never converted into a Journal.

Schema-v2 journals remain readable, but a journal that references a backup is
not eligible for automatic cleanup or recovery: v2 never persisted the inode,
device, or link-count evidence needed to distinguish a same-content
replacement. A backup-free v2 journal also lacks the precommitted recovery
anchors needed to bind rewritten target identities, so it remains
diagnostic-only instead of being upgraded from mutable state. A schema-v2
journal that already claims cleanup is always rejected.

Schema version 0 and unknown versions are rejected. Unknown fields and
malformed evidence objects are rejected. Lock anchors are persistent `0600`
regular files and are not cleanup artifacts.

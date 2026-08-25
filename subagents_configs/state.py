"""Compatibility forwards for the strict state schema implementation."""

from .state_schema import (
    SCHEMA_VERSION,
    LegacyJournalEvidence,
    decode_journal,
    decode_manifest,
    encode_journal,
    encode_manifest,
    inspect_legacy_journal,
    load_journal,
    load_manifest,
    load_state,
    migrate_manifest_schema,
)

__all__ = [
    "SCHEMA_VERSION",
    "LegacyJournalEvidence",
    "decode_journal",
    "decode_manifest",
    "encode_journal",
    "encode_manifest",
    "inspect_legacy_journal",
    "load_journal",
    "load_manifest",
    "load_state",
    "migrate_manifest_schema",
]

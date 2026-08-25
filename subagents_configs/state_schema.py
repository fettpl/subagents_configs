"""Public state-schema seam.

The strict codecs remain implemented in :mod:`subagents_configs.state` for
backward compatibility; this module gives new callers a stable import surface.
"""

from .state import (
    SCHEMA_VERSION,
    decode_journal,
    decode_manifest,
    encode_journal,
    encode_manifest,
    load_journal,
    load_manifest,
    load_state,
    migrate_manifest_schema,
)

__all__ = [
    "SCHEMA_VERSION",
    "decode_journal",
    "decode_manifest",
    "encode_journal",
    "encode_manifest",
    "load_journal",
    "load_manifest",
    "load_state",
    "migrate_manifest_schema",
]

# Installer state schema

The installer writes metadata only.  Managed and backup bytes never appear in
`manifest.json` or `journal.json`.

Schema version 2 is the current read/write format.  Every journal operation
contains `expected_before_evidence` and `expected_after_evidence`; each is
either `null` or an object with exactly `device`, `inode`, `size`, `nlink`,
`mode`, and `sha256`.

Schema version 1 is legacy.  A completed v1 manifest can be migrated only by
the explicit migration path, which re-reads each descriptor-relative managed
path and proves its stored hash and mode.  A pending v1 journal is diagnostic
only and requires manual recovery; it is never converted into a v2 Journal.

Schema version 0 is rejected.  Unknown schema versions, including versions
greater than 2, are rejected.  Unknown fields and malformed evidence objects
are rejected.  Lock anchors are persistent `0600` regular files and are not
cleanup artifacts.

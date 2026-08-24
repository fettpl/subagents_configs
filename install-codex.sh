#!/bin/sh
set -eu
umask 077
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
export PATH
if [ -L "$0" ]; then
    echo "error: wrapper invocation must not be a symlink" >&2
    exit 2
fi
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec "$SCRIPT_DIR/install.sh" --target codex "$@"

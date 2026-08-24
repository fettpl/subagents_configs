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
if [ "${SUBAGENTS_CONFIGS_PYTHON+x}" = x ]; then
    PYTHON=$SUBAGENTS_CONFIGS_PYTHON
    case "$PYTHON" in
        /*) ;;
        *) echo "error: SUBAGENTS_CONFIGS_PYTHON must be an absolute path" >&2; exit 2 ;;
    esac
    if [ ! -f "$PYTHON" ] || [ ! -x "$PYTHON" ]; then
        echo "error: SUBAGENTS_CONFIGS_PYTHON must name an executable file" >&2
        exit 2
    fi
else
    PYTHON=python3
fi
exec "$PYTHON" -I "$SCRIPT_DIR/scripts/manage-subagents-configs.py" install "$@"

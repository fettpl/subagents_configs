#!/bin/sh
set -eu
umask 077

if [ "$#" -eq 0 ]; then
    :
else
    echo "bootstrap-developer.sh accepts no arguments" >&2
    exit 2
fi

if [ -e .venv ] || [ -L .venv ]; then
    echo "refusing any pre-existing .venv entry" >&2
    exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(not (sys.implementation.name == "cpython" and sys.version_info[:2] in ((3, 11), (3, 12), (3, 13), (3, 14))))'; then
    echo "bootstrap requires CPython 3.11 through 3.14" >&2
    exit 1
fi

python3 -m venv --copies .venv
chmod 700 .venv
if [ -L .venv ] || [ ! -d .venv ]; then
    echo "venv creation produced an unsafe directory" >&2
    exit 1
fi
if ! python3 -c 'import os, stat; root = os.lstat(".venv"); interpreter = os.lstat(".venv/bin/python"); raise SystemExit(not (stat.S_ISDIR(root.st_mode) and stat.S_ISREG(interpreter.st_mode) and not stat.S_ISLNK(interpreter.st_mode) and interpreter.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) and root.st_uid == os.getuid() and interpreter.st_uid == os.getuid() and stat.S_IMODE(root.st_mode) & 0o077 == 0 and stat.S_IMODE(interpreter.st_mode) & 0o022 == 0))'; then
    echo "venv interpreter is unsafe" >&2
    exit 1
fi

exec .venv/bin/python -m pip install --require-hashes --requirement requirements-dev.lock

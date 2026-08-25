#!/bin/sh
set -eu
umask 077

if [ "$#" -eq 0 ]; then
    :
else
    echo "bootstrap-developer.sh accepts no arguments" >&2
    exit 2
fi

version="$(python3 --version 2>&1)"
case "$version" in
    "Python 3.11."*|"Python 3.12."*|"Python 3.13."*|"Python 3.14."*) : ;;
    *)
        echo "bootstrap requires CPython 3.11 through 3.14" >&2
        exit 1
        ;;
esac

if [ -e .venv ]; then
    if [ ! -d .venv ] || [ -L .venv ]; then
        echo "refusing an unsafe pre-existing .venv" >&2
        exit 1
    fi
else
    python3 -m venv .venv
fi

exec .venv/bin/python -m pip install --require-hashes --requirement requirements-dev.lock

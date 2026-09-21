#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
PYTHON=${PYTHON:-python3}
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "INCOMPLETE: Python is missing. See START-HERE.md for clean-host prerequisites." >&2
    exit 2
fi
exec "$PYTHON" -I "$ROOT/review.py" bootstrap "$@"

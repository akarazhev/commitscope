#!/bin/sh
# Optional official native CLI installation. Never replace an existing install.
set -eu
case "${1:-}" in
  --help|-h) printf '%s\n' 'Usage: sh scripts/install-claude.sh' 'Installs the pinned official native Claude CLI only if absent. No login, model call, migration or upgrade.'; exit 0 ;;
  '') ;;
  *) echo 'Unknown argument. Use --help.' >&2; exit 2 ;;
esac
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
if command -v claude >/dev/null 2>&1; then
    echo 'Claude is already on PATH; it will NOT be replaced or upgraded.'
    claude --version
    exit 0
fi
if [ -n "${HOME:-}" ] && [ -x "$HOME/.local/bin/claude" ]; then
    echo 'Native Claude is already installed; it will NOT be replaced or upgraded.'
    "$HOME/.local/bin/claude" --version
    exit 0
fi
for tool in curl bash mktemp; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "INCOMPLETE: missing $tool. See START-HERE.md." >&2
        exit 2
    fi
done
if [ -z "${HOME:-}" ] || [ ! -d "$HOME" ]; then
    echo 'INCOMPLETE: HOME must be an existing directory for your normal OS user.' >&2
    exit 2
fi
if [ "$(id -u)" = 0 ]; then
    echo 'INCOMPLETE: install Claude as your normal OS user, not root/sudo.' >&2
    exit 2
fi
VERSION=$(cat "$ROOT/config/claude.version")
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
# The top-level vendor installer is fetched over verified TLS. Its script bytes
# are not pinned by this project; the version argument pins the native payload.
# See the vendor's binary integrity/signing documentation in docs/SOURCES.md.
curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 --retry 2 \
    https://claude.ai/install.sh -o "$TMP/install.sh"
bash "$TMP/install.sh" "$VERSION"
if [ ! -x "$HOME/.local/bin/claude" ]; then
    echo 'INCOMPLETE: official installer did not create $HOME/.local/bin/claude.' >&2
    exit 2
fi
"$HOME/.local/bin/claude" --version
echo 'CLI installed; authentication and live model requests have NOT been tested.'
echo 'For subscription login: "$HOME/.local/bin/claude" auth login'

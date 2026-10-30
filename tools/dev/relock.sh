#!/usr/bin/env bash
# Restore git sources in every module lockfile after working under
# .cargo/config.toml's [patch] (which rewrites them to path sources), and
# refuse to leave a lock that the nix module build cannot resolve.
#
# Usage: tools/dev/relock.sh            # all modules
#        tools/dev/relock.sh rln-auth-module rln-sign-module
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PATCH="$ROOT/.cargo/config.toml"
ASIDE="$PATCH.relock-aside"

# The shared crates every module may pin (package names as in Cargo.toml).
SHARED="rln_auth_vector zksign_light keycard_attest keycard_client rln_auth_vectors pow-claim"

restore() { [ -f "$ASIDE" ] && mv "$ASIDE" "$PATCH" || true; }
trap restore EXIT
[ -f "$PATCH" ] && mv "$PATCH" "$ASIDE"

if [ $# -gt 0 ]; then
  modules=("$@")
else
  modules=()
  for d in "$ROOT"/rust/*/rust-lib; do modules+=("$(basename "$(dirname "$d")")"); done
fi

fail=0
for m in "${modules[@]}"; do
  lib="$ROOT/rust/$m/rust-lib"
  [ -f "$lib/Cargo.toml" ] || { echo "relock: no module at $lib" >&2; fail=1; continue; }
  for c in $SHARED; do
    grep -q "^$c = " "$lib/Cargo.toml" || grep -q "package = \"$c\"" "$lib/Cargo.toml" || continue
    (cd "$lib" && cargo update -q -p "$c" 2>/dev/null) || true
  done
  for c in $SHARED; do
    grep -q "name = \"$c\"" "$lib/Cargo.lock" 2>/dev/null || continue
    if ! awk -v n="$c" '$0 == "name = \"" n "\"" {f=1} f && /^source = /{print; exit}' "$lib/Cargo.lock" | grep -q 'git+https://github.com/logos-co/logos-rln-gifter'; then
      echo "relock: $m: $c is not git-sourced in Cargo.lock (nix cannot build it)" >&2
      fail=1
    fi
  done
  echo "relock: $m ok"
done
exit $fail

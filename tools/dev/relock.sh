#!/usr/bin/env bash
# Regenerate every module lockfile WITHOUT .cargo/config.toml's [patch] (which
# rewrites the shared crates to path sources while developing), and refuse to
# leave a lock the nix module build cannot resolve.
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
  # A lock written under the patch holds path entries for the shared crates;
  # the only clean way back to the git sources is a fresh resolution.
  rm -f "$lib/Cargo.lock"
  (cd "$lib" && cargo generate-lockfile -q) || { echo "relock: $m: cargo generate-lockfile failed" >&2; fail=1; continue; }
  for c in $SHARED; do
    grep -q "name = \"$c\"" "$lib/Cargo.lock" || continue
    if ! awk -v n="$c" '$0 == "name = \"" n "\"" {f=1; next} f && /^source = /{print; exit} f && /^\[\[package\]\]/{exit}' "$lib/Cargo.lock" | grep -q 'git+https://github.com/logos-co/logos-rln-gifter'; then
      echo "relock: $m: $c is not git-sourced in Cargo.lock (nix cannot build it)" >&2
      fail=1
    fi
  done
  [ "$fail" = 0 ] && echo "relock: $m ok"
done
exit $fail

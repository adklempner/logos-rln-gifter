#!/usr/bin/env bash
# Build the liblogos_lez_rln_module STUB .lgx from an rsync-staged copy (untracked
# module → path: flake build). Prints the .lgx path.
set -euo pipefail
export PATH="$PATH:/nix/var/nix/profiles/default/bin"

here="$(cd "$(dirname "$0")" && pwd)"
staged="$here/../runs/src-stub-lez-rln"
mkdir -p "$staged"
rsync -a --delete \
  --exclude 'target' --exclude 'result*' --exclude 'build.sh' \
  --exclude 'logos-rust-sdk-src' --exclude 'rust-lib/generated' \
  "$here/" "$staged/"
out="$(nix build "path:$staged#lgx" --accept-flake-config --no-link --print-out-paths)"
ls "$out"/*.lgx

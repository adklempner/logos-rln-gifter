#!/usr/bin/env bash
# Build a pow-claim module .lgx from an rsync-staged copy (the flake only
# sees git-tracked files; these modules are untracked, so never build in place).
#   build-module.sh [MODULE] [--generate]
#     MODULE = rln_sign_module (default) | rln_auth_module
#   build-module.sh             -> prints the capture module's .lgx path
#   build-module.sh --generate  -> also refreshes rust-lib/generated/provider_gen.rs
#                                  from the builder's generated scaffold
set -euo pipefail
export PATH="$PATH:/nix/var/nix/profiles/default/bin"

here="$(cd "$(dirname "$0")" && pwd)"
rust="$(cd "$here/../../rust" && pwd)"

module="rln_sign_module"
generate=0
for a in "$@"; do
  case "$a" in
    --generate) generate=1 ;;
    rln_sign_module|rln_auth_module) module="$a" ;;
    *) echo "usage: $0 [rln_sign_module|rln_auth_module] [--generate]" >&2; exit 2 ;;
  esac
done

case "$module" in
  rln_sign_module) mod="$rust/rln-sign-module"; staged="$here/runs/src-pcm" ;;
  rln_auth_module) mod="$rust/rln-auth-module"; staged="$here/runs/src-pca" ;;
esac
mkdir -p "$staged"

rsync -a --delete \
  --exclude 'target' --exclude '**/target' --exclude 'result*' --exclude '.git' \
  --exclude 'logos-rust-sdk-src' --exclude 'rust-lib/generated' \
  "$mod/" "$staged/"

if [ "$generate" = 1 ]; then
  out="$(nix build "path:$staged#generate" --accept-flake-config --no-link --print-out-paths)"
  echo "generated: $out"
  # The generate output snapshots the post-codegen tree; locate provider_gen.rs in it.
  pg="$(find "$out" -name provider_gen.rs -print -quit)"
  if [ -z "$pg" ]; then echo "no provider_gen.rs in $out" >&2; ls -R "$out" | head -40 >&2; exit 1; fi
  mkdir -p "$mod/rust-lib/generated"
  cp "$pg" "$mod/rust-lib/generated/provider_gen.rs"
  echo "copied $pg"
  exit 0
fi

out="$(nix build "path:$staged#lgx" --accept-flake-config --no-link --print-out-paths)"
lgx="$(ls "$out"/*.lgx)"
echo "$lgx"

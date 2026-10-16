#!/usr/bin/env bash
# Build a pow-claim module .lgx from an rsync-staged copy (the flake only
# sees git-tracked files; these modules are untracked, so never build in place).
#   build-module.sh [MODULE] [--generate]
#     MODULE = pow_claim_capture_module (default) | pow_claim_auth_module
#   build-module.sh             -> prints the capture module's .lgx path
#   build-module.sh --generate  -> also refreshes rust-lib/generated/provider_gen.rs
#                                  from the builder's generated scaffold
# For pow_claim_auth_module, rust-lib/pow-claim-core is first re-synced from
# the capture module (the single source of truth for that crate).
set -euo pipefail
export PATH="$PATH:/nix/var/nix/profiles/default/bin"

here="$(cd "$(dirname "$0")" && pwd)"
rust="$(cd "$here/../../rust" && pwd)"

module="pow_claim_capture_module"
generate=0
for a in "$@"; do
  case "$a" in
    --generate) generate=1 ;;
    pow_claim_capture_module|pow_claim_auth_module) module="$a" ;;
    *) echo "usage: $0 [pow_claim_capture_module|pow_claim_auth_module] [--generate]" >&2; exit 2 ;;
  esac
done

case "$module" in
  pow_claim_capture_module) mod="$rust/pow-claim-capture-module"; staged="$here/runs/src-pcm" ;;
  pow_claim_auth_module)
    mod="$rust/pow-claim-auth-module"; staged="$here/runs/src-pca"
    rsync -a --delete --exclude target \
      "$rust/pow-claim-capture-module/rust-lib/pow-claim-core/" "$mod/rust-lib/pow-claim-core/"
    ;;
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

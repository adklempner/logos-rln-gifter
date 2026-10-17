#!/usr/bin/env bash
# tools/allocator/docker/build-bundles.sh — build the PORTABLE Linux bundles the
# allocator image (and its testers) need, on the machine that will run them.
#
# Why here and like this: the official catalog ships portable linux-amd64 /
# linux-arm64 bundles for libp2p_module, liblogos_lez_rln_module and
# liblogos_rln_module, but not for this repo's modules. The module builder
# builds natively only (no cross from macOS), and the released logosctl loads
# the portable variant (`linux-amd64`, no `-dev`), so the build runs inside a
# nixos/nix container on the target host — native amd64 on an Intel Mac,
# native arm64 on an Apple-silicon one — and asks for `#lgx-portable`.
#
# Modules (allocator side first, then the two tester-side producers):
#   rln-gifter-module  eth-auth-module  keycard-auth-module  pow-claim-auth-module
#   eth-sign-module    pow-claim-capture-module
# The pow-claim modules are untracked and share rust-lib/pow-claim-core; they
# are rsync-staged exactly as tools/pow-claim-poc/build-module.sh does (that
# script is not modified or invoked: its PoC drivers depend on it).
#
# Usage: build-bundles.sh [module-dir…]       (default: all six)
# Env:   BUNDLES_OUT   (default <here>/bundles)
#        NIX_VOLUME    docker volume for /nix (default rln-allocator-nix); the
#                      first build fetches the rust toolchain (~10 min), later
#                      ones reuse it
#        NIX_JOBS      --max-jobs (default 4)
#        NIX_IMAGE     (default nixos/nix:latest)
# Output: <BUNDLES_OUT>/<module>.lgx, and a line per module with its variant.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
RUST="$REPO/rust"
OUT="${BUNDLES_OUT:-$HERE/bundles}"
VOL="${NIX_VOLUME:-rln-allocator-nix}"
JOBS="${NIX_JOBS:-4}"
IMAGE="${NIX_IMAGE:-nixos/nix:latest}"
MODULES=("$@")
DEFAULTED=0
[ "${#MODULES[@]}" -gt 0 ] || DEFAULTED=1
[ "${#MODULES[@]}" -gt 0 ] || MODULES=(rln-gifter-module eth-auth-module keycard-auth-module pow-claim-auth-module eth-sign-module pow-claim-capture-module)

say() { printf 'build-bundles: %s\n' "$*" >&2; }
die() { say "ERROR: $*"; exit 1; }

command -v docker >/dev/null || die "docker not found"
command -v rsync >/dev/null || die "rsync not found"
mkdir -p "$OUT"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/rln-bundles.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

# Stage every module as a self-contained tree: the flakes only see tracked
# files, the pow-claim modules are untracked, and the container must not see
# host build outputs. The auth module's pow-claim-core is a copy of the
# capture module's (single source of truth there) — resync before staging.
PRESENT=()
for m in "${MODULES[@]}"; do
    if [ ! -d "$RUST/$m" ]; then
        if [ "$DEFAULTED" = 1 ]; then
            say "################################################################"
            say "WARNING: $m is MISSING from this checkout ($RUST/$m)."
            say "  No $m.lgx will be built; an image built now lacks it."
            say "  The pow-claim modules live on branch feat/pow-claim-auth-vector."
            say "################################################################"
        else
            say "skipping $m: $RUST/$m is not in this checkout"
        fi
        continue
    fi
    PRESENT+=("$m")
    if [ "$m" = pow-claim-auth-module ] && [ -d "$RUST/pow-claim-capture-module/rust-lib/pow-claim-core" ]; then
        rsync -a --delete --exclude target \
            "$RUST/pow-claim-capture-module/rust-lib/pow-claim-core/" "$RUST/$m/rust-lib/pow-claim-core/"
    fi
    rsync -a --delete \
        --exclude 'target' --exclude '**/target' --exclude 'result*' --exclude '.git' \
        --exclude 'logos-rust-sdk-src' --exclude 'rust-lib/generated' \
        "$RUST/$m/" "$STAGE/$m/"
    say "staged $m"
done
MODULES=("${PRESENT[@]}")
[ "${#MODULES[@]}" -gt 0 ] || die "nothing to build"

# One container run for all modules: the nix store volume keeps the toolchain
# and the module-builder inputs across runs. Network is needed for flake
# inputs and cargo git deps.
cat > "$STAGE/build.sh" <<EOF
set -eu
export NIX_CONFIG="experimental-features = nix-command flakes
max-jobs = $JOBS"
mkdir -p /out
for m in ${MODULES[*]}; do
    echo "== nix build path:/src/\$m#lgx-portable" >&2
    out=\$(nix build "path:/src/\$m#lgx-portable" --accept-flake-config --no-link --print-out-paths)
    lgx=\$(ls "\$out"/*.lgx | head -1)
    cp "\$lgx" "/out/\$m.lgx"
    echo "built \$m.lgx"
done
EOF

docker run --rm \
    -v "$VOL:/nix" \
    -v "$STAGE:/src" \
    -v "$OUT:/out" \
    "$IMAGE" sh /src/build.sh

# The variant must be the portable one for this host's arch (linux-amd64 /
# linux-arm64, no -dev): that is what the released logosctl loads.
# Docker Desktop runs Linux of the host's arch (see the header).
case "$(uname -m)" in
    arm64|aarch64) ARCH=arm64 ;;
    x86_64|amd64)  ARCH=amd64 ;;
    *) die "unknown host arch $(uname -m)" ;;
esac
say "bundles in $OUT (variants; this run's must carry linux-$ARCH and no -dev):"
python3 -I - "$OUT" "linux-$ARCH" "${MODULES[@]}" <<'PY' || die "a bundle built this run has the wrong variant (see BAD above)"
import glob, os, sys, tarfile
out, want, built = sys.argv[1], sys.argv[2], set(sys.argv[3:])
bad = 0
for f in sorted(glob.glob(os.path.join(out, "*.lgx"))):
    with tarfile.open(f) as t:
        v = sorted({n.split("/")[1] for n in t.getnames() if n.startswith("variants/") and n.count("/") >= 2})
    mark = ""
    if os.path.basename(f)[:-4] in built and (want not in v or any(x.endswith("-dev") for x in v)):
        mark = "  BAD (want %s, no -dev)" % want
        bad += 1
    print("  %s  %s%s" % (os.path.basename(f), " ".join(v), mark))
sys.exit(1 if bad else 0)
PY

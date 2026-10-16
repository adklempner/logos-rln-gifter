#!/usr/bin/env bash
# tools/pow-claim-poc/build-gifter-artifacts.sh [--rebuild-libp2p]
#
# Resolves the two round-2 gifter bundles and writes runs/artifacts.env:
#   LIBP2P_LGX / LIBP2P_REV — logos-libp2p-module-master (prebuilt result-lgx
#                             reused unless --rebuild-libp2p; tree never modified)
#   GIFTER_LGX / GIFTER_REV — rln_gifter_module built from a `git archive` snapshot
#                             of this repo's HEAD (the working tree is edited by others)
#   STUB_LEZ_LGX            — stub-lez-rln/ (liblogos_lez_rln_module stand-in)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUNS="$HERE/runs"
LIBP2P_SRC="${LIBP2P_SRC:-/Users/arseniy/Waku/Logos/logos-libp2p-module-master}"
export PATH="/nix/var/nix/profiles/default/bin:$PATH"

say() { printf '%s\n' "artifacts: $*" >&2; }
die() { printf '%s\n' "artifacts: FAIL: $*" >&2; exit 1; }

REBUILD_LIBP2P=0
for a in "$@"; do
    case "$a" in
        --rebuild-libp2p) REBUILD_LIBP2P=1 ;;
        *) die "unknown arg $a" ;;
    esac
done
mkdir -p "$RUNS"

first_lgx() { ls "$1"/*.lgx 2>/dev/null | head -1; }

# Usage: lgx_field <lgx> <field>
lgx_field() {
    tar xzOf "$1" manifest.json | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$2"
}

# Usage: lgx_has_string <lgx> <needle>   (gunzip → strings → grep; a literal in a
# multi-MB binary "line" is missed by grep -a)
lgx_has_string() {
    local tmp rc=0
    tmp=$(mktemp)
    gzip -dc "$1" 2>/dev/null | strings > "$tmp" || true
    grep -q -- "$2" "$tmp" || rc=1
    rm -f "$tmp"
    return "$rc"
}

# ---------- libp2p ----------------------------------------------------------
[ -d "$LIBP2P_SRC" ] || die "no libp2p tree at $LIBP2P_SRC"
LIBP2P_REV=$(git -C "$LIBP2P_SRC" rev-parse HEAD)
LIBP2P_LGX=""
if [ "$REBUILD_LIBP2P" = 0 ] && [ -e "$LIBP2P_SRC/result-lgx" ]; then
    LIBP2P_LGX=$(first_lgx "$(readlink -f "$LIBP2P_SRC/result-lgx" 2>/dev/null || echo "$LIBP2P_SRC/result-lgx")")
    [ -n "$LIBP2P_LGX" ] && say "reusing prebuilt libp2p bundle $LIBP2P_LGX"
fi
if [ -z "$LIBP2P_LGX" ]; then
    say "building libp2p lgx at $LIBP2P_REV (nix, --no-link)"
    out=$(cd "$LIBP2P_SRC" && nix build .#lgx --no-link --print-out-paths --accept-flake-config) \
        || die "libp2p nix build failed"
    LIBP2P_LGX=$(first_lgx "$out")
fi
[ -f "$LIBP2P_LGX" ] || die "no libp2p .lgx resolved"
[ "$(lgx_field "$LIBP2P_LGX" name)" = "libp2p_module" ] || die "libp2p bundle name mismatch"

# ---------- gifter (git archive snapshot) -------------------------------------
GIFTER_REV=$(git -C "$REPO" rev-parse HEAD)
SNAP="$RUNS/src-gifter-${GIFTER_REV:0:8}"
if [ ! -f "$SNAP/rust/rln-gifter-module/flake.nix" ]; then
    rm -rf "$SNAP"; mkdir -p "$SNAP"
    git -C "$REPO" archive "$GIFTER_REV" rust/rln-gifter-module | tar -x -C "$SNAP"
    say "snapshot $GIFTER_REV -> $SNAP"
fi
say "building rln_gifter_module lgx from snapshot ${GIFTER_REV:0:8}"
out=$(nix build "path:$SNAP/rust/rln-gifter-module#lgx" --accept-flake-config --no-link --print-out-paths) \
    || die "gifter nix build failed"
GIFTER_LGX=$(first_lgx "$out")
[ -f "$GIFTER_LGX" ] || die "no gifter .lgx in $out"
[ "$(lgx_field "$GIFTER_LGX" name)" = "rln_gifter_module" ] || die "gifter bundle name mismatch"
GV=$(lgx_field "$GIFTER_LGX" version)
WANT_V=$(git -C "$REPO" show "$GIFTER_REV:rust/rln-gifter-module/metadata.json" \
    | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["version"])')
[ "$GV" = "$WANT_V" ] || die "gifter manifest version $GV != metadata $WANT_V"
lgx_has_string "$GIFTER_LGX" 'logos/rln/membership' || die "gifter bundle lacks logos/rln/membership"
say "gifter bundle ok (version $GV, carries logos/rln/membership)"

# ---------- liblogos_lez_rln_module STUB (R2 contingency) ----------------------
# The gifter's LEZ client is lazy: with no such module loaded, register waits the
# full 190 s. The stub answers register_member at once → NotSubmitted. See
# stub-lez-rln/rust-lib/src/lib.rs.
say "building liblogos_lez_rln_module stub lgx"
STUB_LEZ_LGX=$("$HERE/stub-lez-rln/build.sh" | tail -1) || die "stub build failed"
[ -f "$STUB_LEZ_LGX" ] || die "no stub .lgx"
[ "$(lgx_field "$STUB_LEZ_LGX" name)" = "liblogos_lez_rln_module" ] || die "stub bundle name mismatch"

cat > "$RUNS/artifacts.env" <<EOF
LIBP2P_LGX=$LIBP2P_LGX
LIBP2P_REV=$LIBP2P_REV
GIFTER_LGX=$GIFTER_LGX
GIFTER_REV=$GIFTER_REV
GIFTER_VERSION=$GV
STUB_LEZ_LGX=$STUB_LEZ_LGX
EOF
cat "$RUNS/artifacts.env"

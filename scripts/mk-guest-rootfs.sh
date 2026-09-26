#!/usr/bin/env bash
set -euo pipefail

# Build the kjit-guest initramfs: Debian bookworm arm64 + redis-server,
# redis-tools (redis-benchmark), busybox, kmod, with scripts/guest/init as /init,
# plus the K2 guest tests (tests/guest/, static binaries built in the dev image)
# in /opt/kjit-tests. Runs on the host (needs docker and bsdtar). The result is
# an uncompressed newc cpio, so the guest kernel needs no decompressor.
#
# rootfs.cpio = base.cpio + tests.cpio (the kernel unpacks concatenated
# archives in order). base.cpio (the Debian export) is built only when it is
# missing or with --rebuild-base; tests.cpio is rebuilt every run.

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

require_cmd docker
require_cmd bsdtar

rebuild_base=0
case "${1:-}" in
    --rebuild-base) rebuild_base=1 ;;
    "") ;;
    *) echo "Usage: $(basename "$0") [--rebuild-base]" >&2; exit 2 ;;
esac

base_image="${KJIT_GUEST_BASE_IMAGE:-debian:bookworm}"
dev_image="${DOCKER_IMAGE:-kjit-dev:latest}"
out_dir="$KJIT_BUILD_ROOT/guest-rootfs"
base="$out_dir/base.cpio"
tests="$out_dir/tests.cpio"
out="$out_dir/rootfs.cpio"
container="kjit-guest-rootfs-$$"

mkdir -p "$out_dir"
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf "$base.tmp" "$tests.tmp" "$out.tmp" "$out_dir/rootfs.tar" "$out_dir/dev.mtree" \
        "$out_dir/tests-root"
}
trap cleanup EXIT

build_base() {
    # policy-rc.d keeps the package scripts from starting redis during the build.
    docker run --platform linux/arm64 --name "$container" \
        -v "$ROOT_DIR/scripts/guest:/kjit-guest-src:ro" \
        "$base_image" sh -euc '
            printf "#!/bin/sh\nexit 101\n" > /usr/sbin/policy-rc.d
            chmod 755 /usr/sbin/policy-rc.d
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                redis-server redis-tools busybox kmod procps
            rm -f /usr/sbin/policy-rc.d
            apt-get clean
            rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man /usr/share/info \
                /usr/share/locale
            install -m 0755 /kjit-guest-src/init /init
            mkdir -p /kjit
            redis-server --version
        '

    # The kernel opens /dev/console for PID 1 before /init mounts devtmpfs, and
    # docker export only has an empty regular-file placeholder there. The char
    # device entry comes later in the archive and replaces it: the kernel unpacker
    # unlinks an existing path of a different file type (init/initramfs.c,
    # clean_path). "native" makes bsdtar store major 5 / minor 1 in the newc header
    # on both macOS and Linux hosts.
    cat > "$out_dir/dev.mtree" <<'MTREE'
#mtree
./dev/console type=char mode=0600 uname=root gname=root device=native,5,1
MTREE

    docker export "$container" > "$out_dir/rootfs.tar"
    bsdtar --format newc --exclude .dockerenv -cf "$base.tmp" \
        @"$out_dir/rootfs.tar" @"$out_dir/dev.mtree"
    mv "$base.tmp" "$base"
}

if (( rebuild_base )) || [[ ! -f "$base" ]]; then
    build_base
fi

# K2 guest tests: static binaries from the dev image (same toolchain as
# e0-bench), owned by root in the archive.
stage="$out_dir/tests-root/opt/kjit-tests"
mkdir -p "$stage"
docker run --rm --user "$(id -u):$(id -g)" \
    -v "$ROOT_DIR/tests/guest:/src:ro" -v "$stage:/out" "$dev_image" \
    sh -euc 'for c in /src/*.c; do
                 cc -O2 -static -pthread -Wall -Werror -o "/out/$(basename "$c" .c)" "$c"
             done'
install -m 0755 "$ROOT_DIR/tests/guest/run-k2.sh" "$stage/run-k2.sh"
(cd "$out_dir/tests-root" && bsdtar --format newc --uid 0 --gid 0 --uname root --gname root \
    -cf "$tests.tmp" opt)
mv "$tests.tmp" "$tests"

cat "$base" "$tests" > "$out.tmp"
mv "$out.tmp" "$out"
echo "Guest rootfs: $out ($(du -h "$out" | cut -f1)); tests: $(ls "$stage" | tr '\n' ' ')"

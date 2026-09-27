#!/usr/bin/env bash
set -euo pipefail

# Build the kjit-guest initramfs: Debian bookworm arm64 + redis-server,
# redis-tools (redis-benchmark), busybox, kmod, with scripts/guest/init as /init,
# plus the K2/K3/K4 guest tests (tests/guest/: static binaries built in the dev
# image, and the runner scripts) in /opt/kjit-tests, plus the K4 redis layer:
# redis $REDIS_VERSION built from the official tarball with its test suite in
# /opt/redis, and tclsh8.6 to run it. Runs on the host (needs docker and
# bsdtar). The result is an uncompressed newc cpio, so the guest kernel needs
# no decompressor.
#
# rootfs.cpio = base.cpio + redis.cpio + tests.cpio (the kernel unpacks
# concatenated archives in order). base.cpio (the Debian export) and redis.cpio
# are built only when missing or with --rebuild-base / --rebuild-redis;
# tests.cpio is rebuilt every run.

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

require_cmd docker
require_cmd bsdtar

rebuild_base=0
rebuild_redis=0
for arg in "$@"; do
    case "$arg" in
        --rebuild-base) rebuild_base=1 ;;
        --rebuild-redis) rebuild_redis=1 ;;
        *) echo "Usage: $(basename "$0") [--rebuild-base] [--rebuild-redis]" >&2; exit 2 ;;
    esac
done

# The version Debian bookworm ships (redis-server 5:7.0.15-1~deb12u*), so the
# suite in /opt/redis matches the distro redis in base.cpio. The hash is the
# one published in https://github.com/redis/redis-hashes.
REDIS_VERSION=7.0.15
REDIS_SHA256=98066f5363504b26c34dd20fbcc3c957990d764cdf42576c836fc021073f4341

base_image="${KJIT_GUEST_BASE_IMAGE:-debian:bookworm}"
dev_image="${DOCKER_IMAGE:-kjit-dev:latest}"
out_dir="$KJIT_BUILD_ROOT/guest-rootfs"
base="$out_dir/base.cpio"
redis="$out_dir/redis.cpio"
tests="$out_dir/tests.cpio"
out="$out_dir/rootfs.cpio"
container="kjit-guest-rootfs-$$"

mkdir -p "$out_dir"
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf "$base.tmp" "$redis.tmp" "$tests.tmp" "$out.tmp" "$out_dir/rootfs.tar" "$out_dir/dev.mtree" \
        "$out_dir/tests-root" "$out_dir/redis-root"
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

# K4 redis layer: /opt/redis is the redis source tree reduced to what
# ./runtest needs (src/redis-* binaries, tests/ with the test modules built,
# runtest*, the sample configs), and tcl8.6 (tclsh8.6, libtcl8.6 and its
# script library; its only other dependencies, libc and zlib, are in base).
# Built in debian:bookworm, so it links against the same glibc as base.cpio.
# Upstream's default flags: like Debian's redis-server (bookworm's
# dpkg-buildflags add no -mbranch-protection), the binaries have no BTI landing
# pads and no PAC; the BTI-built code on redis's paths is glibc's.
build_redis() {
    local root="$out_dir/redis-root"
    rm -rf "$root"
    mkdir -p "$root"
    docker run --rm --platform linux/arm64 -v "$root:/out" "$base_image" sh -euc '
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            build-essential pkg-config curl ca-certificates tcl8.6
        curl -fsSL -o /tmp/redis.tar.gz "https://download.redis.io/releases/redis-$1.tar.gz"
        echo "$2  /tmp/redis.tar.gz" | sha256sum -c -
        mkdir -p /build
        tar -xzf /tmp/redis.tar.gz -C /build
        cd "/build/redis-$1"
        make -j"$(nproc)" BUILD_TLS=no
        make -j"$(nproc)" -C tests/modules
        dst=/out/opt/redis
        mkdir -p "$dst/src"
        cp src/redis-server src/redis-cli src/redis-benchmark "$dst/src/"
        # make builds these as copies of redis-server, which picks its mode
        # from the argv[0] basename; links keep one copy in the initramfs.
        for n in redis-sentinel redis-check-aof redis-check-rdb; do
            ln -s redis-server "$dst/src/$n"
        done
        cp -a tests runtest runtest-moduleapi runtest-sentinel runtest-cluster \
            redis.conf sentinel.conf "$dst/"
        find "$dst/tests" \( -name "*.o" -o -name "*.xo" \) -delete
        for p in tcl8.6 libtcl8.6; do
            dpkg -L "$p"
        done | grep -Ev "^/usr/share/(doc|man|lintian)" | while read -r f; do
            if [ -f "$f" ] || [ -L "$f" ]; then echo "$f"; fi
        done > /tmp/tcl.files
        tar -cf - --no-recursion -T /tmp/tcl.files | tar -xf - -C /out
        chmod -R a+rX /out
        "$dst/src/redis-server" --version
    ' sh "$REDIS_VERSION" "$REDIS_SHA256"
    (cd "$root" && bsdtar --format newc --uid 0 --gid 0 --uname root --gname root \
        -cf "$redis.tmp" opt usr)
    mv "$redis.tmp" "$redis"
    rm -rf "$root"
}

if (( rebuild_base )) || [[ ! -f "$base" ]]; then
    build_base
fi
if (( rebuild_redis )) || [[ ! -f "$redis" ]]; then
    build_redis
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
for script in "$ROOT_DIR"/tests/guest/*.sh; do
    install -m 0755 "$script" "$stage/$(basename "$script")"
done
(cd "$out_dir/tests-root" && bsdtar --format newc --uid 0 --gid 0 --uname root --gname root \
    -cf "$tests.tmp" opt)
mv "$tests.tmp" "$tests"

cat "$base" "$redis" "$tests" > "$out.tmp"
mv "$out.tmp" "$out"
echo "Guest rootfs: $out ($(du -h "$out" | cut -f1)); tests: $(ls "$stage" | tr '\n' ' ')"

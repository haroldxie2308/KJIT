#!/usr/bin/env bash
# Run the harness test suite on Linux arm64, including the native hardware
# oracle (`every_asm_fixture_case_matches_native`), which only compiles there.
#
# On a Linux arm64 host this runs cargo directly. Anywhere else it re-runs itself
# inside a linux/arm64 container with the repo mounted at /workspace:
#   - image: $NATIVE_TEST_IMAGE, else kjit-dev:latest if present, else
#     rust:1.85-bookworm (LLVM tools are then installed at container start);
#   - CARGO_TARGET_DIR and CARGO_HOME live under .kjit/, never the host target/.
# It fails unless the native oracle test actually ran and passed.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NATIVE_TEST_NAME="asm_fixture_tests::every_asm_fixture_case_matches_native"
FALLBACK_IMAGE="rust:1.85-bookworm"

run_suite() {
    local tool
    for tool in llvm-mc llvm-nm llvm-objcopy; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "native-test: '$tool' not found on PATH; the fixture suite needs llvm-mc, llvm-nm and llvm-objcopy" >&2
            exit 1
        fi
    done

    local log
    log="$(mktemp)"
    trap 'rm -f "$log"' RETURN
    cargo test --manifest-path "$ROOT_DIR/harness/Cargo.toml" -- --nocapture 2>&1 | tee "$log"
    if ! grep -q "^test $NATIVE_TEST_NAME \.\.\. ok$" "$log"; then
        echo "native-test: $NATIVE_TEST_NAME did not run and pass" >&2
        exit 1
    fi
}

# Debian images ship LLVM tools only under a versioned directory, and only after
# installing them.
ensure_llvm_tools_in_container() {
    if command -v llvm-mc >/dev/null 2>&1; then
        return
    fi
    if [ "$(id -u)" -ne 0 ] || ! command -v apt-get >/dev/null 2>&1; then
        echo "native-test: llvm-mc missing and cannot be installed (need root + apt-get)" >&2
        exit 1
    fi
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends llvm >/dev/null
    local llvm_bin
    llvm_bin="$(ls -d /usr/lib/llvm-*/bin 2>/dev/null | sort -V | tail -n 1)"
    if [ -z "$llvm_bin" ]; then
        echo "native-test: installed llvm but found no /usr/lib/llvm-*/bin" >&2
        exit 1
    fi
    export PATH="$llvm_bin:$PATH"
}

if [ "${1:-}" = "--in-container" ]; then
    if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "aarch64" ]; then
        echo "native-test: container is $(uname -s) $(uname -m), not Linux aarch64" >&2
        exit 1
    fi
    ensure_llvm_tools_in_container
    run_suite
    exit 0
fi

if [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "aarch64" ]; then
    run_suite
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "native-test: not on Linux arm64 and docker is unavailable; the native oracle needs Linux arm64" >&2
    exit 1
fi

image="${NATIVE_TEST_IMAGE:-}"
if [ -z "$image" ]; then
    if docker image inspect kjit-dev:latest >/dev/null 2>&1; then
        image="kjit-dev:latest"
    else
        image="$FALLBACK_IMAGE"
    fi
fi

mkdir -p "$ROOT_DIR/.kjit/docker-home" "$ROOT_DIR/.kjit/native-cargo-home" "$ROOT_DIR/.kjit/native-target"

user_args=(--user "$(id -u):$(id -g)")
if [ "$image" = "$FALLBACK_IMAGE" ]; then
    # Installing LLVM needs root; Docker Desktop maps written files back to the host user.
    user_args=()
fi

echo "native-test: running in $image (linux/arm64)" >&2
docker run --rm \
    --platform linux/arm64 \
    "${user_args[@]}" \
    -e HOME=/workspace/.kjit/docker-home \
    -e CARGO_HOME=/workspace/.kjit/native-cargo-home \
    -e CARGO_TARGET_DIR=/workspace/.kjit/native-target \
    -e KJIT_IGNORE_LOCAL_ENV=1 \
    -v "$ROOT_DIR:/workspace" \
    -w /workspace \
    "$image" \
    bash /workspace/scripts/native-test.sh --in-container

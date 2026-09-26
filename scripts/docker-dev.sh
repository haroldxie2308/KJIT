#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DOCKER_IMAGE:-kjit-dev:latest}"
CONTAINER_HOSTNAME="${DOCKER_CONTAINER_HOSTNAME:-kjit-dev-container}"
DOCKERFILE="${ROOT_DIR}/docker/dev/Dockerfile"
CONTEXT_DIR="${ROOT_DIR}/docker/dev"

build_image=0
tty_args=()
cmd=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [options] [-- command...]

Run the KJIT development environment in Docker.

Options:
  --build-image     Build or rebuild the Docker image first
  --image <name>    Override the Docker image tag (default: $IMAGE)
  --hostname <name> Override the container hostname (default: $CONTAINER_HOSTNAME)
  --no-tty          Disable interactive TTY allocation
  --help            Show this message

Examples:
  ./scripts/docker-dev.sh
  ./scripts/docker-dev.sh --build-image
  ./scripts/docker-dev.sh -- make kernel-prepare
  ./scripts/docker-dev.sh -- ./scripts/gen-rust-project.sh
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-image)
            build_image=1
            shift
            ;;
        --image)
            IMAGE="$2"
            shift 2
            ;;
        --hostname)
            CONTAINER_HOSTNAME="$2"
            shift 2
            ;;
        --no-tty)
            tty_args=()
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        --)
            shift
            cmd=("$@")
            break
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "Missing required command: docker" >&2
    exit 1
fi

if [[ -t 0 && -t 1 && ${#tty_args[@]} -eq 0 ]]; then
    tty_args=(-it)
fi

if (( build_image )) || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -t "$IMAGE" -f "$DOCKERFILE" "$CONTEXT_DIR"
fi

mkdir -p \
    "$ROOT_DIR/.kjit/docker-home"

# An out-of-repo KJIT_BUILD_ROOT is mounted at the same absolute path, so the
# kernel image paths the container writes are the paths QEMU reads on the host.
build_root_args=()
if [[ -n "${KJIT_BUILD_ROOT:-}" ]]; then
    mkdir -p "$KJIT_BUILD_ROOT"
    build_root_args=(-e "KJIT_BUILD_ROOT=$KJIT_BUILD_ROOT" -v "$KJIT_BUILD_ROOT:$KJIT_BUILD_ROOT")
fi

if [[ ${#cmd[@]} -eq 0 ]]; then
    cmd=(bash)
fi

container_cmd='cd /workspace && bash /workspace/scripts/setup-dev-editor.sh && exec "$@"'

docker run --rm \
    "${tty_args[@]}" \
    --hostname "$CONTAINER_HOSTNAME" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/workspace/.kjit/docker-home \
    -e PATH="/usr/local/cargo/bin:${PATH}" \
    -e KJIT_IGNORE_LOCAL_ENV=1 \
    -e KJIT_DEV_PROMPT="$CONTAINER_HOSTNAME" \
    -e TERM="${TERM:-xterm-256color}" \
    -e USER="${USER:-user}" \
    -e LOGNAME="${USER:-user}" \
    -w /workspace \
    -v "$ROOT_DIR:/workspace" \
    "${build_root_args[@]}" \
    "$IMAGE" \
    bash -lc "$container_cmd" bash "${cmd[@]}"

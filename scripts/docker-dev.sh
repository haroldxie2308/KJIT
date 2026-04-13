#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DOCKER_IMAGE:-kjit-dev:latest}"
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
  --no-tty          Disable interactive TTY allocation
  --help            Show this message

Examples:
  ./scripts/docker-dev.sh
  ./scripts/docker-dev.sh --build-image
  ./scripts/docker-dev.sh -- make docker-kernel-prepare
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

if [[ ${#cmd[@]} -eq 0 ]]; then
    cmd=(bash)
fi

docker run --rm \
    "${tty_args[@]}" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/workspace/.kjit/docker-home \
    -e PATH="/usr/local/cargo/bin:${PATH}" \
    -e KJIT_IGNORE_LOCAL_ENV=1 \
    -e TERM="${TERM:-xterm-256color}" \
    -e USER="${USER:-user}" \
    -e LOGNAME="${USER:-user}" \
    -w /workspace \
    -v "$ROOT_DIR:/workspace" \
    "$IMAGE" \
    bash -lc 'cd /workspace && exec "$@"' bash "${cmd[@]}"

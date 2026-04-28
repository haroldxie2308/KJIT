FROM ubuntu:24.04

ARG RUST_TOOLCHAIN=1.85.0
ARG BINDGEN_VERSION=0.71.1

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH=/usr/local/cargo/bin:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    bc \
    bison \
    build-essential \
    ca-certificates \
    clang \
    cpio \
    curl \
    device-tree-compiler \
    dwarves \
    file \
    flex \
    gdb-multiarch \
    git \
    libclang-dev \
    libelf-dev \
    libssl-dev \
    lld \
    llvm \
    make \
    neovim \
    openssh-client \
    pahole \
    perl \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    rsync \
    ripgrep \
    sudo \
    vim \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p "${CARGO_HOME}" "${RUSTUP_HOME}" \
    && curl https://sh.rustup.rs -sSf | bash -s -- -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" \
    && rustup component add rust-src clippy rustfmt rust-analyzer \
    && rustup target add aarch64-unknown-none \
    && cargo install --locked --version "${BINDGEN_VERSION}" bindgen-cli \
    && chmod -R a+rX "${CARGO_HOME}" "${RUSTUP_HOME}"

RUN git clone https://github.com/preservim/nerdtree.git /opt/kjit/nvim/site/pack/kjit/opt/nerdtree \
    && git -C /opt/kjit/nvim/site/pack/kjit/opt/nerdtree -c advice.detachedHead=false checkout 690d061b591525890f1471c6675bcb5bdc8cdff9 \
    && rm -rf /opt/kjit/nvim/site/pack/kjit/opt/nerdtree/.git

COPY nvim/init.lua /opt/kjit/nvim/init.lua

WORKDIR /workspace
CMD ["/bin/bash"]

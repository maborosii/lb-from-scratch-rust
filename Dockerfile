FROM rust:1.75-slim-bookworm as builder

ARG TARGETARCH

RUN apt-get update
RUN apt-get install --yes \
    build-essential \
    protobuf-compiler \
    pkg-config \
    llvm-16 \
    musl-tools

RUN rustup default stable
RUN rustup install nightly
RUN rustup component add rust-src --toolchain nightly
RUN --mount=type=cache,target=/root/.cargo/registry \
    cargo install bpf-linker

WORKDIR /workspace
# Docker uses the amd64/arm64 convention while Rust uses the x86_64/aarch64 convention.
# Since Dockerfile doesn't support conditional variables (sigh), write the arch in Rust's
# convention to a file for later usage.
RUN if [ "$TARGETARCH" = "amd64" ]; \
    then echo "x86_64" >> arch; \
    else echo "aarch64" >> arch; \
    fi
RUN rustup target add $(eval cat arch)-unknown-linux-musl

COPY . . 
# COPY tools/udp-test-server tools/udp-test-server
# COPY xtask xtask
# COPY Cargo.toml Cargo.toml
# COPY .cargo .cargo

# We need to tell bpf-linker where it can find LLVM's shared library file.
# Ref: https://github.com/aya-rs/rustc-llvm-proxy/blob/cbcb3c6/src/lib.rs#L48
ENV LD_LIBRARY_PATH="/usr/lib/llvm-16/lib"
RUN mkdir app
RUN --mount=type=cache,target=/workspace/target/ \
    --mount=type=cache,target=/root/.cargo/registry \
    cargo xtask build-ebpf --release
RUN --mount=type=cache,target=/workspace/target/ \
    --mount=type=cache,target=/root/.cargo/registry \
    RUSTFLAGS=-Ctarget-feature=+crt-static cargo build \
    --workspace \
    --exclude ebpf \ 
    --release \
    --target=$(eval cat arch)-unknown-linux-musl
RUN --mount=type=cache,target=/workspace/target/ \
    cp /workspace/target/$(eval cat arch)-unknown-linux-musl/release/lb-from-scratch-rust /workspace/app/lb-from-scratch-rust

FROM alpine

WORKDIR /opt/app/

ENV RUST_LOG="info"

COPY --from=builder /workspace/app/lb-from-scratch-rust /opt/app/lb-from-scratch-rust

ENTRYPOINT ["/opt/app/lb-from-scratch-rust"]
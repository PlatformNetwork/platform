# =============================================================================
# Platform Network - Validator Docker Image
# =============================================================================
# Fully decentralized P2P architecture
#
# Build:
#   docker build -t platform:latest .
# =============================================================================

# Build stage
FROM rust:1.92-bookworm AS builder

ARG PLATFORM_NIGHTLY_RUSTFLAGS=""
ARG PLATFORM_LINKER_RUSTFLAGS=""
ARG INSTALL_FAST_LINKER=auto
ENV PLATFORM_NIGHTLY_RUSTFLAGS=${PLATFORM_NIGHTLY_RUSTFLAGS}
ENV PLATFORM_LINKER_RUSTFLAGS=${PLATFORM_LINKER_RUSTFLAGS}
ENV INSTALL_FAST_LINKER=${INSTALL_FAST_LINKER}

# Install dependencies
RUN apt-get update \
    && apt-get install -y \
        pkg-config \
        libssl-dev \
        protobuf-compiler \
        cmake \
        clang \
        libclang-dev \
        lld \
    && if [ "$INSTALL_FAST_LINKER" = "mold" ]; then \
        apt-get install -y mold; \
    fi \
    && rm -rf /var/lib/apt/lists/*

# Set up cargo-chef for caching
RUN cargo install cargo-chef --locked

WORKDIR /app

# Prepare recipe for caching dependencies
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Cache dependencies
FROM rust:1.92-bookworm AS cacher

ARG PLATFORM_NIGHTLY_RUSTFLAGS=""
ARG PLATFORM_LINKER_RUSTFLAGS=""
ARG INSTALL_FAST_LINKER=auto
ENV PLATFORM_NIGHTLY_RUSTFLAGS=${PLATFORM_NIGHTLY_RUSTFLAGS}
ENV PLATFORM_LINKER_RUSTFLAGS=${PLATFORM_LINKER_RUSTFLAGS}
ENV INSTALL_FAST_LINKER=${INSTALL_FAST_LINKER}
RUN apt-get update \
    && apt-get install -y \
        pkg-config \
        libssl-dev \
        protobuf-compiler \
        cmake \
        clang \
        libclang-dev \
        lld \
    && if [ "$INSTALL_FAST_LINKER" = "mold" ]; then \
        apt-get install -y mold; \
    fi \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app
COPY --from=builder /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build stage
FROM rust:1.92-bookworm AS final-builder

ARG PLATFORM_NIGHTLY_RUSTFLAGS=""
ARG PLATFORM_LINKER_RUSTFLAGS=""
ARG INSTALL_FAST_LINKER=auto
ENV PLATFORM_NIGHTLY_RUSTFLAGS=${PLATFORM_NIGHTLY_RUSTFLAGS}
ENV PLATFORM_LINKER_RUSTFLAGS=${PLATFORM_LINKER_RUSTFLAGS}
ENV INSTALL_FAST_LINKER=${INSTALL_FAST_LINKER}
RUN apt-get update \
    && apt-get install -y \
        pkg-config \
        libssl-dev \
        protobuf-compiler \
        cmake \
        clang \
        libclang-dev \
        lld \
    && if [ "$INSTALL_FAST_LINKER" = "mold" ]; then \
        apt-get install -y mold; \
    fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
COPY . .

# Build the validator
RUN cargo build --release -p validator-node

# Runtime stage (Ubuntu 24.04 for glibc 2.39 compatibility)
FROM ubuntu:24.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3t64 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=final-builder /app/target/release/validator-node /usr/local/bin/validator-node

# Create data directory with restricted permissions
# Note: Using 755 instead of 777 for security; the container runs as root by default
RUN mkdir -p /data && chmod 755 /data

# Environment defaults
ENV RUST_LOG=info,validator_node=debug,platform_p2p_consensus=info
ENV DATA_DIR=/data
ENV SUBTENSOR_ENDPOINT=wss://entrypoint-finney.opentensor.ai:443
ENV NETUID=100

# Expose P2P port
EXPOSE 9000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD test -e /data/distributed.db || exit 1

# Default entrypoint
ENTRYPOINT ["validator-node"]
CMD ["--data-dir", "/data", "--listen-addr", "/ip4/0.0.0.0/tcp/9000"]

# Labels
LABEL org.opencontainers.image.source="https://github.com/PlatformNetwork/platform"
LABEL org.opencontainers.image.description="Platform Validator Node - Decentralized P2P"
LABEL org.opencontainers.image.licenses="Apache-2.0"

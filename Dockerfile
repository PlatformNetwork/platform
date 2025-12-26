# =============================================================================
# Platform Network - Unified Docker Image
# =============================================================================
# Single image that can run as either server or validator mode:
#   docker run platform server [OPTIONS]
#   docker run platform validator --secret-key <KEY> [OPTIONS]
# =============================================================================

# Build stage
FROM rust:1.82-bookworm AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Set up cargo-chef for caching
RUN cargo install cargo-chef --locked

WORKDIR /app

# Prepare recipe for caching dependencies
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Cache dependencies
FROM rust:1.82-bookworm AS cacher
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    cmake \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app
COPY --from=builder /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build stage
FROM rust:1.82-bookworm AS final-builder
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
COPY . .

# Build all binaries
RUN cargo build --release -p platform -p validator-node -p csudo

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries
COPY --from=final-builder /app/target/release/platform /usr/local/bin/platform
COPY --from=final-builder /app/target/release/validator-node /usr/local/bin/validator-node
COPY --from=final-builder /app/target/release/csudo /usr/local/bin/csudo

# Create data directory
RUN mkdir -p /data && chmod 777 /data

# Default: run validator-node (reads VALIDATOR_SECRET_KEY from env)
# Validators can use their existing docker-compose without changes
ENTRYPOINT ["validator-node"]
CMD ["--data-dir", "/data", "--platform-server", "https://chain.platform.network"]

# Labels
LABEL org.opencontainers.image.source="https://github.com/PlatformNetwork/platform"
LABEL org.opencontainers.image.description="Platform Network - Unified Server/Validator"
LABEL org.opencontainers.image.licenses="Apache-2.0"

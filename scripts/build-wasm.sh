#!/bin/bash
set -e

# Ensure wasm32 target is installed
rustup target add wasm32-unknown-unknown 2>/dev/null || true

COMPILED_DIR="challenges/compiled"

# ---------------------------------------------------------------------------
# Build a challenge crate when a package name is supplied, otherwise build
# all challenge crates found under challenges/*/.
# ---------------------------------------------------------------------------

build_challenge() {
    local CRATE="$1"
    echo "Building challenge crate: $CRATE ..."

    cargo build --release --target wasm32-unknown-unknown \
        -p "$CRATE" \
        --no-default-features

    # Derive the expected artefact name (hyphens become underscores)
    ARTIFACT_NAME=$(echo "$CRATE" | tr '-' '_')
    WASM_PATH="target/wasm32-unknown-unknown/release/${ARTIFACT_NAME}.wasm"

    if [ ! -f "$WASM_PATH" ]; then
        echo "ERROR: WASM build failed — expected $WASM_PATH"
        return 1
    fi

    SIZE=$(du -h "$WASM_PATH" | cut -f1)
    echo "WASM built successfully: $WASM_PATH ($SIZE)"

    # Strip debug info if wasm-strip is available
    if command -v wasm-strip &> /dev/null; then
        echo "Stripping WASM with wasm-strip..."
        wasm-strip "$WASM_PATH"
        STRIP_SIZE=$(du -h "$WASM_PATH" | cut -f1)
        echo "Stripped WASM: $WASM_PATH ($STRIP_SIZE)"
    fi

    # Optimize with wasm-opt if available
    if command -v wasm-opt &> /dev/null; then
        echo "Optimizing WASM with wasm-opt..."
        wasm-opt -Oz -o "${WASM_PATH%.wasm}_optimized.wasm" "$WASM_PATH"
        OPT_SIZE=$(du -h "${WASM_PATH%.wasm}_optimized.wasm" | cut -f1)
        echo "Optimized WASM: ${WASM_PATH%.wasm}_optimized.wasm ($OPT_SIZE)"
    else
        echo "wasm-opt not found. Install with: cargo install wasm-opt"
    fi

    # Copy to compiled output directory
    mkdir -p "$COMPILED_DIR"
    cp "$WASM_PATH" "$COMPILED_DIR/${ARTIFACT_NAME}.wasm"
    echo "Copied to $COMPILED_DIR/${ARTIFACT_NAME}.wasm"

    # Compute and print SHA256 hash
    if command -v sha256sum &> /dev/null; then
        HASH=$(sha256sum "$COMPILED_DIR/${ARTIFACT_NAME}.wasm" | cut -d' ' -f1)
    elif command -v shasum &> /dev/null; then
        HASH=$(shasum -a 256 "$COMPILED_DIR/${ARTIFACT_NAME}.wasm" | cut -d' ' -f1)
    else
        HASH="(sha256sum not available)"
    fi
    echo "SHA256: $HASH"
    echo ""
}

if [ -n "$1" ]; then
    build_challenge "$1"
else
    # Build term-challenge-wasm if it exists as a workspace member
    if cargo metadata --no-deps --format-version 1 2>/dev/null | grep -q '"name":"term-challenge-wasm"'; then
        build_challenge "term-challenge-wasm"
    fi

    # Build any challenge crates found under challenges/*/
    for dir in challenges/*/; do
        if [ -f "${dir}Cargo.toml" ]; then
            CRATE_NAME=$(grep '^name' "${dir}Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
            if [ -n "$CRATE_NAME" ]; then
                build_challenge "$CRATE_NAME"
            fi
        fi
    done

    # Fallback: build chain-runtime WASM if no challenges were found
    if [ ! -d "$COMPILED_DIR" ] || [ -z "$(ls -A "$COMPILED_DIR" 2>/dev/null)" ]; then
        echo "No challenge crates found. Building chain-runtime WASM..."

        cargo build --release --target wasm32-unknown-unknown \
            -p mini-chain-chain-runtime \
            --no-default-features

        WASM_PATH="target/wasm32-unknown-unknown/release/platform_chain_chain_runtime.wasm"

        if [ -f "$WASM_PATH" ]; then
            SIZE=$(du -h "$WASM_PATH" | cut -f1)
            echo "WASM built successfully: $WASM_PATH ($SIZE)"

            if command -v wasm-opt &> /dev/null; then
                echo "Optimizing WASM with wasm-opt..."
                wasm-opt -Oz -o "${WASM_PATH%.wasm}_optimized.wasm" "$WASM_PATH"
                OPT_SIZE=$(du -h "${WASM_PATH%.wasm}_optimized.wasm" | cut -f1)
                echo "Optimized WASM: ${WASM_PATH%.wasm}_optimized.wasm ($OPT_SIZE)"
            else
                echo "wasm-opt not found. Install with: cargo install wasm-opt"
            fi
        else
            echo "ERROR: WASM build failed"
            exit 1
        fi
    fi
fi

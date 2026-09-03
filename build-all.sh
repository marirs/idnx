#!/usr/bin/env bash
set -euo pipefail

# 1. Ensure required tools are installed
echo "Checking dependencies..."
for cmd in zig cargo-zigbuild rustup cargo; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed." >&2
        exit 1
    fi
done

# 2. Get the binary name from Cargo.toml automatically
BINARY_NAME=$(cargo metadata --no-deps --format-version 1 | grep -o '"name":"[^"]*' | head -n 1 | cut -d'"' -f4)
DIST_DIR="$(pwd)/dist"

echo "Package detected: $BINARY_NAME"
echo "Output directory: $DIST_DIR"

# Clean and recreate the dist folder
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# 3. Define target matrices
TARGETS=(
    "x86_64-unknown-linux-gnu.2.17"
    "aarch64-unknown-linux-gnu.2.17"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
    "x86_64-pc-windows-gnu"
    "aarch64-pc-windows-gnu"
)

# 4. Download missing Rust standard libraries
echo "Ensuring Rust targets are installed..."
for target in "${TARGETS[@]}"; do
    rust_target="${target%%.*}" 
    rustup target add "$rust_target" > /dev/null 2>&1
done

# 5. Compile and Copy to dist/
echo "Starting cross-compilation matrix..."
for target in "${TARGETS[@]}"; do
    echo "--------------------------------------------------"
    echo "🔨 Building for target: $target"
    echo "--------------------------------------------------"
    
    cargo zigbuild --release --target "$target"

    # Strip glibc version suffix to locate the cargo output folder
    rust_target="${target%%.*}"
    
    # Determine the binary source path and set a clean destination name
    if [[ "$rust_target" == *"windows"* ]]; then
        SRC_PATH="target/$rust_target/release/${BINARY_NAME}.exe"
        DEST_PATH="$DIST_DIR/${BINARY_NAME}-${rust_target}.exe"
    else
        SRC_PATH="target/$rust_target/release/${BINARY_NAME}"
        DEST_PATH="$DIST_DIR/${BINARY_NAME}-${rust_target}"
    fi

    # Copy the file to the dist/ folder
    if [ -f "$SRC_PATH" ]; then
        cp "$SRC_PATH" "$DEST_PATH"
        echo "💾 Saved to: $DEST_PATH"
    else
        echo "❌ Error: Could not find compiled binary at $SRC_PATH" >&2
    fi
done

echo "--------------------------------------------------"
echo "✅ All builds complete! Check the 'dist/' folder:"
ls -lh "$DIST_DIR"


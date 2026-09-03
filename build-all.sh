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

# 3. Parse Command-Line Arguments
BUILD_LINUX=false
BUILD_MAC=false
BUILD_WIN=false
BUILD_X86=false
BUILD_AARCH64=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --linux)   BUILD_LINUX=true ;;
        --mac)     BUILD_MAC=true ;;
        --win)     BUILD_WIN=true ;;
        --x86)     BUILD_X86=true ;;
        --aarch64) BUILD_AARCH64=true ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [--linux] [--mac] [--win] [--x86] [--aarch64]" >&2
            exit 1
            ;;
    esac
    shift
done

# If no OS specified, default to ALL operating systems
if [ "$BUILD_LINUX" = false ] && [ "$BUILD_MAC" = false ] && [ "$BUILD_WIN" = false ]; then
    BUILD_LINUX=true; BUILD_MAC=true; BUILD_WIN=true
fi

# If no Architecture specified, default to ALL architectures
if [ "$BUILD_X86" = false ] && [ "$BUILD_AARCH64" = false ]; then
    BUILD_X86=true; BUILD_AARCH64=true
fi

# 4. Construct the Target Matrix Dynamically
TARGETS=()
if [ "$BUILD_LINUX" = true ]; then
    [ "$BUILD_X86" = true ]     && TARGETS+=("x86_64-unknown-linux-gnu.2.17")
    [ "$BUILD_AARCH64" = true ] && TARGETS+=("aarch64-unknown-linux-gnu.2.17")
fi
if [ "$BUILD_MAC" = true ]; then
    [ "$BUILD_X86" = true ]     && TARGETS+=("x86_64-apple-darwin")
    [ "$BUILD_AARCH64" = true ] && TARGETS+=("aarch64-apple-darwin")
fi
if [ "$BUILD_WIN" = true ]; then
    [ "$BUILD_X86" = true ]     && TARGETS+=("x86_64-pc-windows-gnu")
    [ "$BUILD_AARCH64" = true ] && TARGETS+=("aarch64-pc-windows-msvc")
fi

echo "Package detected: $BINARY_NAME"
echo "Output directory: $DIST_DIR"

# Clean and recreate the dist folder
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# 5. Download missing Rust standard libraries safely
echo "Ensuring Rust targets are installed..."
for target in "${TARGETS[@]}"; do
    rust_target="${target%%.*}" 
    
    if ! rustup target list | grep -q "$rust_target (installed)"; then
        echo "📥 Installing target: $rust_target..."
        rustup target add "$rust_target"
    fi
done

# 6. Compile and Copy to dist/
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
echo "✅ Filtered builds complete! Check the 'dist/' folder:"
ls -lh "$DIST_DIR"


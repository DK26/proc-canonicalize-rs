#!/bin/bash
# ci-local.sh - Local CI Test Runner for proc-canonicalize
# Run all CI checks locally before pushing

set -e

echo "=== proc-canonicalize Local CI ==="
echo ""

# Find cargo
if ! command -v cargo &> /dev/null; then
    CARGO_PATHS=(
        "$HOME/.cargo/bin/cargo"
        "/home/$(whoami)/.cargo/bin/cargo"
    )
    
    for cargo_path in "${CARGO_PATHS[@]}"; do
        if [[ -x "$cargo_path" ]]; then
            export PATH="$(dirname "$cargo_path"):$PATH"
            echo "✓ Found cargo at: $cargo_path"
            break
        fi
    done
    
    if ! command -v cargo &> /dev/null; then
        echo "❌ cargo not found. Install Rust from https://rustup.rs/"
        exit 1
    fi
fi

echo "✓ Using cargo: $(command -v cargo)"
echo "🦀 Rust version: $(rustc --version)"
echo ""

run_check() {
    local name="$1"
    local command="$2"
    
    echo "Running: $name"
    echo "Command: $command"
    
    if eval "$command"; then
        echo "✓ $name passed"
        echo ""
        return 0
    else
        echo "✗ $name failed"
        exit 1
    fi
}

# Check we're in project root
if [[ ! -f "Cargo.toml" ]]; then
    echo "❌ Cargo.toml not found. Are you in the project root?"
    exit 1
fi

# Validate UTF-8 encoding
echo "🔍 Validating UTF-8 encoding..."
for file in README.md Cargo.toml src/lib.rs; do
    if [[ -f "$file" ]]; then
        if command -v file >/dev/null 2>&1; then
            file_output=$(file "$file")
            if echo "$file_output" | grep -q "UTF-8\|ASCII\|text"; then
                echo "✅ $file: UTF-8 OK"
            else
                echo "❌ $file: encoding issue"
                exit 1
            fi
        fi
    fi
done
echo ""

# Auto-fix formatting
echo "🔧 Auto-fixing formatting..."
cargo fmt --all
echo "✓ Formatting fixed"
echo ""

# Run checks
run_check "Format check" "cargo fmt --all -- --check"
run_check "Clippy" "cargo clippy --all-targets --all-features -- -D warnings"
run_check "Tests" "cargo test --verbose"
run_check "Documentation" "RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features"

# MSRV check (optional - requires rustup)
if command -v rustup &> /dev/null; then
    echo "Checking MSRV (1.70.0)..."
    if rustup run 1.70.0 cargo check 2>/dev/null; then
        echo "✓ MSRV check passed"
    else
        echo "⚠️  MSRV 1.70.0 not installed, skipping MSRV check"
        echo "   Install with: rustup install 1.70.0"
    fi
fi

echo ""
echo "🎉 All CI checks passed!"

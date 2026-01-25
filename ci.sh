#!/usr/bin/env bash
set -euo pipefail

echo "==> fmt"
cargo fmt --check

echo "==> clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> test (all features)"
cargo test --workspace --all-features

echo "==> test (no features)"
cargo test --workspace

echo "==> doc"
cargo doc --workspace --all-features --no-deps

if command -v cargo-deny >/dev/null 2>&1; then
    echo "==> deny"
    cargo deny check
else
    echo "warn: cargo-deny not found, skipping"
fi

if command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "==> coverage"
    cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info --fail-under-lines 80
else
    echo "warn: cargo-llvm-cov not found, skipping"
fi

#!/bin/bash

echo "# cargo check"
cargo check
echo "# cargo build"
cargo build
cargo build --release --features allow-empty-seeds
echo "# cargo clippy --workspace --all-targets"
cargo clippy --workspace --all-targets
echo "# cargo test"
cargo test -- --test-threads=1 


# PS C:\Users\you\Documents\projects\veil> $env:LIBCLANG_PATH="C:\Program Files\LLVM\bin"
# PS C:\Users\you\Documents\projects\veil> cargo build --release --features allow-empty-seeds


# cargo install cargo-nextest --locked

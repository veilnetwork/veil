use std::{env, fs, path::PathBuf};

fn main() {
    let package =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo manifest directory"));
    let source = package.join("../../src/lib.rs");
    println!("cargo:rerun-if-changed={}", source.display());
    let text = fs::read_to_string(&source).expect("read production FFI source");
    let start = text
        .find("#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn veil_free_string(")
        .expect("production string destructor marker");
    let tail = &text[start..];
    let end = tail
        .find("\n/// Connect to an veil daemon")
        .expect("production string destructor end marker");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("cargo output directory"));
    // Preserve the canonical body exactly; a changed dependency on other SDK
    // state fails this fixture's compilation instead of substituting a stub.
    let docs = "/// # Safety\n/// The pointer must be NULL or an owned string from this fixture.\n";
    fs::write(
        output.join("ffi_memory.rs"),
        format!("{docs}{}", &tail[..end]),
    )
    .expect("write extracted FFI destructor");
}

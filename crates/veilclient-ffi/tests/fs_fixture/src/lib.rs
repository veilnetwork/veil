//! FS-only test fixture compiled from the exact production modules.
//!
//! No SDK version/ABI marker is exported: this library cannot be accepted as
//! veilclient-ffi by the production ABI gate. Tests pass its handle explicitly
//! to the FS bindings. It is never a node, media engine, or release dependency.

use std::ffi::{CString, c_char};

#[path = "../../../src/fs_beneath.rs"]
mod fs_beneath;

// The production error-string destructor, extracted by build.rs rather than
// reimplemented. Errors and allocations belong to the same Rust allocator.
include!(concat!(env!("OUT_DIR"), "/ffi_memory.rs"));

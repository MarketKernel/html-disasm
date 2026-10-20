//! The disassembler's core: decoders and analysis, with no I/O and no host.
//!
//! Nothing here knows where it runs. The page loads it as WebAssembly
//! (crates/wasm), a desktop program can link it natively; both hand it the
//! bytes of a file and read back plain arrays.

pub mod arm32;
pub mod arm64;
pub mod bundle;
pub mod cil;
pub mod demangle;
pub mod disassembly;
pub mod elf;
pub mod image;
pub mod jvm;
pub mod lift;
pub mod macho;
pub mod native;
pub mod objc;
pub mod pe;
pub mod plist;
pub mod refs;
pub mod sha;
pub mod sign;
pub mod text;
pub mod wasm;
pub mod x86;
pub mod zip;

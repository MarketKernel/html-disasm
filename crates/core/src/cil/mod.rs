//! .NET: the metadata of an assembly, the names and signatures as ildasm
//! writes them, the CIL decoder, the analysis of a whole assembly, and what the
//! page shows of it. A port of src/core/cil/ (metadata, names, opcodes, decode,
//! effects, program) and of what src/app/cil.ts read from the metadata.

pub mod decode;
pub mod hla;
pub mod metadata;
pub mod names;
pub mod opcodes;
pub mod page;
pub mod program;

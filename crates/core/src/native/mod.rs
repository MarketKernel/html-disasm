//! Native programs — Mach-O, ELF and PE files of arm64, x86 and 32-bit Arm —
//! read and analysed in the core: the image (`image`), and what the analyses
//! find around their pass over the instructions — the functions and their
//! names, the stubs, the strings (`functions`, and one module per architecture).

pub mod arm32;
pub mod arm64;
pub mod functions;
pub mod image;
pub mod x86;

use functions::Function;

/// A string the analysis found: its address, text, section, and whether a NUL ends it.
#[derive(Clone, Debug, PartialEq)]
pub struct FoundString {
    pub addr: f64,
    pub text: String,
    pub section: String,
    pub cstring: bool,
}

/// What the analysis after a pass found: the functions, every string, and the stubs it named
/// (which the page adds to its image).
pub struct Found {
    pub functions: Vec<Function>,
    pub strings: Vec<FoundString>,
    pub stubs: Vec<(f64, String)>,
}

use crate::macho::parse_macho;
use image::{NativeImage, PeView};

/// The container of a file, as the page found it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Container {
    /// A Mach-O file (a thin one: the page hands over the slice it opened).
    MachO,
    Elf,
    /// A PE file, and which code of a hybrid one.
    Pe(PeView),
}

/// Reads a file into an image; None when it cannot be read (the page read it first, so that does not happen).
pub fn open_image(file: Vec<u8>, container: Container) -> Option<NativeImage> {
    match container {
        Container::MachO => {
            let m = parse_macho(&file, None).ok()?;
            let slice = file[m.slice.0..m.slice.1].to_vec();
            Some(NativeImage::from_macho(m, slice))
        }
        Container::Elf => {
            let e = crate::elf::parse_elf(&file).ok()?;
            Some(NativeImage::from_elf(e, file))
        }
        Container::Pe(view) => {
            let p = crate::pe::parse_pe(&file, false).ok()?;
            Some(NativeImage::from_pe(p, file, view))
        }
    }
}

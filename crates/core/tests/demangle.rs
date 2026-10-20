//! Demangling, against what LLVM's llvm-cxxfilt prints for the same names:
//! Rust v0 symbols from a real program (generics, impls, closures, constants,
//! dyn traits with for<'a> binders, back-references), legacy Rust and C++.
//! Swift against what `swift-demangle` prints, in full and simplified:
//! tests/fixtures/swift-vectors.json (made by tools/verify-swift.mjs from the
//! standard library and SDK frameworks) and the sample framework's own names.
//! MSVC against what LLVM's llvm-undname prints: tests/fixtures/msvc-vectors.json
//! (made by tools/verify-msvc.mjs from LLVM's own tests of its demangler).

use disasm_core::demangle::{demangle, demangle_unprefixed, fold_generics, Language};
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<(String, String, String)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
}

#[test]
fn rust_v0() {
    const RUST: [(&str, &str); 7] = [
        (
            "__RINvMNtCs6D2FZ4ex4jG_9zune_jpeg9bitstreamNtB3_9BitStream16decode_mcu_blockINtNtNtNtCs1H3kjH8UrL8_9zune_core10bytestream6reader14no_std_readers7ZCursorINtNtCs6zY7rJBZy9D_5alloc3vec3VechEEECseXIkZAZvM1D_5image",
            "<zune_jpeg::bitstream::BitStream>::decode_mcu_block::<zune_core::bytestream::reader::no_std_readers::ZCursor<alloc::vec::Vec<u8>>>",
        ),
        ("__RINvMNtCsjIpoRzUjyHQ_4core3stre18trim_start_matchesReECs6thXTpflXIc_14rustc_demangle", "<str>::trim_start_matches::<&str>"),
        (
            "__RINvNtNtNtCsjIpoRzUjyHQ_4core5slice4sort6stable14driftsort_mainNtNtNtCsiu75YnjbALX_10wgpu_types7texture6format13TextureFormatNCINvMNtCs6zY7rJBZy9D_5alloc5sliceSBZ_11sort_by_keybNCNCNvMNtNtCshX3eSjzW1Ue_9wgpu_core6device6globalNtNtB30_6global6Global24surface_get_capabilities00E0INtNtB27_3vec3VecBZ_EEB30_",
            "core::slice::sort::stable::driftsort_main::<wgpu_types::texture::format::TextureFormat, <[wgpu_types::texture::format::TextureFormat]>::sort_by_key<bool, <wgpu_core::global::Global>::surface_get_capabilities::{closure#0}::{closure#0}>::{closure#0}, alloc::vec::Vec<wgpu_types::texture::format::TextureFormat>>",
        ),
        (
            "__RNvNCNKNvNtCsjJlYt0P5xFO_4egui7context27IMMEDIATE_VIEWPORT_RENDERER0023___RUST_STD_INTERNAL_VAL",
            "egui::context::IMMEDIATE_VIEWPORT_RENDERER::{K#0}::{closure#0}::__RUST_STD_INTERNAL_VAL",
        ),
        (
            "__RNvNCNKNvNtNtNtCsjemAGIzwWSp_14regex_automata4util4pool5inner9THREAD_ID0s_023___RUST_STD_INTERNAL_VAL",
            "regex_automata::util::pool::inner::THREAD_ID::{K#0}::{closure#1}::__RUST_STD_INTERNAL_VAL",
        ),
        (
            "__RNvMsn_NtCs6zY7rJBZy9D_5alloc4syncINtB5_3ArcDG1_INtNtNtCsjIpoRzUjyHQ_4core3ops8function2FnTRL2_SNtNtNtCsU4UewP5b0C_4wgpu3api7adapter7AdapterINtNtBR_6option6OptionRL1_INtNtB1A_7surface7SurfaceL0_EEEEp6OutputINtNtBR_6result6ResultB1w_NtNtB7_6string6StringENtNtBR_6marker4SendNtB46_4SyncEL_E9drop_slowCsin6olpeIaud_9egui_wgpu",
            "<alloc::sync::Arc<dyn for<'a, 'b, 'c> core::ops::function::Fn<(&'a [wgpu::api::adapter::Adapter], core::option::Option<&'b wgpu::api::surface::Surface<'c>>), Output = core::result::Result<wgpu::api::adapter::Adapter, alloc::string::String>> + core::marker::Send + core::marker::Sync>>::drop_slow",
        ),
        (
            "__RNvMsn_NtCs6zY7rJBZy9D_5alloc4syncINtB5_3ArcDG_INtNtNtCsjIpoRzUjyHQ_4core3ops8function2FnTQL0_NtNtCsjJlYt0P5xFO_4egui2ui2UiEEp6OutputuNtNtBQ_6marker4SendNtB2a_4SyncEL_E9drop_slowB1y_",
            "<alloc::sync::Arc<dyn for<'a> core::ops::function::Fn<(&'a mut egui::ui::Ui,), Output = ()> + core::marker::Send + core::marker::Sync>>::drop_slow",
        ),
    ];
    for (mangled, expected) in RUST {
        let d = demangle(mangled);
        assert_eq!((d.full.as_str(), d.language), (expected, Language::Rust), "{mangled}");
    }
}

#[test]
fn rust_legacy_cpp_and_c() {
    assert_eq!(demangle("__ZN4core3fmt9Formatter3pad17h0123456789abcdefE").full, "core::fmt::Formatter::pad");
    assert_eq!(
        demangle("__ZN70_$LT$alloc..vec..Vec$LT$T$C$A$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h0123456789abcdefE").full,
        "<alloc::vec::Vec<T,A> as core::ops::drop::Drop>::drop"
    );
    assert_eq!(demangle("__ZN3foo3barEv").full, "foo::bar()");
    assert_eq!(demangle("__ZN3foo3bazEi").full, "foo::baz(…)");
    let c = demangle("_main");
    assert_eq!((c.full.as_str(), c.language), ("main", Language::C));
    assert_eq!(c.language.as_str(), "c");
    assert_eq!(demangle("radr://5614542").full, "radr://5614542");
    // A broken v0 name stays as it was.
    assert_eq!(demangle("__RNvC").full, "__RNvC");
    assert_eq!(fold_generics("<alloc::sync::Arc<dyn Fn<(&u8,)>>>::drop_slow"), "<alloc::sync::Arc<…>>::drop_slow");
    assert_eq!(fold_generics("core::ptr::drop_in_place::<alloc::vec::Vec<u8>>"), "core::ptr::drop_in_place::<alloc::vec::Vec<…>>");
}

#[test]
fn swift_vectors() {
    let vectors = fixture("swift-vectors.json");
    let wrong: Vec<_> = vectors
        .iter()
        .filter(|(symbol, full, short)| {
            let d = demangle(symbol);
            d.full != *full || d.short != *short || d.language != Language::Swift
        })
        .take(3)
        .map(|(symbol, full, _)| (symbol.clone(), full.clone(), demangle(symbol).full))
        .collect();
    assert!(wrong.is_empty(), "swift: {} vectors, wrong: {wrong:#?}", vectors.len());
}

#[test]
fn swift_sample_framework() {
    const HELLOKIT: [(&str, &str, &str); 4] = [
        ("_$s8HelloKit05helloB6AnsweryS2iF", "HelloKit.helloKitAnswer(Swift.Int) -> Swift.Int", "helloKitAnswer(_:)"),
        ("_$s8HelloKit7CounterC9increment2byS2i_tF", "HelloKit.Counter.increment(by: Swift.Int) -> Swift.Int", "Counter.increment(by:)"),
        ("_$s8HelloKit7CounterC5countSivpACTK", "key path getter for HelloKit.Counter.count : Swift.Int : HelloKit.Counter", "key path getter for Counter.count : Counter"),
        (
            "_$s8HelloKit6CircleVAA5ShapeA2aDP4areaSdyFTW",
            "protocol witness for HelloKit.Shape.area() -> Swift.Double in conformance HelloKit.Circle : HelloKit.Shape in HelloKit",
            "protocol witness for Shape.area() in conformance Circle",
        ),
    ];
    for (symbol, full, short) in HELLOKIT {
        let d = demangle(symbol);
        assert_eq!((d.full.as_str(), d.short.as_str()), (full, short), "{symbol}");
    }
    // Swift in ELF, without the leading underscore.
    assert_eq!(demangle_unprefixed("$s8HelloKit7CounterC9increment2byS2i_tF").short, "Counter.increment(by:)");
    // A word substitution (05hello + B = helloKit).
    assert!(demangle("_$s8HelloKit05helloB6AnsweryS2iF").full.starts_with("HelloKit.helloKitAnswer"));
    let broken = demangle("_$s8HelloKit7CounterC9incr");
    assert_eq!((broken.full.as_str(), broken.language), ("_$s8HelloKit7CounterC9incr", Language::Swift));
    // An unknown accessor stays as it was.
    assert_eq!(demangle("_$s8HelloKit7CounterC5countSivZ").full, "_$s8HelloKit7CounterC5countSivZ");
}

#[test]
fn msvc_vectors() {
    let vectors = fixture("msvc-vectors.json");
    let wrong: Vec<_> = vectors
        .iter()
        .filter(|(symbol, full, short)| {
            let d = demangle_unprefixed(symbol);
            d.full != *full || d.short != *short
        })
        .take(3)
        .map(|(symbol, full, _)| (symbol.clone(), full.clone(), demangle_unprefixed(symbol).full))
        .collect();
    assert!(wrong.is_empty(), "msvc: {} vectors, wrong: {wrong:#?}", vectors.len());
}

#[test]
fn msvc_names() {
    let member = demangle_unprefixed("?length@Point@geo@@UEBAHXZ");
    assert_eq!((member.full.as_str(), member.short.as_str()), ("public: virtual int __cdecl geo::Point::length(void) const", "geo::Point::length()"));
    // Template arguments fold in the short name, operators stay.
    assert_eq!(demangle_unprefixed("??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_K@Z").short, "std::basic_ostream<char, std::char_traits<…>>::operator<<(…)");
    assert_eq!(demangle_unprefixed("?f@@YAXXZ").language.as_str(), "c++");
    // A broken name stays as it was.
    assert_eq!(demangle_unprefixed("?f@@YAX").full, "?f@@YAX");
}

/**
 * Demangling through the core (crates/core/src/demangle/, whose own tests in
 * crates/core/tests/demangle.rs check the same and more), against what LLVM's llvm-cxxfilt prints for the same names:
 * Rust v0 symbols from a real program (generics, impls, closures, constants,
 * dyn traits with for<'a> binders, back-references), legacy Rust and C++.
 * Swift against what `swift-demangle` prints, in full and simplified:
 * tests/fixtures/swift-vectors.json (made by tools/verify-swift.mjs from the
 * standard library and SDK frameworks) and the sample framework's own names.
 * MSVC against what LLVM's llvm-undname prints: tests/fixtures/msvc-vectors.json
 * (made by tools/verify-msvc.mjs from LLVM's own tests of its demangler).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const { demangle, demangleAll, demangleUnprefixed } = await load('core/demangle');

const RUST = [
  ['__RINvMNtCs6D2FZ4ex4jG_9zune_jpeg9bitstreamNtB3_9BitStream16decode_mcu_blockINtNtNtNtCs1H3kjH8UrL8_9zune_core10bytestream6reader14no_std_readers7ZCursorINtNtCs6zY7rJBZy9D_5alloc3vec3VechEEECseXIkZAZvM1D_5image',
    '<zune_jpeg::bitstream::BitStream>::decode_mcu_block::<zune_core::bytestream::reader::no_std_readers::ZCursor<alloc::vec::Vec<u8>>>'],
  ['__RINvMNtCsjIpoRzUjyHQ_4core3stre18trim_start_matchesReECs6thXTpflXIc_14rustc_demangle', '<str>::trim_start_matches::<&str>'],
  ['__RINvNtNtNtCsjIpoRzUjyHQ_4core5slice4sort6stable14driftsort_mainNtNtNtCsiu75YnjbALX_10wgpu_types7texture6format13TextureFormatNCINvMNtCs6zY7rJBZy9D_5alloc5sliceSBZ_11sort_by_keybNCNCNvMNtNtCshX3eSjzW1Ue_9wgpu_core6device6globalNtNtB30_6global6Global24surface_get_capabilities00E0INtNtB27_3vec3VecBZ_EEB30_',
    'core::slice::sort::stable::driftsort_main::<wgpu_types::texture::format::TextureFormat, <[wgpu_types::texture::format::TextureFormat]>::sort_by_key<bool, <wgpu_core::global::Global>::surface_get_capabilities::{closure#0}::{closure#0}>::{closure#0}, alloc::vec::Vec<wgpu_types::texture::format::TextureFormat>>'],
  ['__RNvNCNKNvNtCsjJlYt0P5xFO_4egui7context27IMMEDIATE_VIEWPORT_RENDERER0023___RUST_STD_INTERNAL_VAL', 'egui::context::IMMEDIATE_VIEWPORT_RENDERER::{K#0}::{closure#0}::__RUST_STD_INTERNAL_VAL'],
  ['__RNvNCNKNvNtNtNtCsjemAGIzwWSp_14regex_automata4util4pool5inner9THREAD_ID0s_023___RUST_STD_INTERNAL_VAL', 'regex_automata::util::pool::inner::THREAD_ID::{K#0}::{closure#1}::__RUST_STD_INTERNAL_VAL'],
  ['__RNvMsn_NtCs6zY7rJBZy9D_5alloc4syncINtB5_3ArcDG1_INtNtNtCsjIpoRzUjyHQ_4core3ops8function2FnTRL2_SNtNtNtCsU4UewP5b0C_4wgpu3api7adapter7AdapterINtNtBR_6option6OptionRL1_INtNtB1A_7surface7SurfaceL0_EEEEp6OutputINtNtBR_6result6ResultB1w_NtNtB7_6string6StringENtNtBR_6marker4SendNtB46_4SyncEL_E9drop_slowCsin6olpeIaud_9egui_wgpu',
    "<alloc::sync::Arc<dyn for<'a, 'b, 'c> core::ops::function::Fn<(&'a [wgpu::api::adapter::Adapter], core::option::Option<&'b wgpu::api::surface::Surface<'c>>), Output = core::result::Result<wgpu::api::adapter::Adapter, alloc::string::String>> + core::marker::Send + core::marker::Sync>>::drop_slow"],
  ['__RNvMsn_NtCs6zY7rJBZy9D_5alloc4syncINtB5_3ArcDG_INtNtNtCsjIpoRzUjyHQ_4core3ops8function2FnTQL0_NtNtCsjJlYt0P5xFO_4egui2ui2UiEEp6OutputuNtNtBQ_6marker4SendNtB2a_4SyncEL_E9drop_slowB1y_',
    "<alloc::sync::Arc<dyn for<'a> core::ops::function::Fn<(&'a mut egui::ui::Ui,), Output = ()> + core::marker::Send + core::marker::Sync>>::drop_slow"],
];
for (const [mangled, expected] of RUST) {
  const d = demangle(mangled);
  check(`rust v0: ${expected.slice(0, 60)}`, [d.full, d.language], [expected, 'rust']);
}

check('rust legacy', demangle('__ZN4core3fmt9Formatter3pad17h0123456789abcdefE').full, 'core::fmt::Formatter::pad');
check('rust legacy escapes', demangle('__ZN70_$LT$alloc..vec..Vec$LT$T$C$A$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h0123456789abcdefE').full, '<alloc::vec::Vec<T,A> as core::ops::drop::Drop>::drop');
check('c++', demangle('__ZN3foo3barEv').full, 'foo::bar()');
check('c++ with parameters', demangle('__ZN3foo3bazEi').full, 'foo::baz(…)');
check('c', [demangle('_main').full, demangle('_main').language], ['main', 'c']);
check('not mangled', demangle('radr://5614542').full, 'radr://5614542');
check('a broken v0 name stays as it was', demangle('__RNvC').full, '__RNvC');
check('generics fold in the short name', demangle('__RNvMsn_NtCs6zY7rJBZy9D_5alloc4syncINtB5_3ArcDG_INtNtNtCsjIpoRzUjyHQ_4core3ops8function2FnTQL0_NtNtCsjJlYt0P5xFO_4egui2ui2UiEEp6OutputuNtNtBQ_6marker4SendNtB2a_4SyncEL_E9drop_slowB1y_').short, '<alloc::sync::Arc<…>>::drop_slow');

// Swift: the vectors read in one call, as a page of imports reads its names.
const vectors = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'swift-vectors.json'), 'utf8'));
demangleAll(vectors.map(([symbol]) => symbol), false);
const wrong = vectors.filter(([symbol, full, short]) => {
  const d = demangle(symbol);
  return d.full !== full || d.short !== short || d.language !== 'swift';
});
check(`swift: ${vectors.length} vectors`, wrong.slice(0, 3).map(([symbol]) => [symbol, demangle(symbol).full]), []);
const HELLOKIT = [
  ['_$s8HelloKit05helloB6AnsweryS2iF', 'HelloKit.helloKitAnswer(Swift.Int) -> Swift.Int', 'helloKitAnswer(_:)'],
  ['_$s8HelloKit7CounterC9increment2byS2i_tF', 'HelloKit.Counter.increment(by: Swift.Int) -> Swift.Int', 'Counter.increment(by:)'],
  ['_$s8HelloKit7CounterC5countSivpACTK', 'key path getter for HelloKit.Counter.count : Swift.Int : HelloKit.Counter', 'key path getter for Counter.count : Counter'],
  ['_$s8HelloKit6CircleVAA5ShapeA2aDP4areaSdyFTW', 'protocol witness for HelloKit.Shape.area() -> Swift.Double in conformance HelloKit.Circle : HelloKit.Shape in HelloKit',
    'protocol witness for Shape.area() in conformance Circle'],
];
for (const [symbol, full, short] of HELLOKIT) check(`swift: ${short}`, [demangle(symbol).full, demangle(symbol).short], [full, short]);
check('swift in ELF, without the leading underscore', demangleUnprefixed('$s8HelloKit7CounterC9increment2byS2i_tF').short, 'Counter.increment(by:)');
check('a word substitution (05hello + B = helloKit)', demangle('_$s8HelloKit05helloB6AnsweryS2iF').full.startsWith('HelloKit.helloKitAnswer'), true);
check('a broken Swift name stays as it was', [demangle('_$s8HelloKit7CounterC9incr').full, demangle('_$s8HelloKit7CounterC9incr').language], ['_$s8HelloKit7CounterC9incr', 'swift']);
check('an unknown accessor stays as it was', demangle('_$s8HelloKit7CounterC5countSivZ').full, '_$s8HelloKit7CounterC5countSivZ');

// MSVC.
const msvc = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'msvc-vectors.json'), 'utf8'));
const msvcWrong = msvc.filter(([symbol, full, short]) => {
  const d = demangleUnprefixed(symbol);
  return d.full !== full || d.short !== short;
});
check(`msvc: ${msvc.length} vectors`, msvcWrong.slice(0, 3).map(([symbol]) => [symbol, demangleUnprefixed(symbol).full]), []);
check('msvc: a member function', [demangleUnprefixed('?length@Point@geo@@UEBAHXZ').full, demangleUnprefixed('?length@Point@geo@@UEBAHXZ').short],
  ['public: virtual int __cdecl geo::Point::length(void) const', 'geo::Point::length()']);
check('msvc: template arguments fold in the short name, operators stay',
  demangleUnprefixed('??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_K@Z').short, 'std::basic_ostream<char, std::char_traits<…>>::operator<<(…)');
check('msvc: language', demangleUnprefixed('?f@@YAXXZ').language, 'c++');
check('msvc: a broken name stays as it was', demangleUnprefixed('?f@@YAX').full, '?f@@YAX');

done('demangle');

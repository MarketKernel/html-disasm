//! Native programs analysed in the core: how a stripped Windows program's main is found, rule by
//! rule, on made-up calls (formerly in tests/winarm.mjs); the whole analyses are checked against the
//! TypeScript by tools/diff-core.mjs and through the page by tests/*.mjs.

use disasm_core::native::functions::{windows_main, Call, Callee, Function, Kind, StartupCode};
use disasm_core::refs::FxHashSet;

struct Code {
    straight: bool,
    argc: bool,
    instance: bool,
    globals: bool,
}

impl StartupCode for Code {
    fn straight(&self, _: u32, _: u32) -> bool {
        self.straight
    }
    fn argc(&self, _: u32, _: u32) -> bool {
        self.argc
    }
    fn instance(&self, _: u32, _: u32) -> bool {
        self.instance
    }
    fn globals(&self, _: u32, _: u32) -> bool {
        self.globals
    }
}

const PLAIN: Code = Code { straight: true, argc: false, instance: false, globals: false };

fn function(name: &str, kind: Kind) -> Function {
    Function { addr: 0.0, first: 0, count: 20, name: name.into(), full: name.into(), raw: (kind == Kind::Import).then(|| name.into()), kind, language: None }
}

/// The functions the cases call: 0 is the target, then the others by name.
fn functions() -> Vec<Function> {
    vec![
        function("target", Kind::Anonymous),
        function("_get_initial_wide_environment", Kind::Import),
        function("__p___wargv", Kind::Import),
        function("_get_narrow_winmain_command_line", Kind::Import),
        function("a", Kind::Anonymous),
        function("b", Kind::Anonymous),
        function("c", Kind::Anonymous),
        function("_cexit", Kind::Import),
    ]
}

fn call(at: u32, callee: usize, within: i64) -> Call {
    Call { at, within, callee: Callee::Function(callee) }
}

#[test]
fn windows_main_rules() {
    let f = functions();
    let none: FxHashSet<i64> = FxHashSet::default();
    let startup: FxHashSet<i64> = [0].into_iter().collect();
    let found = |calls: &[Call], startup: &FxHashSet<i64>, code: &Code| windows_main(calls, startup, &f, code);
    // MSVC with the runtime in a DLL: main after the environment import, WinMain after the command line.
    assert_eq!(found(&[call(1, 1, 0), call(3, 2, 0), call(6, 0, 0)], &none, &PLAIN), Some((0, "wmain")));
    assert_eq!(found(&[call(1, 3, 0), call(4, 0, 0)], &none, &PLAIN).map(|r| r.1), Some("WinMain"));
    // MSVC with the runtime linked in: main fed argc from the last of three calls…
    let argc = Code { argc: true, ..PLAIN };
    assert_eq!(found(&[call(1, 4, 0), call(3, 5, 0), call(5, 6, 0), call(9, 0, 0)], &startup, &argc).map(|r| r.0), Some(0));
    // …but only in the startup code.
    assert_eq!(found(&[call(1, 4, 1), call(3, 5, 1), call(5, 6, 1), call(9, 0, 1)], &startup, &argc), None);
    // WinMain given the instance handle; main fed from globals (older runtimes).
    assert_eq!(found(&[call(1, 4, 0), call(5, 0, 0)], &startup, &Code { instance: true, ..PLAIN }).map(|r| r.1), Some("WinMain"));
    assert_eq!(found(&[call(1, 4, 0), call(5, 0, 0)], &startup, &Code { globals: true, ..PLAIN }).map(|r| r.0), Some(0));
    // MinGW: main before _cexit, but not across a jump; an import called through its slot counts the same.
    assert_eq!(found(&[call(1, 0, 0), call(6, 7, 0)], &startup, &PLAIN).map(|r| r.0), Some(0));
    assert_eq!(found(&[call(1, 0, 0), call(6, 7, 0)], &startup, &Code { straight: false, ..PLAIN }), None);
    let slot = Call { at: 6, within: 0, callee: Callee::Import("_cexit".into()) };
    assert_eq!(found(&[call(1, 0, 0), slot], &startup, &PLAIN).map(|r| r.0), Some(0));
}

//! The functions of a native program, as the three analyses
//! (src/core/program.ts, x86/program.ts, arm32/program.ts) find them: where
//! each starts — sections, stubs, the file's function starts, exports,
//! symbols, call targets, the entry point — and its names; and a stripped
//! Windows program's `main`, from how its C runtime calls it (`windowsMain`
//! in src/core/disassembly.ts).

use super::image::NativeImage;
use crate::macho::number_key;
use crate::refs::{FxHashMap, FxHashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Export,
    Symbol,
    Import,
    Entry,
    Anonymous,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Export => "export",
            Kind::Symbol => "symbol",
            Kind::Import => "import",
            Kind::Entry => "entry",
            Kind::Anonymous => "anonymous",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Function {
    pub addr: f64,
    pub first: u32,
    pub count: u32,
    pub name: String,
    pub full: String,
    pub raw: Option<String>,
    pub kind: Kind,
    pub language: Option<&'static str>,
}

/// Where functions start, with the name and kind each is known by (`starts` in the analyses).
#[derive(Default)]
pub struct Starts {
    map: FxHashMap<u64, (f64, Option<String>, Kind)>,
}

impl Starts {
    /// Adds a start the caller has checked is an instruction: a name fills one that had none,
    /// a kind replaces `anonymous`.
    pub fn add(&mut self, addr: f64, raw: Option<&str>, kind: Kind) {
        let key = number_key(addr);
        match self.map.get_mut(&key) {
            None => {
                self.map.insert(key, (addr, raw.map(String::from), kind));
            }
            Some(known) => {
                // As JavaScript tests them: an empty name is no name, though it is kept over none.
                let named = |r: Option<&str>| r.is_some_and(|r| !r.is_empty());
                if (known.2 == Kind::Anonymous && kind != Kind::Anonymous) || (!named(known.1.as_deref()) && named(raw)) {
                    if let Some(raw) = raw {
                        known.1 = Some(raw.to_string());
                    }
                    if known.2 == Kind::Anonymous {
                        known.2 = kind;
                    }
                }
            }
        }
    }

    pub fn raw(&self, addr: f64) -> Option<&str> {
        self.map.get(&number_key(addr)).and_then(|s| s.1.as_deref())
    }

    /// The functions, by address: each runs to the next start or the end of its range. `index_of`
    /// is an address's instruction, `range_end` the end of the range an instruction is in.
    /// `main_entry`: an entry point without a name is called main (arm64, x86; not AArch32).
    pub fn build(self, image: &NativeImage, index_of: &dyn Fn(f64) -> i64, range_end: &dyn Fn(u32) -> u32, main_entry: bool) -> Vec<Function> {
        let mut starts: Vec<(f64, Option<String>, Kind)> = self.map.into_values().collect();
        starts.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal));
        let mut out = Vec::with_capacity(starts.len());
        for k in 0..starts.len() {
            let addr = starts[k].0;
            let first = index_of(addr) as u32;
            let end_of_range = range_end(first);
            let next_index = starts.get(k + 1).map_or(-1, |s| index_of(s.0));
            let end = if next_index > first as i64 && next_index <= end_of_range as i64 { next_index as u32 } else { end_of_range };
            let (_, raw, kind) = &starts[k];
            let mut name = format!("sub_{}", crate::text::js_hex(addr));
            let mut full = name.clone();
            let mut language = None;
            if let Some(raw) = raw.as_deref().filter(|r| !r.is_empty()) {
                let d = image.function_names(raw);
                name = d.short;
                full = d.full;
                language = Some(d.language.as_str());
            }
            if main_entry && *kind == Kind::Entry && raw.as_deref().is_none_or(str::is_empty) {
                name = "main".into();
                full = "main".into();
            }
            out.push(Function { addr, first, count: end - first, name, full, raw: raw.clone(), kind: *kind, language });
        }
        out
    }
}

/// A call the Windows startup rules look at: where it is, the function it is in, and what it calls.
pub struct Call {
    pub at: u32,
    pub within: i64,
    pub callee: Callee,
}

#[derive(Clone)]
pub enum Callee {
    /// A function of the program (an index into the functions).
    Function(usize),
    /// An imported function, by name.
    Import(String),
}

/// Questions about the instructions between two others, which only an architecture can answer.
pub trait StartupCode {
    /// The code from one to the other falls through: no jump, return or trap.
    fn straight(&self, from: u32, to: u32) -> bool;
    /// The first argument is loaded from where the last call's result points (argc = *__p___argc()).
    fn argc(&self, from: u32, to: u32) -> bool;
    /// The first argument is the image base (the instance handle) and the second 0.
    fn instance(&self, from: u32, to: u32) -> bool;
    /// The first three arguments are loaded from globals (argc, argv, envp).
    fn globals(&self, from: u32, to: u32) -> bool;
}

/// What the C runtime fetches just before it calls the program's own entry, which that entry is then called.
fn main_after(name: &str) -> Option<&'static str> {
    Some(match name {
        "_get_initial_narrow_environment" => "main",
        "_get_initial_wide_environment" => "wmain",
        "_get_narrow_winmain_command_line" => "WinMain",
        "_get_wide_winmain_command_line" => "wWinMain",
        _ => return None,
    })
}

/// A Windows program's `main` (or `wmain`, `WinMain`), from how its C runtime calls it: the
/// function (an index into `functions`) and the name. See `windowsMain` in src/core/disassembly.ts.
pub fn windows_main(calls: &[Call], startup: &FxHashSet<i64>, functions: &[Function], code: &dyn StartupCode) -> Option<(usize, &'static str)> {
    let kind = |c: &Callee| match c {
        Callee::Function(f) => functions[*f].kind,
        Callee::Import(_) => Kind::Import,
    };
    let function = |c: &Callee| match c {
        Callee::Function(f) => Some(*f),
        Callee::Import(_) => None,
    };
    // The name an import goes by: a call through its slot, or to a thunk listed as the import.
    fn raw<'a>(functions: &'a [Function], c: &'a Callee) -> Option<&'a str> {
        match c {
            Callee::Function(f) => functions[*f].raw.as_deref(),
            Callee::Import(name) => Some(name.as_str()),
        }
    }
    for k in 0..calls.len() {
        let name = if kind(&calls[k].callee) == Kind::Import { raw(functions, &calls[k].callee).and_then(main_after) } else { None };
        let Some(name) = name else { continue };
        let mut j = k + 1;
        while j < (k + 6).min(calls.len()) && calls[j].within == calls[k].within {
            if kind(&calls[j].callee) != Kind::Import {
                return function(&calls[j].callee).map(|f| (f, name));
            }
            j += 1;
        }
    }
    for k in 3..calls.len() {
        let main = &calls[k];
        let first = &calls[k - 3];
        if !startup.contains(&main.within) || first.within != main.within || main.at - first.at > 16 || kind(&main.callee) != Kind::Anonymous {
            continue;
        }
        if [1, 2, 3].iter().all(|&d| kind(&calls[k - d].callee) == Kind::Anonymous) && code.straight(first.at, main.at) && code.argc(calls[k - 1].at, main.at) {
            return function(&main.callee).map(|f| (f, "main"));
        }
    }
    for k in 1..calls.len() {
        let main = &calls[k];
        if !startup.contains(&main.within) || kind(&main.callee) != Kind::Anonymous || calls[k - 1].within != main.within || main.at - calls[k - 1].at > 12 {
            continue;
        }
        if code.instance(calls[k - 1].at, main.at) {
            return function(&main.callee).map(|f| (f, "WinMain"));
        }
        if code.globals(calls[k - 1].at, main.at) {
            return function(&main.callee).map(|f| (f, "main"));
        }
    }
    for last in ["_cexit", "exit"] {
        for k in 1..calls.len() {
            let exit = &calls[k];
            let before = &calls[k - 1];
            let is_last = kind(&exit.callee) == Kind::Import && raw(functions, &exit.callee) == Some(last);
            if !is_last || !startup.contains(&exit.within) || before.within != exit.within || exit.at - before.at > 12 {
                continue;
            }
            if kind(&before.callee) == Kind::Anonymous && code.straight(before.at, exit.at) {
                return function(&before.callee).map(|f| (f, "main"));
            }
        }
    }
    None
}

/// Names a stripped Windows program's main: when it is anonymous, it takes the name.
pub fn name_main(functions: &mut [Function], found: Option<(usize, &'static str)>) {
    if let Some((f, name)) = found {
        if functions[f].kind == Kind::Anonymous {
            functions[f].name = name.into();
            functions[f].full = name.into();
            functions[f].raw = Some(name.into());
        }
    }
}

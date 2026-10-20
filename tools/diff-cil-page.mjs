/**
 * What the page shows of a .NET assembly, from the core, against the TypeScript that read the
 * metadata for it (the original project, checked out beside this one, or ORIGINAL): every
 * instruction as a row and the details show it (its text as ildasm prints it, the operand, the
 * bytes, what a method operand reaches, an ldstr's string, the field a field operand names), every
 * method's card and HLA64 header (attributes, header, locals, clauses, signature), what each
 * method's card counts (calls, calls through a pointer, strings), the Assembly and References
 * pages, every string of #US as ldstr writes it, and the name of every field the code uses.
 *
 * `--damage N` also reads N copies of each file with a few bytes flipped: both must fail to read
 * it the same way, or show the same of it.
 *
 *   node tools/diff-cil-page.mjs <assembly.dll …> [--damage N]
 */
import { readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { load, root } from './load.mjs';

const original = resolve(process.env.ORIGINAL ?? join(root, '..', 'html-disasm'));
const { load: loadOriginal } = await import(join(original, 'tools', 'load.mjs'));
const OLD = await loadOriginal('core/pe', 'core/cil/opcodes', 'core/cil/metadata', 'core/cil/names', 'core/cil/decode', 'core/cil/program');
const NEW = await load('core/pe', 'core/cil/program');
await NEW.loadEngine();

/** A value as comparable text: keys in order, undefined as null. */
const canon = (v) =>
  JSON.stringify(v, (key, value) => {
    if (value === undefined) return null;
    if (value && typeof value === 'object' && !Array.isArray(value)) return Object.fromEntries(Object.keys(value).sort().map((k) => [k, value[k] ?? null]));
    return value;
  });

/* The original page's helpers (src/app/cil.ts), as they were. */

const METHOD_ACCESS = ['privatescope', 'private', 'famandassem', 'assembly', 'family', 'famorassem', 'public', ''];
const METHOD_FLAGS = [[0x10, 'static'], [0x20, 'final'], [0x40, 'virtual'], [0x80, 'hidebysig'], [0x100, 'newslot'], [0x400, 'abstract'], [0x800, 'specialname'], [0x2000, 'pinvokeimpl'], [0x1000, 'rtspecialname']];
const IMPL_FLAGS = [[0x8, 'noinlining'], [0x40, 'nooptimization'], [0x100, 'aggressiveinlining'], [0x200, 'aggressiveoptimization'], [0x20, 'synchronized'], [0x80, 'preservesig'], [0x1000, 'internalcall'], [0x2000, 'async']];
const TYPE_VISIBILITY = ['private', 'public', 'nested public', 'nested private', 'nested family', 'nested assembly', 'nested famandassem', 'nested famorassem'];

function methodFlags(o, method) {
  const t = o.md.table(OLD.TABLE.MethodDef);
  const flags = t.get(method, 'Flags');
  const impl = t.get(method, 'ImplFlags');
  const words = [METHOD_ACCESS[flags & 7], ...METHOD_FLAGS.filter(([bit]) => flags & bit).map(([, w]) => w)].filter(Boolean);
  const code = ['cil', 'native', 'optil', 'runtime'][impl & 3];
  return `${words.join(' ')} · ${code} ${impl & 4 ? 'unmanaged' : 'managed'}${IMPL_FLAGS.filter(([bit]) => impl & bit).map(([, w]) => ` ${w}`).join('')}`;
}

function clauseText(o, clause, generic) {
  const kind = clause.kind & 1 ? `filter ${OLD.label(clause.filterStart)}` : clause.kind & 2 ? 'finally' : clause.kind & 4 ? 'fault' : `catch ${clause.classToken ? o.names.type(clause.classToken, generic) : 'object'}`;
  return `.try ${OLD.label(clause.tryStart)} to ${OLD.label(clause.tryEnd)} ${kind} handler ${OLD.label(clause.handlerStart)} to ${OLD.label(clause.handlerEnd)}`;
}

function version(md, tableId, row) {
  const t = md.table(tableId);
  return `${t.get(row, 'Major')}.${t.get(row, 'Minor')}.${t.get(row, 'Build')}.${t.get(row, 'Revision')}`;
}

function keyText(blob) {
  if (!blob.length) return '';
  const hexed = [...blob].map((b) => b.toString(16).padStart(2, '0')).join('');
  return blob.length === 8 ? hexed : `${hexed.slice(0, 16)}… (${blob.length} B)`;
}

function typeKind(o, row) {
  const md = o.md;
  const types = md.table(OLD.TABLE.TypeDef);
  if (types.get(row, 'Flags') & 0x20) return 'interface';
  const extendsCoded = types.get(row, 'Extends');
  if (!extendsCoded) return row === 1 ? '<Module>' : 'class';
  const base = OLD.decodeIndex('TypeDefOrRef', extendsCoded);
  const name = base.table === OLD.TABLE.TypeRef ? md.string(md.table(OLD.TABLE.TypeRef).get(base.row, 'Name')) : base.table === OLD.TABLE.TypeDef ? md.string(types.get(base.row, 'Name')) : '';
  const ns = base.table === OLD.TABLE.TypeRef ? md.string(md.table(OLD.TABLE.TypeRef).get(base.row, 'Namespace')) : '';
  if (ns === 'System' && name === 'Enum') return 'enum';
  if (ns === 'System' && name === 'ValueType') return 'struct';
  if (ns === 'System' && name === 'MulticastDelegate') return 'delegate';
  return 'class';
}

/* What the original page read. */

function theirInsn(o, i) {
  const insn = o.insn(i, new OLD.CilInsn());
  const ctx = o.context(i);
  const op = insn.op;
  const raw = o.operandBytes(i, insn);
  const md = o.md;
  const tok = insn.a;
  const string = op?.operand === OLD.OPERAND.STRING && OLD.tokenTable(tok) === OLD.USER_STRING ? (md.userString(OLD.tokenRow(tok)) ?? null) : null;
  const isField = op?.operand === OLD.OPERAND.FIELD || (op?.operand === OLD.OPERAND.TOKEN && (OLD.tokenTable(tok) === OLD.TABLE.Field || (OLD.tokenTable(tok) === OLD.TABLE.MemberRef && o.names.isFieldRef(OLD.tokenRow(tok)))));
  return {
    op: op ? { code: op.code, operand: op.operand, flags: op.flags } : null,
    m: insn.m,
    at: insn.at,
    len: insn.len,
    a: insn.a,
    targets: op?.operand === OLD.OPERAND.SWITCH ? insn.targets : null,
    operand: OLD.operandText(md, insn, ctx, raw),
    text: OLD.insnText(md, insn, ctx, raw),
    fileOffset: o.fileOffset(i),
    bytes5: OLD.bytesText(md.bytes, o.fileOffset(i), insn.len, 5),
    bytes24: OLD.bytesText(md.bytes, o.fileOffset(i), insn.len, 24),
    callee: op?.operand === OLD.OPERAND.METHOD ? (o.callee(tok)?.addr ?? null) : null,
    // The function a method operand reaches, by its number (what the original's callee() gave).
    calleeFn: op?.operand === OLD.OPERAND.METHOD && o.callee(tok)?.kind !== 'import' && o.callee(tok) ? o.functions.indexOf(o.callee(tok)) : -1,
    string,
    plain: string !== null && OLD.plainString(string),
    field: isField ? o.names.field(tok, ctx.generic) : null,
    tokenKind: OLD.TABLE_NAMES[OLD.tokenTable(tok)] ?? (OLD.tokenTable(tok) === OLD.USER_STRING ? '#US' : ''),
  };
}

function theirMethod(o, f) {
  const body = o.bodies[f];
  const method = body.method;
  const generic = { type: o.names.methodOwner[method] ?? 0, method };
  const sig = o.names.methodDefSig(method);
  const names = o.names.paramNames(method);
  return {
    token: OLD.token(OLD.TABLE.MethodDef, method),
    attributes: methodFlags(o, method),
    rva: body.rva,
    size: body.size,
    fat: body.fat,
    maxStack: body.maxStack,
    initLocals: body.initLocals,
    locals: body.localsToken ? o.names.locals(body.localsToken, generic) : [],
    clauses: body.clauses.map((c) => ({
      kind: c.kind,
      tryStart: c.tryStart,
      tryEnd: c.tryEnd,
      handlerStart: c.handlerStart,
      handlerEnd: c.handlerEnd,
      filterStart: c.filterStart,
      text: clauseText(o, c, generic),
      catch: c.classToken ? o.names.type(c.classToken, generic) : 'object',
    })),
    signature: `${sig.conv & 0x20 ? 'instance ' : 'static '}${sig.ret} (${sig.params.map((type, k) => (names[k + 1] ? `${type} ${OLD.properName(names[k + 1])}` : type)).join(', ')})`,
    params: sig.params.map((type, k) => [names[k + 1] && /^[A-Za-z_][A-Za-z0-9_]*$/.test(names[k + 1]) ? names[k + 1] : `A_${k + (sig.conv & 0x20 ? 1 : 0)}`, type]),
    ret: sig.ret,
  };
}

function theirRefs(o, f) {
  const fn = o.functions[f];
  const calls = new Map();
  const strings = new Map();
  let indirect = 0;
  const insn = new OLD.CilInsn();
  for (let i = fn.first; i < fn.first + Math.min(fn.count, 50000); i++) {
    o.insn(i, insn);
    if (!insn.op) continue;
    if (insn.op.flags & OLD.F.CALL && insn.op.operand === OLD.OPERAND.METHOD) {
      const callee = o.callee(insn.a);
      if (callee) calls.set(callee.addr, (calls.get(callee.addr) ?? 0) + 1);
    } else if (insn.op.flags & OLD.F.CALL) indirect++;
    if (insn.op.operand === OLD.OPERAND.STRING) strings.set(insn.a, o.md.userString(OLD.tokenRow(insn.a)) ?? '');
  }
  return [[...calls], indirect, [...strings]];
}

function ourRefs(n, f) {
  const refs = n.functionRefs(f);
  const calls = new Map();
  const strings = new Map();
  for (const addr of refs.calls) calls.set(addr, (calls.get(addr) ?? 0) + 1);
  for (const [tok, text] of refs.strings) strings.set(tok, text);
  return [[...calls], refs.indirect, [...strings]];
}

function theirAssembly(o) {
  const md = o.md;
  const T = OLD.TABLE;
  const assembly = md.rows(T.Assembly) ? md.table(T.Assembly) : undefined;
  const resources = md.table(T.ManifestResource);
  const types = md.table(T.TypeDef);
  const methodsOf = new Map();
  for (let m = 1; m < o.names.methodOwner.length; m++) methodsOf.set(o.names.methodOwner[m], (methodsOf.get(o.names.methodOwner[m]) ?? 0) + 1);
  const typeRows = [];
  for (let r = 2; r <= Math.min(types.rows, 3001); r++) {
    const first = o.functions.find((f) => o.names.methodOwner[f.index] === r);
    typeRows.push([o.names.typeDef(r), typeKind(o, r), TYPE_VISIBILITY[types.get(r, 'Flags') & 7] ?? '', methodsOf.get(r) ?? 0, first ? first.addr : null]);
  }
  const resourceRows = [];
  for (let r = 1; r <= resources.rows; r++) {
    const impl = OLD.decodeIndex('Implementation', resources.get(r, 'Implementation'));
    const where = !resources.get(r, 'Implementation') ? null : impl.table === T.AssemblyRef ? md.string(md.table(T.AssemblyRef).get(impl.row, 'Name')) : md.string(md.table(T.File).get(impl.row, 'Name'));
    resourceRows.push([md.string(resources.get(r, 'Name')), (resources.get(r, 'Flags') & 7) === 1, where]);
  }
  return {
    assembly: assembly ? [md.string(assembly.get(1, 'Name')), version(md, T.Assembly, 1), md.string(assembly.get(1, 'Culture')), keyText(md.blob(assembly.get(1, 'PublicKey')))] : null,
    module: [md.string(md.table(T.Module).get(1, 'Name')), md.guid(md.table(T.Module).get(1, 'Mvid'))],
    runtime: [md.version, md.header.runtime, md.schema],
    flags: OLD.CLI_FLAGS.filter(([bit]) => md.header.flags & bit).map(([, name]) => name).join(' '),
    strongName: md.header.strongName.size,
    counts: [md.rows(T.TypeDef), md.rows(T.MethodDef), md.rows(T.Field), md.rows(T.Property), md.rows(T.Event)],
    warnings: md.warnings,
    streams: md.streams.map((s) => [s.name, s.offset, s.size]),
    tables: md.tables.map((tb, id) => (tb ? [id, OLD.TABLE_NAMES[id] ?? '?', tb.rows] : null)).filter(Boolean),
    resources: resourceRows,
    types: typeRows,
  };
}

function theirReferences(o) {
  const md = o.md;
  const T = OLD.TABLE;
  const refs = md.table(T.AssemblyRef);
  const assemblies = [];
  for (let r = 1; r <= refs.rows; r++) assemblies.push([md.string(refs.get(r, 'Name')), version(md, T.AssemblyRef, r), md.string(refs.get(r, 'Culture')), keyText(md.blob(refs.get(r, 'PublicKeyOrToken')))]);
  const exported = md.table(T.ExportedType);
  const forwarders = [];
  for (let r = 1; r <= Math.min(exported.rows, 5000); r++) {
    const impl = OLD.decodeIndex('Implementation', exported.get(r, 'Implementation'));
    const to = impl.table === T.AssemblyRef ? md.string(refs.get(impl.row, 'Name')) : impl.table === T.File ? md.string(md.table(T.File).get(impl.row, 'Name')) : '';
    const ns = md.string(exported.get(r, 'Namespace'));
    forwarders.push([`${ns ? `${ns}.` : ''}${md.string(exported.get(r, 'Name'))}`, to]);
  }
  return { assemblies, forwarders, exported: exported.rows };
}

/* The comparison. */

const args = process.argv.slice(2);
const damageAt = args.indexOf('--damage');
const damage = damageAt < 0 ? 0 : Number(args.splice(damageAt, 2)[1]);

let seed = 0x9e3779b9;
const random = () => {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>>= 0);
};

let failed = 0;
let files = 0;
let threw = 0;

async function analyze(M, bytes) {
  try {
    const pe = M.parsePe(bytes);
    if (!pe.clr) return { error: 'not .NET' };
    return { p: await M.analyzeCil(pe) };
  } catch (err) {
    return { error: `${err.constructor.name === 'NotCil' ? 'NotCil: ' : ''}${err.message}` };
  }
}

async function compareFile(name, bytes, quiet = false) {
  files++;
  const t0 = performance.now();
  const theirs = await analyze(OLD, bytes);
  const ours = await analyze(NEW, bytes);
  if (theirs.error || ours.error) {
    const same = theirs.error === ours.error;
    // A damaged file the original's DataView read past: it threw a RangeError where the core reads zeros.
    if (!same && /Offset is outside the bounds|out of bounds/.test(theirs.error ?? '')) threw++;
    else if (!same) failed++;
    if (!same || !quiet) console.log(`${name.padEnd(40)} ${same ? `not read by either (${theirs.error})` : `DIFFERS: read: ${theirs.error ?? 'ok'} / ${ours.error ?? 'ok'}`}`);
    ours.p?.dispose();
    return;
  }
  const o = theirs.p;
  const n = ours.p;
  const tally = new Map();
  const first = new Map();
  const compare = (what, where, their, our) => {
    let value;
    try {
      value = their();
    } catch {
      threw++;
      return;
    }
    const a = canon(value);
    const b = canon(our());
    if (a === b) return;
    tally.set(what, (tally.get(what) ?? 0) + 1);
    // Where they part: the text around the first character that differs.
    let at = 0;
    while (at < a.length && a[at] === b[at]) at++;
    const from = Math.max(0, at - 200);
    if (!first.has(what)) first.set(what, `${where} (at ${at})\n      TS:   …${a.slice(from, at + 300)}\n      core: …${b.slice(from, at + 300)}`);
  };
  let rows = 0;
  o.functions.forEach((fn, f) => {
    for (let i = fn.first; i < fn.first + fn.count; i++) {
      rows++;
      compare('rows', `${fn.name} #${i - fn.first}`, () => theirInsn(o, i), () => n.insn(i));
    }
    compare('method cards', fn.name, () => theirMethod(o, f), () => n.method(f));
    compare('function cards', fn.name, () => theirRefs(o, f), () => ourRefs(n, f));
  });
  compare('assembly page', name, () => theirAssembly(o), () => n.assemblyInfo());
  compare('references page', name, () => theirReferences(o), () => n.referencesInfo());
  for (const s of o.strings) compare('string texts', s.text.slice(0, 40), () => OLD.stringText(o.md.userString(OLD.tokenRow(s.addr)) ?? ''), () => n.stringText(s.addr));
  for (const tok of o.fieldRefs.keys()) compare('field names', tok.toString(16), () => o.names.field(tok), () => n.fieldName(tok));
  compare('meta', name, () => [o.assemblyName, o.framework, o.entryMethod, o.archLabel(), o.platformLabel(), o.bodies.reduce((k, b) => k + b.size, 0)], () => [n.assemblyName, n.framework, n.entryMethod, n.archLabel(), n.platformLabel(), n.codeBytes]);
  const diffs = [...tally].map(([what, count]) => `${what} (${count})\n      ${first.get(what)}`);
  if (!quiet || diffs.length) console.log(`${name.padEnd(40)} ${String(rows).padStart(9)} rows  ${(performance.now() - t0).toFixed(0).padStart(7)} ms  ${diffs.length ? `DIFFERS: ${diffs.join('\n    ')}` : 'same'}`);
  if (diffs.length) failed++;
  n.dispose();
}

for (const file of args) {
  const bytes = new Uint8Array(readFileSync(file));
  await compareFile(basename(file), bytes);
  for (let k = 0; k < damage; k++) {
    const copy = bytes.slice();
    for (let f = 1 + (random() % 4); f > 0; f--) copy[random() % copy.length] ^= 1 << random() % 8;
    await compareFile(`${basename(file)} damaged #${k}`, copy, true);
  }
}
console.log(`${files} readings, ${failed} differ${threw ? `, ${threw} views of damaged files the TypeScript threw on` : ''}`);
process.exit(failed ? 1 : 0);

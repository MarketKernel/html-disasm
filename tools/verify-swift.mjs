/**
 * Checks the Swift demangler (crates/core/src/demangle/swift.rs) against Apple's
 * swift-demangle: every Swift symbol of the given programs is demangled here
 * and by `swift-demangle --compact`, in full and with `--simplified`, and the
 * texts are compared.
 *
 *   node tools/verify-swift.mjs <program …> [--show N] [--tree]
 *   node tools/verify-swift.mjs --symbols names.txt      one symbol per line
 *   … --vectors tests/fixtures/swift-vectors.json         also keep verified examples
 *
 * A program's symbols are read with `nm -a` (Mach-O and ELF alike; for a
 * universal file, every slice). Results fall in three groups: the same text
 * both ways, not demangled here (the symbol stays as it is, which is safe),
 * and different text — the ones that matter. Differences are grouped by the
 * kind of the tree's first node, most frequent first; --tree prints the two
 * trees of each example shown (`swift-demangle --tree-only`).
 *
 * --vectors adds examples to a JSON file that tests/demangle.mjs checks
 * without Xcode: the shortest symbols that together hold every pair of a node
 * kind and the kind of a child under it. Only symbols of the standard library
 * and the public SDK frameworks are taken, so that names private to the
 * programs they came from stay out of the repository.
 *
 * Needs Xcode (`xcrun swift-demangle`).
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { load } from './load.mjs';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const at = args.indexOf(name);
  if (at < 0) return fallback;
  const [value] = args.splice(at, 2).slice(1);
  return value;
};
const flag = (name) => {
  const at = args.indexOf(name);
  if (at >= 0) args.splice(at, 1);
  return at >= 0;
};
const show = Number(option('--show', 4));
const symbolsFile = option('--symbols', null);
const vectorsFile = option('--vectors', null);
const trees = flag('--tree');

const { demangleSwiftAll, swiftTreeAll } = await load('core/demangle');
const tool = execFileSync('xcrun', ['--find', 'swift-demangle'], { encoding: 'utf8' }).trim();

const symbols = new Set();
if (symbolsFile) for (const line of readFileSync(symbolsFile, 'utf8').split('\n')) if (line.trim()) symbols.add(line.trim());
for (const file of args) {
  const out = execFileSync('nm', ['-a', file], { encoding: 'utf8', maxBuffer: 1 << 30, stdio: ['ignore', 'pipe', 'ignore'] });
  for (const line of out.split('\n')) {
    const name = line.slice(line.lastIndexOf(' ') + 1);
    const at = name.indexOf('$s');
    if (at === 0 || (at === 1 && name[0] === '_')) symbols.add(name.slice(at));
  }
}
const list = [...symbols];
if (!list.length) {
  console.error('no Swift symbols');
  process.exit(1);
}

/** swift-demangle over many names at once, one line out per line in. */
function reference(names, extra) {
  const out = execFileSync(tool, ['--compact', ...extra], { input: names.join('\n') + '\n', encoding: 'utf8', maxBuffer: 1 << 30 });
  return out.split('\n').slice(0, names.length);
}
const full = reference(list, []);
const simple = reference(list, ['--simplified']);

const PUBLIC_MODULES = new Set([
  'Swift', '__C', '__C_Synthesized', '_Concurrency', '_StringProcessing', 'RegexBuilder', 'Foundation', 'FoundationEssentials',
  'Dispatch', 'ObjectiveC', 'CoreGraphics', 'CoreFoundation', 'os', 'Observation', 'Combine', 'SwiftUI', 'SwiftUICore', 'AppKit',
  'UIKit', 'Charts', 'Network', 'AppIntents', 'Accelerate', 'CoreData', 'SwiftData', 'Testing', 'XCTest', 'Distributed',
  'Synchronization', 'CryptoKit', 'RealityKit', 'MapKit', 'AVFoundation', 'CloudKit', 'StoreKit', 'WidgetKit', 'Metal', 'simd',
  'CoreML', 'Vision', 'NaturalLanguage', 'OSLog', 'UniformTypeIdentifiers', 'System', 'Cocoa', 'Darwin', 'Spatial', 'TipKit',
]);
const isPublic = (tree) => {
  const walk = (n) => (n.kind !== 'Module' || PUBLIC_MODULES.has(n.text)) && n.children.every(walk);
  return walk(tree);
};

/** A tree as `swift-demangle --tree-only` prints it (the core's swiftTreeAll) read back into nodes: kind, text, children. */
function treeOf(text) {
  if (text === null) return null;
  const roots = [];
  const path = [];
  for (const line of text.split('\n')) {
    const depth = (line.length - line.trimStart().length) / 2;
    const match = /^kind=([^,]*)(?:, text="(.*)")?/.exec(line.trimStart());
    const node = { kind: match?.[1] ?? '', text: match?.[2], children: [] };
    path.length = depth;
    (depth ? path[depth - 1].children : roots).push(node);
    path.push(node);
  }
  return roots[0] ?? null;
}
const parseAll = (names) => swiftTreeAll(names).map(treeOf);

/** The pairs of a node kind and a child's kind in a tree. */
const edgesOf = (tree) => {
  const edges = new Set();
  const walk = (n) => {
    for (const c of n.children) {
      edges.add(`${n.kind}>${c.kind}`);
      walk(c);
    }
  };
  walk(tree);
  return edges;
};

let same = 0;
let kept = 0;
let keptByThem = 0;
const wrong = new Map();
const missing = new Map();
const vectors = vectorsFile && existsSync(vectorsFile) ? JSON.parse(readFileSync(vectorsFile, 'utf8')) : [];
const covered = new Set(vectors.length ? parseAll(vectors.map(([symbol]) => symbol)).flatMap((tree) => (tree ? [...edgesOf(tree)] : [])) : []);
const oursAll = demangleSwiftAll(list);
const treesAll = swiftTreeAll(list);
const candidates = [];
for (let i = 0; i < list.length; i++) {
  const symbol = list[i];
  const ours = oursAll[i];
  const theirs = { full: full[i], short: simple[i] };
  if (theirs.full === symbol) {
    keptByThem++;
    continue;
  }
  const tree = treeOf(treesAll[i]);
  const group = tree?.children[0]?.kind ?? '(does not parse)';
  if (!ours) {
    kept++;
    if (!missing.has(group)) missing.set(group, []);
    missing.get(group).push({ symbol, theirs });
    continue;
  }
  if (ours.full === theirs.full && ours.short === theirs.short) {
    same++;
    if (vectorsFile && isPublic(tree)) candidates.push([symbol, theirs.full, theirs.short]);
    continue;
  }
  if (!wrong.has(group)) wrong.set(group, []);
  wrong.get(group).push({ symbol, ours, theirs });
}

const report = (title, groups, print) => {
  const sorted = [...groups].sort((a, b) => b[1].length - a[1].length);
  if (!sorted.length) return;
  console.log(`\n${title}:`);
  for (const [group, items] of sorted) {
    console.log(`  ${group}: ${items.length}`);
    for (const item of items.slice(0, show)) print(item);
  }
};
report('different text', wrong, ({ symbol, ours, theirs }) => {
  console.log(`    ${symbol}`);
  if (ours.full !== theirs.full) console.log(`      ours:   ${ours.full}\n      theirs: ${theirs.full}`);
  if (ours.short !== theirs.short) console.log(`      ours (simplified):   ${ours.short}\n      theirs (simplified): ${theirs.short}`);
  if (trees) {
    console.log((swiftTreeAll([symbol])[0] ?? '(does not parse)').replace(/^/gm, '      | '));
    console.log(execFileSync(tool, ['--tree-only', symbol], { encoding: 'utf8' }).replace(/^/gm, '      * '));
  }
});
report('not demangled here', missing, ({ symbol, theirs }) => {
  console.log(`    ${symbol}\n      theirs: ${theirs.full}`);
  if (trees) console.log(execFileSync(tool, ['--tree-only', symbol], { encoding: 'utf8' }).replace(/^/gm, '      * '));
});

const differ = [...wrong.values()].reduce((n, items) => n + items.length, 0);
console.log(`\n${list.length} symbols: ${same} the same, ${differ} different, ${kept} not demangled here, ${keptByThem} not demangled by swift-demangle either`);
if (vectorsFile) {
  candidates.sort((a, b) => a[0].length - b[0].length);
  for (const vector of candidates) {
    const fresh = [...edgesOf(treeOf(swiftTreeAll([vector[0]])[0]))].filter((e) => !covered.has(e));
    if (!fresh.length) continue;
    fresh.forEach((e) => covered.add(e));
    vectors.push(vector);
  }
  writeFileSync(vectorsFile, JSON.stringify(vectors, null, 0).replace(/\],\[/g, '],\n['));
  console.log(`${vectors.length} vectors in ${vectorsFile}`);
}

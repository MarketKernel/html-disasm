/**
 * The strings the interface shows, as the dictionaries in src/locales key
 * them: { context: { English text: null | [one, other] } }. They are read from
 * the t()/tn() calls in the .ts files under src/ and the data-i18n marks in
 * src/app/template.html, so both must use plain string literals.
 *
 * `node tools/i18n.mjs` prints, per language, the strings its dictionary
 * lacks and the ones it has but the interface no longer uses — or, with no
 * dictionaries yet, how many strings a translator would get.
 */
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { root } from './load.mjs';

const LITERAL = String.raw`'((?:\\.|[^'\\])*)'`;
const CALL = new RegExp(String.raw`\b(tn?)\(\s*${LITERAL}\s*,\s*${LITERAL}(?:\s*,\s*${LITERAL})?`, 'g');
const unescape = (text) => text.replace(/\\(.)/g, '$1');
const ATTRIBUTES = ['title', 'placeholder', 'aria-label'];

function add(strings, context, text, forms = null) {
  strings[context] ??= {};
  strings[context][text] = forms;
}

const decode = (html) => html.replace(/&rarr;/g, '→').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"');

export async function extract() {
  const strings = {};
  const dir = join(root, 'src');
  for (const name of (await readdir(dir, { recursive: true })).filter((file) => file.endsWith('.ts')).sort()) {
    const code = await readFile(join(dir, name), 'utf8');
    for (const [, fn, context, first, second] of code.matchAll(CALL)) {
      if (fn === 'tn') add(strings, unescape(context), unescape(second), [unescape(first), unescape(second)]);
      else add(strings, unescape(context), unescape(first));
    }
  }
  const html = await readFile(join(dir, 'app', 'template.html'), 'utf8');
  for (const [, , context, inner] of html.matchAll(/<(\w+)\b[^>]*\sdata-i18n="([\w-]+)"[^>]*>([\s\S]*?)<\/\1>/g)) {
    const text = inner.replace(/<(\w+)\b[^>]*\sdata-slot="(\w+)"[^>]*>[\s\S]*?<\/\1>/g, '{$2}').replace(/<[^>]+>/g, '');
    add(strings, context, decode(text).replace(/\s+/g, ' ').trim());
  }
  for (const [tag] of html.matchAll(/<\w+\b[^>]*\sdata-i18n-attr="[\w-]+"[^>]*>/g)) {
    const context = /data-i18n-attr="([\w-]+)"/.exec(tag)[1];
    for (const attribute of ATTRIBUTES) {
      const value = new RegExp(String.raw`\s${attribute}="([^"]*)"`).exec(tag)?.[1];
      if (value) add(strings, context, decode(value));
    }
  }
  return strings;
}

export async function dictionaries() {
  const dir = join(root, 'src', 'locales');
  const out = {};
  for (const name of (await readdir(dir).catch(() => [])).filter((file) => file.endsWith('.json')).sort()) {
    out[name.replace(/\.json$/, '')] = JSON.parse(await readFile(join(dir, name), 'utf8'));
  }
  return out;
}

export function compare(strings, dictionary) {
  const missing = {};
  const unused = [];
  for (const [context, texts] of Object.entries(strings)) {
    for (const [text, forms] of Object.entries(texts)) {
      if (dictionary[context]?.[text] === undefined) {
        missing[context] ??= {};
        missing[context][text] = forms ? { one: forms[0], other: forms[1] } : text;
      }
    }
  }
  for (const [context, texts] of Object.entries(dictionary)) {
    for (const text of Object.keys(texts)) if (strings[context]?.[text] === undefined) unused.push(`${context} / ${text}`);
  }
  return { missing, unused };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const strings = await extract();
  const total = Object.values(strings).reduce((n, texts) => n + Object.keys(texts).length, 0);
  const all = await dictionaries();
  if (!Object.keys(all).length) console.log(`${total} strings in ${Object.keys(strings).length} contexts; no dictionaries yet (English only).`);
  for (const [language, dictionary] of Object.entries(all)) {
    const { missing, unused } = compare(strings, dictionary);
    const count = Object.values(missing).reduce((n, texts) => n + Object.keys(texts).length, 0);
    console.log(`${language}: ${count} missing, ${unused.length} unused`);
    if (count) console.log(JSON.stringify(missing, null, 2));
    for (const line of unused) console.log(`  unused: ${line}`);
  }
}

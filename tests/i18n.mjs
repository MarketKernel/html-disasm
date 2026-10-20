/**
 * Translations: the lookup in src/core/i18n.ts; every string the interface
 * shows found by the extractor (so plain literals are used); and every
 * dictionary in src/locales complete — nothing missing, nothing stale, the
 * same placeholders as the English text, a form for every plural category
 * of the language.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';
import { compare, dictionaries, extract } from '../tools/i18n.mjs';

const { check, done } = checker();
const I = await load('core/i18n');
const strings = await extract();
const all = await dictionaries();
const placeholders = (text) => [...new Set(text.match(/\{\w+\}/g) ?? [])].sort();

check('a dictionary per language', Object.keys(all).sort(), Object.keys(I.LANGUAGES).filter((code) => code !== 'en').sort());

for (const [language, dictionary] of Object.entries(all)) {
  const { missing, unused } = compare(strings, dictionary);
  check(`${language}: nothing missing`, Object.entries(missing).flatMap(([c, texts]) => Object.keys(texts).map((text) => `${c} / ${text}`)), []);
  check(`${language}: no unused strings`, unused, []);
  const categories = new Intl.PluralRules(language).resolvedOptions().pluralCategories.slice().sort();
  const problems = [];
  for (const [context, texts] of Object.entries(dictionary)) {
    for (const [text, value] of Object.entries(texts)) {
      const forms = strings[context]?.[text];
      if (forms === undefined) continue;
      const expected = placeholders(text);
      if (forms === null) {
        if (typeof value !== 'string' || !value.trim()) problems.push(`${context} / ${text}: not a text`);
        else if (JSON.stringify(placeholders(value)) !== JSON.stringify(expected)) problems.push(`${context} / ${text}: placeholders ${placeholders(value)}`);
        continue;
      }
      if (!value || typeof value !== 'object') {
        problems.push(`${context} / ${text}: plural forms expected`);
        continue;
      }
      if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(categories)) problems.push(`${context} / ${text}: forms ${Object.keys(value)}, the language has ${categories}`);
      for (const [category, form] of Object.entries(value)) {
        const got = placeholders(form);
        if (!got.every((name) => expected.includes(name)) || !expected.filter((n) => n !== '{count}').every((name) => got.includes(name))) {
          problems.push(`${context} / ${text} [${category}]: placeholders ${got}`);
        }
      }
    }
  }
  check(`${language}: well-formed translations`, problems, []);
  // JSON.parse keeps the last of two equal keys silently: each context must appear once.
  const raw = readFileSync(join(root, 'src', 'locales', `${language}.json`), 'utf8');
  const contexts = [...raw.matchAll(/^ {2}"([^"]+)": \{/gm)].map((m) => m[1]);
  check(`${language}: each context once`, contexts.length, new Set(contexts).size);
}

// The lookup.
check('english by default', I.t('menu', 'Settings'), 'Settings');
check('placeholders filled', I.t('open', 'Reading {name}', { name: 'a.out' }), 'Reading a.out');
check('plural one', I.tn('listing', '{count} instruction', '{count} instructions', 1), '1 instruction');
check('plural other', I.tn('listing', '{count} instruction', '{count} instructions', 2039761), '2,039,761 instructions');
check('detect falls back to English', I.detectLanguage(['xx-YY']), 'en');
check('detect Russian', I.detectLanguage(['ru-RU', 'en']), 'ru');
I.setLanguage('ru');
check('russian', I.t('menu', 'Settings'), 'Настройки');
check('russian plural: one', I.tn('listing', '{count} instruction', '{count} instructions', 21), '21 инструкция');
check('russian plural: few', I.tn('listing', '{count} instruction', '{count} instructions', 3), '3 инструкции');
check('russian plural: many', I.tn('listing', '{count} instruction', '{count} instructions', 11), '11 инструкций');
check('russian placeholder', I.t('open', 'Reading {name}', { name: 'a.out' }), 'Читаю a.out');
check('a missing string stays English', I.t('menu', 'No such string'), 'No such string');
I.setLanguage('en');

// t() with anything but literals would hide the string from translators.
const offenders = [];
// Every file but the one that defines them.
for (const file of readdirSync(join(root, 'src'), { recursive: true }).filter((f) => f.endsWith('.ts') && !f.endsWith('i18n.ts')).map((f) => join('src', f))) {
  const code = readFileSync(join(root, file), 'utf8');
  for (const [call] of code.matchAll(/\btn?\(\s*[^'\s)]/g)) offenders.push(`${file}: ${call}`);
}
check('t() and tn() take literals', offenders, []);

done('i18n');

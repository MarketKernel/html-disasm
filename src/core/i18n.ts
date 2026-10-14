/**
 * Interface languages: English and Russian.
 *
 * The English text stays in the code: t() takes a context — the part of the
 * interface a string belongs to — and the English text, both as plain
 * string literals; tn() takes the English singular and plural and a number.
 * The translation is looked up in the dictionary of the chosen language,
 * src/locales/<code>.json:
 *
 *   { "context": { "English text": "translation", … }, … }
 *
 * A translation that depends on a number is an object with one text per
 * plural category of the language (Intl.PluralRules: one, few, many, other),
 * keyed by the English plural form. Whatever a dictionary lacks is shown in
 * English. In the page's markup, `data-i18n="context"` translates an
 * element's text (a child marked `data-slot="name"` stands in it as `{name}`)
 * and `data-i18n-attr="context"` its title, placeholder and aria-label.
 *
 * The instruction catalogue and the HLA64 words have their translations
 * beside them (src/data/*.ru.json); src/core/catalog.ts picks the language.
 */

import ru from '../locales/ru.json';

/** Each language named in itself. */
export const LANGUAGES = {
  en: 'English',
  ru: 'Русский',
} as const;

export type Language = keyof typeof LANGUAGES;

type Forms = Partial<Record<Intl.LDMLPluralRule, string>>;
export type Dictionary = Record<string, Record<string, string | Forms>>;

const DICTIONARIES: Partial<Record<Language, Dictionary>> = { ru: ru as Dictionary };
const RIGHT_TO_LEFT = new Set<string>(['ar', 'ur', 'he', 'fa']);

let current: Language = 'en';
let rules = new Intl.PluralRules('en');

export function isLanguage(value: unknown): value is Language {
  return typeof value === 'string' && Object.hasOwn(LANGUAGES, value);
}

/** The first of the browser's languages that has a dictionary; English otherwise. */
export function detectLanguage(preferred: readonly string[] = typeof navigator === 'undefined' ? [] : navigator.languages): Language {
  for (const tag of preferred) {
    const base = tag.toLowerCase().split('-')[0];
    if (isLanguage(base)) return base;
  }
  return 'en';
}

export function language(): Language {
  return current;
}

export function setLanguage(next: Language): void {
  current = next;
  rules = new Intl.PluralRules(next);
  if (typeof document === 'undefined') return;
  document.documentElement.lang = next;
  document.documentElement.dir = RIGHT_TO_LEFT.has(next) ? 'rtl' : 'ltr';
}

type Values = Record<string, string | number>;

function fill(text: string, values?: Values): string {
  if (!values) return text;
  return text.replace(/\{(\w+)\}/g, (match, name: string) => (Object.hasOwn(values, name) ? String(values[name]) : match));
}

export function t(context: string, text: string, values?: Values): string {
  const found = DICTIONARIES[current]?.[context]?.[text];
  return fill(typeof found === 'string' && found ? found : text, values);
}

export function tn(context: string, one: string, other: string, count: number, values?: Values): string {
  const found = DICTIONARIES[current]?.[context]?.[other];
  const all = { count: count.toLocaleString(current), ...values };
  if (typeof found === 'string' && found) return fill(found, all);
  if (found && typeof found === 'object') {
    const form = found[rules.select(count)] ?? found.other;
    if (form) return fill(form, all);
  }
  return fill(count === 1 ? one : other, all);
}

/** Numbers in the interface language: 2,039,761. */
export function n(value: number): string {
  return value.toLocaleString(current);
}

const ATTRIBUTES = ['title', 'placeholder', 'aria-label'] as const;

interface Source {
  text: string;
  slots: Map<string, Element>;
}

const contents = new WeakMap<Element, Source>();
const attributes = new WeakMap<Element, Partial<Record<(typeof ATTRIBUTES)[number], string>>>();

/** The English text of a `data-i18n` element, as the dictionaries key it. */
export function sourceOf(element: Element): Source {
  let source = contents.get(element);
  if (!source) {
    const slots = new Map<string, Element>();
    let text = '';
    for (const node of Array.from(element.childNodes)) {
      const slot = node instanceof Element ? node.getAttribute('data-slot') : null;
      if (slot && node instanceof Element) {
        slots.set(slot, node);
        text += `{${slot}}`;
      } else text += node.textContent ?? '';
    }
    source = { text: text.replace(/\s+/g, ' ').trim(), slots };
    contents.set(element, source);
  }
  return source;
}

export function translatePage(root: ParentNode = document): void {
  for (const element of Array.from(root.querySelectorAll('[data-i18n]'))) {
    const context = element.getAttribute('data-i18n') ?? '';
    const { text, slots } = sourceOf(element);
    const parts = t(context, text).split(/(\{\w+\})/);
    element.replaceChildren(...parts.filter(Boolean).map((part) => slots.get(part.slice(1, -1)) ?? document.createTextNode(part)));
  }
  for (const element of Array.from(root.querySelectorAll('[data-i18n-attr]'))) {
    const context = element.getAttribute('data-i18n-attr') ?? '';
    let source = attributes.get(element);
    if (!source) {
      source = {};
      for (const name of ATTRIBUTES) {
        const value = element.getAttribute(name);
        if (value) source[name] = value;
      }
      attributes.set(element, source);
    }
    for (const [name, value] of Object.entries(source)) element.setAttribute(name, t(context, value));
  }
}

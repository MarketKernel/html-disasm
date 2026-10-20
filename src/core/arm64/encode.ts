/**
 * The AArch64 assembler: one line of text in, one 32-bit word out — the
 * reverse of the decoder, for patching an instruction in place.
 *
 * The assembler is in the core (crates/core/src/arm64/encode.rs): it reads the
 * syntax the decoder prints and the spellings people type besides, and checks
 * every word by decoding it again and comparing meanings. What is here asks it,
 * answers the names it meets (functions, labels, symbols used as targets) in
 * rounds (../hla.ts), and words its errors in the page's language.
 */

import { engine } from '../engine/engine';
import { rounds } from '../hla';
import { t } from '../i18n';

export interface Assembled {
  word: number;
}

export interface AssembleError {
  /** Already translated. */
  error: string;
}

/** What the core answers: the word, or why there is none and what the message names. */
interface Result {
  word?: number;
  error?: string;
  text?: string;
  value?: string;
  size?: string;
  distance?: string;
  name?: string;
  mnemonic?: string;
}

function message(r: Result): string {
  switch (r.error) {
    case 'empty':
      return t('assemble', 'Enter an instruction.');
    case 'unreadable':
      return t('assemble', 'Cannot read “{text}”.', { text: r.text ?? '' });
    case 'unsupported':
      return t('assemble', 'This instruction cannot be assembled here; enter its encoding in hex instead.');
    case 'immediate':
      return t('assemble', 'The immediate {value} cannot be encoded here.', { value: r.value ?? '' });
    case 'offset':
      return t('assemble', 'The offset {value} is out of range.', { value: r.value ?? '' });
    case 'multiple':
      return t('assemble', 'The offset {value} is not a multiple of {size}.', { value: r.value ?? '', size: Number(r.size) });
    case 'unpredictable':
      return t('assemble', 'Arm leaves the result of this combination of registers unpredictable.');
    case 'align':
      return t('assemble', 'The target is not a multiple of 4 bytes away.');
    case 'far':
      return t('assemble', 'The target is too far: {distance} bytes away.', { distance: r.distance ?? '' });
    case 'name':
      return t('assemble', 'Unknown name: {name}.', { name: r.name ?? '' });
    case 'differs':
      return t('assemble', 'This assembles to “{text}”, not to what was entered; enter the encoding in hex instead.', { text: r.text ?? '' });
  }
  return t('assemble', 'The operands do not fit {mnemonic}.', { mnemonic: r.mnemonic ?? '' });
}

/**
 * One instruction in the syntax the decoder prints, to be placed at `pc`.
 * `resolve` gives the address of a name — a function, a label, a symbol —
 * where the text uses one as a branch or address target.
 */
export function assemble(text: string, pc: number, resolve?: (name: string) => number | undefined): Assembled | AssembleError {
  const e = engine();
  const r = rounds<Result>(
    (input, _kind, _addr, name) => input.f64(resolve?.(name ?? '') ?? NaN),
    (input) => input.text(text),
    (input) => e.arm64Assemble(pc, input),
  );
  return r.word !== undefined ? { word: r.word } : { error: message(r) };
}

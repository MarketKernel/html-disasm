/**
 * What an instruction takes from the stack and puts back, for the analysis
 * (which instructions join into one HLA64 line) and for the HLA64 view
 * (which builds the expressions). Calls, blocks and a few GC instructions
 * depend on the module's types; branches are left to the caller, which knows
 * the labels.
 */

import type { WasmInsn } from './decode';
import type { FuncType, TypeDef } from './module';
import { W, type OpInfo } from './opcodes';

export interface EffectContext {
  /** The type of a function, by its index. */
  funcType(func: number): FuncType | undefined;
  typeDef(type: number): TypeDef | undefined;
  /** The parameters of a tag, for throw. */
  tagParams(tag: number): number;
}

const counts = new Map<OpInfo, [number, number]>();

/** pops and pushes of an instruction with a fixed signature, from `a b > c`; undefined when it has none. */
function fixed(op: OpInfo): [number, number] | undefined {
  if (!op.sig) return undefined;
  let found = counts.get(op);
  if (!found) {
    const [left, right] = op.sig.split('>') as [string, string];
    const n = (side: string) => side.trim().split(/\s+/).filter(Boolean).length;
    found = [n(left), n(right)];
    counts.set(op, found);
  }
  return found;
}

/**
 * pops and pushes of a plain instruction — anything but the structure
 * (block, loop, if, else, end, try…) and the branches (br, br_if, br_table,
 * br_on_*, return), which the caller handles — or null when it cannot tell.
 */
export function effect(insn: WasmInsn, ctx: EffectContext): [number, number] | null {
  const op = insn.op;
  if (!op || op.flags & W.STRUCTURE) return null;
  const known = fixed(op);
  if (known) return known;
  switch (insn.m) {
    case 'call':
    case 'return_call': {
      const type = ctx.funcType(insn.a);
      if (!type) return null;
      return [type.params.length, insn.m === 'call' ? type.results.length : 0];
    }
    case 'call_indirect':
    case 'return_call_indirect':
    case 'call_ref':
    case 'return_call_ref': {
      const type = ctx.typeDef(insn.a)?.func;
      if (!type) return null;
      return [type.params.length + 1, insn.m.startsWith('return') ? 0 : type.results.length];
    }
    case 'struct.new': {
      const def = ctx.typeDef(insn.a);
      return def?.fields ? [def.fields.length, 1] : null;
    }
    case 'array.new_fixed':
      return [insn.b, 1];
    case 'throw':
      return [ctx.tagParams(insn.a), 0];
    case 'unreachable':
      return [0, 0];
  }
  return null;
}

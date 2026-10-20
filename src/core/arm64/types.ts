/**
 * A decoded AArch64 instruction.
 *
 * The decoder keeps operands structured, not only as text: the listing prints
 * them, but the HLA64 view and the analysis (branch targets, adrp pairs,
 * string references) read registers, offsets and addressing modes from them.
 * Immediates carry the exact text LLVM's disassembler prints (hex for most,
 * decimal for shift amounts and bit positions), so the listing can be checked
 * against llvm-objdump line by line.
 */

export type Op =
  | { k: 'reg'; r: string }
  | { k: 'imm'; v: number; t: string }
  | { k: 'label'; addr: number }
  | { k: 'mem'; base: string; off: number; index?: string; ext?: string; amount?: number; showAmount?: boolean; mode: 'off' | 'pre' | 'post'; post?: string; decimal?: boolean }
  | { k: 'shift'; s: string; amount: number; t: string }
  | { k: 'text'; t: string };

/** What an instruction does to control flow and memory, for the analysis. */
export const F = {
  BRANCH: 1, // changes the PC: b, b.cond, cbz, tbz, br, ret, …
  COND: 2, // only sometimes (b.cond, cbz, tbz)
  CALL: 4, // bl, blr
  RET: 8, // ret and its pointer-authenticated forms
  INDIRECT: 16, // target in a register: br, blr, ret
  LOAD: 32,
  STORE: 64,
  SETS_FLAGS: 128,
  READS_FLAGS: 256,
  TRAP: 512, // brk, udf, hlt: execution does not continue
  UNKNOWN: 1024, // not an instruction the decoder knows
  ATOMIC: 2048,
} as const;

export interface Insn {
  /** As printed: add, b.ne, ld1, mov. */
  m: string;
  ops: Op[];
  f: number;
  /** Branch, adr/adrp or literal-load target. */
  target?: number;
  /** The condition of b.cond, csel, ccmp…: eq, ne, lt… */
  cond?: string;
  /** Bytes a load or store moves per register (1, 2, 4, 8, 16). */
  size?: number;
  /** A load that sign-extends (ldrsb, ldrsw, …). */
  signed?: boolean;
}

export const CONDITIONS = ['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv'] as const;

const hex = (v: number | bigint): string => (v < 0 ? `-0x${(-v).toString(16)}` : `0x${v.toString(16)}`);

export const imm = (v: number, decimal = false): Op => ({ k: 'imm', v, t: decimal ? `#${v}` : `#${hex(v)}` });
export const immText = (v: number, t: string): Op => ({ k: 'imm', v, t });
export const reg = (r: string): Op => ({ k: 'reg', r });
export const text = (t: string): Op => ({ k: 'text', t });
export const shift = (s: string, amount: number, hexAmount = false): Op => ({ k: 'shift', s, amount, t: `${s} #${hexAmount ? hex(amount) : amount}` });
export { hex };

export function formatOp(op: Op): string {
  switch (op.k) {
    case 'reg':
      return op.r;
    case 'imm':
      return op.t;
    case 'label':
      return hex(op.addr);
    case 'shift':
      return op.t;
    case 'text':
      return op.t;
    case 'mem': {
      // A few RCpc forms with a fixed writeback amount print it in decimal.
      const off = op.decimal ? String(op.off) : hex(op.off);
      let inner = op.base;
      if (op.index) {
        inner += `, ${op.index}`;
        if (op.ext) inner += op.showAmount ? `, ${op.ext} #${op.amount ?? 0}` : `, ${op.ext}`;
      } else if (op.off !== 0 && op.mode !== 'post') {
        inner += `, #${off}`;
      } else if (op.mode === 'pre') {
        inner += `, #${off}`;
      }
      if (op.mode === 'pre') return `[${inner}]!`;
      if (op.mode === 'post') return `[${inner}], ${op.post ?? `#${off}`}`;
      return `[${inner}]`;
    }
  }
}

export function formatInsn(insn: Insn): string {
  if (!insn.ops.length) return insn.m;
  return `${insn.m} ${insn.ops.map(formatOp).join(', ')}`;
}

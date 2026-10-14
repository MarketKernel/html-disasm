/**
 * x86 instructions printed as LLVM's Intel printer prints them
 * (X86IntelInstPrinter and the parts it shares with the AT&T one), so a
 * line here is the line llvm-objdump -M intel prints, up to whitespace.
 *
 * Each instruction's template (tables.ts) is the Intel half of its
 * assembly string with every operand replaced by the MCInst operand it
 * prints and the method that prints it. Before the template come the
 * prefixes the printer writes on its own (lock, rep, notrack, {vex},
 * addr32); a few instructions print as an alias, and the vector compares
 * with the predicate folded into the mnemonic (cmpltps, vpcmpgtd).
 */

import { INFO, PFX, x86Tables, type McOp, type X86Decoded } from './decode';
import { ALIASES, PRINT_METHODS, SPECIAL, SUFFIXES, XACQUIRE, XRELEASE } from './tables';

export interface X86Printed {
  /** What the printer writes before the instruction: `lock`, `rep`, `notrack`, `{vex}`, `addr32`, joined by spaces. */
  prefix: string;
  /** The mnemonic: `mov`, `jne`, `cmpltps`, `vpaddd`. */
  m: string;
  /** The operands as printed: `qword ptr [rbp - 0x8], rdi`. */
  ops: string;
}

/** LLVM's formatImm in hex: `0x1f`, `-0x80`. */
export function formatImm(v: number | bigint): string {
  if (typeof v === 'bigint') {
    const s = BigInt.asIntN(64, v);
    return s < 0n ? `-0x${(-s).toString(16)}` : `0x${s.toString(16)}`;
  }
  return v < 0 ? `-0x${(-v).toString(16)}` : `0x${v.toString(16)}`;
}

/** An unsigned 64-bit address in hex, as formatHex(uint64_t) prints it. */
export function formatAddress(v: number): string {
  return v < 0 ? `0x${BigInt.asUintN(64, BigInt(v)).toString(16)}` : `0x${v.toString(16)}`;
}

const CONDITIONS = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g'];
const SSE_AVX_CC = ['eq', 'lt', 'le', 'unord', 'neq', 'nlt', 'nle', 'ord', 'eq_uq', 'nge', 'ngt', 'false', 'neq_oq', 'ge', 'gt', 'true', 'eq_os', 'lt_oq', 'le_oq', 'unord_s', 'neq_us', 'nlt_uq', 'nle_uq', 'ord_s', 'eq_us', 'nge_uq', 'ngt_uq', 'false_os', 'neq_os', 'ge_oq', 'gt_oq', 'true_us'];
const VPCOM_CC = ['lt', 'le', 'gt', 'ge', 'eq', 'neq', 'false', 'true'];
const ROUNDING = ['{rn-sae}', '{rd-sae}', '{ru-sae}', '{rz-sae}'];
const GR16 = new Set(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', ...Array.from({ length: 24 }, (_, i) => `r${i + 8}w`)]);
const GR32 = new Set(['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', ...Array.from({ length: 24 }, (_, i) => `r${i + 8}d`)]);

/** A template, parsed: literal text, or [MCInst operand, print method]. */
type Part = string | [number, number];
const parsed = new Map<number, Part[]>();

function templateParts(index: number): Part[] {
  let parts = parsed.get(index);
  if (parts) return parts;
  const text = x86Tables().templates[index] ?? '';
  parts = [];
  let literal = '';
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 1) {
      if (literal) parts.push(literal);
      literal = '';
      parts.push([text.charCodeAt(i + 1) - 65, text.charCodeAt(i + 2) - 65]);
      i += 2;
    } else literal += text[i];
  }
  if (literal) parts.push(literal);
  parsed.set(index, parts);
  return parts;
}

const MEM_SIZE: Record<string, string> = {
  printbytemem: 'byte ptr ', printwordmem: 'word ptr ', printdwordmem: 'dword ptr ', printqwordmem: 'qword ptr ', printxmmwordmem: 'xmmword ptr ',
  printymmwordmem: 'ymmword ptr ', printzmmwordmem: 'zmmword ptr ', printtbytemem: 'tbyte ptr ', printMemReference: '',
};
const SIZE_OF_SUFFIX: Record<string, string> = { '8': 'byte ptr ', '16': 'word ptr ', '32': 'dword ptr ', '64': 'qword ptr ' };

class Printer {
  constructor(readonly d: X86Decoded) {}

  get ops(): McOp[] {
    return this.d.ops;
  }

  operand(i: number): string {
    const op = this.ops[i];
    if (typeof op === 'string') return op;
    return op === undefined ? '' : formatImm(op);
  }

  memory(i: number): string {
    const ops = this.ops;
    const base = ops[i] as string;
    const scale = ops[i + 1] as number;
    const index = ops[i + 2] as string;
    let disp = ops[i + 3] as number;
    const seg = ops[i + 4] as string;
    let s = seg ? `${seg}:[` : '[';
    let plus = false;
    if (base) {
      s += base;
      plus = true;
    }
    if (index) {
      if (plus) s += ' + ';
      if (scale !== 1 || !base) s += `${scale}*`;
      s += index;
      plus = true;
    }
    if (disp || (!index && !base)) {
      if (plus) {
        if (disp > 0) s += ' + ';
        else {
          s += ' - ';
          disp = -disp;
        }
      }
      s += formatImm(disp);
    }
    return `${s}]`;
  }

  method(method: number, i: number): string {
    const name = PRINT_METHODS[method]!;
    const mem = MEM_SIZE[name];
    if (mem !== undefined) return mem + this.memory(i);
    const ops = this.ops;
    switch (name) {
      case 'printOperand':
        return this.operand(i);
      case 'printU8Imm':
        return formatImm(Number(ops[i]) & 0xff);
      case 'printPCRelImm': {
        let target = this.d.addr + this.d.length + Number(ops[i]);
        if (this.d.mode === 32) target = target >>> 0;
        return formatAddress(target);
      }
      case 'printSTiRegOperand':
        return ops[i] === 'st' ? 'st(0)' : this.operand(i);
      case 'printCondCode': {
        const cc = Number(ops[i]);
        if (x86Tables().info[this.d.id]! & INFO.CCMP && (cc === 10 || cc === 11)) return cc === 10 ? 't' : 'f';
        return CONDITIONS[cc] ?? '';
      }
      case 'printCondFlags': {
        const v = Number(ops[i]);
        const flags = [v & 8 ? 'of' : '', v & 4 ? 'sf' : '', v & 2 ? 'zf' : '', v & 1 ? 'cf' : ''].filter(Boolean);
        return `{dfv=${flags.join(',')}}`;
      }
      case 'printRoundingControl':
        return ROUNDING[Number(ops[i]) & 3]!;
      case 'printVKPair':
      case 'printTILEPair':
        // A pair prints as its first register: K2_K3 as k2.
        return String(ops[i]).split('_')[0]!.toLowerCase();
    }
    let m = /^printMemOffs(\d+)$/.exec(name);
    if (m) {
      const seg = ops[i + 1] as string;
      return `${SIZE_OF_SUFFIX[m[1]!]}${seg ? `${seg}:` : ''}[${formatImm(ops[i] as number | bigint)}]`;
    }
    m = /^printSrcIdx(\d+)$/.exec(name);
    if (m) {
      const seg = ops[i + 1] as string;
      return `${SIZE_OF_SUFFIX[m[1]!]}${seg ? `${seg}:` : ''}[${this.operand(i)}]`;
    }
    m = /^printDstIdx(\d+)$/.exec(name);
    if (m) return `${SIZE_OF_SUFFIX[m[1]!]}es:[${this.operand(i)}]`;
    throw new Error(`x86 printer: no method ${name}`);
  }

  /** X86_MC::needsAddressSizeOverride: whether 67 is already implied by the operands (so addr32 is not printed). */
  addressSizeImplied(info: number): boolean {
    const mode = this.d.mode;
    const adsize = (info >> INFO.ADSIZE_SHIFT) & 3;
    if ((mode === 32 && adsize === 1) || (mode === 64 && adsize === 2)) return true;
    const raw = (info >> INFO.RAW_SHIFT) & 3;
    const ops = this.ops;
    if (raw === 1) return (mode !== 32 && ops[1] === 'esi') || (mode === 32 && ops[1] === 'si');
    if (raw === 2) return (mode !== 32 && ops[0] === 'esi') || (mode === 32 && ops[0] === 'si');
    if (raw === 3) return (mode !== 32 && ops[0] === 'edi') || (mode === 32 && ops[0] === 'di');
    const at = (info >> INFO.MEMOP_SHIFT) & 15;
    if (at === 15) return false;
    const base = ops[at];
    const index = ops[at + 2];
    if (mode === 64) {
      if (base === 'eip') return true;
      if (index === 'eiz') return true;
      return (typeof base === 'string' && GR32.has(base)) || (typeof index === 'string' && GR32.has(index));
    }
    return (typeof base === 'string' && GR16.has(base)) || (typeof index === 'string' && GR16.has(index));
  }

  /** X86IntelInstPrinter::printVecCompareInstr, or undefined when it does not apply. */
  vectorCompare(info: number): string | undefined {
    const kind = (info >> INFO.VCMP_SHIFT) & 7;
    if (!kind) return undefined;
    const ops = this.ops;
    const last = ops[ops.length - 1];
    if (!ops.length || typeof last === 'string') return undefined;
    const imm = Number(last);
    const suffix = SUFFIXES[(info >>> INFO.SUFFIX_SHIFT) & 15]!;
    const srcMem = !!(info & INFO.SRCMEM);
    const has = (bit: number) => !!(info & bit);
    if (kind === 1) {
      if (imm < 0 || imm > 7) return undefined;
      const mem = has(INFO.XS) ? 'dword ptr ' : has(INFO.XD) ? 'qword ptr ' : 'xmmword ptr ';
      return `cmp${SSE_AVX_CC[imm]}${suffix}\t${this.operand(0)}, ${srcMem ? mem + this.memory(2) : this.operand(2)}`;
    }
    if (kind === 3) {
      if (imm < 0 || imm > 7) return undefined;
      return `vpcom${VPCOM_CC[imm]}${suffix}\t${this.operand(0)}, ${this.operand(1)}, ${srcMem ? `xmmword ptr ${this.memory(2)}` : this.operand(2)}`;
    }
    if (kind === 2 ? imm < 0 || imm > 31 : !((imm >= 0 && imm <= 2) || (imm >= 4 && imm <= 6))) return undefined;
    let s = `${kind === 2 ? 'vcmp' : 'vpcmp'}${SSE_AVX_CC[imm]}${suffix}\t`;
    let cur = 0;
    s += this.operand(cur++);
    if (has(INFO.EVEX_K)) s += ` {${this.operand(cur++)}}`;
    s += `, ${this.operand(cur++)}, `;
    const w = has(INFO.REX_W);
    const ta = kind === 2 && has(INFO.TA);
    if (srcMem) {
      if (has(INFO.EVEX_B)) {
        s += (ta ? 'word ptr ' : w ? 'qword ptr ' : 'dword ptr ') + this.memory(cur);
        let elements = has(INFO.EVEX_L2) ? (w ? 8 : 16) : has(INFO.VEX_L) ? (w ? 4 : 8) : w ? 2 : 4;
        if (ta) elements *= 2;
        s += `{1to${elements}}`;
      } else if (kind === 2 && has(INFO.XS)) s += (ta ? 'word ptr ' : 'dword ptr ') + this.memory(cur);
      else if (kind === 2 && has(INFO.XD) && !ta) s += `qword ptr ${this.memory(cur)}`;
      else s += (has(INFO.EVEX_L2) ? 'zmmword ptr ' : has(INFO.VEX_L) ? 'ymmword ptr ' : 'xmmword ptr ') + this.memory(cur);
    } else {
      s += this.operand(cur);
      if (kind === 2 && has(INFO.EVEX_B)) s += ', {sae}';
    }
    return s;
  }

  print(): X86Printed {
    const d = this.d;
    const t = x86Tables();
    const info = t.info[d.id]!;
    const prefixes: string[] = [];
    if (info & INFO.LOCK || d.flags & PFX.LOCK) prefixes.push('lock');
    if (info & INFO.NOTRACK) prefixes.push('notrack');
    if (d.flags & PFX.REPEAT_NE) prefixes.push('repne');
    else if (d.flags & PFX.REPEAT) prefixes.push('rep');
    if (info & INFO.NF) prefixes.push('{nf}');
    if (info & INFO.EXPLICIT_VEX) prefixes.push('{vex}');
    else if (info & INFO.EXPLICIT_EVEX) prefixes.push('{evex}');
    if (d.flags & PFX.AD_SIZE && !this.addressSizeImplied(info)) prefixes.push(d.mode === 64 ? 'addr32' : 'addr16');

    let text: string | undefined;
    if (d.xacquire) text = d.id === SPECIAL.REP_PREFIX ? XRELEASE : XACQUIRE;
    for (const [id, conds, alias] of ALIASES) if (text === undefined && id === d.id && conds.every(([at, value]) => Number(d.ops[at]) === value && typeof d.ops[at] !== 'string')) text = alias;
    text ??= this.vectorCompare(info);
    if (text === undefined) {
      text = '';
      for (const part of templateParts(t.template[d.id]!)) text += typeof part === 'string' ? part : this.method(part[1], part[0]);
    }
    const tab = text.indexOf('\t');
    const m = tab < 0 ? text : text.slice(0, tab);
    const ops = tab < 0 ? '' : text.slice(tab + 1).replace(/\t/g, ' ').trim();
    return { prefix: prefixes.join(' '), m, ops };
  }
}

/** How an instruction prints; one that did not decode prints as LLVM's `<unknown>`. */
export function printX86(d: X86Decoded): X86Printed {
  if (!d.id) return { prefix: '', m: '<unknown>', ops: '' };
  return new Printer(d).print();
}

/** The whole line, with single spaces: `lock cmpxchg qword ptr [rdi], rcx`. */
export function formatX86(p: X86Printed): string {
  return [p.prefix, p.m, p.ops].filter(Boolean).join(' ');
}

/** The mnemonic of each template whose mnemonic is plain text (most are); conditions make the rest. */
const literalMnemonic = new Map<number, string | null>();

/** Only the mnemonic, as printX86 would print it: cheaper, for counting every instruction. */
export function mnemonicX86(d: X86Decoded): string {
  if (!d.id) return '<unknown>';
  const t = x86Tables();
  const template = t.template[d.id]!;
  let literal = literalMnemonic.get(template);
  if (literal === undefined) {
    const first = templateParts(template)[0];
    literal = typeof first === 'string' && (first.includes('\t') || templateParts(template).length === 1) ? first.split('\t')[0]! : null;
    literalMnemonic.set(template, literal);
  }
  const info = t.info[d.id]!;
  if (literal !== null && !d.xacquire && !((info >> INFO.VCMP_SHIFT) & 7) && !ALIASES.some(([id]) => id === d.id)) return literal;
  return printX86(d).m;
}

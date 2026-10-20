/**
 * x86 instructions printed as LLVM's Intel printer prints them
 * (X86IntelInstPrinter and the parts it shares with the AT&T one), so a
 * line here is the line llvm-objdump -M intel prints, up to whitespace.
 *
 * The printer is in the Rust core (crates/core/src/x86/print.rs), which
 * prints an instruction as it decodes it: decodeX86 hands over both.
 */

import type { X86Decoded } from './decode';

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

/** How an instruction prints; one that did not decode prints as LLVM's `<unknown>`. */
export function printX86(d: X86Decoded): X86Printed {
  if (!d.id) return { prefix: '', m: '<unknown>', ops: '' };
  if (!d.printed) throw new Error('printX86: an instruction the core did not decode');
  return d.printed;
}

/** The whole line, with single spaces: `lock cmpxchg qword ptr [rdi], rcx`. */
export function formatX86(p: X86Printed): string {
  return [p.prefix, p.m, p.ops].filter(Boolean).join(' ');
}

/** Only the mnemonic, as printX86 prints it. */
export function mnemonicX86(d: X86Decoded): string {
  return printX86(d).m;
}

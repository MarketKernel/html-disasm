/**
 * Wraps raw AArch64 code in a minimal ELF relocatable file, so llvm-objdump
 * prints it in the generic Arm syntax (`cmeq v0.8b, v1.8b, v2.8b`) — for a
 * Mach-O file it switches to Apple's (`cmeq.8b v0, v1, v2`). The section is
 * placed at `address`, so branch targets print as the same absolute addresses
 * the disassembler shows.
 */
export function elfWrap(code, address) {
  const shstr = Buffer.from('\0.text\0.shstrtab\0', 'latin1');
  const textOff = 64;
  const textSize = code.length;
  const strOff = textOff + textSize;
  const shOff = (strOff + shstr.length + 7) & ~7;
  const out = Buffer.alloc(shOff + 3 * 64);
  out.write('\x7fELF', 0, 'latin1');
  out[4] = 2; // 64-bit
  out[5] = 1; // little endian
  out[6] = 1;
  out.writeUInt16LE(1, 16); // ET_REL
  out.writeUInt16LE(183, 18); // EM_AARCH64
  out.writeUInt32LE(1, 20);
  out.writeBigUInt64LE(BigInt(shOff), 40);
  out.writeUInt16LE(64, 52);
  out.writeUInt16LE(64, 58);
  out.writeUInt16LE(3, 60);
  out.writeUInt16LE(2, 62);
  Buffer.from(code.buffer, code.byteOffset, code.length).copy(out, textOff);
  shstr.copy(out, strOff);
  const section = (index, name, type, flags, addr, offset, size, align) => {
    const at = shOff + index * 64;
    out.writeUInt32LE(name, at);
    out.writeUInt32LE(type, at + 4);
    out.writeBigUInt64LE(BigInt(flags), at + 8);
    out.writeBigUInt64LE(BigInt(addr), at + 16);
    out.writeBigUInt64LE(BigInt(offset), at + 24);
    out.writeBigUInt64LE(BigInt(size), at + 32);
    out.writeBigUInt64LE(BigInt(align), at + 48);
  };
  section(1, 1, 1, 6, address, textOff, textSize, 4); // .text: PROGBITS, ALLOC|EXECINSTR
  section(2, 7, 3, 0, 0, strOff, shstr.length, 1); // .shstrtab
  return out;
}

/**
 * The same for AArch32 code: a 32-bit ELF relocatable file for EM_ARM, with
 * one mapping symbol at the start of .text — `$a` for A32, `$t` for T32 — so
 * llvm-objdump decodes the bytes in the right instruction set.
 */
export function elfWrap32(code, address, thumb) {
  const shstr = Buffer.from('\0.text\0.shstrtab\0.symtab\0.strtab\0', 'latin1');
  const strtab = Buffer.from(thumb ? '\0$t\0' : '\0$a\0', 'latin1');
  const textOff = 52;
  const symOff = (textOff + code.length + 3) & ~3;
  const strOff = symOff + 32;
  const shstrOff = strOff + strtab.length;
  const shOff = (shstrOff + shstr.length + 3) & ~3;
  const out = Buffer.alloc(shOff + 5 * 40);
  out.write('\x7fELF', 0, 'latin1');
  out[4] = 1; // 32-bit
  out[5] = 1; // little endian
  out[6] = 1;
  out.writeUInt16LE(1, 16); // ET_REL
  out.writeUInt16LE(40, 18); // EM_ARM
  out.writeUInt32LE(1, 20);
  out.writeUInt32LE(shOff, 32);
  out.writeUInt32LE(0x05000000, 36); // EABI version 5
  out.writeUInt16LE(52, 40);
  out.writeUInt16LE(40, 46);
  out.writeUInt16LE(5, 48);
  out.writeUInt16LE(2, 50);
  Buffer.from(code.buffer, code.byteOffset, code.length).copy(out, textOff);
  const symbol = symOff + 16; // symbol 1: the mapping symbol, local, in section 1
  out.writeUInt32LE(1, symbol);
  out.writeUInt32LE(address, symbol + 4);
  out.writeUInt16LE(1, symbol + 14);
  strtab.copy(out, strOff);
  shstr.copy(out, shstrOff);
  const section = (index, name, type, flags, addr, offset, size, link, info, align, entsize) => {
    const at = shOff + index * 40;
    for (const [i, v] of [name, type, flags, addr, offset, size, link, info, align, entsize].entries()) out.writeUInt32LE(v >>> 0, at + i * 4);
  };
  section(1, 1, 1, 6, address, textOff, code.length, 0, 0, 4, 0); // .text
  section(2, 7, 3, 0, 0, shstrOff, shstr.length, 0, 0, 1, 0); // .shstrtab
  section(3, 17, 2, 0, 0, symOff, 32, 4, 2, 4, 16); // .symtab
  section(4, 25, 3, 0, 0, strOff, strtab.length, 0, 0, 1, 0); // .strtab
  return out;
}

/**
 * The same for x86 code: an ELF relocatable file for EM_X86_64 (64-bit) or
 * EM_386 (32-bit), its .text at `address`, so llvm-objdump decodes it in
 * that mode and prints branch targets as the addresses the decoder computes.
 * A function symbol at each of `symbols` makes llvm-objdump start decoding
 * afresh there, as it does at every symbol.
 */
export function elfWrapX86(code, address, bits = 64, symbols = []) {
  const wide = bits === 64;
  const ehsize = wide ? 64 : 52;
  const shentsize = wide ? 64 : 40;
  const symsize = wide ? 24 : 16;
  const shstr = Buffer.from('\0.text\0.shstrtab\0.symtab\0.strtab\0', 'latin1');
  const names = symbols.map((_, i) => `f${i}`);
  const strtab = Buffer.from(`\0${names.join('\0')}\0`, 'latin1');
  const textOff = ehsize;
  const symOff = (textOff + code.length + 7) & ~7;
  const symCount = symbols.length + 1;
  const strOff = symOff + symCount * symsize;
  const shstrOff = strOff + strtab.length;
  const shOff = (shstrOff + shstr.length + 7) & ~7;
  const out = Buffer.alloc(shOff + 5 * shentsize);
  out.write('\x7fELF', 0, 'latin1');
  out[4] = wide ? 2 : 1;
  out[5] = 1;
  out[6] = 1;
  out.writeUInt16LE(1, 16); // ET_REL
  out.writeUInt16LE(wide ? 62 : 3, 18); // EM_X86_64, EM_386
  out.writeUInt32LE(1, 20);
  if (wide) out.writeBigUInt64LE(BigInt(shOff), 40);
  else out.writeUInt32LE(shOff, 32);
  out.writeUInt16LE(ehsize, wide ? 52 : 40);
  out.writeUInt16LE(shentsize, wide ? 58 : 46);
  out.writeUInt16LE(5, wide ? 60 : 48);
  out.writeUInt16LE(2, wide ? 62 : 50);
  Buffer.from(code.buffer, code.byteOffset, code.length).copy(out, textOff);
  let nameAt = 1;
  symbols.forEach((addr, i) => {
    const at = symOff + (i + 1) * symsize;
    out.writeUInt32LE(nameAt, at);
    nameAt += names[i].length + 1;
    if (wide) {
      out[at + 4] = 0x12; // global function
      out.writeUInt16LE(1, at + 6);
      out.writeBigUInt64LE(BigInt(addr), at + 8);
    } else {
      out.writeUInt32LE(addr >>> 0, at + 4);
      out[at + 12] = 0x12;
      out.writeUInt16LE(1, at + 14);
    }
  });
  strtab.copy(out, strOff);
  shstr.copy(out, shstrOff);
  const section = (index, name, type, flags, addr, offset, size, link, info, align, entsize) => {
    const at = shOff + index * shentsize;
    if (wide) {
      out.writeUInt32LE(name, at);
      out.writeUInt32LE(type, at + 4);
      out.writeBigUInt64LE(BigInt(flags), at + 8);
      out.writeBigUInt64LE(BigInt(addr), at + 16);
      out.writeBigUInt64LE(BigInt(offset), at + 24);
      out.writeBigUInt64LE(BigInt(size), at + 32);
      out.writeUInt32LE(link, at + 40);
      out.writeUInt32LE(info, at + 44);
      out.writeBigUInt64LE(BigInt(align), at + 48);
      out.writeBigUInt64LE(BigInt(entsize), at + 56);
    } else for (const [i, v] of [name, type, flags, addr, offset, size, link, info, align, entsize].entries()) out.writeUInt32LE(v >>> 0, at + i * 4);
  };
  section(1, 1, 1, 6, address, textOff, code.length, 0, 0, 16, 0); // .text
  section(2, 7, 3, 0, 0, shstrOff, shstr.length, 0, 0, 1, 0); // .shstrtab
  section(3, 17, 2, 0, 0, symOff, symCount * symsize, 4, 1, 8, symsize); // .symtab, all symbols global
  section(4, 25, 3, 0, 0, strOff, strtab.length, 0, 0, 1, 0); // .strtab
  return out;
}

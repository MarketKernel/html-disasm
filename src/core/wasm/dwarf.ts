/**
 * Source lines from DWARF: the `.debug_line` section a module built with
 * `-g` or `-gline-tables-only` carries. Its line programs (DWARF 2 to 5) are
 * run to a table of rows — address, file, line, column — and an instruction
 * is looked up by its offset. In a WebAssembly module the addresses count
 * from the start of the code section's contents.
 */

import type { WasmModule } from './module';
import { Reader, utf8 } from './reader';

export interface LineTable {
  files: string[];
  /** The rows, sorted by address: offset in the file, file, line (0 where no line applies), column. */
  addrs: Uint32Array;
  rows: Uint32Array;
  lookup(offset: number): { file: string; line: number; column: number } | undefined;
}

const DW_FORM = { string: 0x08, line_strp: 0x1f, strp: 0x0e, udata: 0x0f, data1: 0x0b, data2: 0x05, data4: 0x06, data8: 0x07, data16: 0x1e, block: 0x09 } as const;

function u16(r: Reader): number {
  return r.u8() | (r.u8() << 8);
}
function u32(r: Reader): number {
  return (r.u8() | (r.u8() << 8) | (r.u8() << 16) | (r.u8() << 24)) >>> 0;
}
function cstring(r: Reader): string {
  const start = r.pos;
  while (r.u8() !== 0);
  return utf8(r.bytes.subarray(start, r.pos - 1));
}
function stringAt(module: WasmModule, section: string, offset: number): string {
  const s = module.debug.get(section);
  if (!s) return '';
  return cstring(new Reader(module.bytes, s.start + offset, s.start + s.size));
}

const join = (dir: string, name: string) => (!dir || name.startsWith('/') ? name : `${dir.replace(/\/$/, '')}/${name}`);

export function readLines(module: WasmModule): LineTable | null {
  const section = module.debug.get('.debug_line');
  const code = module.sections.find((s) => s.id === 10);
  if (!section || !code) return null;
  const files: string[] = [];
  const fileIds = new Map<string, number>();
  const fileId = (path: string) => {
    let id = fileIds.get(path);
    if (id === undefined) {
      id = files.length;
      files.push(path);
      fileIds.set(path, id);
    }
    return id;
  };
  const addrs: number[] = [];
  const rows: number[] = [];
  const r = new Reader(module.bytes, section.start, section.start + section.size);
  while (r.pos + 4 <= r.end) {
    let length = u32(r);
    let wide = false;
    if (length === 0xffffffff) {
      wide = true;
      length = Number(u32(r)) + u32(r) * 2 ** 32;
    }
    const unitEnd = r.pos + length;
    if (unitEnd > r.end || length < 2) break;
    const version = u16(r);
    if (version < 2 || version > 5) {
      r.pos = unitEnd;
      continue;
    }
    let addressSize = 4;
    if (version >= 5) {
      addressSize = r.u8();
      r.u8();
    }
    const headerLength = wide ? u32(r) + u32(r) * 2 ** 32 : u32(r);
    const programStart = r.pos + headerLength;
    const minLength = r.u8();
    if (version >= 4) r.u8();
    const defaultIsStmt = r.u8();
    void defaultIsStmt;
    const lineBase = (r.u8() << 24) >> 24;
    const lineRange = r.u8() || 1;
    const opcodeBase = r.u8();
    const opLengths: number[] = [0];
    for (let i = 1; i < opcodeBase; i++) opLengths.push(r.u8());
    const dirs: string[] = [];
    const names: number[] = [];
    if (version >= 5) {
      const entries = (kindOf: 'dir' | 'file') => {
        const formats: [number, number][] = [];
        for (let n = r.u8(), i = 0; i < n; i++) formats.push([r.u32(), r.u32()]);
        const count = r.u32();
        for (let i = 0; i < count; i++) {
          let path = '';
          let dir = 0;
          for (const [type, form] of formats) {
            let value: string | number = 0;
            switch (form) {
              case DW_FORM.string: value = cstring(r); break;
              case DW_FORM.line_strp: value = stringAt(module, '.debug_line_str', wide ? u32(r) + u32(r) * 2 ** 32 : u32(r)); break;
              case DW_FORM.strp: value = stringAt(module, '.debug_str', wide ? u32(r) + u32(r) * 2 ** 32 : u32(r)); break;
              case DW_FORM.udata: value = r.u32(); break;
              case DW_FORM.data1: value = r.u8(); break;
              case DW_FORM.data2: value = u16(r); break;
              case DW_FORM.data4: value = u32(r); break;
              case DW_FORM.data8: r.bytesN(8); break;
              case DW_FORM.data16: r.bytesN(16); break;
              case DW_FORM.block: r.bytesN(r.u32()); break;
              default: throw new Error(`DWARF form ${form}`);
            }
            if (type === 1) path = String(value);
            if (type === 2) dir = Number(value);
          }
          if (kindOf === 'dir') dirs.push(path);
          else names.push(fileId(join(dirs[dir] ?? '', path)));
        }
      };
      entries('dir');
      entries('file');
    } else {
      dirs.push('');
      for (;;) {
        const dir = cstring(r);
        if (!dir) break;
        dirs.push(dir);
      }
      names.push(-1); // file numbers start at 1 before DWARF 5
      for (;;) {
        const name = cstring(r);
        if (!name) break;
        const dir = r.u32();
        r.u32();
        r.u32();
        names.push(fileId(join(dirs[dir] ?? '', name)));
      }
    }
    r.pos = programStart;

    let address = 0;
    let file = 1;
    let line = 1;
    let column = 0;
    let dead = false;
    const emit = (end = false) => {
      if (dead) return;
      addrs.push(code.start + address);
      rows.push(end ? 0 : names[file] ?? -1, end ? 0 : line, column);
    };
    const reset = () => {
      address = 0;
      file = 1;
      line = 1;
      column = 0;
      dead = false;
    };
    reset();
    while (r.pos < unitEnd) {
      const opcode = r.u8();
      if (opcode >= opcodeBase) {
        const adjusted = opcode - opcodeBase;
        address += Math.floor(adjusted / lineRange) * minLength;
        line += lineBase + (adjusted % lineRange);
        emit();
        continue;
      }
      switch (opcode) {
        case 0: {
          const size = r.u32();
          const end = r.pos + size;
          const sub = size ? r.u8() : 0;
          if (sub === 1) {
            emit(true);
            reset();
          } else if (sub === 2) {
            let value = 0;
            for (let i = 0; i < addressSize && i < 8; i++) value += r.u8() * 2 ** (8 * i);
            address = value;
            // Code the linker dropped keeps a tombstone address: its rows are left out.
            dead = value >= 0xfffffffe || value >= code.size;
          }
          r.pos = end;
          break;
        }
        case 1: emit(); break;
        case 2: address += r.u32() * minLength; break;
        case 3: line += r.s32(); break;
        case 4: file = r.u32(); break;
        case 5: column = r.u32(); break;
        case 6: case 7: case 10: case 11: break;
        case 8: address += Math.floor((255 - opcodeBase) / lineRange) * minLength; break;
        case 9: address += u16(r); break;
        case 12: r.u32(); break;
        default:
          for (let i = 0; i < (opLengths[opcode] ?? 0); i++) r.u32();
      }
    }
    r.pos = unitEnd;
  }
  if (!addrs.length) return null;
  // Sort the rows by address, keeping the order of rows at the same address.
  const order = addrs.map((_, i) => i).sort((a, b) => addrs[a]! - addrs[b]! || a - b);
  const sortedAddrs = new Uint32Array(order.length);
  const sortedRows = new Uint32Array(order.length * 3);
  order.forEach((from, to) => {
    sortedAddrs[to] = addrs[from]!;
    sortedRows[to * 3] = rows[from * 3]! >>> 0;
    sortedRows[to * 3 + 1] = rows[from * 3 + 1]!;
    sortedRows[to * 3 + 2] = rows[from * 3 + 2]!;
  });
  return {
    files,
    addrs: sortedAddrs,
    rows: sortedRows,
    lookup(offset) {
      let lo = 0;
      let hi = sortedAddrs.length - 1;
      let found = -1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (sortedAddrs[mid]! <= offset) {
          found = mid;
          lo = mid + 1;
        } else hi = mid - 1;
      }
      if (found < 0) return undefined;
      const line = sortedRows[found * 3 + 1]!;
      const file = files[sortedRows[found * 3]!];
      if (!line || file === undefined) return undefined;
      return { file, line, column: sortedRows[found * 3 + 2]! };
    },
  };
}

/**
 * Source lines from DWARF: the `.debug_line` section a module built with
 * `-g` or `-gline-tables-only` carries. The core runs its line programs
 * (DWARF 2 to 5; crates/core/src/wasm/dwarf.rs) to a table of rows — address,
 * file, line, column — and an instruction is looked up here by its offset. In a
 * WebAssembly module the addresses count from the start of the code section's
 * contents.
 */

export interface LineTable {
  files: string[];
  /** The rows, sorted by address: offset in the file, file, line (0 where no line applies), column. */
  addrs: Uint32Array;
  rows: Uint32Array;
  lookup(offset: number): { file: string; line: number; column: number } | undefined;
}

/** The table of the core's rows: the last row at or before an offset gives its line. */
export function lineTable(files: string[], addrs: Uint32Array, rows: Uint32Array): LineTable {
  return {
    files,
    addrs,
    rows,
    lookup(offset) {
      let lo = 0;
      let hi = addrs.length - 1;
      let found = -1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (addrs[mid]! <= offset) {
          found = mid;
          lo = mid + 1;
        } else hi = mid - 1;
      }
      if (found < 0) return undefined;
      const line = rows[found * 3 + 1]!;
      const file = files[rows[found * 3]!];
      if (!line || file === undefined) return undefined;
      return { file, line, column: rows[found * 3 + 2]! };
    },
  };
}

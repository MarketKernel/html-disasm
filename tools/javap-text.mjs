/**
 * javap -c's text, read back: the instructions of each method's Code, by pc,
 * as tools/verify-jvm.mjs and tests/jvm.mjs compare them with the decoder.
 * javap writes a switch on several lines; they are joined with spaces, as the
 * decoder writes them. Runs of spaces count as one (`normal`): javap pads its
 * columns.
 */

/** The text of each class, in the order javap printed them: a class ends at a `}` of its own. */
export function javapClasses(text) {
  const classes = [];
  let lines = [];
  for (const line of text.split('\n')) {
    lines.push(line);
    if (line === '}') {
      classes.push(lines);
      lines = [];
    }
  }
  return classes;
}

/** The methods' code in a class's text: one list of [pc, text] per Code block, in order. */
export function codeBlocks(lines) {
  const blocks = [];
  let block = null;
  let pending = null;
  for (const line of lines) {
    if (pending) {
      pending[1] += ` ${line.trim()}`;
      if (line.trim() === '}') {
        block.push(pending);
        pending = null;
      }
      continue;
    }
    if (/^\s+Code:$/.test(line)) {
      block = [];
      blocks.push(block);
      continue;
    }
    // A string constant may hold a line separator (U+2028), which `.` does not match without the s flag.
    const insn = block && /^\s+(\d+): (.*)$/s.exec(line);
    if (insn) {
      const entry = [Number(insn[1]), insn[2]];
      if (/^(table|lookup)switch\s+\{/.test(insn[2])) pending = entry;
      else block.push(entry);
    } else if (block) block = null;
  }
  return blocks;
}

export const normal = (text) => text.replace(/\s+/g, ' ').trim();

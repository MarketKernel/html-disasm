/**
 * ildasm's text of an assembly, read back instruction by instruction for
 * tools/verify-cil.mjs and tests/cil.mjs: the method each line is in (by the
 * RVA ildasm's -bytes option writes before it), the IL offset, and the text
 * on one line — ildasm's own line breaks undone (a signature's parameters, a
 * switch's targets, a long string's pieces `"…" + "…"`, a bytearray without
 * its comments) and the bytes -bytes adds cut off.
 */

/** Are the brackets of a line closed, outside quotes? */
function open(text) {
  let depth = 0;
  let quote = '';
  for (let k = 0; k < text.length; k++) {
    const c = text[k];
    if (quote) {
      if (c === '\\') k++;
      else if (c === quote) quote = '';
    } else if (c === '"' || c === "'") quote = c;
    else if (c === '(') depth++;
    else if (c === ')') depth--;
  }
  return depth > 0;
}

/** `rva:offset` → ildasm's text of the instruction, on one line. */
export function referenceLines(text) {
  const lines = new Map();
  let rva = -1;
  let current = null;
  const flush = () => {
    if (!current) return;
    let body = current.text;
    if (/^ldstr\s+bytearray/.test(body)) body = body.replace(/bytearray \((.*)$/, (_, rest) => `bytearray (${rest.replace(/\s+/g, ' ').trim().replace(/ ?\)$/, ')')}`);
    lines.set(`${rva}:${current.offset}`, body);
    current = null;
  };
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    const begins = /\/\/ Method begins at RVA 0x([0-9a-f]+)/.exec(line);
    if (begins) {
      flush();
      rva = parseInt(begins[1], 16);
      continue;
    }
    const match = /^\s*IL_([0-9a-f]+):  (.*)$/.exec(line);
    if (match) {
      flush();
      current = { offset: parseInt(match[1], 16), text: match[2].replace(/^\/\* [^*]*\*\/ /, '').replace(/\s+$/, '') };
      if (/^ldstr\s+bytearray/.test(current.text)) current.text = current.text.replace(/\s*\/\/.*$/, '');
      continue;
    }
    if (current) {
      const trimmed = line.replace(/\/\*[^*]*\*\//g, '').trim();
      if (trimmed.startsWith('+ "') && current.text.endsWith('"')) {
        current.text = current.text.slice(0, -1) + trimmed.slice(3);
        continue;
      }
      if (open(current.text)) {
        const piece = /^ldstr\s+bytearray/.test(current.text) ? trimmed.replace(/\s*\/\/.*$/, '') : trimmed;
        current.text += current.text.endsWith('(') ? ` ${piece}` : ` ${piece}`;
        continue;
      }
      flush();
    }
    if (/^\s*} \/\/ end of method/.test(line)) rva = -1;
  }
  flush();
  return lines;
}

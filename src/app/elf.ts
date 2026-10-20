/**
 * The page about an ELF file: the header, what Android says about the build
 * (API level, NDK), the libraries it needs, the Arm build
 * attributes, the segments and sections, the dynamic section and the
 * relocations.
 */

import type { Arm32Program } from '../core/arm32/program';
import { SECTION_TYPES, SEGMENT_TYPES, SHF } from '../core/elf';
import { androidVersion, platformOf } from '../core/image';
import { n, t, tn } from '../core/i18n';
import type { Program } from '../core/program';
import type { X86Program } from '../core/x86/program';
import { sizeLabel } from './labels';
import { fnName, state } from './state';
import { esc, hex } from './ui';

const rwx = (flags: number) => `${flags & 4 ? 'r' : '-'}${flags & 2 ? 'w' : '-'}${flags & 1 ? 'x' : '-'}`;

function sectionFlags(flags: number): string {
  let out = '';
  if (flags & SHF.ALLOC) out += 'A';
  if (flags & SHF.WRITE) out += 'W';
  if (flags & SHF.EXEC) out += 'X';
  if (flags & SHF.MERGE) out += 'M';
  if (flags & SHF.STRINGS) out += 'S';
  return out;
}

/** What the arm32 analysis found out about the instruction sets, for the overview. */
function instructionSets(p: Program | Arm32Program | X86Program): string | undefined {
  if (p.arch !== 'arm32') return undefined;
  const a32 = p.kinds.reduce((count, kind) => count + (kind === 0 ? 1 : 0), 0);
  const t32 = p.kinds.reduce((count, kind) => count + (kind === 1 || kind === 2 ? 1 : 0), 0);
  const how = p.mapped ? t('overview', 'from the mapping symbols') : t('overview', 'worked out from the code (the library is stripped)');
  return `T32 ${n(t32)} · A32 ${n(a32)} — ${how}`;
}

export function renderElf(p: Program | Arm32Program | X86Program, page: HTMLElement): void {
  const elf = p.image.elf!;
  const entry = elf.entry ? p.functionAt(elf.entry & ~1) : undefined;
  const info = [
    [t('overview', 'File'), `${state.fileName} · ${sizeLabel(state.fileSize)}`],
    [t('overview', 'Architecture'), `${elf.arch} (${elf.machineName}, ${elf.is64 ? '64' : '32'}-bit)`],
    [t('overview', 'Type'), elf.typeName],
    instructionSets(p) ? [t('overview', 'Instruction sets'), instructionSets(p)!] : null,
    elf.android
      ? [t('overview', 'Android'), `${androidVersion(elf.android.api) ? t('overview', 'Android {version} or newer (API level {level})', { version: androidVersion(elf.android.api)!, level: elf.android.api }) : t('overview', 'API level {level} or newer', { level: elf.android.api })}${elf.android.ndk ? ` · NDK ${elf.android.ndk}${elf.android.build ? ` (${elf.android.build})` : ''}` : ''}`]
      : platformOf(p.image) ? [t('overview', 'Platform'), platformOf(p.image)!.label] : null,
    elf.soname ? [t('overview', 'Library name'), elf.soname] : null,
    elf.interpreter ? [t('overview', 'Loader'), elf.interpreter] : null,
    elf.entry ? [t('overview', 'Entry point'), `${hex(elf.entry)}${entry ? ` (${fnName(entry)})` : ''}`] : null,
    elf.buildId ? ['Build ID', elf.buildId] : null,
    elf.flagNames.length ? [t('overview', 'Header flags'), elf.flagNames.join(' ')] : null,
    elf.features.length ? [t('overview', 'Protection'), elf.features.join(' ')] : null,
    [t('overview', 'Symbols'), `${tn('overview', '{count} dynamic symbol', '{count} dynamic symbols', elf.dynsyms.length)}${elf.symtab.length ? ` · ${tn('overview', '{count} in the symbol table', '{count} in the symbol table', elf.symtab.length)}` : ` · ${t('overview', 'stripped')}`}${elf.debugInfo ? ` · ${t('overview', 'debugging information')}` : ''}`],
    elf.comment.length ? [t('overview', 'Built with'), elf.comment.join('\n')] : null,
  ].filter(Boolean) as [string, string][];

  page.innerHTML = `
    <h2>ELF</h2>
    <p class="lede">${esc(t('overview', 'The container around the code: how the library is laid out in memory, what it needs from the system and what it offers.'))}</p>
    <dl class="kv" style="max-width:900px">${info.map(([k, v]) => `<dt>${esc(k)}</dt><dd style="white-space:pre-line">${esc(v)}</dd>`).join('')}</dl>
    <h3>${esc(tn('overview', '{count} needed library', '{count} needed libraries', elf.needed.length))}</h3>
    ${elf.needed.length ? `<div class="pre">${esc(elf.needed.join('\n'))}</div>` : `<p class="hint">${esc(t('overview', 'None.'))}</p>`}
    ${elf.runpath.length ? `<h3>${esc(t('overview', 'Run-path search paths'))}</h3><div class="pre">${esc(elf.runpath.join('\n'))}</div>` : ''}
    ${
      elf.attributes.length
        ? `<h3>${esc(t('overview', 'Arm build attributes'))}</h3><dl class="kv" style="max-width:900px">${elf.attributes.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`
        : ''
    }
    <h3>${esc(tn('overview', '{count} segment', '{count} segments', elf.segments.length))}</h3>
    <table class="table"><thead><tr><th>${esc(t('overview', 'Type'))}</th><th>${esc(t('overview', 'Access'))}</th><th>${esc(t('overview', 'Address'))}</th><th>${esc(t('overview', 'Size'))}</th><th>${esc(t('overview', 'File offset'))}</th><th>${esc(t('overview', 'In the file'))}</th></tr></thead><tbody>
    ${elf.segments.map((s) => `<tr><td class="mono">${esc(SEGMENT_TYPES[s.type] ?? hex(s.type))}</td><td class="mono">${rwx(s.flags)}</td><td class="mono">${hex(s.vaddr)}</td><td class="mono">${sizeLabel(s.memsz)}</td><td class="mono">${hex(s.offset)}</td><td class="mono">${sizeLabel(s.filesz)}</td></tr>`).join('')}
    </tbody></table>
    <h3>${esc(tn('overview', '{count} section', '{count} sections', elf.sections.length))}${elf.sectionless ? ` <span class="hint">${esc(t('overview', 'the file has no section headers: these are its segments'))}</span>` : ''}</h3>
    <table class="table"><thead><tr><th>${esc(t('overview', 'Section'))}</th><th>${esc(t('overview', 'Type'))}</th><th>${esc(t('overview', 'Address'))}</th><th>${esc(t('overview', 'Size'))}</th><th>${esc(t('overview', 'File offset'))}</th><th>${esc(t('overview', 'Flags'))}</th></tr></thead><tbody>
    ${elf.sections
      .filter((s) => s.type !== 0)
      .map((s) => `<tr><td class="mono">${esc(s.name)}</td><td class="mono">${esc(SECTION_TYPES[s.type] ?? hex(s.type))}</td><td class="mono">${s.addr ? hex(s.addr) : '—'}</td><td class="mono">${sizeLabel(s.size)}</td><td class="mono">${hex(s.offset)}</td><td class="mono">${sectionFlags(s.flags)}${s.flags & SHF.EXEC ? ` · ${esc(t('overview', 'code'))}` : ''}</td></tr>`)
      .join('')}
    </tbody></table>
    <h3>${esc(tn('overview', '{count} relocation', '{count} relocations', [...elf.relocationCounts.values()].reduce((a, b) => a + b, 0)))}${elf.relocationFormats.length ? ` <span class="hint">${esc(elf.relocationFormats.join(', '))}</span>` : ''}</h3>
    <dl class="kv" style="max-width:600px">${[...elf.relocationCounts].map(([k, v]) => `<dt class="mono">${esc(k)}</dt><dd>${n(v)}</dd>`).join('')}</dl>
    <h3>${esc(tn('overview', '{count} dynamic entry', '{count} dynamic entries', elf.dynamic.length))}</h3>
    <table class="table"><thead><tr><th>${esc(t('overview', 'Tag'))}</th><th>${esc(t('overview', 'Value'))}</th></tr></thead><tbody>
    ${elf.dynamic.map((d) => `<tr><td class="mono">${esc(d.name)}</td><td class="mono">${esc(d.text)}</td></tr>`).join('')}
    </tbody></table>
  `;
}

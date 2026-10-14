/**
 * The page about a Windows PE file: the headers, the Windows version and
 * subsystem it is built for, the security features the linker set, the
 * debug information (the PDB it points at), the sections, the data
 * directories, and what the import and export tables hold.
 */

import { n, t, tn } from '../core/i18n';
import { platformOf } from '../core/image';
import { peTime, SECTION_FLAGS } from '../core/pe';
import type { X86Program } from '../core/x86/program';
import type { Program } from '../core/program';
import { sizeLabel } from './labels';
import { fnName, state } from './state';
import { esc, hex } from './ui';

function sectionAccess(flags: number): string {
  return `${flags & SECTION_FLAGS.READ ? 'r' : '-'}${flags & SECTION_FLAGS.WRITE ? 'w' : '-'}${flags & SECTION_FLAGS.EXECUTE ? 'x' : '-'}`;
}

function sectionKind(flags: number): string {
  const kinds: string[] = [];
  if (flags & SECTION_FLAGS.CODE) kinds.push(t('overview', 'code'));
  if (flags & SECTION_FLAGS.INITIALIZED) kinds.push(t('overview', 'data'));
  if (flags & SECTION_FLAGS.UNINITIALIZED) kinds.push(t('overview', 'zero-filled'));
  if (flags & SECTION_FLAGS.DISCARDABLE) kinds.push(t('overview', 'discardable'));
  return kinds.join(' · ');
}

export function renderPe(p: X86Program | Program, page: HTMLElement): void {
  const pe = p.image.pe!;
  const entry = pe.entry !== undefined ? p.functionAt(pe.entry) : undefined;
  const linked = peTime(pe);
  const delayed = new Set(pe.imports.filter((i) => i.delayed).map((i) => i.library));
  const forwarded = pe.exports.filter((e) => e.forwarder).length;
  const info = [
    [t('overview', 'File'), `${state.fileName} · ${sizeLabel(state.fileSize)}`],
    [t('overview', 'Architecture'), `${pe.machineName} (${pe.is64 ? 'PE32+' : 'PE32'})`],
    [t('overview', 'Type'), pe.dll ? t('overview', 'dynamic library (DLL)') : t('overview', 'executable')],
    [t('overview', 'Platform'), `${pe.subsystemName} · ${t('overview', 'Windows {version} or newer', { version: (platformOf(p.image)?.label ?? 'Windows').replace(/^Windows ?/, '').replace(/\+$/, '') || pe.subsystemVersion })} (${pe.subsystemVersion})`],
    pe.dllName ? [t('overview', 'Library name'), pe.dllName] : null,
    [t('overview', 'Image base'), hex(pe.imageBase)],
    pe.entry !== undefined ? [t('overview', 'Entry point'), `${hex(pe.entry)}${entry ? ` (${fnName(entry)})` : ''}`] : null,
    [t('overview', 'Linker'), `${pe.linkerVersion}${linked ? ` · ${t('overview', 'linked {date}', { date: linked })}` : ''}`],
    pe.pdb ? [t('overview', 'Debugging information'), `${pe.pdb.path}\n${pe.pdb.guid} · age ${pe.pdb.age}`] : null,
    [t('overview', 'Protection'), pe.dllFlagNames.join(' ') || '—'],
    [t('overview', 'Header flags'), pe.flagNames.join(' ')],
    [t('overview', 'Signature'), pe.signed ? t('overview', 'signed (Authenticode)') : t('overview', 'not signed')],
    [t('overview', 'Symbols'), pe.symbols.length ? tn('overview', '{count} in the symbol table', '{count} in the symbol table', pe.symbols.length) : t('overview', 'stripped')],
    pe.functionStarts.length ? [t('overview', 'Unwind table'), tn('overview', '{count} function', '{count} functions', pe.functionStarts.length)] : null,
    pe.tlsCallbacks.length ? [t('overview', 'TLS callbacks'), pe.tlsCallbacks.map(hex).join(', ')] : null,
  ].filter(Boolean) as [string, string][];
  const imports = new Map<string, number>();
  for (const i of pe.imports) imports.set(i.library, (imports.get(i.library) ?? 0) + 1);
  // A hybrid program: what kinds of code it holds, and a link to the kind not open.
  const hybrid = pe.hybrid;
  const x64Open = p.arch === 'x86';
  if (hybrid) {
    const arm64 = hybrid.ranges.some((r) => r.kind === 'arm64');
    info.splice(2, 0, [
      t('overview', 'Hybrid'),
      arm64
        ? t('overview', 'ARM64X: arm64 code for Arm processes, and ARM64EC and x64 code for x64 ones, in one file')
        : t('overview', 'ARM64EC: Arm code that follows x64 conventions, beside x64 code'),
    ]);
  }
  const kindLabel = { arm64: 'ARM64', arm64ec: 'ARM64EC', x64: 'x64' } as const;
  const codeMap = hybrid
    ? `<h3>${esc(t('overview', 'Code map'))}</h3>
    <p class="hint">${esc(x64Open ? t('overview', 'The x64 code is open; the Arm code is shown as data.') : t('overview', 'The Arm code is open; the x64 code is shown as data.'))} <a href="#" data-slice="${x64Open ? 'arm' : 'x64'}">${esc(x64Open ? t('overview', 'Open the Arm code') : t('overview', 'Open the x64 code'))}</a></p>
    <table class="table"><thead><tr><th>${esc(t('overview', 'Address'))}</th><th>${esc(t('overview', 'Size'))}</th><th>${esc(t('overview', 'Code'))}</th></tr></thead><tbody>
    ${hybrid.ranges.map((r) => `<tr><td class="mono">${hex(r.addr)}</td><td class="mono">${sizeLabel(r.size)}</td><td>${kindLabel[r.kind]}</td></tr>`).join('')}
    </tbody></table>`
    : '';

  page.innerHTML = `
    <h2>PE</h2>
    <p class="lede">${esc(t('overview', 'The container around the code: how the Windows program is laid out in memory, what it needs from the system and what it offers.'))}</p>
    <dl class="kv" style="max-width:900px">${info.map(([k, v]) => `<dt>${esc(k)}</dt><dd style="white-space:pre-line">${esc(v)}</dd>`).join('')}</dl>
    ${codeMap}
    <h3>${esc(tn('overview', '{count} needed library', '{count} needed libraries', pe.libraries.length))}</h3>
    ${pe.libraries.length ? `<table class="table"><thead><tr><th>${esc(t('imports', 'Library'))}</th><th>${esc(t('imports', 'Symbols'))}</th></tr></thead><tbody>${pe.libraries.map((lib) => `<tr><td class="mono">${esc(lib)}${delayed.has(lib) ? ` <span class="tag">${esc(t('overview', 'delay-loaded'))}</span>` : ''}</td><td class="mono">${n(imports.get(lib) ?? 0)}</td></tr>`).join('')}</tbody></table>` : `<p class="hint">${esc(t('overview', 'None.'))}</p>`}
    ${pe.exports.length ? `<p class="hint">${esc(tn('overview', '{count} export', '{count} exports', pe.exports.length))}${forwarded ? ` · ${esc(tn('overview', '{count} forwarded to another library', '{count} forwarded to another library', forwarded))}` : ''}</p>` : ''}
    <h3>${esc(tn('overview', '{count} section', '{count} sections', pe.sections.length))}</h3>
    <table class="table"><thead><tr><th>${esc(t('overview', 'Section'))}</th><th>${esc(t('overview', 'Access'))}</th><th>${esc(t('overview', 'Address'))}</th><th>${esc(t('overview', 'Size'))}</th><th>${esc(t('overview', 'In the file'))}</th><th>${esc(t('overview', 'File offset'))}</th><th>${esc(t('overview', 'Kind'))}</th></tr></thead><tbody>
    ${pe.sections.map((s) => `<tr><td class="mono">${esc(s.name)}</td><td class="mono">${sectionAccess(s.flags)}</td><td class="mono">${hex(pe.imageBase + s.rva)}</td><td class="mono">${sizeLabel(s.virtualSize)}</td><td class="mono">${sizeLabel(s.rawSize)}</td><td class="mono">${s.rawSize ? hex(s.rawOffset) : '—'}</td><td>${esc(sectionKind(s.flags))}</td></tr>`).join('')}
    </tbody></table>
    <h3>${esc(t('overview', 'Data directories'))}</h3>
    <table class="table"><thead><tr><th>${esc(t('overview', 'Directory'))}</th><th>${esc(t('overview', 'Address'))}</th><th>${esc(t('overview', 'Size'))}</th></tr></thead><tbody>
    ${pe.directories.filter((d) => d.rva || d.size).map((d) => `<tr><td>${esc(d.name)}</td><td class="mono">${hex(pe.imageBase + d.rva)}</td><td class="mono">${sizeLabel(d.size)}</td></tr>`).join('')}
    </tbody></table>
    <p class="hint">${esc(tn('overview', '{count} relocation', '{count} relocations', pe.relocationCount))}</p>
  `;
}

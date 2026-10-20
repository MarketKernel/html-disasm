/**
 * ZIP files: an app (an iOS .ipa, a zipped macOS app), whose bundles' programs
 * are listed — the app, its frameworks and extensions, each with what its
 * Info.plist says and the provisioning profile an app signed for distribution
 * carries — and an Android package (.apk, .aab, .apks, .xapk), whose native
 * libraries are listed by ABI. The one picked is taken out and opened.
 *
 * The core reads the archive, its property lists and profiles, and inflates
 * what was deflated (crates/core/src/{zip,plist,bundle}.rs,
 * crates/wasm/src/archive.rs); the file stays in its session while the page
 * shows the list.
 */

import { engine as currentEngine, type Engine } from './engine/engine';

export const isZip = (bytes: Uint8Array): boolean => bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 3 && bytes[3] === 4;

export class NotZip extends Error {}

export interface ProvisioningProfile {
  name?: string;
  team?: string;
  teamId?: string;
  appId?: string;
  created?: Date;
  expires?: Date;
  /** How many devices a development or ad hoc profile names. */
  devices?: number;
  /** An enterprise profile runs on any device. */
  allDevices?: boolean;
  /** Development builds may be debugged. */
  debuggable?: boolean;
}

export interface Bundle {
  kind: 'app' | 'framework' | 'extension' | 'bundle' | 'library';
  /** Where it is in the archive: `Payload/Hello.app`. */
  path: string;
  /** `Hello.app` */
  name: string;
  identifier?: string;
  /** CFBundleShortVersionString, and the build number (CFBundleVersion). */
  version?: string;
  build?: string;
  /** The lowest system it runs on: MinimumOSVersion (iOS) or LSMinimumSystemVersion (macOS). */
  minimumOS?: string;
  platforms?: string[];
  profile?: ProvisioningProfile;
}

export interface BundledProgram {
  bundle: Bundle;
  /** The executable's file name. */
  file: string;
  size: number;
  read(): Promise<Uint8Array>;
}

/** A native library in an Android package: lib/<abi>/name.so (base/lib/… in an .aab). */
export interface PackagedLibrary {
  abi: string;
  file: string;
  size: number;
  /** The split APK it is in, for an .apks or .xapk bundle. */
  from?: string;
  read(): Promise<Uint8Array>;
}

type CoreError = { error: 'zip' | 'range' | 'inflate'; text: string };

/** The error the TypeScript reader threw: NotZip for what is not a ZIP, its DataView's RangeError, DecompressionStream's TypeError. */
function thrown(e: CoreError): Error {
  return e.error === 'zip' ? new NotZip(e.text) : e.error === 'range' ? new RangeError(e.text) : new TypeError(e.text);
}

/** Closes an archive's session in the core once nothing refers to it. */
const sessions = new FinalizationRegistry<{ engine: Engine; handle: number }>(({ engine, handle }) => {
  if (engine === currentEngine()) engine.x.close(handle);
});

interface CoreProgram {
  kind: Bundle['kind'];
  path: string;
  name: string;
  identifier: string | null;
  version: string | null;
  build: string | null;
  minimumOS: string | null;
  platforms: string[] | null;
  profile: { name: string | null; team: string | null; teamId: string | null; appId: string | null; created: number | 'NaN' | null; expires: number | 'NaN' | null; devices: number | null; allDevices: boolean; debuggable: boolean } | null;
  file: string;
  size: number;
}

/** A ZIP file in the core: its entries, an app's programs, a package's libraries, read one at a time. */
export class Archive {
  private engine: Engine;
  private handle: number;
  /** What the session was asked, to ask it again if the core restarts. */
  private asked: ('names' | 'programs' | 'libraries')[] = [];

  constructor(private readonly bytes: Uint8Array) {
    [this.engine, this.handle] = this.open();
  }

  private open(): [Engine, number] {
    const engine = currentEngine();
    // The core takes the copy over: it is not freed here.
    const handle = engine.call(() => engine.x.archive_open(engine.put(this.bytes), this.bytes.length));
    sessions.register(this, { engine, handle }, this);
    return [engine, handle];
  }

  /** The session, opened again (and asked the same) if the core was restarted since. */
  private live(): number {
    if (this.engine === currentEngine()) return this.handle;
    if (this.engine) sessions.unregister(this);
    [this.engine, this.handle] = this.open();
    for (const what of this.asked) this.ask(what, false);
    return this.handle;
  }

  private ask<T>(what: 'names' | 'programs' | 'libraries', remember = true): T {
    const handle = this.live();
    const x = this.engine.x;
    const call = what === 'names' ? () => x.archive_names(handle) : what === 'programs' ? () => x.archive_programs(handle) : () => x.archive_libraries(handle);
    const r = JSON.parse(this.engine.out(this.engine.call(call))) as T | CoreError;
    if (r && typeof r === 'object' && 'error' in r) throw thrown(r);
    if (remember && !this.asked.includes(what)) this.asked.push(what);
    return r;
  }

  /** Program `k` of a list: 0 an app's programs, 1 a package's libraries, 2 the entries. */
  private read(what: number, k: number): Uint8Array {
    const handle = this.live();
    const r = JSON.parse(this.engine.out(this.engine.call(() => this.engine.x.archive_read(handle, what, k)))) as { len: number } | CoreError;
    if ('error' in r) throw thrown(r);
    return this.engine.copy(handle, 0, Uint8Array);
  }

  /** Closes the core's session now rather than when the archive is collected; it is opened again if asked. */
  dispose(): void {
    sessions.unregister(this);
    if (this.engine === currentEngine()) this.engine.x.close(this.handle);
    this.engine = null as unknown as Engine;
  }

  /** The names of the entries, in the order of the central directory. */
  names(): string[] {
    return this.ask<{ names: string[] }>('names').names;
  }

  /** The bytes of entry `k` of `names()`. */
  entry(k: number): Uint8Array {
    return this.read(2, k);
  }

  /** The programs of the app the archive holds (none when it holds none). */
  programs(): BundledProgram[] {
    const list = this.ask<{ programs: CoreProgram[] }>('programs').programs;
    const date = (v: number | 'NaN' | null) => (v === null ? undefined : new Date(v === 'NaN' ? NaN : v));
    return list.map((p, k) => {
      const bundle: Bundle = { kind: p.kind, path: p.path, name: p.name };
      if (p.kind !== 'library') {
        Object.assign(bundle, {
          identifier: p.identifier ?? undefined,
          version: p.version ?? undefined,
          build: p.build ?? undefined,
          minimumOS: p.minimumOS ?? undefined,
          platforms: p.platforms ?? undefined,
        });
      }
      const f = p.profile;
      if (f) {
        bundle.profile = {
          name: f.name ?? undefined,
          team: f.team ?? undefined,
          teamId: f.teamId ?? undefined,
          appId: f.appId ?? undefined,
          created: date(f.created),
          expires: date(f.expires),
          devices: f.devices ?? undefined,
          allDevices: f.allDevices,
          debuggable: f.debuggable,
        };
      }
      return { bundle, file: p.file, size: p.size, read: async () => this.read(0, k) };
    });
  }

  /** The native libraries of an Android package. */
  libraries(): PackagedLibrary[] {
    const list = this.ask<{ libraries: { abi: string; file: string; size: number; from: string | null }[] }>('libraries').libraries;
    return list.map(({ abi, file, size, from }, k) => ({ abi, file, size, ...(from !== null ? { from } : {}), read: async () => this.read(1, k) }));
  }
}

/** The programs of an app in a ZIP file: none when it holds no app. */
export async function bundledPrograms(bytes: Uint8Array): Promise<BundledProgram[]> {
  return new Archive(bytes).programs();
}

/** The native libraries of an Android package. */
export async function packagedLibraries(bytes: Uint8Array): Promise<PackagedLibrary[]> {
  return new Archive(bytes).libraries();
}

/** The names of a ZIP file's entries. */
export function zipNames(bytes: Uint8Array): string[] {
  return new Archive(bytes).names();
}

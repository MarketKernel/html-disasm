/**
 * The programs of an app packed in a ZIP file: an iOS .ipa (Payload/Name.app/…)
 * or a zipped macOS app (Name.app/Contents/…). Each bundle — the app, its
 * frameworks, its extensions — says in its Info.plist which file is its
 * executable (CFBundleExecutable); loose .dylib files are listed too. An app
 * signed for distribution carries its provisioning profile, which says who
 * signed it and for which devices.
 */

import { parsePlist, profilePlist, type PlistValue } from './plist';
import { zipEntries, zipRead, type ZipEntry } from './zip';

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

/** A bundle's Info.plist: right inside it (iOS), in Contents (macOS apps), or in a framework version's Resources. */
const INFO = /^((?:.*\/)?[^/]+\.(app|framework|appex|xpc|bundle))\/(Contents\/|Versions\/[^/]+\/Resources\/|Resources\/)?Info\.plist$/;

const KINDS: Record<string, Bundle['kind']> = { app: 'app', framework: 'framework', appex: 'extension', xpc: 'extension', bundle: 'bundle' };

const text = (v: PlistValue | undefined): string | undefined => (typeof v === 'string' ? v : undefined);

/** Whether a ZIP file holds an app: a bundle's Info.plist anywhere in it. */
export function isAppArchive(entries: ZipEntry[]): boolean {
  return entries.some((e) => INFO.test(e.name));
}

export async function bundledPrograms(bytes: Uint8Array): Promise<BundledProgram[]> {
  const entries = zipEntries(bytes);
  const byName = new Map(entries.map((e) => [e.name, e]));
  const out: BundledProgram[] = [];
  const taken = new Set<string>();
  for (const entry of entries) {
    const match = INFO.exec(entry.name);
    // Versions/Current is a link to a version listed beside it.
    if (!match || entry.name.includes('/Versions/Current/')) continue;
    const [, path, extension, inner = ''] = match as unknown as [string, string, string, string | undefined];
    let info: { [key: string]: PlistValue } = {};
    try {
      const value = parsePlist(await zipRead(bytes, entry));
      if (value && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Date)) info = value;
    } catch {
      // A bundle with an unreadable Info.plist is still found by its executable's name.
    }
    const name = path.split('/').pop()!;
    const executable = text(info.CFBundleExecutable) ?? name.replace(/\.[^.]+$/, '');
    const home = inner === 'Contents/' ? `${path}/Contents/MacOS/` : inner.startsWith('Versions/') ? `${path}/${inner.replace(/Resources\/$/, '')}` : `${path}/`;
    const exe = byName.get(home + executable);
    if (!exe || !exe.size) continue;
    taken.add(exe.name);
    const bundle: Bundle = {
      kind: KINDS[extension] ?? 'bundle',
      path,
      name,
      identifier: text(info.CFBundleIdentifier),
      version: text(info.CFBundleShortVersionString),
      build: text(info.CFBundleVersion),
      minimumOS: text(info.MinimumOSVersion) ?? text(info.LSMinimumSystemVersion),
      platforms: Array.isArray(info.CFBundleSupportedPlatforms) ? info.CFBundleSupportedPlatforms.filter((p): p is string => typeof p === 'string') : undefined,
    };
    const profileEntry = byName.get(`${path}/embedded.mobileprovision`) ?? byName.get(`${path}/Contents/embedded.provisionprofile`);
    if (profileEntry) {
      const profile = readProfile(await zipRead(bytes, profileEntry));
      if (profile) bundle.profile = profile;
    }
    out.push({ bundle, file: executable, size: exe.size, read: () => zipRead(bytes, exe) });
  }
  // Libraries outside any bundle's executable: Swift's runtime in older apps, plug-in dylibs.
  for (const entry of entries) {
    if (!/\.dylib$/.test(entry.name) || taken.has(entry.name) || !entry.size || entry.name.includes('/Versions/Current/')) continue;
    const slash = entry.name.lastIndexOf('/');
    const file = entry.name.slice(slash + 1);
    out.push({ bundle: { kind: 'library', path: entry.name.slice(0, Math.max(slash, 0)), name: file }, file, size: entry.size, read: () => zipRead(bytes, entry) });
  }
  return out;
}

/** What a provisioning profile says about who may run the app and where. */
export function readProfile(bytes: Uint8Array): ProvisioningProfile | undefined {
  const value = profilePlist(bytes);
  if (!value || typeof value !== 'object' || Array.isArray(value) || value instanceof Uint8Array || value instanceof Date) return undefined;
  const date = (v: PlistValue | undefined) => (v instanceof Date ? v : undefined);
  const entitlements = value.Entitlements && typeof value.Entitlements === 'object' && !Array.isArray(value.Entitlements) && !(value.Entitlements instanceof Uint8Array) && !(value.Entitlements instanceof Date) ? value.Entitlements : {};
  const teamIds = Array.isArray(value.TeamIdentifier) ? value.TeamIdentifier : [];
  return {
    name: text(value.Name),
    team: text(value.TeamName),
    teamId: text(teamIds[0]),
    appId: text(entitlements['application-identifier']) ?? text(entitlements['com.apple.application-identifier']),
    created: date(value.CreationDate),
    expires: date(value.ExpirationDate),
    devices: Array.isArray(value.ProvisionedDevices) ? value.ProvisionedDevices.length : undefined,
    allDevices: value.ProvisionsAllDevices === true,
    debuggable: entitlements['get-task-allow'] === true || entitlements['com.apple.security.get-task-allow'] === true,
  };
}

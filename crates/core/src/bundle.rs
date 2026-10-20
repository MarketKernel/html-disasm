//! The programs of an app packed in a ZIP file: an iOS .ipa (Payload/Name.app/…) or a zipped
//! macOS app (Name.app/Contents/…). Each bundle — the app, its frameworks, its extensions — says in
//! its Info.plist which file is its executable (CFBundleExecutable); loose .dylib files are listed
//! too. An app signed for distribution carries its provisioning profile, which says who signed it
//! and for which devices. A port of the TypeScript the page had (bundle.ts).

use crate::plist::{parse_plist, profile_plist, Plist};
use crate::refs::FxHashMap;
use crate::zip::{zip_entries, zip_read, ZipEntry, ZipError};

/// What a provisioning profile says about who may run the app and where.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Profile {
    pub name: Option<Vec<u16>>,
    pub team: Option<Vec<u16>>,
    pub team_id: Option<Vec<u16>>,
    pub app_id: Option<Vec<u16>>,
    /// JavaScript times (NaN: an invalid date).
    pub created: Option<f64>,
    pub expires: Option<f64>,
    /// How many devices a development or ad hoc profile names.
    pub devices: Option<usize>,
    /// An enterprise profile runs on any device.
    pub all_devices: bool,
    /// Development builds may be debugged.
    pub debuggable: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Bundle {
    /// app, framework, extension, bundle, library
    pub kind: &'static str,
    /// Where it is in the archive: `Payload/Hello.app`.
    pub path: String,
    /// `Hello.app`
    pub name: String,
    pub identifier: Option<Vec<u16>>,
    /// CFBundleShortVersionString, and the build number (CFBundleVersion).
    pub version: Option<Vec<u16>>,
    pub build: Option<Vec<u16>>,
    /// The lowest system it runs on: MinimumOSVersion (iOS) or LSMinimumSystemVersion (macOS).
    pub minimum_os: Option<Vec<u16>>,
    pub platforms: Option<Vec<Vec<u16>>>,
    pub profile: Option<Profile>,
}

/// A program of an app: its bundle, the executable's file name and size, and its entry in the archive.
#[derive(Clone, Debug)]
pub struct BundledProgram {
    pub bundle: Bundle,
    pub file: String,
    pub size: u64,
    pub entry: ZipEntry,
}

/// `/^((?:.*\/)?[^/]+\.(app|framework|appex|xpc|bundle))\/(Contents\/|Versions\/[^/]+\/Resources\/|Resources\/)?Info\.plist$/`:
/// the bundle's path, its extension and where its Info.plist is inside it.
fn info_path(name: &str) -> Option<(&str, &str, &str)> {
    let rest = name.strip_suffix("Info.plist")?;
    let mut best: Option<(usize, usize, &str, &str, &str)> = None;
    // The inner folders in the order the alternation tries them, then none.
    let inners: [&dyn Fn(&str) -> Option<usize>; 4] = [
        &|r: &str| r.ends_with("/Contents/").then_some(9),
        &|r: &str| {
            let r = r.strip_suffix("/Resources/")?;
            let slash = r.rfind('/')?;
            let version = &r[slash + 1..];
            (!version.is_empty() && r[..slash].ends_with("/Versions")).then_some(r.len() - slash + 10 + 9)
        },
        &|r: &str| r.ends_with("/Resources/").then_some(10),
        &|r: &str| r.ends_with('/').then_some(0),
    ];
    for (order, inner) in inners.iter().enumerate() {
        let Some(len) = inner(rest) else { continue };
        // The inner part, and the path before its slash.
        let inner_text = &rest[rest.len() - len..];
        let path = &rest[..rest.len() - len - 1];
        let start = path.rfind('/').map_or(0, |k| k + 1);
        let last = &path[start..];
        let Some(dot) = last.rfind('.') else { continue };
        let extension = &last[dot + 1..];
        if dot == 0 || !matches!(extension, "app" | "framework" | "appex" | "xpc" | "bundle") {
            continue;
        }
        // `.` matches no line terminator: a prefix with one cannot be the `.*\/` part.
        if path[..start].contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
            continue;
        }
        let better = match best {
            None => true,
            Some((s, o, ..)) => start > s || (start == s && order < o),
        };
        if better {
            best = Some((start, order, path, extension, inner_text));
        }
    }
    best.map(|(_, _, path, extension, inner)| (path, extension, inner))
}

/// Whether a ZIP file holds an app: a bundle's Info.plist anywhere in it.
pub fn is_app_archive(entries: &[ZipEntry]) -> bool {
    entries.iter().any(|e| info_path(&e.name).is_some())
}

fn text(v: Option<&Plist>) -> Option<Vec<u16>> {
    v.and_then(Plist::text).map(<[u16]>::to_vec)
}

/// The programs of an app archive, in the order the TypeScript listed them.
pub fn bundled_programs(bytes: &[u8]) -> Result<Vec<BundledProgram>, ZipError> {
    let entries = zip_entries(bytes)?;
    let mut by_name: FxHashMap<&str, &ZipEntry> = FxHashMap::default();
    for e in &entries {
        by_name.insert(&e.name, e);
    }
    let mut out = Vec::new();
    let mut taken: Vec<&str> = Vec::new();
    for entry in &entries {
        let Some((path, extension, inner)) = info_path(&entry.name) else { continue };
        // Versions/Current is a link to a version listed beside it.
        if entry.name.contains("/Versions/Current/") {
            continue;
        }
        // A bundle with an unreadable Info.plist is still found by its executable's name.
        let info = zip_read(bytes, entry).ok().and_then(|b| parse_plist(&b).ok()).filter(|v| matches!(v, Plist::Dict(_)));
        let get = |key: &str| info.as_ref().and_then(|i| i.get(key));
        let name = path.rsplit('/').next().unwrap_or(path).to_string();
        let executable = match text(get("CFBundleExecutable")) {
            Some(e) => String::from_utf16_lossy(&e),
            None => match name.rfind('.') {
                Some(k) if !name[k + 1..].is_empty() => name[..k].to_string(),
                _ => name.clone(),
            },
        };
        let home = if inner == "Contents/" {
            format!("{path}/Contents/MacOS/")
        } else if inner.starts_with("Versions/") {
            format!("{path}/{}", inner.strip_suffix("Resources/").unwrap_or(inner))
        } else {
            format!("{path}/")
        };
        let exe_name = format!("{home}{executable}");
        let Some(exe) = by_name.get(exe_name.as_str()) else { continue };
        if exe.size == 0 {
            continue;
        }
        taken.push(&exe.name);
        let mut bundle = Bundle {
            kind: match extension {
                "app" => "app",
                "framework" => "framework",
                "appex" | "xpc" => "extension",
                _ => "bundle",
            },
            path: path.to_string(),
            name,
            identifier: text(get("CFBundleIdentifier")),
            version: text(get("CFBundleShortVersionString")),
            build: text(get("CFBundleVersion")),
            minimum_os: text(get("MinimumOSVersion")).or_else(|| text(get("LSMinimumSystemVersion"))),
            platforms: match get("CFBundleSupportedPlatforms") {
                Some(Plist::Array(a)) => Some(a.iter().filter_map(|p| p.text().map(<[u16]>::to_vec)).collect()),
                _ => None,
            },
            profile: None,
        };
        let profile =
            by_name.get(format!("{path}/embedded.mobileprovision").as_str()).or_else(|| by_name.get(format!("{path}/Contents/embedded.provisionprofile").as_str())).copied();
        if let Some(profile) = profile {
            bundle.profile = read_profile(&zip_read(bytes, profile)?);
        }
        out.push(BundledProgram { bundle, file: executable, size: exe.size, entry: (*exe).clone() });
    }
    // Libraries outside any bundle's executable: Swift's runtime in older apps, plug-in dylibs.
    for entry in &entries {
        if !entry.name.ends_with(".dylib") || taken.contains(&entry.name.as_str()) || entry.size == 0 || entry.name.contains("/Versions/Current/") {
            continue;
        }
        let slash = entry.name.rfind('/');
        let file = slash.map_or(entry.name.as_str(), |k| &entry.name[k + 1..]).to_string();
        let path = slash.map_or("", |k| &entry.name[..k]).to_string();
        out.push(BundledProgram {
            bundle: Bundle { kind: "library", path, name: file.clone(), identifier: None, version: None, build: None, minimum_os: None, platforms: None, profile: None },
            file,
            size: entry.size,
            entry: entry.clone(),
        });
    }
    Ok(out)
}

/// What a provisioning profile says about who may run the app and where.
pub fn read_profile(bytes: &[u8]) -> Option<Profile> {
    let value = profile_plist(bytes)?;
    if !matches!(value, Plist::Dict(_)) {
        return None;
    }
    let date = |v: Option<&Plist>| match v {
        Some(Plist::Date(t)) => Some(*t),
        _ => None,
    };
    let empty = Plist::Dict(Vec::new());
    let entitlements = match value.get("Entitlements") {
        Some(e @ Plist::Dict(_)) => e,
        _ => &empty,
    };
    let team_ids: &[Plist] = match value.get("TeamIdentifier") {
        Some(Plist::Array(a)) => a,
        _ => &[],
    };
    let yes = |v: Option<&Plist>| v == Some(&Plist::Bool(true));
    Some(Profile {
        name: text(value.get("Name")),
        team: text(value.get("TeamName")),
        team_id: text(team_ids.first()),
        app_id: text(entitlements.get("application-identifier")).or_else(|| text(entitlements.get("com.apple.application-identifier"))),
        created: date(value.get("CreationDate")),
        expires: date(value.get("ExpirationDate")),
        devices: match value.get("ProvisionedDevices") {
            Some(Plist::Array(a)) => Some(a.len()),
            _ => None,
        },
        all_devices: yes(value.get("ProvisionsAllDevices")),
        debuggable: yes(entitlements.get("get-task-allow")) || yes(entitlements.get("com.apple.security.get-task-allow")),
    })
}

#[cfg(test)]
mod tests {
    use super::info_path;

    #[test]
    fn info_paths() {
        assert_eq!(info_path("Payload/Hello.app/Info.plist"), Some(("Payload/Hello.app", "app", "")));
        assert_eq!(info_path("Hello.app/Contents/Info.plist"), Some(("Hello.app", "app", "Contents/")));
        assert_eq!(
            info_path("A.app/Contents/Frameworks/F.framework/Versions/A/Resources/Info.plist"),
            Some(("A.app/Contents/Frameworks/F.framework", "framework", "Versions/A/Resources/"))
        );
        assert_eq!(info_path("P/H.app/Frameworks/K.framework/Info.plist"), Some(("P/H.app/Frameworks/K.framework", "framework", "")));
        assert_eq!(info_path("X.bundle/Resources/Info.plist"), Some(("X.bundle", "bundle", "Resources/")));
        assert_eq!(info_path("Info.plist"), None);
        assert_eq!(info_path("a/.app/Info.plist"), None);
    }
}

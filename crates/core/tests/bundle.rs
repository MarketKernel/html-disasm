//! Property lists, provisioning profiles, an app's programs and an Android package's libraries:
//! tests/fixtures/ios/Hello.ipa and tests/fixtures/android/hello.apk (made by their build.sh), and
//! the small cases the TypeScript's tests had.

use disasm_core::bundle::{bundled_programs, read_profile};
use disasm_core::plist::{parse_date, parse_plist, Plist};
use disasm_core::zip::{zip_entries, zip_read};

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../../tests/fixtures/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn text(v: Option<&Plist>) -> Option<String> {
    v.and_then(Plist::text).map(String::from_utf16_lossy)
}

#[test]
fn xml_property_lists() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Name</key><string>Fish &amp; Chips</string>
  <key>Count</key><integer>-3</integer>
  <key>Ratio</key><real>0.5</real>
  <key>On</key><true/>
  <key>Off</key><false/>
  <key>Empty</key><string/>
  <key>When</key><date>2026-01-02T03:04:05Z</date>
  <key>Bytes</key><data>AAEC</data>
  <key>List</key><array><string>a</string><dict/></array>
</dict>
</plist>"#;
    let v = parse_plist(xml.as_bytes()).unwrap();
    assert_eq!(text(v.get("Name")).as_deref(), Some("Fish & Chips"), "a string with an entity");
    assert_eq!([v.get("Count"), v.get("Ratio")], [Some(&Plist::Num(-3.0)), Some(&Plist::Num(0.5))]);
    assert_eq!([v.get("On"), v.get("Off"), v.get("Empty")], [Some(&Plist::Bool(true)), Some(&Plist::Bool(false)), Some(&Plist::Str(Vec::new()))]);
    assert_eq!(v.get("When"), Some(&Plist::Date(parse_date("2026-01-02T03:04:05.000Z"))));
    assert_eq!(v.get("Bytes"), Some(&Plist::Data(vec![0, 1, 2])));
    assert_eq!(v.get("List"), Some(&Plist::Array(vec![Plist::Str(units("a")), Plist::Dict(Vec::new())])));
    assert!(parse_plist(b"hello").is_err(), "not a plist");
}

#[test]
fn a_provisioning_profile() {
    // The plist sits inside a CMS signature, found by its text.
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>Name</key><string>Hello Dev</string><key>TeamName</key><string>Example Ltd</string>
<key>TeamIdentifier</key><array><string>ABCDE12345</string></array>
<key>ExpirationDate</key><date>2027-05-06T00:00:00Z</date>
<key>ProvisionedDevices</key><array><string>00008101-000A</string><string>00008101-000B</string></array>
<key>Entitlements</key><dict><key>application-identifier</key><string>ABCDE12345.com.example.hello</string><key>get-task-allow</key><true/></dict>
</dict></plist>"#;
    let mut cms = vec![0x30, 0x80, 0x06, 0x09];
    cms.extend_from_slice(xml.as_bytes());
    cms.extend_from_slice(&[0xa0, 0x82, 0x00, 0x00]);
    let p = read_profile(&cms).unwrap();
    assert_eq!(
        [p.name, p.team, p.team_id, p.app_id],
        [Some(units("Hello Dev")), Some(units("Example Ltd")), Some(units("ABCDE12345")), Some(units("ABCDE12345.com.example.hello"))]
    );
    assert_eq!((p.devices, p.all_devices, p.debuggable), (Some(2), false, true));
    assert_eq!(p.expires, Some(parse_date("2027-05-06")));
}

#[test]
fn an_ipa() {
    let ipa = fixture("ios/Hello.ipa");
    let programs = bundled_programs(&ipa).unwrap();
    let mut kinds: Vec<String> = programs.iter().map(|p| format!("{}:{}", p.bundle.kind, p.file)).collect();
    kinds.sort();
    assert_eq!(kinds, ["app:Hello", "framework:HelloKit"]);
    let app = programs.iter().find(|p| p.bundle.kind == "app").unwrap();
    let b = &app.bundle;
    assert_eq!(b.path, "Payload/Hello.app");
    assert_eq!([&b.identifier, &b.version, &b.build, &b.minimum_os], [&Some(units("com.example.hello")), &Some(units("1.2")), &Some(units("34")), &Some(units("15.0"))]);
    assert_eq!(b.platforms, Some(vec![units("iPhoneOS")]));
    assert_eq!(zip_read(&ipa, &app.entry).unwrap().len(), fixture("ios/Hello").len(), "the app is the stripped executable");
}

#[test]
fn stored_and_deflated_libraries() {
    let apk = fixture("android/hello.apk");
    let mut methods: Vec<u16> = zip_entries(&apk).unwrap().iter().filter(|e| e.name.ends_with(".so")).map(|e| e.method).collect();
    methods.sort();
    assert_eq!(methods, [0, 8]);
}

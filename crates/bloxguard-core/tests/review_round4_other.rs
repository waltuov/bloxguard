//! Review round 4 (fix round 5) items 13 and 15, which live outside the
//! analysis module. Every fixture is synthetic: FAKE names, IDs in the reserved
//! 999000000000000 range and inert text. Nothing here executes Luau.

use bloxguard_core::config::Config;
use bloxguard_core::engine::scan_documents;
use bloxguard_core::loading::{load_bytes, load_path};
use bloxguard_core::model::{Completeness, Document, Limits};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Item 13: an attribute blob that does not decode makes the input partial in
// every format, and a valid one stays complete.
// ---------------------------------------------------------------------------

const FORMATS: [&str; 4] = ["rbxmx", "rbxlx", "rbxm", "rbxl"];
/// The script beside the attributes, so every case also shows that the rest of
/// the file is still scanned.
const SOURCE: &str = "require(999000000004130)\nreturn require(script:GetAttribute(\"FAKE_Id\"))";

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for group in bytes.chunks(3) {
        let bits = group.iter().enumerate().fold(0u32, |bits, (index, byte)| {
            bits | (u32::from(*byte) << (16 - 8 * index))
        });
        for index in 0..4 {
            if index <= group.len() {
                encoded.push(ALPHABET[((bits >> (18 - 6 * index)) & 63) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_item(class: &str, source: Option<&str>, blob: &[u8]) -> Vec<u8> {
    let source = source.map_or_else(String::new, |source| {
        format!(
            r#"<ProtectedString name="Source">{}</ProtectedString>"#,
            xml_escape(source)
        )
    });
    format!(
        r#"<roblox version="4"><Item class="{class}" referent="RBX1"><Properties><string name="Name">FAKE_Attributes</string>{source}<BinaryString name="AttributesSerialize">{}</BinaryString></Properties></Item></roblox>"#,
        base64(blob)
    )
    .into_bytes()
}

fn xml_file(blob: &[u8]) -> Vec<u8> {
    xml_item("ModuleScript", Some(SOURCE), blob)
}

fn length_prefixed(value: &[u8]) -> Vec<u8> {
    let mut out = (value.len() as u32).to_le_bytes().to_vec();
    out.extend(value);
    out
}

fn chunk(name: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = name.to_vec();
    out.extend(0u32.to_le_bytes());
    out.extend((data.len() as u32).to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(data);
    out
}

/// The same instance as `xml_item`, in the binary format, as the reviewer's
/// R06 to R08 build it.
fn binary_item(class: &str, source: Option<&str>, blob: &[u8]) -> Vec<u8> {
    let mut out = b"<roblox!\x89\xff\r\n\x1a\n\0\0".to_vec();
    out.extend(1u32.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    out.extend(0u64.to_le_bytes());
    let mut inst = 0u32.to_le_bytes().to_vec();
    inst.extend(length_prefixed(class.as_bytes()));
    inst.push(0);
    inst.extend(1u32.to_le_bytes());
    inst.extend([0; 4]);
    out.extend(chunk(b"INST", &inst));
    let mut properties = vec![(&b"Name"[..], &b"FAKE_Attributes"[..])];
    if let Some(source) = source {
        properties.push((b"Source", source.as_bytes()));
    }
    properties.push((b"AttributesSerialize", blob));
    for (name, value) in properties {
        let mut prop = 0u32.to_le_bytes().to_vec();
        prop.extend(length_prefixed(name));
        prop.push(0x01);
        prop.extend(length_prefixed(value));
        out.extend(chunk(b"PROP", &prop));
    }
    out.extend(chunk(b"PRNT", b"\0\x01\0\0\0\0\0\0\0\0\0\0\x01"));
    out.extend(chunk(b"END\0", b"</roblox>"));
    out
}

fn binary_file(blob: &[u8]) -> Vec<u8> {
    binary_item("ModuleScript", Some(SOURCE), blob)
}

fn load(format: &str, blob: &[u8]) -> Document {
    let bytes = if format.ends_with('x') {
        xml_file(blob)
    } else {
        binary_file(blob)
    };
    load_bytes(
        &format!("FAKE_attributes.{format}"),
        format,
        &bytes,
        &Limits::default(),
    )
}

/// The input is partial for the attribute blob alone, and the script is read.
fn assert_unreadable(format: &str, blob: &[u8], label: &str) {
    let document = load(format, blob);
    assert_eq!(
        document.completeness,
        Completeness::Partial,
        "{label} {format}: {:?}",
        document.reasons
    );
    assert_eq!(
        document.reasons.len(),
        1,
        "{label} {format}: {:?}",
        document.reasons
    );
    assert!(
        document.reasons[0].starts_with("unreadable attributes on \"FAKE_Attributes\": "),
        "{label} {format}: {:?}",
        document.reasons
    );
    assert_eq!(document.instances.len(), 1, "{label} {format}");
    assert_eq!(
        document.instances[0].source.as_deref(),
        Some(SOURCE),
        "{label} {format}"
    );
    assert!(
        document.instances[0].attributes.is_empty(),
        "{label} {format}"
    );
}

/// A blob built field by field, which remembers where its lengths, counts and
/// type bytes are.
#[derive(Default)]
struct Blob {
    bytes: Vec<u8>,
    /// Offsets of every `u32` length or count.
    lengths: Vec<usize>,
    /// Offsets of every value type byte.
    types: Vec<usize>,
    /// Offsets of the first byte of every attribute name.
    names: Vec<usize>,
}

impl Blob {
    fn new(count: u32) -> Self {
        let mut blob = Self::default();
        blob.length(count);
        blob
    }
    fn length(&mut self, value: u32) {
        self.lengths.push(self.bytes.len());
        self.bytes.extend(value.to_le_bytes());
    }
    fn string(&mut self, value: &[u8]) {
        self.length(value.len() as u32);
        self.bytes.extend(value);
    }
    fn attribute(&mut self, name: &str, value_type: u8) -> &mut Self {
        self.length(name.len() as u32);
        self.names.push(self.bytes.len());
        self.bytes.extend(name.as_bytes());
        self.types.push(self.bytes.len());
        self.bytes.push(value_type);
        self
    }
    fn raw(&mut self, value: &[u8]) -> &mut Self {
        self.bytes.extend(value);
        self
    }
    fn f32s(&mut self, values: &[f32]) -> &mut Self {
        for value in values {
            self.bytes.extend(value.to_le_bytes());
        }
        self
    }
}

/// One attribute of every type rbx_types 3.1 reads, all valid.
fn every_type() -> Blob {
    let mut blob = Blob::new(18);
    blob.attribute("FAKE_Id", 0x06)
        .raw(&999_000_000_004_131f64.to_le_bytes());
    blob.attribute("FAKE_Text", 0x02);
    blob.string(b"FAKE text");
    blob.attribute("FAKE_Bool", 0x03).raw(&[1]);
    blob.attribute("FAKE_Int", 0x04).raw(&(-7i32).to_le_bytes());
    blob.attribute("FAKE_Float", 0x05).f32s(&[0.5]);
    blob.attribute("FAKE_UDim", 0x09)
        .f32s(&[0.25])
        .raw(&3i32.to_le_bytes());
    blob.attribute("FAKE_UDim2", 0x0a)
        .f32s(&[0.5])
        .raw(&1i32.to_le_bytes())
        .f32s(&[0.5])
        .raw(&2i32.to_le_bytes());
    blob.attribute("FAKE_Brick", 0x0e)
        .raw(&194u32.to_le_bytes());
    blob.attribute("FAKE_Color", 0x0f).f32s(&[1.0, 0.5, 0.0]);
    blob.attribute("FAKE_V2", 0x10).f32s(&[1.0, 2.0]);
    blob.attribute("FAKE_V3", 0x11).f32s(&[1.0, 2.0, 3.0]);
    blob.attribute("FAKE_CFrame", 0x14)
        .f32s(&[1.0, 2.0, 3.0])
        .raw(&[0])
        .f32s(&[1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]);
    blob.attribute("FAKE_Enum", 0x15);
    blob.string(b"Material");
    blob.raw(&256u32.to_le_bytes());
    blob.attribute("FAKE_Numbers", 0x17);
    blob.length(2);
    blob.f32s(&[0.0, 0.0, 1.0, 0.0, 1.0, 2.0]);
    blob.attribute("FAKE_Colors", 0x19);
    blob.length(2);
    blob.f32s(&[0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0]);
    blob.attribute("FAKE_Range", 0x1b).f32s(&[1.0, 2.0]);
    blob.attribute("FAKE_Rect", 0x1c)
        .f32s(&[0.0, 0.0, 4.0, 4.0]);
    blob.attribute("FAKE_Font", 0x21)
        .raw(&400u16.to_le_bytes())
        .raw(&[0]);
    blob.string(b"rbxasset://fonts/families/FAKE.json");
    blob.string(b"");
    blob
}

#[test]
fn item13_review_r04_to_r09_and_h20() {
    // R04 to R07: one attribute FAKE with the invalid type byte 255.
    let mut bad = 1u32.to_le_bytes().to_vec();
    bad.extend(length_prefixed(b"FAKE"));
    bad.push(0xff);
    // H20: the same entry under a count of 3.
    let mut h20 = 3u32.to_le_bytes().to_vec();
    h20.extend(&bad[4..]);
    for format in FORMATS {
        for (label, blob) in [("R04 to R07", &bad), ("H20", &h20)] {
            assert_unreadable(format, blob, label);
            let reason = &load(format, blob).reasons[0];
            assert!(reason.contains("unknown value type 0xff"), "{reason}");
        }
    }
    // R08 and R09: the same structure with the Float64 999000000009004.
    let mut good = 1u32.to_le_bytes().to_vec();
    good.extend(length_prefixed(b"FAKE_Id"));
    good.push(0x06);
    good.extend(999_000_000_009_004f64.to_le_bytes());
    for format in FORMATS {
        let document = load(format, &good);
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{format}: {:?}",
            document.reasons
        );
        assert_eq!(
            document.instances[0].attributes.get("FAKE_Id"),
            Some(&Value::from(999_000_000_009_004f64)),
            "{format}"
        );
        // The attribute reaches the analysis: BG002 resolves the ID.
        let report = scan_documents(vec![document], &Config::default());
        let bg002 = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "BG002")
            .unwrap_or_else(|| panic!("{format}: {:?}", report.findings));
        assert!(
            bg002.evidence.contains("999000000009004"),
            "{}",
            bg002.evidence
        );
    }
}

#[test]
fn item13_every_valid_attribute_type_stays_complete() {
    let blob = every_type();
    for format in FORMATS {
        let document = load(format, &blob.bytes);
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{format}: {:?}",
            document.reasons
        );
        let attributes = &document.instances[0].attributes;
        assert_eq!(attributes.len(), 18, "{format}: {attributes:?}");
        assert_eq!(attributes["FAKE_Text"], "FAKE text");
        assert_eq!(attributes["FAKE_Int"], -7);
        assert_eq!(attributes["FAKE_Bool"], true);
    }
    // An empty blob, a zero count and bytes after the last attribute are what
    // the reader accepts, so they stay complete too.
    let mut trailing = blob.bytes.clone();
    trailing.extend(b"FAKE trailing");
    for extra in [Vec::new(), 0u32.to_le_bytes().to_vec(), trailing] {
        for format in FORMATS {
            let document = load(format, &extra);
            assert_eq!(
                document.completeness,
                Completeness::Complete,
                "{format} {} bytes: {:?}",
                extra.len(),
                document.reasons
            );
        }
    }
}

#[test]
fn item13_every_cut_of_a_valid_blob_is_unreadable() {
    let blob = every_type().bytes;
    let mut checked = 0;
    for cut in 1..blob.len() {
        for format in FORMATS {
            assert_unreadable(format, &blob[..cut], &format!("cut at {cut}"));
            checked += 1;
        }
    }
    assert!(checked > 1_000, "{checked}");
}

#[test]
fn item13_unknown_type_bytes_at_every_attribute_are_unreadable() {
    let blob = every_type();
    let unknown = [
        0x00, 0x01, 0x07, 0x08, 0x0b, 0x0c, 0x0d, 0x12, 0x13, 0x16, 0x18, 0x1a, 0x1d, 0x1e, 0x1f,
        0x20, 0x22, 0x7f, 0x80, 0xfe, 0xff,
    ];
    let mut checked = 0;
    for (position, &offset) in blob.types.iter().enumerate() {
        for value_type in unknown {
            let mut bytes = blob.bytes.clone();
            bytes[offset] = value_type;
            for format in FORMATS {
                let label = format!("attribute {} type 0x{value_type:02x}", position + 1);
                assert_unreadable(format, &bytes, &label);
                let reason = &load(format, &bytes).reasons[0];
                assert!(
                    reason.contains(&format!(
                        "attribute {} has unknown value type 0x{value_type:02x}",
                        position + 1
                    )),
                    "{label}: {reason}"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 18 * unknown.len() * 4);
}

#[test]
fn item13_oversized_lengths_and_counts_are_unreadable_without_large_allocations() {
    // Every length, count and sequence size set past the end of the blob. Each
    // one would reserve up to tens of GiB inside rbx_types; the scanner checks
    // the blob first, so these finish at once.
    let blob = every_type();
    let started = std::time::Instant::now();
    let mut checked = 0;
    // The attribute count at offset 0 is checked below.
    for &offset in &blob.lengths[1..] {
        let left = (blob.bytes.len() - offset - 4) as u32;
        for value in [u32::MAX, 0x7fff_ffff, 0x1000_0000, left + 1] {
            let mut bytes = blob.bytes.clone();
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            for format in FORMATS {
                assert_unreadable(format, &bytes, &format!("length at {offset} = {value}"));
                checked += 1;
            }
        }
    }
    // An attribute count larger than the attributes present.
    for count in [19, 1_000, u32::MAX] {
        let mut bytes = blob.bytes.clone();
        bytes[..4].copy_from_slice(&count.to_le_bytes());
        for format in FORMATS {
            assert_unreadable(format, &bytes, &format!("count {count}"));
            checked += 1;
        }
    }
    assert!(checked > 300, "{checked}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn item13_values_the_reader_refuses_are_unreadable() {
    let blob = every_type();
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    // A name that is not UTF-8.
    let mut bytes = blob.bytes.clone();
    bytes[blob.names[2]] = 0xff;
    cases.push(("name not UTF-8", bytes));
    // A BrickColor number with no color.
    let mut bytes = blob.bytes.clone();
    let brick = blob.types[7] + 1;
    bytes[brick..brick + 4].copy_from_slice(&9_999u32.to_le_bytes());
    cases.push(("BrickColor 9999", bytes));
    // A CFrame rotation id that names no basic rotation.
    let mut cframe = Blob::new(1);
    cframe
        .attribute("FAKE_CFrame", 0x14)
        .f32s(&[1.0, 2.0, 3.0])
        .raw(&[1]);
    cases.push(("CFrame rotation 1", cframe.bytes));
    // Text inside an EnumItem name and a Font family that is not UTF-8.
    for (label, value_type) in [("EnumItem name", 0x15u8), ("Font family", 0x21)] {
        let mut odd = Blob::new(1);
        odd.attribute("FAKE_Odd", value_type);
        if value_type == 0x21 {
            odd.raw(&400u16.to_le_bytes()).raw(&[0]);
        }
        odd.string(b"FAKE\xff");
        if value_type == 0x21 {
            odd.string(b"");
        } else {
            odd.raw(&1u32.to_le_bytes());
        }
        cases.push((label, odd.bytes));
    }
    for (label, bytes) in &cases {
        for format in FORMATS {
            assert_unreadable(format, bytes, label);
        }
    }
}

#[test]
fn item13_a_bad_blob_on_one_instance_keeps_the_others_readable() {
    // Two Folders in one XML file: the first has a valid attribute, the second
    // a bad one. Only the second loses its attributes.
    let mut good = 1u32.to_le_bytes().to_vec();
    good.extend(length_prefixed(b"FAKE_Id"));
    good.push(0x06);
    good.extend(999_000_000_004_132f64.to_le_bytes());
    let mut bad = good.clone();
    bad[4 + 4 + 7] = 0xff;
    let item = |referent: u32, name: &str, blob: &[u8]| {
        format!(
            r#"<Item class="Folder" referent="RBX{referent}"><Properties><string name="Name">{name}</string><BinaryString name="AttributesSerialize">{}</BinaryString></Properties></Item>"#,
            base64(blob)
        )
    };
    let xml = format!(
        r#"<roblox version="4">{}{}</roblox>"#,
        item(1, "FAKE_Good", &good),
        item(2, "FAKE_Bad", &bad)
    );
    let document = load_bytes(
        "FAKE_two.rbxmx",
        "rbxmx",
        xml.as_bytes(),
        &Limits::default(),
    );
    assert_eq!(document.completeness, Completeness::Partial);
    assert_eq!(document.reasons.len(), 1, "{:?}", document.reasons);
    assert!(
        document.reasons[0].starts_with("unreadable attributes on \"FAKE_Bad\""),
        "{:?}",
        document.reasons
    );
    assert_eq!(document.instances.len(), 2);
    assert_eq!(
        document.instances[0].attributes.get("FAKE_Id"),
        Some(&Value::from(999_000_000_004_132f64))
    );
    assert!(document.instances[1].attributes.is_empty());
}

#[test]
fn item13_attributes_of_an_unknown_class_are_read_or_make_the_input_partial() {
    let load_unknown = |format: &str, blob: &[u8]| {
        let bytes = if format.ends_with('x') {
            xml_item("FAKE_NewClass", None, blob)
        } else {
            binary_item("FAKE_NewClass", None, blob)
        };
        load_bytes(
            &format!("FAKE_unknown.{format}"),
            format,
            &bytes,
            &Limits::default(),
        )
    };
    let mut text = Blob::new(1);
    text.attribute("FAKE_Id", 0x02);
    text.string(b"999000000004133");
    // A Float64, whose bytes are not UTF-8: both decoders keep them exactly.
    let mut number = 1u32.to_le_bytes().to_vec();
    number.extend(length_prefixed(b"FAKE_Id"));
    number.push(0x06);
    number.extend(999_000_000_004_133f64.to_le_bytes());
    for format in FORMATS {
        let document = load_unknown(format, &text.bytes);
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{format}: {:?}",
            document.reasons
        );
        assert_eq!(
            document.instances[0].attributes.get("FAKE_Id"),
            Some(&Value::from("999000000004133")),
            "{format}"
        );
        assert!(
            document
                .diagnostics
                .iter()
                .any(|note| note.message.contains("unknown class \"FAKE_NewClass\"")),
            "{format}: {:?}",
            document.diagnostics
        );

        let document = load_unknown(format, &number);
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{format}: {:?}",
            document.reasons
        );
        assert_eq!(
            document.instances[0].attributes.get("FAKE_Id"),
            Some(&Value::from(999_000_000_004_133f64)),
            "{format}"
        );

        let mut bad = text.bytes.clone();
        bad[text.types[0]] = 0xff;
        let document = load_unknown(format, &bad);
        assert_eq!(document.completeness, Completeness::Partial, "{format}");
        assert!(
            document.reasons[0].starts_with("unreadable attributes on \"FAKE_Attributes\""),
            "{format}: {:?}",
            document.reasons
        );
    }
}

// ---------------------------------------------------------------------------
// Item 15: a Rojo project file that is not valid JSONC makes the input
// partial; comments and trailing commas in every position still read.
// ---------------------------------------------------------------------------

const PROJECT_NAMES: [&str; 2] = ["default.project.json", "default.project.jsonc"];

/// A source tree with one script and one project file, rewritten per case.
struct ProjectTree {
    root: tempfile::TempDir,
}

impl ProjectTree {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("bloxguard_FAKE_jsonc_")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("create repository-local temp directory");
        std::fs::write(root.path().join("FAKE_s.luau"), "return 1").unwrap();
        Self { root }
    }

    fn load(&self, name: &str, project: &str) -> Document {
        for other in PROJECT_NAMES {
            let _ = std::fs::remove_file(self.root.path().join(other));
        }
        std::fs::write(self.root.path().join(name), project).unwrap();
        load_path(self.root.path(), &Limits::default())
            .pop()
            .expect("one document")
    }

    fn assert_refused(&self, project: &str, label: &str) -> Vec<String> {
        let mut reasons = Vec::new();
        for name in PROJECT_NAMES {
            let document = self.load(name, project);
            assert_eq!(
                document.completeness,
                Completeness::Partial,
                "{label} in {name}: {project:?}"
            );
            assert_eq!(document.reasons.len(), 1, "{label}: {:?}", document.reasons);
            assert!(
                document.reasons[0].starts_with("Rojo project mapping in ")
                    && document.reasons[0].contains(&format!("{name} could not be checked: ")),
                "{label}: {:?}",
                document.reasons
            );
            reasons.push(document.reasons[0].clone());
        }
        reasons
    }

    fn assert_read(&self, project: &str, label: &str) {
        for name in PROJECT_NAMES {
            let document = self.load(name, project);
            assert_eq!(
                document.completeness,
                Completeness::Complete,
                "{label} in {name}: {:?}",
                document.reasons
            );
        }
    }
}

#[test]
fn item15_review_h29_and_other_unterminated_block_comments_are_partial() {
    let tree = ProjectTree::new();
    let h29 = "{\"name\":\"FAKE\",\"tree\":{\"$className\":\"DataModel\",/* FAKE */\"FAKE\":{\"$path\":\"./FAKE_s.luau\"},},}\n/* incomplete";
    for (label, project) in [
        ("H29", h29.to_owned()),
        (
            "inside the tree",
            r#"{"name":"FAKE","tree":{"$className":"DataModel" /* FAKE"#.to_owned(),
        ),
        (
            "after a trailing comma",
            r#"{"name":"FAKE","tree":{"$className":"DataModel", /* FAKE }}"#.to_owned(),
        ),
        (
            "slash star slash",
            r#"{"name":"FAKE","tree":{}}/*/"#.to_owned(),
        ),
        (
            "only an opener",
            r#"{"name":"FAKE","tree":{}}/*"#.to_owned(),
        ),
        (
            "a spaced closer in quotes",
            r#"{"name":"FAKE","tree":{}} /* "* /""#.to_owned(),
        ),
        (
            "long",
            format!(
                r#"{{"name":"FAKE","tree":{{}}}} /* {}"#,
                "FAKE ".repeat(20_000)
            ),
        ),
    ] {
        for reason in tree.assert_refused(&project, label) {
            assert!(reason.ends_with("has no closing */"), "{label}: {reason}");
        }
    }
}

#[test]
fn item15_other_jsonc_mistakes_are_partial() {
    let tree = ProjectTree::new();
    for (label, project) in [
        ("cut off string", r#"{"name":"FAKE","tree":{"$path":"src}"#),
        ("cut off key", r#"{"name":"FAKE","tree":{"$pa"#),
        ("lone slash", r#"{"name":"FAKE","tree":{}} /"#),
        ("lone slash inside", r#"{"name":"FAKE",/"tree":{}}"#),
        ("stray closer", r#"{"name":"FAKE","tree":{}} */"#),
        ("single quotes", r#"{'name':'FAKE','tree':{}}"#),
        ("two commas", r#"{"name":"FAKE",,"tree":{}}"#),
        ("leading comma", r#"{,"name":"FAKE","tree":{}}"#),
        ("empty", ""),
        ("only a comment", "// FAKE"),
    ] {
        tree.assert_refused(project, label);
    }
}

/// A JSONC project with comments and trailing commas wherever they can go.
const JSONC_PROJECT: &str = "// FAKE head\n{ /* FAKE */ \"name\": \"FAKE /* not a comment */ // nor this\", // FAKE\n  \"tree\": { \"$className\": \"DataModel\", /* FAKE \"quote\" */\n    \"FAKE\": { \"$path\": \"src//FAKE_missing\", /**/ }, /***/ // FAKE\n  }, // FAKE\n  /* FAKE */ }";

#[test]
fn item15_comments_and_trailing_commas_in_every_position_still_read() {
    let tree = ProjectTree::new();
    tree.assert_read(JSONC_PROJECT, "JSONC project");
    for (label, project) in [
        (
            "line comment at the end without a newline",
            r#"{"name":"FAKE","tree":{}} // FAKE"#,
        ),
        (
            "block comment at the end",
            r#"{"name":"FAKE","tree":{}} /* FAKE */"#,
        ),
        (
            "trailing comma before a line comment",
            "{\"name\":\"FAKE\",\"tree\":{},// FAKE\n}",
        ),
        (
            "trailing comma in an array",
            r#"{"name":"FAKE","globIgnorePaths":["FAKE",/* c */],"tree":{}}"#,
        ),
        ("plain JSON", r#"{"name":"FAKE","tree":{}}"#),
    ] {
        tree.assert_read(project, label);
    }
}

#[test]
fn item15_every_cut_of_a_jsonc_project_is_partial() {
    // Each cut ends inside the root object, so none is a whole project.
    let tree = ProjectTree::new();
    let last = JSONC_PROJECT.rfind('}').unwrap();
    let mut checked = 0;
    for cut in 1..=last {
        if !JSONC_PROJECT.is_char_boundary(cut) {
            continue;
        }
        tree.assert_refused(&JSONC_PROJECT[..cut], &format!("cut at {cut}"));
        checked += 1;
    }
    assert!(checked > 150, "{checked}");
}

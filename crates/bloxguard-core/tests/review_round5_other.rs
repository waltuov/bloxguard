//! Review round 5 (fix round 6) items 5 to 8, which live outside the analysis
//! module. Every fixture is synthetic: FAKE names, IDs in the reserved
//! 999000000000000 range and inert text. Nothing here executes Luau.
//!
//! The caps are written as numbers rather than read from the crate, so this
//! file also builds against the code before the fix and shows what changed.

use bloxguard_core::config::Config;
use bloxguard_core::engine::scan_documents;
use bloxguard_core::loading::{load_bundle, load_bytes, load_path};
use bloxguard_core::model::{Bundle, Completeness, Document, Instance, Limits};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Item 5: attribute caps. At most 10,000 attributes on one instance, 500,000
// in one input and 32 MiB of attribute data decoded per input. A blob above a
// cap is skipped before it is decoded, and the rest of the input is scanned.
// ---------------------------------------------------------------------------

const PER_INSTANCE: usize = 10_000;
const PER_INPUT: usize = 500_000;
const DATA_PER_INPUT: usize = 32 * 1024 * 1024;

const FORMATS: [&str; 4] = ["rbxmx", "rbxlx", "rbxm", "rbxl"];
const SOURCE: &str = "require(999000000006001)\nreturn script:GetAttribute(\"a0\")";

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len() / 3 * 4 + 4);
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

fn length_prefixed(value: &[u8]) -> Vec<u8> {
    let mut out = (value.len() as u32).to_le_bytes().to_vec();
    out.extend(value);
    out
}

/// `count` distinct Bool attributes named `<prefix><n>`.
fn bool_blob(prefix: &str, count: usize) -> Vec<u8> {
    let mut blob = (count as u32).to_le_bytes().to_vec();
    for index in 0..count {
        blob.extend(length_prefixed(format!("{prefix}{index}").as_bytes()));
        blob.extend([0x03, 0x01]);
    }
    blob
}

/// One String attribute `FAKE_text`, padded so the whole blob is `total` bytes.
fn string_blob(total: usize) -> Vec<u8> {
    let name = b"FAKE_text";
    let value_len = total - (4 + 4 + name.len() + 1 + 4);
    let mut blob = 1u32.to_le_bytes().to_vec();
    blob.extend(length_prefixed(name));
    blob.push(0x02);
    blob.extend((value_len as u32).to_le_bytes());
    blob.extend(std::iter::repeat_n(b'F', value_len));
    assert_eq!(blob.len(), total);
    blob
}

fn chunk(name: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = name.to_vec();
    out.extend(0u32.to_le_bytes());
    out.extend((data.len() as u32).to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(data);
    out
}

/// Referents as the binary format stores them: zigzag deltas, interleaved.
fn referents(values: &[i32]) -> Vec<u8> {
    let mut previous = 0i32;
    let words: Vec<[u8; 4]> = values
        .iter()
        .map(|&value| {
            let delta = value.wrapping_sub(previous);
            previous = value;
            (((delta << 1) ^ (delta >> 31)) as u32).to_be_bytes()
        })
        .collect();
    (0..4)
        .flat_map(|byte| words.iter().map(move |word| word[byte]))
        .collect()
}

/// A binary model of top-level instances of one class, each with a name, an
/// optional source and an attribute blob.
fn binary_model(class: &str, items: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    let count = items.len();
    let ids: Vec<i32> = (0..count as i32).collect();
    let mut out = b"<roblox!\x89\xff\r\n\x1a\n\0\0".to_vec();
    out.extend(1u32.to_le_bytes());
    out.extend((count as u32).to_le_bytes());
    out.extend(0u64.to_le_bytes());
    let mut inst = 0u32.to_le_bytes().to_vec();
    inst.extend(length_prefixed(class.as_bytes()));
    inst.push(0);
    inst.extend((count as u32).to_le_bytes());
    inst.extend(referents(&ids));
    out.extend(chunk(b"INST", &inst));
    let mut properties: Vec<(&[u8], Vec<&[u8]>)> = vec![
        (
            b"Name",
            items.iter().map(|item| item.0.as_bytes()).collect(),
        ),
        (
            b"AttributesSerialize",
            items.iter().map(|item| item.2).collect(),
        ),
    ];
    if items.iter().any(|item| item.1.is_some()) {
        properties.push((
            b"Source",
            items
                .iter()
                .map(|item| item.1.unwrap_or_default().as_bytes())
                .collect(),
        ));
    }
    for (name, values) in properties {
        let mut prop = 0u32.to_le_bytes().to_vec();
        prop.extend(length_prefixed(name));
        prop.push(0x01);
        for value in values {
            prop.extend(length_prefixed(value));
        }
        out.extend(chunk(b"PROP", &prop));
    }
    let mut parents = vec![0u8];
    parents.extend((count as u32).to_le_bytes());
    parents.extend(referents(&ids));
    parents.extend(referents(&vec![-1; count]));
    out.extend(chunk(b"PRNT", &parents));
    out.extend(chunk(b"END\0", b"</roblox>"));
    out
}

fn xml_model(class: &str, items: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut out = String::from(r#"<roblox version="4">"#);
    for (index, (name, source, blob)) in items.iter().enumerate() {
        let source = source.map_or_else(String::new, |source| {
            format!(
                r#"<ProtectedString name="Source">{}</ProtectedString>"#,
                source
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
            )
        });
        out.push_str(&format!(
            r#"<Item class="{class}" referent="RBX{index}"><Properties><string name="Name">{name}</string>{source}<BinaryString name="AttributesSerialize">{}</BinaryString></Properties></Item>"#,
            base64(blob)
        ));
    }
    out.push_str("</roblox>");
    out.into_bytes()
}

fn load_model(format: &str, class: &str, items: &[(&str, Option<&str>, &[u8])]) -> Document {
    let bytes = if format.ends_with('x') {
        xml_model(class, items)
    } else {
        binary_model(class, items)
    };
    load_bytes(
        &format!("FAKE_attributes.{format}"),
        format,
        &bytes,
        &Limits::default(),
    )
}

fn limit_reason(name: &str, detail: &str) -> String {
    format!("attribute limit reached on {name:?}: {detail}; its attributes were not read")
}

/// Review H58 in small: one instance declares more attributes than one
/// instance may hold. Its blob is skipped in every format, the script beside
/// it is still read, and exactly at the cap everything stays.
#[test]
fn item5_review_h58_one_instance_above_the_per_instance_cap_keeps_no_attributes() {
    let over = bool_blob("a", PER_INSTANCE + 1);
    let at = bool_blob("a", PER_INSTANCE);
    for format in FORMATS {
        let document = load_model(
            format,
            "ModuleScript",
            &[("FAKE_Attributes", Some(SOURCE), &over)],
        );
        assert_eq!(
            document.completeness,
            Completeness::Partial,
            "{format}: {:?}",
            document.reasons
        );
        assert_eq!(
            document.reasons,
            [limit_reason(
                "FAKE_Attributes",
                "10001 attributes on one instance, more than 10000"
            )],
            "{format}"
        );
        assert!(document.instances[0].attributes.is_empty(), "{format}");
        assert_eq!(
            document.instances[0].source.as_deref(),
            Some(SOURCE),
            "{format}"
        );

        let document = load_model(
            format,
            "ModuleScript",
            &[("FAKE_Attributes", Some(SOURCE), &at)],
        );
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{format}: {:?}",
            document.reasons
        );
        assert_eq!(
            document.instances[0].attributes.len(),
            PER_INSTANCE,
            "{format}"
        );
    }
}

/// The per-input cap counts every instance. A blob that does not fit is
/// skipped without using up any of the budget, so a smaller blob after it is
/// still read.
#[test]
fn item5_the_per_input_cap_skips_only_the_blobs_that_do_not_fit() {
    let full: Vec<(String, Vec<u8>)> = (0..49)
        .map(|index| (format!("FAKE_F{index}"), bool_blob("a", PER_INSTANCE)))
        .collect();
    let almost = bool_blob("a", PER_INSTANCE - 1);
    let two = bool_blob("a", 2);
    let one = bool_blob("a", 1);
    let mut items: Vec<(&str, Option<&str>, &[u8])> = full
        .iter()
        .map(|(name, blob)| (name.as_str(), None, blob.as_slice()))
        .collect();
    items.push(("FAKE_Almost", None, &almost));
    items.push(("FAKE_Two", None, &two));
    items.push(("FAKE_One", None, &one));
    let document = load_model("rbxm", "Folder", &items);

    assert_eq!(document.completeness, Completeness::Partial);
    assert_eq!(
        document.reasons,
        [limit_reason(
            "FAKE_Two",
            "500001 attributes in the input, more than 500000"
        )]
    );
    let kept: Vec<(&str, usize)> = document
        .instances
        .iter()
        .map(|instance| (instance.name.as_str(), instance.attributes.len()))
        .collect();
    assert_eq!(kept[48], ("FAKE_F48", PER_INSTANCE));
    assert_eq!(
        &kept[49..],
        [
            ("FAKE_Almost", PER_INSTANCE - 1),
            ("FAKE_Two", 0),
            ("FAKE_One", 1)
        ]
    );
    let total: usize = kept.iter().map(|(_, count)| count).sum();
    assert_eq!(total, PER_INPUT);
}

/// Attribute data is capped in bytes too, so one long string value cannot make
/// decoding copy hundreds of megabytes.
#[test]
fn item5_the_attribute_data_cap_counts_blob_bytes_across_instances() {
    let exactly = string_blob(DATA_PER_INPUT);
    let document = load_model("rbxm", "Folder", &[("FAKE_Exact", None, &exactly)]);
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    let text = document.instances[0].attributes["FAKE_text"]
        .as_str()
        .expect("a string attribute")
        .len();
    assert_eq!(text, DATA_PER_INPUT - 22);

    let half = string_blob(DATA_PER_INPUT / 2);
    let more = string_blob(DATA_PER_INPUT / 2 + 1);
    let document = load_model(
        "rbxm",
        "Folder",
        &[("FAKE_First", None, &half), ("FAKE_Second", None, &more)],
    );
    assert_eq!(
        document.reasons,
        [limit_reason(
            "FAKE_Second",
            "33554433 bytes of attribute data in the input, more than 33554432"
        )]
    );
    assert_eq!(document.instances[0].attributes.len(), 1);
    assert!(document.instances[1].attributes.is_empty());
}

fn listed_attributes(count: usize) -> std::collections::BTreeMap<String, Value> {
    (0..count)
        .map(|index| (format!("a{index}"), json!(1)))
        .collect()
}

/// Attributes that arrive as JSON (an MCP bundle) follow the same caps.
#[test]
fn item5_bundle_attributes_follow_the_caps() {
    for (count, completeness) in [
        (PER_INSTANCE, Completeness::Complete),
        (PER_INSTANCE + 1, Completeness::Partial),
    ] {
        let bundle = Bundle {
            schema_version: 1,
            instances: vec![Instance {
                name: "FAKE_Big".into(),
                class: "Folder".into(),
                attributes: listed_attributes(count),
                ..Instance::default()
            }],
        };
        let document = load_bundle(bundle, "mcp/bundle", &Limits::default());
        assert_eq!(
            document.completeness, completeness,
            "{count}: {:?}",
            document.reasons
        );
        if completeness == Completeness::Partial {
            assert_eq!(
                document.reasons,
                [limit_reason(
                    "FAKE_Big",
                    "10001 attributes on one instance, more than 10000"
                )]
            );
            assert!(document.instances[0].attributes.is_empty());
        } else {
            assert_eq!(document.instances[0].attributes.len(), count);
        }
    }
}

fn temp_tree(label: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("bloxguard_FAKE_{label}_"))
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory")
}

/// In a source tree, a JSON model, a nested binary model and a metadata file
/// all draw from one budget for the whole tree.
#[test]
fn item5_a_source_tree_shares_one_attribute_budget() {
    let tree = temp_tree("attribute_budget");
    let children: Vec<Value> = (0..50)
        .map(|index| {
            json!({
                "Name": format!("FAKE_J{index}"),
                "ClassName": "Folder",
                "Attributes": listed_attributes(PER_INSTANCE),
            })
        })
        .collect();
    let model = json!({"Name": "FAKE_Model", "ClassName": "Folder", "Children": children});
    std::fs::write(
        tree.path().join("a.model.json"),
        serde_json::to_vec(&model).unwrap(),
    )
    .unwrap();
    let nested_blob = bool_blob("n", 1);
    std::fs::write(
        tree.path().join("b.rbxm"),
        binary_model("Folder", &[("FAKE_Nested", None, &nested_blob)]),
    )
    .unwrap();
    std::fs::write(tree.path().join("c.server.luau"), "return 1").unwrap();
    std::fs::write(
        tree.path().join("c.meta.json"),
        r#"{"attributes": {"FAKE_x": 1}}"#,
    )
    .unwrap();

    let document = load_path(tree.path(), &Limits::default())
        .pop()
        .expect("one document");
    let detail = "500001 attributes in the input, more than 500000";
    let nested = tree.path().join("b.rbxm");
    assert_eq!(
        document.reasons,
        [
            format!(
                "{}: {}",
                nested.display(),
                limit_reason("FAKE_Nested", detail)
            ),
            limit_reason("c", detail),
        ]
    );
    let total: usize = document
        .instances
        .iter()
        .map(|instance| instance.attributes.len())
        .sum();
    assert_eq!(total, PER_INPUT);
}

// ---------------------------------------------------------------------------
// Item 6: one clock per input. Loading, analysis and inventory share
// `max_file_ms`; a later phase does not start a fresh budget.
// ---------------------------------------------------------------------------

/// A script whose analysis alone takes far longer than a millisecond.
fn slow_script() -> String {
    (0..4_000)
        .map(|index| format!("local FAKE_v{index} = {{{index}, \"FAKE\"}}\n"))
        .collect()
}

/// With a 1 ms budget, analysing the first script uses the whole budget. The
/// inventory then has no time left either, so it lists no script instead of
/// starting a fresh millisecond of its own.
#[test]
fn item6_the_inventory_continues_the_budget_that_analysis_used() {
    let document = Document {
        input: "FAKE_clock.rbxm".into(),
        instances: vec![
            Instance {
                name: "FAKE_Slow".into(),
                class: "ModuleScript".into(),
                source: Some(slow_script()),
                ..Instance::default()
            },
            Instance {
                name: "FAKE_Quick".into(),
                class: "Script".into(),
                source: Some("require(999000000006101)".into()),
                ..Instance::default()
            },
        ],
        ..Document::default()
    };
    let mut config = Config::default();
    config.limits.max_file_ms = 1;
    let report = scan_documents(vec![document], &config);

    assert_eq!(report.completeness, Completeness::Partial);
    let reasons = &report.inputs[0].reasons;
    for reason in [
        "analysis time budget exceeded; remaining scripts unexamined",
        "inventory time budget exceeded",
    ] {
        assert!(reasons.iter().any(|r| r == reason), "{reason}: {reasons:?}");
    }
    assert!(
        report.inventory.is_empty(),
        "{:?}",
        report
            .inventory
            .iter()
            .map(|entry| &entry.instance_path)
            .collect::<Vec<_>>()
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.rule_id != "BG001"),
        "the second script was never analyzed"
    );
}

// ---------------------------------------------------------------------------
// Item 7: JSONC project files. A UTF-8 byte order mark at the start is read,
// and a `//` comment ends at CR, LF or CRLF.
// ---------------------------------------------------------------------------

const PROJECT_NAMES: [&str; 2] = ["default.project.json", "default.project.jsonc"];
const BOM: &str = "\u{feff}";

/// Load a fresh source tree with one script and the given extra files.
fn load_tree(files: &[(&str, &str)]) -> (tempfile::TempDir, Document) {
    let tree = temp_tree("jsonc");
    std::fs::write(tree.path().join("FAKE_s.server.luau"), "return 1").unwrap();
    for (name, text) in files {
        std::fs::write(tree.path().join(name), text).unwrap();
    }
    let document = load_path(tree.path(), &Limits::default())
        .pop()
        .expect("one document");
    (tree, document)
}

fn assert_project_read(project: &str, label: &str) {
    for name in PROJECT_NAMES {
        let (_tree, document) = load_tree(&[(name, project)]);
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{label} in {name}: {:?}",
            document.reasons
        );
    }
}

/// Review H40 and H57 (first review) and H248, H249, H260 and K27 (second review): a BOM at the
/// start of a project file made the input partial.
#[test]
fn item7_review_h40_h57_a_bom_at_the_start_of_a_project_file_is_read() {
    let crlf = "{\r\n  \"name\": \"FAKE\",\r\n  \"tree\": {\r\n    \"$className\": \"DataModel\",\r\n    \"ServerScriptService\": {\"$path\": \"src/server\",},\r\n  },\r\n}\r\n";
    let plain = r#"{"name": "FAKE", "tree": {"$className": "DataModel", "ServerScriptService": {"$path": "src/server"}}}"#;
    let jsonc = "// FAKE head\n{\"name\": \"FAKE\", /* FAKE */ \"tree\": {\"$className\": \"DataModel\",},}\n";
    for (label, body) in [
        ("H40 BOM, CRLF and trailing commas", crlf),
        ("H57 BOM and plain JSON", plain),
        ("BOM before a comment", jsonc),
    ] {
        assert_project_read(&format!("{BOM}{body}"), label);
    }
}

/// Review H250 and H251 (second review): with CR line endings a `//` comment ran to the
/// end of the file.
#[test]
fn item7_review_h250_h251_line_comments_end_at_a_carriage_return() {
    for (label, project) in [
        (
            "CR only",
            "// FAKE head\r{\"name\": \"FAKE\", // FAKE\r\"tree\": {\"$className\": \"DataModel\", // FAKE\r},\r}\r",
        ),
        (
            "CR, LF and CRLF mixed",
            "// FAKE\r{\"name\": \"FAKE\", // FAKE\n\"tree\": {// FAKE\r\n\"$className\": \"DataModel\"},// FAKE\r}",
        ),
        (
            "CR before a trailing comma's closer",
            "{\"name\": \"FAKE\", \"tree\": {},// FAKE\r}",
        ),
        (
            "BOM and CR",
            "\u{feff}{\"name\": \"FAKE\", // FAKE\r\"tree\": {}}",
        ),
    ] {
        assert_project_read(project, label);
    }
}

/// A comment that ends at a CR no longer hides what follows it, so the
/// checks on the rest of the project still run.
#[test]
fn item7_text_after_a_comment_that_ends_at_a_carriage_return_is_checked() {
    for name in PROJECT_NAMES {
        let project = "{\"name\": \"FAKE\", // FAKE note\r\"tree\": {\"$className\": \"DataModel\", \"FAKE_Outside\": {\"$path\": \"../FAKE_outside\"}}}";
        let (_tree, document) = load_tree(&[(name, project)]);
        assert_eq!(document.completeness, Completeness::Partial, "{name}");
        assert_eq!(document.reasons.len(), 1, "{name}: {:?}", document.reasons);
        assert!(
            document.reasons[0]
                .ends_with("maps \"../FAKE_outside\" from outside the scanned tree; that content was not scanned"),
            "{name}: {:?}",
            document.reasons
        );

        let project = format!(
            "{BOM}{{\"name\": \"FAKE\", // FAKE\r\"tree\": {{\"$className\": \"DataModel\", \"Workspace\": {{\"$attributes\": {{\"FAKE_id\": 999000000006301}}}}}}}}"
        );
        let (_tree, document) = load_tree(&[(name, &project)]);
        assert_eq!(document.reasons.len(), 1, "{name}: {:?}", document.reasons);
        assert!(
            document.reasons[0].contains("sets attributes inline at tree/Workspace"),
            "{name}: {:?}",
            document.reasons
        );
    }
}

/// Only one BOM, and only at the very start, is dropped.
#[test]
fn item7_a_bom_anywhere_else_is_still_refused() {
    let plain = r#"{"name": "FAKE", "tree": {}}"#;
    for (label, project) in [
        ("after a space", format!(" {BOM}{plain}")),
        ("two of them", format!("{BOM}{BOM}{plain}")),
        (
            "inside the object",
            format!(r#"{{"name": "FAKE", {BOM}"tree": {{}}}}"#),
        ),
    ] {
        for name in PROJECT_NAMES {
            let (_tree, document) = load_tree(&[(name, &project)]);
            assert_eq!(
                document.completeness,
                Completeness::Partial,
                "{label} in {name}"
            );
            assert!(
                document.reasons[0].contains("could not be checked"),
                "{label} in {name}: {:?}",
                document.reasons
            );
        }
    }
}

/// The same editors write `.meta.json` and `.model.json` files, so a BOM at
/// their start is read too.
#[test]
fn item7_meta_and_model_files_with_a_bom_are_read() {
    let meta = format!(r#"{BOM}{{"attributes": {{"FAKE_id": 999000000006302}}}}"#);
    let model = format!(r#"{BOM}{{"Name": "FAKE_Model", "ClassName": "Folder"}}"#);
    let (_tree, document) =
        load_tree(&[("FAKE_s.meta.json", &meta), ("FAKE_m.model.json", &model)]);
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{:?}",
        document.reasons
    );
    let script = document
        .instances
        .iter()
        .find(|instance| instance.name == "FAKE_s")
        .expect("the script");
    assert_eq!(
        script.attributes.get("FAKE_id"),
        Some(&json!(999000000006302u64))
    );
    assert!(
        document
            .instances
            .iter()
            .any(|instance| instance.name == "FAKE_Model")
    );
}

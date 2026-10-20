//! Review round 6 item 9: Rojo `.jsonc` files in source trees, and the
//! metadata Rojo applies. Rojo 7.7 reads every JSON file kind with either
//! extension through one JSONC parser and applies `<name>.meta.json` and then
//! `<name>.meta.jsonc`. Every fixture is synthetic: FAKE names, IDs in the
//! reserved 999000000000000 range and inert text. Nothing here executes Luau.

use bloxguard_core::config::Config;
use bloxguard_core::engine::scan_documents;
use bloxguard_core::finding::{Finding, Severity};
use bloxguard_core::loading::load_path;
use bloxguard_core::model::{Completeness, Document, Instance, Limits};
use bloxguard_core::report::ScanReport;
use serde_json::json;

const BOM: &str = "\u{feff}";
const READS_OWN_ATTRIBUTE: &str = "require(script:GetAttribute(\"FAKE_id\"))";
const READS_PARENT_ATTRIBUTE: &str = "require(script.Parent:GetAttribute(\"FAKE_id\"))";

fn temp_tree() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("bloxguard_FAKE_jsonc_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory")
}

/// Load a fresh source tree made of `files`, given as relative paths.
fn load(files: &[(&str, &str)]) -> (tempfile::TempDir, Document) {
    let tree = temp_tree();
    for (name, text) in files {
        let path = tree.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let document = load_path(tree.path(), &Limits::default())
        .pop()
        .expect("one document");
    (tree, document)
}

/// `relative`, written with `/`, inside `tree`, as the scanner names it.
fn tree_path(tree: &tempfile::TempDir, relative: &str) -> std::path::PathBuf {
    relative
        .split('/')
        .fold(tree.path().to_path_buf(), |path, part| path.join(part))
}

fn scan(document: Document) -> ScanReport {
    scan_documents(vec![document], &Config::default())
}

fn findings<'a>(report: &'a ScanReport, rule: &str) -> Vec<&'a Finding> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == rule)
        .collect()
}

fn by_name<'a>(document: &'a Document, name: &str) -> &'a Instance {
    document
        .instances
        .iter()
        .find(|instance| instance.name == name)
        .unwrap_or_else(|| panic!("no instance {name}"))
}

/// One finding of `rule` at `severity` that resolved `id`.
fn assert_resolved(report: &ScanReport, rule: &str, severity: Severity, id: u64, label: &str) {
    let hits = findings(report, rule);
    let resolved = format!("resolved asset id: {id}");
    assert!(
        hits.iter()
            .any(|finding| finding.severity == severity && finding.evidence.contains(&resolved)),
        "{label}: {:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.severity, &finding.evidence))
            .collect::<Vec<_>>()
    );
}

fn assert_complete(document: &Document, label: &str) {
    assert_eq!(
        document.completeness,
        Completeness::Complete,
        "{label}: {:?}",
        document.reasons
    );
}

/// The same JSONC text with LF, CRLF and CR line endings, and with a byte
/// order mark. `template` uses LF and holds `//` and `/* */` comments and
/// trailing commas. Rojo reads all but the CR form, where its `//` comments
/// run to the end of the file; bloxguard reads that one too.
fn variants(template: &str) -> Vec<(&'static str, String)> {
    let crlf = template.replace('\n', "\r\n");
    vec![
        ("LF", template.to_owned()),
        ("CRLF", crlf.clone()),
        ("CR", template.replace('\n', "\r")),
        ("BOM and CRLF", format!("{BOM}{crlf}")),
        ("BOM and LF", format!("{BOM}{template}")),
    ]
}

const MODEL_TEMPLATE: &str = r#"// FAKE model
{
  "className": "Script", /* FAKE */
  "properties": {
    "Source": "require(ID)", // FAKE
  },
}
"#;

const META_TEMPLATE: &str = r#"{
  // FAKE metadata
  "attributes": {
    "FAKE_id": ID, /* FAKE */
  },
}
"#;

fn with_id(template: &str, id: u64) -> String {
    template.replace("ID", &id.to_string())
}

// ---------------------------------------------------------------------------
// Model files
// ---------------------------------------------------------------------------

/// A `.model.jsonc` file defines instances like a `.model.json` file, at the
/// root and in nested folders, and Rojo reads comments in both.
#[test]
fn item9_model_jsonc_scripts_get_bg001_in_every_folder() {
    for extension in ["model.jsonc", "model.json"] {
        for (label, root_model) in variants(&with_id(MODEL_TEMPLATE, 999_000_000_009_001)) {
            let nested_model = with_id(MODEL_TEMPLATE, 999_000_000_009_002);
            let root_name = format!("FAKE_m.{extension}");
            let nested_name = format!("FAKE_dir/FAKE_inner/FAKE_n.{extension}");
            let (_tree, document) = load(&[
                ("FAKE_s.server.luau", "return 1"),
                (&root_name, &root_model),
                (&nested_name, &nested_model),
            ]);
            let label = format!("{extension}, {label}");
            assert_complete(&document, &label);
            assert_eq!(by_name(&document, "FAKE_m").class, "Script", "{label}");
            assert_eq!(by_name(&document, "FAKE_n").class, "Script", "{label}");
            let report = scan(document);
            assert_resolved(
                &report,
                "BG001",
                Severity::High,
                999_000_000_009_001,
                &label,
            );
            assert_resolved(
                &report,
                "BG001",
                Severity::High,
                999_000_000_009_002,
                &label,
            );
        }
    }
}

/// Rojo builds an instance from each file, so a `.model.json` and a
/// `.model.jsonc` file with one name are two siblings.
#[test]
fn item9_a_model_json_and_model_jsonc_pair_are_two_instances() {
    let (_tree, document) = load(&[
        ("FAKE_s.server.luau", "return 1"),
        (
            "FAKE_twin.model.json",
            &with_id(MODEL_TEMPLATE, 999_000_000_009_003),
        ),
        (
            "FAKE_twin.model.jsonc",
            &with_id(MODEL_TEMPLATE, 999_000_000_009_004),
        ),
    ]);
    assert_complete(&document, "pair");
    let twins = document
        .instances
        .iter()
        .filter(|instance| instance.name == "FAKE_twin")
        .count();
    assert_eq!(twins, 2);
    let report = scan(document);
    assert_resolved(
        &report,
        "BG001",
        Severity::High,
        999_000_000_009_003,
        "json",
    );
    assert_resolved(
        &report,
        "BG001",
        Severity::High,
        999_000_000_009_004,
        "jsonc",
    );
}

// ---------------------------------------------------------------------------
// Metadata files
// ---------------------------------------------------------------------------

/// An attribute from `<name>.meta.jsonc` reaches the script like one from
/// `<name>.meta.json`, and both accept comments, trailing commas, a BOM and
/// any line ending.
#[test]
fn item9_meta_jsonc_attribute_is_seen_like_meta_json() {
    let id = 999_000_000_009_005u64;
    let (_tree, baseline) = load(&[
        ("FAKE_s.server.luau", READS_OWN_ATTRIBUTE),
        (
            "FAKE_s.meta.json",
            &format!(r#"{{"attributes": {{"FAKE_id": {id}}}}}"#),
        ),
    ]);
    assert_complete(&baseline, "plain .meta.json");
    let baseline = scan(baseline);
    assert_resolved(
        &baseline,
        "BG002",
        Severity::Critical,
        id,
        "plain .meta.json",
    );

    for extension in ["meta.jsonc", "meta.json"] {
        for (label, meta) in variants(&with_id(META_TEMPLATE, id)) {
            let label = format!("{extension}, {label}");
            let meta_name = format!("FAKE_s.{extension}");
            let (_tree, document) = load(&[
                ("FAKE_s.server.luau", READS_OWN_ATTRIBUTE),
                (&meta_name, &meta),
            ]);
            assert_complete(&document, &label);
            assert_eq!(
                by_name(&document, "FAKE_s").attributes.get("FAKE_id"),
                Some(&json!(id)),
                "{label}"
            );
            let report = scan(document);
            assert_eq!(
                report.findings.len(),
                baseline.findings.len(),
                "{label}: {:?}",
                report.findings
            );
            assert_resolved(&report, "BG002", Severity::Critical, id, &label);
        }
    }
}

/// `init.meta.jsonc` applies to its folder, with or without an init script.
#[test]
fn item9_init_meta_jsonc_applies_to_its_folder() {
    let folder_meta = r#"{
  "className": "Configuration", // FAKE
  "attributes": {"FAKE_id": 999000000009006,},
}
"#;
    for extension in ["meta.jsonc", "meta.json"] {
        for (label, meta) in variants(folder_meta) {
            let label = format!("init.{extension}, {label}");
            let folder_meta_name = format!("FAKE_cfg/init.{extension}");
            let script_meta_name = format!("FAKE_pkg/init.{extension}");
            let (_tree, document) = load(&[
                ("FAKE_cfg/FAKE_c.server.luau", READS_PARENT_ATTRIBUTE),
                (&folder_meta_name, &meta),
                ("FAKE_pkg/init.server.luau", READS_OWN_ATTRIBUTE),
                (
                    &script_meta_name,
                    &with_id(META_TEMPLATE, 999_000_000_009_007),
                ),
            ]);
            assert_complete(&document, &label);
            assert_eq!(by_name(&document, "FAKE_cfg").class, "Configuration");
            assert_eq!(by_name(&document, "FAKE_pkg").class, "Script");
            let report = scan(document);
            assert_resolved(
                &report,
                "BG002",
                Severity::Critical,
                999_000_000_009_006,
                &label,
            );
            assert_resolved(
                &report,
                "BG002",
                Severity::Critical,
                999_000_000_009_007,
                &label,
            );
        }
    }
}

/// Rojo builds an init script like a file named after its folder, so it also
/// applies `<folder>/<folder name>.meta.json(c)` to it, before `init.meta.json`.
#[test]
fn item9_metadata_named_after_the_folder_applies_to_its_init_script() {
    for extension in ["meta.json", "meta.jsonc"] {
        let meta_name = format!("FAKE_pkg/FAKE_pkg.{extension}");
        let (_tree, document) = load(&[
            ("FAKE_pkg/init.server.luau", READS_OWN_ATTRIBUTE),
            (&meta_name, &with_id(META_TEMPLATE, 999_000_000_009_008)),
        ]);
        assert_complete(&document, extension);
        let report = scan(document);
        assert_resolved(
            &report,
            "BG002",
            Severity::Critical,
            999_000_000_009_008,
            extension,
        );
    }

    let (_tree, document) = load(&[
        ("FAKE_pkg/init.server.luau", "print(\"FAKE\")"),
        (
            "FAKE_pkg/FAKE_pkg.meta.json",
            r#"{"properties": {"Source": "require(999000000009009)"}}"#,
        ),
    ]);
    assert_complete(&document, "Source");
    let report = scan(document);
    assert_resolved(
        &report,
        "BG001",
        Severity::High,
        999_000_000_009_009,
        "Source",
    );
}

/// With both files Rojo 7.7 applies the `.json` file and then the `.jsonc`
/// file: a property it names is replaced, and a nonempty attribute list
/// replaces the whole list. Rojo before 7.7 reads only the `.json` file, so
/// the input is partial.
#[test]
fn item9_json_and_jsonc_metadata_follow_rojo_order() {
    let json = r#"{"properties": {"Disabled": true, "RunContext": "Server"}, "attributes": {"FAKE_old": 999000000009010}}"#;
    let jsonc = "{\"properties\": {\"Disabled\": false,}, // FAKE\n\"attributes\": {\"FAKE_id\": 999000000009011}}";
    let (tree, document) = load(&[
        ("FAKE_s.server.luau", READS_OWN_ATTRIBUTE),
        ("FAKE_s.meta.json", json),
        ("FAKE_s.meta.jsonc", jsonc),
        ("FAKE_cfg/FAKE_c.server.luau", READS_PARENT_ATTRIBUTE),
        ("FAKE_cfg/init.meta.json", json),
        ("FAKE_cfg/init.meta.jsonc", jsonc),
    ]);
    for name in ["FAKE_s", "FAKE_cfg"] {
        let instance = by_name(&document, name);
        assert_eq!(
            instance.properties.get("Disabled"),
            Some(&json!(false)),
            "{name}"
        );
        assert_eq!(
            instance.properties.get("RunContext"),
            Some(&json!("Server")),
            "{name}"
        );
        assert_eq!(
            instance.attributes,
            [("FAKE_id".to_owned(), json!(999_000_000_009_011u64))]
                .into_iter()
                .collect(),
            "{name}"
        );
    }
    assert_eq!(document.completeness, Completeness::Partial);
    let both = |folder: &std::path::Path, stem: &str, name: &str| {
        format!(
            "{} and {} both set metadata for {name:?}; Rojo 7.7 and later apply both, the .jsonc file last, and earlier versions only the .json file",
            folder.join(format!("{stem}.meta.json")).display(),
            folder.join(format!("{stem}.meta.jsonc")).display(),
        )
    };
    assert_eq!(
        document.reasons,
        [
            both(tree.path(), "FAKE_s", "FAKE_s"),
            both(&tree.path().join("FAKE_cfg"), "init", "FAKE_cfg"),
        ]
    );
    let report = scan(document);
    assert_resolved(
        &report,
        "BG002",
        Severity::Critical,
        999_000_000_009_011,
        "both",
    );

    // An empty attribute list in the later file leaves the earlier list.
    let (_tree, document) = load(&[
        ("FAKE_s.server.luau", READS_OWN_ATTRIBUTE),
        ("FAKE_s.meta.json", json),
        ("FAKE_s.meta.jsonc", r#"{"attributes": {}}"#),
    ]);
    assert_eq!(
        by_name(&document, "FAKE_s").attributes.get("FAKE_old"),
        Some(&json!(999_000_000_009_010u64))
    );
}

/// A `.jsonc` file the scanner cannot read makes the input partial instead of
/// being skipped. Unquoted keys and single quoted strings, which Rojo's
/// parser accepts, are refused rather than guessed.
#[test]
fn item9_malformed_jsonc_makes_the_input_partial() {
    for (label, name, text, reason) in [
        (
            "cut off model",
            "FAKE_m.model.jsonc",
            "{\"className\": \"Script\", \"properties\": {\"Source\": \"require(999000000009020)\"}",
            "cannot decode JSON model",
        ),
        (
            "unclosed block comment",
            "FAKE_s.meta.jsonc",
            "{\"attributes\": {\"FAKE_id\": 999000000009021}} /* FAKE",
            "has no closing */",
        ),
        (
            "unquoted keys",
            "FAKE_cfg/init.meta.jsonc",
            "{attributes: {FAKE_id: 999000000009022}}",
            "cannot decode metadata",
        ),
        (
            "single quoted strings",
            "FAKE_s.meta.jsonc",
            "{'attributes': {'FAKE_id': 999000000009023}}",
            "cannot decode metadata",
        ),
        (
            "hexadecimal number",
            "FAKE_s.meta.jsonc",
            "{\"attributes\": {\"FAKE_id\": 0x38C95D0219340}}",
            "cannot decode metadata",
        ),
    ] {
        let (tree, document) = load(&[
            ("FAKE_s.server.luau", READS_OWN_ATTRIBUTE),
            ("FAKE_cfg/FAKE_c.server.luau", READS_PARENT_ATTRIBUTE),
            (name, text),
        ]);
        assert_eq!(document.completeness, Completeness::Partial, "{label}");
        let file = tree_path(&tree, name).display().to_string();
        assert!(
            document
                .reasons
                .iter()
                .any(|r| r.contains(&file) && r.contains(reason)),
            "{label}: {:?}",
            document.reasons
        );
    }
}

/// Rojo ends a `//` comment only at a line feed. Text after a lone carriage
/// return stays inside the comment, so it must not replace a value Rojo reads.
#[test]
fn item9_line_comments_end_at_a_line_feed_like_rojo() {
    let meta = "{\"attributes\": {\"FAKE_id\": 999000000009030 // FAKE\r, \"FAKE_id\": 1\n}}";
    for name in ["FAKE_s.meta.json", "FAKE_s.meta.jsonc"] {
        let (_tree, document) = load(&[("FAKE_s.server.luau", READS_OWN_ATTRIBUTE), (name, meta)]);
        assert_complete(&document, name);
        assert_eq!(
            by_name(&document, "FAKE_s").attributes.get("FAKE_id"),
            Some(&json!(999_000_000_009_030u64)),
            "{name}"
        );
    }

    let project = "{\"name\": \"FAKE\", \"tree\": {\"$className\": \"DataModel\", \"FAKE_Out\": {\"$path\": \"../FAKE_outside\" // FAKE\r, \"$path\": \"FAKE_src\"\n}}}";
    for name in ["default.project.json", "default.project.jsonc"] {
        let (_tree, document) =
            load(&[("FAKE_src/FAKE_s.server.luau", "return 1"), (name, project)]);
        assert_eq!(document.completeness, Completeness::Partial, "{name}");
        assert!(
            document.reasons.iter().any(|reason| reason
                .ends_with("maps \"../FAKE_outside\" from outside the scanned tree; that content was not scanned")),
            "{name}: {:?}",
            document.reasons
        );
    }
}

/// Rojo applies metadata after it reads the script file, so a `Source` in a
/// metadata file replaces the file's text, and that is the code that runs.
#[test]
fn item9_metadata_source_replaces_the_script_text_like_rojo() {
    let source_meta = |id: u64| format!(r#"{{"properties": {{"Source": "require({id})"}}}}"#);
    let (tree, document) = load(&[
        ("FAKE_s.server.luau", "print(\"FAKE\")"),
        ("FAKE_s.meta.json", &source_meta(999_000_000_009_044)),
    ]);
    let notes: Vec<_> = document
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect();
    assert_eq!(
        notes,
        [format!(
            "{} sets Source for {}; Rojo uses it instead of the file's text, so that is what was scanned",
            tree.path().join("FAKE_s.meta.json").display(),
            tree.path().join("FAKE_s.server.luau").display()
        )]
    );
    assert_eq!(by_name(&document, "FAKE_s").source_file, None);

    for (label, files, script, id) in [
        (
            "script file",
            vec![
                ("FAKE_s.server.luau", "print(\"FAKE\")".to_owned()),
                ("FAKE_s.meta.json", source_meta(999_000_000_009_040)),
            ],
            "FAKE_s",
            999_000_000_009_040,
        ),
        (
            "init script",
            vec![
                ("FAKE_pkg/init.server.luau", "print(\"FAKE\")".to_owned()),
                ("FAKE_pkg/init.meta.json", source_meta(999_000_000_009_041)),
            ],
            "FAKE_pkg",
            999_000_000_009_041,
        ),
        (
            "folder turned into a script",
            vec![
                ("FAKE_s.server.luau", "return 1".to_owned()),
                (
                    "FAKE_cfg/init.meta.json",
                    r#"{"className": "Script", "properties": {"Source": "require(999000000009042)"}}"#
                        .to_owned(),
                ),
            ],
            "FAKE_cfg",
            999_000_000_009_042,
        ),
    ] {
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(name, text)| (*name, text.as_str()))
            .collect();
        let (_tree, document) = load(&files);
        assert_complete(&document, label);
        let instance = by_name(&document, script);
        assert_eq!(
            instance.source.as_deref(),
            Some(format!("require({id})").as_str()),
            "{label}"
        );
        assert!(!instance.properties.contains_key("Source"), "{label}");
        let report = scan(document);
        assert_resolved(&report, "BG001", Severity::High, id, label);
    }

    // A typed value is not read, and the input says so.
    let (_tree, document) = load(&[
        ("FAKE_s.server.luau", "print(\"FAKE\")"),
        (
            "FAKE_s.meta.json",
            r#"{"properties": {"Source": {"String": "require(999000000009043)"}}}"#,
        ),
    ]);
    assert_eq!(document.completeness, Completeness::Partial);
    assert!(
        document.reasons[0].ends_with("sets Source to a value direct scans do not read"),
        "{:?}",
        document.reasons
    );
}

/// Rojo before 7.7 ignores `.meta.jsonc`, so a `Source` there replaces the
/// file's text only on newer versions. Its code is scanned and the input is
/// partial, because the file's own text was not.
#[test]
fn item9_jsonc_source_for_a_script_file_is_partial() {
    let (tree, document) = load(&[
        ("FAKE_s.server.luau", "print(\"FAKE\")"),
        (
            "FAKE_s.meta.jsonc",
            "{\"properties\": {\"Source\": \"require(999000000009050)\",}} // FAKE",
        ),
    ]);
    assert_eq!(
        document.reasons,
        [format!(
            "{} sets Source for {}; Rojo 7.7 and later use it, earlier versions use the file's own text, which was not scanned",
            tree.path().join("FAKE_s.meta.jsonc").display(),
            tree.path().join("FAKE_s.server.luau").display()
        )]
    );
    let report = scan(document);
    assert_resolved(
        &report,
        "BG001",
        Severity::High,
        999_000_000_009_050,
        "jsonc Source",
    );
}

/// Rojo applies metadata to the instances it builds from data files, which
/// direct scans do not read. Metadata that sets a rule input there makes the
/// input partial. Metadata Rojo ignores, or that sets nothing the rules read,
/// does not.
#[test]
fn item9_metadata_for_files_direct_scans_do_not_read_is_partial() {
    let attributes = r#"{"attributes": {"FAKE_id": 999000000009060}}"#;
    for (data, meta, text) in [
        (
            "FAKE_ids.json",
            "FAKE_ids.meta.json",
            r#"{"properties": {"Source": "require(999000000009061)"}}"#,
        ),
        ("FAKE_ids.jsonc", "FAKE_ids.meta.jsonc", attributes),
        ("FAKE_note.txt", "FAKE_note.meta.jsonc", attributes),
        (
            "FAKE_note.txt",
            "FAKE_note.meta.json",
            r#"{"properties": {"Value": "999000000009062"}}"#,
        ),
        ("FAKE_tbl.toml", "FAKE_tbl.meta.json", attributes),
        ("FAKE_loc.csv", "FAKE_loc.meta.json", attributes),
        ("FAKE_cfg.yaml", "FAKE_cfg.meta.json", attributes),
        ("FAKE_cfg.yml", "FAKE_cfg.meta.json", attributes),
    ] {
        let (tree, document) = load(&[
            ("FAKE_s.server.luau", "return 1"),
            (data, "FAKE data"),
            (meta, text),
        ]);
        assert_eq!(document.completeness, Completeness::Partial, "{meta}");
        assert_eq!(
            document.reasons,
            [format!(
                "Rojo applies {} to the instance it builds from {}, which direct scans do not read; build with Rojo and scan the output",
                tree.path().join(meta).display(),
                tree.path().join(data).display()
            )],
            "{meta}"
        );
    }

    for (label, files) in [
        (
            "metadata Rojo ignores next to a model",
            [
                ("FAKE_m.model.json", r#"{"className": "Folder"}"#),
                ("FAKE_m.meta.json", attributes),
            ],
        ),
        (
            "metadata that sets no rule input",
            [
                ("FAKE_cfg.json", "{}"),
                (
                    "FAKE_cfg.meta.json",
                    r#"{"ignoreUnknownInstances": true, "properties": {"Archivable": false}}"#,
                ),
            ],
        ),
        (
            "a data file without metadata",
            [("FAKE_cfg.json", "{}"), ("FAKE_note.txt", "FAKE")],
        ),
        (
            "metadata of the folder next to init.csv",
            [
                ("FAKE_loc/init.csv", "FAKE"),
                ("FAKE_loc/init.meta.json", attributes),
            ],
        ),
    ] {
        let mut files = files.to_vec();
        files.push(("FAKE_s.server.luau", "return 1"));
        let (_tree, document) = load(&files);
        assert_complete(&document, label);
    }
}

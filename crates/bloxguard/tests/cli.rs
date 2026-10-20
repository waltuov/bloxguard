use serde_json::{Value, json};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FAKE_ID: u64 = 999_000_000_000_001;

#[test]
fn review_01_nested_interpolations_return_partial_in_cli() {
    let temp = temp_dir();
    let source = format!("return {}1{}", "`{".repeat(1000), "}`".repeat(1000));
    let path = write_source(temp.path(), "FAKE_nested.luau", &source);
    let result = run(
        temp.path(),
        ["scan", path.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(result.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["completeness"], "partial");
    assert!(
        report["inputs"][0]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason.as_str().unwrap().contains("interpolated"))
    );
}

#[test]
fn review_11_baseline_matches_equivalent_input_spellings() {
    let temp = temp_dir();
    let project = temp.path().join("proj");
    fs::create_dir(&project).unwrap();
    write_source(&project, "FAKE_loader.luau", "require(999000000000311)");
    let create = run(
        temp.path(),
        ["baseline", "create", "proj", "--output", "baseline.json"],
    );
    assert_eq!(create.status.code(), Some(0), "{}", text(&create.stderr));
    let absolute = project.to_str().unwrap().to_string();
    for spelling in ["proj", "proj/", "./proj", absolute.as_str()] {
        let result = run(
            temp.path(),
            [
                "scan",
                spelling,
                "--baseline",
                "baseline.json",
                "--format",
                "json",
            ],
        );
        assert_eq!(
            result.status.code(),
            Some(0),
            "{spelling}: {}",
            text(&result.stderr)
        );
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["baseline_count"], 1, "{spelling}: {report}");
        assert_eq!(report["findings"], json!([]));
    }
}

#[test]
fn review_14_explain_is_case_insensitive_and_as_of_errors_name_the_option() {
    let temp = temp_dir();
    let lower = run(temp.path(), ["explain", "bg001"]);
    let upper = run(temp.path(), ["explain", "BG001"]);
    assert_eq!(lower.status.code(), Some(0));
    assert_eq!(lower.stdout, upper.stdout);
    let source = write_source(temp.path(), "FAKE_clean.luau", "return 1");
    let invalid = run(
        temp.path(),
        ["scan", source.to_str().unwrap(), "--as-of", "2026-02-30"],
    );
    assert_eq!(invalid.status.code(), Some(3));
    assert!(text(&invalid.stderr).contains("--as-of"));
    assert!(!text(&invalid.stderr).contains("expires"));
}

#[test]
fn launch_scan_help_describes_every_option() {
    let temp = temp_dir();
    let help = run(temp.path(), ["scan", "--help"]);
    assert_eq!(help.status.code(), Some(0));
    let help = text(&help.stdout);
    for (option, description) in [
        (
            "<PATHS>...",
            "Roblox files (.rbxl, .rbxlx, .rbxm, .rbxmx), Luau files or source folders to scan",
        ),
        ("--format <FORMAT>", "Report format [default: human]"),
        (
            "--output <FILE>",
            "Write the report to this file instead of standard output",
        ),
        (
            "--fail-on <SEVERITY>",
            "Lowest severity that returns exit code 1: low, medium, high or critical. Default: fail_on in the configuration, else high",
        ),
        (
            "--config <FILE>",
            "Configuration file. Without it, bloxguard.toml in the working directory is used when present",
        ),
        (
            "--baseline <FILE>",
            "Baseline JSON file whose findings are hidden. Overrides baseline in the configuration",
        ),
        (
            "--allow-incomplete",
            "Let an incomplete scan return the findings exit code (0 or 1) instead of 2",
        ),
        (
            "--as-of <YYYY-MM-DD>",
            "Evaluate suppression expiry on this UTC date",
        ),
    ] {
        assert!(
            help.lines().any(|line| line
                .split_once(option)
                .is_some_and(|(_, rest)| rest.trim_start().starts_with(description))),
            "{option}: {description}\n---\n{help}"
        );
    }
}

#[test]
fn launch_rbxts_mapping_message_gives_advice_that_works() {
    let temp = temp_dir();
    let project = temp.path().join("FAKE_game");
    let package = project.join("node_modules/@rbxts/FAKE_pkg");
    fs::create_dir_all(&package).unwrap();
    fs::create_dir_all(project.join("out")).unwrap();
    fs::write(
        project.join("default.project.json"),
        r#"{"name":"FAKE_game","tree":{"$className":"DataModel","ReplicatedStorage":{"node_modules":{"$className":"Folder","@rbxts":{"$path":"node_modules/@rbxts"}}},"ServerScriptService":{"$path":"out"}}}"#,
    )
    .unwrap();
    write_source(&project.join("out"), "FAKE_main.server.luau", "print(1)");
    write_source(&package, "init.lua", &format!("return require({FAKE_ID})"));

    let both = run(&project, ["scan", ".", "node_modules", "--format", "json"]);
    let report: Value = serde_json::from_slice(&both.stdout).unwrap();
    // Scanning the excluded folder too reads its code, but the project input
    // stays partial, so the message must not promise otherwise.
    assert_eq!(both.status.code(), Some(2));
    let tree = report["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|input| input["input"] == ".")
        .unwrap();
    assert_eq!(tree["completeness"], "partial");
    let reason = tree["reasons"][0].as_str().unwrap();
    assert!(reason.contains("direct scans exclude"), "{reason}");
    assert!(reason.contains("so this input stays partial"), "{reason}");
    assert!(
        reason.contains("build with Rojo and scan the output"),
        "{reason}"
    );
    assert!(
        reason.contains("also scan that folder and pass --allow-incomplete"),
        "{reason}"
    );
    assert!(!reason.contains("scan that folder explicitly"), "{reason}");
    assert_eq!(report["findings"][0]["rule_id"], "BG001");
    assert_eq!(report["findings"][0]["input"], "node_modules");

    let allowed = run(
        &project,
        ["scan", ".", "node_modules", "--allow-incomplete"],
    );
    assert_eq!(allowed.status.code(), Some(1));
}

/// A model whose script loads a FAKE ID on line 3 of its source. The XML is one
/// line, so a region copied from the script would point past its end.
fn launch_kit_xml(root: &str, id: u64) -> String {
    format!(
        r#"<roblox version="4"><Item class="Model" referent="FAKE1"><Properties><string name="Name">{root}</string></Properties><Item class="Script" referent="FAKE2"><Properties><string name="Name">FAKE_Weld</string><ProtectedString name="Source">-- FAKE weld
local FAKE_unused = 1
require({id})</ProtectedString></Properties></Item></Item></roblox>"#
    )
}

/// A Rojo tree whose project maps `src`, with `file` written at `parts`.
fn launch_rojo_tree(parts: &[&str], contents: &str) -> tempfile::TempDir {
    let temp = temp_dir();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("default.project.json"),
        r#"{"name":"FAKE_game","tree":{"$className":"DataModel","ServerScriptService":{"$path":"src"}}}"#,
    )
    .unwrap();
    let file = parts
        .iter()
        .fold(temp.path().to_owned(), |path, part| path.join(part));
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, contents).unwrap();
    temp
}

/// `scan .` from the tree root: JSON `container_file` (with no
/// `source_file`), the SARIF URI and the human location line all name the
/// nested file, and SARIF has no region. `position` is what the human line and
/// the SARIF message say after the instance path.
fn launch_assert_nested_provenance(
    temp: &tempfile::TempDir,
    parts: &[&str],
    rule: &str,
    instance_path: &str,
    position: &str,
    script_line: Option<u64>,
) {
    let container = parts
        .iter()
        .fold(PathBuf::from("."), |path, part| path.join(part))
        .to_string_lossy()
        .into_owned();
    let uri = parts.join("/");

    let json = run(temp.path(), ["scan", ".", "--format", "json"]);
    assert_eq!(json.status.code(), Some(1), "{}", text(&json.stderr));
    let report: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["completeness"], "complete", "{report:#}");
    let findings: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["rule_id"] == rule)
        .collect();
    assert_eq!(findings.len(), 1, "{report:#}");
    let finding = findings[0];
    assert_eq!(finding["instance_path"], instance_path);
    // `source_file` keeps its meaning: the Luau file whose lines are counted.
    assert!(finding.get("source_file").is_none(), "{finding:#}");
    assert_eq!(finding["container_file"], json!(container));
    assert_eq!(
        finding["location"].get("line"),
        script_line.map(|line| json!(line)).as_ref()
    );

    let sarif = run(temp.path(), ["scan", ".", "--format", "sarif"]);
    let log: Value = serde_json::from_slice(&sarif.stdout).unwrap();
    let result = log["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|result| result["ruleId"] == rule)
        .unwrap();
    let physical = &result["locations"][0]["physicalLocation"];
    assert_eq!(
        physical["artifactLocation"]["uri"],
        json!(uri),
        "{result:#}"
    );
    assert!(physical.get("region").is_none(), "{result:#}");
    assert_eq!(
        result["properties"]
            .get("scriptRegion")
            .map(|region| &region["startLine"]),
        script_line.map(|line| json!(line)).as_ref()
    );
    assert!(
        result["message"]["text"]
            .as_str()
            .unwrap()
            .ends_with(&format!("({instance_path}, {position})")),
        "{result:#}"
    );
    // Provenance is not part of the identity.
    assert_eq!(
        result["partialFingerprints"]["bloxguard/v1"],
        finding["fingerprint"]
    );

    let human = run(temp.path(), ["scan", "."]);
    let human = text(&human.stdout);
    assert!(
        human.contains(&format!(
            "\n    {instance_path} ({container}, {position})\n"
        )),
        "{human}"
    );
}

#[test]
fn launch_provenance_rbxmx_in_a_rojo_tree_scanned_as_dot() {
    let parts = ["models", "FAKE_kit.rbxmx"];
    let temp = launch_rojo_tree(&parts, &launch_kit_xml("FAKE_Kit", 999_000_000_000_211));
    launch_assert_nested_provenance(
        &temp,
        &parts,
        "BG001",
        "/root/models/FAKE_Kit/FAKE_Weld",
        "script line 3:1",
        Some(3),
    );
}

#[test]
fn launch_provenance_model_json_script_in_a_tree() {
    let parts = ["src", "FAKE_part.model.json"];
    let temp = launch_rojo_tree(
        &parts,
        r#"{"className":"Script","properties":{"Source":"-- FAKE\n\n\nrequire(999000000000212)"}}"#,
    );
    launch_assert_nested_provenance(
        &temp,
        &parts,
        "BG001",
        "/root/src/FAKE_part",
        "script line 4:1",
        Some(4),
    );
}

#[test]
fn launch_provenance_metadata_source_names_the_metadata_file() {
    let parts = ["src", "FAKE_meta.meta.json"];
    let temp = launch_rojo_tree(
        &parts,
        r#"{"properties":{"Source":"-- FAKE\nrequire(999000000000214)"}}"#,
    );
    write_source(
        &temp.path().join("src"),
        "FAKE_meta.server.luau",
        "print(1)",
    );
    launch_assert_nested_provenance(
        &temp,
        &parts,
        "BG001",
        "/root/src/FAKE_meta",
        "script line 2:1",
        Some(2),
    );
}

#[test]
fn launch_provenance_folder_metadata_value_names_the_metadata_file() {
    let parts = ["src", "FAKE_note", "init.meta.json"];
    let temp = launch_rojo_tree(
        &parts,
        r#"{"className":"StringValue","properties":{"Value":"paste this into the command bar"}}"#,
    );
    write_source(
        &temp.path().join("src"),
        "FAKE_main.server.luau",
        "print(1)",
    );
    launch_assert_nested_provenance(
        &temp,
        &parts,
        "BG012",
        "/root/src/FAKE_note",
        "property Value",
        None,
    );
}

#[test]
fn launch_provenance_folder_metadata_attribute_names_the_metadata_file() {
    let parts = ["src", "FAKE_attrs", "init.meta.json"];
    let temp = launch_rojo_tree(
        &parts,
        r#"{"attributes":{"FAKE_hint":"paste this into the command bar"}}"#,
    );
    write_source(
        &temp.path().join("src"),
        "FAKE_main.server.luau",
        "print(1)",
    );
    launch_assert_nested_provenance(
        &temp,
        &parts,
        "BG012",
        "/root/src/FAKE_attrs",
        "attribute FAKE_hint",
        None,
    );
}

#[test]
fn launch_provenance_nested_model_two_folders_deep() {
    let parts = ["assets", "kits", "FAKE_deep.rbxmx"];
    let temp = launch_rojo_tree(&parts, &launch_kit_xml("FAKE_Deep", 999_000_000_000_213));
    launch_assert_nested_provenance(
        &temp,
        &parts,
        "BG001",
        "/root/assets/kits/FAKE_Deep/FAKE_Weld",
        "script line 3:1",
        Some(3),
    );
}

fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("bloxguard_FAKE_cli_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory")
}

fn run(temp: &Path, args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Output {
    let scratch = temp.join("tmp");
    fs::create_dir_all(&scratch).expect("create repository-local command scratch directory");
    Command::new(env!("CARGO_BIN_EXE_bloxguard"))
        .args(args)
        .current_dir(temp)
        .env("TEMP", &scratch)
        .env("TMP", &scratch)
        .output()
        .expect("run bloxguard CLI")
}

fn write_source(temp: &Path, name: &str, source: &str) -> PathBuf {
    let path = temp.join(name);
    fs::write(&path, source).expect("write synthetic Luau source");
    path
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn scan_exit_codes_cover_clean_findings_incomplete_precedence_and_usage() {
    let temp = temp_dir();
    let clean = write_source(temp.path(), "FAKE_clean.luau", "return 1");
    let risky = write_source(
        temp.path(),
        "FAKE_risky.luau",
        &format!("require({FAKE_ID})"),
    );
    let missing = temp.path().join("FAKE_missing.luau");

    let clean_output = run(
        temp.path(),
        ["scan", clean.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(
        clean_output.status.code(),
        Some(0),
        "{}",
        text(&clean_output.stderr)
    );

    let risky_output = run(
        temp.path(),
        ["scan", risky.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(
        risky_output.status.code(),
        Some(1),
        "{}",
        text(&risky_output.stderr)
    );

    let incomplete = run(
        temp.path(),
        [
            "scan",
            risky.to_str().unwrap(),
            missing.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(
        incomplete.status.code(),
        Some(2),
        "incomplete status must take precedence over a high finding: {}",
        text(&incomplete.stderr)
    );
    let report: Value = serde_json::from_slice(&incomplete.stdout).unwrap();
    assert_eq!(report["completeness"], json!("failed"));
    assert_eq!(report["findings"][0]["rule_id"], json!("BG001"));

    let allowed = run(
        temp.path(),
        [
            "scan",
            risky.to_str().unwrap(),
            missing.to_str().unwrap(),
            "--allow-incomplete",
            "--format",
            "json",
        ],
    );
    assert_eq!(
        allowed.status.code(),
        Some(1),
        "allowing incomplete scans must still enforce finding thresholds"
    );

    let usage = run(temp.path(), ["scan"]);
    assert_eq!(usage.status.code(), Some(3));
    assert!(text(&usage.stderr).contains("required"));

    let invalid_config = temp.path().join("invalid.toml");
    fs::write(&invalid_config, "unknown_setting = true\n").unwrap();
    let config_error = run(
        temp.path(),
        [
            "scan",
            clean.to_str().unwrap(),
            "--config",
            invalid_config.to_str().unwrap(),
        ],
    );
    assert_eq!(config_error.status.code(), Some(3));
    assert!(text(&config_error.stderr).contains("invalid config"));
}

#[test]
fn empty_source_is_a_complete_success_and_output_can_be_written_to_a_file() {
    let temp = temp_dir();
    let empty = write_source(temp.path(), "FAKE_empty.luau", "");
    let empty_output = run(
        temp.path(),
        ["scan", empty.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(
        empty_output.status.code(),
        Some(0),
        "{}",
        text(&empty_output.stderr)
    );
    let empty_report: Value = serde_json::from_slice(&empty_output.stdout).unwrap();
    assert_eq!(empty_report["completeness"], json!("complete"));
    assert_eq!(empty_report["findings"], json!([]));
    assert_eq!(empty_report["inventory"][0]["size_bytes"], json!(0));

    let risky = write_source(
        temp.path(),
        "FAKE_output.luau",
        &format!("require({FAKE_ID})"),
    );
    let report_path = temp.path().join("result.json");
    let file_output = run(
        temp.path(),
        [
            "scan",
            risky.to_str().unwrap(),
            "--format",
            "json",
            "--output",
            report_path.to_str().unwrap(),
        ],
    );
    assert_eq!(file_output.status.code(), Some(1));
    assert!(file_output.stdout.is_empty());
    let saved: Value = serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
    assert_eq!(saved["findings"][0]["rule_id"], json!("BG001"));
}

#[test]
fn baseline_creation_refuses_incomplete_scans() {
    let temp = temp_dir();
    let missing = temp.path().join("FAKE_missing.luau");
    let baseline = temp.path().join("must-not-exist.json");
    let output = run(
        temp.path(),
        [
            "baseline",
            "create",
            missing.to_str().unwrap(),
            "--output",
            baseline.to_str().unwrap(),
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output.stderr).contains("refusing to create a baseline"));
    assert!(!baseline.exists());
}

#[test]
fn config_resolves_baseline_relative_to_its_own_directory() {
    let temp = temp_dir();
    let source = write_source(
        temp.path(),
        "FAKE_relative.luau",
        &format!("require({FAKE_ID})"),
    );
    let first = run(
        temp.path(),
        ["scan", source.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(first.status.code(), Some(1));
    let first_report: Value = serde_json::from_slice(&first.stdout).unwrap();
    let fingerprint = first_report["findings"][0]["fingerprint"]
        .as_str()
        .expect("finding fingerprint");

    let config_dir = temp.path().join("policy");
    fs::create_dir(&config_dir).unwrap();
    fs::write(
        config_dir.join("known.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "fingerprints": [fingerprint]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        config_dir.join("bloxguard.toml"),
        "baseline = \"known.json\"\n",
    )
    .unwrap();

    let relative = run(
        temp.path(),
        [
            "scan",
            source.to_str().unwrap(),
            "--config",
            config_dir.join("bloxguard.toml").to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(
        relative.status.code(),
        Some(0),
        "{}",
        text(&relative.stderr)
    );
    let report: Value = serde_json::from_slice(&relative.stdout).unwrap();
    assert_eq!(report["findings"], json!([]));
    assert_eq!(report["baseline_count"], json!(1));
}

#[test]
fn newly_created_baseline_is_bound_to_the_reviewed_input() {
    let temp = temp_dir();
    let reviewed_dir = temp.path().join("reviewed");
    let other_dir = temp.path().join("other");
    fs::create_dir(&reviewed_dir).unwrap();
    fs::create_dir(&other_dir).unwrap();
    let reviewed = write_source(
        &reviewed_dir,
        "FAKE_same.luau",
        &format!("require({FAKE_ID})"),
    );
    let other = write_source(&other_dir, "FAKE_same.luau", &format!("require({FAKE_ID})"));
    let baseline = temp.path().join("scoped-baseline.json");

    let created = run(
        temp.path(),
        [
            "baseline",
            "create",
            reviewed.to_str().unwrap(),
            "--output",
            baseline.to_str().unwrap(),
        ],
    );
    assert_eq!(created.status.code(), Some(0), "{}", text(&created.stderr));

    let same_input = run(
        temp.path(),
        [
            "scan",
            reviewed.to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(same_input.status.code(), Some(0));
    let same_report: Value = serde_json::from_slice(&same_input.stdout).unwrap();
    assert_eq!(same_report["baseline_count"], json!(1));
    assert_eq!(same_report["findings"], json!([]));

    let different_input = run(
        temp.path(),
        [
            "scan",
            other.to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(different_input.status.code(), Some(1));
    let different_report: Value = serde_json::from_slice(&different_input.stdout).unwrap();
    assert_eq!(different_report["baseline_count"], json!(0));
    assert_eq!(different_report["findings"][0]["rule_id"], json!("BG001"));
}

use bloxguard_core::config::{Config, RuleConfig, Suppression};
use bloxguard_core::engine::scan_documents;
use bloxguard_core::finding::Severity;
use bloxguard_core::loading::load_source;
use bloxguard_core::model::Limits;
use bloxguard_core::output;
use std::collections::BTreeSet;
use std::fs;

const FAKE_ID_A: u64 = 999_000_000_000_001;
const FAKE_ID_B: u64 = 999_000_000_000_002;

fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("bloxguard_FAKE_policy_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory")
}

fn config_from(text: &str) -> Result<Config, String> {
    let temp = temp_dir();
    let path = temp.path().join("bloxguard.toml");
    fs::write(&path, text).expect("write synthetic config");
    Config::from_path(&path)
}

fn report(source: &str, config: &Config) -> bloxguard_core::report::ScanReport {
    let document = load_source(
        source,
        "FAKE_fixture.luau",
        "ModuleScript",
        &Limits::default(),
    );
    scan_documents(vec![document], config)
}

#[test]
fn unresolved_require_does_not_escalate_obfuscation_to_high() {
    let arguments = std::iter::repeat_n("65", 40).collect::<Vec<_>>().join(",");
    let source = format!(
        "local function lazy(module) return require(module) end\nlocal FAKE_data = string.char({arguments})\nreturn FAKE_data"
    );
    let result = report(&source, &Config::default());
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG001")
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG005")
    );
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.severity < Severity::High)
    );
}

#[test]
fn rule_policy_can_disable_and_raise_severity() {
    let mut disabled = Config::default();
    disabled.rules.insert(
        "BG001".into(),
        RuleConfig {
            enabled: Some(false),
            severity: None,
        },
    );
    let disabled_report = report(&format!("require({FAKE_ID_A})"), &disabled);
    assert!(disabled_report.findings.is_empty());

    let mut raised = Config::default();
    raised.rules.insert(
        "BG001".into(),
        RuleConfig {
            enabled: Some(true),
            severity: Some(Severity::Critical),
        },
    );
    let raised_report = report(&format!("require({FAKE_ID_A})"), &raised);
    assert_eq!(raised_report.findings.len(), 1);
    assert_eq!(raised_report.findings[0].severity, Severity::Critical);
}

#[test]
fn config_rejects_unsafe_or_ineffective_suppressions() {
    let cases = [
        (
            "missing reason",
            r#"
[[suppressions]]
rule = "BG001"
path = "/FAKE_fixture"
"#,
            "reason",
        ),
        (
            "empty reason",
            r#"
[[suppressions]]
rule = "BG001"
path = "/FAKE_fixture"
reason = "   "
"#,
            "suppression reason is required",
        ),
        (
            "unknown rule",
            r#"
[[suppressions]]
rule = "BG999"
path = "/FAKE_fixture"
reason = "FAKE review"
"#,
            "unknown suppression rule: BG999",
        ),
        (
            "unscoped suppression",
            r#"
[[suppressions]]
rule = "BG001"
reason = "FAKE review"
"#,
            "suppression needs a path glob or fingerprint",
        ),
        (
            "malformed path glob",
            r#"
[[suppressions]]
rule = "BG001"
path = "["
reason = "FAKE review"
"#,
            "invalid suppression path glob",
        ),
        (
            "malformed expiry",
            r#"
[[suppressions]]
rule = "BG001"
path = "/FAKE_fixture"
reason = "FAKE review"
expires = "2026-02-30"
"#,
            "expires is not a valid calendar date",
        ),
    ];

    for (name, text, expected) in cases {
        let error = config_from(text).expect_err(name);
        assert!(
            error.contains(expected),
            "{name}: expected {expected:?} in {error:?}"
        );
    }
}

#[test]
fn programmatic_invalid_suppression_fails_closed_without_hiding_findings() {
    let invalid = Config {
        suppressions: vec![Suppression {
            rule: "BG001".into(),
            path: Some("[".into()),
            fingerprint: None,
            reason: "FAKE invalid glob".into(),
            expires: None,
        }],
        ..Config::default()
    };

    let invalid_report = report(&format!("require({FAKE_ID_A})"), &invalid);
    assert_eq!(
        invalid_report.completeness,
        bloxguard_core::model::Completeness::Failed
    );
    assert!(invalid_report.findings.is_empty());
    assert_eq!(invalid_report.suppressed_count, 0);
    let configuration = invalid_report
        .inputs
        .iter()
        .find(|input| input.input == "<configuration>")
        .expect("configuration failure is a report input");
    assert!(
        configuration.reasons[0].contains("invalid suppression path glob"),
        "{:?}",
        configuration.reasons
    );
}

#[test]
fn suppression_expiry_is_inclusive_and_expired_entries_do_not_hide_findings() {
    let suppression = |expires: &str| Suppression {
        rule: "BG001".into(),
        path: Some("/FAKE_fixture".into()),
        fingerprint: None,
        reason: "FAKE reviewed fixture".into(),
        expires: Some(expires.into()),
    };

    let mut active = Config {
        current_date: "2026-10-18".into(),
        suppressions: vec![suppression("2026-10-18")],
        ..Config::default()
    };
    active.validate().unwrap();
    let active_report = report(&format!("require({FAKE_ID_A})"), &active);
    assert!(active_report.findings.is_empty());
    assert_eq!(active_report.suppressed_count, 1);

    active.suppressions = vec![suppression("2026-10-17")];
    let expired_report = report(&format!("require({FAKE_ID_A})"), &active);
    assert_eq!(expired_report.findings.len(), 1);
    assert_eq!(expired_report.suppressed_count, 0);
}

#[test]
fn baseline_hides_only_known_fingerprint_and_keeps_new_finding() {
    let source = format!("require({FAKE_ID_A})\nrequire({FAKE_ID_B})");
    let initial = report(&source, &Config::default());
    assert_eq!(initial.findings.len(), 2);

    let known = initial
        .findings
        .iter()
        .find(|finding| finding.evidence.contains(&FAKE_ID_A.to_string()))
        .expect("first synthetic finding")
        .fingerprint
        .clone();
    let config = Config {
        baseline_fingerprints: BTreeSet::from([known]),
        ..Config::default()
    };
    config.validate().unwrap();

    let rescanned = report(&source, &config);
    assert_eq!(rescanned.baseline_count, 1);
    assert_eq!(rescanned.findings.len(), 1);
    assert!(
        rescanned.findings[0]
            .evidence
            .contains(&FAKE_ID_B.to_string())
    );
}

#[test]
fn json_and_sarif_are_byte_deterministic_across_repeated_scans() {
    let source = format!("require({FAKE_ID_B})\nrequire({FAKE_ID_A})");
    let first = report(&source, &Config::default());
    let second = report(&source, &Config::default());

    assert_eq!(
        output::json(&first).unwrap(),
        output::json(&second).unwrap()
    );
    assert_eq!(
        output::sarif(&first).unwrap(),
        output::sarif(&second).unwrap()
    );
}

#[test]
fn fingerprint_ignores_line_edits_but_changes_with_asset_identity() {
    let original = report(&format!("require({FAKE_ID_A})"), &Config::default());
    let moved = report(
        &format!("-- FAKE review note\n\nrequire({FAKE_ID_A})"),
        &Config::default(),
    );
    let changed = report(&format!("require({FAKE_ID_B})"), &Config::default());
    let same_path_in_another_input = scan_documents(
        vec![load_source(
            &format!("require({FAKE_ID_A})"),
            "FAKE_other_directory/FAKE_fixture.luau",
            "ModuleScript",
            &Limits::default(),
        )],
        &Config::default(),
    );

    assert_eq!(original.findings.len(), 1);
    assert_eq!(moved.findings.len(), 1);
    assert_eq!(changed.findings.len(), 1);
    assert_eq!(same_path_in_another_input.findings.len(), 1);
    assert_eq!(
        original.findings[0].fingerprint, moved.findings[0].fingerprint,
        "source-line movement must not invalidate review identity"
    );
    assert_ne!(
        original.findings[0].fingerprint, changed.findings[0].fingerprint,
        "a different remote asset ID must be a distinct finding"
    );
    assert_eq!(
        original.findings[0].fingerprint, same_path_in_another_input.findings[0].fingerprint,
        "input location is excluded when rule, instance path, and evidence match"
    );
}

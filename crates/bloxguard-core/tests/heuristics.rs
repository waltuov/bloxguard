use bloxguard_core::config::Config;
use bloxguard_core::engine::scan_documents;
use bloxguard_core::finding::{Confidence, Severity};
use bloxguard_core::heuristics;
use bloxguard_core::model::{Document, Instance, Limits};
use serde_json::json;
use std::collections::BTreeSet;

fn root(name: &str, class: &str) -> Instance {
    Instance {
        name: name.into(),
        class: class.into(),
        ..Instance::default()
    }
}

fn script(name: &str, parent: Option<usize>, source: &str) -> Instance {
    Instance {
        name: name.into(),
        class: "Script".into(),
        parent,
        source: Some(source.into()),
        source_file: Some(format!("{name}.server.luau")),
        ..Instance::default()
    }
}

fn document(name: &str, instances: Vec<Instance>) -> Document {
    Document {
        input: name.into(),
        instances,
        ..Document::default()
    }
}

fn rule_count(document: &Document, rule: &str) -> usize {
    heuristics::analyze(document, &Limits::default())
        .findings
        .iter()
        .filter(|finding| finding.rule_id == rule)
        .count()
}

#[test]
fn bg005_detects_dense_escapes_and_string_char_builders() {
    let escaped = (0..20)
        .map(|index| format!("\\{:03}", 65 + index))
        .collect::<String>();
    let samples = [
        format!("local FAKE_blob = \"{escaped}\""),
        "local FAKE_code = string.char(70, 65, 75, 69, 95, 67, 79, 68, 69, 33)".into(),
        r#"local s = "\x46\x41\x4b\x45\x20\x70\x61\x79\x6c\x6f\x61\x64"
return s"#
            .into(),
    ];
    for (index, source) in samples.iter().enumerate() {
        let doc = document(
            &format!("FAKE_BG005_malicious_{index}"),
            vec![script("FAKE_Obfuscated", None, source)],
        );
        assert_eq!(rule_count(&doc, "BG005"), 1, "sample {index}");
    }
}

#[test]
fn bg005_changed_literal_payload_breaks_a_baseline_match() {
    let payload_document = |byte: u8| {
        let escaped = (0..12)
            .map(|_| format!("\\x{byte:02x}"))
            .collect::<String>();
        document(
            "FAKE_BG005_payload_baseline",
            vec![script(
                "FAKE_Obfuscated",
                None,
                &format!("\u{feff}local FAKE_blob = \"{escaped}\""),
            )],
        )
    };

    let original = payload_document(b'A');
    let changed = payload_document(b'B');
    let original_finding = heuristics::analyze(&original, &Limits::default())
        .findings
        .into_iter()
        .find(|finding| finding.rule_id == "BG005")
        .expect("twelve hex escapes should produce BG005");
    let changed_finding = heuristics::analyze(&changed, &Limits::default())
        .findings
        .into_iter()
        .find(|finding| finding.rule_id == "BG005")
        .expect("equal-length changed payload should produce BG005");
    assert!(original_finding.evidence.contains("content_sha256="));
    assert_ne!(original_finding.fingerprint, changed_finding.fingerprint);

    let config = Config {
        baseline_fingerprints: BTreeSet::from([original_finding.fingerprint]),
        ..Config::default()
    };
    let original_report = scan_documents(vec![original], &config);
    assert_eq!(original_report.baseline_count, 1);
    assert!(
        !original_report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG005")
    );

    let changed_report = scan_documents(vec![changed], &config);
    assert_eq!(changed_report.baseline_count, 0);
    assert!(
        changed_report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG005")
    );
}

#[test]
fn bg005_changed_string_char_payload_breaks_a_baseline_match() {
    let payload_document = |byte: u8| {
        let arguments = (0..10)
            .map(|_| byte.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        document(
            "FAKE_BG005_char_baseline",
            vec![script(
                "FAKE_Obfuscated",
                None,
                &format!("local FAKE_blob = string.char({arguments})"),
            )],
        )
    };

    let original = payload_document(65);
    let changed = payload_document(66);
    let original_finding = heuristics::analyze(&original, &Limits::default())
        .findings
        .into_iter()
        .find(|finding| finding.rule_id == "BG005")
        .expect("ten string.char arguments should produce BG005");
    let changed_finding = heuristics::analyze(&changed, &Limits::default())
        .findings
        .into_iter()
        .find(|finding| finding.rule_id == "BG005")
        .expect("equal-length changed string.char payload should produce BG005");
    assert!(original_finding.evidence.contains("content_sha256="));
    assert_ne!(original_finding.fingerprint, changed_finding.fingerprint);

    let config = Config {
        baseline_fingerprints: BTreeSet::from([original_finding.fingerprint]),
        ..Config::default()
    };
    let original_report = scan_documents(vec![original], &config);
    assert_eq!(original_report.baseline_count, 1);
    assert!(
        !original_report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG005")
    );

    let changed_report = scan_documents(vec![changed], &config);
    assert_eq!(changed_report.baseline_count, 0);
    assert!(
        changed_report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG005")
    );
}

#[test]
fn bg005_detects_vm_shape_and_ignores_comment_text() {
    let vm = r#"
        local FAKE_tape = {[1]=17,[2]=91,[3]=44,[4]=73,[5]=12,[6]=63,[7]=5,[8]=88}
        local ip = 1
        repeat
            local op = FAKE_tape[ip]
            if op == 17 then ip = FAKE_tape[2]
            elseif op == 91 then ip = FAKE_tape[3]
            elseif op == 44 then ip = FAKE_tape[4]
            else ip = FAKE_tape[5] end
        until ip == 999
    "#;
    let fingerprint = |source: &str| {
        bloxguard_core::heuristics::analyze(
            &document("FAKE_BG005_vm", vec![script("FAKE_VM", None, source)]),
            &Limits::default(),
        )
        .findings
        .into_iter()
        .find(|finding| finding.rule_id == "BG005")
        .unwrap()
        .fingerprint
    };
    assert_ne!(
        fingerprint(vm),
        fingerprint(&vm.replace("[8]=88", "[8]=89"))
    );
    assert_eq!(
        fingerprint(vm),
        fingerprint(&format!("-- FAKE unrelated comment\n{vm}"))
    );
    let comment_only = format!(
        "{}\nreturn true",
        vm.lines()
            .map(|line| format!("-- {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        rule_count(
            &document("FAKE_BG005_vm", vec![script("FAKE_VM", None, vm)]),
            "BG005"
        ),
        1
    );
    assert_eq!(
        rule_count(
            &document(
                "FAKE_BG005_comment",
                vec![script("FAKE_Comment", None, &comment_only)]
            ),
            "BG005"
        ),
        0
    );
}

#[test]
fn bg005_ignores_clean_minification_and_low_entropy_data() {
    let low_entropy = "A".repeat(500);
    let samples = [
        "local a=1;local b=2;for i=1,10 do a=a+b+i end;return a".to_owned(),
        format!("local FAKE_padding = \"{low_entropy}\"; return #FAKE_padding"),
    ];
    for (index, source) in samples.iter().enumerate() {
        let doc = document(
            &format!("FAKE_BG005_clean_{index}"),
            vec![script("FAKE_Clean", None, source)],
        );
        assert_eq!(rule_count(&doc, "BG005"), 0, "sample {index}");
    }
}

#[test]
fn bg006_detects_deep_hiding_and_core_lookalikes() {
    let mut deep = vec![root("FAKE_Root", "DataModel")];
    for index in 0..9 {
        deep.push(Instance {
            name: format!("FAKE_Nest_{index}"),
            class: if index % 2 == 0 { "Model" } else { "Part" }.into(),
            parent: Some(index),
            ..Instance::default()
        });
    }
    deep.push(script("FAKE_DeepScript", Some(9), "return true"));
    assert_eq!(rule_count(&document("FAKE_BG006_deep", deep), "BG006"), 1);

    let lookalike = document(
        "FAKE_BG006_lookalike",
        vec![
            root("FAKE_Root", "DataModel"),
            script("Wоrkspace", Some(0), "return true"),
        ],
    );
    assert_eq!(rule_count(&lookalike, "BG006"), 1);
}

#[test]
fn bg006_detects_invisible_names_and_run_context_conflicts() {
    let invisible = document(
        "FAKE_BG006_invisible",
        vec![script("FAKE\u{200B}Script", None, "return true")],
    );
    assert_eq!(rule_count(&invisible, "BG006"), 1);

    let mut server_contextual = script("FAKE_ServerContext", Some(0), "return true");
    server_contextual
        .properties
        .insert("RunContext".into(), json!("Client"));
    let server_context = document(
        "FAKE_BG006_server_context",
        vec![
            root("FAKE_Server", "ServerScriptService"),
            server_contextual,
        ],
    );
    let mut workspace_contextual = script("FAKE_WorkspaceContext", Some(1), "return true");
    workspace_contextual
        .properties
        .insert("RunContext".into(), json!("Client"));
    let workspace_context = document(
        "FAKE_BG006_workspace_context",
        vec![
            root("FAKE_Workspace", "Workspace"),
            Instance {
                name: "FAKE_Model".into(),
                class: "Model".into(),
                parent: Some(0),
                ..Instance::default()
            },
            workspace_contextual,
        ],
    );

    for (label, context) in [
        ("ServerScriptService", server_context),
        ("Workspace model", workspace_context),
    ] {
        let findings = heuristics::analyze(&context, &Limits::default()).findings;
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "BG006")
            .unwrap_or_else(|| panic!("RunContext should be reported for {label}"));
        assert_eq!(finding.location.property.as_deref(), Some("RunContext"));
        assert!(finding.evidence.contains("RunContext Client"));
    }
}

#[test]
fn bg006_ignores_distinct_unicode_and_normal_script_locations() {
    let samples = [
        document(
            "FAKE_BG006_unicode_clean",
            vec![script("Café工具", None, "return true")],
        ),
        document(
            "FAKE_BG006_location_clean",
            vec![
                root("FAKE_Server", "ServerScriptService"),
                script("FAKE_Gameplay", Some(0), "return true"),
            ],
        ),
    ];
    for (index, sample) in samples.iter().enumerate() {
        assert_eq!(rule_count(sample, "BG006"), 0, "sample {index}");
    }
}

#[test]
fn bg011_detects_package_links_and_linked_source() {
    let mut package = root("FAKE_PackageLink", "PackageLink");
    package
        .properties
        .insert("PackageId".into(), json!(999000000000011_u64));
    let package_doc = document("FAKE_BG011_package", vec![package]);
    let package_findings = heuristics::analyze(&package_doc, &Limits::default()).findings;
    assert_eq!(rule_count(&package_doc, "BG011"), 1);
    assert_eq!(
        package_findings[0].location.property.as_deref(),
        Some("PackageId")
    );

    let mut linked = script("FAKE_Linked", None, "return true");
    linked
        .properties
        .insert("LinkedSource".into(), json!("rbxassetid://999000000000012"));
    assert_eq!(
        rule_count(&document("FAKE_BG011_linked", vec![linked]), "BG011"),
        1
    );
}

#[test]
fn bg011_ignores_empty_and_bundled_local_references() {
    let mut empty = root("FAKE_EmptyPackage", "PackageLink");
    empty.properties.insert("PackageId".into(), json!(0));
    let mut local = script("FAKE_LocalLinked", None, "return true");
    local.properties.insert(
        "LinkedSource".into(),
        json!("rbxasset://scripts/FAKE_LocalModule.lua"),
    );
    let samples = [
        document("FAKE_BG011_empty", vec![empty]),
        document("FAKE_BG011_local", vec![local]),
    ];
    for (index, sample) in samples.iter().enumerate() {
        assert_eq!(rule_count(sample, "BG011"), 0, "sample {index}");
    }
}

#[test]
fn bg012_detects_command_bar_social_engineering_strings() {
    let samples = [
        "local FAKE_message = \"Paste this into the command bar to fix the model\"",
        "local FAKE_message = \"In Studio's command bar, run this: require(999000000000012)\"",
    ];
    for (index, source) in samples.iter().enumerate() {
        let doc = document(
            &format!("FAKE_BG012_malicious_{index}"),
            vec![script("FAKE_Message", None, source)],
        );
        assert_eq!(rule_count(&doc, "BG012"), 1, "sample {index}");
    }
}

#[test]
fn bg012_ignores_descriptive_tutorial_text_and_harmless_comments() {
    let samples = [
        "local FAKE_help = \"The command bar runs Luau expressions during development.\"",
        "-- Explain the setup steps to the developer.\nreturn true",
    ];
    for (index, source) in samples.iter().enumerate() {
        let doc = document(
            &format!("FAKE_BG012_clean_{index}"),
            vec![script("FAKE_Tutorial", None, source)],
        );
        assert_eq!(rule_count(&doc, "BG012"), 0, "sample {index}");
    }
}

#[test]
fn bg012_detects_comments_at_medium_confidence_and_string_values_at_high_confidence() {
    let comment_doc = document(
        "FAKE_BG012_comment",
        vec![script(
            "FAKE_Readme",
            None,
            "-- To finish setup paste this into the command bar: require(999000000000238)\nreturn true",
        )],
    );
    let comment_findings = heuristics::analyze(&comment_doc, &Limits::default()).findings;
    let comment = comment_findings
        .iter()
        .find(|finding| finding.rule_id == "BG012")
        .expect("command-bar instruction in a comment should be reported");
    assert_eq!(comment.severity, Severity::High);
    assert_eq!(comment.confidence, Confidence::Medium);
    assert_eq!(comment.location.line, Some(1));
    assert_eq!(comment.location.property, None);

    let mut string_value = root("FAKE_README", "StringValue");
    string_value.properties.insert(
        "Value".into(),
        json!("Paste this into the command bar: require(999000000000239)"),
    );
    let value_doc = document("FAKE_BG012_string_value", vec![string_value]);
    let value_findings = heuristics::analyze(&value_doc, &Limits::default()).findings;
    let value = value_findings
        .iter()
        .find(|finding| finding.rule_id == "BG012")
        .expect("command-bar instruction in a StringValue should be reported");
    assert_eq!(value.severity, Severity::High);
    assert_eq!(value.confidence, Confidence::High);
    assert_eq!(value.location.property.as_deref(), Some("Value"));
    assert_eq!(value.location.line, None);
}

#[test]
fn findings_are_stable_and_source_locations_are_preserved() {
    let doc = document(
        "FAKE_determinism",
        vec![script(
            "FAKE_Message",
            None,
            "local message = \"Paste this into the command bar\"",
        )],
    );
    let first = heuristics::analyze(&doc, &Limits::default()).findings;
    let second = heuristics::analyze(&doc, &Limits::default()).findings;
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    let finding = first
        .iter()
        .find(|finding| finding.rule_id == "BG012")
        .unwrap();
    assert_eq!(finding.location.line, Some(1));
    assert!(finding.location.column.is_some());
    assert_eq!(
        finding.source_file.as_deref(),
        Some("FAKE_Message.server.luau")
    );
}

#[test]
fn token_budget_is_reported_instead_of_silently_truncating_tokens() {
    // The parser budget counts code tokens only and passes this source; the heuristic
    // lexer also keeps comments, so the comments push it past the same cap.
    let mut source = format!("local FAKE_values = {{{}}}\n", "1,".repeat(1_000));
    source.push_str(&"--c\n".repeat(100));
    let doc = document(
        "FAKE_budget",
        vec![script("FAKE_LongFlatSource", None, &source)],
    );
    let limits = Limits {
        max_script_bytes: 4_096,
        ..Limits::default()
    };
    assert!(bloxguard_core::analysis::parser_budget(&source, &limits).is_ok());
    let result = heuristics::analyze(&doc, &limits);
    assert!(result.findings.is_empty());
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("token budget exceeded"))
    );
}

#[test]
fn finding_output_limit_is_reported_and_bounded() {
    let instances = (0..10_001)
        .map(|index| {
            let mut package = root(&format!("FAKE_Package_{index}"), "PackageLink");
            package
                .properties
                .insert("PackageId".into(), json!(999000000000011_u64));
            package
        })
        .collect();
    let result = heuristics::analyze(
        &document("FAKE_output_limit", instances),
        &Limits::default(),
    );
    assert_eq!(result.findings.len(), 10_000);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("finding output limit reached"))
    );
}

/// A container class, then `folders` nested Folders, then one Script.
fn buried_script(container: &str, folders: usize, run_context: Option<&str>) -> Document {
    let mut instances = vec![root("FAKE_Top", container)];
    for level in 0..folders {
        let mut folder = root(&format!("FAKE_Folder_{level}"), "Folder");
        folder.parent = Some(level);
        instances.push(folder);
    }
    let mut buried = script("FAKE_Buried", Some(folders), "print(\"FAKE\")");
    if let Some(run_context) = run_context {
        buried
            .properties
            .insert("RunContext".into(), json!(run_context));
    }
    instances.push(buried);
    document("FAKE_buried", instances)
}

#[test]
fn bg006_sees_every_ancestor_of_a_deep_script() {
    for folders in [7, 127, 128, 129, 200, 1_000, 5_000] {
        let model = buried_script("Model", folders, None);
        assert_eq!(
            rule_count(&model, "BG006"),
            1,
            "Model with {folders} folders"
        );
        let odd = buried_script("CoreGui", folders, None);
        assert_eq!(
            rule_count(&odd, "BG006"),
            1,
            "CoreGui with {folders} folders"
        );
        let client = buried_script("ServerScriptService", folders, Some("Client"));
        assert_eq!(
            rule_count(&client, "BG006"),
            1,
            "Client script with {folders} folders"
        );
        let quiet = buried_script("ServerScriptService", folders, Some("Server"));
        assert_eq!(
            rule_count(&quiet, "BG006"),
            0,
            "Server script with {folders} folders"
        );
    }
}

#[test]
fn bg006_placement_survives_a_parent_cycle() {
    let mut first = root("FAKE_First", "Folder");
    first.parent = Some(1);
    let mut second = root("FAKE_Second", "Model");
    second.parent = Some(0);
    let doc = document(
        "FAKE_cycle",
        vec![
            first,
            second,
            script("FAKE_Looped", Some(0), "print(\"FAKE\")"),
        ],
    );
    let result = heuristics::analyze(&doc, &Limits::default());
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.rule_id == "BG006")
    );
}

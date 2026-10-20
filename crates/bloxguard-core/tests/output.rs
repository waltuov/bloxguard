use bloxguard_core::finding::{Confidence, Finding, Location, RelatedLocation, Severity};
use bloxguard_core::model::Completeness;
use bloxguard_core::output;
use bloxguard_core::report::{InputReport, ScanReport, ScriptInventory};
use serde_json::{Value, json};

#[test]
fn review_12_informational_diagnostics_are_visible_and_do_not_fail() {
    let xml = br#"<roblox version="4"><Item class="FAKE_FutureDecoration" referent="FAKE_1"><Properties><string name="Name">FAKE ornament</string></Properties></Item><Item class="ModuleScript" referent="FAKE_2"><Properties><string name="Name">FAKE module</string><ProtectedString name="Source">return {}</ProtectedString></Properties></Item></roblox>"#;
    let document =
        bloxguard_core::loading::load_bytes("FAKE future.rbxlx", "rbxlx", xml, &Default::default());
    let report = bloxguard_core::engine::scan_documents(vec![document], &Default::default());
    assert_eq!(report.completeness, Completeness::Complete);
    assert_eq!(report.exit_code(Severity::High, false), 0);
    assert_eq!(report.inputs[0].diagnostics.len(), 1);
    assert!(report.inputs[0].diagnostics[0].instance_path.is_some());
    assert!(output::human(&report).contains("info:"));
    assert!(output::inventory_human(&report).contains("info:"));
    let json: Value = serde_json::from_str(&output::json(&report).unwrap()).unwrap();
    let schema: Value =
        serde_json::from_str(include_str!("../../../docs/json-output.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&json));
    let sarif: Value = serde_json::from_str(&output::sarif(&report).unwrap()).unwrap();
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/sarif-schema-2.1.0.json")).unwrap();
    assert!(jsonschema::draft4::new(&schema).unwrap().is_valid(&sarif));
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["level"],
        "note"
    );
}

fn report() -> ScanReport {
    let mut finding = Finding::new(
        "BG002",
        Severity::Critical,
        Confidence::High,
        r"C:\work dir\FAKE place.rbxlx",
        "/Workspace/FAKE café/Loader",
        Location {
            line: Some(7),
            column: Some(3),
            end_line: Some(7),
            end_column: Some(18),
            ..Location::default()
        },
        "Remote module ID came from an instance value",
        "require(moduleId)",
    );
    finding.source_file = Some(r"C:\work dir\src\FAKE café.server.luau".into());
    finding.related_locations.push(RelatedLocation {
        instance_path: "/Workspace/FAKE café/Settings/ModuleId".into(),
        location: Location {
            property: Some("Value".into()),
            ..Location::default()
        },
        message: "Resolved moduleId from this NumberValue".into(),
        file: None,
    });

    ScanReport {
        schema_version: 1,
        tool: "bloxguard".into(),
        version: "0.1.0".into(),
        completeness: Completeness::Partial,
        inputs: vec![
            InputReport {
                diagnostics: vec![],
                input: "z-empty.rbxm".into(),
                completeness: Completeness::Partial,
                reasons: vec!["file ended before all properties were read".into()],
                instance_count: 0,
                script_count: 0,
            },
            InputReport {
                diagnostics: vec![],
                input: r"C:\work dir\FAKE place.rbxlx".into(),
                completeness: Completeness::Complete,
                reasons: vec![],
                instance_count: 4,
                script_count: 1,
            },
        ],
        inventory: vec![ScriptInventory {
            input: r"C:\work dir\FAKE place.rbxlx".into(),
            instance_path: "/Workspace/FAKE café/Loader".into(),
            class: "Script".into(),
            run_context: Some(json!("Server")),
            enabled: Some(true),
            size_bytes: 17,
            sha256: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()),
            source_file: Some(r"C:\work dir\src\FAKE café.server.luau".into()),
        }],
        findings: vec![finding],
        suppressed_count: 2,
        baseline_count: 1,
    }
}

#[test]
fn output_snapshots() {
    let report = report();
    insta::assert_snapshot!("human", output::human(&report));
    insta::assert_snapshot!("inventory_human", output::inventory_human(&report));
    insta::assert_snapshot!("json", output::json(&report).unwrap());
    insta::assert_snapshot!("sarif", output::sarif(&report).unwrap());
}

#[test]
fn json_matches_the_committed_public_schema() {
    let schema: Value = serde_json::from_str(include_str!("../../../docs/json-output.schema.json"))
        .expect("JSON output schema is JSON");
    let instance: Value = serde_json::from_str(&output::json(&report()).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("JSON output schema compiles");
    let errors: Vec<_> = validator
        .iter_errors(&instance)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "JSON schema errors:\n{}",
        errors.join("\n")
    );
}

#[test]
fn sarif_matches_the_committed_official_schema() {
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/sarif-schema-2.1.0.json"))
            .expect("official SARIF schema is JSON");
    let instance: Value = serde_json::from_str(&output::sarif(&report()).unwrap()).unwrap();
    let validator = jsonschema::draft4::new(&schema).expect("official SARIF schema compiles");
    let errors: Vec<_> = validator
        .iter_errors(&instance)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "SARIF schema errors:\n{}",
        errors.join("\n")
    );
}

#[test]
fn renderers_sort_unordered_report_collections() {
    let first = report();
    let mut second = first.clone();
    second.inputs.reverse();
    second.inputs[1].reasons.reverse();
    second.inventory.reverse();
    second.findings.reverse();

    assert_eq!(
        output::json(&first).unwrap(),
        output::json(&second).unwrap()
    );
    assert_eq!(
        output::sarif(&first).unwrap(),
        output::sarif(&second).unwrap()
    );
    assert_eq!(output::human(&first), output::human(&second));
    assert_eq!(
        output::inventory_human(&first),
        output::inventory_human(&second)
    );
}

#[test]
fn partial_scan_is_visible_even_without_results() {
    let mut report = ScanReport {
        completeness: Completeness::Failed,
        ..ScanReport::default()
    };
    report.inputs.push(InputReport {
        diagnostics: vec![],
        input: "FAKE-corrupt.rbxm".into(),
        completeness: Completeness::Failed,
        reasons: vec!["not a readable Roblox model".into()],
        instance_count: 0,
        script_count: 0,
    });

    let sarif: Value = serde_json::from_str(&output::sarif(&report).unwrap()).unwrap();
    assert_eq!(sarif["runs"][0]["results"], json!([]));
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        json!(false)
    );
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["properties"]["completeness"],
        json!("failed")
    );
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["level"],
        json!("error")
    );
}

/// SARIF readers and `bloxguard explain` get a link that works outside a
/// checkout: the rule's page on the repository's default branch, which exists.
#[test]
fn rule_help_links_are_absolute_urls_of_existing_pages() {
    let pages = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/rules");
    let sarif: Value = serde_json::from_str(&output::sarif(&report()).unwrap()).unwrap();
    let sarif_rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("SARIF rules are an array");
    assert_eq!(sarif_rules.len(), bloxguard_core::rules::all().len());
    for rule in bloxguard_core::rules::all() {
        let Some(page) = rule
            .help_uri
            .strip_prefix("https://github.com/waltuov/bloxguard/blob/master/docs/rules/")
        else {
            panic!("{} help link is not absolute: {}", rule.id, rule.help_uri);
        };
        assert_eq!(page, format!("{}.md", rule.id));
        assert!(pages.join(page).is_file(), "{} has no page", rule.id);
        let sarif_rule = sarif_rules
            .iter()
            .find(|candidate| candidate["id"] == rule.id)
            .expect("every rule is in SARIF");
        assert_eq!(sarif_rule["properties"]["documentation"], rule.help_uri);
    }
}

#[test]
fn sarif_uses_percent_encoded_file_uris_and_logical_instance_locations() {
    let sarif: Value = serde_json::from_str(&output::sarif(&report()).unwrap()).unwrap();
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        json!("file:///C:/work%20dir/src/FAKE%20caf%C3%A9.server.luau")
    );
    assert_eq!(
        result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
        json!("/Workspace/FAKE café/Loader")
    );
    assert_eq!(
        result["relatedLocations"][0]["properties"]["origin"],
        json!("property")
    );
}

#[test]
fn human_output_makes_terminal_controls_and_unicode_visible() {
    let mut report = ScanReport {
        tool: "bloxguard\u{1b}[2J".into(),
        completeness: Completeness::Partial,
        ..ScanReport::default()
    };
    report.inputs.push(InputReport {
        diagnostics: vec![],
        input: "FAKE\u{1b}[31m\nlabel".into(),
        completeness: Completeness::Partial,
        reasons: vec!["bad\r\nnext".into()],
        instance_count: 1,
        script_count: 1,
    });
    let mut finding = Finding::new(
        "BG012",
        Severity::High,
        Confidence::Medium,
        "FAKE\u{1b}[31m\nlabel",
        "/FAKE\\u{a}/Script",
        Location::default(),
        "message\u{7}\nforged",
        "evidence\u{1b}[0m",
    );
    finding.source_file = Some("FAKE caf\u{e9}\n.server.luau".into());
    report.findings.push(finding);
    report.inventory.push(ScriptInventory {
        input: "FAKE\u{1b}[31m\nlabel".into(),
        instance_path: "/FAKE\\u{a}/Script".into(),
        class: "Script\u{7}".into(),
        run_context: Some(json!("S\u{1b}")),
        enabled: Some(true),
        size_bytes: 1,
        sha256: None,
        source_file: Some("FAKE caf\u{e9}\n.server.luau".into()),
    });

    let human = output::human(&report);
    let inventory = output::inventory_human(&report);
    for rendered in [&human, &inventory] {
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{7}'));
        assert!(!rendered.contains('\r'));
        assert!(!rendered.contains("\nlabel"));
        assert!(rendered.contains(r"FAKE\u{1b}[31m\u{a}label"));
        assert!(rendered.contains(r"/FAKE\u{a}/Script"));
        assert!(!rendered.contains(r"/FAKE\\u{a}/Script"));
    }
    assert!(human.contains(r"message\u{7}\u{a}forged"));
    // Readable text stays as written since round 4; the newline is still escaped.
    assert!(inventory.contains("FAKE caf\u{e9}\\u{a}.server.luau"));
}

/// One line of XML, so a region copied from the script (line 3) would point
/// past the end of the file.
const FAKE_KIT_XML: &str = r#"<roblox version="4"><Item class="Model" referent="FAKE1"><Properties><string name="Name">FAKE_Kit</string></Properties><Item class="Script" referent="FAKE2"><Properties><string name="Name">FAKE_Weld</string><ProtectedString name="Source">-- FAKE weld
local FAKE_unused = 1
require(999000000000131)</ProtectedString></Properties></Item></Item></roblox>"#;

/// Scan relative paths from the package root, the working directory of
/// integration tests, as a CI job scans paths from the repository root.
fn launch_sarif_results(paths: &[std::path::PathBuf]) -> Vec<Value> {
    let report = bloxguard_core::engine::scan_paths(paths, &Default::default());
    assert_eq!(report.completeness, Completeness::Complete, "{report:?}");
    let sarif: Value = serde_json::from_str(&output::sarif(&report).unwrap()).unwrap();
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/sarif-schema-2.1.0.json")).unwrap();
    assert!(jsonschema::draft4::new(&schema).unwrap().is_valid(&sarif));
    sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|result| result["ruleId"] == "BG001")
        .cloned()
        .collect()
}

fn launch_relative_temp() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::Builder::new()
        .prefix("bloxguard_FAKE_sarif_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    let relative = temp
        .path()
        .strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .unwrap()
        .to_owned();
    (temp, relative)
}

fn uri_of(result: &Value) -> &str {
    result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        .as_str()
        .unwrap()
}

fn assert_embedded_location(result: &Value, script_line: u64) {
    let physical = &result["locations"][0]["physicalLocation"];
    assert!(physical.get("region").is_none(), "{result}");
    assert_eq!(
        result["properties"]["scriptRegion"]["startLine"],
        json!(script_line),
        "{result}"
    );
    let message = result["message"]["text"].as_str().unwrap();
    assert!(
        message.contains(&format!("script line {script_line}:")),
        "{message}"
    );
    assert!(
        message.contains(result["properties"]["instancePath"].as_str().unwrap()),
        "{message}"
    );
    assert!(!uri_of(result).starts_with("./"), "{result}");
}

#[test]
fn launch_sarif_model_file_scanned_alone_points_at_the_file_without_a_script_region() {
    let (_temp, relative) = launch_relative_temp();
    let model = relative.join("FAKE_kit.rbxmx");
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&model),
        FAKE_KIT_XML,
    )
    .unwrap();
    let results = launch_sarif_results(std::slice::from_ref(&model));
    assert_eq!(results.len(), 1, "{results:?}");
    assert_ne!(uri_of(&results[0]), ".");
    let result = &results[0];
    assert_embedded_location(result, 3);
    assert_eq!(
        uri_of(result),
        format!(
            "{}/FAKE_kit.rbxmx",
            relative.to_string_lossy().replace('\\', "/")
        )
    );
    assert!(
        result["message"]["text"]
            .as_str()
            .unwrap()
            .ends_with("(/FAKE_Kit/FAKE_Weld, script line 3:1)"),
        "{result}"
    );
}

#[test]
fn launch_sarif_embedded_scripts_in_a_tree_have_no_script_region_and_source_files_keep_theirs() {
    let (_temp, relative) = launch_relative_temp();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&relative);
    std::fs::create_dir_all(root.join("FAKE_game/models")).unwrap();
    std::fs::create_dir_all(root.join("FAKE_game/src")).unwrap();
    std::fs::write(root.join("FAKE_game/models/FAKE_kit.rbxmx"), FAKE_KIT_XML).unwrap();
    std::fs::write(
        root.join("FAKE_game/src/FAKE_part.model.json"),
        r#"{"className":"Script","properties":{"Source":"-- FAKE\n\n\nrequire(999000000000132)"}}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("FAKE_game/src/FAKE_loader.server.luau"),
        "-- FAKE\nrequire(999000000000133)\n",
    )
    .unwrap();

    // The `./` that `scan .` and `scan ./dir` produce is not part of the URI.
    let spelled = std::path::Path::new(".").join(&relative).join("FAKE_game");
    let results = launch_sarif_results(&[spelled]);
    assert_eq!(results.len(), 3, "{results:?}");
    let by_id = |id: &str| {
        results
            .iter()
            .find(|result| {
                result["properties"]["evidence"]
                    .as_str()
                    .unwrap()
                    .contains(id)
            })
            .unwrap()
    };
    let tree = format!(
        "{}/FAKE_game",
        relative.to_string_lossy().replace('\\', "/")
    );

    // Nested model file and JSON model: no region from the script, and the
    // URI names the nested file that holds it.
    assert_embedded_location(by_id("999000000000131"), 3);
    assert_embedded_location(by_id("999000000000132"), 4);
    assert_eq!(
        uri_of(by_id("999000000000131")),
        format!("{tree}/models/FAKE_kit.rbxmx")
    );
    assert_eq!(
        uri_of(by_id("999000000000132")),
        format!("{tree}/src/FAKE_part.model.json")
    );

    let source = by_id("999000000000133");
    assert_eq!(
        uri_of(source),
        format!("{tree}/src/FAKE_loader.server.luau")
    );
    assert_eq!(
        source["locations"][0]["physicalLocation"]["region"]["startLine"],
        json!(2)
    );
    assert!(source["properties"].get("scriptRegion").is_none());
    assert_eq!(
        source["message"]["text"],
        json!("module is loaded from a numeric asset ID")
    );
}

/// A model whose script requires the ID stored in its sibling `IntValue`.
const FAKE_VALUE_KIT_XML: &str = r#"<roblox version="4"><Item class="Model" referent="FAKE1"><Properties><string name="Name">FAKE_Kit</string></Properties><Item class="IntValue" referent="FAKE2"><Properties><string name="Name">FAKE_Id</string><int64 name="Value">999000000000137</int64></Properties></Item><Item class="Script" referent="FAKE3"><Properties><string name="Name">FAKE_Weld</string><ProtectedString name="Source">require(script.Parent.FAKE_Id.Value)</ProtectedString></Properties></Item></Item></roblox>"#;

/// A related location names the file that holds the value, picked like the
/// finding's own file, instead of the scanned folder.
#[test]
fn launch_sarif_related_locations_name_the_file_that_holds_the_value() {
    let (_temp, relative) = launch_relative_temp();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&relative);
    std::fs::create_dir_all(root.join("FAKE_game/src/FAKE_Settings")).unwrap();
    std::fs::create_dir_all(root.join("FAKE_game/models")).unwrap();
    std::fs::write(
        root.join("FAKE_game/src/FAKE_Config.model.json"),
        r#"{"className":"NumberValue","properties":{"Value":999000000000135}}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("FAKE_game/src/FAKE_Settings/init.meta.json"),
        r#"{"attributes":{"FAKE_asset":999000000000136}}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("FAKE_game/src/FAKE_loader.server.luau"),
        "require(script.Parent.FAKE_Config.Value)\nrequire(script.Parent.FAKE_Settings:GetAttribute(\"FAKE_asset\"))\n",
    )
    .unwrap();
    std::fs::write(
        root.join("FAKE_game/models/FAKE_kit.rbxmx"),
        FAKE_VALUE_KIT_XML,
    )
    .unwrap();
    // An object the scanner cannot pin down: the related location is the
    // closest known object, the model, so the file is the nested model file.
    std::fs::write(
        root.join("FAKE_game/models/FAKE_pool.rbxmx"),
        FAKE_VALUE_KIT_XML
            .replace("FAKE_Kit", "FAKE_Pool")
            .replace("999000000000137", "999000000000138")
            .replace(
                "script.Parent.FAKE_Id.Value",
                "script.Parent:GetChildren()[1].Value",
            ),
    )
    .unwrap();

    let tree = relative.join("FAKE_game");
    let report =
        bloxguard_core::engine::scan_paths(std::slice::from_ref(&tree), &Default::default());
    assert_eq!(report.completeness, Completeness::Complete, "{report:?}");
    let sarif: Value = serde_json::from_str(&output::sarif(&report).unwrap()).unwrap();
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/sarif-schema-2.1.0.json")).unwrap();
    assert!(jsonschema::draft4::new(&schema).unwrap().is_valid(&sarif));
    let tree_uri = tree.to_string_lossy().replace('\\', "/");
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    for (id, script_file, value_file) in [
        (
            "999000000000135",
            "src/FAKE_loader.server.luau",
            "src/FAKE_Config.model.json",
        ),
        (
            "999000000000136",
            "src/FAKE_loader.server.luau",
            "src/FAKE_Settings/init.meta.json",
        ),
        (
            "999000000000137",
            "models/FAKE_kit.rbxmx",
            "models/FAKE_kit.rbxmx",
        ),
    ] {
        let result = results
            .iter()
            .find(|result| {
                result["ruleId"] == "BG002"
                    && result["properties"]["evidence"]
                        .as_str()
                        .unwrap()
                        .contains(id)
            })
            .unwrap_or_else(|| panic!("no BG002 finding for {id}: {results:?}"));
        assert_eq!(uri_of(result), format!("{tree_uri}/{script_file}"), "{id}");
        let related = result["relatedLocations"].as_array().unwrap();
        assert_eq!(related.len(), 1, "{id}: {result}");
        assert_eq!(
            related[0]["physicalLocation"]["artifactLocation"]["uri"],
            json!(format!("{tree_uri}/{value_file}")),
            "{id}: {result}"
        );
    }
    let pool = results
        .iter()
        .find(|result| {
            result["ruleId"] == "BG002"
                && result["properties"]["instancePath"]
                    .as_str()
                    .unwrap()
                    .contains("FAKE_Pool")
        })
        .unwrap_or_else(|| panic!("no BG002 finding in FAKE_Pool: {results:?}"));
    let related = pool["relatedLocations"].as_array().unwrap();
    assert_eq!(related.len(), 1, "{pool}");
    assert!(
        related[0]["logicalLocations"][0]["fullyQualifiedName"]
            .as_str()
            .unwrap()
            .ends_with("/FAKE_Pool"),
        "{pool}"
    );
    assert_eq!(
        related[0]["physicalLocation"]["artifactLocation"]["uri"],
        json!(format!("{tree_uri}/models/FAKE_pool.rbxmx")),
        "{pool}"
    );
    // The JSON report keeps its format: related locations carry no file.
    let json: Value = serde_json::from_str(&output::json(&report).unwrap()).unwrap();
    for finding in json["findings"].as_array().unwrap() {
        for related in finding["related_locations"]
            .as_array()
            .into_iter()
            .flatten()
        {
            assert!(related.get("file").is_none(), "{related}");
        }
    }
}

#[test]
fn launch_sarif_rules_carry_the_security_tag_and_no_rule_wide_security_severity() {
    let sarif: Value = serde_json::from_str(&output::sarif(&report()).unwrap()).unwrap();
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 12);
    for rule in rules {
        assert_eq!(rule["properties"]["tags"], json!(["security"]), "{rule}");
        // GitHub shows a rule's security-severity instead of each result's
        // level, and findings of one rule differ in severity: an unresolved
        // `require(v)` is BG001 low, a test runner's `getfenv().expect` is
        // BG004 low. A rule wide value would show them as high.
        assert!(
            rule["properties"].get("security-severity").is_none(),
            "{rule}"
        );
    }
    for (path, source, rule, severity) in [
        (
            "FAKE_services.luau",
            "local M = {}\nfunction M.AddServices(folder)\n  for _, v in ipairs(folder:GetChildren()) do\n    require(v)\n  end\nend\nreturn M\n",
            "BG001",
            Severity::Low,
        ),
        (
            "FAKE_spec.spec.luau",
            "return function()\n  getfenv().expect(1).to.equal(1)\nend\n",
            "BG004",
            Severity::Low,
        ),
    ] {
        let document =
            bloxguard_core::loading::load_source(source, path, "ModuleScript", &Default::default());
        let report = bloxguard_core::engine::scan_documents(vec![document], &Default::default());
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == rule)
            .unwrap_or_else(|| panic!("{source}: {:?}", report.findings));
        assert_eq!(finding.severity, severity, "{source}");
        let sarif: Value = serde_json::from_str(&output::sarif(&report).unwrap()).unwrap();
        let result = sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["ruleId"] == rule)
            .unwrap();
        assert_eq!(result["level"], "note", "{result}");
    }
}

#[test]
fn launch_json_container_file_names_the_nested_file_and_matches_the_schema() {
    let (_temp, relative) = launch_relative_temp();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&relative);
    std::fs::create_dir_all(root.join("FAKE_game/models")).unwrap();
    std::fs::write(root.join("FAKE_game/models/FAKE_kit.rbxmx"), FAKE_KIT_XML).unwrap();
    std::fs::write(
        root.join("FAKE_game/FAKE_loader.server.luau"),
        "require(999000000000134)\n",
    )
    .unwrap();
    let tree = relative.join("FAKE_game");
    let report =
        bloxguard_core::engine::scan_paths(std::slice::from_ref(&tree), &Default::default());
    let json: Value = serde_json::from_str(&output::json(&report).unwrap()).unwrap();
    let schema: Value =
        serde_json::from_str(include_str!("../../../docs/json-output.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<_> = validator
        .iter_errors(&json)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");

    let by_id = |id: &str| {
        json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["evidence"].as_str().unwrap().contains(id))
            .unwrap()
            .clone()
    };
    let nested = by_id("999000000000131");
    assert!(nested.get("source_file").is_none(), "{nested:#}");
    assert_eq!(
        nested["container_file"],
        json!(tree.join("models").join("FAKE_kit.rbxmx").to_string_lossy())
    );
    let source = by_id("999000000000134");
    assert_eq!(
        source["source_file"],
        json!(tree.join("FAKE_loader.server.luau").to_string_lossy())
    );
    assert!(source.get("container_file").is_none(), "{source:#}");
}

#[test]
fn launch_sarif_message_keeps_scanned_names_literal() {
    // Names that would form `[text](https://...)` across three path
    // segments, a placeholder shaped name, and a right to left override in
    // a property name and an attribute name.
    let bundle: bloxguard_core::model::Bundle = serde_json::from_value(json!({
        "schema_version": 1,
        "instances": [
            { "name": "[FAKE click](https:", "class": "Folder" },
            { "name": "", "class": "Folder", "parent": 0 },
            { "name": "example.invalid)", "class": "Folder", "parent": 1 },
            { "name": "FAKE_Label", "class": "TextLabel", "parent": 2,
              "properties": { "\u{202e}FAKEText": "Paste this into the command bar" } },
            { "name": "FAKE_Note", "class": "Folder", "parent": 2,
              "attributes": { "\u{202e}FAKE_note": "Paste this into the command bar" } },
            { "name": "FAKE_{0}", "class": "Folder", "parent": 2,
              "attributes": { "FAKE_plain": "Paste this into the command bar" } }
        ]
    }))
    .unwrap();
    let document = bloxguard_core::loading::load_bundle(bundle, "FAKE_bundle", &Default::default());
    let report = bloxguard_core::engine::scan_documents(vec![document], &Default::default());
    let sarif: Value = serde_json::from_str(&output::sarif(&report).unwrap()).unwrap();
    let messages: Vec<String> = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|result| result["ruleId"] == "BG012")
        .map(|result| result["message"]["text"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(messages.len(), 3, "{messages:#?}");
    let link = r"/\[FAKE\u{{20}}click\](https://example.invalid)";
    for message in &messages {
        assert!(message.contains(link), "{message}");
        assert!(!message.contains('\u{202e}'), "{message}");
        // Every bracket in the message is escaped, so none starts a link.
        for (index, _) in message.match_indices(['[', ']']) {
            assert_eq!(&message[index - 1..index], "\\", "{message}");
        }
    }
    let joined = messages.join("\n");
    assert!(joined.contains(r"property \u{{202e}}FAKEText"), "{joined}");
    assert!(
        joined.contains(r"attribute \u{{202e}}FAKE_note"),
        "{joined}"
    );
    assert!(
        joined.contains("/FAKE_{{0}}, attribute FAKE_plain"),
        "{joined}"
    );
}

#[test]
fn launch_human_output_shows_confidence_and_fingerprint() {
    let document = bloxguard_core::loading::load_source(
        "require(999000000000201)\n",
        "FAKE_loader.server.luau",
        "Script",
        &Default::default(),
    );
    let report = bloxguard_core::engine::scan_documents(vec![document], &Default::default());
    let finding = &report.findings[0];
    let human = output::human(&report);
    assert!(
        human.contains(&format!("  [{}, high confidence] BG001 ", finding.severity)),
        "{human}"
    );
    // The printed value is the one JSON reports and suppressions match.
    let json: Value = serde_json::from_str(&output::json(&report).unwrap()).unwrap();
    let fingerprint = json["findings"][0]["fingerprint"].as_str().unwrap();
    assert_eq!(fingerprint, finding.fingerprint);
    assert!(
        human.contains(&format!("\n    fingerprint: {fingerprint}\n")),
        "{human}"
    );

    let mut medium = finding.clone();
    medium.confidence = Confidence::Medium;
    medium.fingerprint = "FAKE\u{1b}[2J\nforged".into();
    let report = ScanReport {
        inputs: report.inputs.clone(),
        findings: vec![medium],
        ..ScanReport::default()
    };
    let human = output::human(&report);
    assert!(human.contains("[high, medium confidence] BG001"), "{human}");
    assert!(
        human.contains(r"fingerprint: FAKE\u{1b}[2J\u{a}forged"),
        "{human}"
    );
    assert!(!human.contains('\u{1b}'));
    assert!(!human.contains("\nforged"));
}

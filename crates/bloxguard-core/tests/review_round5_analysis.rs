//! Review round 5 regressions for the Luau analyzer: round 6 brief items 1 to 4. Case
//! IDs such as T34 are those of the second review of round 5. Every
//! fixture is synthetic and defanged: asset IDs are in 999000000000000 to
//! 999999999999999 and every name starts with `FAKE`.

use bloxguard_core::analysis::{AnalysisResult, analyze};
use bloxguard_core::finding::{Confidence, Finding, Severity};
use bloxguard_core::model::{Document, Instance, Limits};
use std::collections::BTreeMap;

/// The ID a reader starts with, trusted in the trust cases.
const TRUSTED: u64 = 999_000_000_000_000;
const TR: &str = "999000000000000";
/// The ID an unrelated write stores. It must never show up in a reader's finding.
const X: &str = "999000000006077";

fn script_document(source: &str) -> Document {
    Document {
        input: "FAKE_round5.luau".into(),
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

/// A folder with a local `ModuleScript` named `FAKE_Module` and one script beside it,
/// so `script.Parent.FAKE_Module` is a module of the content.
fn module_document(source: &str) -> Document {
    Document {
        input: "FAKE_round5.rbxmx".into(),
        instances: vec![
            Instance {
                name: "FAKE_Root".into(),
                class: "Folder".into(),
                ..Instance::default()
            },
            Instance {
                name: "FAKE_Module".into(),
                class: "ModuleScript".into(),
                parent: Some(0),
                source: Some("return {}".into()),
                ..Instance::default()
            },
            Instance {
                name: "FAKE_Main".into(),
                class: "Script".into(),
                parent: Some(0),
                source: Some(source.into()),
                ..Instance::default()
            },
        ],
        ..Document::default()
    }
}

fn module_analysis(source: &str) -> AnalysisResult {
    analyze(&module_document(source), 2, &Limits::default(), &[])
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

/// No finding names `id` anywhere in its evidence.
fn never_names(label: &str, result: &AnalysisResult, id: &str) {
    assert!(
        result
            .findings
            .iter()
            .all(|finding| !finding.evidence.contains(id)),
        "{label}: a finding names {id}\n{:#?}",
        describe(&result.findings)
    );
}

/// No BG001 or BG002 finding at all: the module is a local one.
fn no_require_finding(label: &str, result: &AnalysisResult) {
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.rule_id != "BG001" && finding.rule_id != "BG002"),
        "{label}: {:#?}",
        describe(&result.findings)
    );
}

/// A BG001 finding at high confidence that resolves exactly `id`.
fn resolves_to(label: &str, result: &AnalysisResult, id: &str) {
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG001"
                && finding.severity >= Severity::High
                && finding.confidence == Confidence::High
                && finding
                    .evidence
                    .contains(&format!("resolved asset id: {id}"))),
        "{label}: expected the resolved ID {id}\n{:#?}",
        describe(&result.findings)
    );
}

fn names_id(label: &str, result: &AnalysisResult, rule: &str, id: &str) {
    assert!(
        result.findings.iter().any(|finding| finding.rule_id == rule
            && finding.severity >= Severity::High
            && finding.evidence.contains(id)),
        "{label}: expected {rule} naming {id}\n{:#?}",
        describe(&result.findings)
    );
}

// ----- item 1: facts belong to a variable or a known table ---------------------------

/// Second review T47, T48, R10 and R11 (high on clean code) and T34 (trust withheld).
#[test]
fn item1_second_review_clean_cases_stay_quiet() {
    let t47 = "local cfg={id=script.Parent.FAKE_Module}\nlocal function load() return require(cfg.id) end\nlocal telemetry={}\ntelemetry.id=999000000005147\nreturn load()";
    let t48 = "local id=script.Parent.FAKE_Module\nlocal function load() return require(id) end\ndo\n local id=nil\n id=999000000005148\n print(id)\nend\nreturn load()";
    let r10 = "local cfg={id=script.Parent.FAKE_Module}\nlocal function load() return require(cfg.id) end\nlocal menuItem={}\nmenuItem.id=999000000005147\nlocal icon=\"rbxassetid://\"..menuItem.id\nreturn {module=load(),icon=icon}";
    let r11 = "local id=script.Parent.FAKE_Module\nlocal function load() return require(id) end\ndo\n local id=nil\n id=999000000005148\n print(\"FAKE image\",id)\nend\nreturn load()";
    for (label, result) in [
        ("T47", analysis(t47)),
        ("T48", analysis(t48)),
        ("R10", module_analysis(r10)),
        ("R11", module_analysis(r11)),
    ] {
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.severity < Severity::High),
            "{label}: {:#?}",
            describe(&result.findings)
        );
        never_names(label, &result, "99900000000514");
    }
    let t34 = "local id=999000000000000\nlocal function unrelated(id) return id+1 end\nprint(unrelated(4))\nrequire(id)";
    let result = trusted_analysis(t34);
    assert!(
        result.findings.is_empty(),
        "T34: {:#?}",
        describe(&result.findings)
    );
}

/// Ways the script changes `id` (round 4 item 4 capture changes).
fn name_changes() -> Vec<(&'static str, String)> {
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

/// Code around a change so that `id` in it is another variable than the captured one.
fn same_name_bindings() -> Vec<(&'static str, &'static str)> {
    vec![
        ("inner block", "do\nlocal id = 0\n{change}\nend"),
        (
            "parameter",
            "local function other(id)\n{change}\nend\nother(0)",
        ),
        ("numeric loop variable", "for id = 1, 1 do\n{change}\nend"),
        (
            "generic loop variable",
            "for _, id in {0} do\n{change}\nend",
        ),
        (
            "local of another function",
            "local function other()\nlocal id = 0\n{change}\nend\nother()",
        ),
        ("repeat body", "repeat\nlocal id = 0\n{change}\nuntil id"),
    ]
}

/// Ways the reader is called (round 4 item 4 calls).
fn reader_calls() -> Vec<(&'static str, &'static str)> {
    vec![
        ("plain call", "load()"),
        ("task.defer", "task.defer(load)"),
        ("pcall", "pcall(load)"),
        (
            "event",
            "game:GetService(\"Players\").PlayerAdded:Connect(load)",
        ),
        ("never called", ""),
    ]
}

/// Every round 5 capture change applied to an unrelated variable with the same name:
/// the captured variable keeps its one value.
#[test]
fn item1_unrelated_same_name_variables_never_reach_a_capture() {
    let mut count = 0;
    for (change, update) in name_changes() {
        for (binding, wrapper) in same_name_bindings() {
            let shadowed = wrapper.replace("{change}", &update);
            for (call, invoke) in reader_calls() {
                let label = format!("{change} / {binding} / {call}");
                let local = format!(
                    "local id = script.Parent.FAKE_Module\nlocal function load() require(id) return \"FAKE\" end\n{shadowed}\n{invoke}"
                );
                let result = module_analysis(&local);
                no_require_finding(&label, &result);
                never_names(&label, &result, X);
                let numeric = format!(
                    "local id = {TR}\nlocal function load() require(id) return \"FAKE\" end\n{shadowed}\n{invoke}"
                );
                let result = analysis(&numeric);
                resolves_to(&label, &result, TR);
                never_names(&label, &result, X);
                count += 1;
            }
        }
    }
    assert_eq!(count, 270);
}

/// Writes of the same key to another table: the round 4 item 4 field changes and the 29
/// round 4 item 2 write routes, all through `other` instead of `cfg`.
fn other_table_writes() -> Vec<(String, String)> {
    let mut routes: Vec<(String, String)> = vec![
        ("field", format!("other.id = {X}")),
        ("alias", format!("local a = other\na.id = {X}")),
        ("rawset", format!("rawset(other, \"id\", {X})")),
        ("computed key", format!("other[FAKE_k] = {X}")),
        ("in a loop", format!("for i = 1, 1 do other.id = {X} end")),
        (
            "through a parameter",
            format!("local function set(t) t.id = {X} end\nset(other)"),
        ),
        (
            "nested path",
            format!("local nested = {{inner = other}}\nnested.inner.id = {X}"),
        ),
        (
            "method",
            format!("function other:set() self.id = {X} end\nother:set()"),
        ),
        ("insert", format!("table.insert(other, {X})")),
    ]
    .into_iter()
    .map(|(label, route)| (label.to_string(), route))
    .collect();
    for (label, route) in [
        ("select", "select(1, other).id = {x}"),
        ("select second", "select(2, nil, other).id = {x}"),
        ("select from the end", "select(-1, other).id = {x}"),
        (
            "select unknown position",
            "select(FAKE_n, other, other).id = {x}",
        ),
        ("unpack", "table.unpack({other}).id = {x}"),
        (
            "unpack unknown range",
            "table.unpack({other}, FAKE_i).id = {x}",
        ),
        ("assert", "assert(other).id = {x}"),
        ("rawset result", "rawset(other, \"FAKE\", 1).id = {x}"),
        ("setmetatable result", "setmetatable(other, {}).id = {x}"),
        ("parentheses", "(other).id = {x}"),
        (
            "if-expression",
            "(if FAKE_c then other else other).id = {x}",
        ),
        (
            "select in a vararg function",
            "local function f(...) select(1, ...).id = {x} end\nf(other)",
        ),
        (
            "select second in a vararg function",
            "local function f(...) select(2, ...).id = {x} end\nf(nil, other)",
        ),
        (
            "pcall of an anonymous function",
            "local ok, o = pcall(function() return other end)\no.id = {x}",
        ),
        (
            "pcall of a named function",
            "local function get() return other end\nlocal ok, o = pcall(get)\no.id = {x}",
        ),
        (
            "xpcall",
            "local ok, o = xpcall(function() return other end, print)\no.id = {x}",
        ),
        (
            "coroutine.wrap",
            "local o = coroutine.wrap(function() return other end)()\no.id = {x}",
        ),
        (
            "coroutine.resume",
            "local ok, o = coroutine.resume(coroutine.create(function() return other end))\no.id = {x}",
        ),
        (
            "immediately invoked",
            "local o = (function() return other end)()\no.id = {x}",
        ),
        (
            "immediately invoked with varargs",
            "local o = (function(...) return ... end)(other)\no.id = {x}",
        ),
        (
            "__index function",
            "local o = setmetatable({}, {__index = function() return other end}).anything\no.id = {x}",
        ),
        (
            "table as a key",
            "local t = {}\nt[other] = true\nfor k in t do k.id = {x} end",
        ),
        (
            "weak key and rawset",
            "local w = setmetatable({}, {__mode = 'k'})\nw[other] = 1\nfor k in pairs(w) do rawset(k, 'id', {x}) end",
        ),
        (
            "table key in a constructor",
            "local t = {[other] = true}\nfor k in pairs(t) do k.id = {x} end",
        ),
        (
            "key from next",
            "local t = {}\nt[other] = 1\nlocal k = next(t)\nk.id = {x}",
        ),
        (
            "loop variable assigned after the write",
            "local o = nil\nfor i = 1, 2 do\nif o then o.id = {x} end\no = other\nend",
        ),
        (
            "loop field assigned after the write",
            "local box = {}\nfor i = 1, 2 do\nif box.o then box.o.id = {x} end\nbox.o = other\nend",
        ),
        (
            "error value",
            "local ok, o = pcall(function() error(other) end)\no.id = {x}",
        ),
        (
            "global read back",
            "FAKE_cfg = other\nlocal o = FAKE_get()\no.id = {x}",
        ),
    ] {
        routes.push((format!("route {label}"), route.replace("{x}", X)));
    }
    routes
}

/// Every route that writes `id` of another table leaves a captured `cfg.id`, and a
/// direct read of it, exactly as it was.
#[test]
fn item1_same_key_writes_to_other_tables_never_reach_a_captured_field() {
    let mut count = 0;
    for (route, write) in other_table_writes() {
        for (call, invoke) in [
            ("plain call", "load()"),
            ("task.defer", "task.defer(load)"),
            ("never called", ""),
            ("direct read", "require(cfg.id)"),
        ] {
            let label = format!("{route} / {call}");
            let local = format!(
                "local cfg = {{id = script.Parent.FAKE_Module}}\nlocal function load() require(cfg.id) return \"FAKE\" end\nlocal other = {{}}\n{write}\n{invoke}"
            );
            let result = module_analysis(&local);
            no_require_finding(&label, &result);
            never_names(&label, &result, X);
            let numeric = format!(
                "local cfg = {{id = {TR}}}\nlocal function load() require(cfg.id) return \"FAKE\" end\nlocal other = {{}}\n{write}\n{invoke}"
            );
            let result = analysis(&numeric);
            resolves_to(&label, &result, TR);
            never_names(&label, &result, X);
            count += 1;
        }
    }
    assert_eq!(count, 152);
}

/// Writes that may reach the captured table still count: through the table, an alias,
/// a parameter that receives it, a path that holds it, a method on it, or an unknown
/// function that gets it.
#[test]
fn item1_writes_that_reach_the_captured_table_still_count() {
    for write in [
        format!("cfg.id = {X}"),
        format!("local a = cfg\na.id = {X}"),
        format!("local a = cfg\nlocal b = a\nb.id = {X}"),
        format!("local function set(t) t.id = {X} end\nset(cfg)"),
        format!("local holder = {{inner = cfg}}\nholder.inner.id = {X}"),
        format!("function cfg:set() self.id = {X} end\ncfg:set()"),
        format!("select(1, cfg).id = {X}"),
        format!("local list = {{cfg}}\nlist[1].id = {X}"),
        format!("local function get() return cfg end\nget().id = {X}"),
        format!("cfg[FAKE_k] = {X}"),
        format!("rawset(cfg, \"id\", {X})"),
    ] {
        for invoke in ["load()", "task.defer(load)", ""] {
            let source = format!(
                "local cfg = {{id = script.Parent.FAKE_Module}}\nlocal function load() require(cfg.id) return \"FAKE\" end\n{write}\n{invoke}"
            );
            let label = format!("{write} / {invoke}");
            names_id(&label, &module_analysis(&source), "BG001", X);
            let source = format!(
                "local cfg = {{id = {TR}}}\nlocal function load() require(cfg.id) return \"FAKE\" end\n{write}\n{invoke}"
            );
            let result = trusted_analysis(&source);
            names_id(&label, &result, "BG001", X);
        }
    }
    // A table handed to code the scanner cannot see may be changed by any write.
    let source = format!(
        "local cfg = {{id = script.Parent.FAKE_Module}}\nlocal function load() require(cfg.id) return \"FAKE\" end\nFAKE_register(cfg)\nlocal o = FAKE_get()\no.id = {X}\nload()"
    );
    names_id("escaped", &module_analysis(&source), "BG001", X);
}

/// A table read as a value elsewhere may be reached by writes through paths and
/// parameters, but never by a write through another table's own local or its alias.
#[test]
fn item1_writes_through_another_tables_local_skip_a_passed_table() {
    for write in [
        format!("other.id = {X}"),
        format!("local alias = other\nalias.id = {X}"),
        format!("local alias = other\nlocal second = alias\nsecond.id = {X}"),
        format!("rawset(other, \"id\", {X})"),
        format!("other[FAKE_k] = {X}"),
        format!("for i = 1, 2 do other.id = {X} end"),
    ] {
        for invoke in ["load()", "task.defer(load)", ""] {
            let label = format!("{write} / {invoke}");
            let local = format!(
                "local cfg = {{id = script.Parent.FAKE_Module}}\nprint(cfg)\nlocal function load() require(cfg.id) return \"FAKE\" end\nlocal other = {{}}\nprint(other)\n{write}\n{invoke}"
            );
            let result = module_analysis(&local);
            no_require_finding(&label, &result);
            never_names(&label, &result, X);
            let numeric = format!(
                "local cfg = {{id = {TR}}}\nprint(cfg)\nlocal function load() require(cfg.id) return \"FAKE\" end\nlocal other = {{}}\nprint(other)\n{write}\n{invoke}"
            );
            let result = analysis(&numeric);
            resolves_to(&label, &result, TR);
            never_names(&label, &result, X);
        }
    }
    // The same table passed to a writer through a parameter is reached.
    let source = format!(
        "local cfg = {{id = script.Parent.FAKE_Module}}\nlocal function load() require(cfg.id) return \"FAKE\" end\nlocal function set(t) t.id = {X} end\nset(cfg)"
    );
    names_id("parameter", &module_analysis(&source), "BG001", X);
}

/// A replay reads the variable each name refers to in the source, not a variable of
/// the caller that has the same name (probes p13 and p14).
#[test]
fn item1_replays_read_the_variable_each_name_refers_to() {
    for source in [
        format!(
            "local id = script.Parent.FAKE_Module\nlocal function load() return require(id) end\nid = script.Parent.FAKE_Module\ndo\nlocal id = {X}\nprint(id)\nload()\nend"
        ),
        format!(
            "local id = script.Parent.FAKE_Module\nlocal function load() return require(id) end\nid = script.Parent.FAKE_Module\nlocal function caller(id)\nload()\nend\ncaller({X})"
        ),
        format!(
            "local function make()\nlocal mod = script.Parent.FAKE_Module\nlocal function get() return require(mod) end\nmod = script.Parent.FAKE_Module\nreturn get\nend\nlocal f = make()\nlocal mod = {X}\nprint(mod)\nf()"
        ),
        format!(
            "local id = script.Parent.FAKE_Module\nlocal function load() return require(id) end\nlocal function run(f)\nlocal id = {X}\nprint(id)\nf()\nend\nid = script.Parent.FAKE_Module\nrun(load)"
        ),
    ] {
        let result = module_analysis(&source);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.severity < Severity::High),
            "{source}\n{:#?}",
            describe(&result.findings)
        );
        never_names(&source, &result, X);
    }
    // The argument of a replayed call still reaches its parameter.
    let source = format!(
        "local function load(id) return require(id) end\ndo\nlocal id = {X}\nload(id)\nend"
    );
    names_id("parameter", &analysis(&source), "BG001", X);
}

/// A loop widens only variables that outlive an iteration (probe p04).
#[test]
fn item1_loops_widen_only_variables_that_outlive_an_iteration() {
    for body in [
        format!("local id = nil\nid = {X}\nprint(id)"),
        format!("local id = 0\nid += {X}"),
        format!("local id = {{}}\nid.FAKE = {X}"),
    ] {
        for header in [
            "for i = 1, 3 do",
            "while FAKE_c do",
            "for _, v in FAKE_list do",
        ] {
            let source = format!("local id = {TR}\n{header}\n{body}\nend\nrequire(id)");
            let result = analysis(&source);
            resolves_to(&source, &result, TR);
            never_names(&source, &result, X);
        }
    }
    // The loop that assigns the outer variable still widens it.
    let source = format!("local id = {TR}\nfor i = 1, 3 do\nid = {X}\nend\nrequire(id)");
    names_id("outer", &analysis(&source), "BG001", X);
}

/// Constant trust follows the declaration a name refers to (second review T34 and variants).
#[test]
fn item1_constant_trust_follows_the_declaration() {
    for other in [
        "local function unrelated(id) return id + 1 end\nprint(unrelated(4))",
        "local function unrelated(id) id = 5 return id end\nprint(unrelated(4))",
        "for id = 1, 2 do print(id) end",
        "for _, id in {1, 2} do print(id) end",
        "do\nlocal id = 5\nid = 6\nprint(id)\nend",
        "local function other()\nlocal id = 5\nid += 1\nreturn id\nend\nprint(other())",
        "do\nlocal function id() return 5 end\nprint(id())\nend",
        "getfenv().id = 5",
        "repeat local id = 5 until id",
    ] {
        let before = format!("local id = {TR}\n{other}\nrequire(id)");
        no_require_finding(other, &trusted_analysis(&before));
        // Without trust it is one exact ID, so trust removes a real finding.
        resolves_to(other, &analysis(&before), TR);
    }
    // A local that reads the outer one of the same name is still constant.
    let result = trusted_analysis(&format!("local id = {TR}\nlocal id = id\nrequire(id)"));
    assert!(
        result.findings.is_empty(),
        "{:#?}",
        describe(&result.findings)
    );
    // Assigning the variable itself still withholds trust.
    let result = trusted_analysis(&format!(
        "local id = {TR}\nlocal function set() id = {TR} end\nset()\nrequire(id)"
    ));
    expect("reassigned", &result, "BG001", Severity::High, None);
}

/// A gate name belongs to its variable: another variable with the same name is no gate
/// (probe p12), the variable itself still is.
#[test]
fn item1_gate_names_belong_to_their_variable() {
    let shadowed = format!(
        "local RS = game:GetService(\"RunService\")\nlocal function f()\nlocal studio = RS:IsStudio()\nreturn studio\nend\nprint(f())\nlocal studio = 1\nif studio then require({X}) end"
    );
    let result = analysis(&shadowed);
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.rule_id != "BG009"),
        "{:#?}",
        describe(&result.findings)
    );
    let gated = format!(
        "local RS = game:GetService(\"RunService\")\nlocal studio = RS:IsStudio()\nif not studio then require({X}) end"
    );
    expect("gate", &analysis(&gated), "BG009", Severity::Medium, None);
}

/// The `until` condition sees the locals of the repeat body, as in Luau.
#[test]
fn item1_until_reads_the_body_locals() {
    let source = format!("repeat\nlocal id = {X}\nuntil require(id)");
    resolves_to("until", &analysis(&source), X);
}

/// `local x = x` reads the outer `x`, also in a call inside the initializer, which the
/// analyzer visits after the new local exists.
#[test]
fn item1_a_local_initializer_reads_the_outer_variable() {
    let source = "local id = script.Parent.FAKE_Module\nlocal function pick(v) return v end\nlocal id = require(pick(id))";
    no_require_finding("initializer", &module_analysis(source));
    let source = format!("local id = {X}\nlocal id = require(id)");
    resolves_to("initializer", &analysis(&source), X);
}

// ----- item 2: the write pass reads every name it can and counts the rest as all ----

/// A model whose root holds the `FAKE_id` attribute and an `IntValue` named `FAKE_Id`,
/// both set to [`TR`], with one script per source under it.
fn value_model(sources: &[&str]) -> Document {
    let number: f64 = TR.parse().expect("number");
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
        input: "FAKE_round5.rbxmx".into(),
        instances,
        ..Document::default()
    }
}

/// Analysis of the last script of a [`value_model`].
fn value_model_analysis(sources: &[&str]) -> AnalysisResult {
    let document = value_model(sources);
    let id = document.instances.len() - 1;
    analyze(&document, id, &Limits::default(), &[])
}

const VALUE_READER: &str = "require(script.Parent.FAKE_Id.Value)";
const ATTRIBUTE_READER: &str = "require(script.Parent:GetAttribute(\"FAKE_id\"))";

/// The read is reported as BG002 but never as the one resolved stored value.
fn expect_unresolved_bg002(label: &str, result: &AnalysisResult) {
    expect(label, result, "BG002", Severity::Critical, None);
    assert!(
        result.findings.iter().all(|finding| {
            !finding.evidence.contains("resolved asset id")
                && finding.confidence != Confidence::High
        }),
        "{label}: {:#?}",
        describe(&result.findings)
    );
}

/// The read is the stored value, resolved at high confidence.
fn expect_resolved_bg002(label: &str, result: &AnalysisResult) {
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG002"
                && finding.confidence == Confidence::High
                && finding
                    .evidence
                    .contains(&format!("resolved asset id: {TR}"))),
        "{label}: {:#?}",
        describe(&result.findings)
    );
}

/// Writes whose names the pass reads (second review D01, D02, D09 and their siblings), each in
/// another script than the reader.
fn readable_writes() -> Vec<(&'static str, String, &'static str)> {
    let tween = "local T = game:GetService(\"TweenService\")\n";
    vec![
        (
            "D01 backtick property key",
            format!("script.Parent.FAKE_Id[`Value`] = {X}"),
            VALUE_READER,
        ),
        (
            "backtick key, compound",
            "script.Parent.FAKE_Id[`Value`] += 1".into(),
            VALUE_READER,
        ),
        (
            "backtick key in a tween table",
            format!(
                "{tween}T:Create(script.Parent.FAKE_Id, TweenInfo.new(0), {{[`Value`] = {X}}})"
            ),
            VALUE_READER,
        ),
        (
            "D02 backtick attribute name",
            format!("script.Parent:SetAttribute(`FAKE_id`, {X})"),
            ATTRIBUTE_READER,
        ),
        (
            "D09 dot Create",
            format!("{tween}T.Create(T, script.Parent.FAKE_Id, {{Value = {X}}})"),
            VALUE_READER,
        ),
        (
            "dot Create with tween info",
            format!("{tween}T.Create(T, script.Parent.FAKE_Id, TweenInfo.new(0), {{Value = {X}}})"),
            VALUE_READER,
        ),
        (
            "bracket Create",
            format!(
                "{tween}T[\"Create\"](T, script.Parent.FAKE_Id, TweenInfo.new(0), {{Value = {X}}})"
            ),
            VALUE_READER,
        ),
        (
            "backtick Create",
            format!(
                "{tween}T[`Create`](T, script.Parent.FAKE_Id, TweenInfo.new(0), {{Value = {X}}})"
            ),
            VALUE_READER,
        ),
    ]
}

/// Writes whose names the pass cannot read count as every name.
fn unreadable_writes() -> Vec<(&'static str, String, &'static str)> {
    let tween = "local T = game:GetService(\"TweenService\")\n";
    vec![
        (
            "property table in a variable",
            format!(
                "{tween}local goal = {{Value = {X}}}\nT:Create(script.Parent.FAKE_Id, TweenInfo.new(0), goal)"
            ),
            VALUE_READER,
        ),
        (
            "property table from a call",
            format!(
                "{tween}T:Create(script.Parent.FAKE_Id, TweenInfo.new(0), FAKE_merge({{}}, {{Value = {X}}}))"
            ),
            VALUE_READER,
        ),
        (
            "property table with a cast",
            format!("{tween}T:Create(script.Parent.FAKE_Id, TweenInfo.new(0), FAKE_goal :: any)"),
            VALUE_READER,
        ),
        (
            "dot Create with a variable",
            format!(
                "{tween}local goal = {{Value = {X}}}\nT.Create(T, script.Parent.FAKE_Id, TweenInfo.new(0), goal)"
            ),
            VALUE_READER,
        ),
        (
            "Create taken as a value",
            format!(
                "{tween}local create = T.Create\ncreate(T, script.Parent.FAKE_Id, TweenInfo.new(0), {{Value = {X}}})"
            ),
            VALUE_READER,
        ),
        (
            "Create taken with a string key",
            format!(
                "{tween}local create = T[\"Create\"]\ncreate(T, script.Parent.FAKE_Id, TweenInfo.new(0), {{Value = {X}}})"
            ),
            VALUE_READER,
        ),
        (
            "Create returned at the end",
            format!("{tween}return T.Create"),
            VALUE_READER,
        ),
        (
            "interpolated key with an expression",
            format!("script.Parent.FAKE_Id[`{{\"Val\"}}ue`] = {X}"),
            VALUE_READER,
        ),
        (
            "interpolated attribute name with an expression",
            format!("script.Parent:SetAttribute(`FAKE_{{\"id\"}}`, {X})"),
            ATTRIBUTE_READER,
        ),
        (
            "attribute name in parentheses",
            format!("script.Parent:SetAttribute((\"FAKE_id\"), {X})"),
            ATTRIBUTE_READER,
        ),
    ]
}

#[test]
fn item2_names_the_pass_reads_keep_reads_unresolved() {
    for (label, writer, reader) in readable_writes() {
        expect_unresolved_bg002(label, &value_model_analysis(&[&writer, reader]));
    }
}

#[test]
fn item2_names_the_pass_cannot_read_count_as_every_name() {
    for (label, writer, reader) in unreadable_writes() {
        expect_unresolved_bg002(label, &value_model_analysis(&[&writer, reader]));
    }
}

/// Writes of other names, definitions of a `Create` function and the text `Create`
/// leave the stored values resolved.
#[test]
fn item2_other_names_leave_reads_resolved() {
    let tween = "local T = game:GetService(\"TweenService\")\n";
    for writer in [
        "script.Parent.FAKE_Id[`Name`] = \"FAKE_Other\"".to_string(),
        "script.Parent:SetAttribute(`FAKE_other`, 1)".to_string(),
        format!("{tween}T:Create(script.Parent.FAKE_Id, TweenInfo.new(0), {{Size = 1}})"),
        format!("{tween}T.Create(T, script.Parent.FAKE_Id, TweenInfo.new(0), {{Size = 1}})"),
        "local M = {}\nfunction M.Create(a, b, c, d) return d end".to_string(),
        "local M = {}\nfunction M:Create(a, b, c) return c end".to_string(),
        "local M = {}\nM.Create = function(a, b, c, d) return d end".to_string(),
        "print(\"Create\", `Create`)".to_string(),
    ] {
        for reader in [VALUE_READER, ATTRIBUTE_READER] {
            expect_resolved_bg002(&writer, &value_model_analysis(&[&writer, reader]));
        }
    }
}

// ----- item 3: integer keys take the string key path ---------------------------------

/// Shapes that store an ID under the key `{k}` and read it back (second review T29, T32, T39,
/// T40, T41 and the same ideas around them).
fn keyed_shapes() -> Vec<(&'static str, &'static str)> {
    vec![
        ("own field", "local t = {[{k}] = {x}}\nrequire(t[{k}])"),
        (
            "__index table",
            "local base = {[{k}] = {x}}\nlocal proxy = setmetatable({}, {__index = base})\nrequire(proxy[{k}])",
        ),
        (
            "__index chain of three",
            "local a = {[{k}] = {x}}\nlocal b = setmetatable({}, {__index = a})\nlocal c = setmetatable({}, {__index = b})\nrequire(c[{k}])",
        ),
        (
            "__index table written later",
            "local base = {}\nlocal proxy = setmetatable({}, {__index = base})\nbase[{k}] = {x}\nrequire(proxy[{k}])",
        ),
        (
            "__index table set by rawset",
            "local base = {}\nlocal proxy = setmetatable({}, {__index = base})\nrawset(base, {k}, {x})\nrequire(proxy[{k}])",
        ),
        (
            "__index through getmetatable",
            "local proxy = setmetatable({}, {__index = {}})\ngetmetatable(proxy).__index = {[{k}] = {x}}\nrequire(proxy[{k}])",
        ),
        (
            "__index read in a function",
            "local base = {}\nlocal proxy = setmetatable({}, {__index = base})\nlocal function load() return require(proxy[{k}]) end\nbase[{k}] = {x}\nload()",
        ),
        (
            "__index chain past the cap",
            "local t0 = {[{k}] = {x}}\nlocal t1 = setmetatable({}, {__index = t0})\nlocal t2 = setmetatable({}, {__index = t1})\nlocal t3 = setmetatable({}, {__index = t2})\nlocal t4 = setmetatable({}, {__index = t3})\nlocal t5 = setmetatable({}, {__index = t4})\nlocal t6 = setmetatable({}, {__index = t5})\nlocal t7 = setmetatable({}, {__index = t6})\nlocal t8 = setmetatable({}, {__index = t7})\nrequire(t8[{k}])",
        ),
        ("_G", "_G[{k}] = {x}\nrequire(_G[{k}])"),
        ("shared", "shared[{k}] = {x}\nrequire(shared[{k}])"),
        ("getfenv", "getfenv()[{k}] = {x}\nrequire(getfenv()[{k}])"),
        ("rawget of _G", "_G[{k}] = {x}\nrequire(rawget(_G, {k}))"),
        (
            "_G read in a function",
            "local function load() return require(_G[{k}]) end\n_G[{k}] = {x}\nload()",
        ),
    ]
}

/// The BG001 findings of a result as severity and confidence, with the ID they name.
fn bg001_shape(result: &AnalysisResult) -> Vec<(Severity, Confidence, bool)> {
    let mut shape: Vec<(Severity, Confidence, bool)> = result
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "BG001")
        .map(|finding| {
            (
                finding.severity,
                finding.confidence,
                finding.evidence.contains(X),
            )
        })
        .collect();
    shape.sort_by_key(|(severity, confidence, names)| {
        (format!("{severity}"), format!("{confidence:?}"), *names)
    });
    shape.dedup();
    shape
}

#[test]
fn item3_integer_keys_get_the_string_key_result() {
    let mut count = 0;
    for (label, shape) in keyed_shapes() {
        let string = shape.replace("{k}", "\"FAKE_k\"").replace("{x}", X);
        let number = shape.replace("{k}", "2").replace("{x}", X);
        let string_result = analysis(&string);
        let number_result = analysis(&number);
        names_id(label, &number_result, "BG001", X);
        assert_eq!(
            bg001_shape(&number_result),
            bg001_shape(&string_result),
            "{label}\nstring: {:#?}\nnumber: {:#?}",
            describe(&string_result.findings),
            describe(&number_result.findings)
        );
        count += 1;
    }
    assert_eq!(count, 13);
}

/// Second review T39, T40 and T41 exactly: the integer key resolves to the stored ID.
#[test]
fn item3_second_review_integer_key_cases_resolve() {
    for (label, source, id) in [
        (
            "T39",
            "local base={[2]=999000000005139}\nlocal proxy=setmetatable({},{__index=base})\nrequire(proxy[2])",
            "999000000005139",
        ),
        (
            "T40",
            "_G[2]=999000000005140\nrequire(_G[2])",
            "999000000005140",
        ),
        (
            "T41",
            "getfenv()[2]=999000000005141\nrequire(getfenv()[2])",
            "999000000005141",
        ),
        (
            "T29",
            "local base=table.create(2,999000000005001)\nlocal proxy=setmetatable({},{__index=base})\nlocal src={999000000005129}\ntable.move(src,1,1,2,base)\nrequire(proxy[2])",
            "999000000005129",
        ),
    ] {
        resolves_to(label, &analysis(source), id);
    }
    // Past the chain cap the ID is a candidate next to an unknown value (second review T32).
    let t32 = "local t0=table.create(1,999000000005001)\nlocal t1=setmetatable({},{__index=t0})\nlocal t2=setmetatable({},{__index=t1})\nlocal t3=setmetatable({},{__index=t2})\nlocal t4=setmetatable({},{__index=t3})\nlocal t5=setmetatable({},{__index=t4})\nlocal t6=setmetatable({},{__index=t5})\nlocal t7=setmetatable({},{__index=t6})\nlocal t8=setmetatable({},{__index=t7})\nlocal src={999000000005132}\ntable.move(src,1,1,1,t0)\nrequire(t8[1])";
    let result = analysis(t32);
    names_id("T32", &result, "BG001", "999000000005132");
    assert!(
        result
            .findings
            .iter()
            .all(|finding| !finding.evidence.contains("resolved asset id")),
        "{:#?}",
        describe(&result.findings)
    );
}

/// An environment key that is not a name, and an unreadable one, stay apart from the
/// script's globals: a numeric key is no global, an unreadable key may be any.
#[test]
fn item3_environment_integer_keys_are_not_globals() {
    let numeric = format!(
        "FAKE_id = {TR}\ngetfenv()[2] = {X}\nlocal function load() return require(FAKE_id) end\nload()"
    );
    let result = analysis(&numeric);
    resolves_to("integer key", &result, TR);
    never_names("integer key", &result, X);
    // After a write under an unreadable key, a key or global the script never stored
    // may hold that value, whatever the key kind.
    for read in [
        "require(getfenv()[2])",
        "require(getfenv().FAKE_g)",
        "require(FAKE_g)",
    ] {
        let unreadable = format!("getfenv()[FAKE_k] = {X}\n{read}");
        names_id(read, &analysis(&unreadable), "BG001", X);
    }
    // A library function read through the environment stays itself.
    let library = format!("getfenv()[FAKE_k] = 5\ngetfenv().require({X})");
    names_id("library", &analysis(&library), "BG001", X);
}

/// README Known limits on buffers and `string.pack` (second review K51): not folded, low when no
/// whole ID is in sight, high with medium confidence when the `require` expression shows
/// one.
#[test]
fn docs_string_pack_round_trips_are_not_folded() {
    let roundtrip = "local function FAKE_roundtrip(value)\nlocal packed = string.pack(\"<d\", value)\nreturn string.unpack(\"<d\", packed)\nend\n";
    let visible = format!("{roundtrip}require(FAKE_roundtrip({X}))");
    let result = analysis(&visible);
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG001"
                && finding.severity == Severity::High
                && finding.confidence == Confidence::Medium
                && finding.evidence.contains(&format!("asset id literal: {X}"))),
        "{:#?}",
        describe(&result.findings)
    );
    let buffer = format!(
        "local b = buffer.create(8)\nbuffer.writef64(b, 0, {X})\nrequire(buffer.readf64(b, 0))"
    );
    let result = analysis(&buffer);
    expect("buffer", &result, "BG001", Severity::Low, None);
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.severity == Severity::Low),
        "{:#?}",
        describe(&result.findings)
    );
}

// ----- item 4: gate checks under folded keys ------------------------------------------

/// The ID the gated code loads.
const GATED: &str = "999000000006331";

/// Gates whose member name is a bracket key the scanner folds (second review D31 and siblings).
#[test]
fn item4_folded_gate_keys_report_bg009() {
    for gate in [
        format!("if game[\"Place\" .. \"Id\"] == {X} then require({GATED}) end"),
        format!("if game[\"PlaceId\"] == {X} then require({GATED}) end"),
        format!("if game[`PlaceId`] == {X} then require({GATED}) end"),
        format!("if game[(\"Place\") .. `Id`] == {X} then require({GATED}) end"),
        format!("if game[\"Creator\" .. \"Id\"] ~= 1 then return end\nrequire({GATED})"),
        format!("if game[\"Job\" .. \"Id\"] == \"\" then require({GATED}) end"),
        format!("local key = \"Place\" .. \"Id\"\nif game[key] == {X} then require({GATED}) end"),
        format!("local live = game[\"Place\" .. \"Id\"] == {X}\nif live then require({GATED}) end"),
        format!("if os[\"clock\"]() > 100 then require({GATED}) end"),
        format!("assert(game[\"Place\" .. \"Id\"] == {X})\nrequire({GATED})"),
        format!("local _ = game[\"Place\" .. \"Id\"] == {X} and require({GATED})"),
    ] {
        let result = analysis(&gate);
        expect(&gate, &result, "BG009", Severity::Medium, None);
        names_id(&gate, &result, "BG001", GATED);
    }
}

/// Bracket keys that are not gate members, or that the scanner cannot fold, are no
/// gate.
#[test]
fn item4_other_bracket_keys_are_no_gate() {
    for condition in [
        "FAKE_t[\"Name\"] == \"FAKE\"",
        "game[FAKE_key] == 1",
        "FAKE_t[\"Place\" .. \"Name\"] == 1",
        "FAKE_t[1] == 1",
        "os[\"getenv\"] == nil",
    ] {
        let source = format!("if {condition} then require({GATED}) end");
        let result = analysis(&source);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.rule_id != "BG009"),
            "{condition}: {:#?}",
            describe(&result.findings)
        );
    }
}

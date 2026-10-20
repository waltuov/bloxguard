//! Round 6 diff review regressions for the Luau analyzer: a function that runs later
//! reads a field through an `__index` chain, or through a `__newindex` proxy, and the
//! script writes that field afterwards. Every fixture is synthetic and defanged: asset
//! IDs are in 999000000000000 to 999999999999999 and every name starts with `FAKE`.

use bloxguard_core::analysis::{AnalysisResult, analyze};
use bloxguard_core::finding::{Finding, Severity};
use bloxguard_core::model::{Document, Instance, Limits};

/// The ID a later write stores.
const X: &str = "999000000006201";
/// The ID an unrelated write stores. It must never show up in a finding.
const Y: &str = "999000000006299";

/// A folder with a local `ModuleScript` named `FAKE_Module` and one script beside it,
/// so `script.Parent.FAKE_Module` is a module of the content.
fn module_document(source: &str) -> Document {
    Document {
        input: "FAKE_round6.rbxmx".into(),
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

fn analysis(source: &str) -> AnalysisResult {
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

/// A BG001 finding at high severity or above that names `id`.
fn names(label: &str, source: &str, id: &str) {
    let result = analysis(source);
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "BG001"
                && finding.severity >= Severity::High
                && finding.evidence.contains(id)),
        "{label}: expected BG001 naming {id}\nsource:\n{source}\nfindings: {:#?}",
        describe(&result.findings)
    );
}

/// No finding at high severity or above, and none names `id`.
fn quiet(label: &str, source: &str, id: &str) {
    let result = analysis(source);
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.severity < Severity::High && !finding.evidence.contains(id)),
        "{label}: expected no high finding and no {id}\nsource:\n{source}\nfindings: {:#?}",
        describe(&result.findings)
    );
}

/// The two keys each shape is checked with: the field `target` and the integer key 1,
/// as the text after a table name in a read and as a constructor field.
const KEYS: [(&str, &str, &str); 2] = [
    ("string key", ".target", "target = "),
    ("integer key", "[1]", ""),
];

// ----- the reviewer's shapes ---------------------------------------------------------

/// Blocker 1: a class default read in an event handler, written after the handler is
/// connected (Q02).
#[test]
fn class_default_read_in_an_event_handler_sees_a_later_write() {
    for (label, key, _) in KEYS {
        let source = format!(
            "local Base = {{}}\nBase.__index = Base\nBase{key} = script.Parent.FAKE_Module\nlocal obj = setmetatable({{}}, Base)\ngame:GetService(\"Players\").PlayerAdded:Connect(function()\n    require(obj{key})\nend)\nBase{key} = {X}"
        );
        names(label, &source, X);
    }
}

/// P11: the same read in a local function passed to `task.defer`.
#[test]
fn class_default_read_in_a_deferred_function_sees_a_later_write() {
    for (label, key, _) in KEYS {
        let source = format!(
            "local Base = {{}}\nBase.__index = Base\nBase{key} = script.Parent.FAKE_Module\nlocal obj = setmetatable({{}}, Base)\nlocal function go()\n    return require(obj{key})\nend\ntask.defer(go)\nBase{key} = {X}"
        );
        names(label, &source, X);
    }
}

/// P05: the read goes through `self` in a method that a delayed function calls.
#[test]
fn class_default_read_through_self_in_a_method_called_later_sees_a_later_write() {
    for (label, key, _) in KEYS {
        let source = format!(
            "local Loader = {{}}\nLoader.__index = Loader\nLoader{key} = script.Parent.FAKE_Module\nfunction Loader.new()\n    return setmetatable({{}}, Loader)\nend\nfunction Loader:run()\n    return require(self{key})\nend\nlocal l = Loader.new()\ntask.delay(5, function()\n    l:run()\nend)\nLoader{key} = {X}"
        );
        names(label, &source, X);
    }
}

/// P06 and P12: a proxy whose `__index` is a store, and the store is written later.
#[test]
fn proxy_read_through_index_sees_a_later_write_to_its_store() {
    for (label, key, field) in KEYS {
        for (call, invoke) in [
            (
                "event",
                "game:GetService(\"Players\").PlayerAdded:Connect(load)",
            ),
            ("task.defer", "task.defer(load)"),
        ] {
            let source = format!(
                "local store = {{ {field}script.Parent.FAKE_Module }}\nlocal proxy = setmetatable({{}}, {{ __index = store }})\nlocal function load()\n    return require(proxy{key})\nend\n{invoke}\nstore{key} = {X}"
            );
            names(&format!("{label} / {call}"), &source, X);
        }
    }
}

/// P07: a write to a proxy whose `__newindex` is the store that a later read uses.
#[test]
fn write_through_a_newindex_proxy_reaches_its_store() {
    for (label, key, field) in KEYS {
        let source = format!(
            "local store = {{ {field}script.Parent.FAKE_Module }}\nlocal proxy = {{}}\nsetmetatable(proxy, {{ __newindex = store }})\nlocal function load()\n    return require(store{key})\nend\ngame:GetService(\"Players\").PlayerAdded:Connect(load)\nproxy{key} = {X}"
        );
        names(label, &source, X);
    }
}

/// Every way the script sets a `__newindex` table: a constructor field under a name or
/// a bracket key, a field write, `rawset`, and a helper that sets the metatable of its
/// parameter.
#[test]
fn every_way_of_setting_a_newindex_table_redirects_writes() {
    let store = "local store = { target = script.Parent.FAKE_Module }";
    let read = "task.defer(function()\n    require(store.target)\nend)";
    for (label, setup) in [
        (
            "bracket key",
            "local proxy = {}\nsetmetatable(proxy, { [\"__newindex\"] = store })",
        ),
        (
            "field write",
            "local mt = {}\nmt.__newindex = store\nlocal proxy = {}\nsetmetatable(proxy, mt)",
        ),
        (
            "rawset",
            "local mt = {}\nrawset(mt, \"__newindex\", store)\nlocal proxy = {}\nsetmetatable(proxy, mt)",
        ),
        (
            "helper",
            "local function wrap(t)\n    return setmetatable(t, { __newindex = store })\nend\nlocal proxy = {}\nwrap(proxy)",
        ),
        (
            "metatable set by unknown code",
            "local proxy = {}\nFAKE_lib.wrap(proxy, { __newindex = store })",
        ),
    ] {
        let source = format!("{store}\n{setup}\n{read}\nproxy.target = {X}");
        names(label, &source, X);
    }
}

/// The reader is defined before the script sets the `__newindex` metatable, so nothing
/// has escaped yet when the reader is visited.
#[test]
fn a_newindex_set_after_the_reader_is_defined_still_redirects() {
    for (label, key, field) in KEYS {
        let source = format!(
            "local store = {{ {field}script.Parent.FAKE_Module }}\ntask.defer(function()\n    require(store{key})\nend)\nlocal mt = {{}}\nmt.__newindex = store\nlocal proxy = {{}}\nsetmetatable(proxy, mt)\nproxy{key} = {X}"
        );
        names(label, &source, X);
    }
}

/// A write to a table between the reader and the table that holds the key shadows it,
/// so it counts too.
#[test]
fn a_later_write_to_a_table_in_the_middle_of_the_chain_counts() {
    for (label, key, _) in KEYS {
        let source = format!(
            "local Root = {{}}\nRoot.__index = Root\nRoot{key} = script.Parent.FAKE_Module\nlocal Mid = {{}}\nsetmetatable(Mid, Root)\nMid.__index = Mid\nlocal obj = setmetatable({{}}, Mid)\ntask.defer(function()\n    require(obj{key})\nend)\nMid{key} = {X}"
        );
        names(label, &source, X);
    }
}

/// An object made inside the function that runs later still reads its class, which
/// the script writes afterwards.
#[test]
fn an_object_made_in_the_deferred_function_reads_a_later_class_write() {
    for (label, key, _) in KEYS {
        let source = format!(
            "local Base = {{}}\nBase.__index = Base\nBase{key} = script.Parent.FAKE_Module\ntask.defer(function()\n    local obj = setmetatable({{}}, Base)\n    require(obj{key})\nend)\nBase{key} = {X}"
        );
        names(label, &source, X);
    }
}

// ----- guards ------------------------------------------------------------------------

/// Q01: the function called right after the write already reads the new value.
#[test]
fn guard_a_call_after_the_write_reads_the_new_value() {
    for (label, key, _) in KEYS {
        let source = format!(
            "local Base = {{}}\nBase.__index = Base\nBase{key} = script.Parent.FAKE_Module\nlocal obj = setmetatable({{}}, Base)\nlocal function go()\n    return require(obj{key})\nend\nBase{key} = {X}\ngo()"
        );
        names(label, &source, X);
    }
}

/// Q04: a write of the same key to an unrelated table never reaches the chain.
#[test]
fn guard_a_write_to_an_unrelated_table_never_reaches_the_chain() {
    for (label, key, _) in KEYS {
        let source = format!(
            "local Base = {{}}\nBase.__index = Base\nBase{key} = script.Parent.FAKE_Module\nlocal obj = setmetatable({{}}, Base)\ntask.defer(function()\n    require(obj{key})\nend)\nlocal other = {{}}\nother{key} = {Y}\nprint(other)"
        );
        quiet(label, &source, Y);
    }
}

/// A `__newindex` function is called for a write, and only its own writes count: a
/// read-only table does not send other writes anywhere.
#[test]
fn guard_a_newindex_function_does_not_redirect_writes() {
    for (label, handler) in [
        (
            "inline function",
            "function()\n    error(\"FAKE read only\")\nend",
        ),
        ("local function", "FAKE_readOnly"),
    ] {
        let source = format!(
            "local store = {{ target = script.Parent.FAKE_Module }}\nlocal function FAKE_readOnly()\n    error(\"FAKE read only\")\nend\nlocal locked = setmetatable({{}}, {{ __newindex = {handler} }})\nlocal cfg = {{}}\ncfg.target = {Y}\nprint(cfg)\ntask.defer(function()\n    require(store.target)\nend)\nprint(store, locked)"
        );
        quiet(label, &source, Y);
    }
}

/// A `__newindex` table receives redirected writes; other tables do not.
#[test]
fn guard_redirected_writes_reach_only_the_newindex_table() {
    let source = format!(
        "local data = {{}}\nlocal proxy = setmetatable({{}}, {{ __index = data, __newindex = data }})\nlocal mods = {{ target = script.Parent.FAKE_Module }}\nprint(mods)\nlocal cfg = {{}}\ncfg.target = {Y}\nprint(cfg, proxy)\ntask.defer(function()\n    require(mods.target)\nend)"
    );
    quiet("unrelated reader", &source, Y);
}

// ----- generated: every deferred call form with every chain shape --------------------

/// A table shape a later read goes through.
struct Shape {
    name: &'static str,
    setup: String,
    /// The read in a function body, such as `obj.target`.
    read: String,
    /// The table a method `load` is defined on, and the value it is called on.
    owner: &'static str,
    receiver: &'static str,
    /// The read through `self` in that method.
    self_read: String,
    /// A later write that reaches the read.
    write: String,
    /// A later write of the same key to an unrelated table, with its setup.
    unrelated: String,
}

fn shapes() -> Vec<Shape> {
    let module = "script.Parent.FAKE_Module";
    vec![
        Shape {
            name: "class with __index = itself",
            setup: format!(
                "local Base = {{}}\nBase.__index = Base\nBase.target = {module}\nlocal obj = setmetatable({{}}, Base)"
            ),
            read: "obj.target".into(),
            owner: "Base",
            receiver: "obj",
            self_read: "self.target".into(),
            write: format!("Base.target = {X}"),
            unrelated: format!("local other = {{}}\nprint(other)\nother.target = {Y}"),
        },
        Shape {
            name: "proxy table",
            setup: format!(
                "local store = {{ target = {module} }}\nlocal obj = setmetatable({{}}, {{ __index = store }})"
            ),
            read: "obj.target".into(),
            owner: "store",
            receiver: "obj",
            self_read: "self.target".into(),
            write: format!("store.target = {X}"),
            unrelated: format!("local other = {{}}\nprint(other)\nother.target = {Y}"),
        },
        Shape {
            name: "two-level chain",
            setup: format!(
                "local Root = {{}}\nRoot.__index = Root\nRoot.target = {module}\nlocal Mid = {{}}\nsetmetatable(Mid, Root)\nMid.__index = Mid\nlocal obj = setmetatable({{}}, Mid)"
            ),
            read: "obj.target".into(),
            owner: "Root",
            receiver: "obj",
            self_read: "self.target".into(),
            write: format!("Root.target = {X}"),
            unrelated: format!("local other = {{}}\nprint(other)\nother.target = {Y}"),
        },
        Shape {
            name: "integer key",
            setup: format!(
                "local store = {{ {module} }}\nlocal obj = setmetatable({{}}, {{ __index = store }})"
            ),
            read: "obj[1]".into(),
            owner: "store",
            receiver: "obj",
            self_read: "self[1]".into(),
            write: format!("store[1] = {X}"),
            unrelated: format!("local other = {{}}\nprint(other)\nother[1] = {Y}"),
        },
        Shape {
            name: "__newindex proxy",
            setup: format!(
                "local store = {{ target = {module} }}\nlocal obj = {{}}\nsetmetatable(obj, {{ __newindex = store }})"
            ),
            read: "store.target".into(),
            owner: "store",
            receiver: "store",
            self_read: "self.target".into(),
            write: format!("obj.target = {X}"),
            // A table only indexed never gets a metatable, so its writes stay there.
            unrelated: format!("local other = {{}}\nother.target = {Y}"),
        },
    ]
}

/// Ways a function body runs after the rest of the script, around `{body}`.
const DEFERRED: [(&str, &str); 5] = [
    (
        "Connect",
        "game:GetService(\"Players\").PlayerAdded:Connect(function()\n    {body}\nend)",
    ),
    ("task.defer", "task.defer(function()\n    {body}\nend)"),
    (
        "task.spawn",
        "task.spawn(function()\n    task.wait(1)\n    {body}\nend)",
    ),
    ("task.delay", "task.delay(1, function()\n    {body}\nend)"),
    (
        "coroutine.wrap",
        "coroutine.wrap(function()\n    task.wait(1)\n    {body}\nend)()",
    ),
];

/// Each deferred form reads the field directly and through a method called later, on
/// each shape: a later write that reaches the field is a candidate, a write of the
/// same key to an unrelated table is not.
#[test]
fn generated_deferred_reads_through_chains_see_later_writes() {
    let mut count = 0;
    for shape in shapes() {
        for (form, wrapper) in DEFERRED {
            let method = format!(
                "function {}:load()\n    return require({})\nend",
                shape.owner, shape.self_read
            );
            for (body_label, body, extra) in [
                (
                    "direct read",
                    format!("require({})", shape.read),
                    String::new(),
                ),
                (
                    "method called later",
                    format!("{}:load()", shape.receiver),
                    method,
                ),
            ] {
                let deferred = wrapper.replace("{body}", &body);
                let label = format!("{} / {form} / {body_label}", shape.name);
                let reaching = format!("{}\n{extra}\n{deferred}\n{}", shape.setup, shape.write);
                names(&label, &reaching, X);
                let unrelated =
                    format!("{}\n{extra}\n{deferred}\n{}", shape.setup, shape.unrelated);
                quiet(&label, &unrelated, Y);
                count += 1;
            }
        }
    }
    assert_eq!(count, 50);
}

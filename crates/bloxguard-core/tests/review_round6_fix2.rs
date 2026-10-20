//! Round 6 review regressions, second fix. A write through a table's own local
//! reaches the tables a script stores under `__newindex` only when that table may get
//! such a metatable, so an unrelated table with the same keys stays separate. A source
//! tree walk that the time budget cuts short is partial, never an empty tree. Every
//! fixture is synthetic and defanged: asset IDs are in 999000000000000 to
//! 999999999999999 and every name starts with `FAKE`.

use bloxguard_core::analysis::{AnalysisResult, analyze};
use bloxguard_core::config::Config;
use bloxguard_core::engine::scan_documents;
use bloxguard_core::finding::{Finding, Severity};
use bloxguard_core::loading::{load_bytes, load_path};
use bloxguard_core::model::{Completeness, Document, Instance, Limits};

/// The ID a write that reaches the read stores.
const X: &str = "999000000006301";
/// The ID an unrelated write stores. It must never show up in a finding.
const Y: &str = "999000000006399";

/// A folder with a local `ModuleScript` named `FAKE_Module` and one script beside it,
/// so `script.Parent.FAKE_Module` is a module of the content.
fn module_document(source: &str) -> Document {
    Document {
        input: "FAKE_round6_fix2.rbxmx".into(),
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

/// `text` with the one occurrence of `old` replaced.
fn replace(text: &str, old: &str, new: &str) -> String {
    assert_eq!(text.matches(old).count(), 1, "expected one {old:?}");
    text.replacen(old, new, 1)
}

// ----- the reviewer's places (R07, R10 to R12) ------------------------------------------

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn node(class: &str, name: &str, children: &str, source: Option<&str>) -> String {
    let mut properties = format!("<string name=\"Name\">{}</string>", escape(name));
    if let Some(source) = source {
        properties.push_str(&format!(
            "<ProtectedString name=\"Source\">{}</ProtectedString>",
            escape(source)
        ));
    }
    format!("<Item class=\"{class}\"><Properties>{properties}</Properties>{children}</Item>")
}

/// The reviewer's place: two local ModuleScripts in ReplicatedStorage, image labels,
/// and a LocalScript with `bootstrap` as its source.
fn place(bootstrap: &str) -> String {
    let modules = node(
        "Folder",
        "FAKE_Modules",
        &(node(
            "ModuleScript",
            "FAKE_Inventory",
            "",
            Some("return {Start=function() print(\"FAKE Inventory\") end}"),
        ) + &node(
            "ModuleScript",
            "FAKE_Quests",
            "",
            Some("return {Start=function() print(\"FAKE Quests\") end}"),
        )),
        None,
    );
    let shared = node("ReplicatedStorage", "ReplicatedStorage", &modules, None);
    let icons = node(
        "Folder",
        "FAKE_Icons",
        &(node("ImageLabel", "FAKE_Inventory", "", None)
            + &node("ImageLabel", "FAKE_Quests", "", None)),
        None,
    );
    let scripts = node(
        "StarterPlayerScripts",
        "StarterPlayerScripts",
        &(icons + &node("LocalScript", "FAKE_Bootstrap", "", Some(bootstrap))),
        None,
    );
    let player = node("StarterPlayer", "StarterPlayer", &scripts, None);
    format!(
        "<roblox version=\"4\">{}</roblox>",
        node("DataModel", "FAKE_ProxyPlace", &(shared + &player), None)
    )
}

/// The reviewer's bootstrap scripts, built the way the review generator builds them.
fn bootstraps() -> Vec<(&'static str, String)> {
    let base = "--!strict\nlocal FAKE_ReplicatedStorage = game:GetService(\"ReplicatedStorage\")\nlocal FAKE_modules = {\n    Inventory = FAKE_ReplicatedStorage.FAKE_Modules.FAKE_Inventory,\n    Quests = FAKE_ReplicatedStorage.FAKE_Modules.FAKE_Quests,\n}\nlocal FAKE_registry = setmetatable({}, {\n    __index = FAKE_modules,\n    __newindex = FAKE_modules,\n})\nlocal FAKE_menuAssets = {}\nFAKE_menuAssets.Inventory = 999000000006901\nFAKE_menuAssets.Quests = 999000000006902\nlocal function FAKE_start()\n    local FAKE_inventory = require(FAKE_registry.Inventory)\n    local FAKE_quests = require(FAKE_registry.Quests)\n    FAKE_inventory.Start()\n    FAKE_quests.Start()\nend\nlocal FAKE_icons = script.Parent.FAKE_Icons\nFAKE_icons.FAKE_Inventory.Image = \"rbxassetid://\" .. tostring(FAKE_menuAssets.Inventory)\nFAKE_icons.FAKE_Quests.Image = \"rbxassetid://\" .. tostring(FAKE_menuAssets.Quests)\ntask.defer(FAKE_start)\n";
    let direct = base.replace("require(FAKE_registry.", "require(FAKE_modules.");
    let rendered = replace(
        &direct,
        "local FAKE_icons = script.Parent.FAKE_Icons",
        "local function FAKE_renderIcons(FAKE_assets)\nlocal FAKE_icons = script.Parent.FAKE_Icons",
    );
    let rendered = replace(
        &rendered,
        "tostring(FAKE_menuAssets.Inventory)",
        "tostring(FAKE_assets.Inventory)",
    );
    let rendered = replace(
        &rendered,
        "tostring(FAKE_menuAssets.Quests)",
        "tostring(FAKE_assets.Quests)",
    );
    let rendered = replace(
        &rendered,
        "task.defer(FAKE_start)",
        "end\nFAKE_renderIcons(FAKE_menuAssets)\ntask.defer(FAKE_start)",
    );
    let live = replace(
        &rendered,
        "local FAKE_modules = {\n    Inventory = FAKE_ReplicatedStorage.FAKE_Modules.FAKE_Inventory,\n    Quests = FAKE_ReplicatedStorage.FAKE_Modules.FAKE_Quests,\n}",
        "local FAKE_modules = {}",
    );
    let live = replace(
        &live,
        "local FAKE_menuAssets = {}",
        "FAKE_registry.Inventory = FAKE_ReplicatedStorage.FAKE_Modules.FAKE_Inventory\nFAKE_registry.Quests = FAKE_ReplicatedStorage.FAKE_Modules.FAKE_Quests\nlocal FAKE_menuAssets = {}",
    );
    let no_proxy = replace(
        &live,
        "local FAKE_registry = setmetatable({}, {\n    __index = FAKE_modules,\n    __newindex = FAKE_modules,\n})",
        "local FAKE_registry = FAKE_modules",
    );
    let mut other_keys = live.clone();
    for (old, new) in [
        (
            "FAKE_menuAssets.Inventory = 999000000006901",
            "FAKE_menuAssets.InventoryIcon = 999000000006901",
        ),
        (
            "FAKE_menuAssets.Quests = 999000000006902",
            "FAKE_menuAssets.QuestsIcon = 999000000006902",
        ),
        (
            "tostring(FAKE_assets.Inventory)",
            "tostring(FAKE_assets.InventoryIcon)",
        ),
        (
            "tostring(FAKE_assets.Quests)",
            "tostring(FAKE_assets.QuestsIcon)",
        ),
    ] {
        other_keys = replace(&other_keys, old, new);
    }
    vec![
        ("R07 image table passed to a helper", rendered),
        ("R10 active registry proxy", live),
        ("R11 registry alias control", no_proxy),
        ("R12 other image keys control", other_keys),
    ]
}

/// Review cases R07 and R10, with the R11 and R12 controls: the image IDs never enter the
/// module table, so no finding is high and none names them. Both modules are local,
/// and an unresolved `require` stays low.
#[test]
fn a_registry_proxy_does_not_take_the_writes_of_an_image_table() {
    for (label, bootstrap) in bootstraps() {
        let xml = place(&bootstrap);
        let document = load_bytes(
            "FAKE_ProxyPlace.rbxlx",
            "rbxlx",
            xml.as_bytes(),
            &Limits::default(),
        );
        assert_eq!(document.completeness, Completeness::Complete, "{label}");
        let report = scan_documents(vec![document], &Config::default());
        assert_eq!(report.completeness, Completeness::Complete, "{label}");
        assert!(
            report.findings.iter().all(|finding| {
                finding.severity < Severity::High
                    && !finding.evidence.contains("999000000006901")
                    && !finding.evidence.contains("999000000006902")
            }),
            "{label}: {:#?}",
            describe(&report.findings)
        );
        let modules = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "BG001")
            .count();
        assert!(modules <= 2, "{label}: {:#?}", describe(&report.findings));
    }
}

/// Review case K23 and its control K24: a table passed to `print` beside a proxy whose
/// `__newindex` is the store, and the same without the metatable.
#[test]
fn k23_an_unrelated_table_beside_a_fresh_proxy_stays_separate() {
    for (label, proxy) in [
        ("K23 proxy", "setmetatable({}, { __newindex = store })"),
        ("K24 control", "{}"),
    ] {
        let source = format!(
            "local store = {{ target = script.Parent.FAKE_Module }}\nlocal proxy = {proxy}\nlocal preferences = {{}}\npreferences.target = {Y}\nprint(preferences, proxy)\ntask.defer(function() require(store.target) end)"
        );
        quiet(label, &source, Y);
    }
}

// ----- writes that still reach the `__newindex` table ------------------------------------

/// The two keys each shape is checked with: the field `target` and the integer key 1,
/// as the text after a table name and as a constructor field.
const KEYS: [(&str, &str, &str); 2] = [
    ("string key", ".target", "target = "),
    ("integer key", "[1]", ""),
];

/// P07 and the ways the script can give a pinned local's table a `__newindex`
/// metatable: the write through that local, or through an alias of it, reaches the
/// store that a function run later reads.
#[test]
fn a_write_through_a_table_given_a_newindex_metatable_reaches_the_store() {
    for (key_label, key, field) in KEYS {
        for (label, setup, write) in [
            (
                "P07 inline metatable",
                "local proxy = {}\nsetmetatable(proxy, { __newindex = store })",
                "proxy",
            ),
            (
                "bracket key",
                "local proxy = {}\nsetmetatable(proxy, { [\"__newindex\"] = store })",
                "proxy",
            ),
            (
                "metatable through an alias",
                "local proxy = {}\nlocal FAKE_alias = proxy\nsetmetatable(FAKE_alias, { __newindex = store })",
                "proxy",
            ),
            (
                "write through an alias",
                "local proxy = {}\nsetmetatable(proxy, { __newindex = store })\nlocal FAKE_alias = proxy",
                "FAKE_alias",
            ),
            (
                "pinned local metatable",
                "local mt = { __newindex = store }\nlocal proxy = {}\nsetmetatable(proxy, mt)",
                "proxy",
            ),
            (
                "metatable field written later",
                "local mt = {}\nlocal proxy = {}\nsetmetatable(proxy, mt)\nmt.__newindex = store",
                "proxy",
            ),
            (
                "fresh proxy from a local metatable",
                "local mt = {}\nmt.__newindex = store\nlocal proxy = setmetatable({}, mt)",
                "proxy",
            ),
            (
                "one metatable for two tables",
                "local mt = { __newindex = store }\nlocal FAKE_first = {}\nsetmetatable(FAKE_first, mt)\nlocal proxy = {}\nsetmetatable(proxy, mt)",
                "proxy",
            ),
            (
                "chain of two __newindex tables",
                "local FAKE_middle = {}\nsetmetatable(FAKE_middle, { __newindex = store })\nlocal proxy = {}\nsetmetatable(proxy, { __newindex = FAKE_middle })",
                "proxy",
            ),
        ] {
            let source = format!(
                "local store = {{ {field}script.Parent.FAKE_Module }}\n{setup}\ntask.defer(function()\n    require(store{key})\nend)\n{write}{key} = {X}"
            );
            names(&format!("{label} / {key_label}"), &source, X);
        }
    }
}

/// Where the scan cannot tell which tables get a `__newindex` metatable, every table
/// passed as a value may: a `setmetatable` on a parameter or a call result, a
/// metatable handed to other code, `setmetatable` reached another way, `getmetatable`,
/// and `rawset` on the metatable.
#[test]
fn fail_closed_every_passed_table_may_get_a_metatable_the_scan_cannot_place() {
    let store = "local store = { target = script.Parent.FAKE_Module }";
    let read = "task.defer(function()\n    require(store.target)\nend)";
    for (label, setup) in [
        (
            "helper sets the metatable of its parameter",
            "local function wrap(t)\n    return setmetatable(t, { __newindex = store })\nend\nlocal proxy = {}\nwrap(proxy)",
        ),
        (
            "metatable on a call result",
            "local proxy = {}\nFAKE_lib.keep(proxy)\nsetmetatable(FAKE_lib.get(), { __newindex = store })",
        ),
        (
            "metatable set by unknown code",
            "local proxy = {}\nFAKE_lib.wrap(proxy, { __newindex = store })",
        ),
        (
            "local metatable handed to unknown code",
            "local mt = { __newindex = store }\nlocal proxy = {}\nFAKE_lib.apply(proxy, mt)",
        ),
        (
            "setmetatable through _G",
            "local proxy = {}\n_G.setmetatable(proxy, { __newindex = store })",
        ),
        (
            "setmetatable taken as a value",
            "local FAKE_set = setmetatable\nlocal proxy = {}\nFAKE_set(proxy, { __newindex = store })",
        ),
        (
            "local named setmetatable",
            "local setmetatable = FAKE_lib.set\nlocal proxy = {}\nFAKE_lib.keep(proxy)\nlocal FAKE_other = {}\nsetmetatable(FAKE_other, { __newindex = store })",
        ),
        (
            "global setmetatable replaced",
            "setmetatable = FAKE_lib.set\nlocal proxy = {}\nFAKE_lib.keep(proxy)\nlocal FAKE_other = {}\nsetmetatable(FAKE_other, { __newindex = store })",
        ),
        (
            "metatable copied with getmetatable",
            "local FAKE_first = setmetatable({}, { __newindex = store })\nlocal proxy = {}\nFAKE_lib.copy(proxy, getmetatable(FAKE_first))",
        ),
        (
            "rawset on the metatable",
            "local mt = {}\nrawset(mt, \"__newindex\", store)\nlocal proxy = {}\nsetmetatable(proxy, mt)",
        ),
        (
            "__newindex set through getmetatable",
            "local proxy = {}\nsetmetatable(proxy, {})\ngetmetatable(proxy).__newindex = store",
        ),
    ] {
        let source = format!("{store}\n{setup}\n{read}\nproxy.target = {X}");
        names(label, &source, X);
    }
}

// ----- generated: an unrelated same-key table with each `__newindex` setup -------------

/// Ways the script sets a `__newindex` table where the scan can pin down the table
/// that gets the metatable, and the table a write through `proxy` goes to.
const SETUPS: [(&str, &str); 8] = [
    (
        "fresh inline proxy",
        "local proxy = setmetatable({}, { __newindex = store })",
    ),
    (
        "fresh proxy that also reads the store",
        "local proxy = setmetatable({}, { __index = store, __newindex = store })",
    ),
    (
        "fresh proxy from a local metatable",
        "local mt = { __newindex = store }\nlocal proxy = setmetatable({}, mt)",
    ),
    (
        "fresh proxy, metatable field written",
        "local mt = {}\nmt.__newindex = store\nlocal proxy = setmetatable({}, mt)",
    ),
    (
        "pinned proxy, inline metatable",
        "local proxy = {}\nsetmetatable(proxy, { __newindex = store })",
    ),
    (
        "pinned proxy, bracket key",
        "local proxy = {}\nsetmetatable(proxy, { [\"__newindex\"] = store })",
    ),
    (
        "pinned proxy, local metatable",
        "local mt = { __newindex = store }\nlocal proxy = {}\nsetmetatable(proxy, mt)",
    ),
    (
        "pinned proxy through an alias",
        "local proxy = {}\nlocal FAKE_alias = proxy\nsetmetatable(FAKE_alias, { __newindex = store })",
    ),
];

/// Ways an unrelated table `FAKE_assets` is used as a value, which make it a table
/// that is not contained, around its write `{write}`. A metatable without
/// `__newindex` sends no write anywhere.
const UNRELATED: [(&str, &str); 5] = [
    (
        "passed to a local helper",
        "local FAKE_assets = {}\n{write}\nlocal function FAKE_render(FAKE_t)\n    print(FAKE_t)\nend\nFAKE_render(FAKE_assets)",
    ),
    (
        "stored in a local table",
        "local FAKE_assets = {}\n{write}\nlocal FAKE_all = { assets = FAKE_assets }\nprint(FAKE_all.assets)",
    ),
    (
        "returned from a local function",
        "local FAKE_assets = {}\n{write}\nlocal function FAKE_get()\n    return FAKE_assets\nend\nprint(FAKE_get())",
    ),
    (
        "passed to print",
        "local FAKE_assets = {}\n{write}\nprint(FAKE_assets)",
    ),
    (
        "given a metatable without __newindex",
        "local FAKE_assets = {}\n{write}\nsetmetatable(FAKE_assets, { __index = { FAKE_default = 1 } })",
    ),
];

/// Every setup with every unrelated table and both keys: the same-key write to the
/// unrelated table never reaches the store, and a write through the proxy does.
#[test]
fn generated_an_unrelated_same_key_table_stays_separate_from_a_newindex_store() {
    let mut count = 0;
    for (setup_label, setup) in SETUPS {
        for (key_label, key, field) in KEYS {
            let store = format!("local store = {{ {field}script.Parent.FAKE_Module }}");
            let read = format!("task.defer(function()\n    require(store{key})\nend)");
            let reaching = format!("{store}\n{setup}\n{read}\nproxy{key} = {X}");
            names(
                &format!("{setup_label} / {key_label} / proxy write"),
                &reaching,
                X,
            );
            for (use_label, unrelated) in UNRELATED {
                let unrelated = unrelated.replace("{write}", &format!("FAKE_assets{key} = {Y}"));
                // The proxy is used, so it is not only a dead declaration.
                let source = format!("{store}\n{setup}\nprint(proxy)\n{unrelated}\n{read}");
                quiet(
                    &format!("{setup_label} / {key_label} / {use_label}"),
                    &source,
                    Y,
                );
                count += 1;
            }
        }
    }
    assert_eq!(count, 80);
}

// ----- a source tree walk cut short by the time budget -----------------------------------

fn temp_tree(label: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("bloxguard_FAKE_{label}_"))
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory")
}

const EMPTY_TREE: &str = "source tree contains no supported scripts or Roblox model/place files";

fn limits_ms(max_file_ms: u64) -> Limits {
    Limits {
        max_file_ms,
        ..Limits::default()
    }
}

/// The walk stopped by the budget is partial with the time reason, and never says
/// the tree has no supported files.
fn assert_cut_short(document: &Document, budget: &str, label: &str) {
    assert_eq!(
        document.completeness,
        Completeness::Partial,
        "{label}: {:?}",
        document.reasons
    );
    assert!(
        document.reasons.iter().any(|reason| reason == budget),
        "{label}: {:?}",
        document.reasons
    );
    assert!(
        document.reasons.iter().all(|reason| reason != EMPTY_TREE),
        "{label}: {:?}",
        document.reasons
    );
}

/// Review case H30: 2,500 harmless scripts with a 1 ms budget, loaded and then scanned.
#[test]
fn h30_a_tree_walk_cut_short_by_a_tiny_budget_is_partial_not_empty() {
    let tree = temp_tree("h30");
    for index in 0..2_500 {
        std::fs::write(
            tree.path().join(format!("FAKE_s{index:04}.server.luau")),
            format!("print(\"FAKE {index}\")\n"),
        )
        .unwrap();
    }
    let document = load_path(tree.path(), &limits_ms(1)).pop().unwrap();
    assert_cut_short(&document, "time budget of 1 ms exceeded", "load");
    let mut config = Config::default();
    config.limits.max_file_ms = 1;
    let report = scan_documents(vec![document], &config);
    assert_eq!(report.completeness, Completeness::Partial);
    assert!(
        report.inputs[0]
            .reasons
            .iter()
            .all(|reason| reason != EMPTY_TREE),
        "{:?}",
        report.inputs[0].reasons
    );
}

/// A budget used up before the walk reads the first entry: nothing was loaded, and
/// the tree still holds a supported script.
#[test]
fn a_tree_walk_stopped_before_the_first_entry_is_partial_not_empty() {
    let tree = temp_tree("stopped");
    std::fs::write(tree.path().join("FAKE_s.server.luau"), "return 1").unwrap();
    let document = load_path(tree.path(), &limits_ms(0)).pop().unwrap();
    assert_cut_short(&document, "time budget of 0 ms exceeded", "zero budget");
    assert!(document.instances.is_empty(), "{:?}", document.instances);
}

/// A tree that really holds no supported file still fails, also when it has other
/// files.
#[test]
fn guard_a_really_empty_tree_still_fails() {
    for (label, files) in [
        ("empty", &[][..]),
        (
            "only other files",
            &[("FAKE_notes.txt", "FAKE"), ("FAKE_data.csv", "1,2")][..],
        ),
    ] {
        let tree = temp_tree("empty");
        for (name, text) in files {
            std::fs::write(tree.path().join(name), text).unwrap();
        }
        let document = load_path(tree.path(), &Limits::default()).pop().unwrap();
        assert_eq!(
            document.completeness,
            Completeness::Failed,
            "{label}: {:?}",
            document.reasons
        );
        assert!(
            document.reasons.iter().any(|reason| reason == EMPTY_TREE),
            "{label}: {:?}",
            document.reasons
        );
        let report = scan_documents(vec![document], &Config::default());
        assert_eq!(report.completeness, Completeness::Failed, "{label}");
    }
}

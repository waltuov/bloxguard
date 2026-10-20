//! luau-lsp type declaration files over the parser safety caps, such as the Roblox
//! definitions file luau-lsp generates, which has thousands of method signatures. Every
//! fixture is synthetic: names that are not Luau or Roblox names start with `FAKE`, and
//! asset IDs are in 999000000000000 to 999999999999999.

use bloxguard_core::analysis::{analyze, parser_budget};
use bloxguard_core::config::Config;
use bloxguard_core::engine::scan_documents;
use bloxguard_core::loading::{load_path, load_source};
use bloxguard_core::model::{Completeness, Document, Instance, Limits};
use bloxguard_core::parsing::first_declaration;
use bloxguard_core::report::ScanReport;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

const NOTE: &str = "type declaration file, not run by Roblox, not scanned";
const ID: &str = "999000000019101";

fn scan_loose(source: &str) -> ScanReport {
    scan_documents(
        vec![load_source(
            source,
            "FAKE_globalTypes.d.luau",
            "ModuleScript",
            &Limits::default(),
        )],
        &Config::default(),
    )
}

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("parent")).expect("create folder");
    fs::write(path, text).expect("write fixture");
}

/// A definitions file shaped like luau-lsp's Roblox types: type aliases, then
/// `classes` classes in both declaration syntaxes with `methods` method signatures
/// each, `functions` global functions, and global values. A signature has no `end`,
/// so the parser safety check counts each one as an open block.
fn definitions(classes: usize, methods: usize, functions: usize) -> String {
    let mut out = String::from(
        "--!nocheck\n-- FAKE definitions\ntype FAKE_Content = string\ntype FAKE_Map<T> = { [string]: T }\n\n",
    );
    for class in 0..classes {
        if class % 2 == 0 {
            writeln!(out, "declare extern type FAKE_Class{class} with").unwrap();
        } else {
            writeln!(out, "declare class FAKE_Class{class}").unwrap();
        }
        writeln!(out, "\tFAKE_Name: string").unwrap();
        for method in 0..methods {
            writeln!(
                out,
                "\tfunction FAKE_Method{method}(self, value: number, callback: (string) -> ()): FAKE_Map<number>"
            )
            .unwrap();
        }
        out.push_str("end\n\n");
    }
    for function in 0..functions {
        writeln!(
            out,
            "declare function FAKE_global{function}(value: any): ()"
        )
        .unwrap();
    }
    out.push_str("declare FAKE_game: FAKE_Class0\ndeclare FAKE_shared: { [any]: any }\n");
    out
}

fn assert_note_only(label: &str, report: &ScanReport) {
    let input = &report.inputs[0];
    assert_eq!(
        report.completeness,
        Completeness::Complete,
        "{label}: {:?}",
        input.reasons
    );
    assert!(report.findings.is_empty(), "{label}: {:?}", report.findings);
    assert!(input.reasons.is_empty(), "{label}: {:?}", input.reasons);
    let notes: Vec<&str> = input
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect();
    assert_eq!(notes, [NOTE], "{label}");
}

/// Partial from both the analysis and the heuristic rules, with no note.
fn assert_unsafe(label: &str, report: &ScanReport) {
    let input = &report.inputs[0];
    assert_eq!(report.completeness, Completeness::Partial, "{label}");
    assert!(
        input
            .reasons
            .iter()
            .any(|reason| reason.starts_with("cannot safely parse")
                && reason.contains("safety cap")
                && !reason.contains("for heuristic rules")),
        "{label}: {:?}",
        input.reasons
    );
    assert!(
        input
            .reasons
            .iter()
            .any(|reason| reason.starts_with("cannot safely parse")
                && reason.contains("for heuristic rules")),
        "{label}: {:?}",
        input.reasons
    );
    assert!(
        input.diagnostics.is_empty(),
        "{label}: {:?}",
        input.diagnostics
    );
}

/// A definitions file with 5,000 method signatures and 1,100 global functions is over
/// the cap of 1,024 nested blocks, but only the type aliases before its first
/// declaration are parsed, so it gets the note like a short one. Partial on `e559083`.
#[test]
fn a_long_definitions_file_is_complete_with_the_note() {
    for (label, source) in [
        ("classes", definitions(50, 100, 1_100)),
        ("global functions only", definitions(0, 0, 2_000)),
        ("one large class", definitions(1, 3_000, 0)),
        (
            "CRLF and a byte order mark",
            format!(
                "\u{feff}{}",
                definitions(50, 100, 1_100).replace('\n', "\r\n")
            ),
        ),
    ] {
        assert!(
            parser_budget(&source, &Limits::default()).is_err(),
            "{label}: the fixture must be over a safety cap"
        );
        assert_note_only(label, &scan_loose(&source));
    }

    // In a Rojo folder next to ordinary code, where luau-lsp users keep it.
    let root = tempfile::Builder::new()
        .prefix("bloxguard_FAKE_declarations_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory");
    write(
        root.path(),
        "types/FAKE_globalTypes.None.d.luau",
        &definitions(50, 100, 18),
    );
    write(root.path(), "src/init.luau", "return {}\n");
    let report = scan_documents(
        load_path(root.path(), &Limits::default()),
        &Config::default(),
    );
    assert_note_only("tree", &report);
}

/// Deep code before the first declaration is parsed, so every cap still applies to it.
/// Passes on `e559083` too; it guards that only declarations are let through.
#[test]
fn deep_code_before_the_first_declaration_stays_partial() {
    let declarations = definitions(2, 600, 0);
    for (label, code) in [
        (
            "blocks",
            format!("{}{}\n", "do ".repeat(1_100), "end ".repeat(1_100)),
        ),
        (
            "brackets",
            format!(
                "local FAKE_x = {}1{}\n",
                "(".repeat(1_100),
                ")".repeat(1_100)
            ),
        ),
        (
            "operators",
            format!("local FAKE_y = 1{}\n", " + 1".repeat(1_100)),
        ),
    ] {
        assert_unsafe(label, &scan_loose(&format!("{code}{declarations}")));
    }
}

/// Valid Luau that only looks like a declaration file: `1 +` takes `declare` as an
/// operand, so Luau runs the function statement, the long expression and the `require`.
/// The code before the `declare` does not parse on its own, so this stays partial.
/// A `declare` that begins no declaration lets nothing through either. Passes on
/// `e559083` too; it guards the evasion the declaration exception must not open.
#[test]
fn over_the_cap_look_alikes_stay_partial() {
    let operand = format!(
        "local declare = 0\nlocal FAKE_n = 1 +\ndeclare function FAKE_describe(phrase) end\nlocal FAKE_big = 1{}\nrequire({ID})\n",
        " + 1".repeat(1_100)
    );
    assert_unsafe("declare as an operand", &scan_loose(&operand));
    let not_a_declaration = format!(
        "declare FAKE_x\n{}{}\nrequire({ID})\n",
        "do ".repeat(1_100),
        "end ".repeat(1_100)
    );
    assert_unsafe("declare without a type", &scan_loose(&not_a_declaration));
}

/// A file that does not tokenize takes the same route as one over a cap: a character
/// Luau does not know after the declarations gives the note, and one before them keeps
/// the file partial. Partial on `e559083` for the first shape; the second guards it.
#[test]
fn a_file_that_does_not_tokenize_follows_the_same_rule() {
    let after = format!("{}local FAKE_x = $\nrequire({ID})\n", definitions(1, 3, 2));
    assert!(parser_budget(&after, &Limits::default()).is_err());
    assert_note_only("after the declarations", &scan_loose(&after));

    let before = format!("local FAKE_x = $\n{}", definitions(1, 3, 2));
    let report = scan_loose(&before);
    let input = &report.inputs[0];
    assert_eq!(report.completeness, Completeness::Partial);
    for heuristic in [false, true] {
        assert!(
            input
                .reasons
                .iter()
                .any(|reason| reason.contains("tokenization failed")
                    && reason.contains("for heuristic rules") == heuristic),
            "{:?}",
            input.reasons
        );
    }
    assert!(input.diagnostics.is_empty(), "{:?}", input.diagnostics);
}

/// The size limit still covers the whole file when a caller hands the analysis a
/// source the loaders would have cut. Passes on `e559083` too; it guards the size check.
#[test]
fn a_declaration_file_over_max_script_bytes_stays_partial() {
    let source = definitions(4, 400, 0);
    let limits = Limits {
        max_script_bytes: source.len() - 1,
        ..Limits::default()
    };
    let document = Document {
        input: "FAKE_api".into(),
        instances: vec![Instance {
            name: "FAKE_globalTypes".into(),
            class: "ModuleScript".into(),
            source: Some(source),
            ..Instance::default()
        }],
        ..Document::default()
    };
    let result = analyze(&document, 0, &limits, &[]);
    assert!(result.notes.is_empty(), "{:?}", result.notes);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("exceeds max_script_bytes")),
        "{:?}",
        result.reasons
    );
}

/// Code after the declarations is never parsed, so nesting far deeper than the parser
/// stack allows neither crashes the scan nor runs unbounded. Luau rejects the file at
/// its first declaration, so the `require` after it never runs. Partial on `e559083`.
#[test]
fn deep_code_after_the_declarations_is_never_parsed() {
    let source = format!(
        "{}do\n{}local FAKE_x = {}1{}\n{}end\nrequire({ID})\n",
        definitions(1, 3, 2),
        "do ".repeat(100_000),
        "(".repeat(100_000),
        ")".repeat(100_000),
        "end ".repeat(100_000)
    );
    assert!(parser_budget(&source, &Limits::default()).is_err());
    assert_note_only("deep after", &scan_loose(&source));
}

/// Where the declaration exception starts: a `declare` that starts a line and begins a
/// declaration. A `declare` in a string or a comment, after code on its line, or
/// followed by anything else does not count. The new function has no older behavior.
#[test]
fn the_first_declaration_starts_a_line_and_begins_a_declaration() {
    for (source, expected) in [
        ("declare function FAKE_f(): ()\n", Some(0)),
        ("local FAKE_x = 1\n  declare FAKE_y: number\n", Some(19)),
        ("-- note\ndeclare class FAKE_C\nend\n", Some(8)),
        ("declare extern type FAKE_C with\nend\n", Some(0)),
        ("declare\ndeclare function FAKE_f(): ()\n", Some(8)),
        ("local FAKE_x = 1; declare function FAKE_f(): ()\n", None),
        (
            "local FAKE_s = [[\ndeclare function FAKE_f(): ()\n]]\n",
            None,
        ),
        ("--[[\ndeclare function FAKE_f(): ()\n]]\n", None),
        ("declare(999000000019101)\n", None),
        ("declare:FAKE_m()\n", None),
        ("declare FAKE_x\n", None),
        ("declare extern FAKE_x\n", None),
        ("declare class\n", None),
    ] {
        assert_eq!(first_declaration(source), expected, "{source:?}");
    }
}

use bloxguard_core::{
    config::{Baseline, Config},
    finding::Severity,
    model::Completeness,
    output, rules,
};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use std::{
    ffi::{OsStr, OsString},
    io::IsTerminal,
    path::{Path, PathBuf},
    process::ExitCode,
};
mod mcp;

#[derive(Parser)]
#[command(
    name = "bloxguard",
    version,
    about = "Offline security scanner for Roblox files and Luau. Never executes scanned code."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Scan files or source trees for security review findings.
    Scan(ScanArgs),
    /// List every script and its source hash.
    Inventory {
        path: PathBuf,
        #[arg(long, value_enum, default_value = "human")]
        format: Format,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        allow_incomplete: bool,
    },
    /// List the built-in rules.
    Rules {
        #[arg(long, value_enum, default_value = "human")]
        format: Format,
    },
    /// Explain a rule and its false positive considerations.
    Explain {
        id: String,
        #[arg(long, value_enum, default_value = "human")]
        format: Format,
    },
    /// Create a baseline of reviewed finding fingerprints.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    /// Serve read-only tools over stdio. Without roots, only in-memory scans work.
    Mcp {
        #[arg(long)]
        root: Vec<PathBuf>,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
    Sarif,
}
#[derive(clap::Args)]
struct ScanArgs {
    /// Roblox files (.rbxl, .rbxlx, .rbxm, .rbxmx), Luau files or source folders to scan.
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// Report format.
    #[arg(long, value_enum, default_value = "human")]
    format: Format,
    /// Write the report to this file instead of standard output.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Lowest severity that returns exit code 1: low, medium, high or critical. Default: fail_on in the configuration, else high.
    #[arg(long, value_name = "SEVERITY")]
    fail_on: Option<Severity>,
    /// Configuration file. Without it, bloxguard.toml in the working directory is used when present.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Baseline JSON file whose findings are hidden. Overrides baseline in the configuration.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Let an incomplete scan return the findings exit code (0 or 1) instead of 2.
    #[arg(long)]
    allow_incomplete: bool,
    /// Evaluate suppression expiry on this UTC date for reproducible reviews.
    #[arg(long, value_name = "YYYY-MM-DD")]
    as_of: Option<String>,
}
#[derive(Subcommand)]
enum BaselineCommand {
    Create {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(long, default_value = "bloxguard-baseline.json")]
        output: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}
/// Shown when the program starts without arguments in a window of its own.
const INTRO: &str = "bloxguard checks Roblox games for backdoors. To check a game, drag a .rbxl, .rbxlx, .rbxm or .rbxmx file, or a project folder, onto bloxguard.exe.";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let launch = launch_kind(&args, Path::exists);
    let window = keeps_window_open(launch, alone_on_console(), std::io::stdin().is_terminal());
    let code = match launch {
        Launch::Empty if window => {
            println!("{INTRO}");
            0
        }
        Launch::Drop => drop_scan(&args),
        Launch::Empty | Launch::Command => match Cli::try_parse_from(&args) {
            Ok(cli) => match run(cli).await {
                Ok(code) => code,
                Err(error) => {
                    eprintln!("bloxguard: {error}");
                    3
                }
            },
            Err(error) => usage_error(error),
        },
    };
    if window {
        println!("\nPress Enter to close this window.");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
    ExitCode::from(code)
}

/// Print a clap error and return its exit code: 0 for help and version, 3
/// for a usage error.
fn usage_error(error: clap::Error) -> u8 {
    let code = usage_exit_code(&error);
    let _ = error.print();
    code
}

fn usage_exit_code(error: &clap::Error) -> u8 {
    if error.use_stderr() { 3 } else { 0 }
}

/// How the program was started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Launch {
    /// Arguments that clap parses as given.
    Command,
    /// Only paths of existing files or folders, as when Windows Explorer
    /// starts the program for a file dropped onto it. Runs `scan` on them.
    Drop,
    /// No arguments, as when the program is double-clicked.
    Empty,
}

/// Decide how to treat `args`, the program name first. A first argument that
/// is a subcommand name or starts with `-` always goes to clap, even when a
/// file of that name exists, and so does a list with any argument `exists`
/// rejects, so clap reports it as before.
fn launch_kind(args: &[OsString], exists: impl Fn(&Path) -> bool) -> Launch {
    let arguments = args.get(1..).unwrap_or_default();
    let Some(first) = arguments.first() else {
        return Launch::Empty;
    };
    if first.as_encoded_bytes().starts_with(b"-") || is_subcommand(first) {
        Launch::Command
    } else if arguments.iter().all(|argument| exists(Path::new(argument))) {
        Launch::Drop
    } else {
        Launch::Command
    }
}

fn is_subcommand(argument: &OsStr) -> bool {
    // clap adds the `help` subcommand when it builds the command.
    argument == "help"
        || Cli::command().get_subcommands().any(|command| {
            argument == command.get_name()
                || command.get_all_aliases().any(|alias| argument == alias)
        })
}

/// The command line a drop runs: `scan --` and the paths, so a path that
/// looks like an option stays a path.
fn drop_args(args: &[OsString]) -> Vec<OsString> {
    let mut rewritten = Vec::with_capacity(args.len() + 2);
    rewritten.extend(args.first().cloned());
    rewritten.push("scan".into());
    rewritten.push("--".into());
    rewritten.extend(args.iter().skip(1).cloned());
    rewritten
}

/// Drop mode: exactly `scan` with the dropped paths, then a note on what the
/// result means.
fn drop_scan(args: &[OsString]) -> u8 {
    let cli = match Cli::try_parse_from(drop_args(args)) {
        Ok(cli) => cli,
        Err(error) => return usage_error(error),
    };
    let Command::Scan(scan_args) = cli.command else {
        unreachable!("drop mode arguments always parse as scan");
    };
    match scan(scan_args) {
        Ok((code, findings)) => {
            println!("\n{}", drop_note(code, findings));
            code
        }
        Err(error) => {
            eprintln!("bloxguard: {error}");
            3
        }
    }
}

/// The note after a drop mode scan, chosen by its exit code and whether the
/// report lists any finding.
fn drop_note(code: u8, findings: usize) -> &'static str {
    debug_assert!(code <= 2, "a scan returns exit code 0, 1 or 2");
    match code {
        1 => {
            "Some findings meet the high threshold. Open the game in Studio, find each script by the path shown above, and remove it unless you know why it is there. See https://github.com/waltuov/bloxguard#what-to-do-with-the-results"
        }
        2 => {
            "Part of the input could not be checked (see the reasons above), so this result is not complete and not clean."
        }
        _ if findings > 0 => {
            "No finding meets the high threshold. Read the medium and low findings above too: a clean result does not prove the game is safe."
        }
        _ => {
            "No findings. A clean result does not prove the game is safe, but none of the known backdoor tricks were found."
        }
    }
}

/// Wait for Enter before exiting only for a drop or a start without
/// arguments, when the program is alone on its console, which is a window
/// Windows opened for it and closes when it exits, and reads its input from
/// that console. A terminal, a script or CI never waits.
fn keeps_window_open(launch: Launch, alone_on_console: bool, stdin_is_terminal: bool) -> bool {
    launch != Launch::Command && alone_on_console && stdin_is_terminal
}

/// Whether this process is the only one attached to its console.
#[cfg(windows)]
fn alone_on_console() -> bool {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetConsoleProcessList(process_list: *mut u32, process_count: u32) -> u32;
    }

    let mut processes = [0u32; 2];
    // SAFETY: the buffer holds `processes.len()` entries and stays alive for
    // the call, which only writes process IDs into it. The call returns the
    // number of attached processes, or 0 without a console.
    let count = unsafe { GetConsoleProcessList(processes.as_mut_ptr(), processes.len() as u32) };
    count == 1
}

#[cfg(not(windows))]
fn alone_on_console() -> bool {
    false
}
fn config(path: Option<PathBuf>) -> Result<Config, String> {
    if let Some(path) = path {
        Config::from_path(&path)
    } else if std::path::Path::new("bloxguard.toml").is_file() {
        Config::from_path(std::path::Path::new("bloxguard.toml"))
    } else {
        Ok(Config::default())
    }
}
fn render(report: &bloxguard_core::report::ScanReport, format: Format) -> Result<String, String> {
    match format {
        Format::Human => Ok(output::human(report)),
        Format::Json => output::json(report).map_err(|e| e.to_string()),
        Format::Sarif => output::sarif(report).map_err(|e| e.to_string()),
    }
}
fn emit(text: String, path: Option<PathBuf>) -> Result<(), String> {
    use std::io::Write;
    if let Some(path) = path {
        std::fs::write(path, text).map_err(|e| format!("cannot write output: {e}"))
    } else {
        let mut out = std::io::stdout().lock();
        out.write_all(text.as_bytes())
            .and_then(|_| {
                if text.ends_with('\n') {
                    Ok(())
                } else {
                    out.write_all(b"\n")
                }
            })
            .map_err(|e| format!("cannot write stdout: {e}"))
    }
}
/// Run `scan` and return its exit code and the number of findings it reported.
fn scan(args: ScanArgs) -> Result<(u8, usize), String> {
    let mut config = config(args.config)?;
    if let Some(threshold) = args.fail_on {
        config.fail_on = threshold;
    }
    if let Some(date) = args.as_of {
        bloxguard_core::config::check_date(&date)?;
        config.current_date = date;
    }
    config.load_baseline(args.baseline.as_deref())?;
    let report = bloxguard_core::engine::scan_paths(&args.paths, &config);
    let code = report.exit_code(config.fail_on, args.allow_incomplete);
    emit(render(&report, args.format)?, args.output)?;
    Ok((code, report.findings.len()))
}
async fn run(cli: Cli) -> Result<u8, String> {
    match cli.command {
        Command::Scan(args) => scan(args).map(|(code, _)| code),
        Command::Inventory {
            path,
            format,
            config: config_path,
            allow_incomplete,
        } => {
            let config = config(config_path)?;
            let report = bloxguard_core::engine::inventory_documents_with_limits(
                bloxguard_core::loading::load_path(&path, &config.limits),
                &config.limits,
            );
            let text = match format {
                Format::Human => output::inventory_human(&report),
                _ => render(&report, format)?,
            };
            emit(text, None)?;
            Ok(report.exit_code(config.fail_on, allow_incomplete))
        }
        Command::Rules { format } => {
            let text = match format {
                Format::Json => {
                    serde_json::to_string_pretty(rules::all()).map_err(|e| e.to_string())?
                }
                _ => rules::all()
                    .iter()
                    .map(|r| format!("{} {:8} {}\n", r.id, r.default_severity, r.name))
                    .collect(),
            };
            emit(text, None)?;
            Ok(0)
        }
        Command::Explain { id, format } => {
            let rule = rules::rule(&id.trim().to_ascii_uppercase())
                .ok_or_else(|| format!("unknown rule: {id}"))?;
            let text = match format {
                Format::Json => serde_json::to_string_pretty(rule).map_err(|e| e.to_string())?,
                _ => format!(
                    "{}: {}\nDefault severity: {}\n\n{}\n\n{}\n\nFull documentation: {}\n",
                    rule.id,
                    rule.name,
                    rule.default_severity,
                    rule.description,
                    rule.help,
                    rule.help_uri
                ),
            };
            emit(text, None)?;
            Ok(0)
        }
        Command::Baseline {
            command:
                BaselineCommand::Create {
                    paths,
                    output,
                    config: config_path,
                },
        } => {
            let mut config = config(config_path)?;
            config.baseline = None;
            config.baseline_fingerprints.clear();
            config.baseline_scopes = None;
            let report = bloxguard_core::engine::scan_paths(&paths, &config);
            if report.completeness != Completeness::Complete {
                emit(output::human(&report), None)?;
                eprintln!("bloxguard: refusing to create a baseline from an incomplete scan");
                return Ok(2);
            }
            let baseline = Baseline {
                schema_version: 1,
                fingerprints: report
                    .findings
                    .iter()
                    .map(|f| f.fingerprint.clone())
                    .collect(),
                input_scopes: Some(report.findings.iter().fold(
                    std::collections::BTreeMap::new(),
                    |mut scopes, finding| {
                        scopes
                            .entry(finding.fingerprint.clone())
                            .or_insert_with(std::collections::BTreeSet::new)
                            .insert(bloxguard_core::config::normalize_input_scope(
                                &finding.input,
                            ));
                        scopes
                    },
                )),
            };
            let count = baseline.fingerprints.len();
            emit(
                serde_json::to_string_pretty(&baseline).map_err(|e| e.to_string())? + "\n",
                Some(output),
            )?;
            eprintln!(
                "Baseline created with {count} fingerprints. Review them before committing the baseline."
            );
            Ok(0)
        }
        Command::Mcp { root } => {
            mcp::serve(root).await.map_err(|e| e.to_string())?;
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        std::iter::once("bloxguard")
            .chain(list.iter().copied())
            .map(OsString::from)
            .collect()
    }

    fn scan_args(args: &[OsString]) -> ScanArgs {
        let Command::Scan(scan) = Cli::try_parse_from(args).expect("parses").command else {
            panic!("not a scan: {args:?}");
        };
        scan
    }

    #[test]
    fn no_arguments_is_an_empty_launch() {
        assert_eq!(launch_kind(&args(&[]), |_| true), Launch::Empty);
        assert_eq!(launch_kind(&[], |_| true), Launch::Empty);
    }

    #[test]
    fn a_subcommand_name_wins_over_a_file_of_that_name() {
        let names = ["scan", "inventory", "rules", "explain", "baseline", "mcp"];
        // The list above is every subcommand clap defines, so a new one fails here.
        let defined: Vec<_> = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_owned())
            .collect();
        assert_eq!(defined, names);
        for name in names.into_iter().chain(["help"]) {
            assert_eq!(
                launch_kind(&args(&[name]), |_| true),
                Launch::Command,
                "{name}"
            );
            assert_eq!(
                launch_kind(&args(&[name, "FAKE.rbxl"]), |_| true),
                Launch::Command,
                "{name}"
            );
        }
    }

    #[test]
    fn flags_go_to_clap_unchanged() {
        for flag in ["-h", "--help", "-V", "--version", "--format"] {
            assert_eq!(
                launch_kind(&args(&[flag]), |_| true),
                Launch::Command,
                "{flag}"
            );
            assert_eq!(
                launch_kind(&args(&[flag, "FAKE.rbxl"]), |_| true),
                Launch::Command,
                "{flag}"
            );
        }
        // An option after a path is not a path that exists.
        let list = args(&["FAKE.rbxl", "--format", "json"]);
        assert_eq!(
            launch_kind(&list, |path| path == Path::new("FAKE.rbxl")),
            Launch::Command
        );
    }

    #[test]
    fn a_missing_path_keeps_the_usage_error() {
        let list = args(&["FAKE_missing.rbxl"]);
        assert_eq!(launch_kind(&list, |_| false), Launch::Command);
        let error = Cli::try_parse_from(&list)
            .err()
            .expect("an unknown word is a usage error");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
        assert_eq!(usage_exit_code(&error), 3);
        // One missing path among existing ones is not a drop either.
        let list = args(&["FAKE_a.rbxl", "FAKE_missing.rbxl"]);
        assert_eq!(
            launch_kind(&list, |path| path == Path::new("FAKE_a.rbxl")),
            Launch::Command
        );
    }

    #[test]
    fn existing_files_and_folders_become_a_scan_of_those_paths() {
        let temp = tempfile::Builder::new()
            .prefix("bloxguard_FAKE_drop_")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let folder = temp.path().join("FAKE_game");
        std::fs::create_dir(&folder).unwrap();
        let file = temp.path().join("FAKE place.rbxl");
        std::fs::write(&file, "").unwrap();
        for paths in [
            vec![file.clone()],
            vec![folder.clone()],
            vec![file.clone(), folder.clone()],
        ] {
            let list: Vec<OsString> = std::iter::once(OsString::from("bloxguard"))
                .chain(paths.iter().map(|path| path.clone().into_os_string()))
                .collect();
            assert_eq!(launch_kind(&list, Path::exists), Launch::Drop, "{paths:?}");
            let rewritten = drop_args(&list);
            assert_eq!(rewritten[..3], ["bloxguard", "scan", "--"]);
            assert_eq!(rewritten[3..], list[1..]);
            let scan = scan_args(&rewritten);
            assert_eq!(scan.paths, paths);
            assert!(matches!(scan.format, Format::Human));
            assert!(scan.output.is_none());
            assert!(scan.fail_on.is_none());
            assert!(scan.config.is_none());
            assert!(scan.baseline.is_none());
            assert!(!scan.allow_incomplete);
            assert!(scan.as_of.is_none());
        }
    }

    #[test]
    fn a_dropped_path_that_looks_like_an_option_stays_a_path() {
        let list = args(&["FAKE.rbxl", "--allow-incomplete"]);
        assert_eq!(launch_kind(&list, |_| true), Launch::Drop);
        let scan = scan_args(&drop_args(&list));
        assert_eq!(
            scan.paths,
            [
                PathBuf::from("FAKE.rbxl"),
                PathBuf::from("--allow-incomplete")
            ]
        );
        assert!(!scan.allow_incomplete);
    }

    #[test]
    fn the_window_waits_only_for_a_drop_or_no_arguments_alone_on_a_terminal_console() {
        for launch in [Launch::Drop, Launch::Empty] {
            assert!(keeps_window_open(launch, true, true), "{launch:?}");
            assert!(!keeps_window_open(launch, false, true), "{launch:?}");
            assert!(!keeps_window_open(launch, true, false), "{launch:?}");
            assert!(!keeps_window_open(launch, false, false), "{launch:?}");
        }
        assert!(!keeps_window_open(Launch::Command, true, true));
    }

    #[test]
    fn the_drop_note_follows_the_result() {
        assert!(drop_note(1, 3).starts_with("Some findings meet the high threshold."));
        assert!(drop_note(0, 2).starts_with("No finding meets the high threshold."));
        assert!(drop_note(0, 0).starts_with("No findings."));
        for findings in [0, 5] {
            assert!(drop_note(2, findings).starts_with("Part of the input"));
        }
    }
}

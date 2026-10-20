//! Drop mode: `bloxguard <paths>` with only existing paths, as Windows Explorer
//! starts the program for a file dropped onto it, runs `scan` with those paths
//! and adds a note on the result. Every fixture is synthetic and defanged.

use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const EXIT_1_NOTE: &str = "Some findings are high or critical. Open the game in Studio, find each script by the path shown above, and remove it unless you know why it is there. See https://github.com/waltuov/bloxguard#what-to-do-with-the-results";
const EXIT_0_FINDINGS_NOTE: &str = "No high or critical findings. Read the medium and low findings above too: a clean result does not prove the game is safe.";
const EXIT_0_CLEAN_NOTE: &str = "No findings. A clean result does not prove the game is safe, but none of the known backdoor tricks were found.";
const EXIT_2_NOTE: &str = "Part of the input could not be checked (see the reasons above), so this result is not complete and not clean.";

/// A module whose only finding is a low BG001 for `require(v)` in a loop.
const LOW_ONLY: &str = "local M = {}\nfunction M.AddServices(folder)\n  for _, v in ipairs(folder:GetChildren()) do\n    require(v)\n  end\nend\nreturn M\n";

fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("bloxguard_FAKE_drop_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory")
}

/// Run the binary with input from nothing, as the other CLI tests do.
fn run(temp: &Path, args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bloxguard"))
        .args(args)
        .current_dir(temp)
        .output()
        .expect("run bloxguard")
}

fn write(temp: &Path, name: &str, text: &str) -> PathBuf {
    let path = temp.join(name);
    fs::write(&path, text).expect("write synthetic fixture");
    path
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The dropped run prints what `scan` prints, then a blank line and the note.
fn assert_drop_matches_scan(temp: &Path, paths: &[&Path], code: i32, note: &str) {
    let dropped = run(temp, paths);
    let scanned = run(
        temp,
        std::iter::once(Path::new("scan")).chain(paths.iter().copied()),
    );
    assert_eq!(
        scanned.status.code(),
        Some(code),
        "{}",
        text(&scanned.stdout)
    );
    assert_eq!(
        dropped.status.code(),
        Some(code),
        "{}",
        text(&dropped.stdout)
    );
    assert_eq!(text(&dropped.stderr), text(&scanned.stderr));
    assert_eq!(
        text(&dropped.stdout),
        format!("{}\n{note}\n", text(&scanned.stdout)),
        "{paths:?}"
    );
    assert!(!text(&dropped.stdout).contains("Press Enter"));
}

#[test]
fn drop_mode_prints_the_scan_report_and_a_note_for_each_result() {
    let temp = temp_dir();
    let clean = write(temp.path(), "FAKE_clean.luau", "return 1\n");
    let low = write(temp.path(), "FAKE_services.luau", LOW_ONLY);
    let risky = write(temp.path(), "FAKE_risky.luau", "require(999000000000901)\n");
    let broken = write(temp.path(), "FAKE_broken.luau", "local = = =\n");

    assert_drop_matches_scan(temp.path(), &[&clean], 0, EXIT_0_CLEAN_NOTE);
    assert_drop_matches_scan(temp.path(), &[&low], 0, EXIT_0_FINDINGS_NOTE);
    assert_drop_matches_scan(temp.path(), &[&risky], 1, EXIT_1_NOTE);
    assert_drop_matches_scan(temp.path(), &[&broken], 2, EXIT_2_NOTE);
    // Several paths, and a partial input beside a high finding, as in `scan`: the
    // high finding is named before the partial note.
    assert_drop_matches_scan(temp.path(), &[&clean, &low], 0, EXIT_0_FINDINGS_NOTE);
    assert_drop_matches_scan(
        temp.path(),
        &[&risky, &broken],
        2,
        &format!("{EXIT_1_NOTE}\n\n{EXIT_2_NOTE}"),
    );
}

#[test]
fn the_drop_note_follows_the_findings_not_the_threshold() {
    let temp = temp_dir();
    write(temp.path(), "bloxguard.toml", "fail_on = \"low\"\n");
    let low = write(temp.path(), "FAKE_services.luau", LOW_ONLY);
    // The configured threshold fails the scan on a low finding, but the note
    // still says that nothing high or critical was found.
    assert_drop_matches_scan(temp.path(), &[&low], 1, EXIT_0_FINDINGS_NOTE);
}

#[test]
fn drop_mode_scans_a_dropped_folder() {
    let temp = temp_dir();
    let game = temp.path().join("FAKE_game");
    fs::create_dir_all(game.join("src")).unwrap();
    write(
        &game.join("src"),
        "FAKE_loader.server.luau",
        "require(999000000000902)\n",
    );
    assert_drop_matches_scan(temp.path(), &[&game], 1, EXIT_1_NOTE);
    // A relative path from the working directory works too.
    assert_drop_matches_scan(temp.path(), &[Path::new("FAKE_game")], 1, EXIT_1_NOTE);
}

#[test]
fn a_missing_path_or_a_subcommand_name_keeps_the_usual_behavior() {
    let temp = temp_dir();
    let missing = run(temp.path(), ["FAKE_missing.rbxl"]);
    assert_eq!(missing.status.code(), Some(3));
    assert!(
        text(&missing.stderr).contains("unrecognized subcommand"),
        "{}",
        text(&missing.stderr)
    );
    assert!(missing.stdout.is_empty());

    // A folder named like a subcommand does not turn the subcommand into a scan.
    fs::create_dir(temp.path().join("rules")).unwrap();
    let rules = run(temp.path(), ["rules"]);
    assert_eq!(rules.status.code(), Some(0));
    assert!(
        text(&rules.stdout).starts_with("BG001"),
        "{}",
        text(&rules.stdout)
    );
    assert!(!text(&rules.stdout).contains("No findings"));

    // Without arguments in a terminal, script or CI, the usage error stays.
    let empty = run(temp.path(), std::iter::empty::<&str>());
    assert_eq!(empty.status.code(), Some(3));
    assert!(empty.stdout.is_empty());
    assert!(
        text(&empty.stderr).contains("Usage"),
        "{}",
        text(&empty.stderr)
    );
}

/// Input from a pipe that stays open is not a terminal, so the program must
/// exit without waiting for a line, also in a drop.
#[test]
fn drop_mode_with_piped_input_exits_without_waiting() {
    let temp = temp_dir();
    let clean = write(temp.path(), "FAKE_clean.luau", "return 1\n");
    let mut child = Command::new(env!("CARGO_BIN_EXE_bloxguard"))
        .arg(&clean)
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start bloxguard");
    // Keep the input pipe open until the end, so a read would block.
    let input = child.stdin.take().expect("piped input");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll bloxguard") {
            break status;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("bloxguard waited for input on a pipe");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(input);
    assert_eq!(status.code(), Some(0));
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(
        stdout.ends_with(&format!("\n{EXIT_0_CLEAN_NOTE}\n")),
        "{stdout}"
    );
    assert!(!stdout.contains("Press Enter"), "{stdout}");
}

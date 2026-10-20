//! Generate a large, harmless place and time a release BloxGuard scan.

use rbx_dom_weak::{InstanceBuilder, WeakDom};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const SERIALIZED_INSTANCES: usize = 500_000;
const SCRIPT_INSTANCES: usize = 20_000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner_path();
    if !scanner.is_file() {
        return Err(format!(
            "release scanner not found at {}. Run cargo build --locked --release --package bloxguard --bin bloxguard first",
            scanner.display()
        )
        .into());
    }

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temp_root = workspace_root()
        .join("target")
        .join(format!("bloxguard-performance-{nonce}"));
    fs::create_dir(&temp_root)?;
    let _cleanup = Cleanup(temp_root.clone());
    let place_path = temp_root.join("FAKE-large-place.rbxl");
    let report_path = temp_root.join("report.json");

    let generate_started = Instant::now();
    let mut dom = WeakDom::new(InstanceBuilder::new("DataModel"));
    dom.reserve(SERIALIZED_INSTANCES);
    let root = dom.root_ref();
    let workspace = dom.insert(
        root,
        InstanceBuilder::new("Workspace").with_name("Workspace"),
    );
    let scripts = dom.insert(
        root,
        InstanceBuilder::new("ServerScriptService").with_name("ServerScriptService"),
    );

    for index in 0..SCRIPT_INSTANCES {
        let source = format!(
            "-- FAKE harmless performance fixture {index}\nlocal value = {index}\nreturn value\n"
        );
        dom.insert(
            scripts,
            InstanceBuilder::new("ModuleScript")
                .with_name(format!("FAKE_Script_{index:05}"))
                .with_property("Source", source),
        );
    }

    let part_count = SERIALIZED_INSTANCES - SCRIPT_INSTANCES - 2;
    for index in 0..part_count {
        dom.insert(
            workspace,
            InstanceBuilder::new("Part").with_name(format!("FAKE_Part_{index:06}")),
        );
    }
    let generation_time = generate_started.elapsed();

    let serialize_started = Instant::now();
    let writer = BufWriter::new(File::create(&place_path)?);
    rbx_binary::to_writer(writer, &dom, dom.root().children())?;
    let serialization_time = serialize_started.elapsed();
    drop(dom);

    let scan_started = Instant::now();
    let status = Command::new(&scanner)
        .args(["scan", "--format", "json", "--output"])
        .arg(&report_path)
        .arg(&place_path)
        .status()?;
    let scan_time = scan_started.elapsed();

    let place_bytes = fs::metadata(&place_path)?.len();
    let report: serde_json::Value = serde_json::from_reader(File::open(&report_path)?)?;
    let finding_count = report
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    let completeness = report
        .get("completeness")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");

    println!("bloxguard_version={}", bloxguard_core::VERSION);
    println!("serialized_instances={SERIALIZED_INSTANCES}");
    println!("script_instances={SCRIPT_INSTANCES}");
    println!("place_bytes={place_bytes}");
    println!("generation_seconds={:.3}", generation_time.as_secs_f64());
    println!(
        "serialization_seconds={:.3}",
        serialization_time.as_secs_f64()
    );
    println!("scan_seconds={:.3}", scan_time.as_secs_f64());
    println!("completeness={completeness}");
    println!("finding_count={finding_count}");
    if !matches!(status.code(), Some(0 | 1)) {
        return Err(format!("scanner exited with {status}").into());
    }
    Ok(())
}

fn scanner_path() -> PathBuf {
    if let Some(path) = env::var_os("BLOXGUARD_BIN") {
        return PathBuf::from(path);
    }
    let name = if cfg!(windows) {
        "bloxguard.exe"
    } else {
        "bloxguard"
    };
    workspace_root().join("target").join("release").join(name)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0)
            && error.kind() != io::ErrorKind::NotFound
        {
            eprintln!("could not remove temporary benchmark directory: {error}");
        }
    }
}

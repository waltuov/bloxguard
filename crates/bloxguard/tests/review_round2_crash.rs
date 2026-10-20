//! Review round 2, items 2 and 3: unary chains and long call chains through the real
//! CLI and MCP server. Inputs are synthetic; nothing is executed.

use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("bloxguard_FAKE_round2_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory")
}

fn run(temp: &Path, args: &[&str]) -> Output {
    let scratch = temp.join("tmp");
    fs::create_dir_all(&scratch).expect("create scratch directory");
    Command::new(env!("CARGO_BIN_EXE_bloxguard"))
        .args(args)
        .current_dir(temp)
        .env("TEMP", &scratch)
        .env("TMP", &scratch)
        .output()
        .expect("run bloxguard CLI")
}

fn unary_chains() -> Vec<(&'static str, String)> {
    vec![
        ("length", format!("return {}FAKE_t", "#".repeat(20_000))),
        ("minus", format!("return {}1", "- ".repeat(20_000))),
        ("not", format!("return {}FAKE_c", "not ".repeat(20_000))),
    ]
}

fn assert_partial_with_reason(label: &str, report: &Value) {
    assert_eq!(report["completeness"], "partial", "{label}: {report}");
    let reasons = report["inputs"][0]["reasons"].as_array().expect("reasons");
    assert!(
        reasons.iter().any(|reason| reason
            .as_str()
            .unwrap_or_default()
            .contains("expression complexity")),
        "{label}: {reasons:?}"
    );
}

#[test]
fn item2_unary_chains_return_partial_in_cli() {
    let temp = temp_dir();
    for (label, source) in unary_chains() {
        let path = temp.path().join(format!("FAKE_{label}.luau"));
        fs::write(&path, &source).expect("write synthetic source");
        let output = run(
            temp.path(),
            &["scan", path.to_str().unwrap(), "--format", "json"],
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("JSON report");
        assert_partial_with_reason(label, &report);
    }
}

#[test]
fn item3_fifty_thousand_link_chains_scan_in_cli() {
    let temp = temp_dir();
    for (label, source) in [
        ("calls", format!("FAKE_f{}", "()".repeat(50_000))),
        ("methods", format!("FAKE_x{}", ":m()".repeat(50_000))),
    ] {
        let path = temp.path().join(format!("FAKE_{label}.luau"));
        fs::write(&path, &source).expect("write synthetic source");
        let started = Instant::now();
        let output = run(
            temp.path(),
            &["scan", path.to_str().unwrap(), "--format", "json"],
        );
        let elapsed = started.elapsed();
        let report: Value = serde_json::from_slice(&output.stdout).expect("JSON report");
        let reasons = report["inputs"][0]["reasons"].as_array().expect("reasons");
        assert!(reasons.is_empty(), "{label}: {reasons:?}");
        assert_eq!(report["completeness"], "complete", "{label}: {report}");
        // Debug test builds are several times slower than the release build.
        assert!(
            elapsed < Duration::from_secs(20),
            "{label} took {elapsed:?}"
        );
    }
}

struct McpProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bloxguard"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start bloxguard MCP server");
        let stdin = child.stdin.take().expect("MCP stdin");
        let stdout = BufReader::new(child.stdout.take().expect("MCP stdout"));
        let mut server = Self {
            child,
            stdin: Some(stdin),
            stdout,
            next_id: 1,
        };
        server.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "bloxguard-round2-test", "version": "0.1.0"}
            }),
        );
        server
            .write(&json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}));
        server
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.write(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let mut line = String::new();
            let count = self.stdout.read_line(&mut line).expect("read MCP response");
            assert_ne!(
                count, 0,
                "MCP server closed before replying to request {id}"
            );
            let message: Value = serde_json::from_str(&line).expect("MCP JSON");
            if message.get("id") == Some(&json!(id)) {
                return message;
            }
        }
    }

    fn write(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("MCP stdin");
        serde_json::to_writer(&mut *stdin, message).expect("write MCP JSON");
        stdin.write_all(b"\n").expect("write newline");
        stdin.flush().expect("flush");
    }

    fn scan_source(&mut self, source: &str, path: &str) -> Value {
        let response = self.request(
            "tools/call",
            json!({"name": "scan_source", "arguments": {"source": source, "path": path}}),
        );
        assert!(response.get("error").is_none(), "{response:#}");
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text result");
        serde_json::from_str(text).expect("tool JSON")
    }
}

impl Drop for McpProcess {
    fn drop(&mut self) {
        self.stdin.take();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[test]
fn item2_unary_chains_do_not_kill_mcp() {
    let mut server = McpProcess::start();
    for (label, source) in unary_chains() {
        let report = server.scan_source(&source, &format!("FAKE_{label}.luau"));
        assert_partial_with_reason(label, &report);
        let next = server.scan_source("return 1", "FAKE_next.luau");
        assert_eq!(
            next["completeness"], "complete",
            "{label}: server stopped serving"
        );
    }
}

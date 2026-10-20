//! Review round 2 (fix round 3) item 9 checks that need the real binary.

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use serde_json::{Value, json};

struct McpProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpProcess {
    fn start(roots: &[&Path]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bloxguard"));
        command
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for root in roots {
            command.arg("--root").arg(root);
        }
        let mut child = command.spawn().expect("start bloxguard MCP server");
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
                "clientInfo": {"name": "bloxguard-test", "version": "0.1.0"}
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
            let message: Value = serde_json::from_str(&line).expect("MCP response is JSON");
            if message.get("id") == Some(&json!(id)) {
                return message;
            }
        }
    }

    fn write(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("MCP stdin remains open");
        serde_json::to_writer(&mut *stdin, message).expect("write MCP JSON");
        stdin.write_all(b"\n").expect("write MCP newline");
        stdin.flush().expect("flush MCP request");
    }

    fn scan_path(&mut self, path: &Path) -> Value {
        self.request(
            "tools/call",
            json!({"name": "scan_path", "arguments": {"path": path}}),
        )
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

/// The text a client sees for a refused request, whichever form rmcp uses.
fn refusal_text(response: &Value) -> String {
    if let Some(message) = response
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
    {
        return message.to_owned();
    }
    let result = response.get("result").expect("tool result");
    assert_eq!(
        result.get("isError"),
        Some(&Value::Bool(true)),
        "request was not refused: {response:#}"
    );
    result["content"][0]["text"]
        .as_str()
        .expect("refusal text")
        .to_owned()
}

#[test]
fn round2_09_mcp_outside_root_refusal_is_the_same_for_existing_and_missing_files() {
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("mcp-tests");
    fs::create_dir_all(&parent).expect("create repository-local test parent");
    let temp = tempfile::Builder::new()
        .prefix("round2-")
        .tempdir_in(&parent)
        .expect("create repository-local temp directory");
    let allowed = temp.path().join("allowed");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&allowed).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(allowed.join("FAKE_inside.luau"), "return 1\n").unwrap();
    fs::write(outside.join("FAKE_secret.luau"), "return 1\n").unwrap();
    let allowed = fs::canonicalize(&allowed).unwrap();
    let outside = fs::canonicalize(&outside).unwrap();

    let mut server = McpProcess::start(&[&allowed]);
    let existing = refusal_text(&server.scan_path(&outside.join("FAKE_secret.luau")));
    let missing = refusal_text(&server.scan_path(&outside.join("FAKE_absent.luau")));
    let missing_folder =
        refusal_text(&server.scan_path(&outside.join("FAKE_no_folder").join("FAKE_secret.luau")));
    let dotted = refusal_text(
        &server.scan_path(&allowed.join("..").join("outside").join("FAKE_absent.luau")),
    );
    for message in [&existing, &missing, &missing_folder, &dotted] {
        assert!(
            message.contains("outside the configured MCP roots"),
            "{message}"
        );
        assert!(!message.contains("cannot"), "{message}");
    }
    assert_eq!(
        existing.replace("FAKE_secret", "FAKE_name"),
        missing.replace("FAKE_absent", "FAKE_name")
    );

    // The server still serves an allowed path afterwards.
    let response = server.scan_path(&allowed.join("FAKE_inside.luau"));
    assert!(response.get("error").is_none(), "{response:#}");
    assert_ne!(
        response["result"]["isError"],
        Value::Bool(true),
        "{response:#}"
    );
}

#[test]
fn round2_09_action_default_paths_scan_a_typical_rojo_repository_with_exit_zero() {
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("cli-tests");
    fs::create_dir_all(&parent).expect("create repository-local test parent");
    let repo = tempfile::Builder::new()
        .prefix("rojo-")
        .tempdir_in(&parent)
        .expect("create repository-local temp directory");
    for (relative, contents) in [
        (
            "default.project.json",
            r#"{"name":"FAKE","tree":{"$className":"DataModel",
              "ReplicatedStorage":{"Shared":{"$path":"src/shared"},"Packages":{"$path":"Packages"}},
              "ServerScriptService":{"Server":{"$path":"src/server"}},
              "Workspace":{"$properties":{"FilteringEnabled":true}},
              "Lighting":{"$properties":{"Ambient":[0,0,0]}}}}"#,
        ),
        ("src/server/init.server.luau", "print('FAKE server')"),
        (
            "src/shared/FAKE_Util.luau",
            "local Packages = game:GetService('ReplicatedStorage'):WaitForChild('Packages')\nreturn require(Packages.Promise)",
        ),
        (
            "Packages/_Index/fake_promise@4.0.0/promise/default.project.json",
            r#"{"name":"promise","tree":{"$path":"lib"}}"#,
        ),
        (
            "Packages/_Index/fake_promise@4.0.0/promise/lib/init.lua",
            "return {}",
        ),
        ("wally.toml", "[package]\nname = 'fake/place'\n"),
    ] {
        let path = repo.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    let sarif = repo.path().join("FAKE.sarif");
    // The same arguments scripts/action-run.ps1 passes with the default inputs.
    let output = Command::new(env!("CARGO_BIN_EXE_bloxguard"))
        .current_dir(repo.path())
        .args(["scan", ".", "--format", "sarif", "--output"])
        .arg(&sarif)
        .args(["--fail-on", "high"])
        .output()
        .expect("run bloxguard");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let log: Value = serde_json::from_slice(&fs::read(&sarif).unwrap()).unwrap();
    let notes = log["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        notes.iter().any(|note| note["message"]["text"]
            .as_str()
            .is_some_and(|text| text.contains("Rojo project mapping"))),
        "{log:#}"
    );

    let human = Command::new(env!("CARGO_BIN_EXE_bloxguard"))
        .current_dir(repo.path())
        .args(["scan", "."])
        .output()
        .expect("run bloxguard");
    assert_eq!(human.status.code(), Some(0));
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.contains("[complete]"), "{text}");
    assert!(text.contains("info: Rojo project mapping"), "{text}");
}

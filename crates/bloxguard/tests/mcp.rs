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
            .stderr(Stdio::piped());
        for root in roots {
            command.arg("--root").arg(root);
        }
        let mut child = command.spawn().expect("start bloxguard MCP server");
        let stdin = child.stdin.take().expect("MCP stdin");
        let stdout = BufReader::new(child.stdout.take().expect("MCP stdout"));
        Self {
            child,
            stdin: Some(stdin),
            stdout,
            next_id: 1,
        }
    }

    fn initialize(&mut self) -> Value {
        let response = self.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "bloxguard-test", "version": "0.1.0"}
            }),
        );
        self.notify("notifications/initialized", json!({}));
        response
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
            let message: Value = serde_json::from_str(&line)
                .unwrap_or_else(|error| panic!("invalid MCP response {line:?}: {error}"));
            if message.get("id") == Some(&json!(id)) {
                return message;
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.write(&json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    fn write(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("MCP stdin remains open");
        serde_json::to_writer(&mut *stdin, message).expect("write MCP JSON");
        stdin.write_all(b"\n").expect("write MCP newline");
        stdin.flush().expect("flush MCP request");
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

fn tool_call(server: &mut McpProcess, name: &str, arguments: Value) -> Value {
    server.request("tools/call", json!({"name": name, "arguments": arguments}))
}

fn tool_json(response: &Value) -> Value {
    assert!(
        response.get("error").is_none(),
        "tool returned an error: {response:#}"
    );
    let result = response.get("result").expect("tool result");
    assert_ne!(
        result.get("isError"),
        Some(&Value::Bool(true)),
        "tool failed: {response:#}"
    );
    let text = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|content| content.first())
        .and_then(|content| content.get("text"))
        .and_then(Value::as_str)
        .expect("text tool result");
    serde_json::from_str(text).expect("tool text is JSON")
}

fn rejected(response: &Value) -> bool {
    response.get("error").is_some()
        || response
            .get("result")
            .and_then(|result| result.get("isError"))
            == Some(&Value::Bool(true))
}

#[test]
fn review_01_nested_interpolations_do_not_kill_mcp() {
    let mut server = McpProcess::start(&[]);
    server.initialize();
    let source = format!("return {}1{}", "`{".repeat(1000), "}`".repeat(1000));
    let result = tool_call(
        &mut server,
        "scan_source",
        json!({"source":source,"path":"FAKE_nested.luau"}),
    );
    let report = tool_json(&result);
    assert_eq!(report["completeness"], "partial");
    assert!(
        report["inputs"][0]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason.as_str().unwrap().contains("interpolated"))
    );
    let next = tool_call(
        &mut server,
        "scan_source",
        json!({"source":"return 1","path":"FAKE_next.luau"}),
    );
    assert_eq!(tool_json(&next)["completeness"], "complete");
}

#[test]
fn stdio_server_lists_and_runs_read_only_tools_with_root_confinement() {
    let temp_parent = repository_temp_parent();
    fs::create_dir_all(&temp_parent).expect("create repository-local test temp parent");
    let temp = tempfile::Builder::new()
        .prefix("mcp-")
        .tempdir_in(&temp_parent)
        .expect("create repository-local temp directory");
    let allowed_root = temp.path().join("allowed");
    let outside_root = temp.path().join("outside");
    fs::create_dir_all(&allowed_root).expect("create allowed root");
    fs::create_dir_all(&outside_root).expect("create outside root");

    let source_path = allowed_root.join("FAKE_clean.server.luau");
    fs::write(&source_path, "local answer = 40 + 2\nprint(answer)\n")
        .expect("write synthetic clean source");
    let outside_path = outside_root.join("FAKE_outside.luau");
    fs::write(&outside_path, "return 1\n").expect("write synthetic outside source");

    let mut server = McpProcess::start(&[&allowed_root]);
    let initialized = server.initialize();
    assert_eq!(initialized["result"]["serverInfo"]["name"], "bloxguard");

    let list = server.request("tools/list", json!({}));
    let tools = list["result"]["tools"].as_array().expect("tool list");
    let mut names = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "explain_rule",
            "inventory",
            "scan_bundle",
            "scan_path",
            "scan_source"
        ]
    );
    assert!(tools.iter().all(|tool| {
        tool["annotations"]["readOnlyHint"] == true
            && tool["annotations"]["destructiveHint"] == false
            && tool["annotations"]["openWorldHint"] == false
    }));

    let source_report = tool_json(&tool_call(
        &mut server,
        "scan_source",
        json!({
            "source": "local FAKE_ID = 999000000000001\nreturn require(FAKE_ID)",
            "path": "Studio/FAKE_RemoteModule.server.luau",
            "class": "Script"
        }),
    ));
    assert_eq!(source_report["schema_version"], 1);
    assert_eq!(source_report["findings"][0]["rule_id"], "BG001");

    let bundle_report = tool_json(&tool_call(
        &mut server,
        "scan_bundle",
        json!({
            "bundle": {
                "schema_version": 1,
                "instances": [{
                    "name": "FAKE_BundleScript",
                    "class": "ModuleScript",
                    "source": "return 1"
                }]
            }
        }),
    ));
    assert_eq!(bundle_report["schema_version"], 1);
    assert_eq!(bundle_report["inputs"][0]["instance_count"], 1);

    let explanation = tool_json(&tool_call(
        &mut server,
        "explain_rule",
        json!({"id": "bg001"}),
    ));
    assert_eq!(explanation["id"], "BG001");

    let path_report = tool_json(&tool_call(
        &mut server,
        "scan_path",
        json!({"path": source_path}),
    ));
    assert_eq!(path_report["schema_version"], 1);

    let inventory = tool_json(&tool_call(
        &mut server,
        "inventory",
        json!({"path": source_path}),
    ));
    assert_eq!(inventory["schema_version"], 1);
    assert_eq!(inventory["inventory"][0]["class"], "Script");

    let outside = tool_call(&mut server, "scan_path", json!({"path": outside_path}));
    assert!(rejected(&outside), "outside path was accepted: {outside:#}");

    let oversized_source = "x".repeat(2 * 1024 * 1024 + 1);
    let oversized = tool_call(
        &mut server,
        "scan_source",
        json!({"source": oversized_source}),
    );
    assert!(
        rejected(&oversized),
        "oversized source was accepted: {oversized:#}"
    );

    let link_path = allowed_root.join("FAKE_escape_link.luau");
    if create_file_symlink(&outside_path, &link_path) {
        let escaped = tool_call(&mut server, "scan_path", json!({"path": &allowed_root}));
        assert!(
            rejected(&escaped),
            "escaping symlink was accepted: {escaped:#}"
        );
    }

    let mut rootless = McpProcess::start(&[]);
    rootless.initialize();
    let disabled = tool_call(&mut rootless, "scan_path", json!({"path": source_path}));
    assert!(
        rejected(&disabled),
        "rootless server read a path: {disabled:#}"
    );
}

fn repository_temp_parent() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("mcp-tests")
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) -> bool {
    std::os::windows::fs::symlink_file(target, link).is_ok()
}

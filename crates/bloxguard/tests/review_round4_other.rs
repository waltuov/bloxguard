//! Review round 4 (fix round 5) item 14 through the real binary: a request
//! line whose `id` is not a valid request id gets `-32600` without an id
//! instead of being dropped as a notification, and error replies do not
//! repeat long request text. All payloads are synthetic.

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{Receiver, RecvTimeoutError, channel},
    thread,
    time::Duration,
};

use serde_json::{Value, json};

const REPLY_TIMEOUT: Duration = Duration::from_secs(60);

struct McpProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<Option<Vec<u8>>>,
    next_id: u64,
}

impl McpProcess {
    fn start(roots: &[&std::path::Path]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bloxguard"));
        command.arg("mcp");
        for root in roots {
            command.arg("--root").arg(root);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start bloxguard MCP server");
        let stdin = child.stdin.take().expect("MCP stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("MCP stdout"));
        let (sender, lines) = channel();
        // A reader thread, so a missing reply fails the test instead of hanging it.
        thread::spawn(move || {
            loop {
                let mut line = Vec::new();
                match stdout.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => {
                        let _ = sender.send(None);
                        return;
                    }
                    Ok(_) => {
                        if sender.send(Some(line)).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        let mut server = Self {
            child,
            stdin: Some(stdin),
            lines,
            next_id: 1,
        };
        let id = server.send_request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "bloxguard-test", "version": "0.1.0"}
            }),
        );
        assert_eq!(server.next_line()["id"], id, "initialize reply");
        server.write_line(br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#);
        server
    }

    fn write_line(&mut self, line: &[u8]) {
        let stdin = self.stdin.as_mut().expect("MCP stdin remains open");
        stdin.write_all(line).expect("write MCP line");
        stdin.write_all(b"\n").expect("write MCP newline");
        stdin.flush().expect("flush MCP line");
    }

    /// The next output line. Every test here expects one, so a timeout fails.
    fn next_line(&self) -> Value {
        match self.lines.recv_timeout(REPLY_TIMEOUT) {
            Ok(Some(line)) => serde_json::from_slice(&line).expect("reply is JSON"),
            Ok(None) | Err(RecvTimeoutError::Disconnected) => panic!("server closed stdout"),
            Err(RecvTimeoutError::Timeout) => panic!("no MCP output within {REPLY_TIMEOUT:?}"),
        }
    }

    fn send_request(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let line = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        }))
        .unwrap();
        self.write_line(&line);
        id
    }

    /// Send a request and return the very next output line, which must be its reply.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.send_request(method, params);
        let reply = self.next_line();
        assert_eq!(
            reply["id"], id,
            "the next line answers request {id}: {reply}"
        );
        reply
    }

    fn scan_source(&mut self, source: &str) -> Value {
        let response = self.request(
            "tools/call",
            json!({"name": "scan_source", "arguments": {"source": source, "path": "FAKE.luau"}}),
        );
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("tool result: {response:#}"));
        serde_json::from_str(text).expect("report JSON")
    }

    /// A valid request right after a probe is still served, and it is the next
    /// line, so the probe got no second reply.
    fn assert_still_serving(&mut self, label: &str) {
        let report = self.scan_source("require(999000000004140)");
        assert_eq!(report["completeness"], "complete", "{label}");
        assert_eq!(report["findings"][0]["rule_id"], "BG001", "{label}");
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

fn request_line(id: &str, method: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{}}}}"#).into_bytes()
}

#[test]
fn item14_invalid_ids_get_invalid_request_without_an_id() {
    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    for (label, id) in [
        // The reviewers' H35, R10 to R13 and M04, M06.
        ("object", r#"{"FAKE":1}"#),
        ("nested object", r#"{"a":[1,2]}"#),
        ("empty array", "[]"),
        ("array", r#"[1,"FAKE"]"#),
        ("true", "true"),
        ("false", "false"),
        ("null", "null"),
        ("fraction", "1.5"),
        ("whole fraction", "1.0"),
        ("exponent", "1e3"),
        ("negative zero", "-0"),
        ("i64 max plus one", "9223372036854775808"),
        ("i64 min minus one", "-9223372036854775809"),
        ("u64 max", "18446744073709551615"),
        ("2 to the 64", "18446744073709551616"),
        ("huge negative", "-92233720368547758090"),
    ] {
        for method in [
            "tools/list",
            "ping",
            "tools/call",
            "notifications/initialized",
        ] {
            cases.push((format!("{label} id on {method}"), request_line(id, method)));
        }
    }
    // A duplicated id member, whatever its values (M07).
    for (label, ids) in [
        ("two integer ids", r#""id":7,"id":8"#),
        ("the same id twice", r#""id":7,"id":7"#),
        ("two string ids", r#""id":"FAKE-a","id":"FAKE-b""#),
        ("a valid and an object id", r#""id":7,"id":{}"#),
        ("an escaped second id", r#""id":7,"\u0069d":8"#),
    ] {
        for method in ["tools/list", "ping"] {
            cases.push((
                format!("{label} on {method}"),
                format!(r#"{{"jsonrpc":"2.0",{ids},"method":"{method}"}}"#).into_bytes(),
            ));
        }
    }
    let mut server = McpProcess::start(&[]);
    for (label, line) in &cases {
        server.write_line(line);
        let reply = server.next_line();
        assert_eq!(reply["error"]["code"], -32600, "{label}: {reply}");
        assert!(reply.get("id").is_none(), "{label}: {reply}");
        assert!(
            reply["error"]["data"]
                .as_str()
                .is_some_and(|data| data.contains("request id")),
            "{label}: {reply}"
        );
        server.assert_still_serving(label);
    }
    assert!(cases.len() > 70, "{}", cases.len());
}

#[test]
fn item14_valid_ids_and_notifications_behave_as_before() {
    let mut server = McpProcess::start(&[]);
    for (raw, expected) in [
        ("0", json!(0)),
        ("-1", json!(-1)),
        ("9223372036854775807", json!(i64::MAX)),
        ("-9223372036854775808", json!(i64::MIN)),
        ("9007199254740993", json!(9_007_199_254_740_993_i64)),
        (r#""""#, json!("")),
        (r#""FAKE-id""#, json!("FAKE-id")),
        (r#""1.5""#, json!("1.5")),
        (r#""\u0046AKE""#, json!("FAKE")),
    ] {
        server.write_line(&request_line(raw, "ping"));
        let reply = server.next_line();
        assert_eq!(reply.get("id"), Some(&expected), "{raw}: {reply}");
        assert!(reply.get("result").is_some(), "{raw}: {reply}");
        // An unknown method with a valid id keeps its id on the -32601 reply.
        server.write_line(&request_line(raw, "FAKE/unknown"));
        let reply = server.next_line();
        assert_eq!(reply.get("id"), Some(&expected), "{raw}: {reply}");
        assert_eq!(reply["error"]["code"], -32601, "{raw}: {reply}");
    }
    // Notifications have no id member and still get no reply: the next line
    // answers the request after them.
    for notification in [
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"FAKE-none"}}"#,
        r#"{"jsonrpc":"2.0","method":"FAKE/custom","params":{"FAKE":1}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":"FAKE"}"#,
    ] {
        server.write_line(notification.as_bytes());
        server.assert_still_serving(notification);
    }
}

#[test]
fn item14_error_replies_do_not_repeat_long_request_text() {
    let root = tempfile::Builder::new()
        .prefix("bloxguard_FAKE_mcp_root_")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create repository-local temp directory");
    let mut server = McpProcess::start(&[root.path()]);
    let short = |text: &str, label: &str| {
        assert!(text.len() <= 300, "{label}: {} bytes", text.len());
        assert!(text.contains("... (cut from "), "{label}: {text}");
    };

    // A 10 MB method name (M37).
    let method = "m".repeat(10_000_000);
    let reply = server.request(&method, json!({}));
    assert_eq!(reply["error"]["code"], -32601);
    let message = reply["error"]["message"].as_str().unwrap();
    short(message, "method");
    assert!(message.starts_with(&"m".repeat(256)));
    assert!(message.ends_with("(cut from 10000000 bytes)"), "{message}");

    // A long unknown rule id, a long path outside the roots, and a long
    // unknown argument name.
    let rule = format!("FAKE{}", "R".repeat(4_000));
    let reply = server.request(
        "tools/call",
        json!({"name": "explain_rule", "arguments": {"id": rule}}),
    );
    short(reply["error"]["message"].as_str().unwrap(), "rule id");
    // Absolute on every platform, and outside the root.
    let outside = std::path::Path::new(if cfg!(windows) { r"C:\" } else { "/" })
        .join("FAKE_outside")
        .join("d".repeat(2_000))
        .join("FAKE.luau")
        .to_string_lossy()
        .into_owned();
    let reply = server.request(
        "tools/call",
        json!({"name": "scan_path", "arguments": {"path": outside}}),
    );
    short(reply["error"]["message"].as_str().unwrap(), "path");
    let mut arguments = serde_json::Map::new();
    arguments.insert("source".into(), json!("return 1"));
    arguments.insert(format!("FAKE{}", "k".repeat(1_000_000)), json!(1));
    let reply = server.request(
        "tools/call",
        json!({"name": "scan_source", "arguments": arguments}),
    );
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    short(
        reply["result"]["content"][0]["text"].as_str().unwrap(),
        "argument name",
    );

    // Short messages stay as they were.
    let reply = server.request(
        "tools/call",
        json!({"name": "explain_rule", "arguments": {"id": "FAKE999"}}),
    );
    assert_eq!(reply["error"]["message"], "unknown rule id: FAKE999");
    let reply = server.request("tools/call", json!({"name": "FAKE_tool", "arguments": {}}));
    assert_eq!(reply["error"]["message"], "tool not found");
    server.assert_still_serving("after long text");
}

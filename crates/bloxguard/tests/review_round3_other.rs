//! Review round 3 (fix round 4) item 10 through the real binary: every request
//! line the server cannot decode gets a JSON-RPC error reply, and the server
//! keeps serving. All payloads are synthetic.

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
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bloxguard"))
            .arg("mcp")
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
        server.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "bloxguard-test", "version": "0.1.0"}
            }),
        );
        server.write_line(br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#);
        server
    }

    fn write_line(&mut self, line: &[u8]) {
        let stdin = self.stdin.as_mut().expect("MCP stdin remains open");
        stdin.write_all(line).expect("write MCP line");
        stdin.write_all(b"\n").expect("write MCP newline");
        stdin.flush().expect("flush MCP line");
    }

    fn next_line(&self) -> Option<Value> {
        match self.lines.recv_timeout(REPLY_TIMEOUT) {
            Ok(Some(line)) => Some(serde_json::from_slice(&line).expect("reply is JSON")),
            Ok(None) | Err(RecvTimeoutError::Disconnected) => None,
            Err(RecvTimeoutError::Timeout) => panic!("no MCP output within {REPLY_TIMEOUT:?}"),
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let line = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        }))
        .unwrap();
        self.write_line(&line);
        loop {
            let message = self
                .next_line()
                .unwrap_or_else(|| panic!("server closed before replying to {id}"));
            if message.get("id") == Some(&json!(id)) {
                return message;
            }
        }
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

fn tool_call(id: &str, tool: &str, arguments: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments}}}}}"#
    )
    .into_bytes()
}

#[test]
fn round3_10_undecodable_requests_get_parse_errors_and_the_server_keeps_serving() {
    let deep = format!("{}{}", "[".repeat(50_000), "]".repeat(50_000));
    let mut invalid_utf8 = tool_call("904", "scan_source", r#"{"source":"FAKE"}"#);
    let at = invalid_utf8.len() - 4;
    invalid_utf8.splice(at..at, [0xc3, 0x28, 0xff]);
    let cases: Vec<(&str, Vec<u8>, i64, Option<Value>)> = vec![
        // The reviewer's two payloads.
        (
            "50,000 nested arrays",
            tool_call(
                "901",
                "scan_bundle",
                &format!(
                    r#"{{"bundle":{{"schema_version":1,"instances":[{{"name":"FAKE_R","class":"Model","attributes":{{"a":{deep}}}}}]}}}}"#
                ),
            ),
            -32700,
            Some(json!(901)),
        ),
        (
            "lone surrogate",
            tool_call("902", "scan_source", r#"{"source":"\ud800"}"#),
            -32700,
            Some(json!(902)),
        ),
        (
            "cut off",
            br#"{"jsonrpc":"2.0","id":903,"method":"tools/call","params":{"name":"scan_sou"#
                .to_vec(),
            -32700,
            Some(json!(903)),
        ),
        ("invalid UTF-8", invalid_utf8, -32700, Some(json!(904))),
        ("not JSON", b"FAKE not json".to_vec(), -32700, None),
        (
            "id after the nested value",
            format!(
                r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"scan_bundle","arguments":{{"bundle":{deep}}}}},"id":"FAKE-907"}}"#
            )
            .into_bytes(),
            -32700,
            Some(json!("FAKE-907")),
        ),
        (
            "JSON that is not a message",
            br#"{"FAKE":1}"#.to_vec(),
            -32600,
            None,
        ),
        (
            "bad params",
            br#"{"jsonrpc":"2.0","id":908,"method":"tools/call","params":"FAKE"}"#.to_vec(),
            -32600,
            Some(json!(908)),
        ),
    ];
    let mut server = McpProcess::start();
    for (label, line, code, id) in cases {
        server.write_line(&line);
        let reply = server
            .next_line()
            .unwrap_or_else(|| panic!("{label}: server closed"));
        assert_eq!(reply["error"]["code"], code, "{label}: {reply}");
        assert_eq!(reply.get("id"), id.as_ref(), "{label}: {reply}");
        // The next valid request is still served.
        let report = server.scan_source("return 1");
        assert_eq!(report["completeness"], "complete", "{label}");
    }
    // An echoed reply is dropped without a new reply: the next output line
    // belongs to the next request.
    server.write_line(br#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"}}"#);
    let report = server.scan_source("require(999000000004010)");
    assert_eq!(report["findings"][0]["rule_id"], "BG001");
}

#[test]
fn round3_10_oversized_requests_are_still_refused_and_close_the_server() {
    let mut server = McpProcess::start();
    let mut line = br#"{"jsonrpc":"2.0","id":911,"method":"ping","params":{"x":""#.to_vec();
    line.resize(64 * 1024 * 1024 + 1, b'x');
    // The server stops reading at the cap, so the rest of the write may fail.
    if let Some(stdin) = server.stdin.as_mut() {
        let _ = stdin.write_all(&line);
        let _ = stdin.write_all(b"\n");
        let _ = stdin.flush();
    }
    let reply = server
        .next_line()
        .expect("a reply before the server closes");
    assert_eq!(reply["id"], 911);
    assert_eq!(reply["error"]["code"], -32600);
    assert_eq!(reply["error"]["message"], "Request too large");
    assert!(server.next_line().is_none(), "the server closes stdout");
    let status = server.child.wait().expect("server exits");
    assert!(status.success(), "{status:?}");
}

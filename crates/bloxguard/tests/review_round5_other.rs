//! Review round 5 (fix round 6) item 8 through the real binary: MCP request
//! ids are strings or integers that fit in a signed 64 bit integer, and the
//! error says so. All payloads are synthetic.

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{Receiver, RecvTimeoutError, channel},
    thread,
    time::Duration,
};

use serde_json::{Value, json};

const REPLY_TIMEOUT: Duration = Duration::from_secs(60);
const INVALID_ID: &str =
    "a request id must be a string or an integer that fits in a signed 64 bit integer, given once";

struct McpProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<Option<Vec<u8>>>,
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
        };
        server.write_line(
            &serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": "FAKE_init", "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "bloxguard-test", "version": "0.1.0"}
                }
            }))
            .unwrap(),
        );
        assert_eq!(server.next_line()["id"], "FAKE_init");
        server.write_line(br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#);
        server
    }

    fn write_line(&mut self, line: &[u8]) {
        let stdin = self.stdin.as_mut().expect("MCP stdin remains open");
        stdin.write_all(line).expect("write MCP line");
        stdin.write_all(b"\n").expect("write MCP newline");
        stdin.flush().expect("flush MCP line");
    }

    fn next_line(&self) -> Value {
        match self.lines.recv_timeout(REPLY_TIMEOUT) {
            Ok(Some(line)) => serde_json::from_slice(&line).expect("reply is JSON"),
            Ok(None) | Err(RecvTimeoutError::Disconnected) => panic!("server closed stdout"),
            Err(RecvTimeoutError::Timeout) => panic!("no MCP output within {REPLY_TIMEOUT:?}"),
        }
    }

    fn ping(&mut self, id: &str) -> Value {
        self.write_line(format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#).as_bytes());
        self.next_line()
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
fn item8_ids_are_strings_or_signed_64_bit_integers() {
    let mut server = McpProcess::start();
    for (raw, id) in [
        ("9223372036854775807", json!(i64::MAX)),
        ("-9223372036854775808", json!(i64::MIN)),
        ("0", json!(0)),
        ("\"FAKE\"", json!("FAKE")),
    ] {
        let reply = server.ping(raw);
        assert_eq!(reply["id"], id, "{raw}: {reply}");
        assert!(reply.get("result").is_some(), "{raw}: {reply}");
    }
    // Unsigned 64 bit values above i64, an exponent, and `-0`, which the
    // decoder reads as a fraction, are refused with the documented text.
    for raw in ["9223372036854775808", "18446744073709551615", "1e2", "-0"] {
        let reply = server.ping(raw);
        assert!(reply.get("id").is_none(), "{raw}: {reply}");
        assert_eq!(reply["error"]["code"], -32600, "{raw}: {reply}");
        assert_eq!(reply["error"]["data"], INVALID_ID, "{raw}: {reply}");
    }
    // The server still answers afterwards.
    assert_eq!(server.ping("\"FAKE_after\"")["id"], "FAKE_after");
}

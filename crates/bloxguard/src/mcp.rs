//! Read-only MCP integration over stdio.
//!
//! File-backed tools are confined to the roots supplied on the command line.
//! Source and bundle tools only inspect their request payloads and never touch
//! the file system.

use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use bloxguard_core::{
    config::Config,
    engine::{inventory_documents, scan_documents},
    loading::{load_bundle, load_path, load_source},
    model::{Bundle, Limits},
    rules::rule,
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        ContentBlock, Implementation, JsonRpcError, JsonRpcMessage, JsonRpcResponse, RequestId,
        ServerCapabilities, ServerConfig, ServerResult,
    },
    schemars,
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    tool, tool_handler, tool_router,
    transport::Transport,
};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinHandle;

const MAX_MCP_REQUEST_BYTES: usize = 8 * 1024 * 1024;
// JSON escaping can make a valid decoded request several times larger on the
// wire. This cap is applied while a line is read, before it is decoded.
const MAX_MCP_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_LABEL_BYTES: usize = 4 * 1024;
const MAX_CONCURRENT_SCANS: usize = 2;
/// Error replies for bad lines that may wait for the writer at one time. A peer
/// that sends bad lines without reading the replies is slowed down instead of
/// growing a queue.
const MAX_PENDING_REPLIES: usize = 64;
/// Bytes of an error message, string error data or tool error text that a
/// reply keeps. These can repeat request text such as a method name.
const MAX_ERROR_TEXT_BYTES: usize = 256;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PathRequest {
    /// Absolute path to a supported file or source directory inside an allowed root.
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RuleRequest {
    /// Rule id such as BG001.
    id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SourceRequest {
    /// Luau source text. It is parsed and never executed.
    source: String,
    /// Display path used in findings. This does not grant file access.
    #[serde(default)]
    path: Option<String>,
    /// Roblox script class. Defaults to ModuleScript.
    #[serde(default)]
    class: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct BundleRequest {
    /// A bloxguard bundle object with schema_version and a flat instances array.
    bundle: Value,
}

#[derive(Debug, Clone)]
struct BloxguardMcp {
    roots: Arc<Vec<PathBuf>>,
    limits: Limits,
    scans: Arc<Semaphore>,
    tool_router: ToolRouter<Self>,
}

impl BloxguardMcp {
    fn new(roots: Vec<PathBuf>) -> Result<Self, Box<dyn std::error::Error>> {
        let roots = canonicalize_roots(roots)?;
        Ok(Self {
            roots: Arc::new(roots),
            limits: Limits::default(),
            scans: Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS)),
            tool_router: Self::tool_router(),
        })
    }

    async fn scan_file_request(&self, path: String, inventory: bool) -> Result<String, ErrorData> {
        let roots = Arc::clone(&self.roots);
        let limits = self.limits.clone();
        let permit = Arc::clone(&self.scans)
            .acquire_owned()
            .await
            .map_err(|_| ErrorData::internal_error("scan worker is unavailable", None))?;

        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let allowed = validate_requested_path(&path, &roots, limits.max_instances)?;
            let documents = load_path(&allowed, &limits);
            let report = if inventory {
                inventory_documents(documents)
            } else {
                scan_documents(documents, &Config::default())
            };
            report_json(&report)
        })
        .await
        .map_err(|_| ErrorData::internal_error("scan worker stopped unexpectedly", None))?
        .map_err(|message| ErrorData::invalid_params(message, None))
    }
}

#[tool_router]
impl BloxguardMcp {
    /// Scan a supported file or Luau source directory inside an allowed root.
    /// Never execute scanned content. If findings are returned, show them to the
    /// user and do not keep the flagged inserted content until it is reviewed.
    #[tool(
        name = "scan_path",
        annotations(
            title = "Scan a path",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn scan_path(
        &self,
        Parameters(PathRequest { path }): Parameters<PathRequest>,
    ) -> Result<String, ErrorData> {
        self.scan_file_request(path, false).await
    }

    /// List scripts, classes, enabled state, sizes and hashes for a supported
    /// file or source directory inside an allowed root. Review the inventory
    /// before opening unfamiliar content in Studio.
    #[tool(
        name = "inventory",
        annotations(
            title = "Inventory a path",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn inventory(
        &self,
        Parameters(PathRequest { path }): Parameters<PathRequest>,
    ) -> Result<String, ErrorData> {
        self.scan_file_request(path, true).await
    }

    /// Return the metadata and guidance for one bloxguard rule. Use it to
    /// explain a finding to the user. Do not accuse a creator or uploader.
    #[tool(
        name = "explain_rule",
        annotations(
            title = "Explain a rule",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn explain_rule(
        &self,
        Parameters(RuleRequest { id }): Parameters<RuleRequest>,
    ) -> Result<String, ErrorData> {
        if id.len() > MAX_LABEL_BYTES {
            return Err(ErrorData::invalid_params("rule id is too long", None));
        }
        let normalized = id.trim().to_ascii_uppercase();
        let found = rule(&normalized).ok_or_else(|| {
            ErrorData::invalid_params(format!("unknown rule id: {normalized}"), None)
        })?;
        to_json(found).map_err(|message| ErrorData::internal_error(message, None))
    }

    /// Scan Luau text supplied in this request. The path is only a display
    /// label and is never read. Never execute the source. If findings are
    /// returned, show them to the user and remove or quarantine flagged inserted
    /// content until it is reviewed.
    #[tool(
        name = "scan_source",
        annotations(
            title = "Scan Luau source",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn scan_source(
        &self,
        Parameters(SourceRequest {
            source,
            path,
            class,
        }): Parameters<SourceRequest>,
    ) -> Result<String, ErrorData> {
        let path = path.unwrap_or_else(|| "mcp/source.luau".to_owned());
        let class = class.unwrap_or_else(|| "ModuleScript".to_owned());
        check_text_request(&source, &path, &class, self.limits.max_script_bytes)?;

        let limits = self.limits.clone();
        let permit = Arc::clone(&self.scans)
            .acquire_owned()
            .await
            .map_err(|_| ErrorData::internal_error("scan worker is unavailable", None))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let document = load_source(&source, &path, &class, &limits);
            report_json(&scan_documents(vec![document], &Config::default()))
        })
        .await
        .map_err(|_| ErrorData::internal_error("scan worker stopped unexpectedly", None))?
        .map_err(|message| ErrorData::internal_error(message, None))
    }

    /// Scan a JSON snapshot supplied in this request. This tool never reads the
    /// file system. Never execute any source in the bundle. Show findings to the
    /// user and do not keep flagged inserted content until it is reviewed.
    #[tool(
        name = "scan_bundle",
        annotations(
            title = "Scan an instance bundle",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn scan_bundle(
        &self,
        Parameters(BundleRequest { bundle }): Parameters<BundleRequest>,
    ) -> Result<String, ErrorData> {
        let encoded = serde_json::to_vec(&bundle)
            .map_err(|_| ErrorData::invalid_params("bundle is not valid JSON", None))?;
        if encoded.len() > MAX_MCP_REQUEST_BYTES {
            return Err(ErrorData::invalid_params(
                format!("bundle exceeds the {MAX_MCP_REQUEST_BYTES} byte MCP request limit"),
                None,
            ));
        }
        let bundle: Bundle = serde_json::from_value(bundle)
            .map_err(|error| ErrorData::invalid_params(format!("invalid bundle: {error}"), None))?;
        if bundle.instances.len() > self.limits.max_instances {
            return Err(ErrorData::invalid_params(
                format!(
                    "bundle exceeds the {} instance limit",
                    self.limits.max_instances
                ),
                None,
            ));
        }
        if bundle.instances.iter().any(|instance| {
            instance
                .source
                .as_ref()
                .is_some_and(|source| source.len() > self.limits.max_script_bytes)
        }) {
            return Err(ErrorData::invalid_params(
                format!(
                    "bundle contains source over the {} byte script limit",
                    self.limits.max_script_bytes
                ),
                None,
            ));
        }

        let limits = self.limits.clone();
        let permit = Arc::clone(&self.scans)
            .acquire_owned()
            .await
            .map_err(|_| ErrorData::internal_error("scan worker is unavailable", None))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let document = load_bundle(bundle, "mcp/bundle", &limits);
            report_json(&scan_documents(vec![document], &Config::default()))
        })
        .await
        .map_err(|_| ErrorData::internal_error("scan worker stopped unexpectedly", None))?
        .map_err(|message| ErrorData::internal_error(message, None))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for BloxguardMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("bloxguard", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Read-only, offline Roblox security scanning. Scanned source is parsed and never \
                 executed. File tools can only read inside configured roots. Show findings to the \
                 user. Do not keep flagged inserted content until it is reviewed. Do not accuse \
                 creators or uploaders.",
            )
    }
}

/// Serve the read-only MCP protocol on stdin and stdout.
pub async fn serve(roots: Vec<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let transport =
        LineTransport::new(tokio::io::stdin(), tokio::io::stdout(), MAX_MCP_FRAME_BYTES);
    let service = BloxguardMcp::new(roots)?.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}

/// Newline framed JSON-RPC over a reader and a writer, as rmcp's own stdio
/// transport frames it, with two differences:
///
/// - A line longer than the frame cap is refused while it is read, so the
///   buffer never grows past the cap. The server answers it and then closes
///   the transport.
/// - A line that does not decode as a message gets a JSON-RPC error reply:
///   `-32700` when it is not JSON (cut off, too deeply nested, invalid UTF-8,
///   a lone surrogate) and `-32600` when it is JSON but not a message. rmcp
///   drops the first kind silently, which leaves a client waiting for its own
///   timeout. A notification (an object with a string `method` and no `id`)
///   that is JSON but not a valid message gets no reply, because JSON-RPC
///   never answers notifications. A line with an `id` member is never a
///   notification: when rmcp refuses its id and reads it as one anyway, it
///   gets `-32600` too.
///
/// The reply carries the request id when a shallow scan of the line can read
/// one, so the client can fail that request at once. Otherwise the id is
/// omitted, as the MCP specification asks for an unreadable id. Replies are
/// valid error messages, so a peer that echoes them back gets no further reply.
/// Every error reply, also the ones rmcp writes, keeps at most
/// `MAX_ERROR_TEXT_BYTES` of each text it could repeat from the request.
struct LineTransport<R, W> {
    reader: BufReader<R>,
    line: Vec<u8>,
    max_line_bytes: usize,
    writer: Arc<Mutex<Option<W>>>,
    replies: VecDeque<JoinHandle<()>>,
}

const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// What one complete line turned out to be.
#[derive(Debug)]
enum Decoded {
    Message(Box<RxJsonRpcMessage<RoleServer>>),
    Skip,
    Reply(Box<TxJsonRpcMessage<RoleServer>>),
}

enum LineRead {
    Line,
    End,
    TooLong,
}

impl<R, W> LineTransport<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    fn new(reader: R, writer: W, max_line_bytes: usize) -> Self {
        Self {
            reader: BufReader::new(reader),
            line: Vec::new(),
            max_line_bytes,
            writer: Arc::new(Mutex::new(Some(writer))),
            replies: VecDeque::new(),
        }
    }

    /// Append input to `self.line` up to and including the next newline.
    ///
    /// This is cancellation safe, which rmcp needs because it polls `receive`
    /// inside `select!`: bytes move from the reader buffer into `self.line`
    /// without an await in between, so a dropped call loses nothing and the
    /// next call resumes the same line.
    async fn read_line(&mut self) -> std::io::Result<LineRead> {
        loop {
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(LineRead::End);
            }
            let (take, complete) = match available.iter().position(|&byte| byte == b'\n') {
                Some(newline) => (newline + 1, true),
                None => (available.len(), false),
            };
            let content = if complete { take - 1 } else { take };
            if self.line.len().saturating_add(content) > self.max_line_bytes {
                // Keep the start of the line up to the cap, so the reply can name its id.
                let room = self.max_line_bytes.saturating_sub(self.line.len());
                self.line.extend_from_slice(&available[..room]);
                self.reader.consume(room);
                return Ok(LineRead::TooLong);
            }
            self.line.extend_from_slice(&available[..take]);
            self.reader.consume(take);
            if complete {
                return Ok(LineRead::Line);
            }
        }
    }

    /// Write a reply from its own task, so a cancelled `receive` can never
    /// leave half a line on the output.
    fn queue_reply(&mut self, reply: TxJsonRpcMessage<RoleServer>) {
        let writer = Arc::clone(&self.writer);
        let reply = cap_error_text(reply);
        self.replies.push_back(tokio::spawn(async move {
            let _ = write_message(&writer, &reply).await;
        }));
    }

    async fn finish_replies(&mut self) {
        while let Some(reply) = self.replies.front_mut() {
            let _ = reply.await;
            self.replies.pop_front();
        }
    }
}

/// Shorten the text an error reply can repeat from its request: the message
/// and a string `data` of a JSON-RPC error, and the text of a tool error
/// result. rmcp names an unknown method in its `-32601` message and serde names
/// an unknown argument in a tool error, so without this a 10 MB method name
/// comes back in full.
fn cap_error_text(mut message: TxJsonRpcMessage<RoleServer>) -> TxJsonRpcMessage<RoleServer> {
    match &mut message {
        JsonRpcMessage::Error(JsonRpcError { error, .. }) => {
            if let Some(capped) = capped_text(&error.message) {
                error.message = capped.into();
            }
            if let Some(Value::String(data)) = error.data.as_mut()
                && let Some(capped) = capped_text(data)
            {
                *data = capped;
            }
        }
        JsonRpcMessage::Response(JsonRpcResponse {
            result: ServerResult::CallToolResult(result),
            ..
        }) if result.is_error == Some(true) => {
            for block in &mut result.content {
                if let ContentBlock::Text(text) = block
                    && let Some(capped) = capped_text(&text.text)
                {
                    text.text = capped;
                }
            }
        }
        _ => {}
    }
    message
}

/// The first `MAX_ERROR_TEXT_BYTES` of a longer text, cut at a character
/// boundary, with the full length after it.
fn capped_text(text: &str) -> Option<String> {
    if text.len() <= MAX_ERROR_TEXT_BYTES {
        return None;
    }
    let mut end = MAX_ERROR_TEXT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Some(format!(
        "{}... (cut from {} bytes)",
        &text[..end],
        text.len()
    ))
}

async fn write_message<W: AsyncWrite + Unpin>(
    writer: &Mutex<Option<W>>,
    message: &TxJsonRpcMessage<RoleServer>,
) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(message).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut guard = writer.lock().await;
    let Some(writer) = guard.as_mut() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "MCP transport is closed",
        ));
    };
    writer.write_all(&line).await?;
    writer.flush().await
}

impl<R, W> Transport<RoleServer> for LineTransport<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = std::io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let writer = Arc::clone(&self.writer);
        let item = cap_error_text(item);
        async move { write_message(&writer, &item).await }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        loop {
            while self.replies.front().is_some_and(JoinHandle::is_finished) {
                self.replies.pop_front();
            }
            if self.replies.len() >= MAX_PENDING_REPLIES {
                if let Some(reply) = self.replies.front_mut() {
                    let _ = reply.await;
                }
                self.replies.pop_front();
                continue;
            }
            match self.read_line().await {
                Ok(LineRead::Line) => {}
                // A trailing line without a newline is incomplete, as in rmcp.
                Ok(LineRead::End) | Err(_) => {
                    self.finish_replies().await;
                    return None;
                }
                Ok(LineRead::TooLong) => {
                    let id = scan_line_shape(&self.line).id;
                    self.line.clear();
                    self.queue_reply(TxJsonRpcMessage::<RoleServer>::error(
                        ErrorData::invalid_request(
                            "Request too large",
                            Some(Value::String(format!(
                                "MCP request exceeds the {} byte frame limit; the server closes the connection",
                                self.max_line_bytes
                            ))),
                        ),
                        id,
                    ));
                    self.finish_replies().await;
                    return None;
                }
            }
            let decoded = decode_line(&self.line);
            self.line.clear();
            match decoded {
                Decoded::Message(message) => return Some(*message),
                Decoded::Skip => {}
                Decoded::Reply(reply) => self.queue_reply(*reply),
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.finish_replies().await;
        drop(self.writer.lock().await.take());
        Ok(())
    }
}

/// Decode one line including its newline, the same way rmcp does for every
/// line that is a message.
fn decode_line(raw: &[u8]) -> Decoded {
    let line = raw.strip_suffix(b"\n").unwrap_or(raw);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let line = line.strip_prefix(UTF8_BOM).unwrap_or(line);
    if line.iter().all(u8::is_ascii_whitespace) {
        return Decoded::Skip;
    }
    let error = match serde_json::from_slice::<RxJsonRpcMessage<RoleServer>>(line) {
        // rmcp reads a request whose id it refuses (an object, an array, a
        // boolean, null, a fraction, an integer outside i64, or a second id)
        // as a notification, and never answers it. A line with an `id` member
        // is not a notification, so it gets an error instead.
        Ok(JsonRpcMessage::Notification(notification)) => {
            let shape = scan_line_shape(line);
            if !shape.has_id {
                return Decoded::Message(Box::new(JsonRpcMessage::Notification(notification)));
            }
            let detail = if shape.id.is_some() {
                "the line has an id but is not a valid request"
            } else {
                INVALID_ID
            };
            return invalid_request(detail.to_owned(), shape.id);
        }
        Ok(message) => return Decoded::Message(Box::new(message)),
        Err(error) => error,
    };
    let shape = scan_line_shape(line);
    match error.classify() {
        serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
            Decoded::Reply(Box::new(TxJsonRpcMessage::<RoleServer>::error(
                ErrorData::parse_error("Parse error", Some(Value::String(error.to_string()))),
                shape.id,
            )))
        }
        serde_json::error::Category::Data | serde_json::error::Category::Io => {
            if shape.is_notification() {
                return Decoded::Skip;
            }
            let detail = if shape.has_id && shape.id.is_none() {
                INVALID_ID.to_owned()
            } else {
                error.to_string()
            };
            invalid_request(detail, shape.id)
        }
    }
}

/// Why a line with an `id` member gets an error reply without an id.
const INVALID_ID: &str =
    "a request id must be a string or an integer that fits in a signed 64 bit integer, given once";

fn invalid_request(detail: String, id: Option<RequestId>) -> Decoded {
    Decoded::Reply(Box::new(TxJsonRpcMessage::<RoleServer>::error(
        ErrorData::invalid_request("Invalid request", Some(Value::String(detail))),
        id,
    )))
}

/// The top-level members of a request line that matter for an error reply.
#[derive(Debug, Default, PartialEq)]
struct LineShape {
    /// A readable string or integer `id`, when there is exactly one.
    id: Option<RequestId>,
    /// An `id` member was seen, whatever its value.
    has_id: bool,
    /// A `method` member with a string value was seen.
    has_string_method: bool,
}

impl LineShape {
    fn is_notification(&self) -> bool {
        self.has_string_method && !self.has_id
    }
}

/// Read the members of a top-level JSON object without decoding nested
/// values. Nested arrays and objects are skipped with a depth counter and
/// strings are skipped without decoding, so this works on lines that a full
/// decoder refuses (too deep, invalid UTF-8, lone surrogates, cut off) and
/// never recurses. A member counts only when a `,` or `}` follows its value,
/// so a value cut off at the end of the line is never read. A second `id`
/// member makes the id unreadable. The cost is linear in the line length.
fn scan_line_shape(line: &[u8]) -> LineShape {
    let mut shape = LineShape::default();
    let mut id_members = 0usize;
    let mut position = skip_json_whitespace(line, 0);
    if line.get(position) != Some(&b'{') {
        return shape;
    }
    position += 1;
    loop {
        position = skip_json_whitespace(line, position);
        if line.get(position) != Some(&b'"') {
            break;
        }
        let Some(key_end) = json_string_end(line, position) else {
            break;
        };
        let key = &line[position..key_end];
        position = skip_json_whitespace(line, key_end);
        if line.get(position) != Some(&b':') {
            break;
        }
        let value_start = skip_json_whitespace(line, position + 1);
        let Some(value_end) = json_value_end(line, value_start) else {
            break;
        };
        let value = &line[value_start..value_end];
        position = skip_json_whitespace(line, value_end);
        let Some(&separator) = line
            .get(position)
            .filter(|byte| matches!(byte, b',' | b'}'))
        else {
            break;
        };
        match json_key(key).as_deref() {
            Some("id") => {
                id_members += 1;
                shape.has_id = true;
                shape.id = if id_members == 1 {
                    request_id(value)
                } else {
                    None
                };
            }
            Some("method") => {
                shape.has_string_method = serde_json::from_slice::<String>(value).is_ok();
            }
            _ => {}
        }
        if separator == b'}' {
            break;
        }
        position += 1;
    }
    shape
}

fn skip_json_whitespace(line: &[u8], mut position: usize) -> usize {
    while line
        .get(position)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
    {
        position += 1;
    }
    position
}

/// End (exclusive) of the string that starts with the quote at `start`.
fn json_string_end(line: &[u8], start: usize) -> Option<usize> {
    let mut position = start + 1;
    while let Some(&byte) = line.get(position) {
        match byte {
            b'"' => return Some(position + 1),
            b'\\' => position += 2,
            _ => position += 1,
        }
    }
    None
}

/// End (exclusive) of the value that starts at `start`, without validating it.
fn json_value_end(line: &[u8], start: usize) -> Option<usize> {
    match line.get(start)? {
        b'"' => json_string_end(line, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut position = start;
            while let Some(&byte) = line.get(position) {
                match byte {
                    b'"' => {
                        position = json_string_end(line, position)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(position + 1);
                        }
                    }
                    _ => {}
                }
                position += 1;
            }
            None
        }
        _ => {
            let end = line[start..]
                .iter()
                .position(|byte| matches!(byte, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r'))
                .map_or(line.len(), |offset| start + offset);
            (end > start).then_some(end)
        }
    }
}

fn json_key(key: &[u8]) -> Option<String> {
    match key
        .strip_prefix(b"\"")
        .and_then(|key| key.strip_suffix(b"\""))
    {
        Some(plain) if !plain.contains(&b'\\') => String::from_utf8(plain.to_vec()).ok(),
        _ => serde_json::from_slice(key).ok(),
    }
}

/// An MCP request id: a string or an integer. `null` and other values are not ids.
fn request_id(value: &[u8]) -> Option<RequestId> {
    if value.first() == Some(&b'"') {
        let text: String = serde_json::from_slice(value).ok()?;
        Some(RequestId::String(text.into()))
    } else {
        serde_json::from_slice::<i64>(value)
            .ok()
            .map(RequestId::Number)
    }
}

fn check_text_request(
    source: &str,
    path: &str,
    class: &str,
    max_script_bytes: usize,
) -> Result<(), ErrorData> {
    let max_source = max_script_bytes.min(MAX_MCP_REQUEST_BYTES);
    if source.len() > max_source {
        return Err(ErrorData::invalid_params(
            format!("source exceeds the {max_source} byte MCP request limit"),
            None,
        ));
    }
    if path.len() > MAX_LABEL_BYTES || class.len() > MAX_LABEL_BYTES {
        return Err(ErrorData::invalid_params(
            format!("path and class labels must be at most {MAX_LABEL_BYTES} bytes"),
            None,
        ));
    }
    Ok(())
}

fn to_json<T: serde::Serialize + ?Sized>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map_err(|error| format!("could not serialize result: {error}"))
}

fn report_json(report: &bloxguard_core::report::ScanReport) -> Result<String, String> {
    bloxguard_core::output::json(report)
        .map_err(|error| format!("could not serialize result: {error}"))
}

fn canonicalize_roots(roots: Vec<PathBuf>) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut canonical = Vec::with_capacity(roots.len());
    for root in roots {
        if !root.is_absolute() {
            return Err(format!("MCP root must be absolute: {}", root.display()).into());
        }
        reject_network_path(&root)
            .map_err(|message| -> Box<dyn std::error::Error> { message.into() })?;
        let metadata = fs::symlink_metadata(&root)?;
        if is_link_or_reparse(&metadata) {
            return Err(format!(
                "MCP root must not be a symbolic link or junction: {}",
                root.display()
            )
            .into());
        }
        let root = fs::canonicalize(&root)?;
        reject_network_path(&root)
            .map_err(|message| -> Box<dyn std::error::Error> { message.into() })?;
        if !root.is_dir() {
            return Err(format!("MCP root is not a directory: {}", root.display()).into());
        }
        canonical.push(root);
    }
    canonical.sort();
    canonical.dedup();
    Ok(canonical)
}

fn validate_requested_path(
    raw: &str,
    roots: &[PathBuf],
    max_entries: usize,
) -> Result<PathBuf, String> {
    let requested = requested_path_before_io(raw, roots)?;
    validate_requested_path_after_preflight(requested, roots, max_entries)
}

/// Every check here is lexical: nothing touches the file system, so a path
/// outside the roots gets the same answer whether or not it exists.
///
/// The result is the matching canonical root joined with the requested
/// components below it, so later file calls never name a path outside a root.
fn requested_path_before_io(raw: &str, roots: &[PathBuf]) -> Result<PathBuf, String> {
    if roots.is_empty() {
        return Err("file access is disabled because no MCP roots were configured".to_owned());
    }
    if raw.len() > MAX_LABEL_BYTES {
        return Err(format!("path must be at most {MAX_LABEL_BYTES} bytes"));
    }
    let requested = PathBuf::from(raw);
    if !requested.is_absolute() {
        return Err("path must be absolute".to_owned());
    }
    reject_non_disk_prefix(&requested)?;
    confine_lexically(&requested, roots)
}

/// One normalized path element used for the lexical root comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LexicalPart {
    /// A drive such as `C:`, the same for `C:\` and `\\?\C:\`.
    Drive(u8),
    Root,
    Name(std::ffi::OsString),
}

fn lexical_parts(path: &Path) -> Result<Vec<LexicalPart>, String> {
    use std::path::Component;

    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                parts.push(LexicalPart::Drive(disk_letter(prefix.kind())?))
            }
            Component::RootDir => parts.push(LexicalPart::Root),
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(parts.last(), Some(LexicalPart::Name(_))) {
                    parts.pop();
                }
            }
            Component::Normal(name) => {
                check_component(name, path)?;
                parts.push(LexicalPart::Name(name.to_owned()));
            }
        }
    }
    Ok(parts)
}

#[cfg(windows)]
fn disk_letter(prefix: std::path::Prefix<'_>) -> Result<u8, String> {
    use std::path::Prefix;
    match prefix {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Ok(letter.to_ascii_uppercase()),
        _ => Err("only disk and verbatim disk prefixes are allowed".to_owned()),
    }
}

#[cfg(not(windows))]
fn disk_letter(_prefix: std::path::Prefix<'_>) -> Result<u8, String> {
    Err("path prefixes are not supported on this platform".to_owned())
}

/// Windows rewrites some names before opening them: it drops trailing dots and
/// spaces, and `:` selects an alternate data stream. A verbatim path can also
/// hide `/` inside one component. Such names are refused so the lexical check
/// and the opened path cannot disagree.
#[cfg(windows)]
fn check_component(name: &std::ffi::OsStr, path: &Path) -> Result<(), String> {
    let text = name.to_string_lossy();
    if text.contains([':', '/']) || text.ends_with(['.', ' ']) {
        return Err(format!(
            "path components must not contain ':' or '/' or end with a dot or space: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn check_component(_name: &std::ffi::OsStr, _path: &Path) -> Result<(), String> {
    Ok(())
}

/// Windows file names compare without regard to case; other systems compare
/// them exactly.
fn same_part(root: &LexicalPart, requested: &LexicalPart) -> bool {
    match (root, requested) {
        (LexicalPart::Name(root), LexicalPart::Name(requested)) if cfg!(windows) => {
            root.to_string_lossy().to_lowercase() == requested.to_string_lossy().to_lowercase()
        }
        _ => root == requested,
    }
}

fn confine_lexically(requested: &Path, roots: &[PathBuf]) -> Result<PathBuf, String> {
    let requested_parts = lexical_parts(requested)?;
    for root in roots {
        let Ok(root_parts) = lexical_parts(root) else {
            continue;
        };
        if requested_parts.len() >= root_parts.len()
            && root_parts
                .iter()
                .zip(&requested_parts)
                .all(|(root_part, part)| same_part(root_part, part))
        {
            let mut confined = root.clone();
            for part in &requested_parts[root_parts.len()..] {
                if let LexicalPart::Name(name) = part {
                    confined.push(name);
                }
            }
            return Ok(confined);
        }
    }
    Err(outside_roots_message(requested))
}

fn outside_roots_message(path: &Path) -> String {
    format!(
        "path is outside the configured MCP roots: {}",
        path.display()
    )
}

fn validate_requested_path_after_preflight(
    requested: PathBuf,
    roots: &[PathBuf],
    max_entries: usize,
) -> Result<PathBuf, String> {
    reject_network_path(&requested)?;
    // Walk down from the root so no metadata call follows a link out of it.
    let root = roots
        .iter()
        .find(|root| requested.starts_with(root))
        .ok_or_else(|| outside_roots_message(&requested))?;
    let below_root = requested
        .strip_prefix(root)
        .map_err(|_| outside_roots_message(&requested))?;
    let mut current = root.clone();
    let mut metadata = fs::symlink_metadata(&current)
        .map_err(|error| format!("cannot inspect path {}: {error}", current.display()))?;
    for name in below_root.components() {
        if !metadata.is_dir() {
            return Err(format!("not a directory: {}", current.display()));
        }
        current.push(name);
        metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("cannot inspect path {}: {error}", current.display()))?;
        if is_link_or_reparse(&metadata) {
            return Err(format!(
                "symbolic links and junctions are not accepted for MCP file access: {}",
                current.display()
            ));
        }
    }
    let canonical = fs::canonicalize(&requested)
        .map_err(|error| format!("cannot access path {}: {error}", requested.display()))?;
    reject_network_path(&canonical)?;
    ensure_inside_roots(&canonical, roots)?;
    validate_descendants(&canonical, roots, max_entries)?;
    Ok(canonical)
}

fn validate_descendants(path: &Path, roots: &[PathBuf], max_entries: usize) -> Result<(), String> {
    if !path.is_dir() {
        return Ok(());
    }
    let mut pending = vec![path.to_path_buf()];
    let mut seen = 0usize;
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|error| {
            format!("cannot inspect directory {}: {error}", directory.display())
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "cannot inspect an entry under {}: {error}",
                    directory.display()
                )
            })?;
            seen = seen.saturating_add(1);
            if seen > max_entries {
                return Err(format!(
                    "path contains more than {max_entries} entries and cannot be safely confined"
                ));
            }
            let entry_path = entry.path();
            let metadata = fs::symlink_metadata(&entry_path).map_err(|error| {
                format!("cannot inspect path {}: {error}", entry_path.display())
            })?;
            if is_link_or_reparse(&metadata) {
                return Err(format!(
                    "symbolic links and junctions are not accepted for MCP file access: {}",
                    entry_path.display()
                ));
            }
            let resolved = fs::canonicalize(&entry_path).map_err(|error| {
                format!("cannot resolve path {}: {error}", entry_path.display())
            })?;
            reject_network_path(&resolved)?;
            ensure_inside_roots(&resolved, roots)?;

            if metadata.is_dir() {
                pending.push(resolved);
            }
        }
    }
    Ok(())
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn ensure_inside_roots(path: &Path, roots: &[PathBuf]) -> Result<(), String> {
    if roots.iter().any(|root| path.starts_with(root)) {
        Ok(())
    } else {
        Err(format!(
            "path is outside the configured MCP roots: {}",
            path.display()
        ))
    }
}

/// The lexical part of the network check: only `C:\` and `\\?\C:\` style
/// prefixes are accepted. It makes no system call.
#[cfg(windows)]
fn reject_non_disk_prefix(path: &Path) -> Result<u8, String> {
    use std::path::{Component, Prefix};

    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Ok(letter),
            _ => Err(format!(
                "only disk and verbatim disk prefixes are allowed: {}",
                path.display()
            )),
        },
        _ => Err("a local disk path prefix is required".into()),
    }
}

#[cfg(windows)]
fn reject_network_path(path: &Path) -> Result<(), String> {
    let letter = reject_non_disk_prefix(path)?;
    reject_remote_drive(letter, path)
}

#[cfg(windows)]
fn reject_remote_drive(letter: u8, path: &Path) -> Result<(), String> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDriveTypeW(root_path_name: *const u16) -> u32;
    }

    const DRIVE_REMOTE: u32 = 4;
    let root = [
        u16::from(letter.to_ascii_uppercase()),
        u16::from(b':'),
        u16::from(b'\\'),
        0,
    ];
    // SAFETY: `root` is a NUL-terminated UTF-16 drive root and remains alive
    // for the duration of this read-only Windows API call.
    let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
    if drive_type == DRIVE_REMOTE {
        Err(format!(
            "remote drives are not allowed for MCP file access: {}",
            path.display()
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn reject_network_path(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(not(windows))]
fn reject_non_disk_prefix(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod root_tests {
    use super::*;

    struct Fixture {
        _temp: tempfile::TempDir,
        allowed: PathBuf,
        outside: PathBuf,
        roots: Vec<PathBuf>,
    }

    fn fixture() -> Fixture {
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("mcp-tests");
        fs::create_dir_all(&parent).expect("create repository-local test parent");
        let temp = tempfile::Builder::new()
            .prefix("root-")
            .tempdir_in(&parent)
            .expect("create repository-local temp directory");
        let allowed = temp.path().join("allowed");
        let outside = temp.path().join("outside");
        fs::create_dir_all(allowed.join("sub")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(allowed.join("sub").join("FAKE_inside.luau"), "return 1").unwrap();
        fs::write(outside.join("FAKE_exists.luau"), "return 1").unwrap();
        let roots = canonicalize_roots(vec![fs::canonicalize(&allowed).unwrap()]).unwrap();
        // Use the same absolute spelling a client would send.
        let allowed = roots[0].clone();
        let outside = fs::canonicalize(&outside).unwrap();
        Fixture {
            _temp: temp,
            allowed,
            outside,
            roots,
        }
    }

    fn display(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn round2_09_outside_roots_answer_does_not_depend_on_existence() {
        let fixture = fixture();
        let existing = fixture.outside.join("FAKE_exists.luau");
        let missing = fixture.outside.join("FAKE_missing.luau");
        let missing_directory = fixture.outside.join("FAKE_no_dir").join("FAKE.luau");
        let dotted_existing = fixture
            .allowed
            .join("..")
            .join("outside")
            .join("FAKE_exists.luau");
        let dotted_missing = fixture
            .allowed
            .join("sub")
            .join("..")
            .join("..")
            .join("outside")
            .join("FAKE_missing.luau");
        let sibling = PathBuf::from(format!("{}2", display(&fixture.allowed))).join("FAKE.luau");
        for raw in [
            &existing,
            &missing,
            &missing_directory,
            &dotted_existing,
            &dotted_missing,
            &sibling,
        ] {
            let lexical = requested_path_before_io(&display(raw), &fixture.roots).unwrap_err();
            assert_eq!(lexical, outside_roots_message(raw), "{}", raw.display());
            let full = validate_requested_path(&display(raw), &fixture.roots, 1_000).unwrap_err();
            assert_eq!(full, lexical, "{}", raw.display());
        }
        // The existing and the missing file get the same text apart from the name.
        let existing_error =
            validate_requested_path(&display(&existing), &fixture.roots, 1_000).unwrap_err();
        let missing_error =
            validate_requested_path(&display(&missing), &fixture.roots, 1_000).unwrap_err();
        assert_eq!(
            existing_error.replace("FAKE_exists", "FAKE_name"),
            missing_error.replace("FAKE_missing", "FAKE_name")
        );
    }

    #[test]
    fn round2_09_inside_roots_paths_still_resolve() {
        let fixture = fixture();
        let inside = fixture.allowed.join("sub").join("FAKE_inside.luau");
        let dotted = fixture
            .allowed
            .join("sub")
            .join(".")
            .join("..")
            .join("sub")
            .join("FAKE_inside.luau");
        for raw in [&inside, &dotted, &fixture.allowed] {
            let resolved = validate_requested_path(&display(raw), &fixture.roots, 1_000)
                .unwrap_or_else(|error| panic!("{}: {error}", raw.display()));
            assert!(resolved.starts_with(&fixture.roots[0]));
        }
        let missing = fixture.allowed.join("sub").join("FAKE_missing.luau");
        let error = validate_requested_path(&display(&missing), &fixture.roots, 1_000).unwrap_err();
        assert!(error.starts_with("cannot inspect path"), "{error}");
    }

    #[test]
    fn round2_09_links_inside_a_root_are_refused_before_they_are_followed() {
        let fixture = fixture();
        let link = fixture.allowed.join("FAKE_link");
        #[cfg(unix)]
        let created = std::os::unix::fs::symlink(&fixture.outside, &link).is_ok();
        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_dir(&fixture.outside, &link).is_ok();
        if !created {
            return;
        }
        let through_existing = link.join("FAKE_exists.luau");
        let through_missing = link.join("FAKE_missing.luau");
        let existing_error =
            validate_requested_path(&display(&through_existing), &fixture.roots, 1_000)
                .unwrap_err();
        let missing_error =
            validate_requested_path(&display(&through_missing), &fixture.roots, 1_000).unwrap_err();
        assert!(
            existing_error.contains("symbolic links"),
            "{existing_error}"
        );
        assert_eq!(existing_error, missing_error);
    }

    #[cfg(windows)]
    #[test]
    fn round2_09_windows_spellings_are_compared_without_case_and_names_windows_rewrites_are_refused()
     {
        let fixture = fixture();
        let plain = display(&fixture.allowed)
            .trim_start_matches(r"\\?\")
            .to_owned();
        let upper = format!(r"{}\SUB\FAKE_INSIDE.LUAU", plain.to_uppercase());
        validate_requested_path(&upper, &fixture.roots, 1_000).expect("case-insensitive match");
        let forward = format!("{}/sub/FAKE_inside.luau", plain.replace('\\', "/"));
        validate_requested_path(&forward, &fixture.roots, 1_000).expect("forward slashes");
        for raw in [
            format!(r"{plain}\sub\FAKE_inside.luau."),
            format!(r"{plain}\sub\FAKE_inside.luau "),
            format!(r"{plain}\sub\FAKE_inside.luau:FAKE_stream"),
            format!(r"\\?\{plain}\sub/../../outside\FAKE_exists.luau"),
        ] {
            let error = requested_path_before_io(&raw, &fixture.roots).unwrap_err();
            assert!(error.contains("path components must not"), "{raw}: {error}");
        }
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, DuplexStream};

    const NEXT: &[u8] = br#"{"jsonrpc":"2.0","id":"FAKE-next","method":"ping"}"#;

    struct Pipe {
        transport: LineTransport<DuplexStream, DuplexStream>,
        requests: DuplexStream,
        replies: BufReader<DuplexStream>,
    }

    fn pipe(max_line_bytes: usize, reply_buffer: usize) -> Pipe {
        let (requests, server_in) = tokio::io::duplex(1 << 20);
        let (server_out, replies) = tokio::io::duplex(reply_buffer);
        Pipe {
            transport: LineTransport::new(server_in, server_out, max_line_bytes),
            requests,
            replies: BufReader::new(replies),
        }
    }

    impl Pipe {
        async fn send(&mut self, line: &[u8]) {
            self.requests.write_all(line).await.unwrap();
            self.requests.write_all(b"\n").await.unwrap();
        }

        async fn reply(&mut self) -> Value {
            let mut line = Vec::new();
            self.replies.read_until(b'\n', &mut line).await.unwrap();
            serde_json::from_slice(&line).unwrap_or_else(|error| {
                panic!("reply {:?}: {error}", String::from_utf8_lossy(&line))
            })
        }

        /// Close both sides and return every reply line not read yet.
        async fn rest(mut self) -> String {
            drop(self.requests);
            self.transport.close().await.unwrap();
            drop(self.transport);
            let mut rest = String::new();
            self.replies.read_to_string(&mut rest).await.unwrap();
            rest
        }
    }

    fn reply_of(line: &[u8]) -> Option<Value> {
        let mut raw = line.to_vec();
        raw.push(b'\n');
        match decode_line(&raw) {
            Decoded::Reply(reply) => Some(serde_json::to_value(reply).unwrap()),
            Decoded::Message(_) | Decoded::Skip => None,
        }
    }

    fn deep(depth: usize) -> String {
        format!("{}{}", "[".repeat(depth), "]".repeat(depth))
    }

    fn bad_lines() -> Vec<(String, Vec<u8>, i64, Option<Value>)> {
        let call = |id: &str, arguments: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"scan_source","arguments":{arguments}}}}}"#
            )
            .into_bytes()
        };
        let mut invalid_utf8 = call("904", r#"{"source":"FAKE"}"#);
        let at = invalid_utf8.len() - 6;
        invalid_utf8.splice(at..at, [0xff, 0xfe]);
        let mut invalid_key = br#"{"jsonrpc":"2.0",""#.to_vec();
        invalid_key.extend([0xff, b'"', b':', b'1', b',']);
        invalid_key.extend(br#""id":9,"method":"ping"}"#);
        vec![
            (
                "50,000 nested arrays".into(),
                call("901", &format!(r#"{{"bundle":{}}}"#, deep(50_000))),
                -32700,
                Some(json!(901)),
            ),
            (
                "id after 50,000 nested arrays".into(),
                format!(
                    r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"arguments":{}}},"id":"FAKE-907"}}"#,
                    deep(50_000)
                )
                .into_bytes(),
                -32700,
                Some(json!("FAKE-907")),
            ),
            (
                "lone high surrogate".into(),
                call("902", r#"{"source":"\ud800"}"#),
                -32700,
                Some(json!(902)),
            ),
            (
                "lone low surrogate".into(),
                call("905", r#"{"source":"\udc00x"}"#),
                -32700,
                Some(json!(905)),
            ),
            (
                "reversed surrogate pair".into(),
                call(r#""FAKE-906""#, r#"{"source":"\udc00\ud800"}"#),
                -32700,
                Some(json!("FAKE-906")),
            ),
            (
                "invalid UTF-8 in a string".into(),
                invalid_utf8,
                -32700,
                Some(json!(904)),
            ),
            (
                "invalid UTF-8 in a key".into(),
                invalid_key,
                -32700,
                Some(json!(9)),
            ),
            (
                "cut off inside params".into(),
                br#"{"jsonrpc":"2.0","id":903,"method":"tools/call","params":{"name":"scan_sou"#
                    .to_vec(),
                -32700,
                Some(json!(903)),
            ),
            (
                "cut off right after the id".into(),
                br#"{"jsonrpc":"2.0","id":903"#.to_vec(),
                -32700,
                None,
            ),
            (
                "escaped id key".into(),
                br#"{"id":11,"jsonrpc":"2.0","method":"ping","params":["#.to_vec(),
                -32700,
                Some(json!(11)),
            ),
            (
                "null id".into(),
                br#"{"jsonrpc":"2.0","id":null,"method":"ping","#.to_vec(),
                -32700,
                None,
            ),
            (
                "fractional id".into(),
                br#"{"jsonrpc":"2.0","id":1.5,"method":"ping","#.to_vec(),
                -32700,
                None,
            ),
            (
                "not JSON".into(),
                b"FAKE not json".to_vec(),
                -32700,
                None,
            ),
            ("lone brace with CR".into(), b"{\r".to_vec(), -32700, None),
            (
                "JSON that is not a message".into(),
                br#"{"FAKE":1}"#.to_vec(),
                -32600,
                None,
            ),
            (
                "known method with bad params".into(),
                br#"{"jsonrpc":"2.0","id":908,"method":"tools/call","params":"FAKE"}"#.to_vec(),
                -32600,
                Some(json!(908)),
            ),
            (
                "two ids".into(),
                br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":"FAKE"}"#
                    .to_vec(),
                -32600,
                None,
            ),
        ]
    }

    #[tokio::test]
    async fn round3_10_bad_lines_get_an_error_reply_and_the_next_request_still_arrives() {
        for (label, line, code, id) in bad_lines() {
            let mut pipe = pipe(MAX_MCP_FRAME_BYTES, 1 << 20);
            pipe.send(&line).await;
            pipe.send(NEXT).await;
            let next = pipe.transport.receive().await.expect(&label);
            assert_eq!(
                serde_json::to_value(next).unwrap()["id"],
                "FAKE-next",
                "{label}"
            );
            let reply = pipe.reply().await;
            assert_eq!(reply["jsonrpc"], "2.0", "{label}");
            assert_eq!(reply["error"]["code"], code, "{label}: {reply}");
            assert_eq!(reply.get("id"), id.as_ref(), "{label}: {reply}");
            assert!(reply["error"]["data"].is_string(), "{label}: {reply}");
            assert_eq!(pipe.rest().await, "", "{label}: one reply only");
        }
    }

    #[tokio::test]
    async fn round3_10_valid_messages_blank_lines_and_bad_notifications_get_no_reply() {
        let mut bom = UTF8_BOM.to_vec();
        bom.extend_from_slice(NEXT);
        for (label, line, delivered) in [
            ("plain", NEXT.to_vec(), true),
            ("BOM", bom, true),
            ("CRLF", [NEXT, b"\r"].concat(), true),
            ("blank", b"   \t".to_vec(), false),
            (
                "notification with a bad version",
                br#"{"jsonrpc":"1.0","method":"notifications/initialized"}"#.to_vec(),
                false,
            ),
            (
                "notification with bad params",
                br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":"FAKE"}"#.to_vec(),
                false,
            ),
            // The server's own replies, echoed back, are error messages for rmcp
            // to drop. They never start a reply loop.
            (
                "echoed parse error",
                br#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error","data":"x"}}"#
                    .to_vec(),
                true,
            ),
            (
                "echoed reply with an id",
                br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32600,"message":"Invalid request"}}"#
                    .to_vec(),
                true,
            ),
        ] {
            let mut pipe = pipe(MAX_MCP_FRAME_BYTES, 1 << 20);
            pipe.send(&line).await;
            pipe.send(NEXT).await;
            let first = pipe.transport.receive().await.expect(label);
            if delivered {
                let second = pipe.transport.receive().await.expect(label);
                assert_eq!(serde_json::to_value(second).unwrap()["id"], "FAKE-next");
            } else {
                assert_eq!(serde_json::to_value(first).unwrap()["id"], "FAKE-next");
            }
            assert_eq!(pipe.rest().await, "", "{label}");
        }
        // Every reply the transport writes decodes as a message, never as a new reply.
        for (label, line, _, _) in bad_lines() {
            let reply = reply_of(&line).expect(&label);
            let echoed = serde_json::to_vec(&reply).unwrap();
            assert!(reply_of(&echoed).is_none(), "{label}");
        }
    }

    /// Requests whose id sits at the start, the middle or the end, cut at every byte.
    #[test]
    fn round3_10_every_cut_of_a_request_is_a_parse_error_with_the_id_only_when_it_is_complete() {
        let ids = [
            ("7", json!(7)),
            ("-3", json!(-3)),
            ("0", json!(0)),
            ("9007199254740993", json!(9_007_199_254_740_993_i64)),
            (r#""FAKE-a""#, json!("FAKE-a")),
            (r#""FAKE \" quote""#, json!("FAKE \" quote")),
            (r#""FAKEé""#, json!("FAKEé")),
            (r#""""#, json!("")),
        ];
        let params = r#""params":{"name":"scan_source","arguments":{"source":"é 日本 [{\"x\"}]"}}"#;
        let mut checked = 0usize;
        for (raw_id, id) in ids {
            let id_member = format!(r#""id":{raw_id}"#);
            for layout in 0..3 {
                let members = match layout {
                    0 => [
                        id_member.as_str(),
                        r#""jsonrpc":"2.0""#,
                        r#""method":"tools/call""#,
                        params,
                    ],
                    1 => [
                        r#""jsonrpc":"2.0""#,
                        r#""method":"tools/call""#,
                        id_member.as_str(),
                        params,
                    ],
                    _ => [
                        r#""jsonrpc":"2.0""#,
                        r#""method":"tools/call""#,
                        params,
                        id_member.as_str(),
                    ],
                };
                let line = format!("{{{}}}", members.join(",")).into_bytes();
                let id_end = line
                    .windows(id_member.len())
                    .position(|window| window == id_member.as_bytes())
                    .unwrap()
                    + id_member.len();
                assert!(reply_of(&line).is_none(), "the whole line is a request");
                for cut in 1..line.len() {
                    let prefix = &line[..cut];
                    let reply = reply_of(prefix).unwrap_or_else(|| {
                        panic!("no reply for {:?}", String::from_utf8_lossy(prefix))
                    });
                    assert_eq!(reply["error"]["code"], -32700);
                    // The separator after the id member must be inside the cut.
                    let expected = (cut > id_end).then_some(&id);
                    assert_eq!(
                        reply.get("id"),
                        expected,
                        "{:?}",
                        String::from_utf8_lossy(prefix)
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 2_000, "{checked}");
    }

    /// Bad bytes and escapes at every position inside a string keep the id readable.
    #[test]
    fn round3_10_bad_bytes_anywhere_in_a_string_keep_the_id() {
        let head = br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"scan_source","arguments":{"source":""#;
        let body = "FAKE é 日本 text";
        let tail = br#""}},"id":"FAKE-tail"}"#;
        let injections: [&[u8]; 6] = [
            b"\xff",
            b"\xc3",
            b"\xed\xa0\x80",
            br"\ud800",
            br"\udfff",
            br"\x41",
        ];
        for injection in injections {
            for at in 0..=body.len() {
                let mut line = head.to_vec();
                line.extend_from_slice(&body.as_bytes()[..at]);
                line.extend_from_slice(injection);
                line.extend_from_slice(&body.as_bytes()[at..]);
                line.extend_from_slice(tail);
                let reply = reply_of(&line)
                    .unwrap_or_else(|| panic!("accepted {:?}", String::from_utf8_lossy(&line)));
                assert_eq!(reply["error"]["code"], -32700);
                assert_eq!(reply["id"], "FAKE-tail");
            }
        }
    }

    /// Around serde_json's nesting limit a line either arrives or gets a parse
    /// error that names its id. The id comes after the nested value here.
    #[test]
    fn round3_10_nesting_around_the_decoder_limit_arrives_or_names_the_id() {
        let (mut arrived, mut refused) = (0, 0);
        for depth in [1, 60, 100, 120, 124, 125, 126, 127, 128, 200, 5_000, 50_000] {
            let line = format!(
                r#"{{"jsonrpc":"2.0","method":"FAKE/custom","params":{{"a":{}}},"id":{depth}}}"#,
                deep(depth)
            );
            match reply_of(line.as_bytes()) {
                None => arrived += 1,
                Some(reply) => {
                    refused += 1;
                    assert_eq!(reply["error"]["code"], -32700, "{depth}");
                    assert_eq!(reply["id"], depth, "{depth}");
                }
            }
        }
        assert!(arrived > 0 && refused > 0, "{arrived} {refused}");
    }

    #[tokio::test]
    async fn round3_10_oversized_lines_are_answered_and_close_the_transport() {
        let max = 1_024;
        // A line of exactly the cap still arrives.
        let mut exact = NEXT.to_vec();
        exact.resize(max, b' ');
        let mut pipe = pipe(max, 1 << 20);
        pipe.send(&exact).await;
        let message = pipe.transport.receive().await.expect("line at the cap");
        assert_eq!(serde_json::to_value(message).unwrap()["id"], "FAKE-next");

        let mut over = br#"{"jsonrpc":"2.0","id":77,"method":"ping","params":{"x":""#.to_vec();
        over.resize(max + 1, b'x');
        pipe.send(&over).await;
        pipe.send(NEXT).await;
        assert!(pipe.transport.receive().await.is_none());
        let reply = pipe.reply().await;
        assert_eq!(reply["id"], 77);
        assert_eq!(reply["error"]["code"], -32600);
        assert_eq!(reply["error"]["message"], "Request too large");
        assert_eq!(pipe.rest().await, "");
    }

    /// More bad lines than the reply queue holds, with a writer that only takes
    /// a few hundred bytes at a time: every line is answered and nothing hangs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn round3_10_many_bad_lines_are_all_answered_with_a_slow_reader() {
        let count = MAX_PENDING_REPLIES * 3;
        let Pipe {
            mut transport,
            mut requests,
            mut replies,
        } = pipe(MAX_MCP_FRAME_BYTES, 256);
        let writer = tokio::spawn(async move {
            for index in 0..count {
                let line = format!(r#"{{"jsonrpc":"2.0","id":{index},"method":"ping""#);
                requests.write_all(line.as_bytes()).await.unwrap();
                requests.write_all(b"\n").await.unwrap();
            }
            requests.write_all(NEXT).await.unwrap();
            requests.write_all(b"\n").await.unwrap();
            requests
        });
        let reader = tokio::spawn(async move {
            let mut ids = Vec::new();
            for _ in 0..count {
                let mut line = Vec::new();
                replies.read_until(b'\n', &mut line).await.unwrap();
                let reply: Value = serde_json::from_slice(&line).unwrap();
                assert_eq!(reply["error"]["code"], -32700);
                ids.push(reply["id"].as_u64().unwrap());
            }
            ids
        });
        let next = transport
            .receive()
            .await
            .expect("request after the bad lines");
        assert_eq!(serde_json::to_value(next).unwrap()["id"], "FAKE-next");
        let mut ids = reader.await.unwrap();
        ids.sort_unstable();
        assert_eq!(ids, (0..count as u64).collect::<Vec<_>>());
        drop(writer.await.unwrap());
    }
}

#[cfg(all(test, windows))]
mod review_tests {
    use super::*;

    #[test]
    fn review_09_globalroot_is_rejected_before_filesystem_access() {
        let roots = vec![PathBuf::from(r"C:\FAKE_root")];
        for raw in [
            r"\\?\GLOBALROOT\??\C:\FAKE\source.luau",
            r"\\?\GLOBALROOT\??\UNC\FAKE_host\FAKE_share\source.luau",
            r"\\?\FAKE_device\source.luau",
        ] {
            // This is the exact lexical stage used by the server. It has no file APIs.
            let error = requested_path_before_io(raw, &roots).unwrap_err();
            assert!(
                error.contains("only disk and verbatim disk prefixes"),
                "{error}"
            );
        }
    }
}

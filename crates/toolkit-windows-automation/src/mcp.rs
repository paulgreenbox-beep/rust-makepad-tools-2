use crate::contract::{AutomationError, AutomationResult, ErrorCode};
use crate::tool_registry::{GuiToolRegistry, ToolCallEnvelope, ToolDefinition};
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use crate::request_control::RequestControl;
// lib.rs exposes RequestControl only on Windows. Reuse the same portable
// implementation here without expanding the crate's public/cfg surface.
#[cfg(not(windows))]
#[path = "request_control.rs"]
mod stdio_request_control;
#[cfg(not(windows))]
use stdio_request_control::RequestControl;

#[cfg(windows)]
pub mod http;

const STDIO_MAX_LINE: usize = 1024 * 1024;
const STDIO_MAX_PENDING: usize = 32;
// Queue time counts. This is within HTTP's 90s and Codex's 60s tool deadline;
// it does not change the separate 30s input grant or interrupt synchronous COM.
const STDIO_CALL_TIMEOUT: Duration = Duration::from_secs(60);
const OWNER_LIFECYCLE_META: &str = "toolkit/owner-lifecycle-v1";
type StdioResult = Result<(), Box<dyn Error>>;

pub fn run_mcp_stdio() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdout = io::stdout().lock();
    #[cfg(windows)]
    let mut registry = GuiToolRegistry::new_stdio_session()?;
    #[cfg(not(windows))]
    let mut registry = GuiToolRegistry::new()?;
    let inbox = Arc::new(StdioInbox::default());
    let input = Arc::clone(&inbox);
    // Only bytes, JSON and RequestControl cross this boundary. Registry/COM
    // construction, dispatch, explicit owned close and teardown stay on the STA.
    let reader = std::thread::Builder::new()
        .name("mcp-stdio-reader".into())
        .stack_size(512 * 1024)
        .spawn(move || {
            let _exit = ReaderExit(Arc::clone(&input));
            let stdin = io::stdin();
            read_stdio(&mut BufReader::with_capacity(8192, stdin.lock()), &input);
        });
    match reader {
        Ok(_reader) => serve_stdio(&mut registry, &mut stdout, &inbox),
        Err(error) => finish_stdio(
            &mut registry,
            &inbox,
            "stdio_reader_start_error",
            Err(error.into()),
        ),
    }
    // Do not join a reader blocked on an open stdin after an output failure.
    // It owns no COM or sessions and admission is closed before we return.
    // This graceful path cannot run after external TerminateProcess.
}

trait RpcRegistry {
    fn definitions(&self) -> &[ToolDefinition];
    fn invoke(&mut self, name: &str, arguments: Value) -> ToolCallEnvelope;
    fn invoke_operator_lifecycle(&mut self, meta: &Value) -> AutomationResult<Value>;
}

impl RpcRegistry for GuiToolRegistry {
    fn definitions(&self) -> &[ToolDefinition] {
        self.definitions()
    }
    fn invoke(&mut self, name: &str, arguments: Value) -> ToolCallEnvelope {
        self.invoke(name, arguments)
    }
    fn invoke_operator_lifecycle(&mut self, meta: &Value) -> AutomationResult<Value> {
        self.invoke_operator_lifecycle(meta)
    }
}

trait StdioOwner: RpcRegistry {
    fn set_control(&mut self, control: Option<RequestControl>);
    fn finish(&mut self, reason: &str) -> AutomationResult<Value>;
}

impl StdioOwner for GuiToolRegistry {
    fn set_control(&mut self, control: Option<RequestControl>) {
        #[cfg(windows)]
        self.set_request_control(control);
        #[cfg(not(windows))]
        let _ = control;
    }
    fn finish(&mut self, reason: &str) -> AutomationResult<Value> {
        self.finish_owned_sessions(reason)
    }
}

struct StdioCommand {
    request: Value,
    key: String,
    control: RequestControl,
}

enum StdioItem {
    Call(StdioCommand),
    Reply(Value),
}

struct StdioStop {
    reason: &'static str,
    error: Option<io::Error>,
    reply: Option<Value>,
}

#[derive(Default)]
struct StdioState {
    queue: VecDeque<StdioItem>,
    // Includes the running command until its actual completion, not its timeout.
    calls: BTreeMap<String, RequestControl>,
    running: Option<(String, bool)>,
    stop: Option<StdioStop>,
}

impl StdioState {
    fn stop(&mut self, reason: &'static str, error: Option<io::Error>, reply: Option<Value>) {
        if self.stop.is_some() {
            return;
        }
        if reason == "stdio_eof" {
            // A normal stdin half-close still owes replies to accepted requests.
            // Protocol/catalog/evidence reads cannot launch an App or send input.
            if let Some((key, false)) = &self.running {
                if let Some(control) = self.calls.get(key) {
                    control.cancel();
                }
            }
            for item in &self.queue {
                if let StdioItem::Call(command) = item {
                    if !can_drain_after_eof(&command.request) {
                        command.control.cancel();
                    }
                }
            }
        } else {
            self.cancel_all();
        }
        self.stop = Some(StdioStop {
            reason,
            error,
            reply,
        });
    }

    fn cancel_all(&mut self) {
        for control in self.calls.values() {
            control.cancel();
        }
        self.calls.clear();
        self.queue.clear();
    }

    fn reject_overload(&mut self) {
        self.stop(
            "stdio_queue_overflow",
            Some(io::Error::other("stdio pending queue limit exceeded")),
            Some(json_rpc_error(
                Value::Null,
                -32000,
                "Server overloaded",
                json!({"retry_safe": false}),
            )),
        );
    }
}

fn can_drain_after_eof(request: &Value) -> bool {
    match request["method"].as_str() {
        Some("initialize" | "tools/list" | "ping") => true,
        Some("tools/call") if request["params"]["name"] == "windows_get_evidence" => {
            // Lifecycle metadata turns an evidence request into an owned close.
            request["params"].get("_meta").is_none_or(|meta| {
                meta.as_object()
                    .is_some_and(|meta| !meta.contains_key(OWNER_LIFECYCLE_META))
            })
        }
        _ => false, // In particular, windows_find_window can launch an owned App.
    }
}

#[derive(Default)]
struct StdioInbox {
    state: Mutex<StdioState>,
    ready: Condvar,
}

impl StdioInbox {
    fn stop(&self, reason: &'static str, error: Option<io::Error>, reply: Option<Value>) {
        self.state.lock().unwrap().stop(reason, error, reply);
        self.ready.notify_one();
    }

    fn ingest(&self, line: &[u8]) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.stop.is_some() {
            return false;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            return true;
        }
        let item = match parse_stdio_request(line) {
            Err(response) => StdioItem::Reply(response),
            Ok(request) => {
                if request["method"] == "notifications/cancelled" {
                    // A cancellation never queues behind an in-flight STA call.
                    if request.get("id").is_none() {
                        if let Some(key) = request_key(&request["params"]["requestId"]) {
                            if let Some(control) = state.calls.get(&key) {
                                control.cancel();
                            }
                            return true; // Unknown/completed IDs cannot cancel a future reuse.
                        }
                    }
                    return self.enqueue_invalid_cancel(state);
                }
                let Some(id) = request.get("id") else {
                    return true;
                };
                let key = request_key(id).expect("validated stdio request ID");
                if state.calls.contains_key(&key) {
                    state.stop(
                        "stdio_duplicate_id",
                        Some(io::Error::other("duplicate in-flight stdio request ID")),
                        Some(json_rpc_error(
                            Value::Null,
                            -32600,
                            "Duplicate request ID",
                            json!({}),
                        )),
                    );
                    self.ready.notify_one();
                    return false;
                }
                if state.calls.len() >= STDIO_MAX_PENDING || state.queue.len() >= STDIO_MAX_PENDING
                {
                    state.reject_overload();
                    self.ready.notify_one();
                    return false;
                }
                let control = RequestControl::new(STDIO_CALL_TIMEOUT);
                state.calls.insert(key.clone(), control.clone());
                StdioItem::Call(StdioCommand {
                    request,
                    key,
                    control,
                })
            }
        };
        if state.queue.len() >= STDIO_MAX_PENDING {
            state.reject_overload();
            self.ready.notify_one();
            return false;
        }
        state.queue.push_back(item);
        self.ready.notify_one();
        true
    }

    fn enqueue_invalid_cancel(&self, mut state: std::sync::MutexGuard<'_, StdioState>) -> bool {
        if state.queue.len() >= STDIO_MAX_PENDING {
            state.reject_overload();
            self.ready.notify_one();
            return false;
        }
        state.queue.push_back(StdioItem::Reply(json_rpc_error(
            Value::Null,
            -32600,
            "Invalid cancellation notification",
            json!({}),
        )));
        self.ready.notify_one();
        true
    }
}

fn request_key(id: &Value) -> Option<String> {
    (id.is_string() || id.as_i64().is_some() || id.as_u64().is_some()).then(|| id.to_string())
}

fn parse_stdio_request(line: &[u8]) -> Result<Value, Value> {
    let request: Value = serde_json::from_slice(line).map_err(|error| {
        json_rpc_error(
            Value::Null,
            -32700,
            "Parse error",
            json!({"detail": error.to_string()}),
        )
    })?;
    if !request.is_object()
        || request["jsonrpc"] != "2.0"
        || !request["method"]
            .as_str()
            .is_some_and(|method| !method.is_empty())
        || !request.get("id").is_none_or(|id| request_key(id).is_some())
        || !request.get("params").is_none_or(Value::is_object)
    {
        return Err(json_rpc_error(
            Value::Null,
            -32600,
            "Invalid request",
            json!({}),
        ));
    }
    if request["method"] == "tools/call"
        && (!request["params"]["name"].is_string()
            || !request["params"]
                .get("arguments")
                .is_none_or(Value::is_object))
    {
        return Err(json_rpc_error(
            request["id"].clone(),
            -32602,
            "Invalid params",
            json!({}),
        ));
    }
    Ok(request)
}

// Bound allocation before deserialization, even if a peer never sends '\n'.
// An unterminated final frame is not dispatched after observing EOF.
fn read_stdio_line(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unterminated stdio JSON-RPC frame",
                ))
            };
        }
        let end = available.iter().position(|byte| *byte == b'\n');
        let count = end.unwrap_or(available.len());
        if count > STDIO_MAX_LINE - line.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stdio JSON-RPC frame exceeds 1 MiB",
            ));
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count + usize::from(end.is_some()));
        if end.is_some() {
            return Ok(Some(line));
        }
    }
}

fn read_stdio(reader: &mut impl BufRead, inbox: &StdioInbox) {
    loop {
        // Stop promptly between reads following a writer/dispatch failure.
        if inbox.state.lock().unwrap().stop.is_some() {
            return;
        }
        match read_stdio_line(reader) {
            Ok(Some(line)) if inbox.ingest(&line) => {}
            Ok(Some(_)) => return,
            Ok(None) => {
                inbox.stop("stdio_eof", None, None);
                return;
            }
            Err(error) => {
                let reply = (error.kind() == io::ErrorKind::InvalidData
                    || error.kind() == io::ErrorKind::UnexpectedEof)
                    .then(|| {
                        json_rpc_error(
                            Value::Null,
                            -32700,
                            "Invalid input frame",
                            json!({"detail": error.to_string()}),
                        )
                    });
                inbox.stop("stdio_read_error", Some(error), reply);
                return;
            }
        }
    }
}

struct ReaderExit(Arc<StdioInbox>);
impl Drop for ReaderExit {
    fn drop(&mut self) {
        self.0.stop(
            "stdio_reader_stopped",
            Some(io::Error::other("stdio reader stopped unexpectedly")),
            None,
        );
    }
}

fn serve_stdio(
    owner: &mut impl StdioOwner,
    writer: &mut impl Write,
    inbox: &StdioInbox,
) -> StdioResult {
    let (reason, result) = loop {
        let mut state = inbox.state.lock().unwrap();
        while state.queue.is_empty() && state.stop.is_none() {
            state = inbox.ready.wait(state).unwrap();
        }
        let terminal = state
            .stop
            .as_ref()
            .is_some_and(|stop| stop.reason != "stdio_eof" || state.queue.is_empty());
        if terminal {
            let stop = state.stop.as_mut().expect("terminal stdio stop");
            let reason = stop.reason;
            let error = stop.error.take();
            let reply = stop.reply.take();
            drop(state);
            let result = match reply.map(|reply| write_message(writer, &reply)).transpose() {
                Err(error) => Err(Box::new(error) as Box<dyn Error>),
                Ok(_) => error.map_or(Ok(()), |error| Err(Box::new(error) as Box<dyn Error>)),
            };
            break (reason, result);
        }
        let item = state.queue.pop_front().expect("ready stdio item");
        if let StdioItem::Call(command) = &item {
            state.running = Some((command.key.clone(), can_drain_after_eof(&command.request)));
        }
        // Promotion to running is serialized with cancellation/EOF. The same
        // atomic is checked again before dispatch and by the existing backend.
        drop(state);
        let response = match item {
            StdioItem::Reply(response) => Some(response),
            StdioItem::Call(command) => {
                owner.set_control(Some(command.control.clone()));
                let dispatched = match command.control.check() {
                    Err(error) => Ok(Some(json_rpc_error(
                        command.request["id"].clone(),
                        -32800,
                        "Request cancelled before dispatch",
                        json!({"code": error.code, "dispatch_state": "NOT_DISPATCHED", "retry_safe": false}),
                    ))),
                    Ok(()) => dispatch_request_controlled(
                        owner,
                        &command.request,
                        "2024-11-05",
                        Some(&command.control),
                    ),
                };
                owner.set_control(None);
                {
                    let mut state = inbox.state.lock().unwrap();
                    state.calls.remove(&command.key);
                    state.running = None;
                }
                let mut response = match dispatched {
                    Ok(response) => response,
                    Err(error) => {
                        break (
                            "stdio_dispatch_error",
                            Err(Box::new(error) as Box<dyn Error>),
                        );
                    }
                };
                if command
                    .control
                    .cancelled
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    // Preserve the actual backend result; cancellation is not rollback.
                    if let Some(result) = response
                        .as_mut()
                        .and_then(|r| r.get_mut("result"))
                        .and_then(Value::as_object_mut)
                    {
                        let meta = result.entry("_meta").or_insert_with(|| json!({}));
                        meta["toolkit.transport"]["cancellation_requested"] = json!(true);
                        meta["toolkit.transport"]["retry_safe"] = json!(false);
                    }
                }
                response
            }
        };
        if let Some(response) = response {
            if let Err(error) = write_message(writer, &response) {
                break ("stdio_write_error", Err(Box::new(error) as Box<dyn Error>));
            }
        }
    };
    finish_stdio(owner, inbox, reason, result)
}

#[derive(Debug)]
struct StdioCloseError {
    transport: Box<dyn Error>,
    close: AutomationError,
}
impl std::fmt::Display for StdioCloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stdio transport failed: {}; owned close failed: {}",
            self.transport, self.close
        )
    }
}
impl Error for StdioCloseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.close)
    }
}

fn finish_stdio(
    owner: &mut impl StdioOwner,
    inbox: &StdioInbox,
    reason: &'static str,
    transport: StdioResult,
) -> StdioResult {
    inbox.stop(reason, None, None);
    // A writer/dispatch failure may occur while draining a normal half-close.
    // Cancel and release every remaining admission even when EOF was first.
    inbox.state.lock().unwrap().cancel_all();
    // An expired/cancelled tool's control must never cancel explicit cleanup.
    owner.set_control(None);
    match (transport, owner.finish(reason)) {
        (Ok(()), Ok(_receipt)) => Ok(()),
        (Err(error), Ok(_)) => Err(error),
        (Ok(()), Err(close)) => Err(Box::new(close)),
        (Err(transport), Err(close)) => Err(Box::new(StdioCloseError { transport, close })),
    }
}

// Both transports share the tool dispatch, schemas and result envelope.
fn dispatch_request(
    registry: &mut impl RpcRegistry,
    request: &Value,
    protocol: &str,
) -> Result<Option<Value>, serde_json::Error> {
    dispatch_request_controlled(registry, request, protocol, None)
}

fn dispatch_request_controlled(
    registry: &mut impl RpcRegistry,
    request: &Value,
    protocol: &str,
    control: Option<&RequestControl>,
) -> Result<Option<Value>, serde_json::Error> {
    let id = request.get("id").cloned();
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if id.is_none() {
        return Ok(None);
    }
    let id = id.unwrap_or(Value::Null);
    let response = match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {
                    "name": "rust-makepad-toolkit-windows-gui",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }),
        "ping" => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"tools": registry.definitions()}
        }),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(Value::as_str);
            let lifecycle = match owner_lifecycle_meta(&params) {
                Ok(meta) => meta,
                Err(error) => {
                    return Ok(Some(json_rpc_error(
                        id,
                        -32602,
                        "Invalid owner lifecycle metadata",
                        serde_json::to_value(error)?,
                    )));
                }
            };
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match name {
                Some(name) => {
                    // Use the SAME native clock domain as registry/native I/O
                    // receipts. Client Date.now() may differ on Windows; never
                    // repair that difference by rewriting event timestamps.
                    let dispatched_unix_ms = system_unix_ms();
                    let clock_started = Instant::now();
                    let envelope = registry.invoke(name, arguments);
                    let text = serde_json::to_string(&envelope)?;
                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{"type": "text", "text": text}],
                            "structuredContent": envelope,
                            "isError": !envelope.ok
                        }
                    });
                    if let Some(meta) = lifecycle {
                        // The normal evidence content/envelope is unchanged.
                        // Trusted operator opt-in, binding and generation checks
                        // belong exclusively to the existing registry/router.
                        // Do not start a second operation if EOF/cancellation
                        // arrived during evidence collection. Graceful EOF still
                        // uses the unconditional owned-close path on the STA.
                        let close = match control.and_then(|control| control.check().err()) {
                            Some(error) => Err(AutomationError::with_details(
                                ErrorCode::BackendFailure,
                                error.message,
                                json!({"code": error.code, "dispatch_state": "NOT_DISPATCHED", "retry_safe": false}),
                            )),
                            None => registry.invoke_operator_lifecycle(meta),
                        };
                        let failed = close.is_err();
                        let receipt = match close {
                            Ok(proof) => json!({"ok": true, "result": proof}),
                            Err(error) => json!({"ok": false, "error": error}),
                        };
                        response["result"]["_meta"] = json!({(OWNER_LIFECYCLE_META): receipt});
                        if failed {
                            response["result"]["isError"] = json!(true);
                        }
                    }
                    response["result"]["_meta"]["toolkit.transport"]["server_clock"] = json!({
                        "source":"RUST_SYSTEM_TIME_AND_INSTANT", "process_id":std::process::id(),
                        "dispatched_unix_ms":dispatched_unix_ms,"completed_unix_ms":system_unix_ms(),
                        "elapsed_monotonic_ns":clock_started.elapsed().as_nanos().to_string()
                    });
                    response
                }
                None => json_rpc_error(
                    id,
                    -32602,
                    "Invalid params",
                    json!({"detail": "tools/call requires params.name"}),
                ),
            }
        }
        _ => json_rpc_error(
            id,
            -32601,
            "Method not found",
            serde_json::to_value(AutomationError::new(
                ErrorCode::ToolNotFound,
                format!("unknown MCP method: {method}"),
            ))
            .unwrap_or(Value::Null),
        ),
    };
    Ok(Some(response))
}

fn system_unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).ok()
        .and_then(|d|u64::try_from(d.as_millis()).ok()).unwrap_or(0)
}

fn owner_lifecycle_meta(params: &Value) -> AutomationResult<Option<&Value>> {
    let Some(metadata) = params.get("_meta") else {
        return Ok(None);
    };
    let invalid = || {
        AutomationError::invalid_argument(
            "owner lifecycle metadata requires windows_get_evidence and exactly action=close, session_id (nonempty string), generation (u64)",
        )
    };
    let metadata = metadata.as_object().ok_or_else(invalid)?;
    let Some(meta) = metadata.get(OWNER_LIFECYCLE_META) else {
        return Ok(None);
    };
    if params["name"] != "windows_get_evidence"
        || !meta.as_object().is_some_and(|object| object.len() == 3)
        || meta["action"] != "close"
        || !meta["session_id"]
            .as_str()
            .is_some_and(|session| !session.is_empty())
        || meta["generation"]
            .as_u64()
            .is_none_or(|generation| generation == 0)
    {
        return Err(invalid());
    }
    Ok(Some(meta))
}

fn json_rpc_error(id: Value, code: i32, message: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
            "data": data
        }
    })
}

fn write_message(writer: &mut impl Write, message: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, message)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Default)]
    struct Owner {
        control: Option<RequestControl>,
        invoked: Vec<String>,
        closed: Vec<String>,
        lifecycle: Vec<Value>,
        close_error: Option<AutomationError>,
        lifecycle_error: Option<AutomationError>,
        during_invoke: Option<Box<dyn FnOnce(&RequestControl)>>,
    }

    impl RpcRegistry for Owner {
        fn definitions(&self) -> &[ToolDefinition] {
            &[]
        }
        fn invoke(&mut self, name: &str, _arguments: Value) -> ToolCallEnvelope {
            self.invoked.push(name.to_owned());
            if let Some(action) = self.during_invoke.take() {
                action(
                    self.control
                        .as_ref()
                        .expect("control installed before invoke"),
                );
            }
            let error = self
                .control
                .as_ref()
                .and_then(|control| control.check().err())
                .map(|error| {
                    AutomationError::with_details(
                        ErrorCode::BackendFailure,
                        error.message,
                        json!({"code": error.code}),
                    )
                });
            ToolCallEnvelope {
                ok: error.is_none(),
                result: error.is_none().then(|| json!({"evidence": []})),
                error,
                evidence_sequence: self.invoked.len() as u64,
            }
        }
        fn invoke_operator_lifecycle(&mut self, meta: &Value) -> AutomationResult<Value> {
            self.lifecycle.push(meta.clone());
            match self.lifecycle_error.clone() {
                Some(error) => Err(error),
                None => Ok(json!({"normal_close_proved": true})),
            }
        }
    }
    impl StdioOwner for Owner {
        fn set_control(&mut self, control: Option<RequestControl>) {
            self.control = control;
        }
        fn finish(&mut self, reason: &str) -> AutomationResult<Value> {
            assert!(
                self.control.is_none(),
                "cleanup must not inherit cancelled control"
            );
            self.closed.push(reason.into());
            match self.close_error.clone() {
                Some(error) => Err(error),
                None => Ok(json!({"closed": true})),
            }
        }
    }

    struct Output {
        bytes: Vec<u8>,
        inbox: Arc<StdioInbox>,
        stop_after: usize,
        messages: usize,
        fail_flush: bool,
    }
    impl Output {
        fn new(inbox: &Arc<StdioInbox>, stop_after: usize) -> Self {
            Self {
                bytes: Vec::new(),
                inbox: Arc::clone(inbox),
                stop_after,
                messages: 0,
                fail_flush: false,
            }
        }
        fn responses(&self) -> Vec<Value> {
            self.bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice(line).expect("stdout is JSON-RPC only"))
                .collect()
        }
    }
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"));
            }
            self.messages += 1;
            if self.messages == self.stop_after {
                self.inbox.stop("stdio_eof", None, None);
            }
            Ok(())
        }
    }

    fn call(id: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "windows_get_evidence", "arguments": {}}})
    }
    fn mutation(id: Value) -> Value {
        let mut request = call(id);
        request["params"]["name"] = json!("windows_find_window");
        request
    }
    fn enqueue(inbox: &StdioInbox, request: Value) {
        assert!(inbox.ingest(&serde_json::to_vec(&request).unwrap()));
    }
    fn cancel(inbox: &StdioInbox, id: Value) {
        enqueue(
            inbox,
            json!({"jsonrpc":"2.0", "method":"notifications/cancelled", "params":{"requestId": id}}),
        );
    }
    fn close_error() -> AutomationError {
        AutomationError::with_details(
            ErrorCode::BackendFailure,
            "typed close receipt failed",
            json!({"code": "OWNED_CLOSE_RECEIPT_MISSING", "app_count": 1, "job_count": 1}),
        )
    }
    fn lifecycle_request() -> Value {
        let mut request = call(json!(1));
        request["params"]["_meta"] = json!({(OWNER_LIFECYCLE_META): {
            "action": "close", "session_id": "actual-binding", "generation": 4,
        }});
        request
    }

    #[test]
    fn actual_server_clock_encloses_dispatch_without_changing_tool_envelope() {
        let mut registry = Owner::default();
        let response = dispatch_request(&mut registry, &call(json!(1)), "2024-11-05")
            .unwrap().unwrap();
        let clock = &response["result"]["_meta"]["toolkit.transport"]["server_clock"];
        assert_eq!(clock["source"], "RUST_SYSTEM_TIME_AND_INSTANT");
        assert_eq!(clock["process_id"], std::process::id());
        assert!(clock["dispatched_unix_ms"].as_u64().unwrap()>0);
        assert!(clock["completed_unix_ms"].as_u64().unwrap()>=clock["dispatched_unix_ms"].as_u64().unwrap());
        assert!(clock["elapsed_monotonic_ns"].as_str().unwrap().parse::<u128>().unwrap()>0);
        let text: Value = serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text,response["result"]["structuredContent"]);
        assert!(text.get("_meta").is_none());
    }

    #[test]
    fn stdio_bounded_framing_handles_crlf_utf8_and_rejects_partial_eof() {
        let mut reader =
            BufReader::with_capacity(3, Cursor::new("{\"text\":\"тест\"}\r\n".as_bytes()));
        let line = read_stdio_line(&mut reader).unwrap().unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&line).unwrap()["text"],
            "тест"
        );
        assert!(read_stdio_line(&mut reader).unwrap().is_none());
        let error = read_stdio_line(&mut Cursor::new(b"{\"jsonrpc\":\"2.0\"}")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        let mut oversized = vec![b'x'; STDIO_MAX_LINE + 1];
        assert_eq!(
            read_stdio_line(&mut Cursor::new(&oversized))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        oversized.pop();
        oversized.push(b'\n');
        assert_eq!(
            read_stdio_line(&mut Cursor::new(oversized))
                .unwrap()
                .unwrap()
                .len(),
            STDIO_MAX_LINE
        );
    }

    #[test]
    fn stdio_rejects_invalid_rpc_without_dispatch_and_recovers_parse_errors() {
        let inbox = Arc::new(StdioInbox::default());
        assert!(inbox.ingest(b"{"));
        for request in [
            json!([]),
            json!(null),
            json!({"method":"ping", "id":1}),
            json!({"jsonrpc":"1.0", "method":"ping", "id":1}),
            json!({"jsonrpc":"2.0", "method":"ping", "id":null}),
            json!({"jsonrpc":"2.0", "method":"ping", "id":true}),
            json!({"jsonrpc":"2.0", "method":"ping", "id":1.5}),
            json!({"jsonrpc":"2.0", "method":"ping", "id":{}}),
            json!({"jsonrpc":"2.0", "method":"ping", "id":1, "params":[]}),
            json!({"jsonrpc":"2.0", "method":"tools/call", "id":1, "params":{"name":3}}),
            json!({"jsonrpc":"2.0", "method":"tools/call", "id":1, "params":{"name":"windows_get_evidence", "arguments":[]}}),
        ] {
            enqueue(&inbox, request);
        }
        assert!(inbox.ingest(b"\xff"));
        enqueue(&inbox, json!({"jsonrpc":"2.0", "method":"ping", "id":1}));
        let mut output = Output::new(&inbox, 14);
        let mut owner = Owner::default();
        serve_stdio(&mut owner, &mut output, &inbox).unwrap();
        let replies = output.responses();
        assert_eq!(replies.len(), 14);
        assert_eq!(replies[0]["error"]["code"], -32700);
        assert!(
            replies[..13]
                .iter()
                .all(|reply| reply.get("error").is_some())
        );
        assert_eq!(replies[13]["result"], json!({}));
        assert!(owner.invoked.is_empty());
        assert_eq!(owner.closed, ["stdio_eof"]);
    }

    #[test]
    fn stdio_reader_cancels_running_and_queued_requests_without_sta_dispatch() {
        let inbox = Arc::new(StdioInbox::default());
        enqueue(&inbox, call(json!(1)));
        enqueue(&inbox, call(json!("queued")));
        let input = Arc::clone(&inbox);
        let mut owner = Owner {
            during_invoke: Some(Box::new(move |control| {
                std::thread::spawn(move || {
                    cancel(&input, json!(1));
                    cancel(&input, json!("queued"));
                })
                .join()
                .unwrap();
                assert_eq!(control.check().unwrap_err().code, "REQUEST_CANCELLED");
            })),
            ..Owner::default()
        };
        let mut output = Output::new(&inbox, 2);
        serve_stdio(&mut owner, &mut output, &inbox).unwrap();
        assert_eq!(owner.invoked, ["windows_get_evidence"]);
        let replies = output.responses();
        assert_eq!(
            replies[0]["result"]["structuredContent"]["error"]["details"]["code"],
            "REQUEST_CANCELLED"
        );
        assert_eq!(
            replies[0]["result"]["_meta"]["toolkit.transport"]["cancellation_requested"],
            true
        );
        assert_eq!(replies[0]["result"]["_meta"]["toolkit.transport"]["server_clock"]["source"],
            "RUST_SYSTEM_TIME_AND_INSTANT");
        assert_eq!(
            replies[1]["error"]["data"]["dispatch_state"],
            "NOT_DISPATCHED"
        );
        assert_eq!(owner.closed, ["stdio_eof"]);
    }

    #[test]
    fn stdio_deadline_includes_queue_and_unknown_cancel_does_not_poison_reuse() {
        let inbox = Arc::new(StdioInbox::default());
        cancel(&inbox, json!(1));
        enqueue(&inbox, call(json!(1)));
        enqueue(&inbox, call(json!("expired")));
        {
            let mut state = inbox.state.lock().unwrap();
            let StdioItem::Call(command) = state.queue.back_mut().unwrap() else {
                panic!("call");
            };
            command.control = RequestControl::new(Duration::ZERO);
        }
        let mut owner = Owner::default();
        let mut output = Output::new(&inbox, 2);
        serve_stdio(&mut owner, &mut output, &inbox).unwrap();
        assert_eq!(owner.invoked.len(), 1);
        assert_eq!(
            output.responses()[1]["error"]["data"]["code"],
            "REQUEST_DEADLINE_EXCEEDED"
        );
    }

    #[test]
    fn stdio_eof_cancels_queued_work_and_propagates_typed_close_error() {
        let inbox = Arc::new(StdioInbox::default());
        enqueue(&inbox, mutation(json!(1)));
        let control = inbox
            .state
            .lock()
            .unwrap()
            .calls
            .values()
            .next()
            .unwrap()
            .clone();
        read_stdio(&mut Cursor::new(b""), &inbox);
        assert_eq!(control.check().unwrap_err().code, "REQUEST_CANCELLED");
        assert!(!inbox.ingest(&serde_json::to_vec(&call(json!(2))).unwrap()));
        let mut owner = Owner {
            close_error: Some(close_error()),
            ..Owner::default()
        };
        let error =
            serve_stdio(&mut owner, &mut Output::new(&inbox, usize::MAX), &inbox).unwrap_err();
        assert_eq!(
            error.downcast_ref::<AutomationError>(),
            Some(&close_error())
        );
        assert!(owner.invoked.is_empty());
        assert_eq!(owner.closed, ["stdio_eof"]);
    }

    #[test]
    fn stdio_eof_during_call_cancels_atomic_and_closes_before_owner_drop() {
        let inbox = Arc::new(StdioInbox::default());
        enqueue(&inbox, mutation(json!(1)));
        enqueue(&inbox, mutation(json!(2)));
        let input = Arc::clone(&inbox);
        let mut owner = Owner {
            during_invoke: Some(Box::new(move |control| {
                std::thread::spawn(move || read_stdio(&mut Cursor::new(b""), &input))
                    .join()
                    .unwrap();
                assert!(control.check().is_err());
            })),
            ..Owner::default()
        };
        let mut output = Output::new(&inbox, usize::MAX);
        serve_stdio(&mut owner, &mut output, &inbox).unwrap();
        assert_eq!(owner.invoked.len(), 1);
        assert_eq!(owner.closed, ["stdio_eof"]);
        assert!(owner.control.is_none());
        let responses = output.responses();
        assert_eq!(responses.len(), 2);
        assert_eq!(
            responses[1]["error"]["data"]["dispatch_state"],
            "NOT_DISPATCHED"
        );
    }

    #[test]
    fn stdio_full_queue_and_duplicate_ids_fail_closed_but_cancel_bypasses_full_queue() {
        let inbox = Arc::new(StdioInbox::default());
        for id in 0..STDIO_MAX_PENDING {
            enqueue(&inbox, call(json!(id)));
        }
        let control = inbox.state.lock().unwrap().calls["0"].clone();
        cancel(&inbox, json!(0));
        assert!(control.check().is_err());
        assert!(inbox.state.lock().unwrap().stop.is_none());
        assert!(!inbox.ingest(&serde_json::to_vec(&call(json!(STDIO_MAX_PENDING))).unwrap()));
        let mut owner = Owner::default();
        let error =
            serve_stdio(&mut owner, &mut Output::new(&inbox, usize::MAX), &inbox).unwrap_err();
        assert!(error.to_string().contains("queue limit"));
        assert!(owner.invoked.is_empty());
        assert_eq!(owner.closed, ["stdio_queue_overflow"]);
        let inbox = StdioInbox::default();
        enqueue(&inbox, call(json!(1)));
        enqueue(&inbox, call(json!("1"))); // String and numeric IDs are distinct.
        assert!(!inbox.ingest(&serde_json::to_vec(&call(json!(1))).unwrap()));
        assert_eq!(
            inbox.state.lock().unwrap().stop.as_ref().unwrap().reason,
            "stdio_duplicate_id"
        );
    }

    #[test]
    fn stdio_parse_error_flood_is_bounded_and_reader_exit_is_terminal() {
        let inbox = Arc::new(StdioInbox::default());
        for _ in 0..STDIO_MAX_PENDING {
            assert!(inbox.ingest(b"{"));
        }
        assert!(!inbox.ingest(b"{"));
        let state = inbox.state.lock().unwrap();
        assert!(state.queue.is_empty());
        assert!(state.calls.is_empty());
        drop(state);
        let other = Arc::new(StdioInbox::default());
        drop(ReaderExit(Arc::clone(&other)));
        let mut owner = Owner::default();
        assert!(serve_stdio(&mut owner, &mut Output::new(&other, usize::MAX), &other).is_err());
        assert_eq!(owner.closed, ["stdio_reader_stopped"]);
    }

    struct ReadFailure;
    impl io::Read for ReadFailure {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("input failed"))
        }
    }
    impl BufRead for ReadFailure {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("input failed"))
        }
        fn consume(&mut self, _: usize) {}
    }

    #[test]
    fn stdio_read_and_write_failures_always_finish_and_retain_both_errors() {
        let inbox = Arc::new(StdioInbox::default());
        enqueue(&inbox, call(json!(1)));
        read_stdio(&mut ReadFailure, &inbox);
        let mut owner = Owner::default();
        let error =
            serve_stdio(&mut owner, &mut Output::new(&inbox, usize::MAX), &inbox).unwrap_err();
        assert_eq!(error.to_string(), "input failed");
        assert!(owner.invoked.is_empty());
        assert_eq!(owner.closed, ["stdio_read_error"]);
        let inbox = Arc::new(StdioInbox::default());
        enqueue(&inbox, call(json!(1)));
        enqueue(&inbox, call(json!(2)));
        let queued_control = inbox.state.lock().unwrap().calls["2"].clone();
        let mut owner = Owner {
            close_error: Some(close_error()),
            ..Owner::default()
        };
        let mut output = Output::new(&inbox, usize::MAX);
        output.fail_flush = true;
        let error = serve_stdio(&mut owner, &mut output, &inbox).unwrap_err();
        assert_eq!(
            error.source().unwrap().downcast_ref::<AutomationError>(),
            Some(&close_error())
        );
        let combined = error.downcast_ref::<StdioCloseError>().unwrap();
        assert_eq!(
            combined
                .transport
                .downcast_ref::<io::Error>()
                .unwrap()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(queued_control.check().is_err());
        assert_eq!(owner.invoked.len(), 1);
        assert_eq!(owner.closed, ["stdio_write_error"]);
    }

    #[test]
    fn lifecycle_bad_metadata_never_dispatches_or_falls_back() {
        let valid = lifecycle_request();
        let mut invalid = Vec::new();
        let mut wrong_name = valid.clone();
        wrong_name["params"]["name"] = json!("windows_click");
        invalid.push(wrong_name);
        for meta in [
            Value::Null,
            json!({}),
            json!({"action":"kill", "session_id":"actual-binding", "generation":4}),
            json!({"action":"close", "session_id":"", "generation":4}),
            json!({"action":"close", "session_id":"actual-binding", "generation":-1}),
            json!({"action":"close", "session_id":"actual-binding", "generation":0}),
            json!({"action":"close", "session_id":"actual-binding", "generation":4.5}),
            json!({"action":"close", "session_id":"actual-binding", "generation":4, "extra":true}),
        ] {
            let mut request = valid.clone();
            request["params"]["_meta"][OWNER_LIFECYCLE_META] = meta;
            invalid.push(request);
        }
        let mut bad_container = valid.clone();
        bad_container["params"]["_meta"] = json!([]);
        invalid.push(bad_container);
        let mut owner = Owner::default();
        for request in invalid {
            let response = dispatch_request(&mut owner, &request, "2024-11-05")
                .unwrap()
                .unwrap();
            assert_eq!(response["error"]["code"], -32602);
        }
        assert!(owner.invoked.is_empty());
        assert!(owner.lifecycle.is_empty());
    }

    #[test]
    fn lifecycle_preserves_tool_content_and_reports_typed_receipt_errors_in_meta() {
        let mut normal = Owner::default();
        let mut plain = dispatch_request(&mut normal, &call(json!(1)), "2024-11-05")
            .unwrap()
            .unwrap();
        let plain_metadata = plain["result"].as_object_mut().unwrap().remove("_meta").unwrap();
        assert_eq!(plain_metadata["toolkit.transport"]["server_clock"]["source"],
            "RUST_SYSTEM_TIME_AND_INSTANT");
        for fail in [false, true] {
            let mut owner = Owner {
                lifecycle_error: fail.then(close_error),
                ..Owner::default()
            };
            let mut response = dispatch_request(&mut owner, &lifecycle_request(), "2024-11-05")
                .unwrap()
                .unwrap();
            let metadata = response["result"]
                .as_object_mut()
                .unwrap()
                .remove("_meta")
                .unwrap();
            assert_eq!(response["result"]["isError"], fail);
            response["result"]["isError"] = json!(false);
            assert_eq!(response, plain);
            assert_eq!(metadata["toolkit.transport"]["server_clock"]["source"],
                "RUST_SYSTEM_TIME_AND_INSTANT");
            assert_eq!(metadata["toolkit.transport"]["server_clock"]["process_id"],std::process::id());
            assert_eq!(metadata[OWNER_LIFECYCLE_META]["ok"], !fail);
            if fail {
                assert_eq!(
                    metadata[OWNER_LIFECYCLE_META]["error"],
                    serde_json::to_value(close_error()).unwrap()
                );
            }
            assert_eq!(owner.invoked, ["windows_get_evidence"]);
            assert_eq!(
                owner.lifecycle,
                [lifecycle_request()["params"]["_meta"][OWNER_LIFECYCLE_META].clone()]
            );
            let listed = dispatch_request(
                &mut owner,
                &json!({"jsonrpc":"2.0", "id":2, "method":"tools/list"}),
                "2024-11-05",
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                listed["result"]["tools"],
                serde_json::to_value(owner.definitions()).unwrap()
            );
        }
    }

    #[test]
    fn lifecycle_does_not_start_after_eof_during_evidence_collection() {
        let inbox = Arc::new(StdioInbox::default());
        enqueue(&inbox, lifecycle_request());
        let input = Arc::clone(&inbox);
        let mut owner = Owner {
            during_invoke: Some(Box::new(move |_| read_stdio(&mut Cursor::new(b""), &input))),
            ..Owner::default()
        };
        let mut output = Output::new(&inbox, usize::MAX);
        serve_stdio(&mut owner, &mut output, &inbox).unwrap();
        assert!(owner.lifecycle.is_empty());
        let responses = output.responses();
        let meta = &responses[0]["result"]["_meta"];
        assert_eq!(meta[OWNER_LIFECYCLE_META]["ok"], false);
        assert_eq!(
            meta[OWNER_LIFECYCLE_META]["error"]["details"]["code"],
            "REQUEST_CANCELLED"
        );
        assert_eq!(meta["toolkit.transport"]["cancellation_requested"], true);
        assert_eq!(responses[0]["result"]["isError"], true);
        assert_eq!(owner.closed, ["stdio_eof"]);
    }

    #[test]
    fn stdio_normal_half_close_drains_catalog_protocol_and_evidence_only() {
        let inbox = Arc::new(StdioInbox::default());
        let requests = [
            json!({"jsonrpc":"2.0", "id":1, "method":"initialize"}),
            json!({"jsonrpc":"2.0", "id":2, "method":"tools/list"}),
            json!({"jsonrpc":"2.0", "id":3, "method":"ping"}),
            mutation(json!(4)),
            call(json!(5)),
            lifecycle_request(),
        ];
        // Distinct ID for the lifecycle request; duplicate IDs fail closed.
        let mut requests = requests;
        requests[5]["id"] = json!(6);
        let mut frames = Vec::new();
        for request in requests {
            serde_json::to_writer(&mut frames, &request).unwrap();
            frames.push(b'\n');
        }
        // Exact communicate()-style pattern: all complete frames, then EOF,
        // before the STA gets a chance to service even initialize.
        read_stdio(
            &mut BufReader::with_capacity(7, Cursor::new(frames)),
            &inbox,
        );
        let mut owner = Owner::default();
        let mut output = Output::new(&inbox, usize::MAX);
        serve_stdio(&mut owner, &mut output, &inbox).unwrap();
        let replies = output.responses();
        assert_eq!(replies.len(), 6);
        assert_eq!(replies[0]["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(replies[1]["result"]["tools"], json!([]));
        assert_eq!(replies[2]["result"], json!({}));
        assert_eq!(
            replies[3]["error"]["data"]["dispatch_state"],
            "NOT_DISPATCHED"
        );
        assert_eq!(replies[4]["result"]["isError"], false);
        assert_eq!(
            replies[5]["error"]["data"]["dispatch_state"],
            "NOT_DISPATCHED"
        );
        assert_eq!(owner.invoked, ["windows_get_evidence"]);
        assert!(owner.lifecycle.is_empty());
        assert_eq!(owner.closed, ["stdio_eof"]);
    }
}

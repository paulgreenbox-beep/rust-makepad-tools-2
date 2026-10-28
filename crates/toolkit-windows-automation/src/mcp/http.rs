//! Opt-in loopback Streamable HTTP transport for the existing MCP owner.
//! No service installation, auto-start, UIA proxy process or second input arbiter.
mod wire;
mod incremental;
use super::{dispatch_request, dispatch_request_controlled, json_rpc_error};
use crate::{GuiToolRegistry, request_control::RequestControl};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcessId, ReleaseMutex, WaitForSingleObject,
};
use windows::core::PCWSTR;

const PROTOCOL: &str = "2025-06-18";
const MAX_SESSIONS: usize = 32;
const MAX_CONNECTIONS: usize = 64;
const MAX_PENDING: usize = 32;
const PER_SESSION_PENDING: usize = 8;
const CALL_TIMEOUT: Duration = Duration::from_secs(90);
const IDLE_TIMEOUT: Duration = Duration::from_secs(1800);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    port: u16,
    windows_session_id: u32,
    token_file: PathBuf,
    evidence_root: PathBuf,
    /// Trusted operator may narrow the request budget for failure qualification.
    /// MCP arguments cannot set it; the production/default ceiling stays 90s.
    #[serde(default)]
    request_timeout_ms: Option<u64>,
}

impl Config {
    fn call_timeout(&self) -> Result<Duration, &'static str> {
        match self.request_timeout_ms {
            None => Ok(CALL_TIMEOUT),
            Some(ms @ 100..=90_000) => Ok(Duration::from_millis(ms)),
            Some(_) => Err("trusted HTTP request timeout must be 100..90000 ms"),
        }
    }
}

/// Manual operator entry point. The default executable invocation remains stdio.
pub fn run_mcp_http(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !config_path.is_absolute() {
        return Err("HTTP config must be an absolute trusted operator path".into());
    }
    let config_bytes = read_bounded(config_path, 4096)?;
    let config: Config = serde_json::from_slice(&config_bytes)?;
    config.call_timeout()?;
    let mut session_id = 0;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) }?;
    if session_id == 0 || session_id != config.windows_session_id || config.port == 0 {
        return Err(
            "HTTP config must bind this interactive Windows session and a nonzero port".into(),
        );
    }
    if !config.token_file.is_absolute() || !config.evidence_root.is_absolute() {
        return Err("trusted HTTP paths must be absolute".into());
    }
    reject_reparse_ancestors(&config.evidence_root)?;
    reject_reparse_ancestors(&config.token_file)?;
    let token_bytes = read_bounded(&config.token_file, 256)?;
    let token = std::str::from_utf8(&token_bytes)?.trim().to_owned();
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("HTTP token file must contain exactly 64 random hex characters".into());
    }
    // This mutex only prevents duplicate transport hosts. DesktopInput still
    // belongs exclusively to the existing DesktopArbiter registry/mutex.
    let _singleton = Singleton::acquire(session_id)?;
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port))?;
    let server = Arc::new(Server {
        config,
        token,
        sessions: Mutex::new(HashMap::new()),
        connections: Arc::new(AtomicUsize::new(0)),
        workers: Arc::new(AtomicUsize::new(0)),
        pending: Arc::new(AtomicUsize::new(0)),
    });
    eprintln!(
        "experimental Toolkit MCP HTTP listening on 127.0.0.1:{}/mcp (Windows session {session_id}); acceptance NOT_RUN",
        server.config.port
    );
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(stream) => stream,
            Err(_) => {
                // A failed individual accept is not a reason to kill every
                // client's COM apartment. Bound retry CPU without spinning.
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        if !stream.peer_addr().is_ok_and(|peer| peer.ip().is_loopback()) {
            continue;
        }
        let Some(slot) = Slot::try_new(&server.connections, MAX_CONNECTIONS) else {
            let _ = wire::write(&mut stream, 503, b"{}", None);
            wire::finish(&mut stream);
            continue;
        };
        let server = Arc::clone(&server);
        // Connections carry JSON values only. COM is created/dropped on a
        // separate persistent STA thread per MCP session, never moved to here.
        let spawned = thread::Builder::new()
            .name("mcp-http-connection".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                let _slot = slot;
                server.serve(&mut stream);
            });
        if spawned.is_err() {
            // Failed spawn drops the closure's stream and admission slot.
            // Never terminate other live sessions on connection overload.
            eprintln!("Toolkit HTTP connection admission failed; host remains available");
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = fs::File::open(path)?.take(limit + 1);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other(
            "trusted config/token file exceeds limit",
        ));
    }
    Ok(bytes)
}

fn reject_reparse_ancestors(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_attributes() & 0x400 != 0 => {
                return Err(std::io::Error::other(
                    "HTTP paths must not traverse reparse points",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

struct Singleton(HANDLE);
impl Singleton {
    fn acquire(session: u32) -> Result<Self, Box<dyn std::error::Error>> {
        let name: Vec<_> = format!("Local\\MakepadToolkitMcpHttpV1-{session}\0")
            .encode_utf16()
            .collect();
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }?;
        let status = unsafe { WaitForSingleObject(handle, 0) };
        if status != WAIT_OBJECT_0 && status != WAIT_ABANDONED {
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err("one Toolkit HTTP host already owns this Windows session".into());
        }
        Ok(Self(handle))
    }
}
impl Drop for Singleton {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.0);
            let _ = CloseHandle(self.0);
        }
    }
}

// Independent OS randomness: neither a predictable timestamp nor an HWND/PID.
fn random_id() -> std::io::Result<String> {
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut core::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    let mut bytes = [0u8; 32];
    if unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            2,
        )
    } < 0
    {
        return Err(std::io::Error::other("OS random generation failed"));
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

struct Slot(Arc<AtomicUsize>);
impl Slot {
    fn try_new(count: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                if n < limit { Some(n + 1) } else { None }
            })
            .ok()?;
        Some(Self(Arc::clone(count)))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Server {
    config: Config,
    token: String,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    connections: Arc<AtomicUsize>,
    workers: Arc<AtomicUsize>,
    pending: Arc<AtomicUsize>,
}
struct Session {
    tx: mpsc::SyncSender<Command>,
    closed: Arc<AtomicBool>,
    initialized: AtomicBool,
    state: Mutex<SessionState>,
}
struct WorkerExit(Arc<Session>);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::SeqCst);
    }
}
struct SessionState {
    last_used: Instant,
    calls: BTreeMap<String, Arc<Call>>,
}
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Queued,
    Running,
    Completed,
}
struct Call {
    control: RequestControl,
    phase: Mutex<Phase>,
}
struct Command {
    request: Value,
    call: Arc<Call>,
    key: String,
    result: mpsc::SyncSender<Value>,
    _slot: Slot,
}

impl Server {
    fn serve(&self, stream: &mut TcpStream) {
        let request = match wire::read(stream, self.config.port, &self.token) {
            Ok(request) => request,
            Err(status) => {
                let _ = wire::write(stream, status, b"{}", None);
                wire::finish(stream);
                return;
            }
        };
        let (status, body, new_session) = self.route(request);
        let bytes = body
            .map(|body| serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()))
            .unwrap_or_default();
        let _ = wire::write(stream, status, &bytes, new_session.as_deref());
        wire::finish(stream);
    }

    fn route(&self, request: wire::Request) -> (u16, Option<Value>, Option<String>) {
        // No cross-client session list, result broadcast, resume or response cache.
        let sid = request.headers.get("mcp-session-id");
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, session| {
            let state = session.state.lock().unwrap();
            let keep = !session.closed.load(Ordering::SeqCst)
                && (state.last_used.elapsed() < IDLE_TIMEOUT || !state.calls.is_empty());
            if !keep {
                session.closed.store(true, Ordering::SeqCst);
            }
            keep
        });
        if request.method == "DELETE" || request.method == "GET" {
            let Some(sid) = sid else {
                return (400, None, None);
            };
            if !sessions.contains_key(sid) {
                return (404, None, None);
            }
            if request
                .headers
                .get("mcp-protocol-version")
                .map(String::as_str)
                != Some(PROTOCOL)
            {
                return (400, None, None);
            }
            if request.method == "GET" {
                return (405, None, None);
            } // SSE is optional.
            let Some(session) = sessions.remove(sid) else {
                return (404, None, None);
            };
            session.close();
            return (200, None, None);
        }
        let value: Value = match serde_json::from_slice(&request.body) {
            Ok(value) => value,
            Err(_) => {
                return (
                    400,
                    Some(json_rpc_error(
                        Value::Null,
                        -32700,
                        "Parse error",
                        json!({}),
                    )),
                    None,
                );
            }
        };
        if !valid_rpc(&value) {
            return (
                400,
                Some(json_rpc_error(
                    Value::Null,
                    -32600,
                    "Invalid request",
                    json!({}),
                )),
                None,
            );
        }
        let method = value
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if method == "initialize" {
            if sid.is_some()
                || value.get("id").is_none()
                || !value["params"]["protocolVersion"].is_string()
            {
                return (400, None, None);
            }
            let Some(worker_slot) = Slot::try_new(&self.workers, MAX_SESSIONS) else {
                return (429, None, None);
            };
            let (sid, owner) =
                match random_id().and_then(|sid| random_id().map(|owner| (sid, owner))) {
                    Ok(ids) => ids,
                    Err(_) => return (503, None, None),
                };
            let (tx, rx) = mpsc::sync_channel(PER_SESSION_PENDING);
            let session = Arc::new(Session {
                tx,
                closed: Arc::new(AtomicBool::new(false)),
                initialized: AtomicBool::new(false),
                state: Mutex::new(SessionState {
                    last_used: Instant::now(),
                    calls: BTreeMap::new(),
                }),
            });
            let worker_session = Arc::clone(&session);
            let evidence = self.config.evidence_root.join(&owner);
            let init_request = value;
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            if thread::Builder::new()
                .name("mcp-http-uia-sta".into())
                .spawn(move || {
                    let _slot = worker_slot;
                    session_worker(worker_session, rx, owner, evidence, init_request, ready_tx);
                })
                .is_err()
            {
                return (503, None, None);
            }
            // Other clients/control notifications must not wait for COM startup.
            drop(sessions);
            let response = match ready_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(Ok(response)) => response,
                _ => {
                    session.close();
                    return (503, None, None);
                }
            };
            self.sessions.lock().unwrap().insert(sid.clone(), session);
            return (200, Some(response), Some(sid));
        }
        let Some(sid) = sid else {
            return (400, None, None);
        };
        let Some(session) = sessions.get(sid).cloned() else {
            return (404, None, None);
        };
        drop(sessions);
        if request
            .headers
            .get("mcp-protocol-version")
            .map(String::as_str)
            != Some(PROTOCOL)
        {
            return (400, None, None);
        }
        let mut state = session.state.lock().unwrap();
        state.last_used = Instant::now();
        if method == "notifications/initialized" && value.get("id").is_none() {
            session.initialized.store(true, Ordering::SeqCst);
            return (202, None, None);
        }
        if method == "notifications/cancelled" && value.get("id").is_none() {
            if let Some(key) = request_key(&value["params"]["requestId"]) {
                if let Some(call) = state.calls.get(&key) {
                    call.control.cancel();
                }
            } else {
                return (400, None, None);
            }
            return (202, None, None);
        }
        if value.get("id").is_none() {
            return (202, None, None);
        }
        if method != "ping" && !session.initialized.load(Ordering::SeqCst) {
            return (409, None, None);
        }
        let key = request_key(&value["id"]).expect("RPC request id validated");
        if state.calls.contains_key(&key) {
            return (409, None, None);
        }
        if state.calls.len() >= PER_SESSION_PENDING {
            return (429, None, None);
        }
        let Some(slot) = Slot::try_new(&self.pending, MAX_PENDING) else {
            return (429, None, None);
        };
        let call = Arc::new(Call {
            control: RequestControl::new(self.config.call_timeout().expect("validated trusted HTTP timeout")),
            phase: Mutex::new(Phase::Queued),
        });
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        state.calls.insert(key.clone(), Arc::clone(&call));
        let id = value["id"].clone();
        let command = Command {
            request: value,
            key: key.clone(),
            call: Arc::clone(&call),
            result: reply_tx,
            _slot: slot,
        };
        if session.tx.try_send(command).is_err() {
            state.calls.remove(&key);
            session.closed.store(true, Ordering::SeqCst);
            return (503, None, None);
        }
        drop(state);
        match reply_rx.recv_timeout(call.control.remaining()) {
            Ok(response) => (200, Some(response), None),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                session.close();
                (503, None, None)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Synchronize with the worker's pre-dispatch gate. Never call a
                // potentially applied UIA mutation "not executed" or retry it.
                let phase = call.phase.lock().unwrap();
                call.control.cancel();
                let dispatched = *phase != Phase::Queued;
                (
                    200,
                    Some(json_rpc_error(
                        id,
                        -32001,
                        "Request deadline exceeded",
                        json!({
                            "code": "REQUEST_DEADLINE_EXCEEDED", "retry_safe": false,
                            "dispatch_state": if dispatched { "OUTCOME_UNKNOWN_QUERY_EVIDENCE" } else { "NOT_DISPATCHED" }
                        }),
                    )),
                    None,
                )
            }
        }
    }
}

impl Session {
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        for call in self.state.lock().unwrap().calls.values() {
            call.control.cancel();
        }
    }
}

fn session_worker(
    session: Arc<Session>,
    rx: mpsc::Receiver<Command>,
    owner: String,
    evidence: PathBuf,
    init: Value,
    ready: mpsc::SyncSender<Result<Value, ()>>,
) {
    let _exit = WorkerExit(Arc::clone(&session));
    let mut registry = match GuiToolRegistry::new_http_session(&owner) {
        Ok(registry) => registry,
        Err(_) => {
            let _ = ready.send(Err(()));
            session.closed.store(true, Ordering::SeqCst);
            return;
        }
    };
    let frame_opt_in = incremental::negotiated(&init);
    let mut initialized = dispatch_request(&mut registry, &init, PROTOCOL)
        .ok()
        .flatten()
        .ok_or(());
    if frame_opt_in {
        if let Ok(response) = initialized.as_mut() {
            response["result"]["capabilities"]["experimental"] = json!({incremental::CAPABILITY:{"version":1,"method":incremental::METHOD}});
        }
    }
    if ready.send(initialized).is_err() {
        session.close();
        return;
    }
    let mut capture_sequence = 0u64;
    let mut frame_transport = incremental::FrameTransport::new(owner, frame_opt_in);
    loop {
        let command = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(command) => command,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if session.closed.load(Ordering::SeqCst)
                    || session.state.lock().unwrap().last_used.elapsed() >= IDLE_TIMEOUT
                {
                    break;
                }
                continue;
            }
        };
        let mut phase = command.call.phase.lock().unwrap();
        let rejection = command.call.control.check().err();
        let mut response = if session.closed.load(Ordering::SeqCst) || rejection.is_some() {
            json_rpc_error(
                command.request["id"].clone(),
                -32800,
                "Request cancelled before dispatch",
                json!({"code": rejection.map(|e| e.code).unwrap_or_else(|| "SESSION_CLOSED".into()), "dispatch_state": "NOT_DISPATCHED", "retry_safe": false}),
            )
        } else {
            *phase = Phase::Running;
            drop(phase);
            registry.set_request_control(Some(command.call.control.clone()));
            let mut request = command.request.clone();
            // The HTTP policy cannot overwrite another chat's capture or any
            // arbitrary host file via a shared service's output_path parameter.
            let capture_error = if request["method"] == "tools/call"
                && request["params"]["name"] == "windows_capture_window"
            {
                prepare_capture(&mut request, &evidence, &mut capture_sequence).err()
            } else {
                None
            };
            let response = match capture_error {
                Some(message) => json_rpc_error(
                    request["id"].clone(),
                    -32602,
                    message,
                    json!({"code": "INVALID_ARGUMENT", "dispatch_state": "NOT_DISPATCHED"}),
                ),
                None => frame_transport.dispatch(&mut registry, &request, &evidence, &mut capture_sequence)
                    .or_else(|| dispatch_request_controlled(&mut registry, &request, PROTOCOL,
                        Some(&command.call.control)).ok().flatten())
                    .unwrap_or_else(|| {
                        json_rpc_error(
                            request["id"].clone(),
                            -32603,
                            "Dispatch failed",
                            json!({"retry_safe": false}),
                        )
                    }),
            };
            registry.set_request_control(None);
            phase = command.call.phase.lock().unwrap();
            response
        };
        *phase = Phase::Completed;
        if command.call.control.cancelled.load(Ordering::SeqCst) {
            // Preserve the actual backend envelope, including failure or success.
            // A cancellation racing a synchronous COM invocation is not rollback.
            if let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) {
                let meta = result.entry("_meta").or_insert_with(||json!({}));
                meta["toolkit.transport"]["cancellation_requested"] = json!(true);
                meta["toolkit.transport"]["retry_safe"] = json!(false);
            }
        }
        drop(phase);
        session.state.lock().unwrap().calls.remove(&command.key);
        // The admission slot remains occupied until dispatch and its RAII
        // cleanup actually finish, even after an HTTP timeout/disconnect.
        drop(command._slot);
        // Publish only after bookkeeping; a completion immediately followed by
        // another request must not spuriously see a duplicate ID/full slot.
        let _ = command.result.send(response);
    }
    session.closed.store(true, Ordering::SeqCst);
    if let Err(error) = registry.finish_owned_sessions("HTTP_SESSION_CLOSED") {
        eprintln!("Toolkit HTTP owner close unverified: {error}");
    }
    // COM interfaces and apartment are destroyed on this same STA thread.
}

fn prepare_capture(
    request: &mut Value,
    root: &Path,
    sequence: &mut u64,
) -> Result<(), &'static str> {
    let args = request
        .get_mut("params")
        .and_then(|p| p.get_mut("arguments"))
        .and_then(Value::as_object_mut)
        .ok_or("capture arguments must be an object")?;
    if args.contains_key("output_path") {
        return Err(
            "HTTP capture output_path is operator-owned; omit it to use this session's evidence directory",
        );
    }
    reject_reparse_ancestors(root).map_err(|_| "unsafe capture root")?;
    fs::create_dir_all(root).map_err(|_| "cannot create capture root")?;
    *sequence = sequence
        .checked_add(1)
        .ok_or("capture sequence exhausted")?;
    let path = root.join(format!("capture-{sequence}.png"));
    if path.exists() {
        return Err("capture path already exists; refusing overwrite");
    }
    args.insert(
        "output_path".into(),
        Value::String(path.to_string_lossy().into_owned()),
    );
    Ok(())
}

fn request_key(id: &Value) -> Option<String> {
    if id.is_string() || id.as_i64().is_some() || id.as_u64().is_some() {
        Some(id.to_string())
    } else {
        None
    }
}
fn valid_rpc(value: &Value) -> bool {
    value.is_object()
        && value["jsonrpc"] == "2.0"
        && value["method"].is_string()
        && value.get("id").is_none_or(|id| request_key(id).is_some())
        && value.get("params").is_none_or(Value::is_object)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idle_session() -> (Arc<Session>, mpsc::Receiver<Command>) {
        let (tx, rx) = mpsc::sync_channel(PER_SESSION_PENDING);
        (
            Arc::new(Session {
                tx,
                closed: Arc::new(AtomicBool::new(false)),
                initialized: AtomicBool::new(true),
                state: Mutex::new(SessionState {
                    last_used: Instant::now(),
                    calls: BTreeMap::new(),
                }),
            }),
            rx,
        )
    }
    fn server_with(sessions: &[(&str, Arc<Session>)]) -> Server {
        Server {
            config: Config {
                port: 1,
                windows_session_id: 1,
                token_file: PathBuf::new(),
                evidence_root: PathBuf::new(),
                request_timeout_ms: None,
            },
            token: String::new(),
            sessions: Mutex::new(
                sessions
                    .iter()
                    .map(|(id, s)| (id.to_string(), Arc::clone(s)))
                    .collect(),
            ),
            connections: Arc::new(AtomicUsize::new(0)),
            workers: Arc::new(AtomicUsize::new(0)),
            pending: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn request(method: &str, session: &str, body: Value) -> wire::Request {
        wire::Request {
            method: method.into(),
            headers: BTreeMap::from([
                ("mcp-session-id".into(), session.into()),
                ("mcp-protocol-version".into(), PROTOCOL.into()),
            ]),
            body: serde_json::to_vec(&body).unwrap(),
        }
    }
    fn pending_call() -> Arc<Call> {
        Arc::new(Call {
            control: RequestControl::new(Duration::from_secs(60)),
            phase: Mutex::new(Phase::Queued),
        })
    }

    #[test]
    fn trusted_http_timeout_preserves_default_and_only_narrows_absolute_budget() {
        let mut server = server_with(&[]);
        assert_eq!(server.config.call_timeout().unwrap(), CALL_TIMEOUT);
        server.config.request_timeout_ms = Some(500);
        assert_eq!(server.config.call_timeout().unwrap(), Duration::from_millis(500));
        for invalid in [0, 99, 90_001, u64::MAX] {
            server.config.request_timeout_ms = Some(invalid);
            assert!(server.config.call_timeout().is_err());
        }
        server.config.request_timeout_ms = Some(90_000);
        assert_eq!(server.config.call_timeout().unwrap(), CALL_TIMEOUT);
    }

    #[test]
    fn cancel_with_same_rpc_id_is_scoped_to_its_session() {
        let (a, _rx_a) = idle_session();
        let (b, _rx_b) = idle_session();
        let ca = pending_call();
        let cb = pending_call();
        a.state
            .lock()
            .unwrap()
            .calls
            .insert("1".into(), Arc::clone(&ca));
        b.state
            .lock()
            .unwrap()
            .calls
            .insert("1".into(), Arc::clone(&cb));
        let server = server_with(&[("a", a), ("b", b)]);
        let (status, _, _) = server.route(request(
            "POST",
            "a",
            json!({"jsonrpc":"2.0", "method":"notifications/cancelled", "params":{"requestId":1}}),
        ));
        assert_eq!(status, 202);
        assert!(ca.control.check().is_err());
        assert!(cb.control.check().is_ok());
    }
    #[test]
    fn duplicate_and_over_capacity_refuse_without_dispatch() {
        let (a, _rx) = idle_session();
        let server = server_with(&[("a", Arc::clone(&a))]);
        a.state
            .lock()
            .unwrap()
            .calls
            .insert("1".into(), pending_call());
        assert_eq!(
            server
                .route(request(
                    "POST",
                    "a",
                    json!({"jsonrpc":"2.0", "id":1, "method":"ping"})
                ))
                .0,
            409
        );
        for id in 2..=PER_SESSION_PENDING {
            a.state
                .lock()
                .unwrap()
                .calls
                .insert(id.to_string(), pending_call());
        }
        assert_eq!(
            server
                .route(request(
                    "POST",
                    "a",
                    json!({"jsonrpc":"2.0", "id":99, "method":"ping"})
                ))
                .0,
            429
        );
        assert_eq!(server.pending.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn global_capacity_refusal_does_not_close_session() {
        let (a, _rx) = idle_session();
        let server = server_with(&[("a", Arc::clone(&a))]);
        server.pending.store(MAX_PENDING, Ordering::SeqCst);
        assert_eq!(
            server
                .route(request(
                    "POST",
                    "a",
                    json!({"jsonrpc":"2.0", "id":1, "method":"ping"})
                ))
                .0,
            429
        );
        assert!(!a.closed.load(Ordering::SeqCst));
        assert!(a.state.lock().unwrap().calls.is_empty());
    }
    #[test]
    fn dead_worker_refuses_and_releases_admission_slot() {
        let (a, rx) = idle_session();
        drop(rx);
        let server = server_with(&[("a", Arc::clone(&a))]);
        assert_eq!(
            server
                .route(request(
                    "POST",
                    "a",
                    json!({"jsonrpc":"2.0", "id":1, "method":"ping"})
                ))
                .0,
            503
        );
        assert_eq!(server.pending.load(Ordering::SeqCst), 0);
        assert!(a.closed.load(Ordering::SeqCst));
        assert!(a.state.lock().unwrap().calls.is_empty());
    }
    #[test]
    fn delete_cancels_only_owned_work_and_invalidates_session() {
        let (a, _rx) = idle_session();
        let ca = pending_call();
        a.state
            .lock()
            .unwrap()
            .calls
            .insert("1".into(), Arc::clone(&ca));
        let server = server_with(&[("a", Arc::clone(&a))]);
        assert_eq!(server.route(request("DELETE", "a", Value::Null)).0, 200);
        assert!(a.closed.load(Ordering::SeqCst));
        assert!(ca.control.check().is_err());
        assert_eq!(server.route(request("GET", "a", Value::Null)).0, 404);
    }
    #[test]
    fn unknown_session_and_optional_sse_are_distinct() {
        let (a, _rx) = idle_session();
        let server = server_with(&[("a", a)]);
        assert_eq!(server.route(request("GET", "a", Value::Null)).0, 405);
        assert_eq!(server.route(request("GET", "other", Value::Null)).0, 404);
    }
    #[test]
    fn idle_expiry_does_not_expire_active_dispatch() {
        let (a, _rx) = idle_session();
        a.state.lock().unwrap().last_used = Instant::now() - IDLE_TIMEOUT - Duration::from_secs(1);
        let ca = pending_call();
        a.state.lock().unwrap().calls.insert("1".into(), ca);
        let server = server_with(&[("a", Arc::clone(&a))]);
        assert_eq!(server.route(request("GET", "a", Value::Null)).0, 405);
        a.state.lock().unwrap().calls.clear();
        assert_eq!(server.route(request("GET", "a", Value::Null)).0, 404);
    }
    #[test]
    fn custom_capture_path_is_refused_before_filesystem_work() {
        let mut capture =
            json!({"params":{"arguments":{"window_id":"win:test", "output_path":"forbidden.png"}}});
        assert!(prepare_capture(&mut capture, Path::new("unused"), &mut 0).is_err());
    }
    #[test]
    fn slots_bound_outstanding_work_including_draining() {
        let count = Arc::new(AtomicUsize::new(0));
        let slot = Slot::try_new(&count, 1).unwrap();
        assert!(Slot::try_new(&count, 1).is_none());
        drop(slot);
        assert!(Slot::try_new(&count, 1).is_some());
    }
    #[test]
    fn numeric_and_text_request_ids_do_not_alias() {
        assert_ne!(request_key(&json!(1)), request_key(&json!("1")));
        assert!(request_key(&Value::Null).is_none());
        assert!(!valid_rpc(&json!([])));
        assert!(!valid_rpc(
            &json!({"jsonrpc":"2.0", "method":"tools/call", "id":null})
        ));
    }
    #[test]
    fn cancellation_and_expiry_refuse_new_dispatch() {
        let control = RequestControl::new(Duration::from_secs(1));
        assert!(control.check().is_ok());
        control.cancel();
        assert_eq!(control.check().unwrap_err().code, "REQUEST_CANCELLED");
        assert_eq!(
            RequestControl::new(Duration::ZERO)
                .check()
                .unwrap_err()
                .code,
            "REQUEST_DEADLINE_EXCEEDED"
        );
    }
}

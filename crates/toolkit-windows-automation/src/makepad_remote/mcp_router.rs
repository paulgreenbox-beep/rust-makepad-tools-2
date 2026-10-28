//! Private routing inside the existing MCP registry. No tools, transport,
//! Scheduler, arbitrary attach operation, or public launch arguments.
use super::{MakepadRemoteAdapter, RemotePlatform, PINNED_SOURCE, protocol::{RemoteError, Result},
    windows::{ApprovedWindowsApp, WindowsRemotePlatform, read_trusted_profile_bytes},
    wslc::{ApprovedWslcApp, WslcRemotePlatform},
    wslc_identity::{ExpectedWslcIdentity, WSLC_FOCUS_MEMORY_MAX, WSLC_MODULE_SHELL_EXECUTABLE,
        WSLC_MODULE_SHELL_MEMORY_MAX}};
use crate::{*, identity::SessionIds, request_control::RequestControl, tool_registry::DispatchSuccess};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{cell::RefCell, collections::{BTreeMap, BTreeSet}, fs::{self, OpenOptions}, io::{Read, Write},
    path::{Path, PathBuf}, rc::Rc, time::{Duration, SystemTime}};

const CONFIG_ENV: &str = "TOOLKIT_MCP_BACKEND_CONFIG";
const HASH_ENV: &str = "TOOLKIT_MCP_BACKEND_CONFIG_SHA256";
const SCHEMA: &str = "toolkit-mcp-backend-routing-v1";
type Adapter = MakepadRemoteAdapter<Box<dyn RemotePlatform>>;
type Control = Rc<RefCell<Option<RequestControl>>>;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Mode { WindowsHidden, Wslc, WindowsVisibleExplicit }

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WidgetBinding {
    automation_id: String,
    widget_id: String,
    name: String,
    /// This migration only projects source-bound editable text widgets.
    control_type: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    /// Exact selector, not a process/port discovery heuristic. A PID selector
    /// cannot launch/adopt a Remote target.
    selector: WindowQuery,
    profile_path: PathBuf,
    profile_sha256: String,
    #[serde(default)]
    mode: Option<Mode>,
    widgets: Vec<WidgetBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    source_commit: String,
    evidence_root: PathBuf,
    admission_path: PathBuf,
    targets: Vec<Target>,
    /// Explicit ordinary UIA selectors. With no routing config the legacy
    /// UIA policy is unchanged; with one, unknown targets fail closed.
    uia_allowlist: Vec<WindowQuery>,
    /// Trusted operator-only metadata can finalize this client's exact owner.
    /// It does not add a tool or permit arbitrary process/window termination.
    #[serde(default)]
    operator_lifecycle: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsProfile {
    schema: String, experimental_opt_in: bool, source_commit: String,
    executable: PathBuf, executable_sha256: String, working_directory: PathBuf,
    owner: String, hidden: bool, #[serde(default)] key_focus_probe: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleShellProfile {
    source_manifest_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WslcProfile {
    schema: String, experimental_opt_in: bool, source_commit: String, owner: String,
    runtime_directory: PathBuf, admission_path: PathBuf, python_executable: PathBuf,
    helper_sha256: String, expected_identity: ExpectedWslcIdentity,
    #[serde(default)] key_focus_probe: bool,
    #[serde(default)] profile_kind: Option<String>,
    #[serde(default)] module_shell: Option<ModuleShellProfile>,
}

impl WslcProfile {
    fn approved_resource_profile(&self) -> Option<(u64, Option<String>)> {
        match (self.profile_kind.as_deref(), self.module_shell.as_ref()) {
            (None, None) | (Some("FocusFixture"), None) => {
                Some((WSLC_FOCUS_MEMORY_MAX, None))
            }
            (Some("ModuleShell"), Some(module))
                if self.expected_identity.executable == WSLC_MODULE_SHELL_EXECUTABLE
                    && module.source_manifest_sha256.len() == 64
                    && module.source_manifest_sha256.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)) =>
            {
                Some((WSLC_MODULE_SHELL_MEMORY_MAX, Some(module.source_manifest_sha256.clone())))
            }
            _ => None,
        }
    }
}

fn denied(code: &str) -> AutomationError { remote_error(RemoteError::refused(code)) }
fn unsupported(code: &str) -> AutomationError {
    AutomationError::with_details(ErrorCode::ActionNotSupported, code,
        json!({"remote_code":code,"outcome":"NOT_DISPATCHED","retry_safe":false,"fallback_used":false}))
}
fn remote_error(error: RemoteError) -> AutomationError {
    AutomationError::with_details(if error.outcome == "NOT_DISPATCHED" {
        ErrorCode::PermissionDenied
    } else { ErrorCode::InvocationFailed }, "Makepad Remote request refused or unverified",
        json!({"backend":"MakepadRemoteAdapter","remote_error":error,"fallback_used":false}))
}
fn parse<T: for<'de> Deserialize<'de>>(args: &Value) -> AutomationResult<T> {
    serde_json::from_value(args.clone()).map_err(|_| AutomationError::invalid_argument("invalid tool arguments"))
}
fn field<'a>(args: &'a Value, key: &str) -> AutomationResult<&'a str> {
    args.get(key).and_then(Value::as_str).ok_or_else(|| AutomationError::invalid_argument(format!("missing {key}")))
}
fn exact_selector(a: &WindowQuery, b: &WindowQuery) -> bool {
    a.process_id == b.process_id && a.process_name == b.process_name
        && a.title == b.title && a.title_contains == b.title_contains
}

enum RemoteKeys<'a> { Key(&'static str, bool), Text(&'a str) }
fn remote_keys(keys: &str) -> AutomationResult<RemoteKeys<'_>> {
    // Preserve the existing native key grammar's outer whitespace handling.
    let text = keys.trim();
    if text.is_empty() || keys.len() > 4096 || keys.chars().any(char::is_control) {
        return Err(unsupported("UNSUPPORTED_REMOTE_TEXT"));
    }
    let upper = text.to_ascii_uppercase();
    let key = match upper.as_str() {
        "CTRL+A" | "CONTROL+A" => Some(("KeyA", true)),
        "BACKSPACE" => Some(("Backspace", false)),
        "LEFT" | "ARROWLEFT" => Some(("ArrowLeft", false)),
        "RIGHT" | "ARROWRIGHT" => Some(("ArrowRight", false)),
        "HOME" => Some(("Home", false)), "END" => Some(("End", false)),
        _ => None,
    };
    if let Some((key, ctrl)) = key { return Ok(RemoteKeys::Key(key, ctrl)); }
    if text.contains('+') || matches!(upper.as_str(), "ENTER" | "RETURN" | "TAB" | "ESC" | "ESCAPE"
        | "DELETE" | "DEL" | "INSERT" | "INS" | "UP" | "DOWN" | "ARROWUP" | "ARROWDOWN"
        | "PAGEUP" | "PAGEDOWN" | "PGUP" | "PGDN" | "SPACE" | "SPACEBAR"
        | "CTRL" | "CONTROL" | "ALT" | "SHIFT" | "WIN" | "META")
        || upper.strip_prefix('F').is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) {
        return Err(unsupported("UNSUPPORTED_REMOTE_KEY_COMBINATION"));
    }
    Ok(RemoteKeys::Text(text))
}
fn post_dispatch_error<P: RemotePlatform>(adapter: &mut MakepadRemoteAdapter<P>, code: &str, cause: AutomationError,
    observed: Option<Value>) -> AutomationError {
    adapter.fence_mutations();
    let mut error = RemoteError::unknown(code);
    error.details["cause"] = json!(cause);
    if let Some(value) = observed { error.details["observed_action"] = value; }
    remote_error(error)
}

// The lease covers dispatch AND independently observed value/focus/health.
// Public ControlInfo projection must not repeat /snap + focus + /s under that
// lease: those observations already exist in the verified adapter result.
fn verified_input_action<P: RemotePlatform>(adapter: &mut MakepadRemoteAdapter<P>,
    sid: &str, window: u64, widget: &str, plan: Option<&RemoteKeys<'_>>) -> AutomationResult<Value> {
    let token = adapter.acquire_input(sid).map_err(remote_error)?;
    let mut acknowledged = false;
    let mut observed = None;
    let result = (|| {
        let mut action = match plan {
            Some(RemoteKeys::Key(key,ctrl)) => adapter.key_event(sid,window,widget,key,*ctrl,&token).map_err(remote_error)?,
            Some(RemoteKeys::Text(text)) => {
                let current = adapter.find_widget(sid,window,widget).map_err(remote_error)?;
                if current["val"].as_str() != Some("") { return Err(unsupported("UNSUPPORTED_CARET_SELECTION_OBSERVATION")); }
                adapter.type_text(sid,window,widget,text,text,&token).map_err(remote_error)?
            }
            None => adapter.click_widget_with_postcondition(sid,window,widget,&token,None).map_err(remote_error)?,
        };
        acknowledged = true;
        observed = Some(action.clone());
        if matches!(plan,Some(RemoteKeys::Text(_))) {
            // Text's value+health are already verified. Keep one fresh actual
            // post-text KeyFocus observation; do not infer it from the ACK.
            let focused = adapter.observe_key_focus(sid,widget).map_err(remote_error)?;
            action["key_focus_verified"] = json!(focused);
            observed = Some(action.clone());
        }
        verified_action_parts(&action,widget,window,adapter.binding().pid)?;
        Ok(action)
    })().map_err(|cause| if acknowledged {
        post_dispatch_error(adapter,"REMOTE_POST_ACTION_OBSERVATION_FAILED",cause,observed.take())
    } else { cause });
    let release = adapter.release_input(sid,&token).map_err(remote_error);
    if release.is_err() { adapter.fence_mutations(); }
    match (result,release) {
        (Err(mut error),Err(cleanup)) => { error.details["lease_cleanup_error"] = json!(cleanup); Err(error) }
        (Err(error),_) => Err(error),
        (Ok(action),Err(error)) => Err(AutomationError::with_details(ErrorCode::InvocationFailed,
            "post-dispatch lease release unverified",json!({"outcome":"OUTCOME_UNKNOWN","cause":error,
                "observed_action":action,"retry_safe":false}))),
        (Ok(action),Ok(())) => Ok(action),
    }
}

fn verified_action_parts<'a>(action: &'a Value, widget: &str, window: u64, pid: u32)
    -> AutomationResult<(&'a Value,&'a Value)> {
    let row = action.get("verified_readback").or_else(|| action.get("readback")).or_else(|| action.get("widget"))
        .ok_or_else(|| denied("POST_ACTION_READBACK_MISSING"))?;
    let runtime = action.get("runtime").ok_or_else(|| denied("POST_ACTION_HEALTH_UNAVAILABLE"))?;
    if row["i"].as_str()!=Some(widget) || row["w"].as_u64()!=Some(window) || row["ty"]!="TextInput"
        || runtime["pid"].as_u64()!=Some(u64::from(pid))
        || runtime["w"].as_array().is_none_or(|rows| rows.iter().filter(|w| w["i"].as_u64()==Some(window)).count()!=1) {
        return Err(denied("POST_ACTION_OBSERVATION_IDENTITY_MISMATCH"));
    }
    if action["key_focus_verified"]!=true { return Err(denied("POST_ACTION_FOCUS_NOT_CONFIRMED")); }
    Ok((row,runtime))
}
fn validate_config(c: &Config) -> AutomationResult<()> {
    if c.schema != SCHEMA || c.source_commit != PINNED_SOURCE || c.targets.is_empty()
        || c.targets.len() > 8 || c.uia_allowlist.len() > 32
        || !c.evidence_root.is_absolute() || !c.admission_path.is_absolute() {
        return Err(denied("TRUSTED_ROUTING_CONFIG_INVALID"));
    }
    let mut selectors = BTreeSet::new();
    for target in &c.targets {
        if target.selector.process_id.is_some() || target.selector.process_name.as_deref().is_none_or(str::is_empty)
            || !target.profile_path.is_absolute() || target.profile_sha256.len() != 64
            || !target.profile_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || target.widgets.is_empty() || target.widgets.len() > 128
            || !selectors.insert(serde_json::to_string(&target.selector).unwrap_or_default()) {
            return Err(denied("TRUSTED_TARGET_INVALID"));
        }
        let (mut automation, mut widgets) = (BTreeSet::new(), BTreeSet::new());
        for w in &target.widgets {
            if w.automation_id.is_empty() || w.widget_id.is_empty() || w.name.len() > 256
                || w.control_type != "Edit" || w.automation_id.len() > 512 || w.widget_id.len() > 4096
                || !automation.insert(&w.automation_id) || !widgets.insert(&w.widget_id) {
                return Err(denied("TRUSTED_WIDGET_BINDING_INVALID"));
            }
        }
    }
    if c.uia_allowlist.iter().any(WindowQuery::is_empty) {
        return Err(denied("UNBOUNDED_UIA_ALLOWLIST_REFUSED"));
    }
    Ok(())
}

/// A cancellation/deadline is checked again at each mutation boundary, not
/// merely before entering registry dispatch. Cleanup never depends on it.
struct ControlledPlatform { inner: Box<dyn RemotePlatform>, control: Control }
impl ControlledPlatform {
    fn check(&self) -> Result<()> {
        self.control.borrow().as_ref().map(|c| c.check()
            .map_err(|e| RemoteError::refused(&e.code))).unwrap_or(Ok(()))
    }
}
impl RemotePlatform for ControlledPlatform {
    fn binding(&self) -> &super::SessionBinding { self.inner.binding() }
    fn validate(&mut self) -> Result<()> { self.inner.validate() }
    fn request(&mut self, t: &str, m: bool) -> Result<Value> {
        if m { self.check()?; } self.inner.request(t, m)
    }
    fn acquire_input(&mut self) -> Result<String> {
        self.check()?;
        let token = self.inner.acquire_input()?;
        if let Err(mut error) = self.check() {
            if let Err(cleanup) = self.inner.release_input(&token) { error.details["lease_cleanup_error"] = json!(cleanup); }
            return Err(error);
        }
        Ok(token)
    }
    fn validate_input(&mut self, t: &str) -> Result<()> { self.check()?; self.inner.validate_input(t) }
    fn release_input(&mut self, t: &str) -> Result<()> { self.inner.release_input(t) }
    fn copy_native_frame(&mut self, v: &Value, d: u64) -> Result<Value> { self.inner.copy_native_frame(v,d) }
    fn reap_normal_exit(&mut self) -> Result<Value> { self.inner.reap_normal_exit() }
    fn cleanup_owned_resources(&mut self) -> Result<Value> { self.inner.cleanup_owned_resources() }
    fn observe_key_focus(&mut self, w: u64, i: &str) -> Result<bool> { self.inner.observe_key_focus(w,i) }
    fn observe_app_semantics(&mut self, request: &super::semantic::ObservationRequest)
        -> Result<super::semantic::AppObservation> {
        self.check()?;
        let observation = self.inner.observe_app_semantics(request)?;
        self.check()?;
        Ok(observation)
    }
    fn arm_app_semantics(&mut self, authorization: &super::semantic::ActionAuthorization) -> Result<()> {
        self.check()?;
        self.inner.arm_app_semantics(authorization)
    }
    fn disarm_app_semantics(&mut self, authorization: &super::semantic::ActionAuthorization) -> Result<()> {
        self.inner.disarm_app_semantics(authorization)
    }
    fn read_runtime_stderr(&mut self) -> Result<Value> { self.inner.read_runtime_stderr() }
    fn host_window_identity(&mut self) -> Result<(u64,u32,u64)> { self.inner.host_window_identity() }
    fn host_content_geometry(&mut self) -> Result<Option<super::HostContentGeometry>> {
        self.check()?;
        let observed = self.inner.host_content_geometry()?;
        self.check()?;
        Ok(observed)
    }
}

struct OwnedTarget {
    target: usize, adapter: Adapter, window: WindowInfo, elements: BTreeMap<String, WidgetBinding>,
    output: PathBuf,
}
pub(crate) struct McpRemoteRouter {
    config: Config, ids: SessionIds, sessions: BTreeMap<String, OwnedTarget>,
    attempted: BTreeSet<usize>, control: Control,
}

impl McpRemoteRouter {
    pub(crate) fn finish_owned_sessions(&mut self, reason: &str) -> AutomationResult<Value> {
        *self.control.borrow_mut() = None;
        let mut receipts = Vec::new();
        let mut first_error = None;
        for (_, mut session) in std::mem::take(&mut self.sessions) {
            match finish_target(&mut session, reason) {
                Ok(receipt) => receipts.push(receipt),
                Err(error) => { if first_error.is_none() { first_error = Some(error); } }
            }
        }
        match first_error {
            Some(mut error) => {
                error.details["completed_other_sessions"] = json!(receipts);
                Err(error)
            }
            None => Ok(json!({"reason":reason,"closed_sessions":receipts})),
        }
    }

    pub(crate) fn invoke_operator_lifecycle(&mut self, metadata: &Value) -> AutomationResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Close { action: String, session_id: String, generation: u64 }
        if !self.config.operator_lifecycle { return Err(denied("OPERATOR_LIFECYCLE_NOT_ENABLED")); }
        let close: Close = serde_json::from_value(metadata.clone())
            .map_err(|_| AutomationError::invalid_argument("invalid operator lifecycle metadata"))?;
        if close.action != "close" || close.session_id.is_empty() || close.generation == 0 {
            return Err(AutomationError::invalid_argument("invalid operator lifecycle identity/action"));
        }
        let id = self.sessions.iter().find(|(_, session)| {
            let binding = session.adapter.binding();
            binding.session_id == close.session_id && binding.generation == close.generation
        }).map(|(id, _)| id.clone()).ok_or_else(|| denied("UNKNOWN_OR_STALE_OWNED_SESSION"))?;
        // Only this registry's exact owned adapter is removed. No PID lookup,
        // foreign adoption, input retry or native UIA fallback is involved.
        let mut session = self.sessions.remove(&id).expect("matched owned session");
        let control = self.control.borrow_mut().take();
        let result = finish_target(&mut session, "OPERATOR_NORMAL_CLOSE");
        *self.control.borrow_mut() = control;
        result
    }

    pub(crate) fn from_operator_environment() -> AutomationResult<Option<Self>> {
        match (std::env::var_os(CONFIG_ENV), std::env::var(HASH_ENV).ok()) {
            (None, None) => Ok(None),
            (Some(path), Some(hash)) => {
                let path = PathBuf::from(path);
                if !path.is_absolute() { return Err(denied("TRUSTED_ROUTING_CONFIG_PATH_REQUIRED")); }
                let c: Config = serde_json::from_slice(&read_trusted_profile_bytes(&path, &hash).map_err(remote_error)?)
                    .map_err(|_| denied("TRUSTED_ROUTING_CONFIG_INVALID"))?;
                validate_config(&c)?;
                no_reparse(&path)?; no_reparse(&c.evidence_root)?;
                let evidence = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reports/evidence"))
                    .map_err(|_| denied("EVIDENCE_ROOT_UNAVAILABLE"))?;
                fs::create_dir_all(&c.evidence_root).map_err(|_| denied("EVIDENCE_ROOT_UNAVAILABLE"))?;
                if !fs::canonicalize(&c.evidence_root).map_err(|_| denied("EVIDENCE_ROOT_UNAVAILABLE"))?.starts_with(evidence) {
                    return Err(denied("TRUSTED_EVIDENCE_ROOT_REQUIRED"));
                }
                Ok(Some(Self { config:c, ids:SessionIds::new(), sessions:BTreeMap::new(),
                    attempted:BTreeSet::new(), control:Rc::new(RefCell::new(None)) }))
            }
            _ => Err(denied("TRUSTED_ROUTING_CONFIG_PIN_REQUIRED")),
        }
    }
    pub(crate) fn set_control(&mut self, control: Option<RequestControl>) { *self.control.borrow_mut() = control; }

    /// Some is terminal, including unsupported/errors. There is no Remote→UIA fallback.
    pub(crate) fn dispatch(&mut self, name: &str, args: &Value, native: &mut WindowsAutomation)
        -> Option<AutomationResult<DispatchSuccess>> {
        if name == "windows_find_window" { return self.find_window(args, native); }
        if name == "windows_get_evidence" { return None; }
        if name == "windows_list_windows" {
            let query: WindowQuery = match parse(args) { Ok(q) => q, Err(e) => return Some(Err(e)) };
            let result = (|| {
                let mut rows = native.list_windows(&query)?;
                rows.retain(|w| self.uia_authorized(w));
                for owned in self.sessions.values_mut() {
                    refresh_window(owned, native)?;
                    if query.matches(&owned.window) { rows.push(owned.window.clone()); }
                }
                DispatchSuccess::value(rows, "ApprovedUIA+MakepadRemote.OwnedWindows")
            })();
            return Some(result);
        }
        let Some(id) = args.get("window_id").and_then(Value::as_str) else {
            // Unscoped native tools must not expose or act on internal UIA IDs.
            return Some(Err(unsupported("UNSUPPORTED_UNSCOPED_ROUTED_TOOL")));
        };
        if !self.sessions.contains_key(id) {
            if id.starts_with("remote:") { return Some(Err(denied("FOREIGN_OR_STALE_REMOTE_WINDOW"))); }
            return match native.get_window_info(id) {
                Ok(window) if self.uia_authorized(&window) => None,
                Ok(_) => Some(Err(denied("BACKEND_NOT_AUTHORIZED"))), Err(error) => Some(Err(error)),
            };
        }
        let mut owned = self.sessions.remove(id).expect("checked owner");
        let result = self.dispatch_owned(name, args, &mut owned, native);
        self.sessions.insert(id.to_owned(), owned);
        Some(result)
    }
    fn uia_authorized(&self, window: &WindowInfo) -> bool {
        // A partially observed launch must not expose its native registration
        // through an ordinary allowlist. Titles are not ownership authority.
        !self.sessions.values().any(|s| s.window.hwnd.is_empty())
            && self.config.uia_allowlist.iter().any(|q| q.matches(window))
            && !self.config.targets.iter().any(|t| t.selector.process_name.as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case(&window.process_name)))
            && !self.sessions.values().any(|s| s.window.hwnd == window.hwnd)
    }
    fn find_window(&mut self, args: &Value, native: &mut WindowsAutomation) -> Option<AutomationResult<DispatchSuccess>> {
        let query: WindowQuery = match parse(args) { Ok(q) => q, Err(e) => return Some(Err(e)) };
        let selected = self.config.targets.iter().position(|t| exact_selector(&t.selector, &query));
        let Some(index) = selected else {
            // An explicit PID query can only refer to an ordinary allowlisted
            // UIA application, never adopt one of our Remote native windows.
            let found = native.find_window(&query);
            return Some(found.and_then(|window| {
                if self.uia_authorized(&window) {
                    DispatchSuccess::value(window,"EnumWindows")
                } else { Err(denied("BACKEND_NOT_AUTHORIZED")) }
            }));
        };
        let existing = self.sessions.iter().find(|(_,s)| s.target == index).map(|(k,_)| k.clone());
        let result = if let Some(id) = existing {
            let owned = self.sessions.get_mut(&id).unwrap();
            refresh_window(owned,native).and_then(|_| DispatchSuccess::value(&owned.window,"MakepadRemote.OwnedWindow"))
        } else { self.launch(index,native) };
        Some(result)
    }
    fn launch(&mut self, index: usize, native: &mut WindowsAutomation) -> AutomationResult<DispatchSuccess> {
        if let Some(control) = self.control.borrow().as_ref() { control.check().map_err(|e| denied(&e.code))?; }
        // A failed/partially dispatched launch is not automatically retried.
        if self.attempted.contains(&index) { return Err(denied("LAUNCH_ALREADY_ATTEMPTED")); }
        let admission = runtime_admission(&self.config.admission_path)?;
        let target = self.config.targets[index].clone();
        no_reparse(&target.profile_path)?;
        let bytes = read_trusted_profile_bytes(&target.profile_path,&target.profile_sha256).map_err(remote_error)?;
        let id = format!("remote:{}", self.ids.window().map_err(|_| denied("IDENTITY_EXHAUSTED"))?);
        let output = self.config.evidence_root.join(id.replace(':',"-"));
        let header: Value = serde_json::from_slice(&bytes).map_err(|_| denied("TRUSTED_PROFILE_INVALID"))?;
        write_new(&self.config.evidence_root.join(format!("{}-prelaunch-admission.json",id.replace(':',"-"))),
            &json!({"schema":"toolkit-mcp-prelaunch-runtime-admission-v1","window_id":id,
                "target_index":index,"profile_sha256":target.profile_sha256,"admission":admission,
                "process_started_by_this_record":false}))?;
        // Parse and check trusted mode BEFORE marking launch or spawning a process.
        let platform: Box<dyn RemotePlatform> = match header["schema"].as_str() {
            Some("toolkit-makepad-remote-trusted-profile-v1") => {
                let c: WindowsProfile = serde_json::from_slice(&bytes).map_err(|_| denied("TRUSTED_PROFILE_INVALID"))?;
                let mode = target.mode.unwrap_or(Mode::WindowsHidden);
                if !matches!(mode,Mode::WindowsHidden|Mode::WindowsVisibleExplicit)
                    || c.hidden != (mode == Mode::WindowsHidden) || !c.experimental_opt_in || c.source_commit != PINNED_SOURCE
                    || c.schema != "toolkit-makepad-remote-trusted-profile-v1"
                    || !c.executable.is_absolute() || !c.working_directory.is_absolute()
                    || c.executable.file_name().and_then(|n| n.to_str()) != target.selector.process_name.as_deref() {
                    return Err(denied("TRUSTED_WINDOWS_MODE_OR_EXECUTABLE_MISMATCH"));
                }
                self.attempted.insert(index);
                Box::new(WindowsRemotePlatform::launch(&ApprovedWindowsApp { experimental_opt_in:true,
                    executable:c.executable, executable_sha256:c.executable_sha256, working_directory:c.working_directory,
                    source_commit:c.source_commit, owner:scoped_owner(&c.owner,&id)?, hidden:c.hidden,
                    key_focus_probe:c.key_focus_probe, output_directory:output.clone() }).map_err(remote_error)?)
            }
            Some("toolkit-makepad-remote-wslc-trusted-profile-v1") => {
                let c: WslcProfile = serde_json::from_slice(&bytes).map_err(|_| denied("TRUSTED_PROFILE_INVALID"))?;
                if target.mode.unwrap_or(Mode::Wslc) != Mode::Wslc || !c.experimental_opt_in || c.source_commit != PINNED_SOURCE
                    || c.schema != "toolkit-makepad-remote-wslc-trusted-profile-v1" {
                    return Err(denied("TRUSTED_WSLC_MODE_MISMATCH"));
                }
                let Some((expected_memory_max, module_shell_source_manifest_sha256)) =
                    c.approved_resource_profile() else {
                    return Err(denied("TRUSTED_WSLC_PROFILE_KIND_MISMATCH"));
                };
                self.attempted.insert(index);
                Box::new(WslcRemotePlatform::launch(&ApprovedWslcApp { experimental_opt_in:true,
                    source_commit:c.source_commit, owner:wslc_context_owner(&c.owner)?, runtime_directory:c.runtime_directory,
                    admission_path:c.admission_path, python_executable:c.python_executable, helper_sha256:c.helper_sha256,
                    expected_identity:c.expected_identity, key_focus_probe:c.key_focus_probe,
                    expected_memory_max, module_shell_source_manifest_sha256, output_directory:output.clone()
                }).map_err(remote_error)?)
            }
            _ => return Err(denied("TRUSTED_PROFILE_INVALID")),
        };
        let adapter = MakepadRemoteAdapter::from_trusted_platform(Box::new(ControlledPlatform {
            inner:platform, control:Rc::clone(&self.control) }) as Box<dyn RemotePlatform>).map_err(|cause| {
                let mut error = RemoteError::unknown("POST_LAUNCH_ADMISSION_UNCONFIRMED");
                error.details["cause"] = json!(cause); remote_error(error)
            })?;
        let mut owned = OwnedTarget { target:index, adapter, window:empty_window(id.clone()), elements:BTreeMap::new(), output };
        let result = refresh_window(&mut owned,native).and_then(|_| DispatchSuccess::value(&owned.window,"MakepadRemote.OwnedLaunch"))
            .map_err(|cause| post_dispatch_error(&mut owned.adapter,"POST_LAUNCH_OBSERVATION_UNCONFIRMED",cause,None));
        // Retain the owner even on observation error, so teardown is still exact.
        self.sessions.insert(id,owned);
        result
    }
    fn dispatch_owned(&mut self, name: &str, args: &Value, s: &mut OwnedTarget, native: &mut WindowsAutomation)
        -> AutomationResult<DispatchSuccess> {
        refresh_window(s,native)?;
        if name == "windows_get_window_info" {
            return DispatchSuccess::value(&s.window,"MakepadRemote.OwnedWindow");
        }
        let sid = s.adapter.binding().session_id.clone();
        let window = s.adapter.binding().window_id;
        let query: ControlQuery = if name == "windows_find_control" || name == "windows_get_control_tree" {
            parse(args)?
        } else { ControlQuery::default() };
        if matches!(name,"windows_get_control_tree"|"windows_find_control") {
            // A pinned /snap is flat, not an invented UIA hierarchy.
            if query.parent_element_id.is_some() { return Err(unsupported("UNSUPPORTED_REMOTE_PARENT_NAVIGATION")); }
            if args.get("max_depth").and_then(Value::as_u64) == Some(0) {
                return Err(unsupported("UNSUPPORTED_REMOTE_TREE_ROOT"));
            }
            let widgets = self.config.targets[s.target].widgets.clone();
            let mut controls = Vec::new();
            for w in widgets { controls.push(self.control_info(s,&w)?); }
            controls.retain(|c| query.matches(c));
            if name == "windows_find_control" {
                let selected = if let Some(index) = query.index { controls.get(index).cloned() }
                    else if controls.len() == 1 { controls.pop() }
                    else if controls.len() > 1 { return Err(AutomationError::new(ErrorCode::AmbiguousElement,"refine control query")); }
                    else { None };
                return DispatchSuccess::value(selected.ok_or_else(|| AutomationError::new(ErrorCode::ElementNotFound,"no approved Remote widget matched"))?,"MakepadRemote.Snapshot");
            }
            let total = controls.len();
            controls.truncate(args.get("max_elements").and_then(Value::as_u64).unwrap_or(512).clamp(1,20000) as usize);
            let view: TreeView = args.get("view").map(|v| serde_json::from_value(v.clone())).transpose()
                .map_err(|_| AutomationError::invalid_argument("invalid view"))?.unwrap_or_default();
            return DispatchSuccess::value(ControlTreeResult { window_id:s.window.window_id.clone(), backend:"MakepadRemoteAdapter".into(),
                view, truncated:controls.len()<total, total_enumerated:total, elements:controls },"MakepadRemote.Snapshot");
        }
        if matches!(name,"windows_set_value"|"windows_set_value_to_automation_id") {
            return Err(unsupported("UNSUPPORTED_SEMANTIC_SET_VALUE"));
        }
        if name == "windows_capture_window" {
            let capture = s.adapter.capture_frame(&sid,window).map_err(remote_error)?;
            let frame = &capture["frame"];
            let path = publish_capture(frame, args.get("output_path").and_then(Value::as_str), &self.config.evidence_root)?;
            let width = frame["width"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or_else(|| denied("CAPTURE_METADATA_INVALID"))?;
            let height = frame["height"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or_else(|| denied("CAPTURE_METADATA_INVALID"))?;
            let result = CaptureResult { window_id:s.window.window_id.clone(),backend:"MakepadRemoteAdapter".into(),
                hwnd:s.window.hwnd.clone(),pid:s.window.process_id,path:path.to_string_lossy().into(),bounds:s.window.bounds,
                dimensions:CaptureDimensions{width,height}, timestamp_unix_ms:frame["captured_at_unix_ms"].as_u64().unwrap_or(0).into(),
                image_width:width,image_height:height,capture_method:"OFFICIAL_MAKEPAD_GPU_G".into(),non_blank:frame["nonblank"]==true,
                occlusion_independent:true,gpu_compatible:true,fallback_used:false,
                diagnostics:vec![format!("session_id={sid}; host PID is not guest PID")],
                limitations:vec!["Native app content; not an OS desktop/frame capture; independent visual review required".into()],geometry:None };
            return Ok(DispatchSuccess { value:serde_json::to_value(result).map_err(|_| denied("CAPTURE_SERIALIZATION_FAILED"))?,
                method:Some("MakepadRemote./g".into()),state:None,screenshot_path:Some(path.to_string_lossy().into()) });
        }
        if !matches!(name,"windows_get_element_state"|"windows_get_automation_id_state"|"windows_click_element"
            |"windows_click_automation_id"|"windows_focus_element"|"windows_focus_automation_id"|"windows_send_keys_to_automation_id") {
            return Err(unsupported("UNSUPPORTED_REMOTE_TOOL_SEMANTICS"));
        }
        let widget = if name.ends_with("automation_id") || name == "windows_get_automation_id_state" {
            let id = field(args,"automation_id")?;
            self.config.targets[s.target].widgets.iter().find(|w| w.automation_id == id).cloned()
                .ok_or_else(|| AutomationError::new(ErrorCode::ElementNotFound,"unknown approved AutomationId"))?
        } else {
            s.elements.get(field(args,"element_id")?).cloned()
                .ok_or_else(|| AutomationError::new(ErrorCode::StaleElement,"foreign or stale Remote element"))?
        };
        // Parse every keyboard request before acquiring a grant or dispatching
        // any input. In particular, never click to discover an unsupported key.
        let keys = if name == "windows_send_keys_to_automation_id" { Some(field(args,"keys")?) } else { None };
        let key_plan = keys.map(remote_keys).transpose()?;
        let before = self.control_info(s,&widget)?;
        if matches!(name,"windows_get_element_state"|"windows_get_automation_id_state") {
            return DispatchSuccess::value(state(&s.window,&before),"MakepadRemote.Snapshot+CxKeyFocus");
        }
        if let Some(plan) = &key_plan {
            if !before.focused { return Err(denied("WIDGET_KEY_FOCUS_NOT_CONFIRMED")); }
            if matches!(plan,RemoteKeys::Text(_)) && before.value.as_deref()!=Some("") {
                return Err(unsupported("UNSUPPORTED_CARET_SELECTION_OBSERVATION"));
            }
        }
        let action = verified_input_action(&mut s.adapter,&sid,window,&widget.widget_id,key_plan.as_ref())?;
        // No input grant is held beyond this point. Project the exact observed
        // action data, with fresh native geometry/ownership checks but NO new
        // Remote snapshot, focus, or health round trips.
        let result = (|| {
            let (row,runtime) = verified_action_parts(&action,&widget.widget_id,window,s.adapter.binding().pid)?;
            let after = self.project_control_info(s,&widget,row,runtime,true)?;
            if let Some(plan) = &key_plan {
                // FocusResult remains a native-foreground observation. Never
                // label Makepad KeyFocus as successful SetForegroundWindow.
                let focus = FocusResult { requested_window:s.window.clone(),previous_foreground:None,
                    resulting_foreground:None,success:false };
                let value = SendKeysResult { target_window:s.window.clone(),requested_keys:keys.unwrap().into(),focus_acquisition:focus,
                    input_events_requested:1,input_events_injected:1,success:true };
                let mut out = DispatchSuccess::value(value,"KEYBOARD_EDITING_VIA_APP_REMOTE")?;
                out.value["_meta"] = json!({"focus_scope":"MAKEPAD_KEY_FOCUS","native_foreground_requested":false,
                    "business_postcondition_verified":matches!(plan,RemoteKeys::Text(_)),
                    "event_count_scope":"ONE_ACKNOWLEDGED_APP_REMOTE_COMMAND_NOT_WIN32_INPUT_EVENTS",
                    "native_input_events_observed":false,"native_foreground_focus_verified":false,
                    "observed_action":action,"session_id":sid,"mechanism":super::INPUT_MECHANISM,
                    "lease_scope":"DISPATCH_READBACK_FOCUS_HEALTH_RELEASED_BEFORE_PUBLIC_PROJECTION"});
                out.state = Some(json!(state(&s.window,&after)));
                return Ok(out);
            }
            if name.starts_with("windows_focus_") {
                return DispatchSuccess::value(state(&s.window,&after),"MakepadRemote.Click+CxKeyFocus");
            }
            DispatchSuccess::value(ClickResult {success:true,resolved_element:after.clone(),
                action_method:"MakepadRemote.Click+CxKeyFocus".into(),before_state:state(&s.window,&before),
                after_state:Some(state(&s.window,&after)),after_error:None},"MakepadRemote.Click+CxKeyFocus")
        })().map_err(|cause| post_dispatch_error(&mut s.adapter,"REMOTE_POST_ACTION_OBSERVATION_FAILED",cause,Some(action)));
        result
    }
    fn control_info(&mut self, s: &mut OwnedTarget, w: &WidgetBinding) -> AutomationResult<ControlInfo> {
        let sid = s.adapter.binding().session_id.clone();
        let row = s.adapter.find_widget(&sid,s.adapter.binding().window_id,&w.widget_id).map_err(remote_error)?;
        if row["ty"] != "TextInput" { return Err(unsupported("UNSUPPORTED_REMOTE_WIDGET_TYPE")); }
        let focused = s.adapter.observe_key_focus(&sid,&w.widget_id).map_err(remote_error)?;
        let status = s.adapter.inspect_window(&sid).map_err(remote_error)?;
        self.project_control_info(s,w,&row,&status,focused)
    }
    fn project_control_info(&mut self, s: &mut OwnedTarget, w: &WidgetBinding,
        row: &Value, status: &Value, focused: bool) -> AutomationResult<ControlInfo> {
        let id = if let Some((id,_)) = s.elements.iter().find(|(_,b)| b.widget_id == w.widget_id) { id.clone() }
            else { let id = self.ids.element().map_err(|_| denied("IDENTITY_EXHAUSTED"))?; s.elements.insert(id.clone(),w.clone()); id };
        let sid = s.adapter.binding().session_id.clone();
        let (hwnd,pid,birth) = s.adapter.host_window_identity(&sid).map_err(remote_error)?;
        if s.window.hwnd != format!("0x{hwnd:X}") || s.window.process_id != pid {
            return Err(denied("HOST_WINDOW_IDENTITY_CHANGED"));
        }
        crate::desktop_arbiter::owned_window(hwnd,pid,birth).map_err(|_| denied("HOST_WINDOW_IDENTITY_CHANGED"))?;
        let wslc = s.adapter.binding().platform == "linux-wslc-owned-container";
        let geometry = if wslc { s.adapter.host_content_geometry(&sid).map_err(remote_error)? } else { None };
        let bounds = physical_widget_bounds(&s.window,row,status,s.adapter.binding().window_id,wslc,geometry.as_ref())?;
        crate::desktop_arbiter::owned_window(hwnd,pid,birth).map_err(|_| denied("HOST_WINDOW_IDENTITY_CHANGED"))?;
        Ok(ControlInfo { element_id:id,parent_element_id:None,control_type:"Edit".into(),control_type_id:50004,
            localized_control_type:"edit".into(),name:w.name.clone(),value:row["val"].as_str().map(str::to_owned),text:None,
            automation_id:w.automation_id.clone(),class_name:"TextInput".into(),framework_id:"MakepadRemoteAdapter".into(),bounds,
            // Native hidden != semantic widget offscreen. This API reports widget visibility.
            visible:true,offscreen:false,enabled:row["enabled"]==true,focused,selected:None,expand_state:None,
            capabilities:ActionCapabilities::default(),hwnd:Some(s.window.hwnd.clone()) })
    }
}

impl Drop for McpRemoteRouter {
    fn drop(&mut self) {
        if let Err(error) = self.finish_owned_sessions("OWNER_DROP") {
            // Drop cannot propagate, but explicit transport finalization can.
            eprintln!("Toolkit owned owner finalization unverified: {error}");
        }
    }
}

fn finish_target(session: &mut OwnedTarget, reason: &str) -> AutomationResult<Value> {
    let binding = session.adapter.binding().clone();
    let started = std::time::Instant::now();
    let stderr = session.adapter.runtime_stderr(&binding.session_id);
    let close = session.adapter.close(&binding.session_id);
    // Always contain only our exact owner after an uncertain close, without
    // re-dispatching /quit. Containment never becomes normal completion.
    let cleanup = session.adapter.cleanup();
    let normal = close.as_ref().is_ok_and(|value| value["exit_code"] == 0
        && value["normal_exit_observed"] == true)
        && cleanup.as_ref().is_ok_and(|value| value["normal_exit_observed"] == true
            && value["forced_cleanup"] == false && value["active_owned_leases"] == 0
            && value["hwnd_gone"] == true && value["listener_absence_proven"] == true);
    let receipt = json!({"schema":"toolkit-mcp-owner-session-close-v1","session_id":binding.session_id,
        "binding":binding,"server_pid":std::process::id(),"reason":reason,
        "elapsed_ms":started.elapsed().as_millis(),
        "status":if normal {"NORMAL_EXIT_VERIFIED"} else if cleanup.is_ok() {"OWNED_CONTAINMENT"} else {"OUTCOME_UNKNOWN"},
        "runtime_stderr":stderr,"normal_close":close,"cleanup":cleanup,
        "retry_safe":false,"automatic_retry_allowed":false});
    let published = write_new(&session.output.join("mcp-session-close.json"), &receipt);
    if !normal || published.is_err() {
        return Err(AutomationError::with_details(ErrorCode::InvocationFailed,
            "owned session finalization was not verified", json!({"receipt":receipt,"publication":published})));
    }
    Ok(receipt)
}
fn scoped_owner(prefix: &str, id: &str) -> AutomationResult<String> {
    let owner = format!("{prefix}:{id}");
    if prefix.is_empty() || owner.len()>128 { Err(denied("TRUSTED_OWNER_REQUIRED")) } else { Ok(owner) }
}
fn wslc_context_owner(owner: &str) -> AutomationResult<String> {
    // The trusted bootstrap already binds this exact label to CID/image/nonce.
    // A client suffix would invent a different provisioning owner. Per-client
    // isolation remains the router registry plus native SessionId/generation;
    // the existing WSLC owner permits one consumer of the approved context.
    if owner.is_empty() || owner.len() > 128 { Err(denied("TRUSTED_OWNER_REQUIRED")) }
    else { Ok(owner.to_owned()) }
}
fn empty_window(window_id: String) -> WindowInfo {
    WindowInfo {window_id,hwnd:String::new(),process_id:0,process_name:String::new(),title:String::new(),
        class_name:String::new(),bounds:Rect::default(),visible:false,focused:false,foreground:false}
}
fn refresh_window(s: &mut OwnedTarget, native: &mut WindowsAutomation) -> AutomationResult<()> {
    let sid = s.adapter.binding().session_id.clone();
    let (hwnd,pid,birth) = s.adapter.host_window_identity(&sid).map_err(remote_error)?;
    crate::desktop_arbiter::owned_window(hwnd,pid,birth).map_err(|_| denied("HOST_WINDOW_IDENTITY_CHANGED"))?;
    let rows = native.list_windows(&WindowQuery {process_id:Some(pid),..Default::default()})?;
    let mut window = rows.into_iter().find(|w| w.hwnd == format!("0x{hwnd:X}"))
        .ok_or_else(|| denied("HOST_WINDOW_UNAVAILABLE"))?;
    crate::desktop_arbiter::owned_window(hwnd,pid,birth).map_err(|_| denied("HOST_WINDOW_IDENTITY_CHANGED"))?;
    window.window_id = s.window.window_id.clone(); s.window = window;
    Ok(())
}
fn state(window: &WindowInfo, c: &ControlInfo) -> ElementState {
    ElementState {exists:true,element_id:c.element_id.clone(),window_id:window.window_id.clone(),visible:c.visible,
        enabled:c.enabled,focused:c.focused,selected:c.selected,name:c.name.clone(),control_type:c.control_type.clone(),
        bounds:c.bounds,value:c.value.clone(),text:c.text.clone()}
}
fn no_reparse(path: &Path) -> AutomationResult<()> {
    use std::os::windows::fs::MetadataExt;
    if !path.is_absolute() || path.components().any(|c| matches!(c,std::path::Component::ParentDir)) { return Err(denied("UNTRUSTED_ROUTING_PATH")); }
    for p in path.ancestors() {
        match fs::symlink_metadata(p) {
            Ok(m) if m.file_attributes() & 0x400 != 0 => return Err(denied("ROUTING_REPARSE_PATH_REFUSED")),
            Ok(_) => (), Err(e) if e.kind()==std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(denied("ROUTING_PATH_UNAVAILABLE")),
        }
    }
    Ok(())
}
fn write_new(path: &Path, value: &Value) -> AutomationResult<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| denied("EVIDENCE_SERIALIZATION_FAILED"))?;
    OpenOptions::new().write(true).create_new(true).open(path).and_then(|mut f| {
        f.write_all(&bytes)?;
        f.sync_all()
    })
        .map_err(|_| denied("EXCLUSIVE_EVIDENCE_WRITE_FAILED"))
}
fn publish_capture(frame: &Value, requested: Option<&str>, root: &Path) -> AutomationResult<PathBuf> {
    let source = PathBuf::from(frame["path"].as_str().ok_or_else(|| denied("CAPTURE_METADATA_INVALID"))?);
    let Some(requested) = requested else { return Ok(source); };
    let dest = PathBuf::from(requested); no_reparse(&dest)?;
    let parent = fs::canonicalize(dest.parent().ok_or_else(|| denied("CAPTURE_PATH_REFUSED"))?)
        .map_err(|_| denied("CAPTURE_PARENT_UNAVAILABLE"))?;
    if !parent.starts_with(fs::canonicalize(root).map_err(|_| denied("CAPTURE_ROOT_UNAVAILABLE"))?) {
        return Err(denied("CAPTURE_PATH_REFUSED"));
    }
    let mut input = fs::File::open(source).map_err(|_| denied("CAPTURE_READ_FAILED"))?;
    let mut output = OpenOptions::new().write(true).create_new(true).open(&dest).map_err(|_| denied("CAPTURE_PATH_REFUSED"))?;
    std::io::copy(&mut input,&mut output).map_err(|_| denied("CAPTURE_COPY_FAILED"))?;
    Ok(dest)
}

/// Current operator-approved stock runtime floor: 2 GiB, not a RAM waiver.
/// Cold-build admission and internal container limits are owned elsewhere.
fn runtime_admission(path: &Path) -> AutomationResult<Value> {
    no_reparse(path)?;
    let metadata = fs::metadata(path).map_err(|_| denied("RESOURCE_ADMISSION_REQUIRED"))?;
    if !metadata.is_file() || metadata.len()>65536 || SystemTime::now().duration_since(metadata.modified().map_err(|_| denied("RESOURCE_ADMISSION_REQUIRED"))?)
        .map_err(|_| denied("RESOURCE_ADMISSION_REQUIRED"))? > Duration::from_secs(60) {
        return Err(denied("FRESH_RESOURCE_ADMISSION_REQUIRED"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path).map_err(|_| denied("RESOURCE_ADMISSION_REQUIRED"))?.take(65537)
        .read_to_end(&mut bytes).map_err(|_| denied("RESOURCE_ADMISSION_REQUIRED"))?;
    if bytes.len()>65536 { return Err(denied("RESOURCE_ADMISSION_INVALID")); }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| denied("RESOURCE_ADMISSION_INVALID"))?;
    if value["status"] != "ADMITTED" || value["purpose"] != "runtime"
        || value["required_free_kib"].as_u64()!=Some(2*1024*1024)
        || value["free_physical_kib"].as_u64().is_none_or(|v| v<2*1024*1024)
        || !value["active_rust_compilers"].as_array().is_some_and(Vec::is_empty) {
        return Err(denied("RESOURCE_ADMISSION_REFUSED"));
    }
    #[repr(C)]
    struct Memory { length:u32,load:u32,total:u64,available:u64,page_total:u64,page_available:u64,
        virtual_total:u64,virtual_available:u64,extended:u64 }
    #[link(name="kernel32")]
    unsafe extern "system" { fn GlobalMemoryStatusEx(status:*mut Memory) -> i32; }
    let mut memory = Memory {length:std::mem::size_of::<Memory>() as u32,load:0,total:0,available:0,page_total:0,
        page_available:0,virtual_total:0,virtual_available:0,extended:0};
    if unsafe { GlobalMemoryStatusEx(&mut memory) } == 0 || memory.available<2*1024*1024*1024 {
        return Err(denied("RESOURCE_ADMISSION_REFUSED"));
    }
    use sha2::{Digest,Sha256};
    let at = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| denied("RESOURCE_ADMISSION_REQUIRED"))?.as_millis();
    Ok(json!({"status":"ADMITTED","purpose":"runtime","stock_admission_path":path,
        "stock_admission_sha256":format!("{:X}",Sha256::digest(&bytes)),
        "stock_free_physical_kib":value["free_physical_kib"],"required_free_kib":2*1024*1024u64,
        "actual_sample":{"source":"GlobalMemoryStatusEx","observed_unix_ms":at,
            "available_physical_kib":memory.available/1024,"total_physical_kib":memory.total/1024},
        "global_resource_policy_changed":false,"runtime_acceptance_claimed":false}))
}

// Pure mapping from measured rectangles. No padding constants or fallback to
// a native HWND client pretending to be Makepad content. The current RAIL
// contract requires its physical outer/client rectangle to represent the X11
// frame; an additional unproven native decoration is a refusal.
fn wslc_widget_bounds(row: &Value, remote: &Value, g: &super::HostContentGeometry) -> std::result::Result<Rect, &'static str> {
    let x = &g.x11;
    let c = &x.client; let f = &x.frame; let n = &g.native_client;
    let sane = |r: &super::ObservedGeometryRect| r.width>0 && r.height>0 && r.width<=65536 && r.height<=65536;
    if !sane(c)||!sane(f)||!sane(n)||g.native_outer!=g.native_client { return Err("WSLC_RAIL_OUTER_CLIENT_FRAME_MISMATCH"); }
    let [left,right,top,bottom] = x.frame_extents;
    if !matches!(x.frame_source.as_str(),"NET_FRAME_EXTENTS"|"REPARENT_FRAME")
        || x.window==0 || x.root==0 || x.window==x.root
        || (x.frame_source=="REPARENT_FRAME" && x.frame_window.is_none())
        || x.frame_window.is_some_and(|id|id==0||id==x.window||id==x.root)
        || [left,right,top,bottom].iter().any(|v|*v>32768)
        || i64::from(c.x)-i64::from(f.x)!=i64::from(left)
        || i64::from(c.y)-i64::from(f.y)!=i64::from(top)
        || u64::from(f.width)!=u64::from(c.width)+u64::from(left)+u64::from(right)
        || u64::from(f.height)!=u64::from(c.height)+u64::from(top)+u64::from(bottom) {
        return Err("WSLC_X11_FRAME_CONTENT_CONTRADICTION");
    }
    let scale=f64::from(n.width)/f64::from(f.width);
    if !scale.is_finite()||scale<=0.0||scale>16.0
        || (scale-f64::from(n.height)/f64::from(f.height)).abs()>1e-6 {
        return Err("WSLC_NONUNIFORM_FRAME_SCALE");
    }
    let number=|v:&Value|v.as_f64().filter(|v|v.is_finite()).ok_or("WSLC_REMOTE_GEOMETRY_INVALID");
    if row["r"].as_array().is_none_or(|r|r.len()!=4) {return Err("WSLC_REMOTE_GEOMETRY_INVALID");}
    let dpi=number(&remote["dpi"])?;
    if dpi<=0.0 || (number(&remote["px"][0])?-f64::from(c.width)).abs()>0.01
        || (number(&remote["px"][1])?-f64::from(c.height)).abs()>0.01
        || (number(&remote["pos"][0])?*dpi-f64::from(c.x)).abs()>0.01
        || (number(&remote["pos"][1])?*dpi-f64::from(c.y)).abs()>0.01 {
        return Err("WSLC_REMOTE_X11_CONTENT_MISMATCH");
    }
    let (rx,ry,rw,rh)=(number(&row["r"][0])?,number(&row["r"][1])?,number(&row["r"][2])?,number(&row["r"][3])?);
    if rx<0.0||ry<0.0||rw<=0.0||rh<=0.0||(rx+rw)*dpi>f64::from(c.width)||(ry+rh)*dpi>f64::from(c.height) {
        return Err("WSLC_WIDGET_OUTSIDE_CONTENT");
    }
    let origin_x=f64::from(n.x)+f64::from(left)*scale;
    let origin_y=f64::from(n.y)+f64::from(top)*scale;
    let l=(origin_x+rx*dpi*scale).floor();let t=(origin_y+ry*dpi*scale).floor();
    let r=(origin_x+(rx+rw)*dpi*scale).ceil();let b=(origin_y+(ry+rh)*dpi*scale).ceil();
    let integer=|v:f64|if v.is_finite()&&v>=f64::from(i32::MIN)&&v<=f64::from(i32::MAX){Ok(v as i32)}else{Err("WSLC_GEOMETRY_OVERFLOW")};
    if l<f64::from(n.x)||t<f64::from(n.y)||r>f64::from(n.x)+f64::from(n.width)||b>f64::from(n.y)+f64::from(n.height) {
        return Err("WSLC_WIDGET_OUTSIDE_NATIVE_FRAME");
    }
    Ok(Rect{x:integer(l)?,y:integer(t)?,width:integer(r-l)?,height:integer(b-t)?})
}

fn physical_widget_bounds(window: &WindowInfo, row: &Value, status: &Value, id: u64,
    wslc: bool, geometry: Option<&super::HostContentGeometry>) -> AutomationResult<Rect> {
    use windows::Win32::{Foundation::{HWND,POINT,RECT},Graphics::Gdi::ClientToScreen,UI::WindowsAndMessaging::{GetClientRect,GetWindowRect}};
    let _scope = crate::PhysicalPixelScope::enter()?;
    let hwnd = u64::from_str_radix(window.hwnd.trim_start_matches("0x"),16).map_err(|_| denied("HOST_WINDOW_IDENTITY_CHANGED"))?;
    let hwnd = HWND(hwnd as usize as *mut _);
    let mut r = RECT::default(); let mut origin = POINT::default();
    unsafe { GetClientRect(hwnd,&mut r) }.map_err(|_| denied("CLIENT_GEOMETRY_UNAVAILABLE"))?;
    if !unsafe { ClientToScreen(hwnd,&mut origin) }.as_bool() { return Err(denied("CLIENT_GEOMETRY_UNAVAILABLE")); }
    let w = status["w"].as_array().and_then(|rows| rows.iter().find(|w| w["i"].as_u64()==Some(id)))
        .ok_or_else(|| denied("REMOTE_GEOMETRY_UNAVAILABLE"))?;
    let dpi = w["dpi"].as_f64().filter(|v| v.is_finite() && *v>0.0).ok_or_else(|| denied("REMOTE_GEOMETRY_UNAVAILABLE"))?;
    let px = |i:usize| w["px"][i].as_f64().filter(|v| v.is_finite() && *v>0.0)
        .ok_or_else(|| denied("REMOTE_GEOMETRY_UNAVAILABLE"));
    let client_width=f64::from(r.right)-f64::from(r.left);
    let client_height=f64::from(r.bottom)-f64::from(r.top);
    if wslc {
        let mut outer=RECT::default();
        unsafe { GetWindowRect(hwnd,&mut outer) }.map_err(|_|denied("CLIENT_GEOMETRY_UNAVAILABLE"))?;
        let observed_client=super::ObservedGeometryRect{x:origin.x,y:origin.y,
            width:u32::try_from(r.right-r.left).unwrap_or(0),height:u32::try_from(r.bottom-r.top).unwrap_or(0)};
        let observed_outer=super::ObservedGeometryRect{x:outer.left,y:outer.top,
            width:u32::try_from(outer.right-outer.left).unwrap_or(0),height:u32::try_from(outer.bottom-outer.top).unwrap_or(0)};
        let result=geometry.ok_or("WSLC_GEOMETRY_WITNESS_MISSING").and_then(|g|{
            if g.native_client!=observed_client||g.native_outer!=observed_outer||g.native_outer.x!=window.bounds.x
                ||g.native_outer.y!=window.bounds.y||i64::from(g.native_outer.width)!=i64::from(window.bounds.width)
                ||i64::from(g.native_outer.height)!=i64::from(window.bounds.height)
                ||g.rail_hwnd!=u64::from_str_radix(window.hwnd.trim_start_matches("0x"),16).unwrap_or(0)
                ||g.rail_pid!=window.process_id {return Err("WSLC_LIVE_NATIVE_GEOMETRY_CHANGED");}
            wslc_widget_bounds(row,w,g)
        });
        return result.map_err(|reason|AutomationError::with_details(ErrorCode::CoordinateMappingUnverified,
            "native client and Remote render geometry are not proven",json!({"hwnd":window.hwnd,
                "host_window_bounds":window.bounds,"native_client_width":client_width,"native_client_height":client_height,
                "native_client_origin":{"x":origin.x,"y":origin.y},"remote_window":w,"window_id":id,
                "geometry_refusal":reason,"host_content_geometry":geometry,"mutation_dispatched_by_projection":false})));
    }
    if client_width<=0.0 || client_height<=0.0 || (px(0)?-client_width).abs()>1.0 || (px(1)?-client_height).abs()>1.0 {
        return Err(AutomationError::with_details(ErrorCode::CoordinateMappingUnverified,
            "native client and Remote render size disagree", json!({"hwnd":window.hwnd,
                "host_window_bounds":window.bounds,"native_client_width":client_width,
                "native_client_height":client_height,"native_client_origin":{"x":origin.x,"y":origin.y},
                "remote_window":w,"window_id":id,"mutation_dispatched_by_projection":false})));
    }
    let n = |i:usize| -> AutomationResult<f64> { row["r"][i].as_f64().filter(|v| v.is_finite())
        .ok_or_else(|| denied("REMOTE_GEOMETRY_UNAVAILABLE")) };
    let integer = |v:f64| if v.is_finite() && v>=f64::from(i32::MIN) && v<=f64::from(i32::MAX) {Ok(v as i32)}
        else {Err(denied("REMOTE_GEOMETRY_OVERFLOW"))};
    let (x,y,width,height)=(n(0)?,n(1)?,n(2)?,n(3)?);
    if width<=0.0 || height<=0.0 { return Err(denied("REMOTE_GEOMETRY_UNAVAILABLE")); }
    let left=(x*dpi).floor(); let top=(y*dpi).floor();
    Ok(Rect{x:integer(f64::from(origin.x)+left)?,y:integer(f64::from(origin.y)+top)?,
        width:integer(((x+width)*dpi).ceil()-left)?,height:integer(((y+height)*dpi).ceil()-top)?})
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod module_shell_profile_tests {
    use super::*;
    use serde_json::json;

    fn trusted_wslc_profile_value() -> Value {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("module-shell-profile-test-only");
        json!({"schema":"toolkit-makepad-remote-wslc-trusted-profile-v1",
            "experimental_opt_in":true, "source_commit":PINNED_SOURCE, "owner":"synthetic-owner",
            "runtime_directory":root.join("runtime"), "admission_path":root.join("admission.json"),
            "python_executable":root.join("python.exe"), "helper_sha256":"F".repeat(64),
            "expected_identity":{"container_id":"a".repeat(64),
                "image_id":format!("sha256:{}", "b".repeat(64)),
                "executable":WSLC_MODULE_SHELL_EXECUTABLE, "executable_sha256":"C".repeat(64)}})
    }

    #[test]
    fn wslc_trusted_profile_selects_only_fixed_module_shell_memory() {
        let focus: WslcProfile = serde_json::from_value(trusted_wslc_profile_value()).unwrap();
        assert_eq!(focus.approved_resource_profile(), Some((WSLC_FOCUS_MEMORY_MAX, None)));

        let source_sha = "A".repeat(64);
        let mut module_value = trusted_wslc_profile_value();
        module_value["profile_kind"] = json!("ModuleShell");
        module_value["module_shell"] = json!({"source_manifest_sha256":source_sha});
        let module: WslcProfile = serde_json::from_value(module_value.clone()).unwrap();
        assert_eq!(module.approved_resource_profile(),
            Some((WSLC_MODULE_SHELL_MEMORY_MAX, Some(source_sha.clone()))));

        module_value["module_shell"]["source_manifest_sha256"] = json!(source_sha.to_lowercase());
        let lower: WslcProfile = serde_json::from_value(module_value).unwrap();
        assert_eq!(lower.approved_resource_profile(), None);

        let mut arbitrary = trusted_wslc_profile_value();
        arbitrary["profile_kind"] = json!("ModuleShell");
        arbitrary["module_shell"] = json!({"source_manifest_sha256":"A".repeat(64)});
        arbitrary["expected_identity"]["executable"] = json!("/opt/proof/other-app");
        let arbitrary: WslcProfile = serde_json::from_value(arbitrary).unwrap();
        assert_eq!(arbitrary.approved_resource_profile(), None);

        let mut malformed = trusted_wslc_profile_value();
        malformed["unexpected_memory_override"] = json!(2_147_483_648_u64);
        assert!(serde_json::from_value::<WslcProfile>(malformed).is_err());
        let mut malformed = trusted_wslc_profile_value();
        malformed["profile_kind"] = json!("ModuleShell");
        malformed["module_shell"] = json!({"source_manifest_sha256":"A".repeat(64),
            "memory_bytes":2_147_483_648_u64});
        assert!(serde_json::from_value::<WslcProfile>(malformed).is_err());
    }
}

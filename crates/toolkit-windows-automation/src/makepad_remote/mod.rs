//! Experimental official Makepad App Remote adapter.
//!
//! This owner contains no Script runner, HTTP server or Scheduler. Platforms
//! retain process/transport ownership; the adapter owns checked App Remote
//! sequences. Construct it only from operator-approved launch configuration.
#[cfg(test)]
mod adapter_tests;
mod focus_probe;
mod http;
#[cfg(windows)]
pub(crate) mod mcp_router;
mod native_frame;
pub mod protocol;
pub mod semantic;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub mod wslc;
pub mod wslc_identity;
#[cfg(windows)]
mod wslc_pipe;

use protocol::{Activity, RemoteError, Result, encode, exact_widget};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const PINNED_SOURCE: &str = "71c9ddcbb9c01dd208f99621fdd71024a5d35c65";
pub const INPUT_MECHANISM: &str = "KEYBOARD_EDITING_VIA_APP_REMOTE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyFocusPolicy {
    PreserveTarget,
    MayTransition,
}

impl KeyFocusPolicy {
    fn for_key(key: &str, ctrl: bool) -> Result<Self> {
        match (key, ctrl) {
            ("KeyA", _) | ("Backspace" | "ArrowLeft" | "ArrowRight" | "Home" | "End", false) => {
                Ok(Self::PreserveTarget)
            }
            ("Tab" | "Enter" | "Escape", false) => Ok(Self::MayTransition),
            _ => Err(RemoteError::refused("UNSUPPORTED_KEY_COMBINATION")),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::PreserveTarget => "PRESERVE_TARGET",
            Self::MayTransition => "MAY_TRANSITION",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionBinding {
    pub session_id: String,
    pub owner: String,
    pub generation: u64,
    pub pid: u32,
    pub process_birth: String,
    pub executable: String,
    pub executable_sha256: String,
    pub source_commit: String,
    pub window_id: u64,
    pub platform: String,
}

/// Observed geometry from the existing native owner; never supplied by MCP.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedGeometryRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedX11Geometry {
    pub schema: String,
    pub display: String,
    pub title: String,
    /// Owner-verified guest PID is not an observed X11 property/namespace.
    pub expected_guest_pid: u32,
    pub pid_property: Option<u32>,
    pub identity_source: String,
    pub window: u64,
    pub root: u64,
    pub client: ObservedGeometryRect,
    pub frame: ObservedGeometryRect,
    /// X11 order: left, right, top, bottom. All are measured properties/frames.
    pub frame_extents: [u32; 4],
    pub frame_source: String,
    pub frame_window: Option<u64>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostContentGeometry {
    pub schema: String,
    pub session_id: String,
    pub generation: u64,
    pub sequence: u64,
    /// Actual exact X11 title and separately observed WSLg RAIL title.
    pub tag: String,
    pub title: String,
    pub rail_title: String,
    pub container_id: String,
    pub guest_pid: u32,
    pub guest_process_start_ticks: String,
    pub rail_hwnd: u64,
    pub rail_pid: u32,
    pub rail_process_birth: String,
    pub started_monotonic_ns: u64,
    pub observed_monotonic_ns: u64,
    pub observed_unix_ms: u64,
    pub native_client: ObservedGeometryRect,
    pub native_outer: ObservedGeometryRect,
    pub x11: ObservedX11Geometry,
    pub raw_x11_utf8: String,
    pub raw_x11_sha256: String,
}

/// Implemented by an existing trusted platform owner, never by a TestJob.
/// `request` must recheck process birth, executable bytes and listener owner
/// BEFORE HTTP, enforce loopback and the route allowlist, and never retry.
pub trait RemotePlatform {
    fn binding(&self) -> &SessionBinding;
    fn validate(&mut self) -> Result<()>;
    fn request(&mut self, target: &str, mutating: bool) -> Result<Value>;
    fn acquire_input(&mut self) -> Result<String>;
    fn validate_input(&mut self, token: &str) -> Result<()>;
    fn release_input(&mut self, token: &str) -> Result<()>;
    fn copy_native_frame(&mut self, metadata: &Value, dispatched_ms: u64) -> Result<Value>;
    fn reap_normal_exit(&mut self) -> Result<Value>;
    /// Native host identity, NOT the guest PID or the Makepad WindowId.
    fn host_window_identity(&mut self) -> Result<(u64, u32, u64)> {
        Err(RemoteError::refused("UNSUPPORTED_HOST_WINDOW_OBSERVATION"))
    }
    /// Optional read-only content/frame witness. Native Windows uses its
    /// existing client geometry; WSLC must supply a fresh exact owner witness.
    fn host_content_geometry(&mut self) -> Result<Option<HostContentGeometry>> {
        Ok(None)
    }
    fn read_runtime_stderr(&mut self) -> Result<Value> {
        Err(RemoteError::refused(
            "UNSUPPORTED_RUNTIME_STDERR_OBSERVATION",
        ))
    }
    /// Containment cleanup is separate from normal exit and cannot grant PASS.
    fn cleanup_owned_resources(&mut self) -> Result<Value> {
        Err(RemoteError::refused("OWNED_CLEANUP_UNSUPPORTED"))
    }

    /// Must observe exact Makepad widget focus independently, not window
    /// activation, the last click, a cached target, or an AI-supplied boolean.
    fn observe_key_focus(&mut self, _window: u64, _widget: &str) -> Result<bool> {
        Err(RemoteError::refused("UNSUPPORTED_KEY_FOCUS_OBSERVATION"))
    }

    /// Independent, challenge-bound app/UI-thread observation. The existing
    /// owner must authenticate its source before returning it; a snapshot row,
    /// fixture log, AI argument or an echoed request is not an implementation.
    /// No transport or implicit fallback is installed by this extension.
    fn observe_app_semantics(
        &mut self,
        _request: &semantic::ObservationRequest,
    ) -> Result<semantic::AppObservation> {
        Err(RemoteError::refused("UNSUPPORTED_APP_SEMANTIC_OBSERVATION"))
    }
    /// App UI-thread one-shot gate. It must recheck live UID/context/revision
    /// again in the actual handler before a domain write. Sampling alone cannot
    /// prevent a widget/document swap between /snap and input delivery.
    fn arm_app_semantics(&mut self, _authorization: &semantic::ActionAuthorization) -> Result<()> {
        Err(RemoteError::refused("UNSUPPORTED_APP_SEMANTIC_ACTION_GUARD"))
    }
    /// Retire this exact one-shot authorization even on cancellation/refusal.
    fn disarm_app_semantics(&mut self, _authorization: &semantic::ActionAuthorization) -> Result<()> {
        Err(RemoteError::refused("UNSUPPORTED_APP_SEMANTIC_ACTION_GUARD"))
    }
}

// Platform choice is trusted launcher state, not a second action dispatcher.
impl<P: RemotePlatform + ?Sized> RemotePlatform for Box<P> {
    fn binding(&self) -> &SessionBinding {
        (**self).binding()
    }
    fn validate(&mut self) -> Result<()> {
        (**self).validate()
    }
    fn request(&mut self, t: &str, m: bool) -> Result<Value> {
        (**self).request(t, m)
    }
    fn acquire_input(&mut self) -> Result<String> {
        (**self).acquire_input()
    }
    fn validate_input(&mut self, t: &str) -> Result<()> {
        (**self).validate_input(t)
    }
    fn release_input(&mut self, t: &str) -> Result<()> {
        (**self).release_input(t)
    }
    fn copy_native_frame(&mut self, m: &Value, d: u64) -> Result<Value> {
        (**self).copy_native_frame(m, d)
    }
    fn reap_normal_exit(&mut self) -> Result<Value> {
        (**self).reap_normal_exit()
    }
    fn host_window_identity(&mut self) -> Result<(u64, u32, u64)> {
        (**self).host_window_identity()
    }
    fn host_content_geometry(&mut self) -> Result<Option<HostContentGeometry>> {
        (**self).host_content_geometry()
    }
    fn read_runtime_stderr(&mut self) -> Result<Value> {
        (**self).read_runtime_stderr()
    }
    fn cleanup_owned_resources(&mut self) -> Result<Value> {
        (**self).cleanup_owned_resources()
    }
    fn observe_key_focus(&mut self, w: u64, i: &str) -> Result<bool> {
        (**self).observe_key_focus(w, i)
    }
    fn observe_app_semantics(
        &mut self,
        request: &semantic::ObservationRequest,
    ) -> Result<semantic::AppObservation> {
        (**self).observe_app_semantics(request)
    }
    fn arm_app_semantics(&mut self, authorization: &semantic::ActionAuthorization) -> Result<()> {
        (**self).arm_app_semantics(authorization)
    }
    fn disarm_app_semantics(&mut self, authorization: &semantic::ActionAuthorization) -> Result<()> {
        (**self).disarm_app_semantics(authorization)
    }
}

pub struct MakepadRemoteAdapter<P: RemotePlatform> {
    platform: P,
    binding: SessionBinding,
    sequence: Option<(String, u64)>,
    human_epoch: Option<u64>,
    mutation_uncertain: bool,
    closing: bool,
    closed: bool,
    cleanup_complete: bool,
    snapshot_generation: u64,
    semantic_challenge: u64,
    semantic_observation_sequence: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

impl<P: RemotePlatform> MakepadRemoteAdapter<P> {
    pub fn from_trusted_platform(mut platform: P) -> Result<Self> {
        let binding = platform.binding().clone();
        let shape_valid = !(binding.source_commit != PINNED_SOURCE
            || binding.session_id.is_empty()
            || binding.owner.is_empty()
            || binding.generation == 0
            || binding.pid == 0
            || binding.process_birth.is_empty()
            || binding.executable.is_empty()
            || binding.executable_sha256.len() != 64);
        let admission = if shape_valid {
            platform.validate()
        } else {
            Err(RemoteError::refused("TRUSTED_REMOTE_BINDING_REQUIRED"))
        };
        if let Err(cause) = admission {
            // A platform supplied here already owns its approved runtime. The
            // public launcher may have dispatched launch before admission fails.
            // Retire that exact owner and preserve its proof; never claim no-op.
            let cleanup = platform.cleanup_owned_resources();
            let mut error = RemoteError::unknown(&cause.code);
            error.details["phase"] = json!("AFTER_PLATFORM_LAUNCH_ADMISSION");
            error.details["validation_cause"] = json!(cause);
            error.details["owned_cleanup"] = json!(cleanup);
            return Err(error);
        }
        Ok(Self {
            platform,
            binding,
            sequence: None,
            human_epoch: None,
            mutation_uncertain: false,
            closing: false,
            closed: false,
            cleanup_complete: false,
            snapshot_generation: 0,
            semantic_challenge: 0,
            semantic_observation_sequence: 0,
        })
    }

    pub fn binding(&self) -> &SessionBinding {
        &self.binding
    }

    pub fn host_window_identity(&mut self, session: &str) -> Result<(u64, u32, u64)> {
        self.check(session, self.binding.window_id)?;
        self.platform.host_window_identity()
    }
    pub fn host_content_geometry(&mut self, session: &str) -> Result<Option<HostContentGeometry>> {
        self.check(session, self.binding.window_id)?;
        self.platform.host_content_geometry()
    }

    pub fn observe_key_focus(&mut self, session: &str, widget: &str) -> Result<bool> {
        self.check(session, self.binding.window_id)?;
        self.platform
            .observe_key_focus(self.binding.window_id, widget)
    }

    pub fn authorize(&mut self, session: &str, owner: &str, window: u64) -> Result<()> {
        if session != self.binding.session_id {
            return Err(RemoteError::refused("UNKNOWN_SESSION"));
        }
        if owner != self.binding.owner {
            return Err(RemoteError::refused("FOREIGN_SESSION_OWNER"));
        }
        if self.closed {
            return Err(RemoteError::refused("STALE_SESSION"));
        }
        if window != self.binding.window_id {
            return Err(RemoteError::refused("WRONG_WINDOW_ID"));
        }
        if self.platform.binding() != &self.binding {
            return Err(RemoteError::refused("SESSION_GENERATION_CHANGED"));
        }
        self.platform.validate()
    }

    fn check(&mut self, session: &str, window: u64) -> Result<()> {
        self.authorize(session, &self.binding.owner.clone(), window)
    }

    pub fn inspect_window(&mut self, session: &str) -> Result<Value> {
        self.check(session, self.binding.window_id)?;
        let state = self.platform.request("/s", false)?;
        if state["pid"].as_u64() != Some(u64::from(self.binding.pid)) {
            return Err(RemoteError::refused("REMOTE_STATUS_PID_MISMATCH"));
        }
        let matches = state["w"]
            .as_array()
            .ok_or_else(|| RemoteError::refused("REMOTE_WINDOWS_INVALID"))?
            .iter()
            .filter(|w| w["i"].as_u64() == Some(self.binding.window_id))
            .count();
        if matches != 1 {
            return Err(RemoteError::refused("WRONG_WINDOW_ID"));
        }
        Ok(state)
    }

    pub fn snapshot(&mut self, session: &str, window: u64) -> Result<Value> {
        self.check(session, window)?;
        let value = self
            .platform
            .request(&format!("/snap?w={window}&all=1"), false)?;
        if !value["s"].is_array() {
            return Err(RemoteError::refused("SNAPSHOT_ROWS_INVALID"));
        }
        self.snapshot_generation = self
            .snapshot_generation
            .checked_add(1)
            .ok_or_else(|| RemoteError::refused("SNAPSHOT_GENERATION_EXHAUSTED"))?;
        Ok(value)
    }

    pub fn find_widget(&mut self, session: &str, window: u64, widget: &str) -> Result<Value> {
        let snapshot = self.snapshot(session, window)?;
        exact_widget(&snapshot, window, widget)
    }

    pub fn get_activity(&mut self, session: &str) -> Result<Activity> {
        self.check(session, self.binding.window_id)?;
        Activity::parse(&self.platform.request("/activity", false)?)
    }

    pub fn acquire_input(&mut self, session: &str) -> Result<String> {
        self.check(session, self.binding.window_id)?;
        if self.sequence.is_some() {
            return Err(RemoteError::refused("INPUT_LOCK_ALREADY_HELD"));
        }
        if self.mutation_uncertain || self.closing {
            return Err(RemoteError::refused("REMOTE_SEQUENCE_FENCED"));
        }
        let seq = self.get_activity(session)?.quiet()?;
        if self.human_epoch.is_some_and(|original| original != seq) {
            self.mutation_uncertain = true;
            return Err(RemoteError::refused("USER_INTERFERENCE"));
        }
        let token = self.platform.acquire_input()?;
        self.human_epoch = Some(seq);
        self.sequence = Some((token.clone(), seq));
        Ok(token)
    }

    pub fn release_input(&mut self, session: &str, token: &str) -> Result<()> {
        if session != self.binding.session_id {
            return Err(RemoteError::refused("UNKNOWN_SESSION"));
        }
        if self.sequence.as_ref().map(|v| v.0.as_str()) != Some(token) {
            return Err(RemoteError::refused("STALE_LEASE"));
        }
        self.platform.release_input(token)?;
        self.sequence = None;
        Ok(())
    }

    fn mutation_guard(&mut self, session: &str, window: u64, token: &str) -> Result<u64> {
        self.check(session, window)?;
        if self.mutation_uncertain || self.closing {
            return Err(RemoteError::refused("REMOTE_SEQUENCE_FENCED"));
        }
        let (held_token, original_seq) = self
            .sequence
            .as_ref()
            .ok_or_else(|| RemoteError::refused("INPUT_LOCK_REQUIRED"))?
            .clone();
        if held_token != token {
            return Err(RemoteError::refused("STALE_LEASE"));
        }
        self.platform.validate_input(token)?;
        let seq = self.get_activity(session)?.quiet()?;
        if seq != original_seq {
            return Err(RemoteError::refused("USER_INTERFERENCE"));
        }
        Ok(seq)
    }

    fn mutate(&mut self, session: &str, window: u64, token: &str, route: String) -> Result<Value> {
        let seq = self.mutation_guard(session, window, token)?;
        let reply = self
            .platform
            .request(&format!("{route}&if_user_seq={seq}"), true);
        if let Err(mut error) = reply {
            if error.outcome != "NOT_DISPATCHED" {
                self.mutation_uncertain = true;
                // Observation is NOT retry, rollback, or conversion of the
                // original failure into success. Keep its original outcome.
                let snapshot = self.snapshot(session, window).ok();
                let health = self.inspect_window(session).ok();
                error.details["independent_snapshot"] = json!(snapshot);
                error.details["independent_health"] = json!(health);
                error.details["automatic_retry_allowed"] = json!(false);
            }
            return Err(error);
        }
        let after = match self.get_activity(session) {
            Ok(value) => value,
            Err(_) => {
                self.mutation_uncertain = true;
                return Err(RemoteError::unknown("POST_ACTION_ACTIVITY_UNAVAILABLE"));
            }
        };
        if after.user_seq != seq || after.user_active || after.held {
            self.mutation_uncertain = true;
            return Err(RemoteError {
                code: "USER_INTERFERENCE".into(),
                outcome: "POSSIBLY_APPLIED".into(),
                retry_safe: false,
                details: json!({"independent_snapshot":self.snapshot(session,window).ok()}),
            });
        }
        reply
    }

    pub fn click_widget(
        &mut self,
        session: &str,
        window: u64,
        widget: &str,
        token: &str,
    ) -> Result<Value> {
        self.mutation_guard(session, window, token)?;
        let before_window = self.inspect_window(session)?;
        let before = self.find_widget(session, window, widget)?;
        let current = self.find_widget(session, window, widget)?;
        let current_window = self.inspect_window(session)?;
        if before != current || before_window["w"] != current_window["w"] {
            return Err(RemoteError::refused("STALE_WIDGET_LAYOUT"));
        }
        let r = &current["r"];
        let x = r[0].as_f64().unwrap() + r[2].as_f64().unwrap() / 2.0;
        let y = r[1].as_f64().unwrap() + r[3].as_f64().unwrap() / 2.0;
        let ack = self.mutate(
            session,
            window,
            token,
            format!("/click?w={window}&x={x}&y={y}&wait=1"),
        )?;
        let observed = self.find_widget(session, window, widget).map_err(|_| {
            self.mutation_uncertain = true;
            RemoteError::unknown("POST_CLICK_WIDGET_UNAVAILABLE")
        })?;
        let health = self.inspect_window(session).map_err(|_| {
            self.mutation_uncertain = true;
            RemoteError::unknown("POST_ACTION_HEALTH_UNAVAILABLE")
        })?;
        let focused = match self.platform.observe_key_focus(window, widget) {
            Ok(value) => value,
            Err(error) if error.code == "UNSUPPORTED_KEY_FOCUS_OBSERVATION" => false,
            Err(_) => {
                self.mutation_uncertain = true;
                return Err(RemoteError::unknown("POST_CLICK_FOCUS_OBSERVATION_FAILED"));
            }
        };
        Ok(
            json!({"dispatched":true,"ack":ack,"widget":observed,"runtime":health,
            "coordinates":"WINDOW_LOCAL_LOGICAL","snapshot_observation_generation":self.snapshot_generation,
            "upstream_atomic_layout_generation_available":false,
            "key_focus_verified":focused,"business_postcondition_verified":focused}),
        )
    }

    /// Verify the caller's explicit value condition even when focus succeeded.
    /// Failure after the click is uncertain: preserve observations and fence input.
    pub fn click_widget_with_postcondition(
        &mut self,
        session: &str,
        window: u64,
        widget: &str,
        token: &str,
        expected_value: Option<(&str, &str)>,
    ) -> Result<Value> {
        if expected_value.is_some_and(|(id, value)| id.is_empty() || value.len() > 16384) {
            return Err(RemoteError::refused("INVALID_ACTION_POSTCONDITION"));
        }
        let mut result = self.click_widget(session, window, widget, token)?;
        let verified = if let Some((id, expected)) = expected_value {
            let readback = self.find_widget(session, window, id);
            let verified = readback
                .as_ref()
                .is_ok_and(|row| row["val"].as_str() == Some(expected));
            result["explicit_value_readback"] = json!(readback.ok());
            verified
        } else {
            result["key_focus_verified"] == true
        };
        if !verified {
            self.fence_mutations();
            let mut error = RemoteError::unknown("ACTION_POSTCONDITION_NOT_VERIFIED");
            error.details["observed_action"] = result;
            return Err(error);
        }
        result["business_postcondition_verified"] = json!(true);
        Ok(result)
    }

    fn focused_widget(
        &mut self,
        session: &str,
        window: u64,
        widget: &str,
        token: &str,
    ) -> Result<Value> {
        self.mutation_guard(session, window, token)?;
        let current = self.find_widget(session, window, widget)?;
        if !self.platform.observe_key_focus(window, widget)? {
            return Err(RemoteError::refused("WIDGET_KEY_FOCUS_NOT_CONFIRMED"));
        }
        let fresh = self.find_widget(session, window, widget)?;
        if fresh != current {
            return Err(RemoteError::refused("STALE_WIDGET_LAYOUT"));
        }
        if !self.platform.observe_key_focus(window, widget)? {
            return Err(RemoteError::refused("WIDGET_KEY_FOCUS_NOT_CONFIRMED"));
        }
        Ok(fresh)
    }

    pub fn type_text(
        &mut self,
        session: &str,
        window: u64,
        widget: &str,
        text: &str,
        expected: &str,
        token: &str,
    ) -> Result<Value> {
        if text.is_empty()
            || text.len() > 4096
            || text.chars().any(char::is_control)
            || expected.len() > 16384
        {
            return Err(RemoteError::refused("TEXT_BUDGET_EXCEEDED"));
        }
        self.focused_widget(session, window, widget, token)?;
        let ack = self.mutate(
            session,
            window,
            token,
            format!("/t?w={window}&t={}&wait=1", encode(text)),
        )?;
        let actual = self.find_widget(session, window, widget).map_err(|_| {
            self.mutation_uncertain = true;
            RemoteError::unknown("VALUE_READBACK_UNAVAILABLE")
        })?;
        if actual["val"].as_str() != Some(expected) {
            self.mutation_uncertain = true;
            return Err(RemoteError::unknown("VALUE_READBACK_MISMATCH"));
        }
        let runtime = self.inspect_window(session).map_err(|_| {
            self.mutation_uncertain = true;
            RemoteError::unknown("POST_ACTION_HEALTH_UNAVAILABLE")
        })?;
        Ok(
            json!({"mechanism":INPUT_MECHANISM,"ack":ack,"verified_readback":actual,
            "runtime":runtime,"postcondition_verified":true}),
        )
    }

    pub fn key_event(
        &mut self,
        session: &str,
        window: u64,
        widget: &str,
        key: &str,
        ctrl: bool,
        token: &str,
    ) -> Result<Value> {
        let focus_policy = KeyFocusPolicy::for_key(key, ctrl)?;
        self.focused_widget(session, window, widget, token)?;
        let ack = self.mutate(
            session,
            window,
            token,
            format!(
                "/k?w={window}&k=press&c={key}&ctrl={}&wait=1",
                u8::from(ctrl)
            ),
        )?;
        let readback = self.find_widget(session, window, widget).map_err(|_| {
            self.mutation_uncertain = true;
            RemoteError::unknown("VALUE_READBACK_UNAVAILABLE")
        })?;
        let runtime = self.inspect_window(session).map_err(|_| {
            self.mutation_uncertain = true;
            RemoteError::unknown("POST_ACTION_HEALTH_UNAVAILABLE")
        })?;
        let mut observed = json!({"mechanism":INPUT_MECHANISM,"ack":ack,"readback":readback,"runtime":runtime,
            "focus_policy":focus_policy.label(),"key_focus_verified":null,"business_postcondition_verified":false});
        if focus_policy == KeyFocusPolicy::PreserveTarget {
            // A sampled focus check is not atomic routing or selection/caret proof.
            // An observation failure here is AFTER dispatch, never NOT_DISPATCHED.
            let focus = self.platform.observe_key_focus(window, widget);
            if let Ok(focused) = &focus {
                observed["key_focus_verified"] = json!(focused);
            }
            if !matches!(focus, Ok(true)) {
                self.fence_mutations();
                let mut error = RemoteError::unknown(if focus.is_err() {
                    "POST_KEY_FOCUS_OBSERVATION_FAILED"
                } else {
                    "KEY_POSTCONDITION_NOT_VERIFIED"
                });
                error.details["focus_observation"] = match focus {
                    Ok(focused) => json!({"focused":focused}),
                    Err(cause) => json!({"error":cause}),
                };
                error.details["observed_action"] = observed;
                return Err(error);
            }
        }
        // Tab/Enter/Escape may legitimately move focus. Their ACK/readback/health
        // is retained, without claiming a verified business effect for any key.
        Ok(observed)
    }

    pub fn capture_frame(&mut self, session: &str, window: u64) -> Result<Value> {
        self.check(session, window)?;
        self.inspect_window(session)?;
        let dispatched = now_ms();
        let metadata = self.platform.request(&format!("/g?w={window}"), false)?;
        if metadata["w"].as_u64() != Some(window) {
            return Err(RemoteError::refused("CAPTURE_WRONG_WINDOW"));
        }
        let frame = self.platform.copy_native_frame(&metadata, dispatched)?;
        Ok(
            json!({"frame":frame,"session_id":session,"owner":self.binding.owner,"window_id":window,
            "session_generation":self.binding.generation,"runtime":self.inspect_window(session)?,
            "capture_mechanism":"OFFICIAL_MAKEPAD_GPU_G","os_screenshot_fallback":false}),
        )
    }

    pub fn health(&mut self, session: &str) -> Result<Value> {
        Ok(
            json!({"healthy":true,"process_alive":true,"status":self.inspect_window(session)?,
            "mutation_fenced":self.mutation_uncertain,"binding":self.binding}),
        )
    }

    pub fn runtime_stderr(&mut self, session: &str) -> Result<Value> {
        self.check(session, self.binding.window_id)?;
        self.platform.read_runtime_stderr()
    }

    /// An independent public-transport assertion failed after dispatch. Keep
    /// observations available but never authorize another blind input attempt.
    pub fn fence_mutations(&mut self) {
        self.mutation_uncertain = true;
    }

    pub fn close(&mut self, session: &str) -> Result<Value> {
        self.check(session, self.binding.window_id)?;
        if self.closing {
            return Err(RemoteError::refused("CLOSE_ALREADY_DISPATCHED"));
        }
        let observed_seq = self.get_activity(session)?.quiet()?;
        if self
            .human_epoch
            .is_some_and(|original| original != observed_seq)
        {
            return Err(RemoteError::refused("USER_INTERFERENCE"));
        }
        let owned_token = if self.sequence.is_none() {
            let token = self.platform.acquire_input()?;
            self.sequence = Some((token.clone(), observed_seq));
            Some(token)
        } else {
            None
        };
        let token = self.sequence.as_ref().unwrap().0.clone();
        let preflight = (|| {
            self.platform.validate_input(&token)?;
            let seq = self.get_activity(session)?.quiet()?;
            if self.sequence.as_ref().unwrap().1 != seq {
                return Err(RemoteError::refused("USER_INTERFERENCE"));
            }
            Ok(seq)
        })();
        let seq = match preflight {
            Ok(seq) => seq,
            Err(mut error) => {
                if let Some(token) = owned_token.as_deref() {
                    if let Err(cleanup) = self.release_input(session, token) {
                        error.details["lease_cleanup_error"] = json!(cleanup);
                    }
                }
                return Err(error);
            }
        };
        self.closing = true;
        let reply = self
            .platform
            .request(&format!("/quit?if_user_seq={seq}"), true);
        if let Err(mut error) = reply {
            if error.outcome == "NOT_DISPATCHED" {
                self.closing = false;
                if let Some(token) = owned_token {
                    if let Err(cleanup) = self.release_input(session, &token) {
                        error.details["lease_cleanup_error"] = json!(cleanup);
                    }
                }
            } else {
                // Quit may reach the UI thread before its HTTP worker writes
                // an ACK. Observe the exact owned process once, without HTTP,
                // before containment discards its real exit status. Even exit0
                // does NOT turn the lost ACK into an acknowledged operation.
                self.mutation_uncertain = true;
                match self.platform.reap_normal_exit() {
                    Ok(termination) => {
                        error.details["independent_termination"] =
                            json!({"success":true,"result":termination});
                        if let Err(cleanup) = self.release_input(session, &token) {
                            error.details["lease_cleanup_error"] = json!(cleanup);
                        }
                    }
                    Err(observation) => {
                        error.details["independent_termination"] =
                            json!({"success":false,"error":observation});
                        // Keep the owner/grant for containment or Drop; lack
                        // of native termination proof is not a safe release.
                    }
                }
            }
            return Err(error);
        }
        let termination = self.platform.reap_normal_exit().map_err(|error| {
            let mut failure = RemoteError::unknown(&error.code);
            failure.details = json!({"phase":"AFTER_QUIT_DISPATCH_REAP","cause":error});
            failure
        })?;
        self.release_input(session, &token).map_err(|error| {
            let mut failure = RemoteError::unknown(&error.code);
            failure.details = json!({"phase":"AFTER_QUIT_DISPATCH_RELEASE","cause":error});
            failure
        })?;
        self.closed = true;
        Ok(termination)
    }

    pub fn cleanup(&mut self) -> Result<Value> {
        // Fence the session immediately, but retain ownership on failure.
        // A later exact-owner cleanup (or Drop) must still be able to retire it.
        self.closed = true;
        self.mutation_uncertain = true;
        let result = self.platform.cleanup_owned_resources();
        if result.is_ok() {
            self.sequence = None;
            self.cleanup_complete = true;
        }
        result
    }
}

impl<P: RemotePlatform> Drop for MakepadRemoteAdapter<P> {
    fn drop(&mut self) {
        if !self.cleanup_complete {
            let _ = self.platform.cleanup_owned_resources();
        }
    }
}

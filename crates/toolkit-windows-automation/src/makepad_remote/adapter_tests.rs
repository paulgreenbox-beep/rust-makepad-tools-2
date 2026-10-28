//! Pure adapter composition tests. The ledger models ownership only: it does
//! not exercise Windows, HTTP, process identity, or the real Desktop Arbiter.
//! No assertion depends on Drop issuing HTTP or on a real GUI effect.

use super::*;
use std::sync::{Arc, Mutex};

const WIDGET: &str = "input_singleline";
const SESSION: &str = "fake-session-A";
const OWNER: &str = "fake-owner-A";

#[derive(Clone, Debug, PartialEq)]
struct FakeCall {
    target: String,
    mutating: bool,
}

#[derive(Clone, Debug, PartialEq)]
struct Ledger {
    http: Vec<FakeCall>,
    validations: usize,
    input_validations: usize,
    acquisitions: usize,
    releases: usize,
    cleanup_retirements: usize,
    cleanups: usize,
    reaps: usize,
    snapshots: usize,
    lease: Option<String>,
    alive: bool,
    stale_process: bool,
    user_seq: u64,
    user_active: bool,
    held: bool,
    value: String,
    change_rect_on_snapshot: Option<usize>,
    advance_seq_on_acquire: bool,
    fail_input_validation_once: bool,
    fail_release_once: bool,
    fail_cleanup_once: bool,
    observed_focus: Option<bool>,
    focus_after_key: Option<Option<bool>>,
    mutation_error: Option<RemoteError>,
    apply_before_error: bool,
    fail_activity_after_mutation: bool,
    stale_after_mutation: bool,
    input_uncertain: bool,
    quit_requested: bool,
    normal_exit: bool,
    reap_error: Option<RemoteError>,
}

impl Ledger {
    fn new() -> Self {
        Self {
            http: Vec::new(),
            validations: 0,
            input_validations: 0,
            acquisitions: 0,
            releases: 0,
            cleanup_retirements: 0,
            cleanups: 0,
            reaps: 0,
            snapshots: 0,
            lease: None,
            alive: true,
            stale_process: false,
            user_seq: 41,
            user_active: false,
            held: false,
            value: "initial".into(),
            change_rect_on_snapshot: None,
            advance_seq_on_acquire: false,
            fail_input_validation_once: false,
            fail_release_once: false,
            fail_cleanup_once: false,
            observed_focus: None,
            focus_after_key: None,
            mutation_error: None,
            apply_before_error: false,
            fail_activity_after_mutation: false,
            stale_after_mutation: false,
            input_uncertain: false,
            quit_requested: false,
            normal_exit: false,
            reap_error: None,
        }
    }

    fn mutation_count(&self) -> usize {
        self.http.iter().filter(|call| call.mutating).count()
    }

    fn quit_count(&self) -> usize {
        self.http
            .iter()
            .filter(|call| call.target.starts_with("/quit?"))
            .count()
    }

    fn activity(&self) -> Value {
        json!({
            "user_seq":self.user_seq,
            "user_active":self.user_active,
            "held":self.held,
            "quiet_ms":2000
        })
    }
}

struct FakeRemotePlatform {
    binding: SessionBinding,
    ledger: Arc<Mutex<Ledger>>,
}

impl FakeRemotePlatform {
    fn new(label: &str, pid: u32) -> (Self, Arc<Mutex<Ledger>>) {
        let ledger = Arc::new(Mutex::new(Ledger::new()));
        let binding = SessionBinding {
            session_id: format!("fake-session-{label}"),
            owner: format!("fake-owner-{label}"),
            generation: 1,
            pid,
            process_birth: format!("fake-birth-{pid}"),
            executable: format!("fake-only-{label}.exe"),
            executable_sha256: "a".repeat(64),
            source_commit: PINNED_SOURCE.into(),
            window_id: 0,
            platform: "pure-fake-not-windows".into(),
        };
        (
            Self {
                binding,
                ledger: Arc::clone(&ledger),
            },
            ledger,
        )
    }
}

impl RemotePlatform for FakeRemotePlatform {
    fn binding(&self) -> &SessionBinding {
        &self.binding
    }

    fn validate(&mut self) -> Result<()> {
        let mut state = self.ledger.lock().unwrap();
        state.validations += 1;
        if state.stale_process || !state.alive {
            return Err(RemoteError::refused("STALE_PROCESS"));
        }
        Ok(())
    }

    fn request(&mut self, target: &str, mutating: bool) -> Result<Value> {
        // Model the platform's required pre-HTTP validation separately from
        // adapter authorization. Rejected calls are not recorded as HTTP.
        self.validate()?;
        if !protocol::allowed_route(target) {
            return Err(RemoteError::refused("REMOTE_ROUTE_NOT_ALLOWLISTED"));
        }
        let path = target.split('?').next().unwrap_or("");
        let is_mutation = matches!(path, "/click" | "/m" | "/k" | "/t" | "/quit");
        if is_mutation != mutating {
            return Err(RemoteError::refused(
                "REMOTE_MUTATION_CLASSIFICATION_MISMATCH",
            ));
        }
        let mut state = self.ledger.lock().unwrap();
        state.http.push(FakeCall {
            target: target.into(),
            mutating,
        });
        if mutating {
            if state.stale_after_mutation {
                state.stale_process = true;
            }
            if let Some(error) = state.mutation_error.clone() {
                if state.apply_before_error {
                    if path == "/quit" {
                        state.quit_requested = true;
                    } else {
                        state.value = "observed-after-uncertain-input".into();
                    }
                }
                state.input_uncertain = error.outcome != "NOT_DISPATCHED";
                return Err(error);
            }
            match path {
                "/quit" => state.quit_requested = true,
                "/click" => state.value = "observed-after-click".into(),
                "/k" => {
                    if let Some(focus) = state.focus_after_key {
                        state.observed_focus = focus;
                    }
                }
                _ => {}
            }
            return Ok(json!({"ok":1}));
        }
        match path {
            "/s" => Ok(json!({
                "pid":self.binding.pid,
                "w":[{"i":0,"t":"fake","sz":[640,480],"dpi":1,"pos":[0,0]}],
                "activity":state.activity()
            })),
            "/activity" => {
                if state.fail_activity_after_mutation && state.mutation_count() != 0 {
                    return Err(RemoteError::refused("FAKE_POST_ACTION_ACTIVITY_FAILED"));
                }
                Ok(state.activity())
            }
            "/snap" => {
                state.snapshots += 1;
                let x = if state.change_rect_on_snapshot == Some(state.snapshots) {
                    11
                } else {
                    10
                };
                Ok(json!({"s":[{
                    "i":WIDGET,"w":0,"enabled":true,
                    "r":[x,20,120,24],"val":state.value
                }]}))
            }
            _ => Err(RemoteError::refused("FAKE_UNUSED_READ")),
        }
    }

    fn acquire_input(&mut self) -> Result<String> {
        let mut state = self.ledger.lock().unwrap();
        if state.lease.is_some() {
            return Err(RemoteError::refused("INPUT_LOCK_ALREADY_HELD"));
        }
        state.acquisitions += 1;
        let token = format!(
            "fake-lease:{}:{}",
            self.binding.session_id, state.acquisitions
        );
        state.lease = Some(token.clone());
        if state.advance_seq_on_acquire {
            state.user_seq += 1;
        }
        Ok(token)
    }

    fn validate_input(&mut self, token: &str) -> Result<()> {
        let mut state = self.ledger.lock().unwrap();
        state.input_validations += 1;
        if state.fail_input_validation_once {
            state.fail_input_validation_once = false;
            return Err(RemoteError::refused("FAKE_INPUT_VALIDATION_FAILED"));
        }
        if state.lease.as_deref() != Some(token) {
            return Err(RemoteError::refused("STALE_LEASE"));
        }
        Ok(())
    }

    fn release_input(&mut self, token: &str) -> Result<()> {
        self.validate_input(token)?;
        let mut state = self.ledger.lock().unwrap();
        if state.fail_release_once {
            state.fail_release_once = false;
            return Err(RemoteError::refused("FAKE_RELEASE_FAILED"));
        }
        if state.input_uncertain && !state.normal_exit {
            return Err(RemoteError::refused("REMOTE_INPUT_CLEANUP_UNCONFIRMED"));
        }
        state.lease = None;
        state.releases += 1;
        Ok(())
    }

    fn copy_native_frame(&mut self, _metadata: &Value, _dispatched_ms: u64) -> Result<Value> {
        Err(RemoteError::refused("FAKE_NATIVE_FRAME_UNUSED"))
    }

    fn reap_normal_exit(&mut self) -> Result<Value> {
        let mut state = self.ledger.lock().unwrap();
        state.reaps += 1;
        if let Some(error) = state.reap_error.clone() {
            state.input_uncertain = true;
            return Err(error);
        }
        if !state.quit_requested {
            return Err(RemoteError::refused("FAKE_QUIT_NOT_OBSERVED"));
        }
        state.alive = false;
        state.normal_exit = true;
        Ok(json!({
            "exit_code":0,"normal_exit_observed":true,
            "session_id":self.binding.session_id,"evidence_scope":"PURE_FAKE_ONLY"
        }))
    }

    fn cleanup_owned_resources(&mut self) -> Result<Value> {
        // Only the model's explicit containment path retires uncertain input.
        // This is not a claim about real Job/Arbiter cleanup or normal exit.
        let mut state = self.ledger.lock().unwrap();
        state.cleanups += 1;
        if state.fail_cleanup_once {
            state.fail_cleanup_once = false;
            return Err(RemoteError::refused("FAKE_CLEANUP_FAILED"));
        }
        state.alive = false;
        if state.lease.take().is_some() {
            state.cleanup_retirements += 1;
        }
        Ok(json!({
            "normal_exit_observed":state.normal_exit,
            "forced_cleanup":!state.normal_exit,
            "evidence_scope":"PURE_FAKE_ONLY"
        }))
    }

    fn observe_key_focus(&mut self, _window: u64, _widget: &str) -> Result<bool> {
        self.ledger
            .lock()
            .unwrap()
            .observed_focus
            .ok_or_else(|| RemoteError::refused("UNSUPPORTED_KEY_FOCUS_OBSERVATION"))
    }
}

type FakeAdapter = MakepadRemoteAdapter<FakeRemotePlatform>;

#[test]
fn failed_platform_admission_after_owned_launch_cleans_without_quit_and_is_unknown() {
    for malformed_binding in [false, true] {
        let (mut platform, ledger) = FakeRemotePlatform::new("admission", 1003);
        if malformed_binding {
            platform.binding.owner.clear();
        } else {
            ledger.lock().unwrap().stale_process = true;
        }
        let error = match MakepadRemoteAdapter::from_trusted_platform(platform) {
            Ok(_) => panic!("invalid admission"),
            Err(error) => error,
        };
        assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
        assert!(!error.retry_safe);
        assert_eq!(error.details["phase"], "AFTER_PLATFORM_LAUNCH_ADMISSION");
        assert_eq!(
            error.details["validation_cause"]["outcome"],
            "NOT_DISPATCHED"
        );
        assert!(error.details["owned_cleanup"]["Ok"].is_object());
        let state = ledger.lock().unwrap();
        assert_eq!(state.cleanups, 1);
        assert_eq!(state.quit_count(), 0);
        assert!(state.http.is_empty());
    }
}

fn fixture() -> (FakeAdapter, Arc<Mutex<Ledger>>) {
    let (platform, ledger) = FakeRemotePlatform::new("A", 1001);
    (
        MakepadRemoteAdapter::from_trusted_platform(platform).unwrap(),
        ledger,
    )
}

fn assert_not_dispatched(error: &RemoteError, code: &str) {
    assert_eq!(error.code, code);
    assert_eq!(error.outcome, "NOT_DISPATCHED");
    assert!(!error.retry_safe);
}

fn assert_lease_accounted(state: &Ledger) {
    assert_eq!(
        state.acquisitions,
        state.releases + state.cleanup_retirements + usize::from(state.lease.is_some()),
        "every model grant must be retained, explicitly released, or containment-retired"
    );
}

fn conflict(applied: bool) -> RemoteError {
    let body = serde_json::to_vec(&json!({"err":"user_intervened","applied":applied})).unwrap();
    protocol::classify_reply(409, &body, true).unwrap_err()
}

fn assert_independent_reads_after_mutation(state: &Ledger) {
    let index = state.http.iter().position(|call| call.mutating).unwrap();
    let after = &state.http[index + 1..];
    assert!(
        after
            .iter()
            .any(|call| !call.mutating && call.target.starts_with("/snap?"))
    );
    assert!(
        after
            .iter()
            .any(|call| !call.mutating && call.target == "/s")
    );
}

#[test]
fn cross_session_owner_and_window_authorization_refuse_before_http() {
    for (session, owner, window, code) in [
        ("foreign-session", OWNER, 0, "UNKNOWN_SESSION"),
        (SESSION, "foreign-owner", 0, "FOREIGN_SESSION_OWNER"),
        (SESSION, OWNER, 1, "WRONG_WINDOW_ID"),
    ] {
        let (mut adapter, ledger) = fixture();
        let error = adapter.authorize(session, owner, window).unwrap_err();
        assert_not_dispatched(&error, code);
        let state = ledger.lock().unwrap();
        assert!(state.http.is_empty());
        assert_eq!(state.acquisitions, 0);
    }
}

#[test]
fn changed_platform_generation_refuses_before_http() {
    let (mut adapter, ledger) = fixture();
    adapter.platform.binding.generation += 1;
    let error = adapter.snapshot(SESSION, 0).unwrap_err();
    assert_not_dispatched(&error, "SESSION_GENERATION_CHANGED");
    assert!(ledger.lock().unwrap().http.is_empty());
}

#[test]
fn stale_process_refuses_before_http_and_before_input_grant() {
    let (mut adapter, ledger) = fixture();
    ledger.lock().unwrap().stale_process = true;
    assert_not_dispatched(
        &adapter.acquire_input(SESSION).unwrap_err(),
        "STALE_PROCESS",
    );
    let state = ledger.lock().unwrap();
    assert!(state.http.is_empty());
    assert_eq!(state.acquisitions, 0);
}

#[test]
fn held_or_active_user_input_never_grants_a_model_lease_or_mutates() {
    for (held, active) in [(true, false), (false, true)] {
        let (mut adapter, ledger) = fixture();
        {
            let mut state = ledger.lock().unwrap();
            state.held = held;
            state.user_active = active;
        }
        let error = adapter.acquire_input(SESSION).unwrap_err();
        assert_not_dispatched(&error, "USER_INTERFERENCE");
        let state = ledger.lock().unwrap();
        assert_eq!(state.acquisitions, 0);
        assert_eq!(state.mutation_count(), 0);
        assert_lease_accounted(&state);
    }
}

#[test]
fn changed_user_sequence_prevents_mutation_and_keeps_caller_lease_accounted() {
    let (mut adapter, ledger) = fixture();
    let token = adapter.acquire_input(SESSION).unwrap();
    ledger.lock().unwrap().user_seq += 1;
    let error = adapter
        .click_widget(SESSION, 0, WIDGET, &token)
        .unwrap_err();
    assert_not_dispatched(&error, "USER_INTERFERENCE");
    assert_eq!(ledger.lock().unwrap().mutation_count(), 0);
    adapter.release_input(SESSION, &token).unwrap();
    let state = ledger.lock().unwrap();
    assert_eq!(state.releases, 1);
    assert_lease_accounted(&state);
}

#[test]
fn strict_409_not_applied_is_not_success_and_is_not_automatically_resent() {
    let (mut adapter, ledger) = fixture();
    let token = adapter.acquire_input(SESSION).unwrap();
    ledger.lock().unwrap().mutation_error = Some(conflict(false));
    let error = adapter
        .click_widget(SESSION, 0, WIDGET, &token)
        .unwrap_err();
    assert_not_dispatched(&error, "USER_INTERFERENCE");
    assert_eq!(ledger.lock().unwrap().mutation_count(), 1);
    adapter.release_input(SESSION, &token).unwrap();
    assert_lease_accounted(&ledger.lock().unwrap());
}

#[test]
fn input_lock_reacquisition_does_not_silently_rebase_after_human_interference() {
    let (mut adapter, ledger) = fixture();
    let token = adapter.acquire_input(SESSION).unwrap();
    adapter.release_input(SESSION, &token).unwrap();
    ledger.lock().unwrap().user_seq += 1;
    let error = adapter.acquire_input(SESSION).unwrap_err();
    assert_not_dispatched(&error, "USER_INTERFERENCE");
    let state = ledger.lock().unwrap();
    assert_eq!(state.acquisitions, 1);
    assert_eq!(state.releases, 1);
    assert_eq!(state.mutation_count(), 0);
    assert!(state.lease.is_none());
}

#[test]
fn strict_409_possibly_applied_gets_independent_observation_without_resend() {
    let (mut adapter, ledger) = fixture();
    let token = adapter.acquire_input(SESSION).unwrap();
    {
        let mut state = ledger.lock().unwrap();
        state.mutation_error = Some(conflict(true));
        state.apply_before_error = true;
    }
    let error = adapter
        .click_widget(SESSION, 0, WIDGET, &token)
        .unwrap_err();
    assert_eq!(error.code, "USER_INTERFERENCE");
    assert_eq!(error.outcome, "POSSIBLY_APPLIED");
    assert!(!error.retry_safe);
    assert_eq!(
        error.details["independent_snapshot"]["s"][0]["val"],
        "observed-after-uncertain-input"
    );
    assert_eq!(error.details["independent_health"]["pid"], 1001);
    {
        let state = ledger.lock().unwrap();
        assert_eq!(state.mutation_count(), 1);
        assert_independent_reads_after_mutation(&state);
        assert_lease_accounted(&state);
    }
    let requests = ledger.lock().unwrap().http.len();
    let fenced = adapter
        .click_widget(SESSION, 0, WIDGET, &token)
        .unwrap_err();
    assert_not_dispatched(&fenced, "REMOTE_SEQUENCE_FENCED");
    assert_eq!(ledger.lock().unwrap().http.len(), requests);
    let cleanup = adapter.cleanup().unwrap();
    assert_eq!(cleanup["normal_exit_observed"], false);
    assert_lease_accounted(&ledger.lock().unwrap());
}

#[test]
fn timeout_unknown_keeps_original_error_observes_and_fences_without_resend() {
    let (mut adapter, ledger) = fixture();
    let token = adapter.acquire_input(SESSION).unwrap();
    ledger.lock().unwrap().mutation_error = Some(RemoteError::unknown("REMOTE_RESPONSE_TIMEOUT"));
    let error = adapter
        .click_widget(SESSION, 0, WIDGET, &token)
        .unwrap_err();
    assert_eq!(error.code, "REMOTE_RESPONSE_TIMEOUT");
    assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
    assert!(!error.retry_safe);
    assert!(error.details["independent_snapshot"]["s"].is_array());
    assert_eq!(error.details["independent_health"]["pid"], 1001);
    {
        let state = ledger.lock().unwrap();
        assert_eq!(state.mutation_count(), 1);
        assert_independent_reads_after_mutation(&state);
    }
    let requests = ledger.lock().unwrap().http.len();
    assert_not_dispatched(
        &adapter
            .click_widget(SESSION, 0, WIDGET, &token)
            .unwrap_err(),
        "REMOTE_SEQUENCE_FENCED",
    );
    assert_eq!(ledger.lock().unwrap().http.len(), requests);
    adapter.cleanup().unwrap();
    assert_lease_accounted(&ledger.lock().unwrap());
}

#[test]
fn keyboard_and_text_default_focus_refusal_precede_any_keyboard_http() {
    let (mut adapter, ledger) = fixture();
    let token = adapter.acquire_input(SESSION).unwrap();
    assert_not_dispatched(
        &adapter
            .type_text(SESSION, 0, WIDGET, "synthetic", "synthetic", &token)
            .unwrap_err(),
        "UNSUPPORTED_KEY_FOCUS_OBSERVATION",
    );
    assert_not_dispatched(
        &adapter
            .key_event(SESSION, 0, WIDGET, "KeyA", true, &token)
            .unwrap_err(),
        "UNSUPPORTED_KEY_FOCUS_OBSERVATION",
    );
    assert_eq!(ledger.lock().unwrap().mutation_count(), 0);
    assert!(
        !ledger
            .lock()
            .unwrap()
            .http
            .iter()
            .any(|call| { call.target.starts_with("/t?") || call.target.starts_with("/k?") })
    );
    adapter.release_input(SESSION, &token).unwrap();
    assert_lease_accounted(&ledger.lock().unwrap());
}

#[test]
fn post_key_ack_focus_loss_is_unknown_and_fenced_without_resend() {
    // Pure routing/postcondition model only, not actual key effect or native focus.
    for (key, ctrl) in [("KeyA", true), ("KeyA", false), ("Backspace", false),
        ("ArrowLeft", false), ("ArrowRight", false), ("Home", false), ("End", false)] {
        for after in [Some(false), None] {
            let (mut adapter, ledger) = fixture();
            {
                let mut state = ledger.lock().unwrap();
                state.observed_focus = Some(true);
                state.focus_after_key = Some(after);
            }
            let token = adapter.acquire_input(SESSION).unwrap();
            let result = adapter.key_event(SESSION, 0, WIDGET, key, ctrl, &token);
            assert_eq!(ledger.lock().unwrap().mutation_count(), 1);
            let error = result.expect_err("ACK and unchanged text cannot prove retained target focus");
            assert_eq!(error.code, if after.is_some() { "KEY_POSTCONDITION_NOT_VERIFIED" }
                else { "POST_KEY_FOCUS_OBSERVATION_FAILED" });
            assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
            assert!(!error.retry_safe);
            assert_eq!(error.details["observed_action"]["ack"]["ok"], 1);
            assert_eq!(error.details["observed_action"]["readback"]["val"], "initial");
            assert_eq!(error.details["observed_action"]["runtime"]["pid"], 1001);
            if after.is_none() {
                assert_eq!(error.details["focus_observation"]["error"]["code"], "UNSUPPORTED_KEY_FOCUS_OBSERVATION");
                assert_eq!(error.details["focus_observation"]["error"]["outcome"], "NOT_DISPATCHED");
            } else {
                assert_eq!(error.details["focus_observation"]["focused"], false);
            }
            assert!(adapter.mutation_uncertain);
            let before = ledger.lock().unwrap().http.len();
            assert_not_dispatched(&adapter.key_event(SESSION, 0, WIDGET, "KeyA", true, &token).unwrap_err(),
                "REMOTE_SEQUENCE_FENCED");
            assert_not_dispatched(&adapter.type_text(SESSION, 0, WIDGET, "probe", "probe", &token).unwrap_err(),
                "REMOTE_SEQUENCE_FENCED");
            assert_eq!(ledger.lock().unwrap().http.len(), before);
            adapter.release_input(SESSION, &token).unwrap();
            adapter.cleanup().unwrap();
            assert_lease_accounted(&ledger.lock().unwrap());
        }
    }
}

#[test]
fn preserving_key_focus_policy_keeps_allowlist_and_never_claims_selection_effect() {
    for (key, ctrl) in [("KeyA", true), ("KeyA", false), ("Backspace", false),
        ("ArrowLeft", false), ("ArrowRight", false), ("Home", false), ("End", false)] {
        assert_eq!(KeyFocusPolicy::for_key(key, ctrl).unwrap(), KeyFocusPolicy::PreserveTarget);
        let (mut adapter, ledger) = fixture();
        ledger.lock().unwrap().observed_focus = Some(true);
        let token = adapter.acquire_input(SESSION).unwrap();
        let result = adapter.key_event(SESSION, 0, WIDGET, key, ctrl, &token).unwrap();
        assert_eq!(result["focus_policy"], "PRESERVE_TARGET");
        assert_eq!(result["key_focus_verified"], true);
        assert_eq!(result["business_postcondition_verified"], false);
        assert_eq!(result["readback"]["val"], "initial");
        assert_eq!(ledger.lock().unwrap().mutation_count(), 1);
        adapter.release_input(SESSION, &token).unwrap();
        adapter.cleanup().unwrap();
        assert_lease_accounted(&ledger.lock().unwrap());
    }
    for (key, ctrl) in [("Tab", true), ("Enter", true), ("Escape", true), ("Backspace", true),
        ("Home", true), ("End", true), ("ArrowLeft", true), ("ArrowRight", true),
        ("F4", false), ("KeyB", false), ("", false)] {
        assert_not_dispatched(&KeyFocusPolicy::for_key(key, ctrl).unwrap_err(), "UNSUPPORTED_KEY_COMBINATION");
    }
}

#[test]
fn transition_keys_do_not_require_same_focus_or_fabricate_verified_business_effect() {
    for key in ["Tab", "Enter", "Escape"] {
        assert_eq!(KeyFocusPolicy::for_key(key, false).unwrap(), KeyFocusPolicy::MayTransition);
        for after in [Some(false), None] {
            let (mut adapter, ledger) = fixture();
            {
                let mut state = ledger.lock().unwrap();
                state.observed_focus = Some(true);
                state.focus_after_key = Some(after);
            }
            let token = adapter.acquire_input(SESSION).unwrap();
            let result = adapter.key_event(SESSION, 0, WIDGET, key, false, &token).unwrap();
            assert_eq!(result["focus_policy"], "MAY_TRANSITION");
            assert!(result["key_focus_verified"].is_null());
            assert_eq!(result["business_postcondition_verified"], false);
            assert_eq!(result["ack"]["ok"], 1);
            assert_eq!(result["readback"]["val"], "initial");
            assert_eq!(result["runtime"]["pid"], 1001);
            assert!(!adapter.mutation_uncertain);
            adapter.release_input(SESSION, &token).unwrap();
            adapter.cleanup().unwrap();
            assert_lease_accounted(&ledger.lock().unwrap());
        }
    }
}

#[test]
fn key_mutation_failures_preserve_primary_409_and_transport_classifications() {
    let failures = [
        protocol::classify_reply(409, br#"{"applied":false}"#, true).unwrap_err(),
        protocol::classify_reply(409, br#"{"applied":true}"#, true).unwrap_err(),
        RemoteError::unknown("REMOTE_CONNECTION_LOST"),
        RemoteError::unknown("REMOTE_RESPONSE_TIMEOUT"),
    ];
    for original in failures {
        let (mut adapter, ledger) = fixture();
        {
            let mut state = ledger.lock().unwrap();
            state.observed_focus = Some(true);
            state.focus_after_key = Some(None);
            state.mutation_error = Some(original.clone());
        }
        let token = adapter.acquire_input(SESSION).unwrap();
        let error = adapter.key_event(SESSION, 0, WIDGET, "KeyA", true, &token).unwrap_err();
        assert_eq!(error.code, original.code);
        assert_eq!(error.outcome, original.outcome);
        assert_eq!(error.retry_safe, original.retry_safe);
        for (name, value) in original.details.as_object().unwrap() {
            assert_eq!(&error.details[name], value);
        }
        assert_eq!(ledger.lock().unwrap().mutation_count(), 1);
        assert_eq!(adapter.mutation_uncertain, original.outcome != "NOT_DISPATCHED");
        adapter.cleanup().unwrap();
        assert_lease_accounted(&ledger.lock().unwrap());
    }
}

#[test]
fn click_refuses_rect_changed_between_two_fresh_snapshots() {
    let (mut adapter, ledger) = fixture();
    let token = adapter.acquire_input(SESSION).unwrap();
    ledger.lock().unwrap().change_rect_on_snapshot = Some(2);
    let error = adapter
        .click_widget(SESSION, 0, WIDGET, &token)
        .unwrap_err();
    assert_not_dispatched(&error, "STALE_WIDGET_LAYOUT");
    {
        let state = ledger.lock().unwrap();
        assert_eq!(state.snapshots, 2);
        assert_eq!(state.mutation_count(), 0);
    }
    adapter.release_input(SESSION, &token).unwrap();
    assert_lease_accounted(&ledger.lock().unwrap());
}

#[test]
fn close_wrong_session_never_quits_reaps_or_acquires() {
    let (mut adapter, ledger) = fixture();
    assert_not_dispatched(
        &adapter.close("foreign-session").unwrap_err(),
        "UNKNOWN_SESSION",
    );
    let state = ledger.lock().unwrap();
    assert!(state.http.is_empty());
    assert_eq!(state.quit_count(), 0);
    assert_eq!(state.reaps, 0);
    assert_eq!(state.acquisitions, 0);
}

#[test]
fn closing_fake_b_does_not_touch_fake_a_or_a_caller_lease() {
    let (mut a, ledger_a) = fixture();
    let token_a = a.acquire_input(SESSION).unwrap();
    let (platform_b, ledger_b) = FakeRemotePlatform::new("B", 1002);
    let mut b = MakepadRemoteAdapter::from_trusted_platform(platform_b).unwrap();
    let before_a = ledger_a.lock().unwrap().clone();
    let exit = b.close("fake-session-B").unwrap();
    assert_eq!(exit["exit_code"], 0);
    assert_eq!(exit["evidence_scope"], "PURE_FAKE_ONLY");
    assert_eq!(ledger_a.lock().unwrap().clone(), before_a);
    {
        let state_b = ledger_b.lock().unwrap();
        assert_eq!(state_b.quit_count(), 1);
        assert_eq!(state_b.reaps, 1);
        assert_eq!(state_b.releases, 1);
        assert!(state_b.lease.is_none());
        assert_lease_accounted(&state_b);
    }
    a.release_input(SESSION, &token_a).unwrap();
}

#[test]
fn close_owned_lease_is_released_on_pre_dispatch_failure() {
    for fail_validation in [false, true] {
        let (mut adapter, ledger) = fixture();
        {
            let mut state = ledger.lock().unwrap();
            state.fail_input_validation_once = fail_validation;
            state.advance_seq_on_acquire = !fail_validation;
        }
        let error = adapter.close(SESSION).unwrap_err();
        assert_eq!(error.outcome, "NOT_DISPATCHED");
        assert!(!error.retry_safe);
        let state = ledger.lock().unwrap();
        assert_eq!(state.quit_count(), 0);
        assert_eq!(state.reaps, 0);
        assert_eq!(state.acquisitions, 1);
        assert_eq!(
            state.releases, 1,
            "close's own preflight grant must not leak"
        );
        assert!(state.lease.is_none());
        assert_lease_accounted(&state);
    }
}

#[test]
fn post_quit_reap_or_release_refusal_is_never_not_dispatched_or_resent() {
    for fail_reap in [true, false] {
        let (mut adapter, ledger) = fixture();
        {
            let mut state = ledger.lock().unwrap();
            if fail_reap {
                state.reap_error = Some(RemoteError::refused("FAKE_POST_QUIT_REAP_FAILED"));
            } else {
                state.fail_release_once = true;
            }
        }
        let error = adapter.close(SESSION).unwrap_err();
        assert_ne!(error.outcome, "NOT_DISPATCHED", "quit was already sent");
        assert!(!error.retry_safe);
        assert_eq!(ledger.lock().unwrap().quit_count(), 1);
        assert_eq!(ledger.lock().unwrap().reaps, 1);
        assert_lease_accounted(&ledger.lock().unwrap());
        assert!(adapter.close(SESSION).is_err());
        assert_eq!(ledger.lock().unwrap().quit_count(), 1);
        adapter.cleanup().unwrap();
        let state = ledger.lock().unwrap();
        assert!(state.lease.is_none());
        assert_lease_accounted(&state);
    }
}

#[test]
fn lost_quit_ack_keeps_unknown_and_observes_native_exit_without_resend() {
    for (observed_exit, caller_lease) in
        [(true, false), (false, false), (true, true), (false, true)]
    {
        let (mut adapter, ledger) = fixture();
        if caller_lease {
            adapter.acquire_input(SESSION).unwrap();
        }
        let mut original = RemoteError::unknown("REMOTE_CONNECTION_LOST");
        original.details["http_response_bytes"] = json!(0);
        {
            let mut state = ledger.lock().unwrap();
            state.mutation_error = Some(original.clone());
            state.apply_before_error = observed_exit;
            if !observed_exit {
                state.reap_error = Some(RemoteError::unknown("NORMAL_APP_EXIT_UNCONFIRMED"));
            }
        }
        let error = adapter.close(SESSION).unwrap_err();
        assert_eq!(error.code, original.code);
        assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
        assert!(!error.retry_safe);
        assert_eq!(error.details["http_response_bytes"], 0);
        assert_eq!(
            error.details["independent_termination"]["success"],
            observed_exit
        );
        if observed_exit {
            assert_eq!(
                error.details["independent_termination"]["result"]["normal_exit_observed"],
                true
            );
        } else {
            assert_eq!(
                error.details["independent_termination"]["error"]["code"],
                "NORMAL_APP_EXIT_UNCONFIRMED"
            );
        }
        assert!(adapter.mutation_uncertain && adapter.closing && !adapter.closed);
        assert!(adapter.close(SESSION).is_err());
        {
            let state = ledger.lock().unwrap();
            assert_eq!(state.quit_count(), 1);
            assert_eq!(state.reaps, 1);
            assert_eq!(state.releases, usize::from(observed_exit));
            assert_eq!(state.lease.is_some(), !observed_exit);
            assert_lease_accounted(&state);
        }
        let cleanup = adapter.cleanup().unwrap();
        assert_eq!(cleanup["normal_exit_observed"], observed_exit);
        assert!(ledger.lock().unwrap().lease.is_none());
    }
}

#[test]
fn post_http_activity_or_process_refusal_is_unknown_and_fences_next_input() {
    for disappear in [false, true] {
        let (mut adapter, ledger) = fixture();
        let token = adapter.acquire_input(SESSION).unwrap();
        {
            let mut state = ledger.lock().unwrap();
            state.stale_after_mutation = disappear;
            state.fail_activity_after_mutation = !disappear;
        }
        let error = adapter
            .click_widget(SESSION, 0, WIDGET, &token)
            .unwrap_err();
        assert_ne!(error.outcome, "NOT_DISPATCHED");
        assert!(!error.retry_safe);
        assert_eq!(ledger.lock().unwrap().mutation_count(), 1);
        assert!(adapter.click_widget(SESSION, 0, WIDGET, &token).is_err());
        assert_eq!(ledger.lock().unwrap().mutation_count(), 1);
        adapter.cleanup().unwrap();
        assert_lease_accounted(&ledger.lock().unwrap());
    }
}

#[test]
fn failed_cleanup_fences_session_retains_grant_and_can_retry_exact_owner() {
    for retry_on_drop in [false, true] {
        let (mut adapter, ledger) = fixture();
        let token = adapter.acquire_input(SESSION).unwrap();
        ledger.lock().unwrap().fail_cleanup_once = true;
        assert_eq!(adapter.cleanup().unwrap_err().code, "FAKE_CLEANUP_FAILED");
        assert!(!adapter.cleanup_complete);
        assert_eq!(adapter.sequence.as_ref().unwrap().0, token);
        assert_eq!(
            ledger.lock().unwrap().lease.as_deref(),
            Some(token.as_str())
        );
        assert_not_dispatched(
            &adapter.acquire_input(SESSION).unwrap_err(),
            "STALE_SESSION",
        );
        if retry_on_drop {
            drop(adapter);
        } else {
            adapter.cleanup().unwrap();
            assert!(adapter.cleanup_complete);
            assert!(adapter.sequence.is_none());
            drop(adapter);
        }
        let state = ledger.lock().unwrap();
        assert_eq!(state.cleanups, 2);
        assert_eq!(state.cleanup_retirements, 1);
        assert!(state.lease.is_none());
        assert_lease_accounted(&state);
    }
}

#[test]
fn click_focus_never_bypasses_explicit_value_condition_and_failure_fences() {
    for expected in ["wrong-value", "observed-after-click"] {
        let (mut adapter, ledger) = fixture();
        ledger.lock().unwrap().observed_focus = Some(true);
        let token = adapter.acquire_input(SESSION).unwrap();
        let outcome = adapter.click_widget_with_postcondition(
            SESSION,
            0,
            WIDGET,
            &token,
            Some((WIDGET, expected)),
        );
        assert_eq!(ledger.lock().unwrap().mutation_count(), 1);
        if expected == "wrong-value" {
            let error = outcome.unwrap_err();
            assert_eq!(error.code, "ACTION_POSTCONDITION_NOT_VERIFIED");
            assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
            assert_eq!(
                error.details["observed_action"]["explicit_value_readback"]["val"],
                "observed-after-click"
            );
            assert_eq!(error.details["observed_action"]["key_focus_verified"], true);
            assert_not_dispatched(
                &adapter
                    .click_widget(SESSION, 0, WIDGET, &token)
                    .unwrap_err(),
                "REMOTE_SEQUENCE_FENCED",
            );
            assert_eq!(ledger.lock().unwrap().mutation_count(), 1);
        } else {
            let value = outcome.unwrap();
            assert_eq!(value["explicit_value_readback"]["val"], expected);
            assert_eq!(value["business_postcondition_verified"], true);
        }
        adapter.cleanup().unwrap();
    }
}

#[test]
fn normal_close_failed_cleanup_retains_drop_recovery_without_another_quit() {
    let (mut adapter, ledger) = fixture();
    let exit = adapter.close(SESSION).unwrap();
    assert_eq!(exit["exit_code"], 0);
    ledger.lock().unwrap().fail_cleanup_once = true;
    assert_eq!(adapter.cleanup().unwrap_err().code, "FAKE_CLEANUP_FAILED");
    assert!(!adapter.cleanup_complete);
    assert!(adapter.close(SESSION).is_err());
    drop(adapter);
    let state = ledger.lock().unwrap();
    assert_eq!(state.quit_count(), 1);
    assert_eq!(state.cleanups, 2);
    assert!(state.lease.is_none());
    assert_lease_accounted(&state);
}

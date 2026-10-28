//! Pure real-adapter contract tests. The fake port proves no OS/UI/GPU behavior.
use super::*;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Ledger {
    saved: bool,
    value: String,
    focused: bool,
    selection: [usize; 2],
    sequence: u64,
    action_sequence: u64,
    last_action: Option<ActionObservation>,
    armed: Option<ActionAuthorization>,
    input: Option<String>,
    acquired: usize,
    released: usize,
    dispatched: usize,
    disarmed: usize,
    model_revision: u64,
    document_generation: u64,
    uid: u64,
    fault: Option<&'static str>,
    fault_after_dispatch: Option<&'static str>,
    wrong_type: bool,
    port_missing: bool,
    guard_missing: bool,
    handler_missing: bool,
    cancel_input: bool,
    release_failure: bool,
    disarm_failure: bool,
    swap_at_arm: bool,
    swap_after_arm: bool,
    collapse_selection_after_arm: bool,
    lose_focus_after_arm: bool,
    save_during_acquire: bool,
    save_after_arm: bool,
    unknown_after_dispatch: bool,
    wrong_domain: bool,
}
struct Platform {
    binding: SessionBinding,
    ledger: Arc<Mutex<Ledger>>,
}
impl Platform {
    fn context(state: &Ledger) -> Context {
        Context {
            runtime_instance: "runtime-1".into(),
            document_id: "temporary-doc".into(),
            document_generation: state.document_generation,
            object_id: "wall-A".into(),
            object_generation: 1,
        }
    }
}
impl RemotePlatform for Platform {
    fn binding(&self) -> &SessionBinding {
        &self.binding
    }
    fn validate(&mut self) -> Result<()> {
        Ok(())
    }
    fn request(&mut self, target: &str, mutating: bool) -> Result<Value> {
        require(
            super::super::protocol::allowed_route(target),
            "REMOTE_ROUTE_NOT_ALLOWLISTED",
        )?;
        let mut s = self.ledger.lock().unwrap();
        let route = target.split('?').next().unwrap();
        if !mutating {
            return Ok(match route {
                "/activity" => {
                    json!({"user_seq":1,"user_active":false,"held":false,"quiet_ms":2000})
                }
                "/s" => {
                    json!({"pid":self.binding.pid,"w":[{"i":0,"t":"pure fixture","sz":[640,480],"dpi":1,"pos":[0,0]}]})
                }
                "/snap" => json!({"s":[
                    {"i":"panel.height","w":0,"ty":if s.wrong_type {"Button"} else {"TextInput"},
                     "enabled":true,"v":1,"r":[10,20,100,30],"val":s.value},
                    {"i":"panel.save","w":0,"ty":"Button","enabled":true,"v":1,"r":[10,60,100,30]}
                ]}),
                _ => return Err(RemoteError::refused("UNUSED_TEST_ROUTE")),
            });
        }
        let guard = s
            .armed
            .take()
            .ok_or_else(|| RemoteError::refused("APP_ACTION_NOT_ARMED"))?;
        if s.swap_after_arm {
            s.document_generation += 1;
        }
        if s.collapse_selection_after_arm {
            s.selection = [s.value.len(), s.value.len()];
        }
        if s.lose_focus_after_arm {
            s.focused = false;
        }
        if s.save_after_arm {
            s.saved = true;
        }
        require(
            guard.context == Self::context(&s) && guard.model_revision == s.model_revision,
            "APP_GUARD_CONTEXT_CHANGED",
        )?;
        let actual_domain = BTreeMap::from([(
            "saved".to_string(),
            if s.saved && !s.wrong_domain {
                "true"
            } else {
                "false"
            }
            .to_string(),
        )]);
        require(
            guard.expected_domain == actual_domain,
            "APP_GUARD_DOMAIN_PRESTATE_CHANGED",
        )?;
        if guard.request.kind == WidgetKind::TextInput {
            require(
                guard.expected_focused == s.focused
                    && guard.expected_value.as_deref() == Some(s.value.as_str())
                    && guard.expected_selection == Some(s.selection),
                "APP_GUARD_EDIT_PRESTATE_CHANGED",
            )?;
        }
        s.dispatched += 1;
        match guard.action {
            Action::Focus => s.focused = true,
            Action::TypeText => {
                s.value = guard.text.clone().unwrap();
                s.selection = [s.value.len(), s.value.len()];
                s.model_revision += 1;
            }
            Action::SelectAll => s.selection = [0, s.value.len()],
            Action::Backspace => {
                // Model the actual range/caret edit, not a hardcoded clear.
                let [start, end] = s.selection;
                let erase_start = if start == end {
                    s.value[..start].char_indices().last().map_or(0, |(i, _)| i)
                } else {
                    start
                };
                s.value.replace_range(erase_start..end, "");
                s.selection = [erase_start, erase_start];
                s.model_revision += 1;
            }
            Action::Invoke => {
                s.saved = true;
            }
            Action::Read => panic!("read never dispatches"),
        }
        if !s.handler_missing {
            s.action_sequence += 1;
            s.last_action = Some(ActionObservation {
                sequence: s.action_sequence,
                authorization_challenge: guard.request.challenge,
                automation_id: guard.request.automation_id,
                widget_uid: guard.widget_uid,
                action: guard.action,
            });
        }
        if s.unknown_after_dispatch {
            return Err(RemoteError::unknown("TEST_ACK_LOST"));
        }
        Ok(json!({"ok":true}))
    }
    fn acquire_input(&mut self) -> Result<String> {
        let mut s = self.ledger.lock().unwrap();
        require(s.input.is_none(), "INPUT_LOCK_ALREADY_HELD")?;
        s.acquired += 1;
        if s.save_during_acquire {
            s.saved = true;
        }
        s.input = Some("test-lease".into());
        Ok("test-lease".into())
    }
    fn validate_input(&mut self, token: &str) -> Result<()> {
        let s = self.ledger.lock().unwrap();
        require(!s.cancel_input, "TEST_CANCELLED_BEFORE_DISPATCH")?;
        require(s.input.as_deref() == Some(token), "STALE_LEASE")
    }
    fn release_input(&mut self, token: &str) -> Result<()> {
        let mut s = self.ledger.lock().unwrap();
        require(s.input.as_deref() == Some(token), "STALE_LEASE")?;
        if s.release_failure {
            return Err(RemoteError::refused("TEST_RELEASE_FAILED"));
        }
        s.input = None;
        s.released += 1;
        Ok(())
    }
    fn copy_native_frame(&mut self, _: &Value, _: u64) -> Result<Value> {
        Err(RemoteError::refused("TEST_NO_GPU"))
    }
    fn reap_normal_exit(&mut self) -> Result<Value> {
        Err(RemoteError::refused("TEST_NO_PROCESS"))
    }
    fn cleanup_owned_resources(&mut self) -> Result<Value> {
        Ok(json!({"pure_test_only":true}))
    }
    fn arm_app_semantics(&mut self, a: &ActionAuthorization) -> Result<()> {
        let mut s = self.ledger.lock().unwrap();
        require(!s.guard_missing, "UNSUPPORTED_APP_SEMANTIC_ACTION_GUARD")?;
        if s.swap_at_arm {
            s.document_generation += 1;
        }
        require(
            a.context == Self::context(&s)
                && a.model_revision == s.model_revision
                && a.widget_uid == s.uid
                && s.armed.is_none(),
            "APP_GUARD_CONTEXT_CHANGED",
        )?;
        s.armed = Some(a.clone());
        Ok(())
    }
    fn disarm_app_semantics(&mut self, a: &ActionAuthorization) -> Result<()> {
        let mut s = self.ledger.lock().unwrap();
        require(!s.disarm_failure, "TEST_DISARM_FAILED")?;
        require(
            s.armed
                .as_ref()
                .is_none_or(|v| v.request.challenge == a.request.challenge),
            "FOREIGN_APP_ACTION_GUARD",
        )?;
        s.armed = None;
        s.disarmed += 1;
        Ok(())
    }
    fn observe_app_semantics(&mut self, request: &ObservationRequest) -> Result<AppObservation> {
        let mut s = self.ledger.lock().unwrap();
        require(!s.port_missing, "UNSUPPORTED_APP_SEMANTIC_OBSERVATION")?;
        s.sequence += 1;
        let edit = request.kind == WidgetKind::TextInput;
        let mut observation = AppObservation {
            schema: OBSERVATION_SCHEMA.into(),
            request: request.clone(),
            observation_sequence: s.sequence,
            widget_uid: s.uid,
            binding_generation: 1,
            enabled: true,
            visible: true,
            focused: edit && s.focused,
            value: edit.then(|| s.value.clone()),
            selection: edit.then_some(s.selection),
            context: Self::context(&s),
            model_revision: s.model_revision,
            action_sequence: s.action_sequence,
            last_action: s.last_action.clone(),
            domain: BTreeMap::from([(
                "saved".into(),
                if s.saved && !s.wrong_domain {
                    "true"
                } else {
                    "false"
                }
                .into(),
            )]),
        };
        let fault = if s.dispatched > 0 {
            s.fault_after_dispatch.or(s.fault)
        } else {
            s.fault
        };
        match fault {
            Some("session") => observation.request.binding.session_id = "foreign".into(),
            Some("owner") => observation.request.binding.owner = "foreign".into(),
            Some("generation") => observation.request.binding.generation += 1,
            Some("birth") => observation.request.binding.process_birth = "different".into(),
            Some("pid") => observation.request.binding.pid += 1,
            Some("sha") => observation.request.binding.executable_sha256 = "b".repeat(64),
            Some("source") => observation.request.source_manifest_sha256 = "b".repeat(64),
            Some("window") => observation.request.binding.window_id += 1,
            Some("widget") => observation.request.widget_id = "neighbor".into(),
            Some("automation") => observation.request.automation_id = "neighbor".into(),
            Some("challenge") => observation.request.challenge -= 1,
            Some("sequence") => observation.observation_sequence = 0,
            Some("uid") => observation.widget_uid = 0,
            Some("binding") => observation.binding_generation = 0,
            Some("visible") => observation.visible = false,
            Some("disabled") => observation.enabled = false,
            Some("document") => observation.context.document_generation += 1,
            Some("runtime") => observation.context.runtime_instance = "other-runtime".into(),
            Some("value") => observation.value = Some("wrong".into()),
            Some("selection") => observation.selection = Some([1, 999]),
            Some("domain") => {
                observation
                    .domain
                    .insert("not-approved".into(), "value".into());
            }
            Some("action") => {
                if let Some(a) = &mut observation.last_action {
                    a.automation_id = "neighbor".into();
                }
            }
            Some("action_nonce") => {
                if let Some(a) = &mut observation.last_action {
                    a.authorization_challenge += 1;
                }
            }
            _ => (),
        }
        Ok(observation)
    }
}

fn contract() -> AppContract {
    AppContract {
        schema: CONTRACT_SCHEMA.into(),
        contract_id: "test-app".into(),
        source_manifest_sha256: "a".repeat(64),
        widgets: vec![
            WidgetBinding {
                automation_id: "wall.height".into(),
                widget_id: "panel.height".into(),
                kind: WidgetKind::TextInput,
                actions: BTreeSet::from([
                    Action::Read,
                    Action::Focus,
                    Action::TypeText,
                    Action::SelectAll,
                    Action::Backspace,
                ]),
            },
            WidgetBinding {
                automation_id: "document.save".into(),
                widget_id: "panel.save".into(),
                kind: WidgetKind::Button,
                actions: BTreeSet::from([Action::Read, Action::Invoke]),
            },
        ],
        domain_keys: BTreeSet::from(["saved".into()]),
    }
}
fn setup() -> (
    MakepadRemoteAdapter<Platform>,
    Registration,
    Arc<Mutex<Ledger>>,
) {
    let ledger = Arc::new(Mutex::new(Ledger {
        document_generation: 1,
        uid: 42,
        ..Ledger::default()
    }));
    let platform = Platform {
        binding: SessionBinding {
            session_id: "session-A".into(),
            owner: "owner-A".into(),
            generation: 1,
            pid: 23,
            process_birth: "birth-23".into(),
            executable: "approved-test.exe".into(),
            executable_sha256: "e".repeat(64),
            source_commit: super::super::PINNED_SOURCE.into(),
            window_id: 0,
            platform: "PURE_TEST_NOT_NATIVE".into(),
        },
        ledger: ledger.clone(),
    };
    let mut adapter = MakepadRemoteAdapter::from_trusted_platform(platform).unwrap();
    let registration = adapter
        .register_app_semantics("session-A", "owner-A", contract())
        .unwrap();
    (adapter, registration, ledger)
}
fn assert_refused(error: RemoteError, code: &str) {
    assert_eq!(error.code, code);
    assert_eq!(error.outcome, "NOT_DISPATCHED");
}

#[test]
fn typed_whitelist_rejects_invalid_types_duplicates_sources_and_privileges() {
    for i in 0..7 {
        let mut c = contract();
        match i {
            0 => c.source_manifest_sha256 = "not-a-hash".into(),
            1 => c.widgets[1]
                .actions
                .insert(Action::TypeText)
                .then_some(())
                .unwrap(),
            2 => c.widgets[0]
                .actions
                .insert(Action::Invoke)
                .then_some(())
                .unwrap(),
            3 => c.widgets[1].automation_id = c.widgets[0].automation_id.clone(),
            4 => c.widgets[1].widget_id = c.widgets[0].widget_id.clone(),
            5 => {
                c.widgets[0].actions.remove(&Action::Read);
            }
            _ => c.widgets[0].widget_id.clear(),
        }
        assert!(c.validate().is_err(), "case {i}");
    }
}
#[test]
fn real_adapter_text_edit_cycle_and_button_action_release_each_lease() {
    let (mut a, r, l) = setup();
    for (action, text) in [
        (Action::Focus, None),
        (Action::TypeText, Some("ALPHA")),
        (Action::SelectAll, None),
        (Action::Backspace, None),
        (Action::TypeText, Some("BRAVO")),
    ] {
        let state = a
            .app_semantic_state("session-A", &r, "wall.height")
            .unwrap();
        let result = a
            .app_semantic_action("session-A", &r, &state, action, text, None)
            .unwrap();
        assert_eq!(result["postcondition_verified"], true);
        assert!(l.lock().unwrap().input.is_none());
    }
    let state = a
        .app_semantic_state("session-A", &r, "document.save")
        .unwrap();
    let post = Postcondition {
        context: state.observation.context.clone(),
        domain_key: "saved".into(),
        expected_value: "true".into(),
    };
    let result = a
        .app_semantic_action("session-A", &r, &state, Action::Invoke, None, Some(&post))
        .unwrap();
    assert_eq!(
        result["mechanism"],
        "APP_REMOTE_BUTTON_CLICK_WITH_APP_READBACK"
    );
    assert_eq!(result["semantic_uia_invoke_or_setvalue"], false);
    let s = l.lock().unwrap();
    assert_eq!(s.value, "BRAVO");
    assert_eq!(
        (s.acquired, s.released, s.dispatched, s.disarmed),
        (6, 6, 6, 6)
    );
}
#[test]
fn observation_rejects_cross_session_process_widget_source_nonce_and_sequence() {
    for fault in [
        "session",
        "owner",
        "generation",
        "birth",
        "pid",
        "sha",
        "source",
        "window",
        "widget",
        "automation",
        "challenge",
        "sequence",
        "uid",
        "binding",
        "visible",
        "disabled",
        "value",
        "selection",
        "domain",
    ] {
        let (mut a, r, l) = setup();
        l.lock().unwrap().fault = Some(fault);
        assert!(
            a.app_semantic_state("session-A", &r, "wall.height")
                .is_err(),
            "{fault}"
        );
        let s = l.lock().unwrap();
        assert_eq!(s.dispatched, 0);
        assert_eq!(s.acquired, 0);
    }
}
#[test]
fn real_snapshot_type_is_checked_before_observer_or_any_input() {
    let (mut a, r, l) = setup();
    l.lock().unwrap().wrong_type = true;
    assert_refused(
        a.app_semantic_state("session-A", &r, "wall.height")
            .unwrap_err(),
        "APP_SEMANTIC_WIDGET_TYPE_MISMATCH",
    );
    assert_eq!(l.lock().unwrap().sequence, 0);
}
#[test]
fn unsupported_producer_refuses_without_acquiring_or_dispatching() {
    let (mut a, r, l) = setup();
    l.lock().unwrap().port_missing = true;
    assert_refused(
        a.app_semantic_state("session-A", &r, "wall.height")
            .unwrap_err(),
        "UNSUPPORTED_APP_SEMANTIC_OBSERVATION",
    );
    let s = l.lock().unwrap();
    assert_eq!((s.acquired, s.dispatched), (0, 0));
}
#[test]
fn read_only_registration_cannot_grant_invoke_or_fill() {
    let (mut a, _, l) = setup();
    let mut c = contract();
    for w in &mut c.widgets {
        w.actions = BTreeSet::from([Action::Read]);
    }
    let r = a.register_app_semantics("session-A", "owner-A", c).unwrap();
    let state = a
        .app_semantic_state("session-A", &r, "wall.height")
        .unwrap();
    assert_refused(
        a.app_semantic_action("session-A", &r, &state, Action::Focus, None, None)
            .unwrap_err(),
        "UNSUPPORTED_APP_SEMANTIC_ACTION",
    );
    assert_eq!(l.lock().unwrap().dispatched, 0);
}
#[test]
fn old_bim_document_or_widget_uid_never_gets_a_new_lease() {
    for change_uid in [true, false] {
        let (mut a, r, l) = setup();
        let state = a
            .app_semantic_state("session-A", &r, "wall.height")
            .unwrap();
        if change_uid {
            l.lock().unwrap().uid += 1;
        } else {
            l.lock().unwrap().document_generation += 1;
        }
        assert_refused(
            a.app_semantic_action("session-A", &r, &state, Action::Focus, None, None)
                .unwrap_err(),
            "APP_SEMANTIC_PRESTATE_CHANGED",
        );
        assert_eq!(l.lock().unwrap().acquired, 0);
    }
}
#[test]
fn unknown_and_foreign_session_and_generation_are_fenced_before_observation() {
    let (mut a, r, l) = setup();
    assert_refused(
        a.app_semantic_state("foreign", &r, "wall.height")
            .unwrap_err(),
        "UNKNOWN_SESSION",
    );
    assert!(
        a.register_app_semantics("session-A", "other-owner", contract())
            .is_err()
    );
    a.platform.binding.generation += 1;
    assert!(
        a.app_semantic_state("session-A", &r, "wall.height")
            .is_err()
    );
    assert_eq!(l.lock().unwrap().sequence, 0);
}
#[test]
fn missing_button_postcondition_refuses_before_any_mutation_or_lease() {
    let (mut a, r, l) = setup();
    let state = a
        .app_semantic_state("session-A", &r, "document.save")
        .unwrap();
    assert_refused(
        a.app_semantic_action("session-A", &r, &state, Action::Invoke, None, None)
            .unwrap_err(),
        "APP_SEMANTIC_POSTCONDITION_REQUIRED",
    );
    assert_eq!(l.lock().unwrap().acquired, 0);
}
#[test]
fn failed_focus_selection_guard_or_cancellation_release_once_without_input() {
    for fault in ["focus", "selection", "guard", "cancel"] {
        let (mut a, r, l) = setup();
        let state = a
            .app_semantic_state("session-A", &r, "wall.height")
            .unwrap();
        {
            let mut s = l.lock().unwrap();
            s.guard_missing = fault == "guard";
            s.cancel_input = fault == "cancel";
        }
        let (action, text) = match fault {
            "focus" => (Action::TypeText, Some("ALPHA")),
            "selection" => (Action::Backspace, None),
            _ => (Action::Focus, None),
        };
        // Empty selection is deliberately valid for empty Backspace, so make a
        // real prestate before testing a nonempty unselected value.
        let state = if fault == "selection" {
            let mut s = l.lock().unwrap();
            s.value = "old".into();
            s.selection = [3, 3];
            s.focused = true;
            drop(s);
            a.app_semantic_state("session-A", &r, "wall.height")
                .unwrap()
        } else {
            state
        };
        assert!(
            a.app_semantic_action("session-A", &r, &state, action, text, None)
                .is_err(),
            "{fault}"
        );
        let s = l.lock().unwrap();
        assert_eq!(s.dispatched, 0);
        assert_eq!(s.released, 1);
        assert!(s.input.is_none());
    }
}
#[test]
fn app_guard_closes_document_swap_between_snapshot_arm_and_native_event() {
    for during_arm in [true, false] {
        let (mut a, r, l) = setup();
        let state = a
            .app_semantic_state("session-A", &r, "wall.height")
            .unwrap();
        {
            let mut s = l.lock().unwrap();
            s.swap_at_arm = during_arm;
            s.swap_after_arm = !during_arm;
        }
        assert_refused(
            a.app_semantic_action("session-A", &r, &state, Action::Focus, None, None)
                .unwrap_err(),
            "APP_GUARD_CONTEXT_CHANGED",
        );
        let s = l.lock().unwrap();
        assert_eq!(s.dispatched, 0);
        assert_eq!(s.released, 1);
        assert!(s.armed.is_none());
    }
}
#[test]
fn ack_without_handler_domain_or_exact_action_nonce_is_unknown_and_never_replayed() {
    for fault in ["handler", "domain", "action", "action_nonce", "document"] {
        let (mut a, r, l) = setup();
        let state = a
            .app_semantic_state("session-A", &r, "document.save")
            .unwrap();
        let post = Postcondition {
            context: state.observation.context.clone(),
            domain_key: "saved".into(),
            expected_value: "true".into(),
        };
        {
            let mut s = l.lock().unwrap();
            s.handler_missing = fault == "handler";
            s.wrong_domain = fault == "domain";
            if matches!(fault, "action" | "action_nonce" | "document") {
                s.fault_after_dispatch = Some(fault);
            }
        }
        let e = a
            .app_semantic_action("session-A", &r, &state, Action::Invoke, None, Some(&post))
            .unwrap_err();
        assert_eq!(e.outcome, "OUTCOME_UNKNOWN");
        assert!(!e.retry_safe);
        assert!(
            a.app_semantic_action("session-A", &r, &state, Action::Invoke, None, Some(&post))
                .is_err()
        );
        let s = l.lock().unwrap();
        assert_eq!(s.dispatched, 1);
        assert_eq!(s.released, 1);
        assert!(s.armed.is_none());
    }
}
#[test]
fn lost_ack_preserves_original_unknown_and_does_not_reissue_the_event() {
    let (mut a, r, l) = setup();
    let state = a
        .app_semantic_state("session-A", &r, "wall.height")
        .unwrap();
    l.lock().unwrap().unknown_after_dispatch = true;
    let e = a
        .app_semantic_action("session-A", &r, &state, Action::Focus, None, None)
        .unwrap_err();
    assert_eq!(e.code, "TEST_ACK_LOST");
    assert_eq!(e.outcome, "OUTCOME_UNKNOWN");
    assert_eq!(l.lock().unwrap().dispatched, 1);
    assert_eq!(l.lock().unwrap().released, 1);
}
#[test]
fn release_failure_retains_action_observations_and_fences_following_input() {
    let (mut a, r, l) = setup();
    let state = a
        .app_semantic_state("session-A", &r, "wall.height")
        .unwrap();
    l.lock().unwrap().release_failure = true;
    let e = a
        .app_semantic_action("session-A", &r, &state, Action::Focus, None, None)
        .unwrap_err();
    assert_eq!(e.code, "POST_ACTION_LEASE_RELEASE_UNVERIFIED");
    assert_eq!(e.outcome, "OUTCOME_UNKNOWN");
    assert_eq!(e.details["observed_action"]["postcondition_verified"], true);
    assert!(
        a.app_semantic_action("session-A", &r, &state, Action::Focus, None, None)
            .is_err()
    );
    assert_eq!(l.lock().unwrap().dispatched, 1);
}
#[test]
fn producer_decoder_refuses_duplicate_keys_unknown_fields_and_oversized_bytes() {
    let (mut a, r, _) = setup();
    let s = a
        .app_semantic_state("session-A", &r, "wall.height")
        .unwrap();
    let raw = serde_json::to_vec(&s.observation).unwrap();
    assert!(AppObservation::from_json_bytes(&raw).is_ok());
    let text = String::from_utf8(raw).unwrap();
    let duplicate = text.replacen("{", "{\"schema\":\"duplicate\",", 1);
    assert!(AppObservation::from_json_bytes(duplicate.as_bytes()).is_err());
    let mut value = serde_json::to_value(&s.observation).unwrap();
    value["unknown"] = json!(true);
    assert!(AppObservation::from_json_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut nested = serde_json::to_value(&s.observation).unwrap();
    nested["request"]["binding"]["unrecognized"] = json!(true);
    assert!(AppObservation::from_json_bytes(&serde_json::to_vec(&nested).unwrap()).is_err());
    assert!(AppObservation::from_json_bytes(&vec![b' '; 65537]).is_err());
}

#[test]
fn already_true_domain_value_is_not_a_fresh_button_postcondition() {
    let (mut a, r, l) = setup();
    l.lock().unwrap().saved = true;
    let state = a
        .app_semantic_state("session-A", &r, "document.save")
        .unwrap();
    let p = Postcondition {
        context: state.observation.context.clone(),
        domain_key: "saved".into(),
        expected_value: "true".into(),
    };
    assert_refused(
        a.app_semantic_action("session-A", &r, &state, Action::Invoke, None, Some(&p))
            .unwrap_err(),
        "APP_SEMANTIC_POSTCONDITION_ALREADY_SATISFIED",
    );
    assert_eq!(l.lock().unwrap().acquired, 0);
}

#[test]
fn guard_cleanup_failure_is_unknown_and_lease_release_is_still_attempted() {
    let (mut a, r, l) = setup();
    let state = a
        .app_semantic_state("session-A", &r, "wall.height")
        .unwrap();
    l.lock().unwrap().disarm_failure = true;
    let error = a
        .app_semantic_action("session-A", &r, &state, Action::Focus, None, None)
        .unwrap_err();
    assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
    assert_eq!(error.code, "APP_SEMANTIC_GUARD_CLEANUP_UNVERIFIED");
    assert_eq!(l.lock().unwrap().released, 1);
    assert_eq!(l.lock().unwrap().dispatched, 1);
}

#[test]
fn post_arm_focus_or_selection_race_is_refused_before_widget_text_changes() {
    for collapse in [true, false] {
        let (mut a, r, l) = setup();
        {
            let mut s = l.lock().unwrap();
            s.value = "ABCD".into();
            s.selection = [0, 4];
            s.focused = true;
        }
        let state = a
            .app_semantic_state("session-A", &r, "wall.height")
            .unwrap();
        {
            let mut s = l.lock().unwrap();
            s.collapse_selection_after_arm = collapse;
            s.lose_focus_after_arm = !collapse;
        }
        assert_refused(
            a.app_semantic_action("session-A", &r, &state, Action::Backspace, None, None)
                .unwrap_err(),
            "APP_GUARD_EDIT_PRESTATE_CHANGED",
        );
        let s = l.lock().unwrap();
        assert_eq!(s.value, "ABCD");
        assert_eq!(s.dispatched, 0);
        assert_eq!(s.released, 1);
        assert!(s.armed.is_none());
    }
}

#[test]
fn background_domain_change_during_acquire_or_after_arm_cannot_become_button_success() {
    for during_acquire in [true, false] {
        let (mut a, r, l) = setup();
        let state = a
            .app_semantic_state("session-A", &r, "document.save")
            .unwrap();
        let p = Postcondition {
            context: state.observation.context.clone(),
            domain_key: "saved".into(),
            expected_value: "true".into(),
        };
        {
            let mut s = l.lock().unwrap();
            s.save_during_acquire = during_acquire;
            s.save_after_arm = !during_acquire;
        }
        let error = a
            .app_semantic_action("session-A", &r, &state, Action::Invoke, None, Some(&p))
            .unwrap_err();
        assert_refused(
            error,
            if during_acquire {
                "APP_SEMANTIC_PRESTATE_CHANGED"
            } else {
                "APP_GUARD_DOMAIN_PRESTATE_CHANGED"
            },
        );
        let s = l.lock().unwrap();
        assert_eq!(s.dispatched, 0);
        assert_eq!(s.released, 1);
        assert!(s.armed.is_none());
    }
}

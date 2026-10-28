//! Pure source regressions only: no environment mutation, files, native HWNDs,
//! HTTP, or application launch. The mock cannot establish native acceptance.
use super::*;

fn synthetic_content_geometry() -> super::super::HostContentGeometry {
    serde_json::from_value(json!({"schema":"toolkit-wslc-host-content-geometry-v1", "session_id":"synthetic",
        "generation":1,"sequence":1,"tag":"synthetic-tag","title":"synthetic-title","rail_title":"synthetic-rail-title","container_id":"a".repeat(64),
        "guest_pid":10,"guest_process_start_ticks":"20","rail_hwnd":30,"rail_pid":40,"rail_process_birth":"50",
        "started_monotonic_ns":1,"observed_monotonic_ns":2,"observed_unix_ms":3,
        "native_client":{"x":118,"y":28,"width":951,"height":697},
        "native_outer":{"x":118,"y":28,"width":951,"height":697},
        "x11":{"schema":"toolkit-wslc-x11-content-geometry-v1","display":":0","expected_guest_pid":10,"pid_property":10,"identity_source":"NET_WM_PID_AND_UNIQUE_TITLE","title":"synthetic-title",
            "window":100,"root":1,"client":{"x":156,"y":87,"width":875,"height":600},
            "frame":{"x":118,"y":28,"width":951,"height":697},"frame_extents":[38,38,59,38],
            "frame_source":"NET_FRAME_EXTENTS","frame_window":200},
        "raw_x11_utf8":"SYNTHETIC_NOT_NATIVE","raw_x11_sha256":"0".repeat(64)})).unwrap()
}

#[test]
fn wslc_content_geometry_maps_measured_frame_insets_without_padding_constants() {
    let mut g = synthetic_content_geometry();
    let row = json!({"r":[20,30,100,40]});
    let remote = json!({"px":[875,600],"pos":[156,87],"dpi":1.0});
    assert_eq!(
        wslc_widget_bounds(&row, &remote, &g).unwrap(),
        Rect {
            x: 176,
            y: 117,
            width: 100,
            height: 40
        }
    );
    g.native_client = super::super::ObservedGeometryRect {
        x: -200,
        y: 100,
        width: 1902,
        height: 1394,
    };
    g.native_outer = g.native_client.clone();
    assert_eq!(
        wslc_widget_bounds(&row, &remote, &g).unwrap(),
        Rect {
            x: -84,
            y: 278,
            width: 200,
            height: 80
        }
    );
    // Reparent geometry is equally admissible only with its actual frame XID.
    g.x11.frame_source = "REPARENT_FRAME".into();
    assert!(wslc_widget_bounds(&row, &remote, &g).is_ok());
    g.x11.frame_window = None;
    assert_eq!(
        wslc_widget_bounds(&row, &remote, &g).unwrap_err(),
        "WSLC_X11_FRAME_CONTENT_CONTRADICTION"
    );
}

#[test]
fn wslc_content_geometry_refuses_contradictions_nonuniform_scale_and_outside_widgets() {
    let g = synthetic_content_geometry();
    let row = json!({"r":[20,30,100,40]});
    let remote = json!({"px":[875,600],"pos":[156,87],"dpi":1.0});
    for change in 0..6 {
        let mut changed = g.clone();
        match change {
            0 => changed.x11.frame_extents[0] += 1,
            1 => changed.x11.client.width += 1,
            2 => changed.native_client.width *= 2,
            3 => changed.native_outer.x += 1,
            4 => changed.x11.frame_source = "GUESSED_PADDING".into(),
            _ => changed.x11.frame_window = Some(changed.x11.root),
        }
        assert!(wslc_widget_bounds(&row, &remote, &changed).is_err());
    }
    for changed in [
        json!({"px":[874,600],"pos":[156,87],"dpi":1}),
        json!({"px":[875,600],"pos":[118,28],"dpi":1}),
        json!({"px":[875,600],"pos":[156,87],"dpi":0}),
    ] {
        assert!(wslc_widget_bounds(&row, &changed, &g).is_err());
    }
    for r in [
        json!([-1, 0, 1, 1]),
        json!([0, 0, 876, 1]),
        json!([0, 599, 1, 2]),
        json!([0, 0, 0, 1]),
    ] {
        assert!(wslc_widget_bounds(&json!({"r":r}), &remote, &g).is_err());
    }
}

#[test]
fn wslc_provisioning_owner_remains_exact_while_windows_owner_is_client_scoped() {
    let parent = "Makepad_Toolkit:approved-wslc-context";
    assert_eq!(wslc_context_owner(parent).unwrap(), parent);
    assert_ne!(scoped_owner(parent, "remote:client-a").unwrap(), parent);
    assert_ne!(
        scoped_owner(parent, "remote:client-a").unwrap(),
        scoped_owner(parent, "remote:client-b").unwrap()
    );
    assert!(wslc_context_owner("").is_err());
    assert!(wslc_context_owner(&"x".repeat(129)).is_err());
}
use super::super::SessionBinding;

fn config_value() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("pure-router-test-only");
    json!({
        "schema": SCHEMA,
        "source_commit": PINNED_SOURCE,
        "evidence_root": root.join("evidence"),
        "admission_path": root.join("admission.json"),
        "targets": [{
            "selector": {"process_name":"fixture.exe", "title":"Exact fixture"},
            "profile_path": root.join("profile.json"),
            "profile_sha256": "a".repeat(64),
            "widgets": [{"automation_id":"editor", "widget_id":"body.editor",
                "name":"Editor", "control_type":"Edit"}]
        }],
        "uia_allowlist": [{"process_name":"ordinary.exe"}]
    })
}

fn config(value: Value) -> Config {
    serde_json::from_value(value).expect("synthetic config must deserialize")
}

fn assert_config_refused(value: Value, code: &str) {
    let error = validate_config(&config(value)).expect_err("invalid config admitted");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(error.details["remote_error"]["code"], code);
    assert_eq!(error.details["remote_error"]["outcome"], "NOT_DISPATCHED");
    assert_eq!(error.details["fallback_used"], false);
}

#[test]
fn validate_config_accepts_minimal_and_exact_capacity_bounds() {
    assert!(validate_config(&config(config_value())).is_ok());
    let mut value = config_value();
    let target = value["targets"][0].clone();
    value["targets"] = Value::Array(
        (0..8)
            .map(|i| {
                let mut target = target.clone();
                target["selector"]["process_name"] = json!(format!("fixture-{i}.exe"));
                target["widgets"] = Value::Array((0..128).map(|j| json!({
            "automation_id":format!("editor-{j}"), "widget_id":format!("body.editor-{j}"),
            "name":"n".repeat(256), "control_type":"Edit"
        })).collect());
                target
            })
            .collect(),
    );
    value["uia_allowlist"] = json!(
        (1..=32)
            .map(|pid| json!({"process_id":pid}))
            .collect::<Vec<_>>()
    );
    assert!(validate_config(&config(value)).is_ok());

    let mut value = config_value();
    value["targets"][0]["widgets"][0]["automation_id"] = json!("a".repeat(512));
    value["targets"][0]["widgets"][0]["widget_id"] = json!("w".repeat(4096));
    assert!(validate_config(&config(value)).is_ok());
}

#[test]
fn validate_config_rejects_wrong_provenance_paths_and_collection_overflow() {
    for (key, replacement) in [
        ("schema", json!("foreign-schema")),
        ("source_commit", json!("0".repeat(40))),
        ("evidence_root", json!("relative/evidence")),
        ("admission_path", json!("relative/admission.json")),
        ("targets", json!([])),
    ] {
        let mut value = config_value();
        value[key] = replacement;
        assert_config_refused(value, "TRUSTED_ROUTING_CONFIG_INVALID");
    }
    let mut value = config_value();
    value["targets"] = json!(vec![value["targets"][0].clone(); 9]);
    assert_config_refused(value, "TRUSTED_ROUTING_CONFIG_INVALID");
    let mut value = config_value();
    value["uia_allowlist"] = json!(vec![json!({"process_name":"ordinary.exe"}); 33]);
    assert_config_refused(value, "TRUSTED_ROUTING_CONFIG_INVALID");
}

#[test]
fn validate_config_rejects_pid_adoption_unpinned_or_duplicate_targets() {
    for (key, replacement) in [
        (
            "selector",
            json!({"process_id":42,"process_name":"fixture.exe"}),
        ),
        ("selector", json!({"title":"Exact fixture"})),
        ("selector", json!({"process_name":""})),
        ("profile_path", json!("relative/profile.json")),
        ("profile_sha256", json!("a".repeat(63))),
        ("profile_sha256", json!("a".repeat(65))),
        ("profile_sha256", json!("g".repeat(64))),
        ("widgets", json!([])),
    ] {
        let mut value = config_value();
        value["targets"][0][key] = replacement;
        assert_config_refused(value, "TRUSTED_TARGET_INVALID");
    }
    let mut value = config_value();
    value["targets"] = json!(vec![value["targets"][0].clone(); 2]);
    assert_config_refused(value, "TRUSTED_TARGET_INVALID");
    let mut value = config_value();
    value["targets"][0]["widgets"] = json!(vec![value["targets"][0]["widgets"][0].clone(); 129]);
    assert_config_refused(value, "TRUSTED_TARGET_INVALID");
}

#[test]
fn validate_config_rejects_ambiguous_or_non_edit_widget_bindings() {
    for (key, replacement) in [
        ("automation_id", json!("")),
        ("widget_id", json!("")),
        ("automation_id", json!("a".repeat(513))),
        ("widget_id", json!("w".repeat(4097))),
        ("name", json!("n".repeat(257))),
        ("control_type", json!("Button")),
    ] {
        let mut value = config_value();
        value["targets"][0]["widgets"][0][key] = replacement;
        assert_config_refused(value, "TRUSTED_WIDGET_BINDING_INVALID");
    }
    for duplicate_key in ["automation_id", "widget_id"] {
        let mut value = config_value();
        let first = value["targets"][0]["widgets"][0].clone();
        let mut second = json!({"automation_id":"other", "widget_id":"body.other",
            "name":"Other", "control_type":"Edit"});
        second[duplicate_key] = first[duplicate_key].clone();
        value["targets"][0]["widgets"] = json!([first, second]);
        assert_config_refused(value, "TRUSTED_WIDGET_BINDING_INVALID");
    }
}

#[test]
fn validate_config_requires_bounded_explicit_uia_allowlist_entries() {
    let mut value = config_value();
    value["uia_allowlist"] = json!([{}]);
    assert_config_refused(value, "UNBOUNDED_UIA_ALLOWLIST_REFUSED");
    let mut value = config_value();
    value["uia_allowlist"] = json!([]);
    assert!(validate_config(&config(value)).is_ok());
}

#[test]
fn config_deserialization_rejects_unknown_trusted_fields() {
    for location in ["config", "target", "widget"] {
        let mut value = config_value();
        match location {
            "config" => value["fallback_to_uia"] = json!(true),
            "target" => value["targets"][0]["attach_pid"] = json!(42),
            _ => value["targets"][0]["widgets"][0]["semantic_set_value"] = json!(true),
        }
        assert!(
            serde_json::from_value::<Config>(value).is_err(),
            "{location}"
        );
    }
}

#[test]
fn exact_selector_compares_every_field_without_subset_or_case_folding() {
    let selector = WindowQuery {
        process_name: Some("fixture.exe".into()),
        process_id: Some(42),
        title: Some("Exact fixture".into()),
        title_contains: Some("fixture".into()),
    };
    assert!(exact_selector(&selector, &selector.clone()));
    let mut candidates = Vec::new();
    let mut other = selector.clone();
    other.process_id = None;
    candidates.push(other);
    let mut other = selector.clone();
    other.process_id = Some(43);
    candidates.push(other);
    let mut other = selector.clone();
    other.process_name = None;
    candidates.push(other);
    let mut other = selector.clone();
    other.process_name = Some("FIXTURE.EXE".into());
    candidates.push(other);
    let mut other = selector.clone();
    other.title = None;
    candidates.push(other);
    let mut other = selector.clone();
    other.title = Some("Exact fixture neighbor".into());
    candidates.push(other);
    let mut other = selector.clone();
    other.title_contains = None;
    candidates.push(other);
    let mut other = selector.clone();
    other.title_contains = Some("Exact".into());
    candidates.push(other);
    for other in candidates {
        assert!(!exact_selector(&selector, &other), "{other:?}");
        assert!(!exact_selector(&other, &selector), "{other:?}");
    }
    assert!(!exact_selector(
        &WindowQuery::default(),
        &WindowQuery {
            title: Some(String::new()),
            ..Default::default()
        }
    ));
}

#[test]
fn omitted_mode_is_not_explicit_visible_and_profile_probe_defaults_off() {
    let value = config_value();
    assert_eq!(config(value.clone()).targets[0].mode, None);
    for (spelling, mode) in [
        ("windows_hidden", Mode::WindowsHidden),
        ("wslc", Mode::Wslc),
        ("windows_visible_explicit", Mode::WindowsVisibleExplicit),
    ] {
        let mut value = value.clone();
        value["targets"][0]["mode"] = json!(spelling);
        assert_eq!(config(value).targets[0].mode, Some(mode));
    }
    for spelling in ["visible", "windows_visible", "auto", "uia"] {
        let mut value = value.clone();
        value["targets"][0]["mode"] = json!(spelling);
        assert!(serde_json::from_value::<Config>(value).is_err());
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut profile = json!({"schema":"toolkit-makepad-remote-trusted-profile-v1",
        "experimental_opt_in":true, "source_commit":PINNED_SOURCE,
        "executable":root.join("fixture.exe"), "executable_sha256":"a".repeat(64),
        "working_directory":root, "owner":"synthetic-owner", "hidden":true});
    assert!(
        !serde_json::from_value::<WindowsProfile>(profile.clone())
            .unwrap()
            .key_focus_probe
    );
    profile["key_focus_probe"] = json!(true);
    assert!(
        serde_json::from_value::<WindowsProfile>(profile.clone())
            .unwrap()
            .key_focus_probe
    );
    profile.as_object_mut().unwrap().remove("hidden");
    assert!(serde_json::from_value::<WindowsProfile>(profile).is_err());
}

#[test]
fn scoped_owner_preserves_exact_session_and_enforces_byte_limit() {
    assert_eq!(
        scoped_owner("operator", "remote:win:a:1").unwrap(),
        "operator:remote:win:a:1"
    );
    assert_ne!(
        scoped_owner("operator", "remote:win:a:1").unwrap(),
        scoped_owner("operator", "remote:win:b:1").unwrap()
    );
    assert_ne!(
        scoped_owner("operator-a", "remote:win:a:1").unwrap(),
        scoped_owner("operator-b", "remote:win:a:1").unwrap()
    );
    assert!(scoped_owner("", "remote:win:a:1").is_err());
    assert_eq!(scoped_owner("owner", &"x".repeat(122)).unwrap().len(), 128);
    assert!(scoped_owner("owner", &"x".repeat(123)).is_err());
    assert!(scoped_owner(&"é".repeat(64), "x").is_err());
}

#[test]
fn remote_ids_remain_monotonic_typed_and_session_scoped() {
    let mut a = SessionIds::with_nonce("router-a".into());
    let mut b = SessionIds::with_nonce("router-b".into());
    let window = a.window().unwrap();
    let next_window = a.window().unwrap();
    let element = a.element().unwrap();
    assert_ne!(window, next_window);
    assert_ne!(
        format!("remote:{window}"),
        format!("remote:{}", b.window().unwrap())
    );
    assert!(a.owns_window(&window));
    assert!(a.owns_element(&element));
    assert!(!b.owns_window(&window));
    assert!(!b.owns_element(&element));
    assert!(!a.owns_element(&window));
    assert!(!a.owns_window(&element));
    let empty = empty_window(format!("remote:{window}"));
    assert_eq!(empty.window_id, format!("remote:{window}"));
    assert_eq!(empty.process_id, 0);
    assert!(empty.hwnd.is_empty());
    assert!(!empty.visible && !empty.focused && !empty.foreground);
}

#[derive(Default)]
struct Calls {
    events: Vec<&'static str>,
    requests: Vec<(String, bool)>,
    releases: Vec<String>,
}

struct MockPlatform {
    binding: SessionBinding,
    calls: Rc<RefCell<Calls>>,
    cancel_on_acquire: Option<RequestControl>,
    fail_release: bool,
    fail_request: bool,
}

// These exercise the production router/adapter close path, not a native
// acceptance certificate. Real process/Job receipts are qualified separately.
#[test]
fn operator_lifecycle_is_default_off_and_foreign_identity_never_touches_a_target() {
    let mut router = McpRemoteRouter {
        config: config(config_value()),
        ids: SessionIds::new(),
        sessions: BTreeMap::new(),
        attempted: BTreeSet::new(),
        control: Rc::new(RefCell::new(None)),
    };
    let request = json!({"action":"close","session_id":"foreign","generation":1});
    let error = router.invoke_operator_lifecycle(&request).unwrap_err();
    assert_eq!(
        error.details["remote_error"]["code"],
        "OPERATOR_LIFECYCLE_NOT_ENABLED"
    );
    router.config.operator_lifecycle = true;
    for invalid in [
        json!({"action":"close","session_id":"foreign","generation":0}),
        json!({"action":"close","session_id":"foreign","generation":1,"pid":42}),
        json!({"action":"kill","session_id":"foreign","generation":1}),
    ] {
        assert_eq!(
            router.invoke_operator_lifecycle(&invalid).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }
    assert_eq!(
        router
            .invoke_operator_lifecycle(&request)
            .unwrap_err()
            .details["remote_error"]["code"],
        "UNKNOWN_OR_STALE_OWNED_SESSION"
    );
    assert!(router.sessions.is_empty());
}

#[test]
fn uncertain_close_keeps_original_cause_contains_once_and_never_replays_on_drop() {
    let nonce = SessionIds::new().window().unwrap().replace(':', "-");
    let directory = std::env::temp_dir().join(format!("toolkit-close-{nonce}"));
    std::fs::create_dir(&directory).unwrap();
    let (mock, calls) = MockPlatform::new();
    let adapter =
        MakepadRemoteAdapter::from_trusted_platform(Box::new(mock) as Box<dyn RemotePlatform>)
            .unwrap();
    let mut router = McpRemoteRouter {
        config: config(config_value()),
        ids: SessionIds::new(),
        sessions: BTreeMap::new(),
        attempted: BTreeSet::new(),
        control: Rc::new(RefCell::new(None)),
    };
    router.config.operator_lifecycle = true;
    router.sessions.insert(
        "owned-window".into(),
        OwnedTarget {
            target: 0,
            adapter,
            window: empty_window("owned-window".into()),
            elements: BTreeMap::new(),
            output: directory.clone(),
        },
    );
    let error = router
        .invoke_operator_lifecycle(
            &json!({"action":"close","session_id":"synthetic-session","generation":1}),
        )
        .unwrap_err();
    assert_eq!(
        error.details["receipt"]["normal_close"]["Err"]["code"],
        "ACTIVITY_INVALID"
    );
    assert_ne!(error.details["receipt"]["status"], "NORMAL_EXIT_VERIFIED");
    let before = calls.borrow().events.clone();
    assert_eq!(
        before.iter().filter(|event| **event == "cleanup").count(),
        1
    );
    assert!(
        router
            .invoke_operator_lifecycle(
                &json!({"action":"close","session_id":"synthetic-session","generation":1})
            )
            .is_err()
    );
    drop(router);
    assert_eq!(calls.borrow().events, before);
    assert_eq!(
        calls
            .borrow()
            .requests
            .iter()
            .filter(|(route, _)| route.starts_with("/quit"))
            .count(),
        0
    );
    let raw: Value =
        serde_json::from_slice(&std::fs::read(directory.join("mcp-session-close.json")).unwrap())
            .unwrap();
    assert_eq!(
        raw["normal_close"],
        error.details["receipt"]["normal_close"]
    );
    std::fs::remove_file(directory.join("mcp-session-close.json")).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

impl MockPlatform {
    fn new() -> (Self, Rc<RefCell<Calls>>) {
        let calls = Rc::new(RefCell::new(Calls::default()));
        (
            Self {
                binding: SessionBinding {
                    session_id: "synthetic-session".into(),
                    owner: "synthetic-owner".into(),
                    generation: 1,
                    pid: 42,
                    process_birth: "synthetic-birth".into(),
                    executable: "mock-only.exe".into(),
                    executable_sha256: "a".repeat(64),
                    source_commit: PINNED_SOURCE.into(),
                    window_id: 7,
                    platform: "pure-mock-not-native".into(),
                },
                calls: Rc::clone(&calls),
                cancel_on_acquire: None,
                fail_release: false,
                fail_request: false,
            },
            calls,
        )
    }

    fn record(&self, event: &'static str) {
        self.calls.borrow_mut().events.push(event);
    }
}

impl RemotePlatform for MockPlatform {
    fn binding(&self) -> &SessionBinding {
        &self.binding
    }
    fn validate(&mut self) -> Result<()> {
        self.record("validate");
        Ok(())
    }
    fn request(&mut self, target: &str, mutating: bool) -> Result<Value> {
        self.calls
            .borrow_mut()
            .requests
            .push((target.into(), mutating));
        if self.fail_request {
            Err(RemoteError::unknown("MOCK_REMOTE_OUTCOME_UNKNOWN"))
        } else {
            Ok(json!({"mock_only":true}))
        }
    }
    fn acquire_input(&mut self) -> Result<String> {
        self.record("acquire");
        if let Some(control) = &self.cancel_on_acquire {
            control.cancel();
        }
        Ok("mock-lease".into())
    }
    fn validate_input(&mut self, token: &str) -> Result<()> {
        self.record("validate_input");
        if token == "mock-lease" {
            Ok(())
        } else {
            Err(RemoteError::refused("MOCK_FOREIGN_LEASE"))
        }
    }
    fn release_input(&mut self, token: &str) -> Result<()> {
        self.calls.borrow_mut().releases.push(token.into());
        if self.fail_release {
            Err(RemoteError::refused("MOCK_RELEASE_FAILED"))
        } else {
            Ok(())
        }
    }
    fn copy_native_frame(&mut self, metadata: &Value, _dispatched_ms: u64) -> Result<Value> {
        self.record("frame");
        Ok(metadata.clone())
    }
    fn reap_normal_exit(&mut self) -> Result<Value> {
        self.record("reap");
        Ok(json!({"mock_only":true}))
    }
    fn cleanup_owned_resources(&mut self) -> Result<Value> {
        self.record("cleanup");
        Ok(json!({"mock_only":true}))
    }
    fn observe_key_focus(&mut self, _window: u64, _widget: &str) -> Result<bool> {
        self.record("focus_observation");
        Ok(false)
    }
    fn read_runtime_stderr(&mut self) -> Result<Value> {
        self.record("stderr");
        Ok(json!({"mock_only":true}))
    }
    fn host_window_identity(&mut self) -> Result<(u64, u32, u64)> {
        self.record("host_identity");
        Ok((17, 23, 29))
    }
}

fn controlled(mock: MockPlatform, control: Option<RequestControl>) -> ControlledPlatform {
    ControlledPlatform {
        inner: Box::new(mock),
        control: Rc::new(RefCell::new(control)),
    }
}

fn assert_remote_refusal(error: RemoteError, code: &str) {
    assert_eq!(error.code, code);
    assert_eq!(error.outcome, "NOT_DISPATCHED");
    assert!(!error.retry_safe);
}

#[test]
fn adapter_rejects_foreign_session_owner_window_and_changed_generation_before_io() {
    let (mock, calls) = MockPlatform::new();
    let mut adapter = MakepadRemoteAdapter::from_trusted_platform(mock).unwrap();
    assert_eq!(calls.borrow().events, ["validate"]);
    for (session, owner, window, code) in [
        ("foreign-session", "synthetic-owner", 7, "UNKNOWN_SESSION"),
        (
            "synthetic-session",
            "foreign-owner",
            7,
            "FOREIGN_SESSION_OWNER",
        ),
        ("synthetic-session", "synthetic-owner", 8, "WRONG_WINDOW_ID"),
    ] {
        assert_remote_refusal(adapter.authorize(session, owner, window).unwrap_err(), code);
        assert_eq!(calls.borrow().events, ["validate"]);
        assert!(calls.borrow().requests.is_empty());
    }
    adapter
        .authorize("synthetic-session", "synthetic-owner", 7)
        .unwrap();
    assert_eq!(calls.borrow().events, ["validate", "validate"]);
    adapter.platform.binding.generation += 1;
    assert_remote_refusal(
        adapter
            .authorize("synthetic-session", "synthetic-owner", 7)
            .unwrap_err(),
        "SESSION_GENERATION_CHANGED",
    );
    assert_eq!(calls.borrow().events, ["validate", "validate"]);
}

#[test]
fn controlled_platform_without_control_delegates_each_boundary_once() {
    let (mock, calls) = MockPlatform::new();
    let mut platform = controlled(mock, None);
    assert_eq!(platform.binding().owner, "synthetic-owner");
    platform.validate().unwrap();
    platform.request("/s", false).unwrap();
    platform.request("/t?mock=1", true).unwrap();
    let token = platform.acquire_input().unwrap();
    platform.validate_input(&token).unwrap();
    platform.release_input(&token).unwrap();
    assert_eq!(
        calls.borrow().events,
        ["validate", "acquire", "validate_input"]
    );
    assert_eq!(
        calls.borrow().requests,
        [("/s".to_owned(), false), ("/t?mock=1".to_owned(), true)]
    );
    assert_eq!(calls.borrow().releases, ["mock-lease"]);
}

#[test]
fn cancelled_control_blocks_mutation_acquisition_and_lease_validation_before_delegate() {
    let control = RequestControl::new(Duration::from_secs(3600));
    control.cancel();
    let (mock, calls) = MockPlatform::new();
    let mut platform = controlled(mock, Some(control));
    assert_remote_refusal(
        platform.request("/t?mock=1", true).unwrap_err(),
        "REQUEST_CANCELLED",
    );
    assert_remote_refusal(platform.acquire_input().unwrap_err(), "REQUEST_CANCELLED");
    assert_remote_refusal(
        platform.validate_input("mock-lease").unwrap_err(),
        "REQUEST_CANCELLED",
    );
    assert!(calls.borrow().events.is_empty());
    assert!(calls.borrow().requests.is_empty());
    assert!(calls.borrow().releases.is_empty());
}

#[test]
fn zero_deadline_refuses_without_sleep_or_environment_dependency() {
    let (mock, calls) = MockPlatform::new();
    let mut platform = controlled(mock, Some(RequestControl::new(Duration::ZERO)));
    assert_remote_refusal(
        platform.request("/t?mock=1", true).unwrap_err(),
        "REQUEST_DEADLINE_EXCEEDED",
    );
    assert_remote_refusal(
        platform.acquire_input().unwrap_err(),
        "REQUEST_DEADLINE_EXCEEDED",
    );
    assert_remote_refusal(
        platform.validate_input("mock-lease").unwrap_err(),
        "REQUEST_DEADLINE_EXCEEDED",
    );
    assert!(calls.borrow().events.is_empty());
    assert!(calls.borrow().requests.is_empty());
}

#[test]
fn cancellation_during_acquisition_releases_exact_new_token_and_never_returns_it() {
    let control = RequestControl::new(Duration::from_secs(3600));
    let (mut mock, calls) = MockPlatform::new();
    mock.cancel_on_acquire = Some(control.clone());
    let mut platform = controlled(mock, Some(control));
    assert_remote_refusal(platform.acquire_input().unwrap_err(), "REQUEST_CANCELLED");
    assert_eq!(calls.borrow().events, ["acquire"]);
    assert_eq!(calls.borrow().releases, ["mock-lease"]);
    assert!(calls.borrow().requests.is_empty());
}

#[test]
fn cancelled_acquisition_preserves_release_failure_without_replay() {
    let control = RequestControl::new(Duration::from_secs(3600));
    let (mut mock, calls) = MockPlatform::new();
    mock.cancel_on_acquire = Some(control.clone());
    mock.fail_release = true;
    let mut platform = controlled(mock, Some(control));
    let error = platform.acquire_input().unwrap_err();
    assert_eq!(
        error.details["lease_cleanup_error"]["code"],
        "MOCK_RELEASE_FAILED"
    );
    assert_remote_refusal(error, "REQUEST_CANCELLED");
    assert_eq!(calls.borrow().events, ["acquire"]);
    assert_eq!(calls.borrow().releases, ["mock-lease"]);
    assert!(calls.borrow().requests.is_empty());
}

#[test]
fn shared_control_replacement_is_observed_at_the_next_mutation_boundary() {
    let (mock, calls) = MockPlatform::new();
    let mut platform = controlled(mock, None);
    platform.request("/t?before=1", true).unwrap();
    let control = RequestControl::new(Duration::from_secs(3600));
    control.cancel();
    *platform.control.borrow_mut() = Some(control);
    assert_remote_refusal(
        platform.request("/t?cancelled=1", true).unwrap_err(),
        "REQUEST_CANCELLED",
    );
    *platform.control.borrow_mut() = None;
    platform.request("/t?after=1", true).unwrap();
    assert_eq!(
        calls.borrow().requests,
        [
            ("/t?before=1".to_owned(), true),
            ("/t?after=1".to_owned(), true)
        ]
    );
}

#[test]
fn cancellation_does_not_gate_read_observation_or_owned_cleanup_delegation() {
    let control = RequestControl::new(Duration::from_secs(3600));
    control.cancel();
    let (mock, calls) = MockPlatform::new();
    let mut platform = controlled(mock, Some(control));
    platform.validate().unwrap();
    platform.request("/s", false).unwrap();
    platform.release_input("mock-lease").unwrap();
    assert_eq!(
        platform
            .copy_native_frame(&json!({"mock_only":true}), 0)
            .unwrap(),
        json!({"mock_only":true})
    );
    assert!(!platform.observe_key_focus(7, "body.editor").unwrap());
    assert_eq!(platform.host_window_identity().unwrap(), (17, 23, 29));
    platform.read_runtime_stderr().unwrap();
    platform.reap_normal_exit().unwrap();
    platform.cleanup_owned_resources().unwrap();
    assert_eq!(
        calls.borrow().events,
        [
            "validate",
            "frame",
            "focus_observation",
            "host_identity",
            "stderr",
            "reap",
            "cleanup"
        ]
    );
    assert_eq!(calls.borrow().requests, [("/s".to_owned(), false)]);
    assert_eq!(calls.borrow().releases, ["mock-lease"]);
}

#[test]
fn controlled_remote_error_is_forwarded_once_without_retry() {
    let (mut mock, calls) = MockPlatform::new();
    mock.fail_request = true;
    let mut platform = controlled(mock, None);
    let error = platform.request("/t?mock=1", true).unwrap_err();
    assert_eq!(error.code, "MOCK_REMOTE_OUTCOME_UNKNOWN");
    assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
    assert!(!error.retry_safe);
    assert_eq!(calls.borrow().requests, [("/t?mock=1".to_owned(), true)]);
    assert!(calls.borrow().events.is_empty());
}

#[test]
fn refusal_envelopes_preserve_no_fallback_and_no_semantic_set_value_claim() {
    // These are pure envelope assertions, not dispatch_owned/native HWND proof.
    for (remote, code, outcome) in [
        (
            RemoteError::refused("MOCK_REFUSED"),
            ErrorCode::PermissionDenied,
            "NOT_DISPATCHED",
        ),
        (
            RemoteError::unknown("MOCK_UNCERTAIN"),
            ErrorCode::InvocationFailed,
            "OUTCOME_UNKNOWN",
        ),
    ] {
        let error = remote_error(remote);
        assert_eq!(error.code, code);
        assert_eq!(error.details["backend"], "MakepadRemoteAdapter");
        assert_eq!(error.details["fallback_used"], false);
        assert_eq!(error.details["remote_error"]["outcome"], outcome);
        assert_eq!(error.details["remote_error"]["retry_safe"], false);
    }
    let error = unsupported("UNSUPPORTED_SEMANTIC_SET_VALUE");
    assert_eq!(error.code, ErrorCode::ActionNotSupported);
    assert_eq!(
        error.details["remote_code"],
        "UNSUPPORTED_SEMANTIC_SET_VALUE"
    );
    assert_eq!(error.details["outcome"], "NOT_DISPATCHED");
    assert_eq!(error.details["retry_safe"], false);
    assert_eq!(error.details["fallback_used"], false);
}

// Virtual monotonic cost, not sleeps or a mock native acceptance claim. Each
// real adapter request/focus observation costs 2300ms; the actual router helper
// must finish/release inside the unchanged 30s lease before public projection.
#[derive(Default)]
struct ActionLedger {
    elapsed_ms: u64,
    deadline_ms: u64,
    released_ms: u64,
    held: bool,
    releases: usize,
    dispatches: usize,
    value: String,
    selected: bool,
    fail_release: bool,
    expire_after_dispatch: bool,
    lose_focus: bool,
    unknown_dispatch: bool,
    wrong_readback: bool,
    requests: Vec<String>,
}
struct ActionPlatform {
    binding: SessionBinding,
    ledger: Rc<RefCell<ActionLedger>>,
}
impl ActionPlatform {
    fn new(value: &str) -> (Self, Rc<RefCell<ActionLedger>>) {
        let mut binding = MockPlatform::new().0.binding;
        binding.pid = 23;
        let ledger = Rc::new(RefCell::new(ActionLedger {
            value: value.into(),
            ..Default::default()
        }));
        (
            Self {
                binding,
                ledger: Rc::clone(&ledger),
            },
            ledger,
        )
    }
}
impl RemotePlatform for ActionPlatform {
    fn binding(&self) -> &SessionBinding {
        &self.binding
    }
    fn validate(&mut self) -> Result<()> {
        Ok(())
    }
    fn request(&mut self, route: &str, mutating: bool) -> Result<Value> {
        let mut state = self.ledger.borrow_mut();
        state.elapsed_ms += 2300;
        state.requests.push(route.into());
        if mutating {
            state.dispatches += 1;
            if route.starts_with("/t?") {
                state.value = if route.contains("t=ALPHA") {
                    "ALPHA"
                } else {
                    "BRAVO"
                }
                .into();
            }
            if route.contains("c=KeyA") {
                state.selected = true;
            }
            if route.contains("c=Backspace") && state.selected {
                state.value.clear();
                state.selected = false;
            }
            if state.expire_after_dispatch {
                state.elapsed_ms = state.deadline_ms + 1;
            }
            if state.unknown_dispatch {
                return Err(RemoteError::unknown("MOCK_DISPATCH_OUTCOME_UNKNOWN"));
            }
            return Ok(json!({"ok":1}));
        }
        if route == "/activity" {
            return Ok(json!({"user_seq":0,"user_active":false,"held":false}));
        }
        if route == "/s" {
            return Ok(json!({"pid":self.binding.pid,"w":[{"i":self.binding.window_id}]}));
        }
        if route.starts_with("/snap?") {
            let value = if state.wrong_readback && state.dispatches > 0 {
                "MISMATCH"
            } else {
                &state.value
            };
            return Ok(
                json!({"s":[{"i":"body.editor","w":self.binding.window_id,"ty":"TextInput",
                "val":value,"enabled":true,"r":[1,2,100,30]}]}),
            );
        }
        Err(RemoteError::refused("MOCK_UNEXPECTED_ROUTE"))
    }
    fn acquire_input(&mut self) -> Result<String> {
        let mut state = self.ledger.borrow_mut();
        assert!(!state.held);
        state.held = true;
        state.deadline_ms = state.elapsed_ms + 30000;
        Ok("action-lease".into())
    }
    fn validate_input(&mut self, token: &str) -> Result<()> {
        let state = self.ledger.borrow();
        if token != "action-lease" || !state.held || state.elapsed_ms >= state.deadline_ms {
            Err(RemoteError::refused("STALE_LEASE"))
        } else {
            Ok(())
        }
    }
    fn release_input(&mut self, token: &str) -> Result<()> {
        self.validate_input(token)?;
        let mut state = self.ledger.borrow_mut();
        if state.fail_release {
            return Err(RemoteError::refused("MOCK_RELEASE_FAILED"));
        }
        state.held = false;
        state.releases += 1;
        state.released_ms = state.elapsed_ms;
        Ok(())
    }
    fn observe_key_focus(&mut self, _window: u64, _widget: &str) -> Result<bool> {
        let mut state = self.ledger.borrow_mut();
        state.elapsed_ms += 2300;
        Ok(!(state.lose_focus && state.dispatches > 0))
    }
    fn copy_native_frame(&mut self, _: &Value, _: u64) -> Result<Value> {
        unreachable!("no capture in pure input test")
    }
    fn reap_normal_exit(&mut self) -> Result<Value> {
        unreachable!("no runtime in pure input test")
    }
    fn cleanup_owned_resources(&mut self) -> Result<Value> {
        Ok(json!({"mock_only":true}))
    }
    fn read_runtime_stderr(&mut self) -> Result<Value> {
        unreachable!("no runtime in pure input test")
    }
    fn host_window_identity(&mut self) -> Result<(u64, u32, u64)> {
        unreachable!("no native window in pure input test")
    }
}

#[test]
fn verified_input_action_releases_before_slow_public_projection_without_extending_lease() {
    for plan in [
        Some(RemoteKeys::Key("Backspace", false)),
        Some(RemoteKeys::Key("KeyA", true)),
        Some(RemoteKeys::Text("ALPHA")),
        None,
    ] {
        let (platform, ledger) = ActionPlatform::new("");
        let mut adapter = MakepadRemoteAdapter::from_trusted_platform(platform).unwrap();
        let action = verified_input_action(
            &mut adapter,
            "synthetic-session",
            7,
            "body.editor",
            plan.as_ref(),
        )
        .unwrap();
        assert!(verified_action_parts(&action, "body.editor", 7, 23).is_ok());
        {
            let state = ledger.borrow();
            assert_eq!(state.releases, 1);
            assert!(!state.held);
            assert!(state.released_ms < state.deadline_ms);
            assert_eq!(state.dispatches, 1);
        }
        // The legacy duplicate public read sequence would cross the deadline.
        // Here it happens AFTER release and cannot turn the verified action into
        // STALE_LEASE. Production projects its existing data without these IOs.
        adapter
            .find_widget("synthetic-session", 7, "body.editor")
            .unwrap();
        adapter
            .observe_key_focus("synthetic-session", "body.editor")
            .unwrap();
        adapter.inspect_window("synthetic-session").unwrap();
        let state = ledger.borrow();
        assert!(state.elapsed_ms >= state.deadline_ms);
        assert_eq!(state.releases, 1);
        assert_eq!(state.dispatches, 1);
        assert!(!state.held);
    }
}

#[test]
fn verified_input_action_ctrl_a_backspace_bravo_has_real_adapter_readbacks_and_exact_release_order()
{
    let (platform, ledger) = ActionPlatform::new("ALPHA");
    let mut adapter = MakepadRemoteAdapter::from_trusted_platform(platform).unwrap();
    for (plan, expected) in [
        (RemoteKeys::Key("KeyA", true), "ALPHA"),
        (RemoteKeys::Key("Backspace", false), ""),
        (RemoteKeys::Text("BRAVO"), "BRAVO"),
    ] {
        let action = verified_input_action(
            &mut adapter,
            "synthetic-session",
            7,
            "body.editor",
            Some(&plan),
        )
        .unwrap();
        let (row, _) = verified_action_parts(&action, "body.editor", 7, 23).unwrap();
        assert_eq!(row["val"], expected);
        assert!(!ledger.borrow().held);
    }
    let state = ledger.borrow();
    assert_eq!(state.value, "BRAVO");
    assert_eq!(state.dispatches, 3);
    assert_eq!(state.releases, 3);
}

#[test]
fn verified_input_action_genuine_expiry_is_unknown_fenced_and_not_retried() {
    let (platform, ledger) = ActionPlatform::new("ALPHA");
    ledger.borrow_mut().expire_after_dispatch = true;
    let mut adapter = MakepadRemoteAdapter::from_trusted_platform(platform).unwrap();
    let error = verified_input_action(
        &mut adapter,
        "synthetic-session",
        7,
        "body.editor",
        Some(&RemoteKeys::Key("Backspace", false)),
    )
    .unwrap_err();
    assert_eq!(error.details["outcome"], "OUTCOME_UNKNOWN");
    assert_eq!(error.details["retry_safe"], false);
    assert_eq!(
        error.details["cause"]["details"]["remote_error"]["code"],
        "STALE_LEASE"
    );
    assert_eq!(ledger.borrow().dispatches, 1);
    assert_eq!(ledger.borrow().releases, 0);
    assert!(adapter.acquire_input("synthetic-session").is_err());
    assert_eq!(ledger.borrow().dispatches, 1);
}

#[test]
fn verified_input_action_focus_or_value_failure_never_becomes_pass_and_releases_once() {
    for focus_failure in [true, false] {
        let (platform, ledger) = ActionPlatform::new("");
        if focus_failure {
            ledger.borrow_mut().lose_focus = true;
        } else {
            ledger.borrow_mut().wrong_readback = true;
        }
        let mut adapter = MakepadRemoteAdapter::from_trusted_platform(platform).unwrap();
        let error = verified_input_action(
            &mut adapter,
            "synthetic-session",
            7,
            "body.editor",
            Some(&RemoteKeys::Text("ALPHA")),
        )
        .unwrap_err();
        assert_eq!(error.details["remote_error"]["outcome"], "OUTCOME_UNKNOWN");
        assert_eq!(error.details["remote_error"]["retry_safe"], false);
        assert_eq!(ledger.borrow().dispatches, 1);
        assert_eq!(ledger.borrow().releases, 1);
        assert!(!ledger.borrow().held);
        assert_eq!(
            adapter.acquire_input("synthetic-session").unwrap_err().code,
            "REMOTE_SEQUENCE_FENCED"
        );
    }
}

#[test]
fn verified_input_action_release_failure_and_unknown_dispatch_preserve_original_typed_failure() {
    for unknown in [false, true] {
        let (platform, ledger) = ActionPlatform::new("ALPHA");
        ledger.borrow_mut().fail_release = true;
        ledger.borrow_mut().unknown_dispatch = unknown;
        let mut adapter = MakepadRemoteAdapter::from_trusted_platform(platform).unwrap();
        let error = verified_input_action(
            &mut adapter,
            "synthetic-session",
            7,
            "body.editor",
            Some(&RemoteKeys::Key("KeyA", true)),
        )
        .unwrap_err();
        if unknown {
            assert_eq!(
                error.details["remote_error"]["code"],
                "MOCK_DISPATCH_OUTCOME_UNKNOWN"
            );
            assert_eq!(
                error.details["lease_cleanup_error"]["details"]["remote_error"]["code"],
                "MOCK_RELEASE_FAILED"
            );
        } else {
            assert_eq!(error.details["outcome"], "OUTCOME_UNKNOWN");
        }
        assert_eq!(ledger.borrow().dispatches, 1);
        assert_eq!(ledger.borrow().releases, 0);
    }
}

#[test]
fn verified_action_parts_rejects_cross_widget_window_pid_missing_focus_or_health() {
    let action = json!({"readback":{"i":"body.editor","w":7,"ty":"TextInput"},
        "runtime":{"pid":23,"w":[{"i":7}]},"key_focus_verified":true});
    assert!(verified_action_parts(&action, "body.editor", 7, 23).is_ok());
    for (pointer, replacement) in [
        ("/readback/i", json!("foreign")),
        ("/readback/w", json!(8)),
        ("/runtime/pid", json!(24)),
        ("/runtime/w", json!([])),
        ("/runtime/w", json!([{"i":7},{"i":7}])),
        ("/key_focus_verified", json!(false)),
        ("/key_focus_verified", Value::Null),
        ("/runtime", Value::Null),
    ] {
        let mut bad = action.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            verified_action_parts(&bad, "body.editor", 7, 23).is_err(),
            "{pointer}"
        );
    }
}

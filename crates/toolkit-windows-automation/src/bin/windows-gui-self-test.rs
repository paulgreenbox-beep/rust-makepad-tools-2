#[cfg(not(windows))]
fn main() {
    eprintln!("windows-gui-self-test is available only on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    if let Err(error) = self_test::run() {
        eprintln!("Windows GUI self-test failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod self_test {
    use serde_json::{Value, json};
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};
    use std::thread;
    use std::time::{Duration, Instant};
    use toolkit_windows_automation::{AutomationError, ErrorCode, GuiToolRegistry, now_unix_ms};

    pub fn run() -> Result<(), Box<dyn Error>> {
        let output_dir = argument_path("--output-dir").unwrap_or_else(|| {
            PathBuf::from("reports")
                .join("evidence")
                .join("windows-gui-self-test")
        });
        fs::create_dir_all(&output_dir)?;
        let fixture = argument_path("--fixture").unwrap_or_else(default_fixture_path);
        if !fixture.is_file() {
            return Err(format!(
                "fixture executable not found at {}; build package bins first",
                fixture.display()
            )
            .into());
        }

        let title = format!(
            "Toolkit Windows GUI Self-Test {} {}",
            std::process::id(),
            now_unix_ms()
        );
        eprintln!("self-test: spawn first fixture");
        let mut first = ChildGuard::spawn(&fixture, &title)?;
        eprintln!("self-test: initialize registry");
        let mut registry = GuiToolRegistry::new()?;

        let missing = registry.invoke(
            "windows_find_window",
            json!({"title": format!("{title} missing")}),
        );
        require_error(&missing, ErrorCode::WindowNotFound)?;

        eprintln!("self-test: resolve first window");
        let window = retry_call(
            &mut registry,
            "windows_find_window",
            json!({"process_id": first.id(), "title": title.clone()}),
            Duration::from_secs(8),
        )?;
        let window_id = string(&window, "window_id")?.to_owned();

        eprintln!("self-test: spawn ambiguous second fixture");
        let mut second = ChildGuard::spawn(&fixture, &title)?;
        retry_call(
            &mut registry,
            "windows_find_window",
            json!({"process_id": second.id(), "title": title.clone()}),
            Duration::from_secs(8),
        )?;
        let ambiguous_window = registry.invoke("windows_find_window", json!({"title": title}));
        require_error(&ambiguous_window, ErrorCode::AmbiguousWindow)?;
        second.terminate();

        eprintln!("self-test: enumerate control tree");
        let tree = call(
            &mut registry,
            "windows_get_control_tree",
            json!({"window_id": window_id, "view": "control"}),
        )?;
        let total_elements = tree["total_enumerated"].as_u64().unwrap_or(0);
        eprintln!("self-test: control tree elements={total_elements}");
        if total_elements < 8 {
            return Err(format!(
                "fixture exposed only {total_elements} UIA elements; expected standard controls"
            )
            .into());
        }
        fs::write(
            output_dir.join("control-tree.json"),
            serde_json::to_vec_pretty(&tree)?,
        )?;

        let ambiguous_element = registry.invoke(
            "windows_find_control",
            json!({
                "window_id": window_id,
                "name": "Duplicate",
                "control_type": "Button"
            }),
        );
        require_error(&ambiguous_element, ErrorCode::AmbiguousElement)?;

        let duplicate_b = call(
            &mut registry,
            "windows_find_control",
            json!({
                "window_id": window_id,
                "name": "Duplicate",
                "control_type": "Button",
                "index": 1
            }),
        )?;
        if string(&duplicate_b, "element_id")?.is_empty() {
            return Err("indexed element resolution returned an empty element_id".into());
        }

        let status = find_control(
            &mut registry,
            &window_id,
            json!({"name": "Count: 0", "control_type": "Text"}),
        )?;
        let status_id = string(&status, "element_id")?.to_owned();
        let increment = find_control(
            &mut registry,
            &window_id,
            json!({"name": "Increment", "control_type": "Button"}),
        )?;
        call(
            &mut registry,
            "windows_click_element",
            json!({
                "window_id": window_id,
                "element_id": string(&increment, "element_id")?
            }),
        )?;
        let changed_status = retry_element_name(
            &mut registry,
            &window_id,
            &status_id,
            "Count: 1",
            Duration::from_secs(3),
        )?;
        if changed_status["name"] != "Count: 1" {
            return Err("ID-addressed Invoke did not update fixture state".into());
        }

        let transient = find_control(
            &mut registry,
            &window_id,
            json!({"name": "Transient control", "control_type": "Text"}),
        )?;
        let transient_id = string(&transient, "element_id")?.to_owned();
        let remove = find_control(
            &mut registry,
            &window_id,
            json!({"name": "Remove transient", "control_type": "Button"}),
        )?;
        call(
            &mut registry,
            "windows_click_element",
            json!({
                "window_id": window_id,
                "element_id": string(&remove, "element_id")?
            }),
        )?;
        let stale = registry.invoke(
            "windows_get_element_state",
            json!({"window_id": window_id, "element_id": transient_id}),
        );
        require_error(&stale, ErrorCode::StaleElement)?;

        let edit = find_control(&mut registry, &window_id, json!({"control_type": "Edit"}))?;
        let edit_id = string(&edit, "element_id")?.to_owned();
        call(
            &mut registry,
            "windows_click_element",
            json!({"window_id": window_id, "element_id": edit_id}),
        )?;
        call(
            &mut registry,
            "windows_send_keys",
            json!({"window_id": window_id, "keys": "CTRL+A"}),
        )?;
        call(
            &mut registry,
            "windows_send_keys",
            json!({"window_id": window_id, "keys": "typed by toolkit"}),
        )?;
        let edit_state = retry_element_value(
            &mut registry,
            &window_id,
            &edit_id,
            "typed by toolkit",
            Duration::from_secs(3),
        )?;

        call(
            &mut registry,
            "windows_send_keys",
            json!({"window_id": window_id, "keys": "CTRL+TAB"}),
        )?;
        call(
            &mut registry,
            "windows_send_keys",
            json!({"window_id": window_id, "keys": "CTRL+SHIFT+TAB"}),
        )?;
        call(
            &mut registry,
            "windows_send_keys",
            json!({"window_id": window_id, "keys": "CTRL+W"}),
        )?;

        let sizes = [
            ("large", 900, 650),
            ("medium", 700, 500),
            ("narrow", 480, 560),
        ];
        let mut captures = Vec::new();
        for (label, width, height) in sizes {
            let resized = call(
                &mut registry,
                "windows_set_window_bounds",
                json!({
                    "window_id": window_id,
                    "width": width,
                    "height": height
                }),
            )?;
            if resized["actual_bounds"]["width"].as_i64().unwrap_or(0) <= 0
                || resized["actual_bounds"]["height"].as_i64().unwrap_or(0) <= 0
            {
                return Err(format!("{label} resize produced invalid bounds").into());
            }
            let screenshot = output_dir.join(format!("self-test-{label}.png"));
            let captured = call(
                &mut registry,
                "windows_capture_window",
                json!({
                    "window_id": window_id,
                    "output_path": screenshot
                }),
            )?;
            if !Path::new(string(&captured, "path")?).is_file() {
                return Err(format!("{label} screenshot artifact was not created").into());
            }
            captures.push(captured);
        }

        let exit = find_control(
            &mut registry,
            &window_id,
            json!({"name": "Exit fixture", "control_type": "Button"}),
        )?;
        call(
            &mut registry,
            "windows_click_element",
            json!({
                "window_id": window_id,
                "element_id": string(&exit, "element_id")?
            }),
        )?;
        if !first.wait_for_exit(Duration::from_secs(5)) {
            return Err("fixture did not exit after ID-addressed close-like button".into());
        }
        let closed_window =
            registry.invoke("windows_focus_window", json!({"window_id": window_id}));
        require_error(&closed_window, ErrorCode::WindowNotFound)?;

        let evidence_path = output_dir.join("evidence.json");
        registry.export_evidence(&evidence_path)?;
        let summary = json!({
            "status": "WINDOWS_GUI_AUTOMATION_SELF_TEST_PASSED",
            "fixture": fixture,
            "window_id": window_id,
            "control_tree_elements": total_elements,
            "increment_state": changed_status,
            "edit_state": edit_state,
            "captures": captures,
            "evidence_path": evidence_path,
            "checks": {
                "window_not_found": true,
                "ambiguous_window": true,
                "control_enumeration": true,
                "ambiguous_element": true,
                "indexed_secondary_discriminator": true,
                "invoke_by_element_id": true,
                "stale_element": true,
                "keyboard_window_binding": true,
                "required_chords_injected": true,
                "large_medium_narrow_resize": true,
                "target_window_png": true,
                "closed_window_rejected": true
            }
        });
        fs::write(
            output_dir.join("summary.json"),
            serde_json::to_vec_pretty(&summary)?,
        )?;
        println!("{}", serde_json::to_string(&summary)?);
        Ok(())
    }

    fn find_control(
        registry: &mut GuiToolRegistry,
        window_id: &str,
        query: Value,
    ) -> Result<Value, Box<dyn Error>> {
        let mut object = query.as_object().cloned().unwrap_or_default();
        object.insert("window_id".into(), Value::String(window_id.to_owned()));
        call(registry, "windows_find_control", Value::Object(object))
    }

    fn retry_element_name(
        registry: &mut GuiToolRegistry,
        window_id: &str,
        element_id: &str,
        expected: &str,
        timeout: Duration,
    ) -> Result<Value, Box<dyn Error>> {
        retry_state(registry, window_id, element_id, timeout, |state| {
            state["name"] == expected
        })
    }

    fn retry_element_value(
        registry: &mut GuiToolRegistry,
        window_id: &str,
        element_id: &str,
        expected: &str,
        timeout: Duration,
    ) -> Result<Value, Box<dyn Error>> {
        retry_state(registry, window_id, element_id, timeout, |state| {
            state["value"] == expected
        })
    }

    fn retry_state(
        registry: &mut GuiToolRegistry,
        window_id: &str,
        element_id: &str,
        timeout: Duration,
        predicate: impl Fn(&Value) -> bool,
    ) -> Result<Value, Box<dyn Error>> {
        let deadline = Instant::now() + timeout;
        loop {
            let state = call(
                registry,
                "windows_get_element_state",
                json!({"window_id": window_id, "element_id": element_id}),
            )?;
            if predicate(&state) {
                return Ok(state);
            }
            if Instant::now() >= deadline {
                return Err(format!("element state did not reach expected value: {state}").into());
            }
            thread::sleep(Duration::from_millis(80));
        }
    }

    fn retry_call(
        registry: &mut GuiToolRegistry,
        tool: &str,
        arguments: Value,
        timeout: Duration,
    ) -> Result<Value, Box<dyn Error>> {
        let deadline = Instant::now() + timeout;
        loop {
            let envelope = registry.invoke(tool, arguments.clone());
            if envelope.ok {
                return Ok(envelope.result.unwrap_or(Value::Null));
            }
            if Instant::now() >= deadline {
                return Err(Box::new(envelope.error.unwrap_or_else(|| {
                    AutomationError::new(ErrorCode::BackendFailure, "tool failed without an error")
                })));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn call(
        registry: &mut GuiToolRegistry,
        tool: &str,
        arguments: Value,
    ) -> Result<Value, Box<dyn Error>> {
        let envelope = registry.invoke(tool, arguments);
        if envelope.ok {
            Ok(envelope.result.unwrap_or(Value::Null))
        } else {
            Err(Box::new(envelope.error.unwrap_or_else(|| {
                AutomationError::new(ErrorCode::BackendFailure, "tool failed without an error")
            })))
        }
    }

    fn require_error(
        envelope: &toolkit_windows_automation::ToolCallEnvelope,
        expected: ErrorCode,
    ) -> Result<(), Box<dyn Error>> {
        match &envelope.error {
            Some(error) if error.code == expected && !envelope.ok => Ok(()),
            Some(error) => Err(format!(
                "expected {expected:?}, received {:?}: {}",
                error.code, error.message
            )
            .into()),
            None => Err(format!("expected {expected:?}, tool unexpectedly succeeded").into()),
        }
    }

    fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, Box<dyn Error>> {
        value
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing string field {key} in {value}").into())
    }

    fn argument_path(flag: &str) -> Option<PathBuf> {
        let mut arguments = std::env::args();
        while let Some(argument) = arguments.next() {
            if argument == flag {
                return arguments.next().map(PathBuf::from);
            }
        }
        None
    }

    fn default_fixture_path() -> PathBuf {
        let mut path = std::env::current_exe().unwrap_or_default();
        path.set_file_name("windows-gui-self-test-fixture.exe");
        path
    }

    struct ChildGuard {
        child: Option<Child>,
    }

    impl ChildGuard {
        fn spawn(path: &Path, title: &str) -> Result<Self, Box<dyn Error>> {
            let child = Command::new(path).arg("--title").arg(title).spawn()?;
            Ok(Self { child: Some(child) })
        }

        fn id(&self) -> u32 {
            self.child.as_ref().map(Child::id).unwrap_or(0)
        }

        fn terminate(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        fn wait_for_exit(&mut self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            loop {
                let Some(child) = self.child.as_mut() else {
                    return true;
                };
                match child.try_wait() {
                    Ok(Some(_)) => {
                        self.child = None;
                        return true;
                    }
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(80));
                    }
                    _ => return false,
                }
            }
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            self.terminate();
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("windows-accessibility-bridge-smoke is available only on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
#[path = "windows-accessibility-bridge-smoke/consumer.rs"]
mod consumer;

#[cfg(windows)]
fn main() {
    if std::env::args().any(|arg| arg == "--consumer-pid") {
        if let Err(error) = consumer::run() {
            eprintln!("AI Revit native UIA proof failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(error) = smoke::run() {
        eprintln!("Makepad accessibility bridge smoke failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod smoke {
    use serde_json::json;
    use std::{
        error::Error,
        fs,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use toolkit_windows_automation::{
        ControlInfo, ControlQuery, ControlTreeOptions, ErrorCode, TreeView, WindowInfo,
        WindowQuery, WindowsAutomation,
    };

    const WINDOW_TITLE: &str = "Rust Makepad Toolkit - Accessibility Bridge";

    pub fn run() -> Result<(), Box<dyn Error>> {
        let demo = argument_path("--demo").unwrap_or_else(default_demo_path);
        let output_dir = argument_path("--output-dir").unwrap_or_else(|| {
            PathBuf::from("reports")
                .join("evidence")
                .join("makepad-accessibility-bridge-smoke")
        });
        if !demo.is_file() {
            return Err(format!(
                "Makepad demo executable not found at {}; build accessibility-bridge-demo first",
                demo.display()
            )
            .into());
        }
        fs::create_dir_all(&output_dir)?;

        let mut demo = ChildGuard::spawn(&demo)?;
        let mut automation = WindowsAutomation::new()?;
        let window = retry_window(&mut automation, demo.id(), Duration::from_secs(12))?;
        let tree = retry_tree(&mut automation, &window.window_id, Duration::from_secs(12))?;

        let toolbar = require_control(&tree.elements, "Controls", "ToolBar")?;
        let zoom_group = require_control(&tree.elements, "Zoom", "Group")?;
        let zoom_50 = require_control(&tree.elements, "50 percent", "RadioButton")?;
        let zoom_100 = require_control(&tree.elements, "100 percent", "RadioButton")?;
        let zoom_200 = require_control(&tree.elements, "200 percent", "RadioButton")?;
        let reset = require_control(&tree.elements, "Reset scroll", "Button")?;
        let preview = require_control(&tree.elements, "Virtual canvas preview", "Pane")?;

        for control in [
            toolbar, zoom_group, zoom_50, zoom_100, zoom_200, reset, preview,
        ] {
            if !control.bounds.is_actionable() {
                return Err(format!(
                    "{} exported non-actionable bounds: {:?}",
                    control.name, control.bounds
                )
                .into());
            }
        }
        if zoom_group.parent_element_id.as_ref() != Some(&toolbar.element_id)
            || zoom_200.parent_element_id.as_ref() != Some(&zoom_group.element_id)
        {
            return Err("UIA fragment parent/child relationships are incorrect".into());
        }
        if zoom_50.selected != Some(false)
            || zoom_100.selected != Some(true)
            || zoom_200.selected != Some(false)
        {
            return Err("initial zoom selection was not exported correctly".into());
        }
        if !reset.capabilities.invoke || !zoom_200.capabilities.select {
            return Err("Invoke or SelectionItem capability was not exported".into());
        }

        let reset_click = automation.click_element(&window.window_id, &reset.element_id)?;
        if reset_click.action_method != "InvokePattern" {
            return Err(format!(
                "reset used {}, expected InvokePattern",
                reset_click.action_method
            )
            .into());
        }
        let status_after_invoke = retry_control(
            &mut automation,
            &window.window_id,
            ControlQuery {
                name: Some("Zoom 100 percent; Reset invocations: 1".into()),
                control_type: Some("Text".into()),
                ..Default::default()
            },
            Duration::from_secs(5),
        )?;

        let zoom_click = automation.click_element(&window.window_id, &zoom_200.element_id)?;
        if zoom_click.action_method != "SelectionItem.Select" {
            return Err(format!(
                "zoom used {}, expected SelectionItem.Select",
                zoom_click.action_method
            )
            .into());
        }
        let selected_zoom = retry_selected(
            &mut automation,
            &window.window_id,
            &zoom_200.element_id,
            Duration::from_secs(5),
        )?;
        if selected_zoom.selected != Some(true) {
            return Err("SelectionItem.Select did not update selected state".into());
        }

        let final_tree = automation.get_control_tree(
            &window.window_id,
            &ControlTreeOptions {
                max_depth: Some(16),
                max_elements: Some(128),
                view: TreeView::Control,
                ..Default::default()
            },
        )?;
        let screenshot_path = output_dir.join("makepad-accessibility-bridge.png");
        let screenshot_path = screenshot_path.to_string_lossy().into_owned();
        let screenshot = automation.capture_window(&window.window_id, Some(&screenshot_path))?;
        fs::write(
            output_dir.join("control-tree.json"),
            serde_json::to_vec_pretty(&final_tree)?,
        )?;

        let summary = json!({
            "status": "MAKEPAD_ACCESSIBILITY_BRIDGE_SMOKE_PASSED",
            "window": window,
            "tree_elements": final_tree.total_enumerated,
            "invoke": {
                "method": reset_click.action_method,
                "status": status_after_invoke,
            },
            "selection": {
                "method": zoom_click.action_method,
                "selected": selected_zoom.selected,
            },
            "screenshot": screenshot,
            "checks": {
                "makepad_hwnd_provider": true,
                "fragment_tree": true,
                "roles_names_bounds": true,
                "stable_element_identity_after_updates": true,
                "invoke_pattern": true,
                "selection_item_pattern": true,
                "selection_state_update": true,
            }
        });
        fs::write(
            output_dir.join("summary.json"),
            serde_json::to_vec_pretty(&summary)?,
        )?;
        println!("{}", serde_json::to_string(&summary)?);

        demo.terminate();
        Ok(())
    }

    fn retry_window(
        automation: &mut WindowsAutomation,
        process_id: u32,
        timeout: Duration,
    ) -> Result<WindowInfo, Box<dyn Error>> {
        let deadline = Instant::now() + timeout;
        loop {
            match automation.find_window(&WindowQuery {
                process_id: Some(process_id),
                title: Some(WINDOW_TITLE.into()),
                ..Default::default()
            }) {
                Ok(window) => return Ok(window),
                Err(error)
                    if error.code == ErrorCode::WindowNotFound && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn retry_tree(
        automation: &mut WindowsAutomation,
        window_id: &str,
        timeout: Duration,
    ) -> Result<toolkit_windows_automation::ControlTreeResult, Box<dyn Error>> {
        let deadline = Instant::now() + timeout;
        loop {
            let tree = automation.get_control_tree(
                window_id,
                &ControlTreeOptions {
                    max_depth: Some(16),
                    max_elements: Some(128),
                    view: TreeView::Control,
                    ..Default::default()
                },
            )?;
            if tree
                .elements
                .iter()
                .any(|control| control.name == "Virtual canvas preview")
            {
                return Ok(tree);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "Makepad window exposed {} elements but not the semantic bridge tree",
                    tree.total_enumerated
                )
                .into());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn retry_control(
        automation: &mut WindowsAutomation,
        window_id: &str,
        query: ControlQuery,
        timeout: Duration,
    ) -> Result<ControlInfo, Box<dyn Error>> {
        let deadline = Instant::now() + timeout;
        loop {
            match automation.find_control(window_id, &query) {
                Ok(control) => return Ok(control),
                Err(error)
                    if error.code == ErrorCode::ElementNotFound && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(75));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn retry_selected(
        automation: &mut WindowsAutomation,
        window_id: &str,
        element_id: &str,
        timeout: Duration,
    ) -> Result<toolkit_windows_automation::ElementState, Box<dyn Error>> {
        let deadline = Instant::now() + timeout;
        loop {
            let state = automation.get_element_state(window_id, element_id)?;
            if state.selected == Some(true) {
                return Ok(state);
            }
            if Instant::now() >= deadline {
                return Err(format!("selected state did not update: {state:?}").into());
            }
            thread::sleep(Duration::from_millis(75));
        }
    }

    fn require_control<'a>(
        elements: &'a [ControlInfo],
        name: &str,
        control_type: &str,
    ) -> Result<&'a ControlInfo, Box<dyn Error>> {
        elements
            .iter()
            .find(|control| control.name == name && control.control_type == control_type)
            .ok_or_else(|| format!("missing UIA {control_type} named {name}").into())
    }

    fn argument_path(name: &str) -> Option<PathBuf> {
        let mut arguments = std::env::args_os();
        while let Some(argument) = arguments.next() {
            if argument == name {
                return arguments.next().map(PathBuf::from);
            }
        }
        None
    }

    fn default_demo_path() -> PathBuf {
        Path::new("target")
            .join("debug")
            .join("accessibility-bridge-demo.exe")
    }

    struct ChildGuard {
        child: Child,
    }

    impl ChildGuard {
        fn spawn(path: &Path) -> Result<Self, Box<dyn Error>> {
            let child = Command::new(path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()?;
            Ok(Self { child })
        }

        fn id(&self) -> u32 {
            self.child.id()
        }

        fn terminate(&mut self) {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            self.terminate();
        }
    }
}

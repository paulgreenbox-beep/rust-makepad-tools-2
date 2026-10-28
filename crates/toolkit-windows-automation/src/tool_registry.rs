use crate::contract::{
    AutomationError, AutomationResult, ControlQuery, ControlTreeOptions, ErrorCode, TreeView,
    WindowFrameTargetKind, WindowQuery, WindowState,
};
use crate::evidence::{EvidenceDraft, EvidenceEntry, EvidenceLog};
use crate::platform::WindowsAutomation;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Clone, Debug, Serialize)]
pub struct ToolDefinition {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCallEnvelope {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AutomationError>,
    pub evidence_sequence: u64,
}

pub(crate) struct DispatchSuccess {
    pub(crate) value: Value,
    pub(crate) method: Option<String>,
    pub(crate) state: Option<Value>,
    pub(crate) screenshot_path: Option<String>,
}

impl DispatchSuccess {
    pub(crate) fn value(value: impl Serialize, method: impl Into<String>) -> AutomationResult<Self> {
        Ok(Self {
            value: serde_json::to_value(value).map_err(serialization_error)?,
            method: Some(method.into()),
            state: None,
            screenshot_path: None,
        })
    }
}

pub struct GuiToolRegistry {
    // Drop owned Remote sessions BEFORE native COM/apartment teardown.
    #[cfg(all(windows, feature = "experimental-makepad-remote"))]
    remote: Option<crate::makepad_remote::mcp_router::McpRemoteRouter>,
    backend: WindowsAutomation,
    evidence: EvidenceLog,
    definitions: Vec<ToolDefinition>,
}

impl GuiToolRegistry {
    #[cfg(windows)]
    pub(crate) fn new_stdio_session() -> AutomationResult<Self> {
        let owner = crate::identity::SessionIds::new().window().map_err(|_| {
            AutomationError::new(ErrorCode::BackendFailure, "stdio owner identity exhausted")
        })?;
        let mut registry = Self::new()?;
        registry.backend.enable_desktop_arbiter_runtime("mcp-stdio", &owner, &owner)?;
        registry.backend.bind_desktop_arbiter_session(&owner)?;
        Ok(registry)
    }

    /// Internal transport lifecycle; the public 20-tool catalog is unchanged.
    pub(crate) fn finish_owned_sessions(&mut self, reason: &str) -> AutomationResult<Value> {
        #[cfg(windows)]
        self.set_request_control(None);
        #[cfg(all(windows, feature = "experimental-makepad-remote"))]
        if let Some(mut remote) = self.remote.take() {
            return remote.finish_owned_sessions(reason);
        }
        Ok(json!({"reason":reason,"closed_sessions":[]}))
    }

    pub(crate) fn invoke_operator_lifecycle(&mut self, metadata: &Value) -> AutomationResult<Value> {
        #[cfg(all(windows, feature = "experimental-makepad-remote"))]
        if let Some(remote) = self.remote.as_mut() {
            return remote.invoke_operator_lifecycle(metadata);
        }
        let _ = metadata;
        Err(AutomationError::new(ErrorCode::ActionNotSupported,
            "operator owner lifecycle requires an explicitly approved Remote configuration"))
    }

    pub fn new() -> AutomationResult<Self> {
        #[cfg(not(all(windows, feature = "experimental-makepad-remote")))]
        if std::env::var_os("TOOLKIT_MCP_BACKEND_CONFIG").is_some()
            || std::env::var_os("TOOLKIT_MCP_BACKEND_CONFIG_SHA256").is_some()
        {
            return Err(AutomationError::new(
                ErrorCode::PermissionDenied,
                "configured Remote routing requires a Windows feature-enabled MCP; UIA fallback is forbidden",
            ));
        }
        Ok(Self {
            #[cfg(all(windows, feature = "experimental-makepad-remote"))]
            remote: crate::makepad_remote::mcp_router::McpRemoteRouter::from_operator_environment()?,
            backend: WindowsAutomation::new()?,
            evidence: EvidenceLog::default(),
            definitions: tool_definitions(),
        })
    }

    pub fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }

    #[cfg(windows)]
    pub(crate) fn new_http_session(owner: &str) -> AutomationResult<Self> {
        let mut registry = Self::new()?;
        registry.evidence = EvidenceLog::new(64);
        registry.backend.enable_desktop_arbiter_runtime("mcp-http", owner, owner)?;
        registry.backend.bind_desktop_arbiter_session(owner)?;
        Ok(registry)
    }

    #[cfg(windows)]
    pub(crate) fn set_request_control(&mut self, control: Option<crate::request_control::RequestControl>) {
        #[cfg(feature = "experimental-makepad-remote")]
        if let Some(remote) = self.remote.as_mut() {
            remote.set_control(control.clone());
        }
        // A timed-out request still must release its native reservation. The
        // backend receives the unchanged dispatch deadline/cancellation, with
        // its pre-existing 60s reservation cap kept separate from that deadline.
        self.backend.set_request_control(control.map(|c|c.for_native_cleanup_reservation()));
    }

    pub fn evidence(&self) -> &EvidenceLog {
        &self.evidence
    }

    pub fn export_evidence(&self, path: impl AsRef<Path>) -> AutomationResult<()> {
        self.evidence.write_json(path)
    }

    pub fn invoke(&mut self, name: &str, arguments: Value) -> ToolCallEnvelope {
        let mut window_id = string_field(&arguments, "window_id");
        let mut element_id = string_field(&arguments, "element_id");
        let dispatched = self.dispatch(name, arguments.clone());
        if let Ok(success) = &dispatched {
            window_id = window_id.or_else(|| string_field(&success.value, "window_id"));
            element_id = element_id.or_else(|| string_field(&success.value, "element_id"));
        }
        let (result_value, method, state, screenshot_path) = match &dispatched {
            Ok(success) => (
                success.value.clone(),
                success.method.clone(),
                success.state.clone(),
                success.screenshot_path.clone(),
            ),
            Err(error) => (
                serde_json::to_value(error).unwrap_or_else(|_| {
                    json!({
                        "code": "BACKEND_FAILURE",
                        "message": "failed to serialize automation error"
                    })
                }),
                None,
                None,
                None,
            ),
        };
        let sequence = self.evidence.record(EvidenceDraft {
            tool: name.to_owned(),
            window_id,
            element_id,
            request: arguments,
            execution_method: method,
            result: result_value,
            resulting_state: state,
            screenshot_path,
        });
        match dispatched {
            Ok(success) => ToolCallEnvelope {
                ok: true,
                result: Some(success.value),
                error: None,
                evidence_sequence: sequence,
            },
            Err(error) => ToolCallEnvelope {
                ok: false,
                result: None,
                error: Some(error),
                evidence_sequence: sequence,
            },
        }
    }

    fn dispatch(&mut self, name: &str, arguments: Value) -> AutomationResult<DispatchSuccess> {
        if matches!(name, "windows_click_automation_id" | "windows_focus_automation_id"
            | "windows_send_keys_to_automation_id" | "windows_get_automation_id_state"
            | "windows_set_value_to_automation_id")
            && arguments.get("automation_id").and_then(Value::as_str) == Some("")
        {
            return Err(AutomationError::invalid_argument("automation_id must be a nonempty string"));
        }
        // The existing registry remains the public dispatcher. A handled
        // Remote refusal/uncertain result MUST NOT fall through to UIA.
        #[cfg(all(windows, feature = "experimental-makepad-remote"))]
        if self.definitions.iter().any(|tool| tool.name == name) {
            if let Some(remote) = self.remote.as_mut() {
                if let Some(result) = remote.dispatch(name, &arguments, &mut self.backend) {
                    return result;
                }
            }
        }
        match name {
            "windows_find_window" => {
                let query: WindowQuery = parse(arguments)?;
                DispatchSuccess::value(self.backend.find_window(&query)?, "EnumWindows")
            }
            "windows_get_control_tree" => {
                let args: ControlTreeArgs = parse(arguments)?;
                let result = self
                    .backend
                    .get_control_tree(&args.window_id, &args.options())?;
                DispatchSuccess::value(
                    result,
                    match args.view {
                        TreeView::Control => "UIAutomation.ControlViewWalker",
                        TreeView::Raw => "UIAutomation.RawViewWalker",
                    },
                )
            }
            "windows_find_control" => {
                let args: FindControlArgs = parse(arguments)?;
                DispatchSuccess::value(
                    self.backend.find_control(&args.window_id, &args.query)?,
                    "UIAutomation.ServerSideFilter",
                )
            }
            "windows_click_automation_id" => {
                let args: AutomationIdArgs = parse(arguments)?;
                let result = self
                    .backend
                    .click_automation_id(&args.window_id, &args.automation_id)?;
                let state = result
                    .after_state
                    .as_ref()
                    .and_then(|state| serde_json::to_value(state).ok());
                Ok(DispatchSuccess {
                    value: serde_json::to_value(result).map_err(serialization_error)?,
                    method: Some("UIAutomation.AutomationId+Invoke".to_owned()),
                    state,
                    screenshot_path: None,
                })
            }
            "windows_focus_automation_id" => {
                let args: AutomationIdArgs = parse(arguments)?;
                let state = self
                    .backend
                    .focus_automation_id(&args.window_id, &args.automation_id)?;
                let value = serde_json::to_value(&state).map_err(serialization_error)?;
                Ok(DispatchSuccess {
                    value: value.clone(),
                    method: Some("UIAutomation.SetFocusByAutomationId".to_owned()),
                    state: Some(value),
                    screenshot_path: None,
                })
            }
            "windows_send_keys_to_automation_id" => {
                let args: AutomationKeysArgs = parse(arguments)?;
                DispatchSuccess::value(
                    self.backend.send_keys_to_automation_id(
                        &args.window_id,
                        &args.automation_id,
                        &args.keys,
                    )?,
                    "UIAutomation.SetFocusByAutomationId+SendInput",
                )
            }
            "windows_get_automation_id_state" => {
                let args: AutomationIdArgs = parse(arguments)?;
                let state = self
                    .backend
                    .get_automation_id_state(&args.window_id, &args.automation_id)?;
                let value = serde_json::to_value(&state).map_err(serialization_error)?;
                Ok(DispatchSuccess {
                    value: value.clone(),
                    method: Some("UIAutomation.CurrentPropertiesByAutomationId".to_owned()),
                    state: Some(value),
                    screenshot_path: None,
                })
            }
            "windows_set_value_to_automation_id" => {
                let args: AutomationValueArgs = parse(arguments)?;
                let state = self.backend.set_value_automation_id(
                    &args.window_id,
                    &args.automation_id,
                    &args.value,
                )?;
                let value = serde_json::to_value(&state).map_err(serialization_error)?;
                Ok(DispatchSuccess {
                    value: value.clone(),
                    method: Some("UIAutomation.SetValueByAutomationId".to_owned()),
                    state: Some(value),
                    screenshot_path: None,
                })
            }
            "windows_click_element" => {
                let args: ElementArgs = parse(arguments)?;
                let result = self
                    .backend
                    .click_element(&args.window_id, &args.element_id)?;
                let method = result.action_method.clone();
                let state = result
                    .after_state
                    .as_ref()
                    .and_then(|state| serde_json::to_value(state).ok());
                Ok(DispatchSuccess {
                    value: serde_json::to_value(result).map_err(serialization_error)?,
                    method: Some(method),
                    state,
                    screenshot_path: None,
                })
            }
            "windows_focus_element" => {
                let args: ElementArgs = parse(arguments)?;
                let state = self
                    .backend
                    .focus_element(&args.window_id, &args.element_id)?;
                let value = serde_json::to_value(&state).map_err(serialization_error)?;
                Ok(DispatchSuccess {
                    value: value.clone(),
                    method: Some("UIAutomation.SetFocus".to_owned()),
                    state: Some(value),
                    screenshot_path: None,
                })
            }
            "windows_set_value" => {
                let args: SetValueArgs = parse(arguments)?;
                let state =
                    self.backend
                        .set_value(&args.window_id, &args.element_id, &args.value)?;
                let value = serde_json::to_value(&state).map_err(serialization_error)?;
                Ok(DispatchSuccess {
                    value: value.clone(),
                    method: Some("UIAutomation.ValuePattern.SetValue".to_owned()),
                    state: Some(value),
                    screenshot_path: None,
                })
            }
            "windows_send_keys" => {
                let args: SendKeysArgs = parse(arguments)?;
                DispatchSuccess::value(
                    self.backend.send_keys(&args.window_id, &args.keys)?,
                    "SendInput",
                )
            }
            "windows_get_element_state" => {
                let args: ElementArgs = parse(arguments)?;
                let state = self
                    .backend
                    .get_element_state(&args.window_id, &args.element_id)?;
                let value = serde_json::to_value(&state).map_err(serialization_error)?;
                Ok(DispatchSuccess {
                    value: value.clone(),
                    method: Some("UIAutomation.CurrentProperties".into()),
                    state: Some(value),
                    screenshot_path: None,
                })
            }
            "windows_inspect_window_interaction" => {
                let args: WindowIdArgs = parse(arguments)?;
                DispatchSuccess::value(
                    self.backend.inspect_window_interaction(&args.window_id)?,
                    "GetWindowRect+GetDpiForWindow+MonitorFromWindow+WM_NCHITTEST",
                )
            }
            "windows_resolve_window_frame_target" => {
                let args: FrameTargetArgs = parse(arguments)?;
                DispatchSuccess::value(
                    self.backend
                        .resolve_window_frame_target(&args.window_id, args.target)?,
                    "GetWindowRect+GetDpiForWindow+WM_NCHITTEST",
                )
            }
            "windows_set_window_state" => {
                let args: WindowStateArgs = parse(arguments)?;
                DispatchSuccess::value(
                    self.backend.set_window_state(&args.window_id, args.state)?,
                    "ShowWindow",
                )
            }
            "windows_set_window_bounds" => {
                let args: SetWindowBoundsArgs = parse(arguments)?;
                DispatchSuccess::value(
                    self.backend.set_window_bounds(
                        &args.window_id,
                        args.x,
                        args.y,
                        args.width,
                        args.height,
                    )?,
                    "SetWindowPos",
                )
            }
            "windows_capture_window" => {
                let args: CaptureArgs = parse(arguments)?;
                let result = self
                    .backend
                    .capture_window(&args.window_id, args.output_path.as_deref())?;
                let method = result.capture_method.clone();
                let screenshot_path = Some(result.path.clone());
                Ok(DispatchSuccess {
                    value: serde_json::to_value(result).map_err(serialization_error)?,
                    method: Some(method),
                    state: None,
                    screenshot_path,
                })
            }
            "windows_focus_window" => {
                let args: WindowIdArgs = parse(arguments)?;
                DispatchSuccess::value(
                    self.backend.focus_window(&args.window_id)?,
                    "SetForegroundWindow",
                )
            }
            "windows_get_evidence" => {
                let args: EvidenceArgs = parse(arguments)?;
                let entries: Vec<EvidenceEntry> =
                    self.evidence.entries_since(args.since_sequence, args.limit);
                DispatchSuccess::value(
                    json!({
                        "entries": entries,
                        "dropped_entries": self.evidence.dropped_entries()
                    }),
                    "EvidenceLog.Query",
                )
            }
            _ => Err(AutomationError::with_details(
                ErrorCode::ToolNotFound,
                format!("unknown tool: {name}"),
                json!({"available_tools": self.definitions.iter().map(|tool| tool.name).collect::<Vec<_>>() }),
            )),
        }
    }
}

#[derive(Deserialize)]
struct WindowIdArgs {
    window_id: String,
}

#[derive(Deserialize)]
struct ElementArgs {
    window_id: String,
    element_id: String,
}

#[derive(Deserialize)]
struct SetValueArgs {
    window_id: String,
    element_id: String,
    value: String,
}

#[derive(Deserialize)]
struct AutomationIdArgs {
    window_id: String,
    automation_id: String,
}

#[derive(Deserialize)]
struct AutomationKeysArgs {
    window_id: String,
    automation_id: String,
    keys: String,
}

#[derive(Deserialize)]
struct AutomationValueArgs {
    window_id: String,
    automation_id: String,
    value: String,
}

#[derive(Deserialize)]
struct SendKeysArgs {
    window_id: String,
    keys: String,
}

#[derive(Deserialize)]
struct CaptureArgs {
    window_id: String,
    output_path: Option<String>,
}

#[derive(Deserialize)]
struct FrameTargetArgs {
    window_id: String,
    target: WindowFrameTargetKind,
}

#[derive(Deserialize)]
struct WindowStateArgs {
    window_id: String,
    state: WindowState,
}
#[derive(Deserialize)]
struct SetWindowBoundsArgs {
    window_id: String,
    x: Option<i32>,
    y: Option<i32>,
    width: i32,
    height: i32,
}

#[derive(Deserialize)]
struct EvidenceArgs {
    since_sequence: Option<u64>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct FindControlArgs {
    window_id: String,
    #[serde(flatten)]
    query: ControlQuery,
}

#[derive(Deserialize)]
struct ControlTreeArgs {
    window_id: String,
    name: Option<String>,
    name_contains: Option<String>,
    control_type: Option<String>,
    automation_id: Option<String>,
    class_name: Option<String>,
    parent_element_id: Option<String>,
    visible_only: Option<bool>,
    max_depth: Option<usize>,
    max_elements: Option<usize>,
    #[serde(default)]
    view: TreeView,
}

impl ControlTreeArgs {
    fn options(&self) -> ControlTreeOptions {
        ControlTreeOptions {
            query: ControlQuery {
                name: self.name.clone(),
                name_contains: self.name_contains.clone(),
                control_type: self.control_type.clone(),
                automation_id: self.automation_id.clone(),
                class_name: self.class_name.clone(),
                parent_element_id: self.parent_element_id.clone(),
                visible_only: self.visible_only,
                index: None,
            },
            max_depth: self.max_depth,
            max_elements: self.max_elements,
            view: self.view,
        }
    }
}

fn parse<T: for<'de> Deserialize<'de>>(arguments: Value) -> AutomationResult<T> {
    serde_json::from_value(arguments)
        .map_err(|error| AutomationError::invalid_argument(error.to_string()))
}

fn serialization_error(error: serde_json::Error) -> AutomationError {
    AutomationError::new(ErrorCode::BackendFailure, error.to_string())
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

fn string_property(description: &str) -> Value {
    json!({"type": "string", "description": description})
}

fn query_properties() -> Value {
    json!({
        "name": {"type": "string"},
        "name_contains": {"type": "string"},
        "control_type": {"type": "string"},
        "automation_id": {"type": "string"},
        "class_name": {"type": "string"},
        "parent_element_id": {"type": "string"},
        "visible_only": {"type": "boolean"},
        "index": {
            "type": "integer",
            "minimum": 0,
            "description": "Zero-based secondary discriminator used only after all other filters."
        }
    })
}

fn tool_definitions() -> Vec<ToolDefinition> {
    let mut control_tree_properties = query_properties();
    control_tree_properties
        .as_object_mut()
        .expect("query schema is an object")
        .remove("index");
    control_tree_properties
        .as_object_mut()
        .expect("query schema is an object")
        .extend([
            (
                "window_id".into(),
                string_property("Opaque Toolkit window identity."),
            ),
            (
                "max_depth".into(),
                json!({"type": "integer", "minimum": 0, "maximum": 256}),
            ),
            (
                "max_elements".into(),
                json!({"type": "integer", "minimum": 1, "maximum": 20000}),
            ),
            (
                "view".into(),
                json!({"type": "string", "enum": ["control", "raw"], "default": "control"}),
            ),
        ]);

    let mut find_control_properties = query_properties();
    find_control_properties
        .as_object_mut()
        .expect("query schema is an object")
        .insert(
            "window_id".into(),
            string_property("Opaque Toolkit window identity."),
        );

    vec![
        ToolDefinition {
            name: "windows_find_window",
            description: "Resolve exactly one top-level Windows window and allocate a stable opaque window_id.",
            input_schema: object(
                json!({
                    "process_name": {"type": "string"},
                    "process_id": {"type": "integer", "minimum": 1},
                    "title": {"type": "string"},
                    "title_contains": {"type": "string"}
                }),
                &[],
            ),
        },
        ToolDefinition {
            name: "windows_get_control_tree",
            description: "Enumerate a filtered Microsoft UI Automation tree for a resolved window.",
            input_schema: object(control_tree_properties, &["window_id"]),
        },
        ToolDefinition {
            name: "windows_find_control",
            description: "Resolve exactly one accessible control using server-side filters and return element_id.",
            input_schema: object(find_control_properties, &["window_id"]),
        },
        ToolDefinition {
            name: "windows_click_automation_id",
            description: "Invoke a visible ERP control by its app-owned semantic AutomationId.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "automation_id": string_property("Stable application-owned UI Automation identifier.")
                }),
                &["window_id", "automation_id"],
            ),
        },
        ToolDefinition {
            name: "windows_focus_automation_id",
            description: "Set keyboard focus on a control resolved by its app-owned AutomationId.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "automation_id": string_property("Stable application-owned UI Automation identifier.")
                }),
                &["window_id", "automation_id"],
            ),
        },
        ToolDefinition {
            name: "windows_send_keys_to_automation_id",
            description: "Focus a control by AutomationId and inject text or a key chord.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "automation_id": string_property("Stable application-owned UI Automation identifier."),
                    "keys": {
                        "type": "string",
                        "description": "Unicode text or a supported key chord such as ENTER or CTRL+A."
                    }
                }),
                &["window_id", "automation_id", "keys"],
            ),
        },
        ToolDefinition {
            name: "windows_get_automation_id_state",
            description: "Read current UIA state for a control resolved by its app-owned AutomationId.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "automation_id": string_property("Stable application-owned UI Automation identifier.")
                }),
                &["window_id", "automation_id"],
            ),
        },
        ToolDefinition {
            name: "windows_set_value_to_automation_id",
            description: "Set an editable ERP control value by its app-owned AutomationId through UI Automation ValuePattern.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "automation_id": string_property("Stable application-owned UI Automation identifier."),
                    "value": {
                        "type": "string",
                        "description": "Value to assign to the editable control."
                    }
                }),
                &["window_id", "automation_id", "value"],
            ),
        },
        ToolDefinition {
            name: "windows_click_element",
            description: "Invoke, select, or click a previously resolved element_id without public coordinates.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "element_id": string_property("Opaque Toolkit UIA element identity.")
                }),
                &["window_id", "element_id"],
            ),
        },
        ToolDefinition {
            name: "windows_focus_element",
            description: "Set keyboard focus through UI Automation for a previously resolved element_id.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "element_id": string_property("Opaque Toolkit UIA element identity.")
                }),
                &["window_id", "element_id"],
            ),
        },
        ToolDefinition {
            name: "windows_set_value",
            description: "Set an editable control value through UI Automation ValuePattern without keyboard injection.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "element_id": string_property("Opaque Toolkit UIA element identity."),
                    "value": string_property("Replacement value for a control that exposes UI Automation ValuePattern.")
                }),
                &["window_id", "element_id", "value"],
            ),
        },
        ToolDefinition {
            name: "windows_send_keys",
            description: "Focus a resolved window and inject a chord or Unicode text bound to that window_id.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "keys": {
                        "type": "string",
                        "description": "Examples: CTRL+TAB, CTRL+SHIFT+TAB, CTRL+W, ENTER, or ordinary Unicode text."
                    }
                }),
                &["window_id", "keys"],
            ),
        },
        ToolDefinition {
            name: "windows_get_element_state",
            description: "Read current UIA state for a previously resolved element_id.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "element_id": string_property("Opaque Toolkit UIA element identity.")
                }),
                &["window_id", "element_id"],
            ),
        },
        ToolDefinition {
            name: "windows_inspect_window_interaction",
            description: "Read fresh HWND bounds, DPI, monitor, state, and live non-client frame targets without injecting input.",
            input_schema: object(
                json!({"window_id": string_property("Opaque Toolkit window identity.")}),
                &["window_id"],
            ),
        },
        ToolDefinition {
            name: "windows_resolve_window_frame_target",
            description: "Resolve one fresh physical title, edge, or corner target through bounded WM_NCHITTEST; this tool does not inject input.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "target": {"type": "string", "enum": ["title", "left", "right", "top", "bottom", "top_left", "top_right", "bottom_left", "bottom_right"]}
                }),
                &["window_id", "target"],
            ),
        },
        ToolDefinition {
            name: "windows_set_window_state",
            description: "Programmatically minimize, maximize, or restore a resolved window for setup/recovery; it is not proof of physical title-bar UX.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "state": {"type": "string", "enum": ["normal", "minimized", "maximized"]}
                }),
                &["window_id", "state"],
            ),
        },
        ToolDefinition {
            name: "windows_set_window_bounds",
            description: "Deterministically resize and optionally move a resolved native window.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                    "width": {"type": "integer", "minimum": 1},
                    "height": {"type": "integer", "minimum": 1}
                }),
                &["window_id", "width", "height"],
            ),
        },
        ToolDefinition {
            name: "windows_capture_window",
            description: "Capture the target native window to PNG and return artifact metadata.",
            input_schema: object(
                json!({
                    "window_id": string_property("Opaque Toolkit window identity."),
                    "output_path": {"type": "string"}
                }),
                &["window_id"],
            ),
        },
        ToolDefinition {
            name: "windows_focus_window",
            description: "Activate a resolved window and verify it became the foreground target.",
            input_schema: object(
                json!({"window_id": string_property("Opaque Toolkit window identity.")}),
                &["window_id"],
            ),
        },
        ToolDefinition {
            name: "windows_get_evidence",
            description: "Read the bounded structured evidence trail for this automation session.",
            input_schema: object(
                json!({
                    "since_sequence": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 4096}
                }),
                &[],
            ),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn empty_automation_id_is_refused_by_real_dispatch_before_target_lookup() {
        let mut registry = GuiToolRegistry {
            #[cfg(feature = "experimental-makepad-remote")]
            remote: None,
            backend: WindowsAutomation::new().expect("own Windows automation apartment"),
            evidence: EvidenceLog::default(),
            definitions: tool_definitions(),
        };
        for name in ["windows_click_automation_id", "windows_focus_automation_id",
            "windows_send_keys_to_automation_id", "windows_get_automation_id_state",
            "windows_set_value_to_automation_id"]
        {
            let result = registry.invoke(name, json!({"window_id":"foreign-window",
                "automation_id":"", "keys":"ALPHA", "value":"ALPHA"}));
            assert!(!result.ok);
            assert_eq!(result.error.unwrap().code, ErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn migration_preserves_all_twenty_public_tool_schema_builders() {
        use sha2::{Digest, Sha256};
        // Freeze includes shared property builders, descriptions, ordering and
        // all input schemas. This is source compatibility, not runtime proof.
        let source = include_str!("tool_registry.rs").replace("\r\n", "\n");
        let schema = source.split_once("fn object(").unwrap().1;
        let schema = format!("fn object({}", schema.split_once("#[cfg(test)]").unwrap().0);
        assert_eq!(format!("{:x}", Sha256::digest(schema.as_bytes())),
            "13323c01f2db9c04521bb5ef50d836956e49e35385466988c9f264e7802a3606");
        assert_eq!(tool_definitions().len(), 20);
        assert!(tool_definitions().iter().all(|d| d.input_schema["additionalProperties"] == false));
    }

    #[test]
    fn registry_exposes_all_required_tools_with_object_schemas() {
        let definitions = tool_definitions();
        let names = definitions
            .iter()
            .map(|definition| definition.name)
            .collect::<Vec<_>>();
        for required in [
            "windows_find_window",
            "windows_get_control_tree",
            "windows_find_control",
            "windows_click_automation_id",
            "windows_focus_automation_id",
            "windows_send_keys_to_automation_id",
            "windows_get_automation_id_state",
            "windows_set_value_to_automation_id",
            "windows_click_element",
            "windows_focus_element",
            "windows_set_value",
            "windows_send_keys",
            "windows_get_element_state",
            "windows_inspect_window_interaction",
            "windows_resolve_window_frame_target",
            "windows_set_window_state",
            "windows_set_window_bounds",
            "windows_capture_window",
            "windows_focus_window",
        ] {
            assert!(names.contains(&required), "missing {required}");
        }
        assert!(
            definitions
                .iter()
                .all(|definition| definition.input_schema["type"] == "object")
        );

        let set_value = definitions
            .iter()
            .find(|definition| definition.name == "windows_set_value")
            .expect("windows_set_value definition");
        assert_eq!(
            set_value.input_schema["required"],
            json!(["window_id", "element_id", "value"])
        );
    }
}

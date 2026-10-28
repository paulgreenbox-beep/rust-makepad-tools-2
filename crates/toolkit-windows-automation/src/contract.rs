use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::fmt;

pub type AutomationResult<T> = Result<T, AutomationError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    WindowNotFound,
    AmbiguousWindow,
    WindowNotMovable,
    WindowNotResizable,
    WindowFrameTargetUnavailable,
    WindowTitleRegionUnavailable,
    WindowResizeConstraint,
    WindowBoundsNotChanged,
    WindowMoveVerificationFailed,
    WindowResizeVerificationFailed,
    WindowDpiConversionFailed,
    CoordinateMappingUnverified,
    WindowStateTransitionFailed,
    ElementNotFound,
    AmbiguousElement,
    StaleElement,
    WindowNotFocused,
    ActionNotSupported,
    InputInjectionFailed,
    ScreenshotFailed,
    AccessibilityUnavailable,
    OwnerHwndUnavailable,
    InvocationFailed,
    PermissionDenied,
    InvalidArgument,
    ToolNotFound,
    BackendFailure,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AutomationError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub details: Value,
}

impl AutomationError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: Value::Null,
        }
    }

    pub fn with_details(
        code: ErrorCode,
        message: impl Into<String>,
        details: impl Serialize,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            details: serde_json::to_value(details).unwrap_or(Value::Null),
        }
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }
}

impl fmt::Display for AutomationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl Error for AutomationError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

impl Rect {
    pub fn is_actionable(self) -> bool {
        self.width > 0 && self.height > 0
    }

    pub fn center(self) -> Option<(i32, i32)> {
        self.is_actionable()
            .then_some((self.x + self.width / 2, self.y + self.height / 2))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct WindowQuery {
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub title: Option<String>,
    pub title_contains: Option<String>,
}

impl WindowQuery {
    pub fn matches(&self, candidate: &WindowInfo) -> bool {
        optional_eq(&self.process_name, &candidate.process_name)
            && self
                .process_id
                .is_none_or(|process_id| process_id == candidate.process_id)
            && optional_eq(&self.title, &candidate.title)
            && optional_contains(&self.title_contains, &candidate.title)
    }

    pub fn is_empty(&self) -> bool {
        self.process_name.is_none()
            && self.process_id.is_none()
            && self.title.is_none()
            && self.title_contains.is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WindowInfo {
    pub window_id: String,
    pub hwnd: String,
    pub process_id: u32,
    pub process_name: String,
    pub title: String,
    pub class_name: String,
    pub bounds: Rect,
    pub visible: bool,
    pub focused: bool,
    pub foreground: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlQuery {
    pub name: Option<String>,
    pub name_contains: Option<String>,
    pub control_type: Option<String>,
    pub automation_id: Option<String>,
    pub class_name: Option<String>,
    pub parent_element_id: Option<String>,
    pub visible_only: Option<bool>,
    pub index: Option<usize>,
}

impl ControlQuery {
    pub fn matches(&self, control: &ControlInfo) -> bool {
        optional_eq(&self.name, &control.name)
            && optional_contains(&self.name_contains, &control.name)
            && optional_control_type(&self.control_type, &control.control_type)
            && optional_eq(&self.automation_id, &control.automation_id)
            && optional_eq(&self.class_name, &control.class_name)
            && self
                .parent_element_id
                .as_ref()
                .is_none_or(|parent| control.parent_element_id.as_ref() == Some(parent))
            && self.visible_only.unwrap_or(false).not_or(control.visible)
    }

    pub fn without_index(&self) -> Self {
        let mut query = self.clone();
        query.index = None;
        query
    }

    pub fn is_empty_except_index(&self) -> bool {
        self.name.is_none()
            && self.name_contains.is_none()
            && self.control_type.is_none()
            && self.automation_id.is_none()
            && self.class_name.is_none()
            && self.parent_element_id.is_none()
            && !self.visible_only.unwrap_or(false)
    }
}

trait BoolQueryExt {
    fn not_or(self, actual: bool) -> bool;
}

impl BoolQueryExt for bool {
    fn not_or(self, actual: bool) -> bool {
        !self || actual
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreeView {
    #[default]
    Control,
    Raw,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlTreeOptions {
    #[serde(default)]
    pub query: ControlQuery,
    pub max_depth: Option<usize>,
    pub max_elements: Option<usize>,
    #[serde(default)]
    pub view: TreeView,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionCapabilities {
    pub invoke: bool,
    pub select: bool,
    pub value: bool,
    pub expand_collapse: bool,
    pub native_action: bool,
    pub synthesized_pointer: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlInfo {
    pub element_id: String,
    pub parent_element_id: Option<String>,
    pub control_type: String,
    pub control_type_id: i32,
    pub localized_control_type: String,
    pub name: String,
    pub value: Option<String>,
    pub text: Option<String>,
    pub automation_id: String,
    pub class_name: String,
    pub framework_id: String,
    pub bounds: Rect,
    pub visible: bool,
    pub offscreen: bool,
    pub enabled: bool,
    pub focused: bool,
    pub selected: Option<bool>,
    pub expand_state: Option<String>,
    pub capabilities: ActionCapabilities,
    pub hwnd: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlTreeResult {
    pub window_id: String,
    pub backend: String,
    pub view: TreeView,
    pub elements: Vec<ControlInfo>,
    pub total_enumerated: usize,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ElementState {
    pub exists: bool,
    pub element_id: String,
    pub window_id: String,
    pub visible: bool,
    pub enabled: bool,
    pub focused: bool,
    pub selected: Option<bool>,
    pub name: String,
    pub control_type: String,
    pub bounds: Rect,
    pub value: Option<String>,
    pub text: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClickResult {
    pub success: bool,
    pub resolved_element: ControlInfo,
    pub action_method: String,
    pub before_state: ElementState,
    pub after_state: Option<ElementState>,
    pub after_error: Option<AutomationError>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ForegroundRef {
    pub hwnd: String,
    pub window_id: Option<String>,
    pub title: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FocusResult {
    pub requested_window: WindowInfo,
    pub previous_foreground: Option<ForegroundRef>,
    pub resulting_foreground: Option<ForegroundRef>,
    pub success: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SendKeysResult {
    pub target_window: WindowInfo,
    pub requested_keys: String,
    pub focus_acquisition: FocusResult,
    pub input_events_requested: usize,
    pub input_events_injected: usize,
    pub success: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WindowBoundsResult {
    pub requested_bounds: Rect,
    pub actual_bounds: Rect,
    pub success: bool,
}

/// A screen-space point represented in physical desktop pixels. This is the
/// only coordinate system accepted by Win32 non-client hit testing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScreenPoint {
    pub x: i32,
    pub y: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowFrameTargetKind {
    Title,
    Left,
    Right,
    Top,
    Bottom,
    TopLeft,
    TopRight,
    BottomLeft,
    BottomRight,
}

impl WindowFrameTargetKind {
    pub const RESIZE_TARGETS: [Self; 8] = [
        Self::Left,
        Self::Right,
        Self::Top,
        Self::Bottom,
        Self::TopLeft,
        Self::TopRight,
        Self::BottomLeft,
        Self::BottomRight,
    ];

    pub fn is_resize_target(self) -> bool {
        !matches!(self, Self::Title)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WindowFrameTarget {
    pub target: WindowFrameTargetKind,
    pub screen_point: ScreenPoint,
    /// The concrete WM_NCHITTEST result returned by the live HWND.
    pub hit_test: String,
    /// Always `wm_nchittest` for targets discovered by this generic backend.
    pub source: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowState {
    #[default]
    Normal,
    Minimized,
    Maximized,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowFrameKind {
    NativeCaption,
    CustomCaption,
    Borderless,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MonitorInfo {
    pub handle: String,
    pub bounds: Rect,
    pub work_area: Rect,
    pub primary: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WindowInteractionInfo {
    pub window: WindowInfo,
    pub coordinate_model: String,
    pub dpi: u32,
    pub scale_factor: f64,
    pub monitor: MonitorInfo,
    pub state: WindowState,
    pub frame_kind: WindowFrameKind,
    /// Whether the currently live HWND exposes a caption hit target suitable
    /// for a physical title/header drag.
    pub movable: bool,
    /// Whether the current HWND exposes at least one live resize hit target.
    pub resizable: bool,
    pub minimizable: bool,
    pub maximizable: bool,
    pub restorable: bool,
    pub offscreen: bool,
    pub clipped_to_work_area: bool,
    /// Min/max tracking constraints are not advertised by a generic Win32
    /// query. They are reported only after an attempted, verified gesture.
    pub constraint_observation: String,
    pub title_target: Option<WindowFrameTarget>,
    pub frame_targets: Vec<WindowFrameTarget>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WindowStateResult {
    pub window_id: String,
    pub requested_state: WindowState,
    pub previous_state: WindowState,
    pub actual_state: WindowState,
    pub actual_bounds: Rect,
    pub success: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureDimensions {
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureResult {
    pub window_id: String,
    pub backend: String,
    pub hwnd: String,
    pub pid: u32,
    pub path: String,
    pub bounds: Rect,
    pub dimensions: CaptureDimensions,
    pub timestamp_unix_ms: u128,
    pub image_width: u32,
    pub image_height: u32,
    pub capture_method: String,
    pub non_blank: bool,
    pub occlusion_independent: bool,
    pub gpu_compatible: bool,
    pub fallback_used: bool,
    pub diagnostics: Vec<String>,
    pub limitations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geometry: Option<crate::CaptureGeometry>,
}

fn folded(value: &str) -> String {
    value.to_lowercase()
}

fn optional_eq(expected: &Option<String>, actual: &str) -> bool {
    expected
        .as_ref()
        .is_none_or(|expected| folded(expected) == folded(actual))
}

fn optional_contains(expected: &Option<String>, actual: &str) -> bool {
    expected
        .as_ref()
        .is_none_or(|expected| folded(actual).contains(&folded(expected)))
}

fn optional_control_type(expected: &Option<String>, actual: &str) -> bool {
    expected
        .as_ref()
        .is_none_or(|expected| normalized_control_type(expected) == normalized_control_type(actual))
}

fn normalized_control_type(value: &str) -> String {
    let value = folded(value);
    value
        .strip_prefix("controltype.")
        .unwrap_or(&value)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(title: &str) -> WindowInfo {
        WindowInfo {
            window_id: "win:test:1".into(),
            hwnd: "0x1".into(),
            process_id: 7,
            process_name: "fixture.exe".into(),
            title: title.into(),
            class_name: "Fixture".into(),
            bounds: Rect::default(),
            visible: true,
            focused: false,
            foreground: false,
        }
    }

    fn control(name: &str) -> ControlInfo {
        ControlInfo {
            element_id: "el:test:1".into(),
            parent_element_id: Some("el:test:0".into()),
            control_type: "Button".into(),
            control_type_id: 50_000,
            localized_control_type: "button".into(),
            name: name.into(),
            value: None,
            text: None,
            automation_id: "101".into(),
            class_name: "Button".into(),
            framework_id: "Win32".into(),
            bounds: Rect {
                x: 1,
                y: 2,
                width: 3,
                height: 4,
            },
            visible: true,
            offscreen: false,
            enabled: true,
            focused: false,
            selected: None,
            expand_state: None,
            capabilities: ActionCapabilities::default(),
            hwnd: Some("0x2".into()),
        }
    }

    #[test]
    fn window_query_is_deterministic_and_case_insensitive() {
        let query = WindowQuery {
            process_name: Some("FIXTURE.EXE".into()),
            process_id: Some(7),
            title_contains: Some("unique".into()),
            ..Default::default()
        };
        assert!(query.matches(&window("Unique Window")));
        assert!(!query.matches(&window("Different Window")));
    }

    #[test]
    fn control_query_supports_parent_and_visible_filters() {
        let query = ControlQuery {
            name: Some("increment".into()),
            control_type: Some("ControlType.Button".into()),
            automation_id: Some("101".into()),
            parent_element_id: Some("el:test:0".into()),
            visible_only: Some(true),
            ..Default::default()
        };
        assert!(query.matches(&control("Increment")));
        let mut hidden = control("Increment");
        hidden.visible = false;
        assert!(!query.matches(&hidden));
    }

    #[test]
    fn errors_have_machine_readable_codes() {
        let error = AutomationError::new(ErrorCode::StaleElement, "gone");
        let json = serde_json::to_value(error).unwrap();
        assert_eq!(json["code"], "STALE_ELEMENT");
    }
}

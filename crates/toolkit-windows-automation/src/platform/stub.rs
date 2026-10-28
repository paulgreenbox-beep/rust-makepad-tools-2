use crate::contract::{
    AutomationError, AutomationResult, CaptureResult, ClickResult, ControlInfo, ControlQuery,
    ControlTreeOptions, ControlTreeResult, ElementState, ErrorCode, FocusResult, SendKeysResult,
    WindowBoundsResult, WindowInfo, WindowQuery,
};

pub struct WindowsAutomation;

impl WindowsAutomation {
    pub fn new() -> AutomationResult<Self> {
        Ok(Self)
    }

    pub fn find_window(&mut self, _query: &WindowQuery) -> AutomationResult<WindowInfo> {
        Err(unavailable())
    }

    pub fn list_windows(&mut self, _query: &WindowQuery) -> AutomationResult<Vec<WindowInfo>> {
        Err(unavailable())
    }

    pub fn get_control_tree(
        &mut self,
        _window_id: &str,
        _options: &ControlTreeOptions,
    ) -> AutomationResult<ControlTreeResult> {
        Err(unavailable())
    }

    pub fn find_control(
        &mut self,
        _window_id: &str,
        _query: &ControlQuery,
    ) -> AutomationResult<ControlInfo> {
        Err(unavailable())
    }

    pub fn find_automation_id(
        &mut self,
        _window_id: &str,
        _automation_id: &str,
    ) -> AutomationResult<ControlInfo> {
        Err(unavailable())
    }

    pub fn click_automation_id(
        &mut self,
        _window_id: &str,
        _automation_id: &str,
    ) -> AutomationResult<ClickResult> {
        Err(unavailable())
    }

    pub fn focus_automation_id(
        &mut self,
        _window_id: &str,
        _automation_id: &str,
    ) -> AutomationResult<ElementState> {
        Err(unavailable())
    }

    pub fn send_keys_to_automation_id(
        &mut self,
        _window_id: &str,
        _automation_id: &str,
        _keys: &str,
    ) -> AutomationResult<SendKeysResult> {
        Err(unavailable())
    }

    pub fn get_automation_id_state(
        &mut self,
        _window_id: &str,
        _automation_id: &str,
    ) -> AutomationResult<ElementState> {
        Err(unavailable())
    }

    pub fn set_value_automation_id(
        &mut self,
        _window_id: &str,
        _automation_id: &str,
        _value: &str,
    ) -> AutomationResult<ElementState> {
        Err(unavailable())
    }

    pub fn click_element(
        &mut self,
        _window_id: &str,
        _element_id: &str,
    ) -> AutomationResult<ClickResult> {
        Err(unavailable())
    }

    pub fn focus_element(
        &mut self,
        _window_id: &str,
        _element_id: &str,
    ) -> AutomationResult<ElementState> {
        Err(unavailable())
    }

    pub fn send_keys(&mut self, _window_id: &str, _keys: &str) -> AutomationResult<SendKeysResult> {
        Err(unavailable())
    }

    pub fn send_text(&mut self, _window_id: &str, _text: &str) -> AutomationResult<SendKeysResult> {
        Err(unavailable())
    }

    pub fn send_key_repeat(
        &mut self,
        _window_id: &str,
        _key: &str,
        _count: usize,
    ) -> AutomationResult<SendKeysResult> {
        Err(unavailable())
    }
    pub fn get_element_state(
        &mut self,
        _window_id: &str,
        _element_id: &str,
    ) -> AutomationResult<ElementState> {
        Err(unavailable())
    }

    pub fn set_value(
        &mut self,
        _window_id: &str,
        _element_id: &str,
        _value: &str,
    ) -> AutomationResult<ElementState> {
        Err(unavailable())
    }

    pub fn set_window_bounds(
        &mut self,
        _window_id: &str,
        _x: Option<i32>,
        _y: Option<i32>,
        _width: i32,
        _height: i32,
    ) -> AutomationResult<WindowBoundsResult> {
        Err(unavailable())
    }

    pub fn capture_window(
        &mut self,
        _window_id: &str,
        _output_path: Option<&str>,
    ) -> AutomationResult<CaptureResult> {
        Err(unavailable())
    }

    pub fn focus_window(&mut self, _window_id: &str) -> AutomationResult<FocusResult> {
        Err(unavailable())
    }
}

fn unavailable() -> AutomationError {
    AutomationError::new(
        ErrorCode::AccessibilityUnavailable,
        "Windows GUI automation is available only on Windows",
    )
}

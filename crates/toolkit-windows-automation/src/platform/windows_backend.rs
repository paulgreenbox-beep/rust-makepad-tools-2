use crate::accessibility::MAKEPAD_EMPTY_VALUE_SENTINEL;
use crate::contract::{
    ActionCapabilities, AutomationError, AutomationResult, CaptureDimensions, CaptureResult,
    ClickResult, ControlInfo, ControlQuery, ControlTreeOptions, ControlTreeResult, ElementState,
    ErrorCode, FocusResult, ForegroundRef, MonitorInfo, Rect, ScreenPoint, SendKeysResult,
    TreeView, WindowBoundsResult, WindowFrameKind, WindowFrameTarget, WindowFrameTargetKind,
    WindowInfo, WindowInteractionInfo, WindowQuery, WindowState, WindowStateResult,
};
use crate::evidence::now_unix_ms;
use crate::identity::SessionIds;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::fs::File;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use windows::core::{Error as WindowsError, Interface, BOOL, BSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, E_ACCESSDENIED, HWND, LPARAM, RECT, TRUE, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits,
    GetMonitorInfoW, GetWindowDC, MonitorFromWindow, ReleaseDC, SelectObject, BITMAPINFO,
    BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HGDIOBJ, MONITORINFO, MONITOR_DEFAULTTONEAREST,
    SRCCOPY,
};
use windows::Win32::Storage::Xps::{PrintWindow, PRINT_WINDOW_FLAGS};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::Threading::{
    AttachThreadInput, GetCurrentThreadId, OpenProcess, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, CUIAutomation8, ExpandCollapseState, IUIAutomation, IUIAutomation2,
    IUIAutomationElement, IUIAutomationExpandCollapsePattern, IUIAutomationInvokePattern,
    IUIAutomationSelectionItemPattern, IUIAutomationTreeWalker, IUIAutomationValuePattern,
    IUIAutomationWindowPattern, UIA_ExpandCollapsePatternId, UIA_InvokePatternId,
    UIA_SelectionItemPatternId, UIA_ValuePatternId, UIA_WindowPatternId, UIA_E_ELEMENTNOTAVAILABLE,
    UIA_E_NOTSUPPORTED,
};
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE, VIRTUAL_KEY,
    VK_BACK, VK_CONTROL, VK_DELETE, VK_DOWN, VK_END, VK_ESCAPE, VK_HOME, VK_LEFT, VK_LWIN, VK_MENU,
    VK_NEXT, VK_PRIOR, VK_RETURN, VK_RIGHT, VK_SHIFT, VK_SPACE, VK_TAB, VK_UP,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, EnumWindows, GetAncestor, GetClassNameW, GetForegroundWindow,
    GetWindowLongPtrW, GetWindowRect, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible, IsZoomed, SendMessageTimeoutW,
    SendMessageW, SetForegroundWindow, SetWindowPos, ShowWindow, BM_CLICK, GA_ROOT, GWL_STYLE,
    HTBOTTOM, HTBOTTOMLEFT, HTBOTTOMRIGHT, HTCAPTION, HTLEFT, HTRIGHT, HTTOP, HTTOPLEFT,
    HTTOPRIGHT, MONITORINFOF_PRIMARY, PW_RENDERFULLCONTENT, SMTO_ABORTIFHUNG, SWP_NOACTIVATE,
    SWP_NOZORDER, SW_MAXIMIZE, SW_MINIMIZE, SW_RESTORE, SW_SHOW, WM_NCHITTEST, WS_CAPTION,
    WS_MAXIMIZEBOX, WS_MINIMIZEBOX, WS_SIZEBOX,
};

#[path = "arbiter_guard.rs"]
mod arbiter_guard;
pub use arbiter_guard::DesktopInputReservation;
use arbiter_guard::{DesktopArbiterGuard, DesktopArbiterRuntime};

const MAX_DEFAULT_ELEMENTS: usize = 5_000;
const MAX_ALLOWED_ELEMENTS: usize = 20_000;
const MAX_DEFAULT_DEPTH: usize = 64;
const E_POINTER_U32: u32 = 0x8000_4003;
const E_ACCESSDENIED_U32: u32 = 0x8007_0005;
const COR_E_INVALIDOPERATION_U32: u32 = 0x8013_1505;
const UIA_ROOT_RESOLVE_ATTEMPTS: usize = 3;
const UIA_ROOT_RETRY_DELAY_MS: u64 = 25;
/// Bound provider RPC so a read-only postcondition cannot hold a test run
/// forever when an application accessibility provider stops responding.
const UIA_CONNECTION_TIMEOUT_MS: u32 = 3_000;
const UIA_TRANSACTION_TIMEOUT_MS: u32 = 5_000;
const WINDOW_HIT_TEST_TIMEOUT_MS: u32 = 120;
const WINDOW_STATE_POLL_TIMEOUT_MS: u64 = 1_500;
const WINDOW_STATE_POLL_MS: u64 = 30;

fn value_pattern_bstr(value: &str, framework_id: &str) -> BSTR {
    if value.is_empty() && framework_id.eq_ignore_ascii_case("Makepad") {
        // UI Automation filters empty values before invoking a custom provider.
        // The Makepad provider decodes this noncharacter-delimited clear token.
        BSTR::from(MAKEPAD_EMPTY_VALUE_SENTINEL)
    } else {
        BSTR::from(value)
    }
}

struct ComApartment;

impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

#[derive(Clone)]
struct WindowRecord {
    id: String,
    hwnd: isize,
    process_id: u32,
    process_birth: Option<u64>,
}

#[derive(Clone)]
struct ElementRecord {
    id: String,
    window_id: String,
    element: IUIAutomationElement,
    parent_element_id: Option<String>,

    automation_id: String,
}

pub struct WindowsAutomation {
    // Rust drops fields in declaration order: release every UIA COM interface
    // before the apartment guard calls CoUninitialize.
    automation: IUIAutomation,
    ids: SessionIds,
    windows: BTreeMap<String, WindowRecord>,
    window_by_hwnd: HashMap<isize, String>,
    elements: BTreeMap<String, ElementRecord>,
    desktop_arbiter_runtime: Option<DesktopArbiterRuntime>,
    capture_geometries: BTreeMap<String, crate::CaptureGeometry>,
    _com: ComApartment,
}

impl WindowsAutomation {
    pub fn new() -> AutomationResult<Self> {
        unsafe {
            let initialized = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            if initialized.is_err() {
                return Err(AutomationError::with_details(
                    ErrorCode::AccessibilityUnavailable,
                    "failed to initialize the Windows COM STA required by UI Automation",
                    json!({"hresult": format!("0x{:08X}", initialized.0 as u32)}),
                ));
            }
            let com = ComApartment;
            let automation = match CoCreateInstance::<_, IUIAutomation2>(
                &CUIAutomation8,
                None,
                CLSCTX_INPROC_SERVER,
            ) {
                Ok(automation_v2) => {
                    automation_v2
                        .SetConnectionTimeout(UIA_CONNECTION_TIMEOUT_MS)
                        .map_err(|error| {
                            uia_backend_error(
                                "failed to set UI Automation connection timeout",
                                error,
                            )
                        })?;
                    automation_v2
                        .SetTransactionTimeout(UIA_TRANSACTION_TIMEOUT_MS)
                        .map_err(|error| {
                            uia_backend_error(
                                "failed to set UI Automation transaction timeout",
                                error,
                            )
                        })?;
                    automation_v2.cast::<IUIAutomation>().map_err(|error| {
                        uia_backend_error("failed to downcast CUIAutomation8", error)
                    })?
                }
                Err(_) => {
                    CoCreateInstance::<_, IUIAutomation>(&CUIAutomation, None, CLSCTX_INPROC_SERVER)
                        .map_err(|error| {
                            uia_backend_error("failed to create CUIAutomation", error)
                        })?
                }
            };
            let backend = Self {
                automation,
                _com: com,
                ids: SessionIds::new(),
                windows: BTreeMap::new(),
                window_by_hwnd: HashMap::new(),
                elements: BTreeMap::new(),
                desktop_arbiter_runtime: None,
                capture_geometries: BTreeMap::new(),
            };
            match std::env::var("TOOLKIT_WINDOWS_DESKTOP_ARBITER_V1").as_deref() {
                Ok("1" | "0") | Err(_) => {}
                Ok(_) => {
                    return Err(AutomationError::invalid_argument(
                        "trusted TOOLKIT_WINDOWS_DESKTOP_ARBITER_V1 flag must be 0 or 1",
                    ));
                }
            }
            // Trusted managers bind their job identity before actions. A raw
            // MCP/native caller gets the kernel-derived lazy fallback at its
            // first mutation; neither unset nor 0 bypasses the shared arbiter.
            Ok(backend)
        }
    }

    /// Enables cooperative desktop arbitration for trusted runtime callers.
    pub fn desktop_arbiter_enabled(&self) -> bool {
        self.desktop_arbiter_runtime.is_some()
    }

    pub(crate) fn set_request_control(&mut self, control: Option<crate::request_control::RequestControl>) {
        if let Some(runtime) = self.desktop_arbiter_runtime.as_mut() {
            runtime.request_control = control;
        }
    }

    /// The owner identity is immutable after the first successful enablement.
    pub fn enable_desktop_arbiter_runtime(
        &mut self,
        worker: &str,
        job: &str,
        attempt: &str,
    ) -> AutomationResult<()> {
        if worker.trim().is_empty() || job.trim().is_empty() || attempt.trim().is_empty() {
            return Err(AutomationError::invalid_argument(
                "desktop arbiter worker, job, and attempt IDs must not be empty",
            ));
        }
        if let Some(runtime) = &self.desktop_arbiter_runtime {
            return if runtime.matches(worker, job, attempt) {
                Ok(())
            } else {
                Err(AutomationError::invalid_argument(
                    "desktop arbiter runtime owner cannot be rebound",
                ))
            };
        }

        self.desktop_arbiter_runtime = Some(
            DesktopArbiterRuntime::new(worker, job, attempt)
                .map_err(desktop_arbiter_backend_error)?,
        );
        Ok(())
    }

    /// Reserves the exact registered window for trusted physical-input callers.
    /// The returned opaque guard owns the same RAII lease as backend actions.
    pub fn reserve_physical_input(
        &mut self,
        window_id: &str,
    ) -> AutomationResult<Option<DesktopInputReservation>> {
        self.acquire_desktop_guard(window_id)
            .map(|guard| guard.map(DesktopInputReservation::new))
    }
    pub fn bind_desktop_arbiter_session(&mut self, session: &str) -> AutomationResult<()> {
        self.desktop_arbiter_runtime
            .as_mut()
            .ok_or_else(|| {
                AutomationError::invalid_argument(
                    "trusted runtime must bind before its canonical session",
                )
            })?
            .bind_session(session)
            .map_err(desktop_arbiter_backend_error)
    }

    /// Logical mutation scope: no focus, global keyboard, or desktop lease.
    /// Covers prestate, dispatch and readback in the caller's existing action.
    pub fn reserve_window_mutation(
        &mut self,
        window_id: &str,
    ) -> AutomationResult<Option<DesktopInputReservation>> {
        self.acquire_window_guard(window_id, false)
            .map(|guard| guard.map(DesktopInputReservation::new))
    }

    pub fn find_window(&mut self, query: &WindowQuery) -> AutomationResult<WindowInfo> {
        let mut registered = self.list_windows(query)?;
        if registered.is_empty() {
            return Err(AutomationError::with_details(
                ErrorCode::WindowNotFound,
                "no top-level Windows window matched the query",
                query,
            ));
        }
        if registered.len() != 1 {
            return Err(AutomationError::with_details(
                ErrorCode::AmbiguousWindow,
                format!(
                    "{} windows matched; refine the query or use a returned window_id",
                    registered.len()
                ),
                json!({"candidates": registered}),
            ));
        }
        Ok(registered.remove(0))
    }

    /// Enumerates and registers every top-level window matching `query`.
    ///
    /// Unlike [`Self::find_window`], this intentionally permits zero or many
    /// matches so callers can implement waits and session-scoped filtering
    /// without losing the stable `window_id` assigned by this backend.
    pub fn list_windows(&mut self, query: &WindowQuery) -> AutomationResult<Vec<WindowInfo>> {
        let mut candidates = enumerate_top_level_windows()?
            .into_iter()
            .filter(|candidate| query.matches(candidate))
            .collect::<Vec<_>>();
        candidates.sort_by_key(|candidate| {
            (
                candidate.process_id,
                candidate.title.to_lowercase(),
                candidate.hwnd.clone(),
            )
        });

        let mut registered = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            registered.push(self.register_window(candidate)?);
        }
        Ok(registered)
    }

    /// Refresh a registered HWND by its session-owned opaque ID. This does not
    /// rediscover by title or process, so two top-level windows in one process
    /// remain unambiguous after a move or resize.
    pub fn get_window_info(&mut self, window_id: &str) -> AutomationResult<WindowInfo> {
        self.resolve_window(window_id).map(|(_, info)| info)
    }

    /// Inspect the live top-level HWND using only physical desktop pixels.
    /// `WM_NCHITTEST` is queried with a bounded timeout, which lets custom
    /// Makepad caption/resize behavior be discovered without vendor patches.
    pub fn inspect_window_interaction(
        &mut self,
        window_id: &str,
    ) -> AutomationResult<WindowInteractionInfo> {
        let (hwnd, info) = self.resolve_window(window_id)?;
        build_window_interaction_info(hwnd, info)
    }

    /// Resolve a fresh physical non-client target immediately before a frame
    /// gesture. The returned point must not be cached across a window action.
    pub fn resolve_window_frame_target(
        &mut self,
        window_id: &str,
        target: WindowFrameTargetKind,
    ) -> AutomationResult<WindowFrameTarget> {
        let _dpi = CaptureDpiScope::enter()?;
        let (hwnd, info) = self.resolve_window(window_id)?;
        let interaction = build_window_interaction_info(hwnd, info.clone())?;
        if interaction.state == WindowState::Minimized {
            return Err(AutomationError::with_details(
                if target == WindowFrameTargetKind::Title {
                    ErrorCode::WindowNotMovable
                } else {
                    ErrorCode::WindowNotResizable
                },
                "a minimized top-level window has no actionable frame target",
                &interaction,
            ));
        }
        if target == WindowFrameTargetKind::Title {
            return interaction.title_target.clone().ok_or_else(|| {
                AutomationError::with_details(
                    ErrorCode::WindowNotMovable,
                    "the live HWND did not expose an HTCAPTION target",
                    interaction,
                )
            });
        }
        if !has_window_style(hwnd, WS_SIZEBOX) {
            return Err(AutomationError::with_details(
                ErrorCode::WindowNotResizable,
                "the HWND does not advertise WS_SIZEBOX",
                interaction,
            ));
        }
        interaction
            .frame_targets
            .clone()
            .into_iter()
            .find(|candidate| candidate.target == target)
            .ok_or_else(|| {
                AutomationError::with_details(
                    ErrorCode::WindowFrameTargetUnavailable,
                    "the live HWND did not expose the requested resize hit target",
                    json!({"target": target, "interaction": interaction}),
                )
            })
    }

    /// Variant used by a script host after it resolved an application-owned
    /// semantic title/header region. The region is validated against the fresh
    /// HWND bounds and is still confirmed by WM_NCHITTEST before input.
    pub fn resolve_window_title_target_in_region(
        &mut self,
        window_id: &str,
        region: Rect,
    ) -> AutomationResult<WindowFrameTarget> {
        if !region.is_actionable() {
            return Err(AutomationError::with_details(
                ErrorCode::WindowTitleRegionUnavailable,
                "the semantic title region has no actionable bounds",
                json!({"window_id": window_id, "region": region}),
            ));
        }
        let (hwnd, info) = self.resolve_window(window_id)?;
        if !rect_contains_rect(info.bounds, region) {
            return Err(AutomationError::with_details(
                ErrorCode::WindowTitleRegionUnavailable,
                "the semantic title region is outside the fresh top-level window bounds",
                json!({"window_id": window_id, "window_bounds": info.bounds, "region": region}),
            ));
        }
        let dpi = window_dpi(hwnd)?;
        find_frame_target(
            hwnd,
            info.bounds,
            dpi,
            WindowFrameTargetKind::Title,
            Some(region),
        )?
        .ok_or_else(|| {
            AutomationError::with_details(
                ErrorCode::WindowTitleRegionUnavailable,
                "no point in the semantic title region produced HTCAPTION",
                json!({"window_id": window_id, "region": region, "dpi": dpi}),
            )
        })
    }

    /// Programmatic state transition for setup/recovery. It is deliberately
    /// separate from physical title-bar gestures and reports failure as data.
    pub fn set_window_state(
        &mut self,
        window_id: &str,
        requested_state: WindowState,
    ) -> AutomationResult<WindowStateResult> {
        let desktop_guard = self.acquire_desktop_guard(window_id)?;
        let (hwnd, _) = self.resolve_window(window_id)?;
        let previous_state = current_window_state(hwnd);
        let command = match requested_state {
            WindowState::Normal => SW_RESTORE,
            WindowState::Minimized => SW_MINIMIZE,
            WindowState::Maximized => SW_MAXIMIZE,
        };
        if let Some(guard) = &desktop_guard {
            guard.validate_before_dispatch().map_err(desktop_arbiter_backend_error)?;
        }
        unsafe {
            let _ = ShowWindow(hwnd, command);
        }
        let deadline =
            std::time::Instant::now() + Duration::from_millis(WINDOW_STATE_POLL_TIMEOUT_MS);
        let mut actual_state = current_window_state(hwnd);
        while actual_state != requested_state && std::time::Instant::now() < deadline {
            // A minimized maximized window first restores to its prior
            // maximized presentation. `normal` is a literal requested state,
            // so issue the second restore only after the first readback proves
            // that intermediate state.
            if requested_state == WindowState::Normal && actual_state == WindowState::Maximized {
                if let Some(guard) = &desktop_guard {
                    guard.validate_before_dispatch().map_err(desktop_arbiter_backend_error)?;
                }
                unsafe {
                    let _ = ShowWindow(hwnd, SW_RESTORE);
                }
            }
            thread::sleep(Duration::from_millis(WINDOW_STATE_POLL_MS));
            actual_state = current_window_state(hwnd);
        }
        Ok(WindowStateResult {
            window_id: window_id.to_owned(),
            requested_state,
            previous_state,
            actual_state,
            actual_bounds: window_rect(hwnd)?,
            success: actual_state == requested_state,
        })
    }

    pub fn get_control_tree(
        &mut self,
        window_id: &str,
        options: &ControlTreeOptions,
    ) -> AutomationResult<ControlTreeResult> {
        let (_, root) = self.resolve_window_root(window_id)?;
        let walker = unsafe {
            match options.view {
                TreeView::Control => self.automation.ControlViewWalker(),
                TreeView::Raw => self.automation.RawViewWalker(),
            }
        }
        .map_err(|error| {
            uia_backend_error("failed to acquire the UI Automation tree walker", error)
        })?;

        let max_elements = options
            .max_elements
            .unwrap_or(MAX_DEFAULT_ELEMENTS)
            .clamp(1, MAX_ALLOWED_ELEMENTS);
        let max_depth = options.max_depth.unwrap_or(MAX_DEFAULT_DEPTH).min(256);

        let root_id = self.register_element(window_id, root.clone(), None)?;
        let mut all = Vec::new();
        all.push(self.control_info_for(&root_id)?);
        let mut truncated = false;
        self.walk_children(
            window_id,
            &walker,
            &root,
            &root_id,
            1,
            max_depth,
            max_elements,
            &mut all,
            &mut truncated,
        )?;
        let total_enumerated = all.len();
        let elements = all
            .into_iter()
            .filter(|element| options.query.matches(element))
            .collect();

        Ok(ControlTreeResult {
            window_id: window_id.to_owned(),
            backend: "Microsoft UI Automation".into(),
            view: options.view,
            elements,
            total_enumerated,
            truncated,
        })
    }

    pub fn find_control(
        &mut self,
        window_id: &str,
        query: &ControlQuery,
    ) -> AutomationResult<ControlInfo> {
        let tree = self.get_control_tree(
            window_id,
            &ControlTreeOptions {
                query: query.without_index(),
                max_depth: None,
                max_elements: None,
                view: TreeView::Control,
            },
        )?;
        let candidates = tree.elements;
        if let Some(index) = query.index {
            return candidates.get(index).cloned().ok_or_else(|| {
                AutomationError::with_details(
                    ErrorCode::ElementNotFound,
                    format!(
                        "control index {index} is outside {} filtered candidates",
                        candidates.len()
                    ),
                    json!({"query": query, "candidates": candidates}),
                )
            });
        }
        match candidates.len() {
            0 => Err(AutomationError::with_details(
                ErrorCode::ElementNotFound,
                "no accessible element matched the query",
                query,
            )),
            1 => Ok(candidates.into_iter().next().expect("one candidate")),
            count => Err(AutomationError::with_details(
                ErrorCode::AmbiguousElement,
                format!("{count} accessible elements matched; add a discriminator"),
                json!({
                    "query": query,
                    "candidates": candidates.into_iter().take(100).collect::<Vec<_>>()
                }),
            )),
        }
    }

    pub fn find_automation_id(
        &mut self,
        window_id: &str,
        automation_id: &str,
    ) -> AutomationResult<ControlInfo> {
        if automation_id.trim().is_empty() {
            return Err(AutomationError::invalid_argument(
                "automation_id must not be empty",
            ));
        }
        self.find_control(
            window_id,
            &ControlQuery {
                automation_id: Some(automation_id.to_owned()),
                ..Default::default()
            },
        )
    }

    pub fn click_automation_id(
        &mut self,
        window_id: &str,
        automation_id: &str,
    ) -> AutomationResult<ClickResult> {
        let control = self.find_automation_id(window_id, automation_id)?;
        self.click_element(window_id, &control.element_id)
    }

    pub fn focus_automation_id(
        &mut self,
        window_id: &str,
        automation_id: &str,
    ) -> AutomationResult<ElementState> {
        let control = self.find_automation_id(window_id, automation_id)?;
        self.focus_element(window_id, &control.element_id)
    }

    pub fn send_keys_to_automation_id(
        &mut self,
        window_id: &str,
        automation_id: &str,
        keys: &str,
    ) -> AutomationResult<SendKeysResult> {
        let control = self.find_automation_id(window_id, automation_id)?;
        let mut desktop_guard = self.acquire_desktop_guard(window_id)?;
        // Re-resolve after a potentially long queue wait, then activate the
        // owned window before asking its event loop to focus the control.
        let (resolved_id, info, element, _) =
            self.resolve_action_target(window_id, &control.element_id)?;
        if !info.enabled {
            return Err(AutomationError::with_details(
                ErrorCode::ActionNotSupported,
                "cannot focus a disabled accessible element",
                &info,
            ));
        }
        self.focus_window_inner(window_id, desktop_guard.as_ref())?;
        let focus_result =
            self.focus_element_action(window_id, &resolved_id, &element, desktop_guard.as_ref());
        let mut state = focus_result.map_err(|error| {
            if let Some(guard) = desktop_guard.as_mut() {
                // A provider may have accepted an asynchronous focus request
                // even when its completion/readback is unavailable.
                guard.mark_input_state_uncertain();
            }
            error
        })?;
        let focus_deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !state.focused {
            if let Some(guard) = desktop_guard.as_ref() {
                guard
                    .validate_before_dispatch()
                    .map_err(desktop_arbiter_backend_error)?;
            }
            let observed_window = self.resolve_window(window_id).map_err(|error| {
                if let Some(guard) = desktop_guard.as_mut() {
                    guard.mark_input_state_uncertain();
                }
                error
            })?;
            if std::time::Instant::now() >= focus_deadline
                || unsafe { GetForegroundWindow() } != observed_window.0
            {
                if let Some(guard) = desktop_guard.as_mut() {
                    guard.mark_input_state_uncertain();
                }
                return Err(AutomationError::with_details(
                    ErrorCode::WindowNotFocused,
                    "target control did not acquire observed keyboard focus; input refused",
                    &state,
                ));
            }
            thread::sleep(Duration::from_millis(15));
            state = self
                .get_element_state(window_id, &resolved_id)
                .map_err(|error| {
                    if let Some(guard) = desktop_guard.as_mut() {
                        guard.mark_input_state_uncertain();
                    }
                    error
                })?;
        }
        self.send_input_batch_inner(
            window_id,
            keys,
            key_inputs(keys)?,
            &mut desktop_guard,
            Some(&resolved_id),
        )
    }

    pub fn get_automation_id_state(
        &mut self,
        window_id: &str,
        automation_id: &str,
    ) -> AutomationResult<ElementState> {
        let control = self.find_automation_id(window_id, automation_id)?;
        self.get_element_state(window_id, &control.element_id)
    }

    pub fn set_value_automation_id(
        &mut self,
        window_id: &str,
        automation_id: &str,
        value: &str,
    ) -> AutomationResult<ElementState> {
        let control = self.find_automation_id(window_id, automation_id)?;
        self.set_value(window_id, &control.element_id, value)
    }

    pub fn click_element(
        &mut self,
        window_id: &str,
        element_id: &str,
    ) -> AutomationResult<ClickResult> {
        let window_guard = self.acquire_window_guard(window_id, false)?;
        let (resolved_id, info, element, owner_hwnd) =
            self.resolve_action_target(window_id, element_id)?;
        let before_state = self.get_element_state(window_id, &resolved_id)?;
        let mut action_method = None;
        let mut invocation_error = None;

        unsafe {
            match element.GetCurrentPatternAs::<IUIAutomationInvokePattern>(UIA_InvokePatternId) {
                Ok(pattern) => {
                    if let Some(guard) = &window_guard {
                        guard
                            .validate_before_dispatch()
                            .map_err(desktop_arbiter_backend_error)?;
                    }
                    match pattern.Invoke() {
                        Ok(()) => action_method = Some("InvokePattern".to_owned()),
                        Err(error) if is_stale_error(&error) => {
                            return Err(stale_element_error(&resolved_id, error));
                        }
                        Err(error) => {
                            return Err(invoke_dispatch_indeterminate_error(error));
                        }
                    }
                }
                Err(error) if is_stale_error(&error) => {
                    return Err(stale_element_error(&resolved_id, error));
                }
                Err(_) => {}
            }
        }

        if action_method.is_none() {
            unsafe {
                match element.GetCurrentPatternAs::<IUIAutomationSelectionItemPattern>(
                    UIA_SelectionItemPatternId,
                ) {
                    Ok(pattern) => {
                        if let Some(guard) = &window_guard {
                            guard
                                .validate_before_dispatch()
                                .map_err(desktop_arbiter_backend_error)?;
                        }
                        match pattern.Select() {
                            Ok(()) => action_method = Some("SelectionItem.Select".to_owned()),
                            Err(error) if is_stale_error(&error) => {
                                return Err(stale_element_error(&resolved_id, error));
                            }
                            Err(error) => {
                                return Err(windows_error(
                                        ErrorCode::InvocationFailed,
                                        "UI Automation SelectionItem.Select failed",
                                        error,
                                    ));
                            }
                        }
                    }
                    Err(error) if is_stale_error(&error) => {
                        return Err(stale_element_error(&resolved_id, error));
                    }
                    Err(_) => {}
                }
            }
        }

        if action_method.is_none() && matches!(info.control_type.as_str(), "Edit" | "Document") {
            let desktop_guard = self.acquire_desktop_guard(window_id)?;
            if let Some(guard) = &desktop_guard {
                guard
                    .validate_before_dispatch()
                    .map_err(desktop_arbiter_backend_error)?;
            }
            unsafe { element.SetFocus() }.map_err(|error| {
                if is_stale_error(&error) {
                    stale_element_error(&resolved_id, error)
                } else {
                    windows_error(
                        ErrorCode::ActionNotSupported,
                        "UI Automation could not focus the editable element",
                        error,
                    )
                }
            })?;
            action_method = Some("SetFocus".to_owned());
        }
        if action_method.is_none() && info.control_type == "Button" {
            let child = unsafe { element.CurrentNativeWindowHandle() };
            match child {
                Ok(child) if !child.0.is_null() && top_level_ancestor(child) == owner_hwnd => {
                    if let Some(guard) = &window_guard {
                        guard.validate_before_dispatch().map_err(desktop_arbiter_backend_error)?;
                    }
                    unsafe {
                        SendMessageW(child, BM_CLICK, Some(WPARAM(0)), Some(LPARAM(0)));
                    }
                    action_method = Some("BM_CLICK".to_owned());
                }
                Err(error) if is_stale_error(&error) => {
                    return Err(stale_element_error(&resolved_id, error));
                }
                _ => {}
            }
        }

        if action_method.is_none() && info.control_type == "Button" {
            let mut desktop_guard = self.acquire_desktop_guard(window_id)?;
            match self.keyboard_activate(window_id, &element, &mut desktop_guard) {
                Ok(()) => action_method = Some("KeyboardActivation".to_owned()),
                Err(error) => {
                    invocation_error.get_or_insert(error);
                }
            }
        }

        let action_method = match action_method {
            Some(method) => method,
            None => {
                return Err(invocation_error.unwrap_or_else(|| {
                    AutomationError::with_details(
                        ErrorCode::ActionNotSupported,
                        "element has no supported UIA/native activation pattern",
                        json!({
                            "element_id": resolved_id,
                            "automation_id": info.automation_id,
                            "owner_hwnd": format_hwnd(owner_hwnd),
                            "control_type": info.control_type,
                        }),
                    )
                }));
            }
        };

        thread::sleep(Duration::from_millis(60));
        let (after_state, after_error) = match self.get_element_state(window_id, &resolved_id) {
            Ok(state) => (Some(state), None),
            Err(error) => (None, Some(error)),
        };
        Ok(ClickResult {
            success: true,
            resolved_element: info,
            action_method,
            before_state,
            after_state,
            after_error,
        })
    }

    fn keyboard_activate(
        &mut self,
        window_id: &str,
        element: &IUIAutomationElement,
        desktop_guard: &mut Option<DesktopArbiterGuard>,
    ) -> AutomationResult<()> {
        self.focus_window_inner(window_id, desktop_guard.as_ref())?;
        if let Some(guard) = desktop_guard.as_ref() {
            guard.validate_before_dispatch().map_err(desktop_arbiter_backend_error)?;
        }
        unsafe { element.SetFocus() }.map_err(|error| {
            if is_stale_error(&error) {
                stale_element_error("keyboard-activation", error)
            } else {
                windows_error(
                    ErrorCode::InvocationFailed,
                    "UI Automation could not focus the element for keyboard activation",
                    error,
                )
            }
        })?;
        thread::sleep(Duration::from_millis(40));
        if desktop_guard.is_some()
            && unsafe { GetForegroundWindow() } != self.resolve_window(window_id)?.0
        {
            return Err(AutomationError::new(
                ErrorCode::WindowNotFocused,
                "foreground changed before guarded keyboard activation; input refused",
            ));
        }
        let inputs = [
            keyboard_input(VK_RETURN, false),
            keyboard_input(VK_RETURN, true),
        ];
        if let Some(guard) = desktop_guard.as_ref() {
            guard.validate_before_dispatch().map_err(desktop_arbiter_backend_error)?;
        }
        let injected = unsafe { SendInput(&inputs, size_of::<INPUT>() as i32) };
        if injected as usize != inputs.len() {
            if let Some(guard) = desktop_guard.as_mut() {
                guard.mark_input_state_uncertain();
            }
            return Err(AutomationError::with_details(
                ErrorCode::InputInjectionFailed,
                "keyboard activation did not submit every event",
                json!({"requested": inputs.len(), "injected": injected}),
            ));
        }
        Ok(())
    }
    pub fn focus_element(
        &mut self,
        window_id: &str,
        element_id: &str,
    ) -> AutomationResult<ElementState> {
        let (resolved_id, info, element, _) = self.resolve_action_target(window_id, element_id)?;
        if !info.enabled {
            return Err(AutomationError::with_details(
                ErrorCode::ActionNotSupported,
                "cannot focus a disabled accessible element",
                &info,
            ));
        }
        let desktop_guard = self.acquire_desktop_guard(window_id)?;
        self.focus_element_action(window_id, &resolved_id, &element, desktop_guard.as_ref())
    }

    fn focus_element_action(
        &mut self,
        window_id: &str,
        resolved_id: &str,
        element: &IUIAutomationElement,
        guard: Option<&DesktopArbiterGuard>,
    ) -> AutomationResult<ElementState> {
        if let Some(guard) = guard {
            guard
                .validate_before_dispatch()
                .map_err(desktop_arbiter_backend_error)?;
        }
        unsafe { element.SetFocus() }.map_err(|error| {
            if is_stale_error(&error) {
                stale_element_error(resolved_id, error)
            } else {
                windows_error(
                    ErrorCode::ActionNotSupported,
                    "UI Automation could not focus the accessible element",
                    error,
                )
            }
        })?;
        thread::sleep(Duration::from_millis(40));
        self.get_element_state(window_id, resolved_id)
    }
    pub fn send_keys(&mut self, window_id: &str, keys: &str) -> AutomationResult<SendKeysResult> {
        self.send_input_batch(window_id, keys, key_inputs(keys)?)
    }

    /// Sends literal text as Unicode input, independently of the active
    /// Windows keyboard layout. Named keys and chords intentionally remain
    /// the responsibility of `send_keys`.
    pub fn send_text(&mut self, window_id: &str, text: &str) -> AutomationResult<SendKeysResult> {
        self.send_input_batch(window_id, text, text_inputs(text)?)
    }

    /// Sends one named virtual key repeatedly in a single, foreground-verified
    /// SendInput batch. This is intentionally separate from `send_keys` so
    /// literal text such as `DOWN*99` remains safe for `type_text`.
    pub fn send_key_repeat(
        &mut self,
        window_id: &str,
        key: &str,
        count: usize,
    ) -> AutomationResult<SendKeysResult> {
        let key = key.trim();
        let requested_keys = format!("{key}*{count}");
        self.send_input_batch(
            window_id,
            &requested_keys,
            repeated_named_key_inputs(key, count)?,
        )
    }

    fn send_input_batch(
        &mut self,
        window_id: &str,
        requested_keys: &str,
        inputs: Vec<INPUT>,
    ) -> AutomationResult<SendKeysResult> {
        let mut desktop_guard = self.acquire_desktop_guard(window_id)?;
        self.send_input_batch_inner(window_id, requested_keys, inputs, &mut desktop_guard, None)
    }

    fn send_input_batch_inner(
        &mut self,
        window_id: &str,
        requested_keys: &str,
        inputs: Vec<INPUT>,
        desktop_guard: &mut Option<DesktopArbiterGuard>,
        required_focused_element: Option<&str>,
    ) -> AutomationResult<SendKeysResult> {
        const FOCUS_ATTEMPTS: usize = 5;
        const RETRY_DELAY_MS: u64 = 75;

        if input_batch_uses_clipboard(&inputs) {
            if let Some(guard) = desktop_guard.as_ref() {
                guard
                    .require_clipboard_transaction()
                    .map_err(desktop_arbiter_backend_error)?;
            }
        }

        let (target_hwnd, target_window) = self.resolve_window(window_id)?;
        let mut focus_attempts = Vec::new();
        for attempt in 1..=FOCUS_ATTEMPTS {
            let foreground_before = unsafe { GetForegroundWindow() };
            if required_focused_element.is_some() && foreground_before != target_hwnd {
                return Err(AutomationError::new(
                    ErrorCode::WindowNotFocused,
                    "foreground changed after control focus; input refused without reactivation",
                ));
            }
            let focus_acquisition = if foreground_before == target_hwnd {
                let foreground = self.foreground_ref(foreground_before);
                Ok(FocusResult {
                    requested_window: target_window.clone(),
                    previous_foreground: foreground.clone(),
                    resulting_foreground: foreground,
                    success: true,
                })
            } else {
                self.focus_window_inner(window_id, desktop_guard.as_ref())
            };
            match focus_acquisition {
                Ok(focus_acquisition) => {
                    let foreground = unsafe { GetForegroundWindow() };
                    if foreground == target_hwnd {
                        if let Some(element_id) = required_focused_element {
                            let state = self.get_element_state(window_id, element_id)?;
                            if !state.focused
                                || !state.enabled
                                || unsafe { GetForegroundWindow() } != target_hwnd
                            {
                                return Err(AutomationError::with_details(
                                    ErrorCode::WindowNotFocused,
                                    "control focus changed before keyboard dispatch; input refused",
                                    &state,
                                ));
                            }
                        }
                        if let Some(guard) = desktop_guard.as_ref() {
                            guard
                                .validate_before_dispatch()
                                .map_err(desktop_arbiter_backend_error)?;
                        }
                        let injected = unsafe { SendInput(&inputs, size_of::<INPUT>() as i32) };
                        if injected as usize != inputs.len() {
                            if let Some(guard) = desktop_guard.as_mut() {
                                guard.mark_input_state_uncertain();
                            }
                            return Err(AutomationError::with_details(
                                ErrorCode::InputInjectionFailed,
                                "SendInput did not inject every requested keyboard event",
                                json!({
                                    "window_id": window_id,
                                    "keys": requested_keys,
                                    "requested": inputs.len(),
                                    "injected": injected
                                }),
                            ));
                        }
                        return Ok(SendKeysResult {
                            target_window,
                            requested_keys: requested_keys.to_owned(),
                            focus_acquisition,
                            input_events_requested: inputs.len(),
                            input_events_injected: injected as usize,
                            success: true,
                        });
                    }
                    focus_attempts.push(json!({
                        "attempt": attempt,
                        "focus_acquisition": focus_acquisition,
                        "resulting_foreground": self.foreground_ref(foreground),
                    }));
                }
                Err(error) if error.code == ErrorCode::WindowNotFocused => {
                    focus_attempts.push(json!({
                        "attempt": attempt,
                        "focus_error": error,
                    }));
                }
                Err(error) => return Err(error),
            }
            if attempt < FOCUS_ATTEMPTS {
                thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
            }
        }
        Err(AutomationError::with_details(
            ErrorCode::WindowNotFocused,
            "target window did not become foreground before keyboard input after retries",
            json!({
                "window_id": window_id,
                "keys": requested_keys,
                "attempts": focus_attempts,
            }),
        ))
    }
    pub fn set_value(
        &mut self,
        window_id: &str,
        element_id: &str,
        value: &str,
    ) -> AutomationResult<ElementState> {
        let window_guard = self.acquire_window_guard(window_id, false)?;
        let (resolved_id, info, element, _) = self.resolve_action_target(window_id, element_id)?;
        if !info.enabled {
            return Err(AutomationError::with_details(
                ErrorCode::ActionNotSupported,
                "cannot set value on a disabled accessible element",
                &info,
            ));
        }
        let pattern = unsafe {
            element
                .GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
                .map_err(|error| {
                    if is_stale_error(&error) {
                        stale_element_error(&resolved_id, error)
                    } else {
                        windows_error(
                            ErrorCode::ActionNotSupported,
                            "UI Automation could not resolve a value pattern for the element",
                            error,
                        )
                    }
                })?
        };
        let value = value_pattern_bstr(value, &info.framework_id);
        if let Some(guard) = &window_guard {
            guard
                .validate_before_dispatch()
                .map_err(desktop_arbiter_backend_error)?;
        }
        unsafe { pattern.SetValue(&value) }.map_err(|error| {
            if is_stale_error(&error) {
                stale_element_error(&resolved_id, error)
            } else {
                windows_error(
                    ErrorCode::ActionNotSupported,
                    "UI Automation could not set the element value",
                    error,
                )
            }
        })?;
        thread::sleep(Duration::from_millis(60));
        self.get_element_state(window_id, &resolved_id)
    }
    pub fn get_element_state(
        &mut self,
        window_id: &str,
        element_id: &str,
    ) -> AutomationResult<ElementState> {
        let info = self.control_info_for_owned(window_id, element_id)?;
        let element = self.element_record(window_id, element_id)?.element.clone();
        let value = unsafe {
            match element.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId) {
                Ok(pattern) => pattern.CurrentValue().ok().map(|value| value.to_string()),
                Err(error) if is_stale_error(&error) => {
                    return Err(stale_element_error(element_id, error));
                }
                Err(_) => None,
            }
        };
        let text = if info.control_type == "Text" {
            info.value.clone().or_else(|| Some(info.name.clone()))
        } else if info.control_type == "Edit" || info.control_type == "Document" {
            value.clone()
        } else {
            None
        };
        Ok(ElementState {
            exists: true,
            element_id: element_id.to_owned(),
            window_id: window_id.to_owned(),
            visible: info.visible,
            enabled: info.enabled,
            focused: info.focused,
            selected: info.selected,
            name: info.name,
            control_type: info.control_type,
            bounds: info.bounds,
            value,
            text,
        })
    }

    pub fn set_window_bounds(
        &mut self,
        window_id: &str,
        x: Option<i32>,
        y: Option<i32>,
        width: i32,
        height: i32,
    ) -> AutomationResult<WindowBoundsResult> {
        let _dpi = CaptureDpiScope::enter()?;
        if width <= 0 || height <= 0 {
            return Err(AutomationError::invalid_argument(
                "window width and height must both be positive",
            ));
        }
        let desktop_guard = self.acquire_desktop_guard(window_id)?;
        let (hwnd, info) = self.resolve_window(window_id)?;
        let requested = Rect {
            x: x.unwrap_or(info.bounds.x),
            y: y.unwrap_or(info.bounds.y),
            width,
            height,
        };
        if let Some(guard) = &desktop_guard {
            guard.validate_before_dispatch().map_err(desktop_arbiter_backend_error)?;
        }
        unsafe {
            SetWindowPos(
                hwnd,
                None,
                requested.x,
                requested.y,
                requested.width,
                requested.height,
                SWP_NOZORDER | SWP_NOACTIVATE,
            )
        }
        .map_err(|error| {
            windows_error(
                ErrorCode::BackendFailure,
                "SetWindowPos failed for the resolved window",
                error,
            )
        })?;
        thread::sleep(Duration::from_millis(80));
        let actual = window_rect(hwnd)?;
        Ok(WindowBoundsResult {
            requested_bounds: requested,
            actual_bounds: actual,
            success: actual == requested,
        })
    }

    pub fn capture_window(
        &mut self,
        window_id: &str,
        output_path: Option<&str>,
    ) -> AutomationResult<CaptureResult> {
        // GetWindowRect is virtualized for a DPI-unaware caller, whereas
        // PrintWindow paints physical pixels. Scope only the capture thread so
        // high-DPI fixtures are not silently cropped; restore on every exit.
        let _capture_dpi = CaptureDpiScope::enter()?;
        let (hwnd, info) = self.resolve_window(window_id)?;
        let path = output_path
            .map(PathBuf::from)
            .unwrap_or_else(|| default_capture_path(window_id));
        // PrintWindow renders in the TARGET window's awareness space. An
        // unaware target paints 760x560, not 950x700, into the supplied DC.
        // Preserve that complete lossless source, rather than padding it or
        // pretending resampled pixels are native physical pixels.
        let captured = {
            let target_context = unsafe { windows::Win32::UI::HiDpi::GetWindowDpiAwarenessContext(hwnd) };
            let _target_dpi = CaptureDpiScope::enter_context(target_context)?;
            let drawing_bounds = window_rect_in_current_context(hwnd)?;
            capture_pixels(hwnd, drawing_bounds)?
        };
        if window_rect(hwnd)? != info.bounds {
            return Err(AutomationError::new(ErrorCode::CoordinateMappingUnverified,
                "window geometry changed during capture; no mapping is returned"));
        }
        let mut captured = captured;
        captured.diagnostics.push(
            "bounds=SCREEN_PHYSICAL_PIXEL; image=CAPTURE_PIXEL; PrintWindow=target_window_dpi_context; no resampling".into(),
        );
        let client_rect = physical_client_rect(hwnd)?;
        let record = self.windows.get(window_id).expect("resolved window record");
        let birth = record.process_birth.ok_or_else(|| AutomationError::new(
            ErrorCode::CoordinateMappingUnverified, "process birth is unavailable"))?;
        let mut geometry = crate::CaptureGeometry {
            window_id: window_id.into(), hwnd: info.hwnd.clone(), pid: info.process_id, process_birth: birth,
            monitor_identity: format!("{:?}", unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) }),
            geometry_generation: 1,
            inspection_coordinate_space: "SCREEN_PHYSICAL_PIXEL".into(),
            capture_coordinate_space: "CAPTURE_PIXEL".into(), screen_coordinate_space: "SCREEN_PHYSICAL_PIXEL".into(),
            window_rect_screen_physical: info.bounds,
            client_rect_screen_physical: client_rect,
            content_rect_capture_pixels: Rect { x:0,y:0,width:captured.width as i32,height:captured.height as i32 },
            capture_width_pixels:captured.width, capture_height_pixels:captured.height,
            target_window_dpi: unsafe { GetDpiForWindow(hwnd) }, monitor_scale_percent: monitor_scale_percent(hwnd)?,
            dpi_awareness_context:"inspection=PER_MONITOR_AWARE_V2; capture=target_window_context".into(),
            transform_provenance:"physical GetWindowRect + physical ClientToScreen; source GetWindowRect in target DPI context; rational scale and translation".into(),
            // A complete bitmap is not independent proof of an arbitrary
            // application's PrintWindow footprint. Image->input stays closed.
            mapping_verified:false,
        };
        if let Some(previous) = self.capture_geometries.get(window_id) {
            geometry.geometry_generation = previous.geometry_generation;
            if previous != &geometry { geometry.geometry_generation = previous.geometry_generation.checked_add(1)
                .ok_or_else(|| AutomationError::new(ErrorCode::CoordinateMappingUnverified, "geometry generation exhausted"))?; }
        }
        self.capture_geometries.insert(window_id.into(), geometry.clone());
        write_png(&path, captured.width, captured.height, &captured.pixels)?;
        Ok(CaptureResult {
            window_id: window_id.to_owned(),
            backend: "windows-gdi".into(),
            hwnd: info.hwnd,
            pid: info.process_id,
            path: path.to_string_lossy().into_owned(),
            bounds: info.bounds,
            dimensions: CaptureDimensions {
                width: captured.width,
                height: captured.height,
            },
            timestamp_unix_ms: now_unix_ms(),
            image_width: captured.width,
            image_height: captured.height,
            capture_method: captured.method,
            non_blank: captured.non_blank,
            occlusion_independent: captured.occlusion_independent,
            gpu_compatible: captured.gpu_compatible,
            fallback_used: captured.fallback_used,
            diagnostics: captured.diagnostics,
            limitations: vec![
                "PrintWindow support is application-defined; GPU surfaces may require visible BitBlt fallback."
                    .into(),
            ],
            geometry: Some(geometry),
        })
    }

    /// Revalidates the current native identity and mapping before converting an
    /// image pixel. The pure CaptureGeometry transform alone is NOT authority
    /// to dispatch input; callers must also hold/fence a DesktopInput reservation.
    pub fn capture_point_to_screen(
        &mut self, geometry: &crate::CaptureGeometry, x: u32, y: u32,
    ) -> AutomationResult<ScreenPoint> {
        let _dpi = CaptureDpiScope::enter()?;
        let (hwnd, info) = self.resolve_window(&geometry.window_id)?;
        let current_monitor = format!("{:?}", unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) });
        if self.capture_geometries.get(&geometry.window_id) != Some(geometry)
            || geometry.window_rect_screen_physical != info.bounds
            || geometry.client_rect_screen_physical != physical_client_rect(hwnd)?
            || geometry.monitor_identity != current_monitor
            || geometry.monitor_scale_percent != monitor_scale_percent(hwnd)?
            || geometry.target_window_dpi != unsafe { GetDpiForWindow(hwnd) }
        {
            return Err(AutomationError::new(ErrorCode::CoordinateMappingUnverified,
                "native geometry/identity differs from the captured generation"));
        }
        geometry.capture_to_screen(x, y, geometry.geometry_generation)
    }

    pub fn focus_window(&mut self, window_id: &str) -> AutomationResult<FocusResult> {
        let desktop_guard = self.acquire_desktop_guard(window_id)?;
        self.focus_window_inner(window_id, desktop_guard.as_ref())
    }

    fn focus_window_inner(
        &mut self,
        window_id: &str,
        guard: Option<&DesktopArbiterGuard>,
    ) -> AutomationResult<FocusResult> {
        let (hwnd, requested_window) = self.resolve_window(window_id)?;
        let previous_hwnd = unsafe { GetForegroundWindow() };
        let previous_foreground = self.foreground_ref(previous_hwnd);

        unsafe {
            if let Some(guard) = guard {
                guard
                    .validate_before_dispatch()
                    .map_err(desktop_arbiter_backend_error)?;
            }
            if IsIconic(hwnd).as_bool() {
                let _ = ShowWindow(hwnd, SW_RESTORE);
            } else {
                let _ = ShowWindow(hwnd, SW_SHOW);
            }
            let current_thread = GetCurrentThreadId();
            let target_thread = GetWindowThreadProcessId(hwnd, None);
            let foreground_thread = if previous_hwnd.0.is_null() {
                0
            } else {
                GetWindowThreadProcessId(previous_hwnd, None)
            };
            let attached_target = target_thread != 0
                && target_thread != current_thread
                && AttachThreadInput(current_thread, target_thread, true).as_bool();
            let attached_foreground = foreground_thread != 0
                && foreground_thread != current_thread
                && foreground_thread != target_thread
                && AttachThreadInput(current_thread, foreground_thread, true).as_bool();

            let _ = BringWindowToTop(hwnd);
            let fence = guard
                .map(|guard| {
                    guard
                        .validate_before_dispatch()
                        .map_err(desktop_arbiter_backend_error)
                })
                .transpose();
            if fence.is_ok() {
                let _ = SetForegroundWindow(hwnd);
            }

            if attached_foreground {
                let _ = AttachThreadInput(current_thread, foreground_thread, false);
            }
            if attached_target {
                let _ = AttachThreadInput(current_thread, target_thread, false);
            }
            fence?;
        }
        thread::sleep(Duration::from_millis(80));
        let resulting_hwnd = unsafe { GetForegroundWindow() };
        let root = if resulting_hwnd.0.is_null() {
            resulting_hwnd
        } else {
            unsafe { GetAncestor(resulting_hwnd, GA_ROOT) }
        };
        let resulting_foreground = self.foreground_ref(resulting_hwnd);
        let result = FocusResult {
            requested_window,
            previous_foreground,
            resulting_foreground,
            success: root == hwnd,
        };
        if !result.success {
            return Err(AutomationError::with_details(
                ErrorCode::WindowNotFocused,
                "Windows foreground restrictions prevented deterministic focus acquisition",
                &result,
            ));
        }
        Ok(result)
    }

    fn resolve_window_root(
        &mut self,
        window_id: &str,
    ) -> AutomationResult<(HWND, IUIAutomationElement)> {
        let (registered_hwnd, _) = self.resolve_window(window_id)?;
        let owner_hwnd = top_level_ancestor(registered_hwnd);
        if owner_hwnd.0.is_null() {
            return Err(AutomationError::with_details(
                ErrorCode::OwnerHwndUnavailable,
                "the registered window has no live top-level owner HWND",
                json!({"window_id": window_id}),
            ));
        }
        let root = self.resolve_uia_root(window_id, owner_hwnd)?;
        Ok((owner_hwnd, root))
    }

    fn resolve_uia_root(
        &mut self,
        window_id: &str,
        owner_hwnd: HWND,
    ) -> AutomationResult<IUIAutomationElement> {
        let mut last_error = None;
        for attempt in 1..=UIA_ROOT_RESOLVE_ATTEMPTS {
            match unsafe { self.automation.ElementFromHandle(owner_hwnd) } {
                Ok(root) => return Ok(root),
                Err(error) if is_transient_root_error(&error) => {
                    last_error = Some(error);
                    if attempt < UIA_ROOT_RESOLVE_ATTEMPTS {
                        thread::sleep(Duration::from_millis(UIA_ROOT_RETRY_DELAY_MS));
                    }
                }
                Err(error) => {
                    return Err(AutomationError::with_details(
                        ErrorCode::AccessibilityUnavailable,
                        "UI Automation could not resolve the live top-level window",
                        json!({
                            "window_id": window_id,
                            "owner_hwnd": format_hwnd(owner_hwnd),
                            "hresult": format!("0x{:08X}", error.code().0 as u32),
                            "attempt": attempt,
                        }),
                    ));
                }
            }
        }
        let error = last_error.expect("root resolution must record the last error");
        Err(AutomationError::with_details(
            ErrorCode::AccessibilityUnavailable,
            "UI Automation could not resolve the live top-level window after retries",
            json!({
                "window_id": window_id,
                "owner_hwnd": format_hwnd(owner_hwnd),
                "hresult": format!("0x{:08X}", error.code().0 as u32),
                "attempts": UIA_ROOT_RESOLVE_ATTEMPTS,
            }),
        ))
    }

    fn resolve_owner_hwnd(
        &mut self,
        window_id: &str,
        element: &IUIAutomationElement,
    ) -> AutomationResult<HWND> {
        let (registered_hwnd, window_info) = self.resolve_window(window_id)?;
        let owner_hwnd = top_level_ancestor(registered_hwnd);
        if owner_hwnd.0.is_null() {
            return Err(AutomationError::with_details(
                ErrorCode::OwnerHwndUnavailable,
                "the target window has no top-level owner HWND",
                json!({"window_id": window_id}),
            ));
        }
        let mut owner_process_id = 0;
        unsafe { GetWindowThreadProcessId(owner_hwnd, Some(&mut owner_process_id)) };
        if owner_process_id != window_info.process_id {
            return Err(AutomationError::with_details(
                ErrorCode::OwnerHwndUnavailable,
                "the resolved owner HWND belongs to a different process",
                json!({
                    "window_id": window_id,
                    "owner_hwnd": format_hwnd(owner_hwnd),
                    "expected_process_id": window_info.process_id,
                    "actual_process_id": owner_process_id,
                }),
            ));
        }

        let root = self.resolve_uia_root(window_id, owner_hwnd)?;
        let window_pattern_available = unsafe {
            root.GetCurrentPatternAs::<IUIAutomationWindowPattern>(UIA_WindowPatternId)
                .is_ok()
        };
        let native =
            unsafe { element.CurrentNativeWindowHandle().ok() }.filter(|hwnd| !hwnd.0.is_null());
        if let Some(native_hwnd) = native {
            let native_root = top_level_ancestor(native_hwnd);
            let mut native_process_id = 0;
            unsafe { GetWindowThreadProcessId(native_hwnd, Some(&mut native_process_id)) };
            if native_root != owner_hwnd || native_process_id != window_info.process_id {
                return Err(AutomationError::with_details(
                    ErrorCode::OwnerHwndUnavailable,
                    "the element native HWND is not owned by the target top-level window",
                    json!({
                        "window_id": window_id,
                        "owner_hwnd": format_hwnd(owner_hwnd),
                        "native_hwnd": format_hwnd(native_hwnd),
                        "native_root_hwnd": format_hwnd(native_root),
                        "expected_process_id": window_info.process_id,
                        "actual_process_id": native_process_id,
                        "window_pattern_available": window_pattern_available,
                    }),
                ));
            }
        }
        // Makepad fragment nodes normally have no native HWND of their own.
        // In that case the validated top-level window is their owner.
        Ok(owner_hwnd)
    }

    fn resolve_action_target(
        &mut self,
        window_id: &str,
        element_id: &str,
    ) -> AutomationResult<(String, ControlInfo, IUIAutomationElement, HWND)> {
        // Retain the original provider throughout validation AND dispatch.
        // Refreshing by AutomationId here creates a TOCTOU retargeting race:
        // selection may bind that ID to another object between the two calls.
        // A caller must explicitly find a new element after a stale refusal.
        let resolved_id = element_id.to_owned();
        let element = self
            .element_record(window_id, &resolved_id)?
            .element
            .clone();
        let owner_hwnd = self.resolve_owner_hwnd(window_id, &element)?;
        let info = self.control_info_for(&resolved_id)?;
        Ok((resolved_id, info, element, owner_hwnd))
    }
    fn register_window(&mut self, mut info: WindowInfo) -> AutomationResult<WindowInfo> {
        let hwnd_value = parse_hwnd(&info.hwnd)?;
        // Preserve the incarnation observed when this opaque window ID is
        // registered. Guarded operations must never re-identify a recycled PID.
        let process_birth = crate::desktop_arbiter::process_birth(info.process_id)
            .ok()
            .filter(|birth| *birth != 0);
        if let Some(existing_id) = self.window_by_hwnd.get(&hwnd_value).cloned() {
            let valid = self.windows.get(&existing_id).is_some_and(|record| {
                record.process_id == info.process_id
                    && (self.desktop_arbiter_runtime.is_none()
                        || record.process_birth == process_birth)
            });
            if valid {
                info.window_id = existing_id;
                return Ok(info);
            }
            self.window_by_hwnd.remove(&hwnd_value);
            self.windows.remove(&existing_id);
        }
        let id = self
            .ids
            .window()
            .map_err(|error| AutomationError::new(ErrorCode::BackendFailure, error.to_string()))?;
        self.window_by_hwnd.insert(hwnd_value, id.clone());
        self.windows.insert(
            id.clone(),
            WindowRecord {
                id: id.clone(),
                hwnd: hwnd_value,
                process_id: info.process_id,
                process_birth,
            },
        );
        info.window_id = id;
        Ok(info)
    }

    fn resolve_window(&mut self, window_id: &str) -> AutomationResult<(HWND, WindowInfo)> {
        if !self.ids.owns_window(window_id) {
            return Err(AutomationError::with_details(
                ErrorCode::WindowNotFound,
                "window_id does not belong to this automation session",
                json!({"window_id": window_id}),
            ));
        }
        let record = self.windows.get(window_id).cloned().ok_or_else(|| {
            AutomationError::with_details(
                ErrorCode::WindowNotFound,
                "window_id is unknown or was never discovered",
                json!({"window_id": window_id}),
            )
        })?;
        let hwnd = hwnd_from_isize(record.hwnd);
        let mut process_id = 0;
        let valid = unsafe {
            IsWindow(Some(hwnd)).as_bool() && {
                GetWindowThreadProcessId(hwnd, Some(&mut process_id));
                process_id == record.process_id
            }
        };
        let birth_matches = record.process_birth.is_some_and(|birth|
            crate::desktop_arbiter::process_birth(process_id).ok() == Some(birth));
        if !valid || !birth_matches {
            self.window_by_hwnd.remove(&record.hwnd);
            self.windows.remove(window_id);
            self.capture_geometries.remove(window_id);
            return Err(AutomationError::with_details(
                ErrorCode::WindowNotFound,
                "registered window is closed or its native HWND was recycled",
                json!({"window_id": window_id, "stale": true}),
            ));
        }
        let mut info = window_info(hwnd)?;
        info.window_id = record.id;
        Ok((hwnd, info))
    }

    fn acquire_desktop_guard(
        &mut self,
        window_id: &str,
    ) -> AutomationResult<Option<DesktopArbiterGuard>> {
        self.acquire_window_guard(window_id, true)
    }

    fn acquire_window_guard(
        &mut self,
        window_id: &str,
        physical: bool,
    ) -> AutomationResult<Option<DesktopArbiterGuard>> {
        if self.desktop_arbiter_runtime.is_none() {
            // Safe legacy fallback: opt-out never grants unguarded native input.
            // Lazy binding lets trusted manager context bind BEFORE first action.
            let pid = std::process::id();
            let birth = crate::desktop_arbiter::process_birth(pid)
                .map_err(desktop_arbiter_backend_error)?;
            self.enable_desktop_arbiter_runtime(
                &format!("native-process:{pid}"),
                "native-desktop",
                &format!("process:{birth}"),
            )?;
        }

        let record = self.windows.get(window_id).cloned().ok_or_else(|| {
            AutomationError::with_details(
                ErrorCode::WindowNotFound,
                "window_id is unknown or was never discovered",
                json!({"window_id": window_id}),
            )
        })?;
        let (hwnd, info) = self.resolve_window(window_id)?;
        let window_birth = record.process_birth.ok_or_else(|| {
            AutomationError::with_details(
                ErrorCode::OwnerHwndUnavailable,
                "the registered window has no captured process birth for arbitration",
                json!({"window_id": window_id, "process_id": record.process_id}),
            )
        })?;
        if record.id != window_id
            || record.hwnd != hwnd_to_isize(hwnd)
            || record.process_id != info.process_id
            || parse_hwnd(&info.hwnd)? != record.hwnd
        {
            return Err(AutomationError::with_details(
                ErrorCode::OwnerHwndUnavailable,
                "the resolved WindowInfo no longer matches its registered HWND/PID identity",
                json!({
                    "window_id": window_id,
                    "registered_hwnd": format_hwnd(hwnd_from_isize(record.hwnd)),
                    "resolved_hwnd": info.hwnd,
                    "registered_process_id": record.process_id,
                    "resolved_process_id": info.process_id,
                }),
            ));
        }

        let runtime = self
            .desktop_arbiter_runtime
            .as_ref()
            .expect("runtime presence checked above");
        let acquire = if physical {
            DesktopArbiterGuard::acquire
        } else {
            DesktopArbiterGuard::acquire_window
        };
        acquire(
            runtime,
            window_id,
            hwnd.0 as usize as u64,
            info.process_id,
            window_birth,
        )
        .map(Some)
        .map_err(desktop_arbiter_backend_error)
    }

    fn register_element(
        &mut self,
        window_id: &str,
        element: IUIAutomationElement,
        parent_element_id: Option<String>,
    ) -> AutomationResult<String> {
        let automation_id = current_automation_id(&element);
        let existing = self.elements.iter().find_map(|(id, record)| {
            if record.window_id != window_id {
                return None;
            }
            unsafe {
                self.automation
                    .CompareElements(&record.element, &element)
                    .ok()
                    .filter(|same| same.as_bool())
                    .map(|_| id.clone())
            }
        });
        if let Some(id) = existing {
            if let Some(record) = self.elements.get_mut(&id) {
                record.parent_element_id = parent_element_id;
                record.automation_id = automation_id.clone();
                record.element = element;
            }
            return Ok(id);
        }
        let id = self
            .ids
            .element()
            .map_err(|error| AutomationError::new(ErrorCode::BackendFailure, error.to_string()))?;
        self.elements.insert(
            id.clone(),
            ElementRecord {
                id: id.clone(),
                window_id: window_id.to_owned(),
                element,
                parent_element_id,
                automation_id,
            },
        );
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_children(
        &mut self,
        window_id: &str,
        walker: &IUIAutomationTreeWalker,
        parent: &IUIAutomationElement,
        parent_id: &str,
        depth: usize,
        max_depth: usize,
        max_elements: usize,
        output: &mut Vec<ControlInfo>,
        truncated: &mut bool,
    ) -> AutomationResult<()> {
        if depth > max_depth {
            return Ok(());
        }
        let mut child = match unsafe { walker.GetFirstChildElement(parent) } {
            Ok(child) => Some(child),
            Err(error) if is_no_element_error(&error) => None,
            Err(error) if is_stale_error(&error) => {
                return Err(uia_backend_error(
                    "UIA tree became stale during enumeration",
                    error,
                ));
            }
            Err(error) => {
                return Err(uia_backend_error(
                    "failed to enumerate UIA child elements",
                    error,
                ));
            }
        };
        while let Some(current) = child {
            if output.len() >= max_elements {
                *truncated = true;
                return Ok(());
            }
            let id =
                self.register_element(window_id, current.clone(), Some(parent_id.to_owned()))?;
            output.push(self.control_info_for(&id)?);
            self.walk_children(
                window_id,
                walker,
                &current,
                &id,
                depth + 1,
                max_depth,
                max_elements,
                output,
                truncated,
            )?;
            child = match unsafe { walker.GetNextSiblingElement(&current) } {
                Ok(next) => Some(next),
                Err(error) if is_no_element_error(&error) => None,
                Err(error) if is_stale_error(&error) => {
                    return Err(uia_backend_error(
                        "UIA tree became stale during enumeration",
                        error,
                    ));
                }
                Err(error) => {
                    return Err(uia_backend_error(
                        "failed to enumerate UIA sibling elements",
                        error,
                    ));
                }
            };
        }
        Ok(())
    }

    fn element_record(
        &mut self,
        window_id: &str,
        element_id: &str,
    ) -> AutomationResult<&ElementRecord> {
        self.resolve_window(window_id)?;
        if !self.ids.owns_element(element_id) {
            return Err(AutomationError::with_details(
                ErrorCode::ElementNotFound,
                "element_id does not belong to this automation session",
                json!({"element_id": element_id}),
            ));
        }
        let record = self.elements.get(element_id).ok_or_else(|| {
            AutomationError::with_details(
                ErrorCode::ElementNotFound,
                "element_id is unknown or was never enumerated",
                json!({"element_id": element_id}),
            )
        })?;
        if record.window_id != window_id {
            return Err(AutomationError::with_details(
                ErrorCode::StaleElement,
                "element_id belongs to a different window_id",
                json!({
                    "element_id": element_id,
                    "expected_window_id": record.window_id,
                    "provided_window_id": window_id
                }),
            ));
        }
        unsafe {
            record.element.CurrentProcessId().map_err(|error| {
                if is_stale_error(&error) {
                    stale_element_error(element_id, error)
                } else {
                    uia_backend_error("failed to validate UIA element", error)
                }
            })?;
        }
        Ok(record)
    }

    fn control_info_for_owned(
        &mut self,
        window_id: &str,
        element_id: &str,
    ) -> AutomationResult<ControlInfo> {
        self.element_record(window_id, element_id)?;
        self.control_info_for(element_id)
    }

    fn control_info_for(&self, element_id: &str) -> AutomationResult<ControlInfo> {
        let record = self.elements.get(element_id).ok_or_else(|| {
            AutomationError::new(ErrorCode::ElementNotFound, "element registry lookup failed")
        })?;
        element_to_info(record)
    }

    fn foreground_ref(&self, hwnd: HWND) -> Option<ForegroundRef> {
        if hwnd.0.is_null() {
            return None;
        }
        let value = hwnd_to_isize(hwnd);
        Some(ForegroundRef {
            hwnd: format_hwnd(hwnd),
            window_id: self.window_by_hwnd.get(&value).cloned(),
            title: window_title(hwnd),
        })
    }
}

struct CaptureDpiScope(windows::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT);

/// Thread-local physical coordinate scope for existing trusted native drivers.
/// Does not grant input authority; the DesktopArbiter reservation is separate.
/// !Send/!Sync: restoring a DPI context on a different thread is invalid.
pub struct PhysicalPixelScope {
    _scope: CaptureDpiScope,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl PhysicalPixelScope {
    pub fn enter() -> AutomationResult<Self> {
        Ok(Self { _scope: CaptureDpiScope::enter()?, _thread_bound: std::marker::PhantomData })
    }
}
impl CaptureDpiScope {
    fn enter() -> AutomationResult<Self> {
        use windows::Win32::UI::HiDpi::{
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        };
        Self::enter_context(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
    }
    fn enter_context(context: windows::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT) -> AutomationResult<Self> {
        let previous = unsafe { windows::Win32::UI::HiDpi::SetThreadDpiAwarenessContext(context) };
        if previous.0.is_null() {
            return Err(AutomationError::new(
                ErrorCode::CoordinateMappingUnverified,
                "could not enter physical-pixel capture scope",
            ));
        }
        Ok(Self(previous))
    }
}
impl Drop for CaptureDpiScope {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::UI::HiDpi::SetThreadDpiAwarenessContext(self.0);
        }
    }
}

fn desktop_arbiter_backend_error(error: crate::desktop_arbiter::ArbiterError) -> AutomationError {
    let arbiter_code = error.code;
    AutomationError::with_details(
        ErrorCode::BackendFailure,
        format!("desktop arbiter operation failed: {}", error.message),
        json!({
            "component": "windows-desktop-arbiter",
            "classification": "FAIL_TEST_INFRA",
            "arbiter_code": arbiter_code,
        }),
    )
}

fn current_window_state(hwnd: HWND) -> WindowState {
    if unsafe { IsIconic(hwnd).as_bool() } {
        WindowState::Minimized
    } else if unsafe { IsZoomed(hwnd).as_bool() } {
        WindowState::Maximized
    } else {
        WindowState::Normal
    }
}

fn window_dpi(hwnd: HWND) -> AutomationResult<u32> {
    let dpi = unsafe { GetDpiForWindow(hwnd) };
    if dpi == 0 {
        return Err(AutomationError::with_details(
            ErrorCode::WindowDpiConversionFailed,
            "GetDpiForWindow returned zero for a live HWND",
            json!({"hwnd": format_hwnd(hwnd)}),
        ));
    }
    Ok(dpi)
}

fn monitor_scale_percent(hwnd: HWND) -> AutomationResult<i32> {
    let _dpi = CaptureDpiScope::enter()?;
    use windows::Win32::UI::HiDpi::{
        GetAwarenessFromDpiAwarenessContext, GetWindowDpiAwarenessContext,
        DPI_AWARENESS_PER_MONITOR_AWARE,
    };
    // For a per-monitor-aware HWND, GetDpiForWindow is the documented DPI of
    // its current monitor. Do not infer monitor DPI from an unaware/system-
    // aware target, whose window DPI may instead be virtualized or system-wide.
    if unsafe { GetAwarenessFromDpiAwarenessContext(GetWindowDpiAwarenessContext(hwnd)) }
        == DPI_AWARENESS_PER_MONITOR_AWARE
    {
        let dpi = unsafe { GetDpiForWindow(hwnd) };
        if dpi == 0 {
            return Err(AutomationError::new(ErrorCode::CoordinateMappingUnverified,
                "per-monitor target DPI is unavailable"));
        }
        return i32::try_from((u64::from(dpi) * 100 + 48) / 96).map_err(|_| {
            AutomationError::new(ErrorCode::CoordinateMappingUnverified,
                "per-monitor target DPI exceeds the supported scale range")
        });
    }
    unsafe { windows::Win32::UI::Shell::GetScaleFactorForMonitor(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST)) }
        .map(|scale| scale.0)
        .map_err(|e| windows_error(ErrorCode::CoordinateMappingUnverified, "GetScaleFactorForMonitor failed", e))
}

fn has_window_style(
    hwnd: HWND,
    expected: windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE,
) -> bool {
    let style = unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) } as u32;
    (style & expected.0) == expected.0
}

fn build_window_interaction_info(
    hwnd: HWND,
    window: WindowInfo,
) -> AutomationResult<WindowInteractionInfo> {
    let _dpi_scope = CaptureDpiScope::enter()?;
    let dpi = window_dpi(hwnd)?;
    let monitor = monitor_info(hwnd)?;
    let state = current_window_state(hwnd);
    let bounds = window.bounds;
    let style_caption = has_window_style(hwnd, WS_CAPTION);
    let style_resizable = has_window_style(hwnd, WS_SIZEBOX);
    let minimizable = has_window_style(hwnd, WS_MINIMIZEBOX);
    let maximizable = has_window_style(hwnd, WS_MAXIMIZEBOX);

    let title_target = if state == WindowState::Minimized || !window.visible {
        None
    } else {
        find_frame_target(hwnd, bounds, dpi, WindowFrameTargetKind::Title, None)?
    };
    let mut frame_targets = Vec::new();
    if state != WindowState::Minimized && window.visible && style_resizable {
        for target in WindowFrameTargetKind::RESIZE_TARGETS {
            if let Some(resolved) = find_frame_target(hwnd, bounds, dpi, target, None)? {
                frame_targets.push(resolved);
            }
        }
    }

    let frame_kind = if style_caption {
        WindowFrameKind::NativeCaption
    } else if title_target.is_some() {
        WindowFrameKind::CustomCaption
    } else if !style_caption {
        WindowFrameKind::Borderless
    } else {
        WindowFrameKind::Unknown
    };
    let offscreen = rect_intersection(bounds, monitor.bounds).is_none();
    let clipped_to_work_area = !rect_contains_rect(monitor.work_area, bounds);
    let mut limitations = vec![
        "Physical GetWindowRect under Per-Monitor-v2; dpi describes the TARGET window, not a verified monitor effective DPI."
            .to_owned(),
        "Generic Win32 inspection cannot advertise application min/max tracking sizes before an attempted resize."
            .to_owned(),
    ];
    if state == WindowState::Minimized {
        limitations
            .push("A minimized HWND has no actionable title or resize frame target.".to_owned());
    }
    if !window.visible {
        limitations.push("A hidden HWND has no actionable physical frame target.".to_owned());
    }
    if title_target.is_none() && state != WindowState::Minimized && window.visible {
        limitations.push(
            "No live HTCAPTION point was found; expose an app semantic title region only when the window actually returns HTCAPTION there."
                .to_owned(),
        );
    }
    if !style_resizable {
        limitations.push(
            "WS_SIZEBOX is absent, so the HWND is fixed-size at the native frame level.".to_owned(),
        );
    } else if frame_targets.is_empty() && state != WindowState::Minimized && window.visible {
        limitations.push(
            "WS_SIZEBOX is present but no live resize hit target was found; physical resize is unavailable until that mismatch is resolved."
                .to_owned(),
        );
    }

    Ok(WindowInteractionInfo {
        window,
        coordinate_model: "screen_physical_pixels".to_owned(),
        dpi,
        scale_factor: dpi as f64 / 96.0,
        monitor,
        state,
        frame_kind,
        movable: title_target.is_some() && state != WindowState::Minimized,
        resizable: !frame_targets.is_empty() && state != WindowState::Minimized,
        minimizable,
        maximizable,
        restorable: state != WindowState::Normal,
        offscreen,
        clipped_to_work_area,
        constraint_observation: "not_observable_before_verified_resize".to_owned(),
        title_target,
        frame_targets,
        limitations,
    })
}

fn monitor_info(hwnd: HWND) -> AutomationResult<MonitorInfo> {
    let _dpi = CaptureDpiScope::enter()?;
    let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
    if monitor.0.is_null() {
        return Err(AutomationError::with_details(
            ErrorCode::BackendFailure,
            "MonitorFromWindow did not resolve a monitor for the live HWND",
            json!({"hwnd": format_hwnd(hwnd)}),
        ));
    }
    let mut native = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    if !unsafe { GetMonitorInfoW(monitor, &mut native as *mut MONITORINFO).as_bool() } {
        return Err(AutomationError::with_details(
            ErrorCode::BackendFailure,
            "GetMonitorInfoW failed for the monitor nearest the live HWND",
            json!({"hwnd": format_hwnd(hwnd), "monitor": format!("{monitor:?}")}),
        ));
    }
    Ok(MonitorInfo {
        handle: format!("{monitor:?}"),
        bounds: rect_from_win32(native.rcMonitor),
        work_area: rect_from_win32(native.rcWork),
        primary: native.dwFlags & MONITORINFOF_PRIMARY != 0,
    })
}

fn find_frame_target(
    hwnd: HWND,
    window_bounds: Rect,
    dpi: u32,
    target: WindowFrameTargetKind,
    region: Option<Rect>,
) -> AutomationResult<Option<WindowFrameTarget>> {
    for point in frame_target_candidates(window_bounds, dpi, target, region) {
        let Some(hit_test) = window_hit_test(hwnd, point)? else {
            continue;
        };
        if hit_test == expected_hit_test(target) {
            return Ok(Some(WindowFrameTarget {
                target,
                screen_point: point,
                hit_test: hit_test_name(hit_test).to_owned(),
                source: "wm_nchittest".to_owned(),
            }));
        }
    }
    Ok(None)
}

fn frame_target_candidates(
    bounds: Rect,
    dpi: u32,
    target: WindowFrameTargetKind,
    semantic_region: Option<Rect>,
) -> Vec<ScreenPoint> {
    if !bounds.is_actionable() {
        return Vec::new();
    }
    let scale = dpi as f64 / 96.0;
    let scaled = |pixels: i32| ((pixels as f64 * scale).round() as i32).max(1);
    let right = bounds.x.saturating_add(bounds.width).saturating_sub(1);
    let bottom = bounds.y.saturating_add(bounds.height).saturating_sub(1);
    let center_x = bounds.x.saturating_add(bounds.width / 2);
    let center_y = bounds.y.saturating_add(bounds.height / 2);
    let mut candidates = Vec::new();
    let mut push = |point: ScreenPoint| {
        if point.x >= bounds.x
            && point.x <= right
            && point.y >= bounds.y
            && point.y <= bottom
            && !candidates.contains(&point)
        {
            candidates.push(point);
        }
    };

    if target == WindowFrameTargetKind::Title {
        let area = semantic_region.unwrap_or_else(|| {
            let inset = scaled(8);
            Rect {
                x: bounds.x.saturating_add(inset),
                y: bounds.y.saturating_add(inset),
                width: bounds.width.saturating_sub(inset.saturating_mul(2)),
                height: scaled(42).min((bounds.height / 3).max(1)),
            }
        });
        if !area.is_actionable() {
            return candidates;
        }
        let area_right = area.x.saturating_add(area.width).saturating_sub(1);
        let area_bottom = area.y.saturating_add(area.height).saturating_sub(1);
        for y_fraction in [1_i32, 2, 3] {
            for x_fraction in [2_i32, 3, 4] {
                push(ScreenPoint {
                    x: area
                        .x
                        .saturating_add(area.width * x_fraction / 6)
                        .min(area_right),
                    y: area
                        .y
                        .saturating_add(area.height * y_fraction / 4)
                        .min(area_bottom),
                });
            }
        }
        return candidates;
    }

    for base_inset in [1_i32, 2, 3, 4, 6, 8, 12, 16] {
        let inset = scaled(base_inset);
        let left = bounds.x.saturating_add(inset);
        let right_inset = right.saturating_sub(inset);
        let top = bounds.y.saturating_add(inset);
        let bottom_inset = bottom.saturating_sub(inset);
        let point = match target {
            WindowFrameTargetKind::Left => ScreenPoint {
                x: left,
                y: center_y,
            },
            WindowFrameTargetKind::Right => ScreenPoint {
                x: right_inset,
                y: center_y,
            },
            WindowFrameTargetKind::Top => ScreenPoint {
                x: center_x,
                y: top,
            },
            WindowFrameTargetKind::Bottom => ScreenPoint {
                x: center_x,
                y: bottom_inset,
            },
            WindowFrameTargetKind::TopLeft => ScreenPoint { x: left, y: top },
            WindowFrameTargetKind::TopRight => ScreenPoint {
                x: right_inset,
                y: top,
            },
            WindowFrameTargetKind::BottomLeft => ScreenPoint {
                x: left,
                y: bottom_inset,
            },
            WindowFrameTargetKind::BottomRight => ScreenPoint {
                x: right_inset,
                y: bottom_inset,
            },
            WindowFrameTargetKind::Title => unreachable!("title is handled above"),
        };
        push(point);
    }
    candidates
}

fn window_hit_test(hwnd: HWND, point: ScreenPoint) -> AutomationResult<Option<u32>> {
    let packed = ((point.y as u32 & 0xffff) << 16) | (point.x as u32 & 0xffff);
    let mut result = 0_usize;
    let completed = unsafe {
        SendMessageTimeoutW(
            hwnd,
            WM_NCHITTEST,
            WPARAM(0),
            LPARAM(packed as isize),
            SMTO_ABORTIFHUNG,
            WINDOW_HIT_TEST_TIMEOUT_MS,
            Some(&mut result),
        )
    };
    if completed.0 == 0 {
        return Ok(None);
    }
    Ok(Some(result as u32))
}

fn expected_hit_test(target: WindowFrameTargetKind) -> u32 {
    match target {
        WindowFrameTargetKind::Title => HTCAPTION,
        WindowFrameTargetKind::Left => HTLEFT,
        WindowFrameTargetKind::Right => HTRIGHT,
        WindowFrameTargetKind::Top => HTTOP,
        WindowFrameTargetKind::Bottom => HTBOTTOM,
        WindowFrameTargetKind::TopLeft => HTTOPLEFT,
        WindowFrameTargetKind::TopRight => HTTOPRIGHT,
        WindowFrameTargetKind::BottomLeft => HTBOTTOMLEFT,
        WindowFrameTargetKind::BottomRight => HTBOTTOMRIGHT,
    }
}

fn hit_test_name(hit_test: u32) -> &'static str {
    match hit_test {
        HTCAPTION => "caption",
        HTLEFT => "left",
        HTRIGHT => "right",
        HTTOP => "top",
        HTBOTTOM => "bottom",
        HTTOPLEFT => "top_left",
        HTTOPRIGHT => "top_right",
        HTBOTTOMLEFT => "bottom_left",
        HTBOTTOMRIGHT => "bottom_right",
        _ => "other",
    }
}

fn rect_from_win32(rect: RECT) -> Rect {
    Rect {
        x: rect.left,
        y: rect.top,
        width: rect.right.saturating_sub(rect.left),
        height: rect.bottom.saturating_sub(rect.top),
    }
}

fn rect_contains_rect(outer: Rect, inner: Rect) -> bool {
    inner.x >= outer.x
        && inner.y >= outer.y
        && inner.x.saturating_add(inner.width) <= outer.x.saturating_add(outer.width)
        && inner.y.saturating_add(inner.height) <= outer.y.saturating_add(outer.height)
}

fn rect_intersection(left: Rect, right: Rect) -> Option<Rect> {
    let x = left.x.max(right.x);
    let y = left.y.max(right.y);
    let right_edge = left
        .x
        .saturating_add(left.width)
        .min(right.x.saturating_add(right.width));
    let bottom_edge = left
        .y
        .saturating_add(left.height)
        .min(right.y.saturating_add(right.height));
    let width = right_edge.saturating_sub(x);
    let height = bottom_edge.saturating_sub(y);
    (width > 0 && height > 0).then_some(Rect {
        x,
        y,
        width,
        height,
    })
}
fn enumerate_top_level_windows() -> AutomationResult<Vec<WindowInfo>> {
    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let handles = unsafe { &mut *(lparam.0 as *mut Vec<HWND>) };
        handles.push(hwnd);
        TRUE
    }

    let mut handles = Vec::<HWND>::new();
    unsafe {
        EnumWindows(
            Some(callback),
            LPARAM((&mut handles as *mut Vec<HWND>) as isize),
        )
    }
    .map_err(|error| windows_error(ErrorCode::BackendFailure, "EnumWindows failed", error))?;

    let mut windows = Vec::new();
    for hwnd in handles {
        if let Ok(info) = window_info(hwnd) {
            windows.push(info);
        }
    }
    Ok(windows)
}

fn window_info(hwnd: HWND) -> AutomationResult<WindowInfo> {
    let mut process_id = 0;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
    let foreground = unsafe { GetForegroundWindow() };
    Ok(WindowInfo {
        window_id: String::new(),
        hwnd: format_hwnd(hwnd),
        process_id,
        process_name: process_name(process_id).unwrap_or_default(),
        title: window_title(hwnd),
        class_name: window_class(hwnd),
        bounds: window_rect(hwnd)?,
        visible: unsafe { IsWindowVisible(hwnd).as_bool() },
        focused: foreground == hwnd,
        foreground: foreground == hwnd,
    })
}

fn window_title(hwnd: HWND) -> String {
    unsafe {
        let length = GetWindowTextLengthW(hwnd).max(0) as usize;
        let mut buffer = vec![0u16; length.saturating_add(1).max(1)];
        let read = GetWindowTextW(hwnd, &mut buffer).max(0) as usize;
        String::from_utf16_lossy(&buffer[..read])
    }
}

fn window_class(hwnd: HWND) -> String {
    unsafe {
        let mut buffer = vec![0u16; 512];
        let read = GetClassNameW(hwnd, &mut buffer).max(0) as usize;
        String::from_utf16_lossy(&buffer[..read])
    }
}

fn process_name(process_id: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id).ok()?;
        let mut buffer = vec![0u16; 32_768];
        let mut length = buffer.len() as u32;
        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        );
        let _ = CloseHandle(handle);
        result.ok()?;
        let path = std::ffi::OsString::from_wide(&buffer[..length as usize]);
        Path::new(&path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    }
}

fn window_rect(hwnd: HWND) -> AutomationResult<Rect> {
    let _dpi = CaptureDpiScope::enter()?;
    window_rect_in_current_context(hwnd)
}

fn window_rect_in_current_context(hwnd: HWND) -> AutomationResult<Rect> {
    let mut rect = RECT::default();
    unsafe { GetWindowRect(hwnd, &mut rect) }
        .map_err(|error| windows_error(ErrorCode::BackendFailure, "GetWindowRect failed", error))?;
    Ok(Rect {
        x: rect.left,
        y: rect.top,
        width: rect.right.saturating_sub(rect.left),
        height: rect.bottom.saturating_sub(rect.top),
    })
}

fn physical_client_rect(hwnd: HWND) -> AutomationResult<Rect> {
    use windows::Win32::Foundation::POINT;
    let _dpi = CaptureDpiScope::enter()?;
    let mut client = RECT::default();
    unsafe { windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut client) }
        .map_err(|e| windows_error(ErrorCode::CoordinateMappingUnverified, "GetClientRect failed", e))?;
    let mut origin = POINT { x: client.left, y: client.top };
    let mut end = POINT { x: client.right, y: client.bottom };
    for point in [&mut origin, &mut end] {
        if !unsafe { windows::Win32::Graphics::Gdi::ClientToScreen(hwnd, point) }.as_bool() {
            return Err(AutomationError::new(ErrorCode::CoordinateMappingUnverified, "ClientToScreen failed"));
        }
    }
    Ok(Rect { x:origin.x, y:origin.y, width:end.x-origin.x, height:end.y-origin.y })
}

fn element_to_info(record: &ElementRecord) -> AutomationResult<ControlInfo> {
    // UIA can virtualize provider bounds for a DPI-unaware caller. Keep these
    // observations in the same physical screen space as capture and geometry;
    // the existing scope restores the caller's context on every return path.
    let _dpi = CaptureDpiScope::enter()?;
    let element = &record.element;
    let core = unsafe {
        (
            element.CurrentControlType(),
            element.CurrentName(),
            element.CurrentAutomationId(),
            element.CurrentClassName(),
            element.CurrentBoundingRectangle(),
            element.CurrentIsOffscreen(),
            element.CurrentIsEnabled(),
            element.CurrentHasKeyboardFocus(),
        )
    };
    let (control_type, name, automation_id, class_name, bounds, offscreen, enabled, focused) =
        match core {
            (Ok(a), Ok(b), Ok(c), Ok(d), Ok(e), Ok(f), Ok(g), Ok(h)) => (a, b, c, d, e, f, g, h),
            values => {
                let errors = [
                    values.0.err(),
                    values.1.err(),
                    values.2.err(),
                    values.3.err(),
                    values.4.err(),
                    values.5.err(),
                    values.6.err(),
                    values.7.err(),
                ];
                if let Some(error) = errors.into_iter().flatten().find(is_stale_error) {
                    return Err(stale_element_error(&record.id, error));
                }
                return Err(AutomationError::new(
                    ErrorCode::BackendFailure,
                    "failed to read required UI Automation element properties",
                ));
            }
        };

    let localized = unsafe {
        element
            .CurrentLocalizedControlType()
            .map(|value| value.to_string())
            .unwrap_or_default()
    };
    let framework = unsafe {
        element
            .CurrentFrameworkId()
            .map(|value| value.to_string())
            .unwrap_or_default()
    };
    let native =
        unsafe { element.CurrentNativeWindowHandle().ok() }.filter(|hwnd| !hwnd.0.is_null());
    let selected_pattern = unsafe {
        element
            .GetCurrentPatternAs::<IUIAutomationSelectionItemPattern>(UIA_SelectionItemPatternId)
            .ok()
    };
    let selected = selected_pattern
        .as_ref()
        .and_then(|pattern| unsafe { pattern.CurrentIsSelected().ok() })
        .map(|value| value.as_bool());
    let expand_pattern = unsafe {
        element
            .GetCurrentPatternAs::<IUIAutomationExpandCollapsePattern>(UIA_ExpandCollapsePatternId)
            .ok()
    };
    let expand_state = expand_pattern
        .as_ref()
        .and_then(|pattern| unsafe { pattern.CurrentExpandCollapseState().ok() })
        .map(expand_state_name);
    let invoke = unsafe {
        element
            .GetCurrentPatternAs::<IUIAutomationInvokePattern>(UIA_InvokePatternId)
            .is_ok()
    };
    let value = unsafe {
        element
            .GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
            .is_ok()
    };
    let rect = Rect {
        x: bounds.left,
        y: bounds.top,
        width: bounds.right.saturating_sub(bounds.left),
        height: bounds.bottom.saturating_sub(bounds.top),
    };
    let offscreen = offscreen.as_bool();
    let enabled = enabled.as_bool();
    let focused = focused.as_bool();
    let type_name = control_type_name(control_type.0).to_owned();
    let current_value = unsafe {
        element
            .GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
            .ok()
            .and_then(|pattern| pattern.CurrentValue().ok())
            .map(|value| value.to_string())
    };
    let text = if type_name == "Text" {
        current_value.clone().or_else(|| Some(name.to_string()))
    } else if type_name == "Edit" || type_name == "Document" {
        current_value.clone()
    } else {
        None
    };
    Ok(ControlInfo {
        element_id: record.id.clone(),
        parent_element_id: record.parent_element_id.clone(),
        control_type: type_name.clone(),
        control_type_id: control_type.0,
        localized_control_type: localized,
        name: name.to_string(),
        value: current_value,
        text,
        automation_id: automation_id.to_string(),
        class_name: class_name.to_string(),
        framework_id: framework,
        bounds: rect,
        visible: !offscreen && rect.is_actionable(),
        offscreen,
        enabled,
        focused,
        selected,
        expand_state,
        capabilities: ActionCapabilities {
            invoke,
            select: selected_pattern.is_some(),
            value,
            expand_collapse: expand_pattern.is_some(),
            native_action: native.is_some() && type_name == "Button",
            synthesized_pointer: false,
        },
        hwnd: native.map(format_hwnd),
    })
}

fn control_type_name(id: i32) -> &'static str {
    match id {
        50_000 => "Button",
        50_001 => "Calendar",
        50_002 => "CheckBox",
        50_003 => "ComboBox",
        50_004 => "Edit",
        50_005 => "Hyperlink",
        50_006 => "Image",
        50_007 => "ListItem",
        50_008 => "List",
        50_009 => "Menu",
        50_010 => "MenuBar",
        50_011 => "MenuItem",
        50_012 => "ProgressBar",
        50_013 => "RadioButton",
        50_014 => "ScrollBar",
        50_015 => "Slider",
        50_016 => "Spinner",
        50_017 => "StatusBar",
        50_018 => "Tab",
        50_019 => "TabItem",
        50_020 => "Text",
        50_021 => "ToolBar",
        50_022 => "ToolTip",
        50_023 => "Tree",
        50_024 => "TreeItem",
        50_025 => "Custom",
        50_026 => "Group",
        50_027 => "Thumb",
        50_028 => "DataGrid",
        50_029 => "DataItem",
        50_030 => "Document",
        50_031 => "SplitButton",
        50_032 => "Window",
        50_033 => "Pane",
        50_034 => "Header",
        50_035 => "HeaderItem",
        50_036 => "Table",
        50_037 => "TitleBar",
        50_038 => "Separator",
        50_039 => "SemanticZoom",
        50_040 => "AppBar",
        _ => "Unknown",
    }
}

fn expand_state_name(state: ExpandCollapseState) -> String {
    match state.0 {
        0 => "collapsed",
        1 => "expanded",
        2 => "partially_expanded",
        3 => "leaf",
        _ => "unknown",
    }
    .into()
}

fn input_batch_uses_clipboard(inputs: &[INPUT]) -> bool {
    let down_keys: Vec<_> = inputs
        .iter()
        .filter(|event| event.r#type == INPUT_KEYBOARD)
        .map(|event| unsafe { event.Anonymous.ki })
        .filter(|key| key.dwFlags.0 & (KEYEVENTF_KEYUP.0 | KEYEVENTF_UNICODE.0) == 0)
        .map(|key| {
            if key.dwFlags.0 & KEYEVENTF_SCANCODE.0 != 0 && key.wScan == 0x53 {
                VK_DELETE
            } else {
                key.wVk
            }
        })
        .collect();
    let ctrl = down_keys.contains(&VK_CONTROL);
    let shift = down_keys.contains(&VK_SHIFT);
    (ctrl
        && down_keys
            .iter()
            .any(|key| matches!(key.0, 0x43 | 0x56 | 0x58)))
        || (shift && down_keys.contains(&VK_DELETE))
}

fn key_inputs(keys: &str) -> AutomationResult<Vec<INPUT>> {
    let keys = keys.trim();
    if keys.is_empty() {
        return Err(AutomationError::invalid_argument("keys must not be empty"));
    }
    if keys.contains('+') {
        return chord_inputs(keys);
    }
    if let Some(key) = named_virtual_key(keys) {
        return Ok(vec![keyboard_input(key, false), keyboard_input(key, true)]);
    }
    text_inputs(keys)
}

fn text_inputs(text: &str) -> AutomationResult<Vec<INPUT>> {
    if text.is_empty() {
        return Err(AutomationError::invalid_argument("text must not be empty"));
    }
    let mut inputs = Vec::new();
    for unit in text.encode_utf16() {
        inputs.push(unicode_input(unit, false));
        inputs.push(unicode_input(unit, true));
    }
    Ok(inputs)
}

const MAX_REPEATED_NAMED_KEY_COUNT: usize = 512;

fn repeated_named_key_inputs(key: &str, count: usize) -> AutomationResult<Vec<INPUT>> {
    if count == 0 || count > MAX_REPEATED_NAMED_KEY_COUNT {
        return Err(AutomationError::with_details(
            ErrorCode::InvalidArgument,
            format!(
                "count must be between 1 and {MAX_REPEATED_NAMED_KEY_COUNT} for repeated key input"
            ),
            json!({"key": key, "count": count, "max": MAX_REPEATED_NAMED_KEY_COUNT}),
        ));
    }
    let key = named_virtual_key(key).ok_or_else(|| {
        AutomationError::with_details(
            ErrorCode::InvalidArgument,
            "repeated key input requires one named virtual key without modifiers",
            json!({"key": key}),
        )
    })?;
    let mut inputs = Vec::with_capacity(count.saturating_mul(2));
    for _ in 0..count {
        inputs.push(keyboard_input(key, false));
        inputs.push(keyboard_input(key, true));
    }
    Ok(inputs)
}
fn chord_inputs(chord: &str) -> AutomationResult<Vec<INPUT>> {
    let mut modifiers = Vec::new();
    let mut primary = None;
    for token in chord
        .split('+')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let upper = token.to_ascii_uppercase();
        let modifier = match upper.as_str() {
            "CTRL" | "CONTROL" => Some(VK_CONTROL),
            "SHIFT" => Some(VK_SHIFT),
            "ALT" => Some(VK_MENU),
            "WIN" | "META" => Some(VK_LWIN),
            _ => None,
        };
        if let Some(modifier) = modifier {
            if !modifiers.contains(&modifier) {
                modifiers.push(modifier);
            }
            continue;
        }
        if primary.is_some() {
            return Err(AutomationError::invalid_argument(
                "a key chord may contain only one non-modifier key",
            ));
        }
        primary = named_virtual_key(&upper).or_else(|| {
            (upper.len() == 1)
                .then(|| upper.as_bytes()[0] as u16)
                .map(VIRTUAL_KEY)
        });
        if primary.is_none() {
            return Err(AutomationError::with_details(
                ErrorCode::InvalidArgument,
                format!("unsupported key token: {token}"),
                json!({"chord": chord}),
            ));
        }
    }
    let primary = primary.ok_or_else(|| {
        AutomationError::invalid_argument("a key chord requires one non-modifier key")
    })?;
    let mut inputs = Vec::new();
    for modifier in &modifiers {
        inputs.push(keyboard_input(*modifier, false));
    }
    inputs.push(keyboard_input(primary, false));
    inputs.push(keyboard_input(primary, true));
    for modifier in modifiers.iter().rev() {
        inputs.push(keyboard_input(*modifier, true));
    }
    Ok(inputs)
}

fn named_virtual_key(value: &str) -> Option<VIRTUAL_KEY> {
    let upper = value.to_ascii_uppercase();
    match upper.as_str() {
        "TAB" => Some(VK_TAB),
        "ENTER" | "RETURN" => Some(VK_RETURN),
        "ESC" | "ESCAPE" => Some(VK_ESCAPE),
        "SPACE" => Some(VK_SPACE),
        "BACKSPACE" => Some(VK_BACK),
        "DELETE" | "DEL" => Some(VK_DELETE),
        "HOME" => Some(VK_HOME),
        "END" => Some(VK_END),
        "LEFT" => Some(VK_LEFT),
        "RIGHT" => Some(VK_RIGHT),
        "UP" => Some(VK_UP),
        "DOWN" => Some(VK_DOWN),
        "PAGEUP" => Some(VK_PRIOR),
        "PAGEDOWN" => Some(VK_NEXT),
        _ if upper.len() == 1 => {
            let byte = upper.as_bytes()[0];
            (byte.is_ascii_alphanumeric()).then_some(VIRTUAL_KEY(byte as u16))
        }
        _ => None,
    }
}

fn keyboard_input(key: VIRTUAL_KEY, key_up: bool) -> INPUT {
    let (w_vk, w_scan, flags) = match extended_navigation_scan_code(key) {
        Some(scan_code) => (
            VIRTUAL_KEY(0),
            scan_code,
            KEYBD_EVENT_FLAGS(keyboard_event_flags(key, key_up).0 | KEYEVENTF_SCANCODE.0),
        ),
        None => (key, 0, keyboard_event_flags(key, key_up)),
    };
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: w_vk,
                wScan: w_scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn keyboard_event_flags(key: VIRTUAL_KEY, key_up: bool) -> KEYBD_EVENT_FLAGS {
    let mut flags = KEYBD_EVENT_FLAGS(0);
    if is_extended_navigation_key(key) {
        flags = KEYBD_EVENT_FLAGS(flags.0 | KEYEVENTF_EXTENDEDKEY.0);
    }
    if key_up {
        flags = KEYBD_EVENT_FLAGS(flags.0 | KEYEVENTF_KEYUP.0);
    }
    flags
}

fn is_extended_navigation_key(key: VIRTUAL_KEY) -> bool {
    matches!(
        key,
        VK_DELETE | VK_HOME | VK_END | VK_PRIOR | VK_NEXT | VK_LEFT | VK_RIGHT | VK_UP | VK_DOWN
    )
}

fn extended_navigation_scan_code(key: VIRTUAL_KEY) -> Option<u16> {
    match key {
        VK_DELETE => Some(0x53),
        VK_HOME => Some(0x47),
        VK_END => Some(0x4f),
        VK_PRIOR => Some(0x49),
        VK_NEXT => Some(0x51),
        VK_LEFT => Some(0x4b),
        VK_RIGHT => Some(0x4d),
        VK_UP => Some(0x48),
        VK_DOWN => Some(0x50),
        _ => None,
    }
}

fn unicode_input(unit: u16, key_up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: unit,
                dwFlags: if key_up {
                    KEYEVENTF_UNICODE | KEYEVENTF_KEYUP
                } else {
                    KEYEVENTF_UNICODE
                },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

struct CapturedPixels {
    pixels: Vec<u8>,
    width: u32,
    height: u32,
    method: String,
    occlusion_independent: bool,
    non_blank: bool,
    gpu_compatible: bool,
    fallback_used: bool,
    diagnostics: Vec<String>,
}

fn capture_pixels(hwnd: HWND, bounds: Rect) -> AutomationResult<CapturedPixels> {
    if !bounds.is_actionable() {
        return Err(AutomationError::with_details(
            ErrorCode::ScreenshotFailed,
            "target window has zero or negative bounds",
            bounds,
        ));
    }
    let width = bounds.width as u32;
    let height = bounds.height as u32;
    let byte_count = (width as usize).checked_mul(height as usize).and_then(|n| n.checked_mul(4))
        .filter(|n| *n <= 64 * 1024 * 1024)
        .ok_or_else(|| AutomationError::new(ErrorCode::ScreenshotFailed, "capture exceeds 64 MiB pixel budget"))?;
    unsafe {
        let source = GetWindowDC(Some(hwnd));
        if source.0.is_null() {
            return Err(AutomationError::new(
                ErrorCode::ScreenshotFailed,
                "GetWindowDC returned a null device context",
            ));
        }
        let memory = CreateCompatibleDC(Some(source));
        if memory.0.is_null() {
            let _ = ReleaseDC(Some(hwnd), source);
            return Err(AutomationError::new(
                ErrorCode::ScreenshotFailed,
                "CreateCompatibleDC returned a null device context",
            ));
        }
        let bitmap = CreateCompatibleBitmap(source, bounds.width, bounds.height);
        if bitmap.0.is_null() {
            let _ = DeleteDC(memory);
            let _ = ReleaseDC(Some(hwnd), source);
            return Err(AutomationError::new(
                ErrorCode::ScreenshotFailed,
                "CreateCompatibleBitmap returned a null bitmap",
            ));
        }
        let old = SelectObject(memory, HGDIOBJ(bitmap.0));
        let printed = PrintWindow(hwnd, memory, PRINT_WINDOW_FLAGS(PW_RENDERFULLCONTENT)).as_bool();
        let mut diagnostics = vec![format!("print_window_returned={printed}")];
        let (mut method, mut independent, mut draw_result) = if printed {
            ("PrintWindow(PW_RENDERFULLCONTENT)".to_owned(), true, Ok(()))
        } else {
            diagnostics.push("print_window_fallback=BitBlt(WindowDC)".into());
            (
                "BitBlt(WindowDC)".to_owned(),
                false,
                BitBlt(
                    memory,
                    0,
                    0,
                    bounds.width,
                    bounds.height,
                    Some(source),
                    0,
                    0,
                    SRCCOPY,
                ),
            )
        };

        let mut pixels = vec![0u8; byte_count];
        let mut info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: bounds.width,
                biHeight: -bounds.height,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                biSizeImage: pixels.len() as u32,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut lines = if draw_result.is_ok() {
            GetDIBits(
                memory,
                bitmap,
                0,
                height,
                Some(pixels.as_mut_ptr().cast::<c_void>()),
                &mut info,
                DIB_RGB_COLORS,
            )
        } else {
            0
        };
        if printed
            && draw_result.is_ok()
            && lines == bounds.height
            && pixels_are_completely_black(&pixels)
        {
            draw_result = BitBlt(
                memory,
                0,
                0,
                bounds.width,
                bounds.height,
                Some(source),
                0,
                0,
                SRCCOPY,
            );
            if draw_result.is_ok() {
                pixels.fill(0);
                lines = GetDIBits(
                    memory,
                    bitmap,
                    0,
                    height,
                    Some(pixels.as_mut_ptr().cast::<c_void>()),
                    &mut info,
                    DIB_RGB_COLORS,
                );
                method = "PrintWindow(empty)->BitBlt(WindowDC)".to_owned();
                independent = false;
                diagnostics.push("print_window_non_blank_check=fallback_used".into());
            }
        }

        let _ = SelectObject(memory, old);
        let _ = DeleteObject(HGDIOBJ(bitmap.0));
        let _ = DeleteDC(memory);
        let _ = ReleaseDC(Some(hwnd), source);

        if draw_result.is_err() || lines != bounds.height {
            return Err(AutomationError::with_details(
                ErrorCode::ScreenshotFailed,
                "window capture or pixel extraction failed",
                json!({"scan_lines": lines, "expected": bounds.height}),
            ));
        }
        let non_blank = !pixels_are_completely_black(&pixels);
        if !non_blank {
            return Err(AutomationError::with_details(
                ErrorCode::ScreenshotFailed,
                "PrintWindow and BitBlt produced a completely black frame",
                json!({"capture_method": method, "width": width, "height": height}),
            ));
        }
        for pixel in pixels.chunks_exact_mut(4) {
            pixel.swap(0, 2);
            pixel[3] = 255;
        }
        let fallback_used = method.contains("BitBlt");
        let gpu_compatible = !fallback_used;
        diagnostics.push(format!("non_blank={non_blank}"));
        diagnostics.push(format!("fallback_used={fallback_used}"));
        diagnostics.push(format!("occlusion_independent={independent}"));
        diagnostics.push(format!(
            "gpu_compatible={gpu_compatible}; inferred_from_capture_path=true"
        ));
        Ok(CapturedPixels {
            pixels,
            width,
            height,
            method,
            occlusion_independent: independent,
            non_blank,
            gpu_compatible,
            fallback_used,
            diagnostics,
        })
    }
}

fn pixels_are_completely_black(pixels: &[u8]) -> bool {
    pixels
        .chunks_exact(4)
        .all(|pixel| pixel[0] <= 2 && pixel[1] <= 2 && pixel[2] <= 2)
}

fn write_png(path: &Path, width: u32, height: u32, pixels: &[u8]) -> AutomationResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(screenshot_io_error)?;
    }
    let file = File::create(path).map_err(screenshot_io_error)?;
    let mut encoder = png::Encoder::new(file, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().map_err(screenshot_encoding_error)?;
    writer
        .write_image_data(pixels)
        .map_err(screenshot_encoding_error)?;
    writer.finish().map_err(screenshot_encoding_error)?;
    Ok(())
}

fn default_capture_path(window_id: &str) -> PathBuf {
    let safe_id = window_id.replace(':', "_");
    std::env::temp_dir()
        .join("rust-makepad-toolkit")
        .join("windows-evidence")
        .join(format!("{safe_id}_{}.png", now_unix_ms()))
}

fn screenshot_io_error(error: std::io::Error) -> AutomationError {
    let code = if error.kind() == std::io::ErrorKind::PermissionDenied {
        ErrorCode::PermissionDenied
    } else {
        ErrorCode::ScreenshotFailed
    };
    AutomationError::new(code, error.to_string())
}

fn screenshot_encoding_error(error: png::EncodingError) -> AutomationError {
    AutomationError::new(ErrorCode::ScreenshotFailed, error.to_string())
}

fn parse_hwnd(value: &str) -> AutomationResult<isize> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    isize::from_str_radix(value, 16)
        .map_err(|_| AutomationError::invalid_argument("native HWND must be a hexadecimal string"))
}

fn top_level_ancestor(hwnd: HWND) -> HWND {
    if hwnd.0.is_null() {
        return hwnd;
    }
    let root = unsafe { GetAncestor(hwnd, GA_ROOT) };
    if root.0.is_null() {
        hwnd
    } else {
        root
    }
}

fn current_automation_id(element: &IUIAutomationElement) -> String {
    unsafe {
        element
            .CurrentAutomationId()
            .ok()
            .map(|value| value.to_string())
            .unwrap_or_default()
    }
}

fn is_transient_root_error(error: &WindowsError) -> bool {
    let raw = error.code().0 as u32;
    raw == COR_E_INVALIDOPERATION_U32 || raw == E_POINTER_U32 || raw == UIA_E_ELEMENTNOTAVAILABLE
}
fn hwnd_from_isize(value: isize) -> HWND {
    HWND(value as *mut c_void)
}

fn hwnd_to_isize(hwnd: HWND) -> isize {
    hwnd.0 as isize
}

fn format_hwnd(hwnd: HWND) -> String {
    format!("0x{:X}", hwnd_to_isize(hwnd) as usize)
}

fn is_stale_error(error: &WindowsError) -> bool {
    error.code().0 as u32 == UIA_E_ELEMENTNOTAVAILABLE
}

fn is_no_element_error(error: &WindowsError) -> bool {
    let raw = error.code().0 as u32;
    raw == 0 || raw == E_POINTER_U32
}

fn stale_element_error(element_id: &str, error: WindowsError) -> AutomationError {
    AutomationError::with_details(
        ErrorCode::StaleElement,
        "UI Automation reports that the element is no longer available",
        json!({
            "element_id": element_id,
            "hresult": format!("0x{:08X}", error.code().0 as u32)
        }),
    )
}

fn uia_backend_error(context: &str, error: WindowsError) -> AutomationError {
    let raw = error.code().0 as u32;
    let code = if raw == E_ACCESSDENIED_U32 || error.code() == E_ACCESSDENIED {
        ErrorCode::PermissionDenied
    } else if raw == UIA_E_NOTSUPPORTED {
        ErrorCode::ActionNotSupported
    } else {
        ErrorCode::AccessibilityUnavailable
    };
    AutomationError::with_details(
        code,
        format!("{context}: {error}"),
        json!({"hresult": format!("0x{raw:08X}")}),
    )
}

fn windows_error(code: ErrorCode, context: &str, error: WindowsError) -> AutomationError {
    let raw = error.code().0 as u32;
    let code = if raw == E_ACCESSDENIED_U32 {
        ErrorCode::PermissionDenied
    } else {
        code
    };
    AutomationError::with_details(
        code,
        format!("{context}: {error}"),
        json!({"hresult": format!("0x{raw:08X}")}),
    )
}

fn invoke_dispatch_indeterminate_error(error: WindowsError) -> AutomationError {
    let raw = error.code().0 as u32;
    let mut mapped = windows_error(
        ErrorCode::InvocationFailed,
        "UI Automation InvokePattern did not confirm delivery",
        error,
    );
    if mapped.code == ErrorCode::InvocationFailed {
        mapped
            .message
            .push_str("; fallback activation was suppressed");
        mapped.details = json!({
            "hresult": format!("0x{raw:08X}"),
            "activation_attempted": true,
            "attempted_pattern": "InvokePattern",
            "delivery": "unknown",
            "fallback_suppressed": true
        });
    }
    mapped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_pixel_scope_restores_thread_context_on_nested_exit_and_error() {
        use windows::Win32::UI::HiDpi::{GetThreadDpiAwarenessContext, AreDpiAwarenessContextsEqual,
            GetAwarenessFromDpiAwarenessContext, DPI_AWARENESS_PER_MONITOR_AWARE};
        let before = unsafe { GetThreadDpiAwarenessContext() };
        let fail = || -> AutomationResult<()> {
            let _scope = PhysicalPixelScope::enter()?;
            assert_eq!(unsafe { GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext()) }, DPI_AWARENESS_PER_MONITOR_AWARE);
            { let _nested = PhysicalPixelScope::enter()?; }
            Err(AutomationError::invalid_argument("test error"))
        };
        assert!(fail().is_err());
        assert!(unsafe { AreDpiAwarenessContextsEqual(before, GetThreadDpiAwarenessContext()) }.as_bool());
    }

    #[test]
    fn clipboard_guard_detects_chords_but_not_literal_text_or_other_input() {
        for chord in ["Ctrl+C", "Control+V", "Ctrl+X", "Shift+Delete"] {
            assert!(
                input_batch_uses_clipboard(&key_inputs(chord).unwrap()),
                "{chord}"
            );
        }
        for chord in ["Ctrl+A", "Shift+Right", "Enter", "ALPHA"] {
            assert!(
                !input_batch_uses_clipboard(&key_inputs(chord).unwrap()),
                "{chord}"
            );
        }
        assert!(!input_batch_uses_clipboard(&text_inputs("Ctrl+C").unwrap()));
    }

    #[test]
    fn empty_makepad_value_uses_a_non_empty_clear_token_for_uia_dispatch() {
        let value = value_pattern_bstr("", "Makepad");
        assert_eq!(value.to_string(), MAKEPAD_EMPTY_VALUE_SENTINEL);
        let raw = value.into_raw();
        assert!(!raw.is_null());
        unsafe { drop(BSTR::from_raw(raw)) };
    }

    #[test]
    fn required_keyboard_chords_expand_to_balanced_input_sequences() {
        assert_eq!(key_inputs("CTRL+TAB").unwrap().len(), 4);
        assert_eq!(key_inputs("CTRL+SHIFT+TAB").unwrap().len(), 6);
        assert_eq!(key_inputs("CTRL+W").unwrap().len(), 4);
        assert_eq!(key_inputs("hello").unwrap().len(), 10);
    }

    #[test]
    fn literal_text_uses_unicode_even_for_a_single_letter() {
        assert_eq!(text_inputs("n").unwrap().len(), 2);
        assert_eq!(text_inputs("т").unwrap().len(), 2);
        assert!(text_inputs("").is_err());
    }

    #[test]
    fn extended_navigation_keys_preserve_their_windows_identity() {
        assert!(is_extended_navigation_key(VK_DELETE));
        assert!(is_extended_navigation_key(VK_HOME));
        assert!(!is_extended_navigation_key(VK_BACK));
        assert_ne!(
            keyboard_event_flags(VK_DELETE, false).0 & KEYEVENTF_EXTENDEDKEY.0,
            0
        );
        assert_ne!(
            keyboard_event_flags(VK_DELETE, true).0 & KEYEVENTF_KEYUP.0,
            0
        );
        assert_eq!(extended_navigation_scan_code(VK_DELETE), Some(0x53));
        assert_eq!(extended_navigation_scan_code(VK_LEFT), Some(0x4b));
        assert_eq!(extended_navigation_scan_code(VK_BACK), None);
    }

    #[test]
    fn repeated_named_key_inputs_are_bounded_and_never_parse_text() {
        assert_eq!(repeated_named_key_inputs("DOWN", 3).unwrap().len(), 6);

        let unknown_key = match repeated_named_key_inputs("not-a-key", 1) {
            Err(error) => error,
            Ok(_) => panic!("unknown named key unexpectedly parsed"),
        };
        assert_eq!(unknown_key.code, ErrorCode::InvalidArgument);

        let zero_count = match repeated_named_key_inputs("DOWN", 0) {
            Err(error) => error,
            Ok(_) => panic!("zero repetitions unexpectedly parsed"),
        };
        assert_eq!(zero_count.code, ErrorCode::InvalidArgument);

        let unbounded_count =
            match repeated_named_key_inputs("DOWN", MAX_REPEATED_NAMED_KEY_COUNT + 1) {
                Err(error) => error,
                Ok(_) => panic!("unbounded repetitions unexpectedly parsed"),
            };
        assert_eq!(unbounded_count.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn malformed_chords_fail_before_input_injection() {
        let error = match key_inputs("CTRL+W+TAB") {
            Err(error) => error,
            Ok(_) => panic!("malformed chord unexpectedly parsed"),
        };
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        let error = match key_inputs("") {
            Err(error) => error,
            Ok(_) => panic!("empty key request unexpectedly parsed"),
        };
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn control_type_names_are_stable_and_not_localized() {
        assert_eq!(control_type_name(50_000), "Button");
        assert_eq!(control_type_name(50_019), "TabItem");
        assert_eq!(control_type_name(-1), "Unknown");
    }
}

//! Native Microsoft UI Automation provider for a Makepad HWND.
//!
//! The provider is deliberately driven by an application-neutral snapshot. It
//! subclasses the Makepad window only to answer WM_GETOBJECT; drawing and widget
//! lifecycle remain owned by Makepad.

use crate::accessibility::{
    AccessibilityIndex, AccessibilityRole, AccessibilityTree, AccessibilityTreeError,
    IndexedAccessibilityNode, MAKEPAD_EMPTY_VALUE_SENTINEL,
};
use std::collections::HashMap;
use std::ffi::c_void;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, VARIANT_BOOL, VARIANT_TRUE, WPARAM};
use windows::Win32::System::Com::SAFEARRAY;
use windows::Win32::System::Ole::{SafeArrayCreateVector, SafeArrayDestroy, SafeArrayPutElement};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::System::Variant::{
    VARENUM, VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VT_ARRAY, VT_BOOL, VT_BSTR, VT_I4,
    VT_R8, VT_UNKNOWN,
};
use windows::Win32::UI::Accessibility::{
    IInvokeProvider, IInvokeProvider_Impl, IRawElementProviderFragment,
    IRawElementProviderFragment_Impl, IRawElementProviderFragmentRoot,
    IRawElementProviderFragmentRoot_Impl, IRawElementProviderSimple,
    IRawElementProviderSimple_Impl, ISelectionItemProvider, ISelectionItemProvider_Impl,
    ISelectionProvider, ISelectionProvider_Impl, IValueProvider, IValueProvider_Impl,
    NavigateDirection, NavigateDirection_FirstChild, NavigateDirection_LastChild,
    NavigateDirection_NextSibling, NavigateDirection_Parent, NavigateDirection_PreviousSibling,
    ProviderOptions, ProviderOptions_ServerSideProvider, UIA_AutomationIdPropertyId,
    UIA_BoundingRectanglePropertyId, UIA_ClassNamePropertyId, UIA_ControlTypePropertyId,
    UIA_FrameworkIdPropertyId, UIA_HasKeyboardFocusPropertyId, UIA_InvokePatternId,
    UIA_IsContentElementPropertyId, UIA_IsControlElementPropertyId, UIA_IsEnabledPropertyId,
    UIA_IsKeyboardFocusablePropertyId, UIA_IsOffscreenPropertyId,
    UIA_LocalizedControlTypePropertyId, UIA_NamePropertyId, UIA_ProviderDescriptionPropertyId,
    UIA_RuntimeIdPropertyId, UIA_SelectionCanSelectMultiplePropertyId,
    UIA_SelectionIsSelectionRequiredPropertyId, UIA_SelectionItemIsSelectedPropertyId,
    UIA_SelectionItemPatternId, UIA_SelectionPatternId, UIA_ValueIsReadOnlyPropertyId,
    UIA_ValuePatternId, UIA_ValueValuePropertyId, UiaAppendRuntimeId, UiaHostProviderFromHwnd,
    UiaRect, UiaReturnRawElementProvider, UiaRootObjectId,
};
use windows::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows::Win32::UI::WindowsAndMessaging::{
    GetWindowThreadProcessId, IsWindow, SMTO_ABORTIFHUNG, SMTO_BLOCK, SMTO_ERRORONEXIT,
    SendMessageTimeoutW, WM_DESTROY, WM_GETOBJECT, WM_NCDESTROY, WM_NULL,
};
use windows::core::{
    BOOL, BSTR, Error, HRESULT, IUnknown, Interface, PCWSTR, Result as WinResult, implement,
};

mod nullable_abi;
use nullable_abi::{AbiFragment, AbiRoot, AbiSimple};

const E_FAIL: HRESULT = HRESULT(0x8000_4005u32 as i32);
const UIA_E_ELEMENTNOTAVAILABLE: HRESULT = HRESULT(0x8004_0201u32 as i32);
const UIA_E_NOTSUPPORTED: HRESULT = HRESULT(0x8004_0204u32 as i32);
const UIA_E_ELEMENTNOTENABLED: HRESULT = HRESULT(0x8004_0200u32 as i32);
const SUBCLASS_ID: usize = 0x4d50_5549;
static NEXT_ATTACHMENT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessibilityAction {
    Invoke,
    Select,
    AddToSelection,
    RemoveFromSelection,
    Focus,
    SetValue(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessibilityActionRequest {
    pub node_id: String,
    pub action: AccessibilityAction,
}

/// Opaque publication/attachment fence for a request posted to the UI thread.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessibilityActionTicket {
    request: AccessibilityActionRequest,
    /// Fence the queued request again on the application UI thread.
    attachment_id: u64,
    generation: u64,
    instance_key: Option<u64>,
}

impl AccessibilityActionTicket {
    pub fn request(&self) -> &AccessibilityActionRequest {
        &self.request
    }
    pub fn into_request(self) -> AccessibilityActionRequest {
        self.request
    }
}

pub type AccessibilityActionHandler =
    Arc<dyn Fn(AccessibilityActionRequest) -> Result<(), String> + Send + Sync + 'static>;
pub type CheckedAccessibilityActionHandler =
    Arc<dyn Fn(AccessibilityActionTicket) -> Result<(), String> + Send + Sync + 'static>;

struct BridgeState {
    hwnd_value: isize,
    attachment_id: u64,
    alive: AtomicBool,
    snapshot: RwLock<AccessibilityIndex>,
    action_handler: CheckedAccessibilityActionHandler,
}

impl BridgeState {
    fn validate_dispatch_window(&self) -> WinResult<()> {
        // In-memory unit snapshots have no HWND. attach_checked always rejects
        // zero; this branch cannot be reached by an attached production bridge.
        #[cfg(test)]
        if self.hwnd_value == 0 {
            return Ok(());
        }
        let hwnd = hwnd_from_value(self.hwnd_value);
        let mut pid = 0;
        let thread = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if thread == 0 || pid != std::process::id() || !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
            return Err(bridge_error(
                UIA_E_ELEMENTNOTAVAILABLE,
                "dispatch window no longer exists",
            ));
        }
        if thread != unsafe { GetCurrentThreadId() } {
            // A posted UI action must not be acknowledged when the owning UI
            // thread cannot pump even WM_NULL. Bounded, read-only responsiveness
            // check; no activation, input or user thread suspension is performed.
            let result = unsafe {
                SendMessageTimeoutW(
                    hwnd,
                    WM_NULL,
                    WPARAM(0),
                    LPARAM(0),
                    SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT,
                    250,
                    None,
                )
            };
            if result.0 == 0 {
                return Err(bridge_error(
                    HRESULT(windows::Win32::UI::Accessibility::UIA_E_TIMEOUT as i32),
                    "owning UI thread unavailable",
                ));
            }
        }
        Ok(())
    }
    fn validate_request(&self, ticket: &AccessibilityActionTicket) -> WinResult<()> {
        if !self.alive.load(Ordering::Acquire) || ticket.attachment_id != self.attachment_id {
            return Err(bridge_error(
                UIA_E_ELEMENTNOTAVAILABLE,
                "closed or replaced window attachment",
            ));
        }
        let snapshot = self
            .snapshot
            .read()
            .map_err(|_| bridge_error(E_FAIL, "snapshot unavailable"))?;
        if ticket.generation != snapshot.generation {
            return Err(bridge_error(
                UIA_E_ELEMENTNOTAVAILABLE,
                "queued action has a stale snapshot generation",
            ));
        }
        let request = &ticket.request;
        let node = &snapshot
            .nodes
            .get(&request.node_id)
            .ok_or_else(|| bridge_error(UIA_E_ELEMENTNOTAVAILABLE, "unknown accessibility node"))?
            .node;
        if node.instance_key != ticket.instance_key {
            return Err(bridge_error(
                UIA_E_ELEMENTNOTAVAILABLE,
                "queued action targets a replaced instance",
            ));
        }
        if !node.enabled {
            return Err(bridge_error(
                UIA_E_ELEMENTNOTENABLED,
                "accessibility element is disabled",
            ));
        }
        let allowed = match &request.action {
            AccessibilityAction::Invoke => node.actions.invoke,
            AccessibilityAction::Select => node.actions.select,
            AccessibilityAction::AddToSelection => node.actions.add_to_selection,
            AccessibilityAction::RemoveFromSelection => node.actions.remove_from_selection,
            AccessibilityAction::Focus => node.actions.focus,
            AccessibilityAction::SetValue(_) => node.actions.set_value,
        };
        if !allowed {
            return Err(bridge_error(
                UIA_E_NOTSUPPORTED,
                "accessibility action is not supported",
            ));
        }
        Ok(())
    }
}

static BRIDGES: OnceLock<Mutex<HashMap<isize, Arc<BridgeState>>>> = OnceLock::new();

fn bridges() -> &'static Mutex<HashMap<isize, Arc<BridgeState>>> {
    BRIDGES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A generic Windows UIA bridge attached to an existing Makepad window.
pub struct WindowsAccessibilityBridge {
    hwnd_value: isize,
    state: Arc<BridgeState>,
    // Set/RemoveWindowSubclass are same-window-thread APIs. The owner may not
    // be moved to another thread even though snapshots/callbacks are thread safe.
    _window_thread: PhantomData<Rc<()>>,
}

impl WindowsAccessibilityBridge {
    pub fn attach(
        hwnd: HWND,
        tree: AccessibilityTree,
        action_handler: AccessibilityActionHandler,
    ) -> WinResult<Self> {
        Self::attach_checked(
            hwnd,
            tree,
            Arc::new(move |ticket| action_handler(ticket.into_request())),
        )
    }

    /// Attach the same provider with a fence retained through UI-thread dispatch.
    /// The original attach/handler API remains available for legacy consumers.
    pub fn attach_checked(
        hwnd: HWND,
        tree: AccessibilityTree,
        action_handler: CheckedAccessibilityActionHandler,
    ) -> WinResult<Self> {
        let hwnd_value = hwnd.0 as isize;
        if hwnd.0.is_null() || !unsafe { IsWindow(Some(hwnd)).as_bool() } {
            return Err(bridge_error(
                E_FAIL,
                "cannot attach accessibility bridge to an invalid HWND",
            ));
        }
        let mut pid = 0;
        let thread = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if pid != std::process::id() || thread != unsafe { GetCurrentThreadId() } {
            return Err(bridge_error(
                E_FAIL,
                "bridge must attach on its own HWND UI thread",
            ));
        }
        let index = tree
            .index()
            .map_err(|error| bridge_error(E_FAIL, error.to_string()))?;

        let mut registry = bridges()
            .lock()
            .expect("accessibility bridge registry poisoned");
        if registry.contains_key(&hwnd_value) {
            return Err(bridge_error(
                E_FAIL,
                "an accessibility bridge is already attached to this HWND",
            ));
        }

        let attachment_id = NEXT_ATTACHMENT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| bridge_error(E_FAIL, "bridge attachment identity exhausted"))?;
        let state = Arc::new(BridgeState {
            hwnd_value,
            attachment_id,
            alive: AtomicBool::new(true),
            snapshot: RwLock::new(index),
            action_handler,
        });
        registry.insert(hwnd_value, state.clone());
        drop(registry);
        if !unsafe { SetWindowSubclass(hwnd, Some(accessibility_subclass_proc), SUBCLASS_ID, 0) }
            .as_bool()
        {
            state.alive.store(false, Ordering::Release);
            bridges()
                .lock()
                .expect("bridge registry poisoned")
                .remove(&hwnd_value);
            return Err(bridge_error(E_FAIL, "SetWindowSubclass failed"));
        }
        Ok(Self {
            hwnd_value,
            state,
            _window_thread: PhantomData,
        })
    }

    pub fn hwnd(&self) -> HWND {
        hwnd_from_value(self.hwnd_value)
    }

    pub fn update(&self, tree: AccessibilityTree) -> Result<(), AccessibilityTreeError> {
        let index = tree.index()?;
        *self
            .state
            .snapshot
            .write()
            .expect("accessibility snapshot lock poisoned") = index;
        Ok(())
    }

    /// Revalidate a posted COM request immediately before a widget/domain action.
    /// Consumers must additionally validate their actual document/object binding.
    pub fn validate_action(&self, ticket: &AccessibilityActionTicket) -> WinResult<()> {
        self.state.validate_request(ticket)
    }

    /// Checked publishers keep the root identity and advance generations without reuse.
    pub fn update_checked(&self, tree: AccessibilityTree) -> WinResult<()> {
        if !self.state.alive.load(Ordering::Acquire) {
            return Err(bridge_error(UIA_E_ELEMENTNOTAVAILABLE, "closed bridge"));
        }
        let next = tree
            .index()
            .map_err(|error| bridge_error(E_FAIL, error.to_string()))?;
        let mut current = self
            .state
            .snapshot
            .write()
            .map_err(|_| bridge_error(E_FAIL, "snapshot unavailable"))?;
        if next.root_id != current.root_id || next.generation <= current.generation {
            return Err(bridge_error(
                E_FAIL,
                "root identity changed or generation did not advance",
            ));
        }
        *current = next;
        Ok(())
    }

    pub fn generation(&self) -> u64 {
        self.state
            .snapshot
            .read()
            .expect("accessibility snapshot lock poisoned")
            .generation
    }

    /// Invalidate cached providers before removing the same-thread native hook.
    /// A failed removal retains an inactive registry entry until WM_NCDESTROY;
    /// it must not allow a second attachment on an uncertain hook lifetime.
    pub fn detach(&mut self) -> WinResult<()> {
        self.state.alive.store(false, Ordering::Release);
        let ours = bridges()
            .lock()
            .map_err(|_| bridge_error(E_FAIL, "registry unavailable"))?
            .get(&self.hwnd_value)
            .is_some_and(|state| Arc::ptr_eq(state, &self.state));
        if !ours {
            return Ok(());
        }
        let hwnd = self.hwnd();
        if unsafe { IsWindow(Some(hwnd)).as_bool() } {
            if !unsafe {
                RemoveWindowSubclass(hwnd, Some(accessibility_subclass_proc), SUBCLASS_ID)
            }
            .as_bool()
            {
                return Err(bridge_error(
                    E_FAIL,
                    "RemoveWindowSubclass failed; bridge remains inactive",
                ));
            }
            unsafe {
                UiaReturnRawElementProvider(
                    hwnd,
                    WPARAM(0),
                    LPARAM(0),
                    None::<&IRawElementProviderSimple>,
                );
            }
        }
        let mut registry = bridges()
            .lock()
            .map_err(|_| bridge_error(E_FAIL, "registry unavailable"))?;
        if registry
            .get(&self.hwnd_value)
            .is_some_and(|state| Arc::ptr_eq(state, &self.state))
        {
            registry.remove(&self.hwnd_value);
        }
        Ok(())
    }
}

impl Drop for WindowsAccessibilityBridge {
    fn drop(&mut self) {
        if let Err(error) = self.detach() {
            eprintln!("accessibility bridge detach: {error}");
        }
    }
}

unsafe extern "system" fn accessibility_subclass_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _subclass_id: usize,
    _reference: usize,
) -> LRESULT {
    let state = bridges()
        .lock()
        .ok()
        .and_then(|registry| registry.get(&(hwnd.0 as isize)).cloned());

    let Some(state) = state else {
        return unsafe { DefSubclassProc(hwnd, message, wparam, lparam) };
    };

    if message == WM_GETOBJECT
        && lparam.0 as i32 == UiaRootObjectId
        && state.alive.load(Ordering::Acquire)
    {
        let root_id = state
            .snapshot
            .read()
            .ok()
            .map(|snapshot| snapshot.root_id.clone());
        if let Some(root_id) = root_id {
            let provider: IRawElementProviderSimple = Provider::new(state, root_id).into();
            return unsafe { UiaReturnRawElementProvider(hwnd, wparam, lparam, &provider) };
        }
    }

    if message == WM_DESTROY {
        state.alive.store(false, Ordering::Release);
        unsafe {
            UiaReturnRawElementProvider(
                hwnd,
                WPARAM(0),
                LPARAM(0),
                None::<&IRawElementProviderSimple>,
            );
        }
    }
    if message == WM_NCDESTROY {
        state.alive.store(false, Ordering::Release);
        unsafe {
            let _ = RemoveWindowSubclass(hwnd, Some(accessibility_subclass_proc), SUBCLASS_ID);
        }
        let _ = bridges()
            .lock()
            .map(|mut registry| registry.remove(&(hwnd.0 as isize)));
    }
    unsafe { DefSubclassProc(hwnd, message, wparam, lparam) }
}

#[derive(Clone)]
#[implement(
    AbiSimple,
    AbiFragment,
    AbiRoot,
    IInvokeProvider,
    ISelectionItemProvider,
    ISelectionProvider,
    IValueProvider
)]
struct Provider {
    state: Arc<BridgeState>,
    node_id: String,
    /// Only transient controls opt in to this token. It prevents a late UIA
    /// invoke from reaching a replacement control with the same AutomationId.
    instance_key: Option<u64>,
}

impl Provider {
    fn validated_snapshot(&self) -> WinResult<std::sync::RwLockReadGuard<'_, AccessibilityIndex>> {
        let snapshot = self
            .state
            .snapshot
            .read()
            .map_err(|_| bridge_error(E_FAIL, "snapshot unavailable"))?;
        if !self.state.alive.load(Ordering::Acquire)
            || snapshot
                .nodes
                .get(&self.node_id)
                .is_none_or(|node| node.node.instance_key != self.instance_key)
        {
            return Err(bridge_error(
                UIA_E_ELEMENTNOTAVAILABLE,
                "closed or replaced provider",
            ));
        }
        Ok(snapshot)
    }

    fn bound_fragment(
        &self,
        snapshot: &AccessibilityIndex,
        id: String,
    ) -> IRawElementProviderFragment {
        Provider {
            state: self.state.clone(),
            instance_key: snapshot.nodes[&id].node.instance_key,
            node_id: id,
        }
        .into()
    }

    fn navigate_optional(
        &self,
        direction: NavigateDirection,
    ) -> WinResult<Option<IRawElementProviderFragment>> {
        let snapshot = self.validated_snapshot()?;
        navigation_target_index(&snapshot, &self.node_id, direction)
            .map(|target| target.map(|id| self.bound_fragment(&snapshot, id)))
    }

    fn point_optional(&self, x: f64, y: f64) -> WinResult<Option<IRawElementProviderFragment>> {
        let snapshot = self.validated_snapshot()?;
        if !x.is_finite() || !y.is_finite() {
            return Err(bridge_error(
                HRESULT(0x80070057u32 as i32),
                "non-finite screen point",
            ));
        }
        Ok(hit_test_index(&snapshot, &snapshot.root_id, x, y)
            .map(|id| self.bound_fragment(&snapshot, id)))
    }

    fn focus_optional(&self) -> WinResult<Option<IRawElementProviderFragment>> {
        let snapshot = self.validated_snapshot()?;
        Ok(snapshot
            .nodes
            .values()
            .find(|node| node.node.focused)
            .map(|node| self.bound_fragment(&snapshot, node.node.id.clone())))
    }
    fn new(state: Arc<BridgeState>, node_id: String) -> Self {
        let instance_key = state.snapshot.read().ok().and_then(|snapshot| {
            snapshot
                .nodes
                .get(&node_id)
                .and_then(|node| node.node.instance_key)
        });
        Self {
            state,
            node_id,
            instance_key,
        }
    }

    fn current_snapshot(&self) -> std::sync::RwLockReadGuard<'_, AccessibilityIndex> {
        self.state
            .snapshot
            .read()
            .expect("accessibility snapshot lock poisoned")
    }

    fn node(&self) -> WinResult<IndexedAccessibilityNode> {
        if !self.state.alive.load(Ordering::Acquire) {
            return Err(bridge_error(
                UIA_E_ELEMENTNOTAVAILABLE,
                "bridge window is closed or detached",
            ));
        }
        let node = self
            .current_snapshot()
            .nodes
            .get(&self.node_id)
            .cloned()
            .ok_or_else(|| {
                bridge_error(UIA_E_ELEMENTNOTAVAILABLE, "accessibility node is stale")
            })?;
        if node.node.instance_key != self.instance_key {
            return Err(bridge_error(
                UIA_E_ELEMENTNOTAVAILABLE,
                "accessibility provider targets a replaced transient control",
            ));
        }
        Ok(node)
    }

    fn simple_for(&self, node_id: String) -> IRawElementProviderSimple {
        Provider::new(self.state.clone(), node_id).into()
    }

    fn fragment_for(&self, node_id: String) -> IRawElementProviderFragment {
        Provider::new(self.state.clone(), node_id).into()
    }

    fn is_root(&self) -> bool {
        self.current_snapshot().root_id == self.node_id
    }

    fn action(&self, action: AccessibilityAction) -> WinResult<()> {
        let ticket = {
            // Capture the binding and its generation from ONE publication.
            let snapshot = self.current_snapshot();
            let node = snapshot
                .nodes
                .get(&self.node_id)
                .ok_or_else(|| bridge_error(UIA_E_ELEMENTNOTAVAILABLE, "unknown node"))?;
            if node.node.instance_key != self.instance_key {
                return Err(bridge_error(
                    UIA_E_ELEMENTNOTAVAILABLE,
                    "replaced provider instance",
                ));
            }
            AccessibilityActionTicket {
                request: AccessibilityActionRequest {
                    node_id: self.node_id.clone(),
                    action,
                },
                attachment_id: self.state.attachment_id,
                generation: snapshot.generation,
                instance_key: node.node.instance_key,
            }
        };
        self.state.validate_request(&ticket)?;
        self.state.validate_dispatch_window()?;
        self.state.validate_request(&ticket)?;
        (self.state.action_handler)(ticket).map_err(|error| bridge_error(E_FAIL, error))
    }

    fn selection_container_id(&self) -> WinResult<String> {
        let _ = self.node()?;
        let snapshot = self.current_snapshot();
        let mut parent = snapshot
            .nodes
            .get(&self.node_id)
            .and_then(|node| node.parent_id.clone());
        while let Some(parent_id) = parent {
            let parent_node = snapshot.nodes.get(&parent_id).ok_or_else(|| {
                bridge_error(UIA_E_ELEMENTNOTAVAILABLE, "selection parent is stale")
            })?;
            if parent_node.node.selection.is_some() {
                return Ok(parent_id);
            }
            parent = parent_node.parent_id.clone();
        }
        Err(bridge_error(
            UIA_E_NOTSUPPORTED,
            "selection item has no selection container",
        ))
    }

    fn navigation_target(&self, direction: NavigateDirection) -> WinResult<Option<String>> {
        let snapshot = self.validated_snapshot()?;
        navigation_target_index(&snapshot, &self.node_id, direction)
    }

    fn hit_test(&self, x: f64, y: f64) -> WinResult<String> {
        let snapshot = self.validated_snapshot()?;
        let root_id = snapshot.root_id.clone();
        hit_test_index(&snapshot, &root_id, x, y).ok_or_else(|| {
            bridge_error(UIA_E_ELEMENTNOTAVAILABLE, "no accessibility node at point")
        })
    }

    fn focused_node(&self) -> WinResult<String> {
        self.validated_snapshot()?
            .nodes
            .values()
            .find(|node| node.node.focused)
            .map(|node| node.node.id.clone())
            .ok_or_else(|| bridge_error(UIA_E_ELEMENTNOTAVAILABLE, "no focused element"))
    }
}

fn navigation_target_index(
    snapshot: &AccessibilityIndex,
    node_id: &str,
    direction: NavigateDirection,
) -> WinResult<Option<String>> {
    let node = snapshot
        .nodes
        .get(node_id)
        .ok_or_else(|| bridge_error(UIA_E_ELEMENTNOTAVAILABLE, "accessibility node is stale"))?;

    let target = if direction == NavigateDirection_Parent {
        node.parent_id.clone()
    } else if direction == NavigateDirection_FirstChild {
        node.children.first().cloned()
    } else if direction == NavigateDirection_LastChild {
        node.children.last().cloned()
    } else if direction == NavigateDirection_NextSibling
        || direction == NavigateDirection_PreviousSibling
    {
        let Some(parent_id) = node.parent_id.as_deref() else {
            return Ok(None);
        };
        let siblings = &snapshot
            .nodes
            .get(parent_id)
            .ok_or_else(|| {
                bridge_error(UIA_E_ELEMENTNOTAVAILABLE, "accessibility parent is stale")
            })?
            .children;
        let position = siblings.iter().position(|id| id == node_id);
        position.and_then(|position| {
            if direction == NavigateDirection_NextSibling {
                siblings.get(position + 1).cloned()
            } else {
                position
                    .checked_sub(1)
                    .and_then(|index| siblings.get(index).cloned())
            }
        })
    } else {
        return Err(bridge_error(
            HRESULT(0x80070057u32 as i32),
            "invalid navigation direction",
        ));
    };
    Ok(target)
}

fn hit_test_index(snapshot: &AccessibilityIndex, node_id: &str, x: f64, y: f64) -> Option<String> {
    let node = snapshot.nodes.get(node_id)?;
    if !node.node.visible || !contains(node.node.bounds, x, y) {
        return None;
    }
    for child_id in node.children.iter().rev() {
        if let Some(hit) = hit_test_index(snapshot, child_id, x, y) {
            return Some(hit);
        }
    }
    Some(node_id.to_owned())
}

fn contains(bounds: crate::AccessibilityRect, x: f64, y: f64) -> bool {
    bounds.width > 0.
        && bounds.height > 0.
        && x >= bounds.x
        && y >= bounds.y
        && x < bounds.x + bounds.width
        && y < bounds.y + bounds.height
}

#[allow(non_upper_case_globals)]
impl IRawElementProviderSimple_Impl for Provider_Impl {
    fn ProviderOptions(&self) -> WinResult<ProviderOptions> {
        Ok(ProviderOptions_ServerSideProvider)
    }

    fn GetPatternProvider(
        &self,
        patternid: windows::Win32::UI::Accessibility::UIA_PATTERN_ID,
    ) -> WinResult<IUnknown> {
        let node = self.node()?.node;
        if patternid == UIA_InvokePatternId && node.actions.invoke {
            return Ok(IInvokeProvider::from(self.this.clone()).into());
        }
        if patternid == UIA_SelectionItemPatternId
            && (node.selected.is_some() || node.actions.select)
        {
            return Ok(ISelectionItemProvider::from(self.this.clone()).into());
        }
        if patternid == UIA_SelectionPatternId && node.selection.is_some() {
            return Ok(ISelectionProvider::from(self.this.clone()).into());
        }
        if patternid == UIA_ValuePatternId && (node.value.is_some() || node.actions.set_value) {
            return Ok(IValueProvider::from(self.this.clone()).into());
        }
        Err(bridge_error(
            UIA_E_NOTSUPPORTED,
            "UIA pattern is not supported",
        ))
    }

    fn GetPropertyValue(
        &self,
        propertyid: windows::Win32::UI::Accessibility::UIA_PROPERTY_ID,
    ) -> WinResult<VARIANT> {
        let node = self.node()?.node;
        let value = match propertyid {
            UIA_RuntimeIdPropertyId => {
                return runtime_id_variant(&self.state, &self.node_id, self.instance_key);
            }
            UIA_NamePropertyId => variant_string(&node.name),
            UIA_ControlTypePropertyId => variant_i32(role_control_type(node.role)),
            UIA_LocalizedControlTypePropertyId => variant_string(node.role.as_str()),
            UIA_BoundingRectanglePropertyId => return bounds_variant(node.bounds),
            UIA_AutomationIdPropertyId => variant_string(&node.id),
            UIA_ClassNamePropertyId => variant_string("MakepadAccessibility"),
            UIA_FrameworkIdPropertyId => variant_string("Makepad"),
            UIA_ProviderDescriptionPropertyId => variant_string("Rust Makepad Toolkit UIA bridge"),
            UIA_IsControlElementPropertyId | UIA_IsContentElementPropertyId => variant_bool(true),
            UIA_IsEnabledPropertyId => variant_bool(node.enabled),
            UIA_IsOffscreenPropertyId => variant_bool(!node.visible),
            UIA_HasKeyboardFocusPropertyId => variant_bool(node.focused),
            UIA_IsKeyboardFocusablePropertyId => variant_bool(node.actions.focus || node.focused),
            UIA_ValueValuePropertyId => node
                .value
                .as_deref()
                .map(variant_string)
                .unwrap_or_default(),
            UIA_ValueIsReadOnlyPropertyId => variant_bool(!node.actions.set_value),
            UIA_SelectionItemIsSelectedPropertyId => {
                return node
                    .selected
                    .map(variant_bool)
                    .ok_or_else(|| bridge_error(UIA_E_NOTSUPPORTED, "node is not selectable"));
            }
            UIA_SelectionCanSelectMultiplePropertyId => node
                .selection
                .map(|selection| variant_bool(selection.can_select_multiple))
                .ok_or_else(|| {
                    bridge_error(UIA_E_NOTSUPPORTED, "node is not a selection container")
                })?,
            UIA_SelectionIsSelectionRequiredPropertyId => node
                .selection
                .map(|selection| variant_bool(selection.is_selection_required))
                .ok_or_else(|| {
                    bridge_error(UIA_E_NOTSUPPORTED, "node is not a selection container")
                })?,
            _ => VARIANT::default(),
        };
        Ok(value)
    }

    fn HostRawElementProvider(&self) -> WinResult<IRawElementProviderSimple> {
        let _ = self.node()?;
        if self.is_root() {
            unsafe { UiaHostProviderFromHwnd(hwnd_from_value(self.state.hwnd_value)) }
        } else {
            Err(bridge_error(
                UIA_E_NOTSUPPORTED,
                "only the fragment root has a host provider",
            ))
        }
    }
}

impl IRawElementProviderFragment_Impl for Provider_Impl {
    fn Navigate(&self, direction: NavigateDirection) -> WinResult<IRawElementProviderFragment> {
        let _ = self.node()?;
        match self.navigation_target(direction)? {
            Some(id) => Ok(self.fragment_for(id)),
            None => Err(bridge_error(
                UIA_E_ELEMENTNOTAVAILABLE,
                "navigation target does not exist",
            )),
        }
    }

    fn GetRuntimeId(&self) -> WinResult<*mut SAFEARRAY> {
        let _ = self.node()?;
        runtime_id(&self.state, &self.node_id, self.instance_key)
    }

    fn BoundingRectangle(&self) -> WinResult<UiaRect> {
        let node = self.node()?.node;
        Ok(UiaRect {
            left: node.bounds.x,
            top: node.bounds.y,
            width: node.bounds.width,
            height: node.bounds.height,
        })
    }

    fn GetEmbeddedFragmentRoots(&self) -> WinResult<*mut SAFEARRAY> {
        let _ = self.node()?;
        Ok(std::ptr::null_mut())
    }

    fn SetFocus(&self) -> WinResult<()> {
        self.action(AccessibilityAction::Focus)
    }

    fn FragmentRoot(&self) -> WinResult<IRawElementProviderFragmentRoot> {
        let _ = self.node()?;
        let root_id = self.current_snapshot().root_id.clone();
        Ok(Provider::new(self.state.clone(), root_id).into())
    }
}

impl IRawElementProviderFragmentRoot_Impl for Provider_Impl {
    fn ElementProviderFromPoint(&self, x: f64, y: f64) -> WinResult<IRawElementProviderFragment> {
        let _ = self.node()?;
        Ok(self.fragment_for(self.hit_test(x, y)?))
    }

    fn GetFocus(&self) -> WinResult<IRawElementProviderFragment> {
        let _ = self.node()?;
        Ok(self.fragment_for(self.focused_node()?))
    }
}

impl IInvokeProvider_Impl for Provider_Impl {
    fn Invoke(&self) -> WinResult<()> {
        self.action(AccessibilityAction::Invoke)
    }
}

impl IValueProvider_Impl for Provider_Impl {
    fn Value(&self) -> WinResult<BSTR> {
        Ok(BSTR::from(
            self.node()?.node.value.as_deref().unwrap_or_default(),
        ))
    }

    fn IsReadOnly(&self) -> WinResult<BOOL> {
        Ok(BOOL::from(!self.node()?.node.actions.set_value))
    }

    fn SetValue(&self, value: &PCWSTR) -> WinResult<()> {
        if value.is_null() {
            return Err(bridge_error(
                HRESULT(0x80070057u32 as i32),
                "null ValuePattern input",
            ));
        }
        let value = unsafe { value.to_string() }.map_err(|_| {
            bridge_error(
                HRESULT(0x80070057u32 as i32),
                "invalid UTF-16 ValuePattern input",
            )
        })?;
        let value = if value == MAKEPAD_EMPTY_VALUE_SENTINEL {
            String::new()
        } else {
            value
        };
        self.action(AccessibilityAction::SetValue(value))
    }
}

impl ISelectionItemProvider_Impl for Provider_Impl {
    fn Select(&self) -> WinResult<()> {
        self.action(AccessibilityAction::Select)
    }

    fn AddToSelection(&self) -> WinResult<()> {
        self.action(AccessibilityAction::AddToSelection)
    }

    fn RemoveFromSelection(&self) -> WinResult<()> {
        self.action(AccessibilityAction::RemoveFromSelection)
    }

    fn IsSelected(&self) -> WinResult<BOOL> {
        self.node()?
            .node
            .selected
            .map(BOOL::from)
            .ok_or_else(|| bridge_error(UIA_E_NOTSUPPORTED, "node is not selectable"))
    }

    fn SelectionContainer(&self) -> WinResult<IRawElementProviderSimple> {
        Ok(self.simple_for(self.selection_container_id()?))
    }
}

impl ISelectionProvider_Impl for Provider_Impl {
    fn GetSelection(&self) -> WinResult<*mut SAFEARRAY> {
        let _ = self.node()?;
        let snapshot = self.current_snapshot();
        let node = snapshot.nodes.get(&self.node_id).ok_or_else(|| {
            bridge_error(UIA_E_ELEMENTNOTAVAILABLE, "accessibility node is stale")
        })?;
        if node.node.selection.is_none() {
            return Err(bridge_error(
                UIA_E_NOTSUPPORTED,
                "node is not a selection container",
            ));
        }
        let selected = node
            .children
            .iter()
            .filter_map(|child_id| snapshot.nodes.get(child_id))
            .filter(|child| child.node.selected == Some(true))
            .map(|child| child.node.id.clone())
            .collect::<Vec<_>>();
        drop(snapshot);
        provider_array(self, &selected)
    }

    fn CanSelectMultiple(&self) -> WinResult<BOOL> {
        self.node()?
            .node
            .selection
            .map(|selection| BOOL::from(selection.can_select_multiple))
            .ok_or_else(|| bridge_error(UIA_E_NOTSUPPORTED, "node is not a selection container"))
    }

    fn IsSelectionRequired(&self) -> WinResult<BOOL> {
        self.node()?
            .node
            .selection
            .map(|selection| BOOL::from(selection.is_selection_required))
            .ok_or_else(|| bridge_error(UIA_E_NOTSUPPORTED, "node is not a selection container"))
    }
}

fn provider_array(provider: &Provider, ids: &[String]) -> WinResult<*mut SAFEARRAY> {
    let array = unsafe { SafeArrayCreateVector(VT_UNKNOWN, 0, ids.len() as u32) };
    if array.is_null() {
        return Err(bridge_error(
            E_FAIL,
            "failed to allocate UIA provider SAFEARRAY",
        ));
    }
    for (index, id) in ids.iter().enumerate() {
        let simple = provider.simple_for(id.clone());
        let unknown: IUnknown = simple
            .cast()
            .map_err(|_| bridge_error(E_FAIL, "failed to cast UIA provider to IUnknown"))?;
        let raw = unknown.as_raw();
        let index = index as i32;
        if let Err(error) = unsafe { SafeArrayPutElement(array, &index, raw as *const c_void) } {
            unsafe {
                let _ = SafeArrayDestroy(array);
            }
            return Err(error);
        }
    }
    Ok(array)
}

fn runtime_id_variant(
    state: &BridgeState,
    node_id: &str,
    instance_key: Option<u64>,
) -> WinResult<VARIANT> {
    Ok(variant_array(
        runtime_id(state, node_id, instance_key)?,
        VARENUM(VT_I4.0 | VT_ARRAY.0),
    ))
}

fn runtime_id(
    state: &BridgeState,
    node_id: &str,
    instance_key: Option<u64>,
) -> WinResult<*mut SAFEARRAY> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    state.hwnd_value.hash(&mut hasher);
    state.attachment_id.hash(&mut hasher);
    instance_key.hash(&mut hasher);
    node_id.hash(&mut hasher);
    let id = hasher.finish();
    i32_array(&[UiaAppendRuntimeId as i32, id as i32, (id >> 32) as i32])
}

fn i32_array(values: &[i32]) -> WinResult<*mut SAFEARRAY> {
    let array = unsafe { SafeArrayCreateVector(VT_I4, 0, values.len() as u32) };
    if array.is_null() {
        return Err(bridge_error(
            E_FAIL,
            "failed to allocate UIA integer SAFEARRAY",
        ));
    }
    for (index, value) in values.iter().enumerate() {
        let index = index as i32;
        if let Err(error) =
            unsafe { SafeArrayPutElement(array, &index, value as *const i32 as *const c_void) }
        {
            unsafe {
                let _ = SafeArrayDestroy(array);
            }
            return Err(error);
        }
    }
    Ok(array)
}

fn bounds_variant(bounds: crate::AccessibilityRect) -> WinResult<VARIANT> {
    let values = [bounds.x, bounds.y, bounds.width, bounds.height];
    let array = unsafe { SafeArrayCreateVector(VT_R8, 0, values.len() as u32) };
    if array.is_null() {
        return Err(bridge_error(
            E_FAIL,
            "failed to allocate UIA bounds SAFEARRAY",
        ));
    }
    for (index, value) in values.iter().enumerate() {
        let index = index as i32;
        if let Err(error) =
            unsafe { SafeArrayPutElement(array, &index, value as *const f64 as *const c_void) }
        {
            unsafe {
                let _ = SafeArrayDestroy(array);
            }
            return Err(error);
        }
    }
    Ok(variant_array(array, VARENUM(VT_R8.0 | VT_ARRAY.0)))
}

fn variant_array(array: *mut SAFEARRAY, vt: VARENUM) -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 { parray: array },
            }),
        },
    }
}

fn variant_string(value: &str) -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_BSTR,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 {
                    bstrVal: ManuallyDrop::new(BSTR::from(value)),
                },
            }),
        },
    }
}

fn variant_i32(value: i32) -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_I4,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 { lVal: value },
            }),
        },
    }
}

fn variant_bool(value: bool) -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_BOOL,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 {
                    boolVal: if value { VARIANT_TRUE } else { VARIANT_BOOL(0) },
                },
            }),
        },
    }
}

fn role_control_type(role: AccessibilityRole) -> i32 {
    match role {
        AccessibilityRole::Button => 50_000,
        AccessibilityRole::CheckBox => 50_002,
        AccessibilityRole::ComboBox => 50_003,
        AccessibilityRole::Edit => 50_004,
        AccessibilityRole::Hyperlink => 50_005,
        AccessibilityRole::Image => 50_006,
        AccessibilityRole::ListItem => 50_007,
        AccessibilityRole::List => 50_008,
        AccessibilityRole::Menu => 50_009,
        AccessibilityRole::MenuBar => 50_010,
        AccessibilityRole::MenuItem => 50_011,
        AccessibilityRole::ProgressBar => 50_012,
        AccessibilityRole::RadioButton => 50_013,
        AccessibilityRole::ScrollBar => 50_014,
        AccessibilityRole::Slider => 50_015,
        AccessibilityRole::Spinner => 50_016,
        AccessibilityRole::StatusBar => 50_017,
        AccessibilityRole::Tab => 50_018,
        AccessibilityRole::TabItem => 50_019,
        AccessibilityRole::Text => 50_020,
        AccessibilityRole::ToolBar => 50_021,
        AccessibilityRole::Tree => 50_023,
        AccessibilityRole::TreeItem => 50_024,
        AccessibilityRole::Custom | AccessibilityRole::Unknown => 50_025,
        AccessibilityRole::Group => 50_026,
        AccessibilityRole::DataGrid => 50_028,
        AccessibilityRole::DataItem => 50_029,
        AccessibilityRole::Document => 50_030,
        AccessibilityRole::SplitButton => 50_031,
        AccessibilityRole::Window => 50_032,
        AccessibilityRole::Pane => 50_033,
        AccessibilityRole::TitleBar => 50_037,
    }
}

fn hwnd_from_value(value: isize) -> HWND {
    HWND(value as *mut c_void)
}

fn bridge_error(code: HRESULT, message: impl Into<String>) -> Error {
    let message = message.into();
    Error::new(code, &message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessibility::{AccessibilityActions, AccessibilityNode, AccessibilityRect};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn abi_state() -> Arc<BridgeState> {
        let bounds = AccessibilityRect {
            x: 0.,
            y: 0.,
            width: 200.,
            height: 200.,
        };
        let mut root = AccessibilityNode::new("root", AccessibilityRole::Window, "Root", bounds);
        let mut group = AccessibilityNode::new("group", AccessibilityRole::Group, "Group", bounds);
        for (id, x) in [("a", 10.), ("b", 40.)] {
            let mut node = AccessibilityNode::new(
                id,
                AccessibilityRole::Edit,
                id,
                AccessibilityRect {
                    x,
                    y: 10.,
                    width: 20.,
                    height: 20.,
                },
            );
            node.instance_key = Some(1);
            node.value = Some("3.2".into());
            group.children.push(node);
        }
        root.children.push(group);
        root.children.push(AccessibilityNode::new(
            "status",
            AccessibilityRole::Text,
            "Status",
            AccessibilityRect {
                x: 0.,
                y: 180.,
                width: 100.,
                height: 20.,
            },
        ));
        Arc::new(BridgeState {
            hwnd_value: 0,
            attachment_id: 1000,
            alive: AtomicBool::new(true),
            snapshot: RwLock::new(
                AccessibilityTree::new(root)
                    .unwrap()
                    .with_generation(1)
                    .index()
                    .unwrap(),
            ),
            action_handler: Arc::new(|_| Ok(())),
        })
    }

    fn abi_navigate(
        fragment: &IRawElementProviderFragment,
        direction: NavigateDirection,
    ) -> WinResult<Option<IRawElementProviderFragment>> {
        let mut out = std::ptr::dangling_mut::<c_void>();
        let hr = unsafe { (fragment.vtable().Navigate)(fragment.as_raw(), direction, &mut out) };
        assert_ne!(
            out,
            std::ptr::dangling_mut::<c_void>(),
            "ABI must initialize the uninitialized out parameter"
        );
        hr.ok()?;
        Ok((!out.is_null()).then(|| unsafe { IRawElementProviderFragment::from_raw(out) }))
    }

    fn abi_id(fragment: &IRawElementProviderFragment) -> String {
        let simple: IRawElementProviderSimple = fragment.cast().unwrap();
        unsafe {
            let mut value = simple.GetPropertyValue(UIA_AutomationIdPropertyId).unwrap();
            assert_eq!(value.Anonymous.Anonymous.vt, VT_BSTR);
            let text = value.Anonymous.Anonymous.Anonymous.bstrVal.to_string();
            windows::Win32::System::Variant::VariantClear(&mut value).unwrap();
            text
        }
    }

    #[test]
    fn accessibility_com_abi_nullable_navigation_and_bidirectional_tree() {
        let state = abi_state();
        let root: IRawElementProviderFragment = Provider::new(state.clone(), "root".into()).into();
        for direction in [
            NavigateDirection_Parent,
            NavigateDirection_PreviousSibling,
            NavigateDirection_NextSibling,
        ] {
            assert!(abi_navigate(&root, direction).unwrap().is_none());
        }
        let group = abi_navigate(&root, NavigateDirection_FirstChild)
            .unwrap()
            .unwrap();
        let status = abi_navigate(&root, NavigateDirection_LastChild)
            .unwrap()
            .unwrap();
        assert_eq!(abi_id(&group), "group");
        assert_eq!(abi_id(&status), "status");
        assert_eq!(
            abi_id(
                &abi_navigate(&group, NavigateDirection_NextSibling)
                    .unwrap()
                    .unwrap()
            ),
            "status"
        );
        assert_eq!(
            abi_id(
                &abi_navigate(&status, NavigateDirection_PreviousSibling)
                    .unwrap()
                    .unwrap()
            ),
            "group"
        );
        let a = abi_navigate(&group, NavigateDirection_FirstChild)
            .unwrap()
            .unwrap();
        let b = abi_navigate(&group, NavigateDirection_LastChild)
            .unwrap()
            .unwrap();
        assert_eq!(abi_id(&a), "a");
        assert_eq!(abi_id(&b), "b");
        assert_eq!(
            abi_id(
                &abi_navigate(&a, NavigateDirection_NextSibling)
                    .unwrap()
                    .unwrap()
            ),
            "b"
        );
        assert_eq!(
            abi_id(
                &abi_navigate(&b, NavigateDirection_PreviousSibling)
                    .unwrap()
                    .unwrap()
            ),
            "a"
        );
        assert!(
            abi_navigate(&a, NavigateDirection_PreviousSibling)
                .unwrap()
                .is_none()
        );
        assert!(
            abi_navigate(&b, NavigateDirection_NextSibling)
                .unwrap()
                .is_none()
        );
        assert!(
            abi_navigate(&a, NavigateDirection_FirstChild)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            abi_id(&abi_navigate(&a, NavigateDirection_Parent).unwrap().unwrap()),
            "group"
        );
        let mut out = std::ptr::dangling_mut::<c_void>();
        let hr =
            unsafe { (root.vtable().Navigate)(root.as_raw(), NavigateDirection(99), &mut out) };
        assert_eq!(hr, HRESULT(0x80070057u32 as i32));
        assert!(out.is_null());
        state.alive.store(false, Ordering::Release);
        assert_eq!(
            abi_navigate(&root, NavigateDirection_FirstChild)
                .unwrap_err()
                .code(),
            UIA_E_ELEMENTNOTAVAILABLE
        );
    }

    #[test]
    fn accessibility_com_abi_point_focus_unsupported_pattern_and_layout() {
        use windows::Win32::UI::Accessibility::{
            IRawElementProviderFragment_Vtbl, IRawElementProviderFragmentRoot_Vtbl,
            IRawElementProviderSimple_Vtbl,
        };
        assert_eq!(
            std::mem::size_of::<nullable_abi::AbiSimple_Vtbl>(),
            std::mem::size_of::<IRawElementProviderSimple_Vtbl>()
        );
        assert_eq!(
            std::mem::size_of::<nullable_abi::AbiFragment_Vtbl>(),
            std::mem::size_of::<IRawElementProviderFragment_Vtbl>()
        );
        assert_eq!(
            std::mem::size_of::<nullable_abi::AbiRoot_Vtbl>(),
            std::mem::size_of::<IRawElementProviderFragmentRoot_Vtbl>()
        );
        let state = abi_state();
        let root: IRawElementProviderFragmentRoot =
            Provider::new(state.clone(), "root".into()).into();
        let mut out = std::ptr::dangling_mut::<c_void>();
        assert_eq!(
            unsafe { (root.vtable().GetFocus)(root.as_raw(), &mut out) },
            HRESULT(0)
        );
        assert!(out.is_null());
        assert_eq!(
            unsafe { (root.vtable().ElementProviderFromPoint)(root.as_raw(), -1., -1., &mut out) },
            HRESULT(0)
        );
        assert!(out.is_null());
        assert_eq!(
            unsafe { (root.vtable().ElementProviderFromPoint)(root.as_raw(), 15., 15., &mut out) },
            HRESULT(0)
        );
        let hit = unsafe { IRawElementProviderFragment::from_raw(out) };
        assert_eq!(abi_id(&hit), "a");
        state
            .snapshot
            .write()
            .unwrap()
            .nodes
            .get_mut("b")
            .unwrap()
            .node
            .focused = true;
        assert_eq!(
            unsafe { (root.vtable().GetFocus)(root.as_raw(), &mut out) },
            HRESULT(0)
        );
        let focused = unsafe { IRawElementProviderFragment::from_raw(out) };
        assert_eq!(abi_id(&focused), "b");
        let simple: IRawElementProviderSimple = hit.cast().unwrap();
        assert_eq!(
            unsafe {
                (simple.vtable().GetPatternProvider)(simple.as_raw(), UIA_InvokePatternId, &mut out)
            },
            HRESULT(0)
        );
        assert!(out.is_null());
        assert_eq!(
            unsafe { (simple.vtable().HostRawElementProvider)(simple.as_raw(), &mut out) },
            HRESULT(0)
        );
        assert!(out.is_null());
        state.alive.store(false, Ordering::Release);
        assert_eq!(
            unsafe { (root.vtable().GetFocus)(root.as_raw(), &mut out) },
            UIA_E_ELEMENTNOTAVAILABLE
        );
        assert!(out.is_null());
    }

    #[test]
    fn accessibility_com_abi_runtime_id_stable_and_null_output_refused() {
        use windows::Win32::System::Ole::{
            SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
        };
        fn runtime(fragment: &IRawElementProviderFragment) -> Vec<i32> {
            unsafe {
                let array = fragment.GetRuntimeId().unwrap();
                let first = SafeArrayGetLBound(array, 1).unwrap();
                let last = SafeArrayGetUBound(array, 1).unwrap();
                let ids = (first..=last)
                    .map(|i| {
                        let mut value = 0i32;
                        SafeArrayGetElement(array, &i, &mut value as *mut _ as *mut c_void)
                            .unwrap();
                        value
                    })
                    .collect();
                SafeArrayDestroy(array).unwrap();
                ids
            }
        }
        let state = abi_state();
        let a: IRawElementProviderFragment = Provider::new(state.clone(), "a".into()).into();
        let before = runtime(&a);
        {
            let mut snap = state.snapshot.write().unwrap();
            snap.generation += 1;
            snap.nodes.get_mut("a").unwrap().node.value = Some("4.2".into());
        }
        assert_eq!(before, runtime(&a));
        assert_eq!(
            unsafe { (a.vtable().GetRuntimeId)(a.as_raw(), std::ptr::null_mut()) },
            HRESULT(0x80004003u32 as i32)
        );
        assert_eq!(
            unsafe {
                (a.vtable().Navigate)(a.as_raw(), NavigateDirection_Parent, std::ptr::null_mut())
            },
            HRESULT(0x80004003u32 as i32)
        );
        let simple: IRawElementProviderSimple = a.cast().unwrap();
        assert_eq!(
            unsafe {
                (simple.vtable().GetPropertyValue)(
                    simple.as_raw(),
                    UIA_NamePropertyId,
                    std::ptr::null_mut(),
                )
            },
            HRESULT(0x80004003u32 as i32)
        );
        state
            .snapshot
            .write()
            .unwrap()
            .nodes
            .get_mut("a")
            .unwrap()
            .node
            .instance_key = Some(99);
        assert!(unsafe { a.GetRuntimeId() }.is_err());
        let replacement: IRawElementProviderFragment = Provider::new(state, "a".into()).into();
        assert_ne!(before, runtime(&replacement));
    }

    #[test]
    fn accessibility_com_value_invalid_utf16_and_disabled_readonly_refuse() {
        let state = abi_state();
        let provider: IRawElementProviderSimple = Provider::new(state.clone(), "a".into()).into();
        let value: IValueProvider = provider.cast().unwrap();
        assert!(unsafe { value.IsReadOnly() }.unwrap().as_bool());
        let input = [b'9' as u16, 0];
        assert_eq!(
            unsafe { value.SetValue(PCWSTR(input.as_ptr())) }
                .unwrap_err()
                .code(),
            UIA_E_NOTSUPPORTED
        );
        state
            .snapshot
            .write()
            .unwrap()
            .nodes
            .get_mut("a")
            .unwrap()
            .node
            .actions
            .set_value = true;
        state
            .snapshot
            .write()
            .unwrap()
            .nodes
            .get_mut("a")
            .unwrap()
            .node
            .enabled = false;
        assert_eq!(
            unsafe { value.SetValue(PCWSTR(input.as_ptr())) }
                .unwrap_err()
                .code(),
            UIA_E_ELEMENTNOTENABLED
        );
        let invalid = [0xd800, 0];
        assert_eq!(
            unsafe { value.SetValue(PCWSTR(invalid.as_ptr())) }
                .unwrap_err()
                .code(),
            HRESULT(0x80070057u32 as i32)
        );
        assert_eq!(
            state.snapshot.read().unwrap().nodes["a"]
                .node
                .value
                .as_deref(),
            Some("3.2")
        );
    }

    fn indexed_button_snapshot(generation: u64, instance_key: u64) -> AccessibilityIndex {
        let mut root = AccessibilityNode::new(
            "app.window",
            AccessibilityRole::Window,
            "Test window",
            AccessibilityRect::default(),
        );
        let mut accept = AccessibilityNode::new(
            "dialog.confirmation.accept",
            AccessibilityRole::Button,
            "Подтвердить",
            AccessibilityRect::default(),
        );
        accept.actions = AccessibilityActions {
            invoke: true,
            ..Default::default()
        };
        accept.instance_key = Some(instance_key);
        root.children.push(accept);
        AccessibilityTree::new(root)
            .expect("valid test accessibility tree")
            .with_generation(generation)
            .index()
            .expect("index test accessibility tree")
    }

    #[test]
    fn stale_provider_cannot_invoke_replacement_with_same_automation_id() {
        let invoked = Arc::new(AtomicUsize::new(0));
        let recorded = invoked.clone();
        let handler: CheckedAccessibilityActionHandler = Arc::new(move |_| {
            recorded.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let state = Arc::new(BridgeState {
            hwnd_value: 0,
            attachment_id: 1,
            alive: AtomicBool::new(true),
            snapshot: RwLock::new(indexed_button_snapshot(1, 1)),
            action_handler: handler,
        });
        let old = Provider::new(state.clone(), "dialog.confirmation.accept".to_owned());

        *state.snapshot.write().expect("test snapshot lock poisoned") =
            indexed_button_snapshot(2, 2);

        let error = old
            .action(AccessibilityAction::Invoke)
            .expect_err("old provider must be stale after snapshot replacement");
        assert_eq!(error.code(), UIA_E_ELEMENTNOTAVAILABLE);
        assert_eq!(invoked.load(Ordering::SeqCst), 0);

        Provider::new(state, "dialog.confirmation.accept".to_owned())
            .action(AccessibilityAction::Invoke)
            .expect("current provider may invoke the current control");
        assert_eq!(invoked.load(Ordering::SeqCst), 1);
    }

    fn test_state() -> Arc<BridgeState> {
        Arc::new(BridgeState {
            hwnd_value: 0,
            attachment_id: 700,
            alive: AtomicBool::new(true),
            snapshot: RwLock::new(indexed_button_snapshot(10, 20)),
            action_handler: Arc::new(|_| Ok(())),
        })
    }

    fn ticket() -> AccessibilityActionTicket {
        AccessibilityActionTicket {
            request: AccessibilityActionRequest {
                node_id: "dialog.confirmation.accept".into(),
                action: AccessibilityAction::Invoke,
            },
            attachment_id: 700,
            generation: 10,
            instance_key: Some(20),
        }
    }

    #[test]
    fn accessibility_queued_action_is_fenced_again_at_dispatch() {
        let state = test_state();
        let queued = ticket();
        state.validate_request(&queued).unwrap();
        *state.snapshot.write().unwrap() = indexed_button_snapshot(11, 20);
        assert_eq!(
            state.validate_request(&queued).unwrap_err().code(),
            UIA_E_ELEMENTNOTAVAILABLE
        );
        *state.snapshot.write().unwrap() = indexed_button_snapshot(10, 21);
        assert_eq!(
            state.validate_request(&queued).unwrap_err().code(),
            UIA_E_ELEMENTNOTAVAILABLE
        );
    }

    #[test]
    fn accessibility_live_provider_survives_revision_but_old_ticket_does_not() {
        let state = test_state();
        let provider = Provider::new(state.clone(), "dialog.confirmation.accept".into());
        let queued = ticket();
        *state.snapshot.write().unwrap() = indexed_button_snapshot(11, 20);
        assert!(
            provider.node().is_ok(),
            "same logical instance survives value/revision updates"
        );
        assert_eq!(
            state.validate_request(&queued).unwrap_err().code(),
            UIA_E_ELEMENTNOTAVAILABLE
        );
        assert!(
            provider.action(AccessibilityAction::Invoke).is_ok(),
            "a fresh dispatch gets the current generation"
        );
    }

    #[test]
    fn accessibility_retained_validated_provider_refuses_rebind_before_dispatch() {
        let state = test_state();
        let retained = Provider::new(state.clone(), "dialog.confirmation.accept".into());
        retained
            .node()
            .expect("original provider passes pre-dispatch validation");
        // Simulate selection/document binding changing in the client gap.
        *state.snapshot.write().unwrap() = indexed_button_snapshot(11, 99);
        assert_eq!(
            retained
                .action(AccessibilityAction::Invoke)
                .unwrap_err()
                .code(),
            UIA_E_ELEMENTNOTAVAILABLE
        );
        // Never substitute a fresh provider with the same AutomationId here.
    }

    #[test]
    fn accessibility_disabled_readonly_unknown_and_wrong_attachment_refuse() {
        let state = test_state();
        let mut queued = ticket();
        state
            .snapshot
            .write()
            .unwrap()
            .nodes
            .get_mut(&queued.request.node_id)
            .unwrap()
            .node
            .enabled = false;
        assert_eq!(
            state.validate_request(&queued).unwrap_err().code(),
            UIA_E_ELEMENTNOTENABLED
        );
        state
            .snapshot
            .write()
            .unwrap()
            .nodes
            .get_mut(&queued.request.node_id)
            .unwrap()
            .node
            .enabled = true;
        queued.request.action = AccessibilityAction::SetValue("3.2".into());
        assert_eq!(
            state.validate_request(&queued).unwrap_err().code(),
            UIA_E_NOTSUPPORTED
        );
        queued.request.action = AccessibilityAction::Invoke;
        queued.request.node_id = "missing".into();
        assert_eq!(
            state.validate_request(&queued).unwrap_err().code(),
            UIA_E_ELEMENTNOTAVAILABLE
        );
        queued = ticket();
        queued.attachment_id += 1;
        assert_eq!(
            state.validate_request(&queued).unwrap_err().code(),
            UIA_E_ELEMENTNOTAVAILABLE
        );
    }

    #[test]
    fn accessibility_closed_window_invalidates_cached_provider_and_pending_action() {
        let state = test_state();
        let cached = Provider::new(state.clone(), "dialog.confirmation.accept".into());
        state.alive.store(false, Ordering::Release);
        assert_eq!(
            state.validate_request(&ticket()).unwrap_err().code(),
            UIA_E_ELEMENTNOTAVAILABLE
        );
        assert_eq!(cached.node().unwrap_err().code(), UIA_E_ELEMENTNOTAVAILABLE);
        assert_eq!(
            cached
                .action(AccessibilityAction::Invoke)
                .unwrap_err()
                .code(),
            UIA_E_ELEMENTNOTAVAILABLE
        );
        assert_eq!(
            cached.selection_container_id().unwrap_err().code(),
            UIA_E_ELEMENTNOTAVAILABLE
        );
    }
}

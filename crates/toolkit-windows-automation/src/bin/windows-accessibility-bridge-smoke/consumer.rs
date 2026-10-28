//! Attach-only consumer mode of the EXISTING bridge smoke. Never launches a
//! second application, resolves a replacement cached provider, or falls back
//! to physical input for a failed semantic action.
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use toolkit_windows_automation::{
    ControlQuery, ControlTreeOptions, ErrorCode, TreeView, WindowQuery, WindowsAutomation,
    now_unix_ms,
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HWND, POINT},
        System::{
            Com::{CLSCTX_INPROC_SERVER, CoCreateInstance},
            Threading::{
                GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME,
            },
        },
        UI::{
            Accessibility::{
                CUIAutomation, CUIAutomation8, IUIAutomation, IUIAutomation2, IUIAutomationElement,
                IUIAutomationInvokePattern, IUIAutomationValuePattern, TreeScope_Subtree,
                UIA_E_ELEMENTNOTAVAILABLE, UIA_E_NOTSUPPORTED, UIA_E_TIMEOUT, UIA_InvokePatternId,
                UIA_ValuePatternId,
            },
            HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetThreadDpiAwarenessContext},
            WindowsAndMessaging::{
                GUITHREADINFO, GetForegroundWindow, GetGUIThreadInfo, GetWindowThreadProcessId,
                IsWindow,
            },
        },
    },
    core::{BSTR, Interface},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn check(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn arg(name: &str) -> Result<String> {
    let args: Vec<_> = std::env::args().collect();
    args.windows(2)
        .find(|p| p[0] == name)
        .map(|p| p[1].clone())
        .ok_or_else(|| format!("missing {name}").into())
}
fn find(
    client: &IUIAutomation,
    root: &IUIAutomationElement,
    id: &str,
) -> Result<IUIAutomationElement> {
    unsafe {
        let condition = client.CreateTrueCondition()?;
        let elements = root.FindAll(TreeScope_Subtree, &condition)?;
        check(elements.Length()? <= 32, "unbounded consumer UIA surface")?;
        for i in 0..elements.Length()? {
            let e = elements.GetElement(i)?;
            if e.CurrentAutomationId()?.to_string() == id {
                return Ok(e);
            }
        }
    }
    Err(format!("ELEMENT_NOT_FOUND: {id}").into())
}
fn api(port: u16, method: &str, params: Value) -> Result<Value> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = json!({"id":"native-uia-proof","method":method,"params":params});
    if method == "document.open" {
        request["token"] = json!(std::env::var("AI_REVIT_API_TOKEN")?);
    }
    serde_json::to_writer(&mut stream, &request)?;
    stream.write_all(b"\n")?;
    let mut line = String::new();
    let mut reader = BufReader::new(stream).take(1024 * 1024);
    reader.read_line(&mut line)?;
    let reply: Value = serde_json::from_str(&line)?;
    check(
        reply["ok"] == true,
        "consumer API refused observation/action",
    )?;
    Ok(reply["result"].clone())
}
fn domain(port: u16, id: u64) -> Result<Value> {
    api(port, "element.inspect", json!({"element_id":id}))
}
fn wait_height(port: u16, id: u64, expected: f64) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let state = domain(port, id)?;
        if state["placement"]["wall"]["height_m"].as_f64() == Some(expected) {
            return Ok(state);
        }
        check(
            Instant::now() < deadline,
            "domain height postcondition did not arrive",
        )?;
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn wait_selection(port: u16, id: u64) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let state = api(port, "ui.state", json!({}))?;
        if state["selection"]["element_id"] == id && state["property_editing"]["element_id"] == id {
            return Ok(state);
        }
        check(
            Instant::now() < deadline,
            "selection/panel owner postcondition missing",
        )?;
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn mark(events: &mut Vec<Value>, operation: &str, started: u128, actual: Value) {
    events.push(json!({"operation":operation,"dispatched_at_unix_ms":started,"observed_at_unix_ms":now_unix_ms(),"actual":actual}));
}

fn runtime_id(element: &IUIAutomationElement) -> Result<Vec<i32>> {
    use windows::Win32::System::Ole::{
        SafeArrayDestroy, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
    };
    unsafe {
        let array = element.GetRuntimeId()?;
        check(!array.is_null(), "null RuntimeId")?;
        let result = (|| -> Result<Vec<i32>> {
            let first = SafeArrayGetLBound(array, 1)?;
            let last = SafeArrayGetUBound(array, 1)?;
            check(
                last >= first && last - first < 32,
                "invalid RuntimeId array",
            )?;
            (first..=last)
                .map(|i| {
                    let mut value = 0i32;
                    SafeArrayGetElement(array, &i, &mut value as *mut _ as *mut std::ffi::c_void)?;
                    Ok(value)
                })
                .collect()
        })();
        SafeArrayDestroy(array)?;
        result
    }
}

fn walk_contract(client: &IUIAutomation, root: &IUIAutomationElement) -> Result<Value> {
    use windows::Win32::UI::Accessibility::IUIAutomationTreeWalker;
    fn edge(
        w: &IUIAutomationTreeWalker,
        e: &IUIAutomationElement,
        direction: usize,
    ) -> Result<Option<IUIAutomationElement>> {
        unsafe {
            let table = w.vtable();
            let call = [
                table.GetParentElement,
                table.GetFirstChildElement,
                table.GetLastChildElement,
                table.GetNextSiblingElement,
                table.GetPreviousSiblingElement,
            ][direction];
            let mut out = std::ptr::dangling_mut::<std::ffi::c_void>();
            let hr = call(w.as_raw(), e.as_raw(), &mut out);
            check(hr.0 == 0, &format!("walker HRESULT 0x{:08X}", hr.0 as u32))?;
            Ok(if out.is_null() {
                None
            } else {
                Some(IUIAutomationElement::from_raw(out))
            })
        }
    }
    let walker = unsafe { client.RawViewWalker() }?;
    let mut pending = vec![root.clone()];
    let mut seen = std::collections::HashSet::new();
    let mut nodes = Vec::new();
    let mut null_edges = 0;
    while let Some(parent) = pending.pop() {
        let id = runtime_id(&parent)?;
        check(
            seen.insert(id.clone()) && seen.len() <= 32,
            "UIA navigation cycle/duplicate RuntimeId",
        )?;
        nodes.push(json!({"automation_id":unsafe{parent.CurrentAutomationId()}?.to_string(),"runtime_id":id}));
        let first = edge(&walker, &parent, 1)?;
        let last = edge(&walker, &parent, 2)?;
        check(
            first.is_some() == last.is_some(),
            "first/last child disagreement",
        )?;
        let mut child = first;
        let mut previous: Option<IUIAutomationElement> = None;
        let mut siblings = 0;
        if child.is_none() {
            null_edges += 2;
        }
        while let Some(current) = child {
            siblings += 1;
            check(siblings <= 32, "sibling cycle")?;
            let p = edge(&walker, &current, 0)?.ok_or("child has no parent")?;
            check(
                unsafe { client.CompareElements(&p, &parent) }?.as_bool(),
                "nonreciprocal parent",
            )?;
            let prev = edge(&walker, &current, 4)?;
            match (&previous, prev) {
                (None, None) => null_edges += 1,
                (Some(a), Some(b)) => check(
                    unsafe { client.CompareElements(a, &b) }?.as_bool(),
                    "nonreciprocal previous sibling",
                )?,
                _ => return Err("previous sibling boundary mismatch".into()),
            }
            let next = edge(&walker, &current, 3)?;
            if next.is_none() {
                null_edges += 1;
                check(
                    unsafe {
                        client.CompareElements(&current, last.as_ref().ok_or("last child absent")?)
                    }?
                    .as_bool(),
                    "last child mismatch",
                )?;
            }
            pending.push(current.clone());
            previous = Some(current);
            child = next;
        }
    }
    check(
        seen.len() == 16,
        "navigation did not reach all sixteen nodes",
    )?;
    Ok(
        json!({"nodes":nodes,"s_ok_null_edges":null_edges,"cycles":0,"reciprocal_parent_and_siblings":true}),
    )
}

pub fn run() -> Result<()> {
    let pid: u32 = arg("--consumer-pid")?.parse()?;
    let birth: u64 = arg("--consumer-birth")?.parse()?;
    let port: u16 = arg("--consumer-port")?.parse()?;
    let case = arg("--consumer-case")?;
    let output = PathBuf::from(arg("--output-dir")?);
    check(
        output.is_dir(),
        "fresh preplanned output directory required",
    )?;
    check(
        toolkit_windows_automation::desktop_arbiter::process_birth(pid)? == birth,
        "process incarnation mismatch",
    )?;
    let mut events = Vec::new();
    let mut context = json!({"pid":pid,"process_birth":birth,"case":case,"started_at_unix_ms":now_unix_ms(),"runner":"existing windows-accessibility-bridge-smoke --consumer-pid; attach-only","core_acceptance":"NOT_YET_VERIFIED"});
    let result = execute(pid, birth, port, &case, &output, &mut events, &mut context);
    let summary = json!({"schema_version":2,"evidence_origin":"real","status":if result.is_ok(){"NATIVE_CASE_PASSED"}else{"FAILED"},"context":context,"events":events,"error":result.as_ref().err().map(|e|e.to_string()),"finished_at_unix_ms":now_unix_ms(),"full_core_v2_accepted":false});
    fs::write(
        output.join("native-uia-report.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    println!(
        "{}",
        json!({"case":case,"status":summary["status"],"events":events.len(),"pid":pid})
    );
    result
}

fn execute(
    pid: u32,
    birth: u64,
    port: u16,
    case: &str,
    output: &Path,
    events: &mut Vec<Value>,
    context: &mut Value,
) -> Result<()> {
    let mut automation = WindowsAutomation::new()?;
    automation.enable_desktop_arbiter_runtime(
        "Makepad_Toolkit",
        "uia-final",
        &format!("{case}-{pid}-{}", now_unix_ms()),
    )?;
    let window = automation.find_window(&WindowQuery {
        process_id: Some(pid),
        title: Some("AI Revit v0.4".into()),
        ..Default::default()
    })?;
    let hwnd = HWND(
        usize::from_str_radix(window.hwnd.trim_start_matches("0x"), 16)? as *mut std::ffi::c_void,
    );
    check(
        toolkit_windows_automation::desktop_arbiter::process_birth(pid)? == birth,
        "process birth changed after window resolution",
    )?;
    context["window"] = serde_json::to_value(&window)?;
    let old_dpi =
        unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    check(
        !old_dpi.0.is_null(),
        "physical-coordinate DPI scope unavailable",
    )?;
    struct Dpi(windows::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT);
    impl Drop for Dpi {
        fn drop(&mut self) {
            unsafe {
                SetThreadDpiAwarenessContext(self.0);
            }
        }
    }
    let _dpi = Dpi(old_dpi);
    let client: IUIAutomation = unsafe {
        CoCreateInstance(
            if case == "unavailable" {
                &CUIAutomation8
            } else {
                &CUIAutomation
            },
            None,
            CLSCTX_INPROC_SERVER,
        )
    }?;
    if case == "unavailable" {
        // Explicit caller deadline is part of this fault scenario. A temporary
        // UI pause shorter than UIA's default transaction timeout is not a
        // timeout contract. Verify that an expired native call cannot mutate
        // the model when the UI thread resumes.
        let timed: IUIAutomation2 = client.cast()?;
        unsafe { timed.SetTransactionTimeout(500) }?;
        context["uia_transaction_timeout_ms"] = json!(500);
    }
    let root = unsafe { client.ElementFromHandle(hwnd) }?;
    let initial = api(port, "document.info", json!({}))?;
    check(
        initial["session_id"]
            .as_str()
            .is_none_or(|s| s.starts_with(&format!("{pid}-"))),
        "domain API belongs to another process",
    )?;
    let started = now_unix_ms();
    let raw = automation.get_control_tree(
        &window.window_id,
        &ControlTreeOptions {
            view: TreeView::Raw,
            max_depth: Some(8),
            max_elements: Some(32),
            ..Default::default()
        },
    )?;
    let control = automation.get_control_tree(
        &window.window_id,
        &ControlTreeOptions {
            view: TreeView::Control,
            max_depth: Some(8),
            max_elements: Some(32),
            ..Default::default()
        },
    )?;
    check(
        !raw.truncated
            && !control.truncated
            && raw.total_enumerated > 1
            && control.total_enumerated > 1,
        "external UIA sees no complete child tree",
    )?;
    if case != "empty" {
        check(
            raw.total_enumerated == 16 && control.total_enumerated == 16,
            "normal consumer surface changed from 16 nodes",
        )?;
    }
    mark(
        events,
        "independent_raw_control",
        started,
        json!({"raw":raw,"control":control,"document":initial}),
    );
    if case == "empty" {
        check(
            initial["open"] == false,
            "empty debug fixture did not leave document closed",
        )?;
        let save = find(&client, &root, "toolbar.save")?;
        check(
            !unsafe { save.CurrentIsEnabled() }?.as_bool(),
            "Save not disabled",
        )?;
        let pattern: IUIAutomationInvokePattern =
            unsafe { save.GetCurrentPatternAs(UIA_InvokePatternId) }?;
        let t = now_unix_ms();
        let error = unsafe { pattern.Invoke() }
            .err()
            .ok_or("disabled Save must refuse")?;
        check(
            error.code().0 as u32 == 0x80040200,
            "disabled Save returned wrong HRESULT",
        )?;
        let after = api(port, "document.info", json!({}))?;
        check(after == initial, "disabled Save mutated document state")?;
        mark(
            events,
            "disabled_save",
            t,
            json!({"hresult":format!("0x{:08X}",error.code().0 as u32),"domain_after":after}),
        );
        return Ok(());
    }
    let height = find(&client, &root, "properties.wall.height")?;
    let cached: IUIAutomationValuePattern =
        unsafe { height.GetCurrentPatternAs(UIA_ValuePatternId) }?;
    let height_runtime_id = runtime_id(&height)?;
    if case == "happy" {
        let t = now_unix_ms();
        let result = walk_contract(&client, &root)?;
        mark(events, "native_navigation_runtime_ids", t, result);
    }
    let before_a = domain(port, 1)?;
    if case == "readonly" {
        check(
            unsafe { cached.CurrentIsReadOnly() }?.as_bool(),
            "real TextInput is not read-only",
        )?;
        let t = now_unix_ms();
        let error = unsafe { cached.SetValue(&BSTR::from("3.2")) }
            .err()
            .ok_or("readonly ValuePattern must refuse")?;
        check(
            [UIA_E_NOTSUPPORTED, 0x80131509, 0x80070005].contains(&(error.code().0 as u32)),
            &format!(
                "read-only HRESULT mismatch: 0x{:08X}",
                error.code().0 as u32
            ),
        )?;
        check(
            domain(port, 1)? == before_a,
            "read-only ValuePattern changed model",
        )?;
        mark(
            events,
            "readonly_height",
            t,
            json!({"hresult":format!("0x{:08X}",error.code().0 as u32),"domain":before_a}),
        );
        save(&mut automation, &window.window_id, events)?;
        return Ok(());
    }
    if case == "pending" {
        let t = now_unix_ms();
        let ack = unsafe { cached.SetValue(&BSTR::from("3.2")) };
        let until = Instant::now() + Duration::from_secs(5);
        while unsafe { IsWindow(Some(hwnd)) }.as_bool() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(25));
        }
        check(
            !unsafe { IsWindow(Some(hwnd)) }.as_bool(),
            "pending-close fixture did not normally destroy window",
        )?;
        let closed_error = unsafe { cached.SetValue(&BSTR::from("9.9")) }
            .err()
            .ok_or("closed provider accepted another action")?;
        let receipt = PathBuf::from(arg("--pending-receipt")?);
        let data: Value = serde_json::from_slice(&fs::read(receipt)?)?;
        check(
            data["real_com_ticket_received"] == true
                && data["refused"] == true
                && data["hresult"] == "0x80040201"
                && data["domain_unchanged"] == true
                && data["domain_before"] == data["domain_after"],
            "pending action not refused before domain mutation",
        )?;
        mark(
            events,
            "close_during_pending_ticket",
            t,
            json!({"dispatch_acknowledged":ack.is_ok(),"closed_provider_hresult":format!("0x{:08X}",closed_error.code().0 as u32),"note":"acknowledgement is not domain success","receipt":data}),
        );
        return Ok(());
    }
    if case == "unavailable" {
        let thread = unsafe { GetWindowThreadProcessId(hwnd, None) };
        check(
            thread != 0 && thread != unsafe { GetCurrentThreadId() },
            "invalid injection UI thread",
        )?;
        let handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, thread) }?;
        let previous = unsafe { SuspendThread(handle) };
        if previous != 0 {
            if previous != u32::MAX {
                unsafe {
                    ResumeThread(handle);
                }
            }
            unsafe { CloseHandle(handle) }?;
            return Err("UI thread already suspended or injection failed".into());
        }
        let suspended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let watchdog = suspended.clone();
        let raw_handle = handle.0 as usize;
        let guard = std::thread::Builder::new()
            .name("uia-owned-thread-resume".into())
            .spawn(move || {
                std::thread::sleep(Duration::from_secs(2));
                if watchdog.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    unsafe {
                        ResumeThread(windows::Win32::Foundation::HANDLE(
                            raw_handle as *mut std::ffi::c_void,
                        ));
                    }
                }
            });
        let guard = match guard {
            Ok(handle) => handle,
            Err(error) => {
                if suspended.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    unsafe {
                        ResumeThread(handle);
                    }
                }
                unsafe { CloseHandle(handle) }?;
                return Err(error.into());
            }
        };
        let t = now_unix_ms();
        let result = unsafe { cached.SetValue(&BSTR::from("3.2")) };
        if suspended.swap(false, std::sync::atomic::Ordering::SeqCst) {
            unsafe {
                ResumeThread(handle);
            }
        }
        guard.join().map_err(|_| "resume watchdog panicked")?;
        unsafe { CloseHandle(handle) }?;
        let after_injection = domain(port, 1)?;
        mark(
            events,
            "unavailable_ui_thread_observation",
            t,
            json!({"dispatch_acknowledged":result.is_ok(),"hresult":result.as_ref().err().map(|e|format!("0x{:08X}",e.code().0 as u32)),"before":before_a,"after":after_injection,"domain_unchanged":before_a==after_injection,"watchdog_joined":true,"thread_resumed":true}),
        );
        let error = result
            .err()
            .ok_or("unavailable UI thread must not acknowledge queued mutation")?;
        check(
            error.code().0 as u32 == UIA_E_TIMEOUT,
            "unavailable UI thread returned wrong HRESULT",
        )?;
        check(
            domain(port, 1)? == before_a,
            "unavailable UI thread caused delayed mutation",
        )?;
        mark(
            events,
            "unavailable_ui_thread",
            t,
            json!({"hresult":format!("0x{:08X}",error.code().0 as u32),"watchdog_joined":true,"thread_resumed":true,"domain":before_a}),
        );
        return Ok(());
    }
    if case == "replace" {
        let fixture = PathBuf::from(arg("--fixture-document")?).canonicalize()?;
        check(
            fixture.starts_with(output.canonicalize()?),
            "replacement fixture must be private in this attempt",
        )?;
        let t = now_unix_ms();
        api(
            port,
            "document.open",
            json!({"path":fixture,"expected_session_id":initial["session_id"],"expected_document_id":initial["document_uuid"]}),
        )?;
        let fresh = api(port, "document.info", json!({}))?;
        check(
            fresh["document_uuid"] != initial["document_uuid"]
                && fresh["open_generation"] != initial["open_generation"],
            "document replacement identity did not change",
        )?;
        let prior = api(port, "elements.list", json!({}))?;
        let error = unsafe { cached.SetValue(&BSTR::from("9.9")) }
            .err()
            .ok_or("old document ValuePattern must refuse")?;
        let stale_read = unsafe { cached.CurrentValue() };
        check(
            [UIA_E_ELEMENTNOTAVAILABLE, 0x80131509].contains(&(error.code().0 as u32)),
            "old document provider HRESULT mismatch",
        )?;
        check(
            api(port, "elements.list", json!({}))? == prior
                && api(port, "document.info", json!({}))? == fresh,
            "cached old-document pattern mutated replacement",
        )?;
        mark(
            events,
            "wrong_document_provider",
            t,
            json!({"old_document":initial,"new_document":fresh,"hresult":format!("0x{:08X}",error.code().0 as u32),"cached_value":stale_read.as_ref().ok().map(|v|v.to_string()),"cached_value_error":stale_read.err().map(|e|format!("0x{:08X}",e.code().0 as u32)),"domain_after":prior}),
        );
        return Ok(());
    }
    check(case == "happy", "unknown bounded native case")?;
    let cached_record = automation.find_control(
        &window.window_id,
        &ControlQuery {
            automation_id: Some("properties.wall.height".into()),
            ..Default::default()
        },
    )?;
    let t = now_unix_ms();
    let state = automation.set_value(&window.window_id, &cached_record.element_id, "3.2")?;
    check(
        state.value.as_deref() == Some("3.2"),
        "latest client ValuePattern readback not verified",
    )?;
    let a = wait_height(port, 1, 3.2)?;
    check(
        runtime_id(&height)? == height_runtime_id,
        "RuntimeId changed with ordinary value/revision",
    )?;
    check(
        unsafe { cached.CurrentValue() }?.to_string() == "3.2",
        "retained native pattern did not survive ordinary revision",
    )?;
    mark(
        events,
        "set_height_a",
        t,
        json!({"client_state":state,"domain":a}),
    );
    let before_b = domain(port, 2)?;
    let b = automation.find_control(
        &window.window_id,
        &ControlQuery {
            automation_id: Some("object_tree.element.2".into()),
            ..Default::default()
        },
    )?;
    check(
        b.capabilities.select,
        "BIM row has no SelectionItem capability",
    )?;
    let t = now_unix_ms();
    let selection = automation.click_element(&window.window_id, &b.element_id)?;
    check(
        selection.action_method == "SelectionItem.Select",
        "semantic selection used fallback",
    )?;
    let selected = wait_selection(port, 2)?;
    mark(
        events,
        "select_wall_b",
        t,
        json!({"selection":selection,"panel":selected["property_editing"]}),
    );
    let t = now_unix_ms();
    let error = unsafe { cached.SetValue(&BSTR::from("9.9")) }
        .err()
        .ok_or("cached native wall-A pattern must refuse")?;
    // UIAutomationCore may preflight IsReadOnly before calling a stale
    // IValueProvider::SetValue, yielding COR_E_INVALIDOPERATION, and return a
    // default property value on provider failure. Preserve these native facts;
    // identity safety is the retained pattern plus independent A/B domain state,
    // not a fabricated exact HRESULT from the framework wrapper.
    let stale_read = unsafe { cached.CurrentValue() };
    mark(
        events,
        "cached_pattern_native_errors",
        t,
        json!({"set_hresult":format!("0x{:08X}",error.code().0 as u32),"set_message":error.message(),"cached_value":stale_read.as_ref().ok().map(|v|v.to_string()),"cached_value_error":stale_read.err().map(|e|format!("0x{:08X}",e.code().0 as u32)),"wall_b":domain(port,2)?}),
    );
    check(
        [UIA_E_ELEMENTNOTAVAILABLE, 0x80131509].contains(&(error.code().0 as u32)),
        "cached native pattern did not preserve stale identity",
    )?;
    let client_error = automation
        .set_value(&window.window_id, &cached_record.element_id, "9.9")
        .err()
        .ok_or("latest Toolkit client must retain original provider")?;
    check(
        [ErrorCode::StaleElement, ErrorCode::ActionNotSupported].contains(&client_error.code),
        "client retargeted/refused with wrong code",
    )?;
    check(domain(port, 2)? == before_b, "cached A action changed B")?;
    check(domain(port, 1)? == a, "cached A action changed A")?;
    mark(
        events,
        "cached_provider_refusal",
        t,
        json!({"raw_pattern_hresult":format!("0x{:08X}",error.code().0 as u32),"toolkit_error":client_error,"wall_b":before_b}),
    );
    let fresh = automation.find_control(
        &window.window_id,
        &ControlQuery {
            automation_id: Some("properties.wall.height".into()),
            ..Default::default()
        },
    )?;
    let fresh_native = find(&client, &root, "properties.wall.height")?;
    check(
        runtime_id(&fresh_native)? != height_runtime_id,
        "BIM object replacement reused old RuntimeId",
    )?;
    let t = now_unix_ms();
    let state = automation.set_value(&window.window_id, &fresh.element_id, "3.2")?;
    check(
        state.value.as_deref() == Some("3.2"),
        "fresh B readback failed",
    )?;
    let after_b = wait_height(port, 2, 3.2)?;
    mark(
        events,
        "fresh_wall_b_allowed",
        t,
        json!({"state":state,"domain":after_b,"wall_a":domain(port,1)?}),
    );
    let t = now_unix_ms();
    for value in ["NaN", "-1", "3200 mm"] {
        let current = find(&client, &root, "properties.wall.height")?;
        let pattern: IUIAutomationValuePattern =
            unsafe { current.GetCurrentPatternAs(UIA_ValuePatternId) }?;
        check(
            unsafe { pattern.SetValue(&BSTR::from(value)) }.is_err(),
            "invalid value accepted",
        )?;
        check(domain(port, 2)? == after_b, "invalid value changed B")?;
    }
    mark(
        events,
        "invalid_values_no_mutation",
        t,
        json!({"domain":domain(port,2)?}),
    );
    let t = now_unix_ms();
    automation.focus_window(&window.window_id)?;
    let current = find(&client, &root, "properties.wall.height")?;
    unsafe { current.SetFocus() }?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let focus = loop {
        let ui = api(port, "ui.state", json!({}))?;
        if ui["property_editing"]["makepad_key_focus"] == true
            && unsafe { current.CurrentHasKeyboardFocus() }?.as_bool()
        {
            break ui;
        };
        check(
            Instant::now() < deadline,
            "TextInput did not acquire actual Makepad KeyFocus",
        )?;
        std::thread::sleep(Duration::from_millis(25));
    };
    let mut native = GUITHREADINFO {
        cbSize: std::mem::size_of::<GUITHREADINFO>() as u32,
        ..Default::default()
    };
    unsafe { GetGUIThreadInfo(GetWindowThreadProcessId(hwnd, None), &mut native) }?;
    check(
        unsafe { GetForegroundWindow() } == hwnd && native.hwndFocus == hwnd,
        "foreground/window focus is not the owned window",
    )?;
    let independently_focused = unsafe { client.GetFocusedElement() }?;
    check(
        unsafe { independently_focused.CurrentAutomationId() }?.to_string()
            == "properties.wall.height",
        "independent UIA GetFocus did not return Height",
    )?;
    mark(
        events,
        "actual_textinput_focus",
        t,
        json!({"foreground_hwnd":format!("0x{:X}",hwnd.0 as usize),"window_focus_hwnd":format!("0x{:X}",native.hwndFocus.0 as usize),"makepad_key_focus":focus["property_editing"]["makepad_key_focus"],"uia_has_keyboard_focus":true}),
    );
    let t = now_unix_ms();
    let before = automation.inspect_window_interaction(&window.window_id)?;
    let resized = automation.set_window_bounds(&window.window_id, None, None, 1400, 900)?;
    let after = automation.inspect_window_interaction(&window.window_id)?;
    let tree = automation.get_control_tree(
        &window.window_id,
        &ControlTreeOptions {
            max_elements: Some(32),
            ..Default::default()
        },
    )?;
    let refreshed = find(&client, &root, "properties.wall.height")?;
    let bounds = unsafe { refreshed.CurrentBoundingRectangle() }?;
    check(
        bounds.right > bounds.left && bounds.bottom > bounds.top,
        "Height has no physical bounds after resize",
    )?;
    let point = POINT {
        x: (bounds.left + bounds.right) / 2,
        y: (bounds.top + bounds.bottom) / 2,
    };
    let hit = unsafe { client.ElementFromPoint(point) }?;
    check(
        unsafe { hit.CurrentAutomationId() }?.to_string() == "properties.wall.height",
        "independent point provider disagrees with refreshed physical bounds",
    )?;
    mark(
        events,
        "independent_point_and_focus",
        t,
        json!({"focus_automation_id":"properties.wall.height","point":{"x":point.x,"y":point.y},"physical_bounds":{"left":bounds.left,"top":bounds.top,"right":bounds.right,"bottom":bounds.bottom},"hit_automation_id":"properties.wall.height"}),
    );
    let capture = automation.capture_window(
        &window.window_id,
        Some(&output.join("fresh-consumer.png").to_string_lossy()),
    )?;
    check(
        capture.non_blank && !capture.fallback_used,
        "fresh capture failed or fell back",
    )?;
    mark(
        events,
        "dpi_resize_capture",
        t,
        json!({"before":before,"resize":resized,"after":after,"tree":tree,"capture":capture}),
    );
    save(&mut automation, &window.window_id, events)?;
    Ok(())
}

fn save(automation: &mut WindowsAutomation, window: &str, events: &mut Vec<Value>) -> Result<()> {
    let save = automation.find_control(
        window,
        &ControlQuery {
            automation_id: Some("toolbar.save".into()),
            ..Default::default()
        },
    )?;
    check(save.capabilities.invoke, "Save has no InvokePattern")?;
    let t = now_unix_ms();
    let port = arg("--consumer-port")?.parse()?;
    let document = api(port, "document.info", json!({}))?;
    let save_path = PathBuf::from(arg("--save-path")?);
    check(
        save_path
            .parent()
            .ok_or("save path has no parent")?
            .canonicalize()?
            .starts_with(PathBuf::from(arg("--output-dir")?).canonicalize()?),
        "Save target must be private to this attempt",
    )?;
    let action = automation.click_element(window, &save.element_id)?;
    check(
        action.action_method == "InvokePattern",
        "Save used a fallback",
    )?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(metadata) = fs::metadata(&save_path) {
            if metadata.len() > 0
                && metadata
                    .modified()?
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis()
                    >= t
            {
                break;
            }
        }
        check(
            Instant::now() < deadline,
            "Invoke Save produced no fresh disposable file",
        )?;
        std::thread::sleep(Duration::from_millis(25));
    }
    let text = fs::read_to_string(&save_path)?;
    check(
        text.contains(
            document["document_uuid"]
                .as_str()
                .ok_or("document UUID missing")?,
        ),
        "saved file has wrong document identity",
    )?;
    check(
        api(port, "document.info", json!({}))? == document,
        "Save changed canonical document state",
    )?;
    mark(
        events,
        "save_invoke",
        t,
        json!({"action":action,"saved_path":save_path,"file_bytes":text.len(),"saved_document_uuid":document["document_uuid"],"document_after":document}),
    );
    Ok(())
}

use super::*;
use std::{
    fs,
    io::Write,
    os::windows::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use windows as windows_uia;
use windows_uia::{
    Win32::{
        Foundation::{
            CloseHandle, FILETIME, HANDLE, HWND, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW},
        System::{
            DataExchange::{
                CountClipboardFormats, GetClipboardOwner, GetClipboardSequenceNumber,
                GetOpenClipboardWindow, IsClipboardFormatAvailable,
            },
            RemoteDesktop::ProcessIdToSessionId,
            Threading::{
                CreateMutexW, GetCurrentProcessId, GetProcessTimes, OpenProcess,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, ReleaseMutex,
                WaitForSingleObject,
            },
        },
        UI::{
            Input::KeyboardAndMouse::{
                GetAsyncKeyState, VK_CONTROL, VK_LBUTTON, VK_LWIN, VK_MBUTTON, VK_MENU, VK_RBUTTON,
                VK_RWIN, VK_SHIFT, VK_XBUTTON1, VK_XBUTTON2,
            },
            Shell::{
                FOLDERID_LocalAppData, FOLDERID_System, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
            },
            WindowsAndMessaging::{
                GetForegroundWindow, GetWindowThreadProcessId, IsWindow, IsWindowVisible, SW_HIDE,
                SW_SHOWNOACTIVATE, ShowWindow,
            },
        },
    },
    core::PCWSTR,
};

fn err(code: &str, message: impl Into<String>) -> ArbiterError {
    ArbiterError {
        code: code.into(),
        message: message.into(),
    }
}
pub fn clock_ms() -> u64 {
    crate::now_unix_ms().try_into().unwrap_or(u64::MAX)
}
fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.as_ref().encode_wide().chain(Some(0)).collect()
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
struct MutexGuard(Handle);
impl Drop for MutexGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.0.0);
        }
    }
}

/// Birth time is from the live kernel process, not caller-supplied PID metadata.
pub fn process_birth(pid: u32) -> Result<u64, ArbiterError> {
    let handle = Handle(
        unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        }
        .map_err(|e| err("OWNER_IDENTITY_UNAVAILABLE", e.to_string()))?,
    );
    if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_TIMEOUT {
        return Err(err("OWNER_LOST", "process has exited"));
    }
    let (mut born, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe { GetProcessTimes(handle.0, &mut born, &mut exit, &mut kernel, &mut user) }
        .map_err(|e| err("OWNER_IDENTITY_UNAVAILABLE", e.to_string()))?;
    Ok((u64::from(born.dwHighDateTime) << 32) | u64::from(born.dwLowDateTime))
}
pub fn current_owner(
    worker: &str,
    job: &str,
    attempt: &str,
    session: &str,
) -> Result<Owner, ArbiterError> {
    let pid = unsafe { GetCurrentProcessId() };
    Ok(Owner {
        worker_id: worker.into(),
        job_id: job.into(),
        attempt_id: attempt.into(),
        session_id: session.into(),
        pid,
        process_birth: process_birth(pid)?,
    })
}
fn validate_owner(owner: &Owner) -> Result<(), ArbiterError> {
    if owner.pid != unsafe { GetCurrentProcessId() }
        || process_birth(owner.pid)? != owner.process_birth
    {
        return Err(err(
            "OWNER_IDENTITY_MISMATCH",
            "lease owner is not this live process incarnation",
        ));
    }
    Ok(())
}
fn confirmed_dead_or_reused(owner: &Owner) -> Result<bool, ArbiterError> {
    let handle = match unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            owner.pid,
        )
    } {
        Ok(handle) => Handle(handle),
        Err(e) if e.code().0 as u32 == 0x80070057 => return Ok(true), // invalid PID, kernel says absent
        Err(e) => return Err(err("OWNER_LIVENESS_UNKNOWN", e.to_string())),
    };
    if unsafe { WaitForSingleObject(handle.0, 0) } == WAIT_OBJECT_0 {
        return Ok(true);
    }
    Ok(process_birth(owner.pid)? != owner.process_birth)
}
pub fn owned_window(hwnd: u64, pid: u32, birth: u64) -> Result<Resource, ArbiterError> {
    let window = HWND(hwnd as usize as *mut _);
    let mut actual = 0;
    unsafe {
        GetWindowThreadProcessId(window, Some(&mut actual));
    }
    if !unsafe { IsWindow(Some(window)) }.as_bool() || actual != pid || process_birth(pid)? != birth
    {
        return Err(err(
            "WINDOW_IDENTITY_MISMATCH",
            "HWND/PID/birth no longer identifies the trusted owned window",
        ));
    }
    Ok(Resource::WindowMutation {
        hwnd,
        pid,
        process_birth: birth,
    })
}
fn validate_resources(resources: &[Resource]) -> Result<(), ArbiterError> {
    for resource in resources {
        if let Resource::WindowMutation {
            hwnd,
            pid,
            process_birth: birth,
        } = resource
        {
            owned_window(*hwnd, *pid, *birth)?;
        }
    }
    Ok(())
}

/// Observes physical state; never sends speculative global key-up/button-up.
pub fn observe_safe_point(
    background_observed: bool,
    host_buttons: bool,
    host_modifiers: bool,
    pending_focus_action: bool,
    clipboard_transaction: bool,
) -> SafePoint {
    let pressed = |key| unsafe { GetAsyncKeyState(key) } < 0;
    SafePoint {
        held_buttons: host_buttons
            || [VK_LBUTTON, VK_RBUTTON, VK_MBUTTON, VK_XBUTTON1, VK_XBUTTON2]
                .iter()
                .any(|k| pressed(i32::from(k.0))),
        held_modifiers: host_modifiers
            || [VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN]
                .iter()
                .any(|k| pressed(i32::from(k.0))),
        pending_focus_action,
        clipboard_transaction,
        background_observed,
    }
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClipboardObservation {
    pub sequence: u32,
    pub owner_hwnd: u64,
    pub owner_pid: u32,
    pub format_count: i32,
    pub unicode_text_available: bool,
    pub open_owner_hwnd: u64,
    pub sequence_after: u32,
    pub consistent: bool,
    pub native_text_readback_verified: bool,
    pub owner_identity_verified: bool,
    pub verification_source: String,
}
pub fn clipboard_observation() -> ClipboardObservation {
    let before_sequence = unsafe { GetClipboardSequenceNumber() };
    let hwnd = unsafe { GetClipboardOwner() }.unwrap_or_default();
    let mut pid = 0;
    if !hwnd.0.is_null() {
        unsafe {
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
        }
    }
    let format_count = unsafe { CountClipboardFormats() };
    let unicode_text_available = unsafe { IsClipboardFormatAvailable(13) }.is_ok();
    let open_owner_hwnd = unsafe { GetOpenClipboardWindow() }.unwrap_or_default().0 as u64;
    let after_sequence = unsafe { GetClipboardSequenceNumber() };
    ClipboardObservation {
        sequence: before_sequence,
        owner_hwnd: hwnd.0 as u64,
        owner_pid: pid,
        format_count,
        unicode_text_available,
        open_owner_hwnd,
        sequence_after: after_sequence,
        consistent: before_sequence == after_sequence,
        native_text_readback_verified: false,
        owner_identity_verified: false,
        verification_source: "win32_clipboard_metadata".into(),
    }
}

/// Authenticated transaction handle; clipboard bytes are never collected here.
pub struct ClipboardTicket {
    lease: Lease,
    owner: Owner,
    before: ClipboardObservation,
    window: Resource,
}
impl ClipboardTicket {
    pub fn before(&self) -> &ClipboardObservation {
        &self.before
    }
}

/// Reuse the native `Get-Clipboard -Raw` observer used by the RudraOffice
/// clipboard harness. Fixed read-only command, bounded child, no clipboard
/// writer and no unexpected clipboard bytes in stdout, errors, or evidence.
fn native_clipboard_matches(expected: &str) -> Result<bool, ArbiterError> {
    if expected.len() > 4096 {
        return Err(err(
            "CLIPBOARD_READBACK_LIMIT",
            "controlled expectation is limited to 4096 UTF-8 bytes",
        ));
    }
    let folder = unsafe { SHGetKnownFolderPath(&FOLDERID_System, KF_FLAG_DEFAULT, None) }
        .map_err(|e| err("CLIPBOARD_OBSERVER_UNAVAILABLE", e.to_string()))?;
    let system = unsafe { folder.to_string() }
        .map_err(|e| err("CLIPBOARD_OBSERVER_UNAVAILABLE", e.to_string()));
    unsafe {
        windows_uia::Win32::System::Com::CoTaskMemFree(Some(folder.0 as *const _));
    }
    let executable = PathBuf::from(system?).join("WindowsPowerShell/v1.0/powershell.exe");
    let script = "$ErrorActionPreference='Stop';[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);$expected=[Console]::In.ReadToEnd();try{$actual=Get-Clipboard -Raw;[Console]::Write($(if([string]::Equals([string]$actual,$expected,[StringComparison]::Ordinal)){'MATCH'}else{'MISMATCH'}))}catch{[Console]::Write('OBSERVER_FAILED');exit 2}";
    let mut child = Command::new(executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .creation_flags(0x08000000)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| err("CLIPBOARD_OBSERVER_UNAVAILABLE", e.to_string()))?;
    if child
        .stdin
        .take()
        .ok_or_else(|| err("CLIPBOARD_OBSERVER_UNAVAILABLE", "missing observer stdin"))?
        .write_all(expected.as_bytes())
        .is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(err("CLIPBOARD_OBSERVER_FAILURE", "observer stdin failed"));
    }
    let deadline = Instant::now() + Duration::from_millis(2000);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err(
                    "CLIPBOARD_OBSERVER_TIMEOUT",
                    "bounded native observer did not complete",
                ));
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|_| err("CLIPBOARD_OBSERVER_FAILURE", "observer result unavailable"))?;
    if !output.status.success() {
        return Err(err(
            "CLIPBOARD_OBSERVER_FAILURE",
            "native observer failed; clipboard bytes not collected",
        ));
    }
    Ok(output.stdout == b"MATCH")
}

/// One registry for the current user/Windows session. The named mutex protects
/// only short read/transition/atomic-write operations, never GUI or wait callbacks.
/// This is a cooperative trusted-worker protocol, not a security boundary against
/// arbitrary code running as the same Windows user.
#[derive(Clone, Debug)]
pub struct DesktopArbiter {
    root: PathBuf,
    mutex_name: Vec<u16>,
}
impl DesktopArbiter {
    pub fn borrow_reservation(&self, lease: &Lease, owner: &Owner) -> Result<(), ArbiterError> {
        validate_owner(owner)?;
        self.transaction(|r| r.borrow_reservation(lease, owner, clock_ms()))
    }
    pub fn return_reservation(&self, lease: &Lease, owner: &Owner) -> Result<(), ArbiterError> {
        validate_owner(owner)?;
        self.transaction(|r| r.return_reservation(lease, owner, clock_ms()))
    }
    pub fn begin_clipboard_transaction(
        &self,
        lease: &Lease,
        owner: &Owner,
    ) -> Result<ClipboardTicket, ArbiterError> {
        self.validate(lease, owner)?;
        let registry = self.inspect_arbiter()?;
        let entry = registry
            .entries
            .iter()
            .find(|entry| {
                entry.request_id == lease.request_id
                    && entry.generation == lease.generation
                    && entry.owner == *owner
            })
            .ok_or_else(|| err("STALE_GENERATION", "clipboard lease not current"))?;
        let parent = entry.continuation_of.and_then(|(id, generation)| {
            registry.entries.iter().find(|parent| {
                parent.request_id == id && parent.generation == generation && parent.owner == *owner
            })
        });
        let windows: Vec<_> = entry
            .resources
            .iter()
            .chain(
                parent
                    .into_iter()
                    .flat_map(|parent| parent.resources.iter()),
            )
            .filter(|r| matches!(r, Resource::WindowMutation { .. }))
            .cloned()
            .collect();
        if windows.len() != 1 {
            return Err(err(
                "CLIPBOARD_RESOURCE_REQUIRED",
                "clipboard needs one authenticated app window before marking pending",
            ));
        }
        validate_resources(&windows)?;
        let before = clipboard_observation();
        if !before.consistent || before.open_owner_hwnd != 0 {
            return Err(err(
                "CLIPBOARD_BUSY_OR_CHANGED",
                "clipboard observation is not quiescent",
            ));
        }
        self.transaction(|r| r.begin_clipboard(lease, owner, clock_ms()))?;
        Ok(ClipboardTicket {
            lease: lease.clone(),
            owner: owner.clone(),
            before,
            window: windows[0].clone(),
        })
    }
    pub fn finish_clipboard_copy(
        &self,
        ticket: ClipboardTicket,
        expected_text: &str,
    ) -> Result<ClipboardObservation, ArbiterError> {
        self.validate(&ticket.lease, &ticket.owner)?;
        let Resource::WindowMutation {
            hwnd,
            pid,
            process_birth: birth,
        } = ticket.window
        else {
            return Err(err("CLIPBOARD_RESOURCE_REQUIRED", "copy window missing"));
        };
        owned_window(hwnd, pid, birth)?;
        let deadline = Instant::now() + Duration::from_millis(1500);
        loop {
            let mut after = clipboard_observation();
            if after.consistent && after.sequence != ticket.before.sequence {
                if process_birth(pid)? != birth {
                    return Err(err(
                        "WINDOW_IDENTITY_MISMATCH",
                        "clipboard app incarnation changed",
                    ));
                }
                // Makepad currently uses OpenClipboard(NULL). Null owner is
                // unattributed, not proof of a foreign writer or an owned PID.
                if after.owner_pid != 0 && after.owner_pid != pid {
                    return Err(err(
                        "CLIPBOARD_EXTERNAL_INTERFERENCE",
                        "clipboard has a foreign owner",
                    ));
                }
                if after.open_owner_hwnd == 0 && after.unicode_text_available {
                    if !native_clipboard_matches(expected_text)? {
                        return Err(err(
                            "CLIPBOARD_EXTERNAL_INTERFERENCE",
                            "independent native clipboard readback differs from controlled expectation",
                        ));
                    }
                    let checked = clipboard_observation();
                    if !checked.consistent
                        || checked.sequence != after.sequence
                        || checked.owner_hwnd != after.owner_hwnd
                        || checked.open_owner_hwnd != 0
                    {
                        return Err(err(
                            "CLIPBOARD_EXTERNAL_INTERFERENCE",
                            "clipboard changed during native readback",
                        ));
                    }
                    self.validate(&ticket.lease, &ticket.owner)?;
                    after.native_text_readback_verified = true;
                    after.owner_identity_verified = after.owner_pid == pid;
                    after.verification_source =
                        "win32_metadata_and_existing_powershell_native_readback".into();
                    self.transaction(|r| {
                        r.finish_clipboard(&ticket.lease, &ticket.owner, clock_ms())
                    })?;
                    return Ok(after);
                }
            }
            if Instant::now() >= deadline {
                return Err(err(
                    "CLIPBOARD_CHANGE_NOT_OBSERVED",
                    "copy dispatch did not prove ownership, sequence and format",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    pub fn finish_clipboard_paste(
        &self,
        ticket: ClipboardTicket,
        expected: &ClipboardObservation,
        domain_verified: bool,
    ) -> Result<ClipboardObservation, ArbiterError> {
        self.validate(&ticket.lease, &ticket.owner)?;
        let after = clipboard_observation();
        if !after.consistent
            || ticket.before.sequence != expected.sequence
            || after.sequence != expected.sequence
            || after.owner_hwnd != expected.owner_hwnd
            || after.owner_pid != expected.owner_pid
        {
            return Err(err(
                "CLIPBOARD_EXTERNAL_INTERFERENCE",
                "clipboard changed during the reserved paste transaction",
            ));
        }
        if !domain_verified || after.open_owner_hwnd != 0 {
            return Err(err(
                "CLIPBOARD_POSTCONDITION_MISSING",
                "paste needs actual app readback and closed clipboard",
            ));
        }
        self.transaction(|r| r.finish_clipboard(&ticket.lease, &ticket.owner, clock_ms()))?;
        Ok(after)
    }
    pub fn open() -> Result<Self, ArbiterError> {
        let mut session = 0;
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }
            .map_err(|e| err("DESKTOP_SESSION_UNAVAILABLE", e.to_string()))?;
        // The Windows user profile location is OS-resolved, not TEMP/AI/job env.
        let folder = unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None) }
            .map_err(|e| err("ARBITER_STORAGE_FAILURE", e.to_string()))?;
        let folder_string = unsafe { folder.to_string() }
            .map_err(|e| err("ARBITER_STORAGE_FAILURE", e.to_string()));
        unsafe {
            windows_uia::Win32::System::Com::CoTaskMemFree(Some(folder.0 as *const _));
        }
        let root = PathBuf::from(folder_string?)
            .join("MakepadToolkit")
            .join("desktop-arbiter-v1")
            .join(format!("session-{session}"));
        fs::create_dir_all(&root).map_err(|e| err("ARBITER_STORAGE_FAILURE", e.to_string()))?;
        if root
            .symlink_metadata()
            .map_err(|e| err("ARBITER_STORAGE_FAILURE", e.to_string()))?
            .file_type()
            .is_symlink()
        {
            return Err(err(
                "RESOURCE_QUARANTINED",
                "registry root must not be a symlink",
            ));
        }
        Ok(Self {
            root,
            mutex_name: wide(format!("Local\\MakepadToolkitDesktopArbiterV1-{session}")),
        })
    }
    pub fn registry_path(&self) -> PathBuf {
        self.root.join("resource-registry.json")
    }
    fn transaction<T>(
        &self,
        update: impl FnOnce(&mut Registry) -> Result<T, ArbiterError>,
    ) -> Result<T, ArbiterError> {
        let handle = Handle(
            unsafe { CreateMutexW(None, false, PCWSTR(self.mutex_name.as_ptr())) }
                .map_err(|e| err("ARBITER_MUTEX_FAILURE", e.to_string()))?,
        );
        let wait = unsafe { WaitForSingleObject(handle.0, 2_000) };
        if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
            return Err(err(
                "ARBITER_STATE_LOCK_TIMEOUT",
                "bounded registry mutex wait failed",
            ));
        }
        let _guard = MutexGuard(handle);
        let abandoned_path = self.root.join("abandoned-recovery-required.json");
        if wait == WAIT_ABANDONED {
            fs::write(
                &abandoned_path,
                b"{\"state\":\"RECOVERING\",\"reason\":\"WAIT_ABANDONED\"}",
            )
            .map_err(|e| err("RESOURCE_QUARANTINED", e.to_string()))?;
        }
        let path = self.registry_path();
        let initialized = self.root.join("registry-initialized");
        if path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink() || m.len() > 16 * 1024 * 1024)
        {
            return Err(err("RESOURCE_QUARANTINED", "unsafe or oversized registry"));
        }
        let mut registry: Registry = match fs::read(&path) {
            Ok(bytes) if bytes.len() <= 16 * 1024 * 1024 => serde_json::from_slice(&bytes)
                .map_err(|e| {
                    err(
                        "RESOURCE_QUARANTINED",
                        format!("invalid registry; operator recovery required: {e}"),
                    )
                })?,
            Ok(_) => return Err(err("RESOURCE_QUARANTINED", "oversize registry")),
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && wait != WAIT_ABANDONED
                    && !initialized.exists() =>
            {
                use std::io::Write;
                let mut marker = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&initialized)
                    .map_err(|e| err("RESOURCE_QUARANTINED", e.to_string()))?;
                marker
                    .write_all(b"schema1\n")
                    .and_then(|_| marker.sync_all())
                    .map_err(|e| err("RESOURCE_QUARANTINED", e.to_string()))?;
                Registry::default()
            }
            Err(e) => {
                return Err(err(
                    "RESOURCE_QUARANTINED",
                    format!("registry unavailable: {e}"),
                ));
            }
        };
        registry
            .validate_storage()
            .map_err(|e| err("RESOURCE_QUARANTINED", e.to_string()))?;
        // An abandoned mutex means any nonterminal holder is uncertain, even if
        // its heartbeat has not expired. Never turn WAIT_ABANDONED into PASS.
        let now = clock_ms();
        let owners: Vec<Owner> = registry
            .entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.state,
                    State::Leased
                        | State::GuiActive
                        | State::Quiescing
                        | State::Verifying
                        | State::BackgroundRunning
                ) && (wait == WAIT_ABANDONED
                    || process_birth(entry.owner.pid).is_ok_and(|b| b != entry.owner.process_birth)
                    || process_birth(entry.owner.pid).is_err())
            })
            .map(|entry| entry.owner.clone())
            .collect();
        for owner in owners {
            registry.owner_lost(&owner, now)?;
        }
        registry.expire(now)?;
        let result = if abandoned_path.exists() {
            Err(err(
                "ARBITER_ABANDONED_RECOVERY_REQUIRED",
                "named mutex was abandoned; explicit recovery validation required",
            ))
        } else {
            update(&mut registry)
        };
        // Persist loss, timeout and cancellation even when the requested action failed.
        let data = serde_json::to_vec_pretty(&registry)
            .map_err(|e| err("ARBITER_STORAGE_FAILURE", e.to_string()))?;
        let temporary = self
            .root
            .join(format!("resource-registry-{}.pending", unsafe {
                GetCurrentProcessId()
            }));
        let mut file = fs::File::create(&temporary)
            .map_err(|e| err("ARBITER_STORAGE_FAILURE", e.to_string()))?;
        use std::io::Write;
        file.write_all(&data)
            .and_then(|_| file.sync_all())
            .map_err(|e| err("ARBITER_STORAGE_FAILURE", e.to_string()))?;
        drop(file);
        unsafe {
            MoveFileExW(
                PCWSTR(wide(&temporary).as_ptr()),
                PCWSTR(wide(&path).as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|e| err("RESOURCE_QUARANTINED", e.to_string()))?;
        result
    }
    pub fn request_lease(
        &self,
        resources: Vec<Resource>,
        owner: &Owner,
        deadline: u64,
    ) -> Result<u64, ArbiterError> {
        validate_owner(owner)?;
        validate_resources(&resources)?;
        self.transaction(|r| r.request(owner.clone(), resources, clock_ms(), deadline))
    }
    pub fn wait_lease(
        &self,
        request: u64,
        owner: &Owner,
        cancelled: &AtomicBool,
    ) -> Result<Lease, ArbiterError> {
        let wait_deadline = clock_ms().saturating_add(60_000);
        loop {
            validate_owner(owner)?;
            if cancelled.load(Ordering::Acquire) {
                self.retire_unreturned_request(request, owner)?;
                return Err(err(
                    "LEASE_WAIT_CANCELLED",
                    "waiting for desktop lease cancelled; no GUI dispatch",
                ));
            }
            if clock_ms() >= wait_deadline {
                self.retire_unreturned_request(request, owner)?;
                return Err(err(
                    "LEASE_WAIT_TIMEOUT",
                    "bounded acquisition wait exceeded; no GUI dispatch",
                ));
            }
            match self.transaction(|r| r.poll(request, owner, clock_ms())) {
                Ok(Some(lease)) => return Ok(lease),
                Ok(None) => {}
                Err(e) if e.code == "TIMED_OUT" => {
                    return Err(err(
                        "LEASE_WAIT_TIMEOUT",
                        "resource wait deadline exceeded; no GUI dispatch",
                    ));
                }
                Err(e) => {
                    self.retire_unreturned_request(request, owner)
                        .map_err(|cleanup| {
                            err(
                                "ARBITER_WAIT_CLEANUP_UNVERIFIED",
                                format!("original={e}; cleanup={cleanup}; resources retained"),
                            )
                        })?;
                    return Err(e);
                }
            }
            thread::sleep(Duration::from_millis(15));
        }
    }
    /// This request has NEVER been returned to a dispatch caller. Under the
    /// same native mutex, retire queued work or safely release an uncertain
    /// Leased grant. Never release GUI_ACTIVE, a borrower or pending clipboard.
    fn retire_unreturned_request(&self, request: u64, owner: &Owner) -> Result<(), ArbiterError> {
        validate_owner(owner)?;
        let proof = observe_safe_point(false, false, false, false, false);
        self.transaction(|r| {
            let entry = r
                .entries
                .iter()
                .find(|entry| entry.request_id == request && entry.owner == *owner)
                .ok_or_else(|| err("OWNER_MISMATCH", "unreturned request identity unavailable"))?
                .clone();
            match entry.state {
                State::Queued | State::WaitingResources | State::ResumeQueued => {
                    r.cancel(request, owner, clock_ms())
                }
                State::Leased if entry.active_reservations == 0 && !entry.clipboard_pending => {
                    let lease = Lease {
                        request_id: request,
                        generation: entry.generation,
                        owner: entry.owner,
                        resources: entry.resources,
                        acquired_at: entry
                            .acquired_at
                            .ok_or_else(|| err("INVALID_REGISTRY", "lease acquisition missing"))?,
                        deadline: entry.deadline,
                    };
                    r.release(&lease, owner, &proof, clock_ms())
                }
                State::Completed | State::Cancelled | State::TimedOut | State::OwnerLost
                    if entry.acquired_at.is_none() =>
                {
                    Ok(())
                }
                _ => Err(err(
                    "RESOURCE_QUARANTINED",
                    "unreturned request cannot be safely retired",
                )),
            }
        })
    }
    pub fn cancel_wait(&self, request: u64, owner: &Owner) -> Result<(), ArbiterError> {
        validate_owner(owner)?;
        self.transaction(|r| r.cancel(request, owner, clock_ms()))
    }
    pub fn validate(&self, lease: &Lease, owner: &Owner) -> Result<(), ArbiterError> {
        validate_owner(owner)?;
        validate_resources(&lease.resources)?;
        self.transaction(|r| r.heartbeat(lease, owner, clock_ms()))
    }
    pub fn begin_gui(&self, lease: &Lease, owner: &Owner) -> Result<(), ArbiterError> {
        validate_owner(owner)?;
        validate_resources(&lease.resources)?;
        self.transaction(|r| r.begin_gui(lease, owner, clock_ms()))
    }
    pub fn quarantine_uncertain_lease(
        &self,
        lease: &Lease,
        owner: &Owner,
    ) -> Result<(), ArbiterError> {
        validate_owner(owner)?;
        self.transaction(|r| {
            r.validate(lease, owner, clock_ms())?;
            r.owner_lost(owner, clock_ms())
        })
    }
    pub fn release_lease(
        &self,
        lease: &Lease,
        owner: &Owner,
        proof: &SafePoint,
    ) -> Result<(), ArbiterError> {
        validate_owner(owner)?;
        self.transaction(|r| r.release(lease, owner, proof, clock_ms()))
    }
    pub fn yield_gui(
        &self,
        lease: &Lease,
        owner: &Owner,
        proof: &SafePoint,
    ) -> Result<(), ArbiterError> {
        validate_owner(owner)?;
        self.transaction(|r| r.yield_gui(lease, owner, proof, clock_ms()))
    }
    pub fn resume_gui(
        &self,
        yielded: u64,
        owner: &Owner,
        deadline: u64,
    ) -> Result<u64, ArbiterError> {
        validate_owner(owner)?;
        self.transaction(|r| r.resume(yielded, owner, clock_ms(), deadline))
    }
    pub fn yield_retaining_logical(
        &self,
        lease: &Lease,
        owner: &Owner,
        proof: &SafePoint,
    ) -> Result<Lease, ArbiterError> {
        validate_owner(owner)?;
        validate_resources(&lease.resources)?;
        self.transaction(|r| r.yield_retaining_logical(lease, owner, proof, clock_ms()))
    }
    pub fn request_input_continuation(
        &self,
        parent: &Lease,
        owner: &Owner,
        deadline: u64,
    ) -> Result<u64, ArbiterError> {
        validate_owner(owner)?;
        validate_resources(&parent.resources)?;
        self.transaction(|r| r.request_input_continuation(parent, owner, clock_ms(), deadline))
    }
    pub fn inspect_arbiter(&self) -> Result<Registry, ArbiterError> {
        self.transaction(|r| Ok(r.clone()))
    }
    /// Explicit recovery of a confirmed-dead incarnation. Heartbeat timeout or
    /// unknown clipboard safety alone is insufficient; no input is injected.
    pub fn recover_dead_owner(&self, request: u64) -> Result<(), ArbiterError> {
        let registry = self.inspect_arbiter()?;
        let entry = registry
            .entries
            .iter()
            .find(|e| e.request_id == request)
            .ok_or_else(|| err("STALE_LEASE", "unknown recovery request"))?;
        if !confirmed_dead_or_reused(&entry.owner)? {
            return Err(err(
                "RECOVERY_OWNER_STILL_ALIVE",
                "live owner must release cooperatively",
            ));
        }
        let parent = entry.continuation_of.and_then(|(id, _)| {
            registry
                .entries
                .iter()
                .find(|candidate| candidate.request_id == id)
        });
        if entry.continuation_of.is_some() && parent.is_none() {
            return Err(err(
                "RESOURCE_QUARANTINED",
                "continuation cleanup needs its pinned logical parent",
            ));
        }
        for target in entry.resources.iter().chain(
            parent
                .into_iter()
                .flat_map(|parent| parent.resources.iter()),
        ) {
            if let Resource::WindowMutation {
                hwnd,
                pid,
                process_birth: birth,
            } = target
            {
                if owned_window(*hwnd, *pid, *birth).is_ok() {
                    return Err(err(
                        "RESOURCE_QUARANTINED",
                        "owned application window remains alive; owned lifecycle cleanup required first",
                    ));
                }
                let process = Owner {
                    pid: *pid,
                    process_birth: *birth,
                    ..entry.owner.clone()
                };
                if !confirmed_dead_or_reused(&process)? {
                    return Err(err(
                        "RESOURCE_QUARANTINED",
                        "application process still alive or identity uncertain",
                    ));
                }
            }
        }
        let proof = observe_safe_point(false, false, false, false, false);
        if !proof.safe_for_release() {
            return Err(err(
                "RESOURCE_QUARANTINED",
                "actual input is not neutral; no guessed key-up or clipboard recovery",
            ));
        }
        if entry.resources.contains(&Resource::SystemClipboard) {
            let before = clipboard_observation();
            let after = clipboard_observation();
            if !before.consistent
                || !after.consistent
                || before.sequence != after.sequence
                || after.open_owner_hwnd != 0
            {
                return Err(err(
                    "RESOURCE_QUARANTINED",
                    "clipboard remains open/changing; recovery refused, contents not restored",
                ));
            }
            self.transaction(|r| r.recover_clipboard_checkpoint(request, clock_ms()))?;
        }
        self.transaction(|r| {
            r.recover_reservations_checkpoint(request, clock_ms())?;
            r.recover(request, &proof, clock_ms())
        })
    }
    /// Operator-only validation. Does not free any lease; dead leases still need
    /// individually validated recovery. File removal is under the same mutex.
    pub fn validate_abandoned_recovery(&self) -> Result<(), ArbiterError> {
        let handle = Handle(
            unsafe { CreateMutexW(None, false, PCWSTR(self.mutex_name.as_ptr())) }
                .map_err(|e| err("ARBITER_MUTEX_FAILURE", e.to_string()))?,
        );
        let result = unsafe { WaitForSingleObject(handle.0, 2000) };
        if result != WAIT_OBJECT_0 && result != WAIT_ABANDONED {
            return Err(err(
                "ARBITER_STATE_LOCK_TIMEOUT",
                "recovery mutex unavailable",
            ));
        }
        let _guard = MutexGuard(handle);
        let registry: Registry = serde_json::from_slice(
            &fs::read(self.registry_path())
                .map_err(|e| err("RESOURCE_QUARANTINED", e.to_string()))?,
        )
        .map_err(|e| err("RESOURCE_QUARANTINED", e.to_string()))?;
        registry
            .validate_storage()
            .map_err(|e| err("RESOURCE_QUARANTINED", e.to_string()))?;
        let proof = observe_safe_point(false, false, false, false, false);
        if proof.held_buttons || proof.held_modifiers {
            return Err(err("RESOURCE_QUARANTINED", "physical input is not neutral"));
        }
        if registry.entries.iter().any(|e| {
            matches!(
                e.state,
                State::Leased
                    | State::GuiActive
                    | State::Quiescing
                    | State::Verifying
                    | State::BackgroundRunning
            )
        }) {
            return Err(err("RESOURCE_QUARANTINED", "active leases still uncertain"));
        }
        let flag = self.root.join("abandoned-recovery-required.json");
        if flag.is_file() {
            fs::remove_file(flag).map_err(|e| err("RESOURCE_QUARANTINED", e.to_string()))?;
        }
        Ok(())
    }
    pub fn require_foreground(
        &self,
        lease: &Lease,
        owner: &Owner,
        target: &Resource,
    ) -> Result<(), ArbiterError> {
        self.validate(lease, owner)?;
        let Resource::WindowMutation {
            hwnd,
            pid,
            process_birth: birth,
        } = target
        else {
            return Err(err("WINDOW_IDENTITY_MISMATCH", "not a window capability"));
        };
        owned_window(*hwnd, *pid, *birth)?;
        let registry = self.inspect_arbiter()?;
        let parent_bound = registry
            .entries
            .iter()
            .find(|entry| {
                entry.request_id == lease.request_id
                    && entry.generation == lease.generation
                    && entry.owner == *owner
            })
            .and_then(|entry| entry.continuation_of)
            .is_some_and(|(id, generation)| {
                registry.entries.iter().any(|parent| {
                    parent.request_id == id
                        && parent.generation == generation
                        && parent.owner == *owner
                        && parent.resources.contains(target)
                        && parent.acquired_at.is_some()
                })
            });
        if !lease.resources.contains(&Resource::DesktopInput)
            || !(lease.resources.contains(target) || parent_bound)
            || unsafe { GetForegroundWindow() }.0 as u64 != *hwnd
        {
            return Err(err(
                "FOREGROUND_ACQUISITION_DENIED",
                "actual foreground does not match leased window",
            ));
        }
        Ok(())
    }
    /// Hide is capability-gated by a caller-owned dedicated app proof. It is not
    /// inferred from a Linux RAIL test or from HWND ownership alone.
    pub fn set_background_visibility(
        &self,
        lease: &Lease,
        owner: &Owner,
        target: &Resource,
        visible: bool,
        background_safe_hide: bool,
    ) -> Result<(), ArbiterError> {
        if !background_safe_hide {
            return Err(err(
                "UNSUPPORTED_BACKGROUND_SAFE_HIDE",
                "no trusted app capability proof",
            ));
        }
        self.validate(lease, owner)?;
        if !lease.resources.contains(target) || !lease.resources.contains(&Resource::DesktopInput) {
            return Err(err(
                "WINDOW_IDENTITY_MISMATCH",
                "window mutation not reserved with desktop",
            ));
        }
        let Resource::WindowMutation {
            hwnd,
            pid,
            process_birth: birth,
        } = target
        else {
            return Err(err("WINDOW_IDENTITY_MISMATCH", "missing owned window"));
        };
        owned_window(*hwnd, *pid, *birth)?;
        unsafe {
            let _ = ShowWindow(
                HWND(*hwnd as usize as *mut _),
                if visible { SW_SHOWNOACTIVATE } else { SW_HIDE },
            );
        }
        let deadline = Instant::now() + Duration::from_millis(1000);
        loop {
            owned_window(*hwnd, *pid, *birth)?;
            if unsafe { IsWindowVisible(HWND(*hwnd as usize as *mut _)) }.as_bool() == visible {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(err(
                    "WINDOW_VISIBILITY_NOT_OBSERVED",
                    "ShowWindow call is not proof",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

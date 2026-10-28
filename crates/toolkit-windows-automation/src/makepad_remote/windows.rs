//! Windows owner extracted from the pinned pilot's native.rs. No SendInput,
//! foreground acquisition, arbitrary URL attachment, or production registration.
use super::protocol::{RemoteError, Result, allowed_route, classify_reply};
use super::{PINNED_SOURCE, RemotePlatform, SessionBinding, now_ms};
use crate::{
    WindowQuery, WindowsAutomation,
    desktop_arbiter::{
        DesktopArbiter, Lease, Owner, Resource, clock_ms, current_owner, observe_safe_point,
        owned_window, process_birth,
    },
    owned_process::OwnedWindowsProcess,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, UNIX_EPOCH},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HWND},
        System::Threading::{
            OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
        UI::WindowsAndMessaging::IsWindow,
    },
    core::PWSTR,
};

/// Trusted operator configuration, deliberately NOT deserializable from a
/// public Script, MCP call, TestJob, environment map, PID, or URL.
#[derive(Clone, Debug)]
pub struct ApprovedWindowsApp {
    pub experimental_opt_in: bool,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub working_directory: PathBuf,
    pub source_commit: String,
    pub owner: String,
    pub hidden: bool,
    /// Explicit source-bound fixture contract, NOT a general Remote feature.
    /// Never infer support merely from the executable accepting --remote.
    pub key_focus_probe: bool,
    pub output_directory: PathBuf,
}

#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetExtendedTcpTable(
        table: *mut u8,
        size: *mut u32,
        order: i32,
        family: u32,
        class: u32,
        reserved: u32,
    ) -> u32;
}
fn refuse(code: &str) -> RemoteError {
    RemoteError::refused(code)
}
fn checked(condition: bool, code: &str) -> Result<()> {
    if condition { Ok(()) } else { Err(refuse(code)) }
}
fn startup_window(status: &Value, expected_pid: u32) -> Result<Option<u64>> {
    checked(status["pid"].as_u64() == Some(u64::from(expected_pid)),
        "REMOTE_STARTUP_IDENTITY_MISMATCH")?;
    let rows = status["w"].as_array().ok_or_else(|| refuse("REMOTE_WINDOWS_INVALID"))?;
    if rows.is_empty() { return Ok(None); }
    checked(rows.len() == 1, "REMOTE_STARTUP_IDENTITY_MISMATCH")?;
    rows[0]["i"].as_u64().map(Some).ok_or_else(|| refuse("REMOTE_WINDOW_ID_INVALID"))
}
fn request_deadline(startup_deadline: Option<Instant>, now: Instant) -> Result<Instant> {
    let ordinary = now + Duration::from_secs(15);
    let deadline = startup_deadline.map_or(ordinary, |limit| limit.min(ordinary));
    checked(deadline > now, "REMOTE_STARTUP_TIMEOUT")?;
    Ok(deadline)
}
fn is_input_route(route: &str) -> bool {
    matches!(route, "/click" | "/m" | "/k" | "/t")
}
fn input_policy(route: &str, input_uncertain: bool) -> Result<bool> {
    let input = is_input_route(route);
    checked(!input || !input_uncertain, "REMOTE_SEQUENCE_FENCED")?;
    Ok(input)
}
fn window_mode(expected_hidden: bool, visible: bool) -> Result<()> {
    checked(visible == !expected_hidden, "WINDOW_MODE_MISMATCH")
}
fn secondary_error(error: &mut RemoteError, key: &str, cause: &RemoteError) {
    if !error.details.is_object() {
        let original = std::mem::replace(&mut error.details, json!({}));
        error.details["original_details"] = original;
    }
    // Only local typed codes/outcomes, never OS text, paths or remote bodies.
    error.details[key] = json!({"code":cause.code,"outcome":cause.outcome});
}
fn after_input_mode(result: Result<Value>, mode: Result<()>, input_uncertain: &mut bool) -> Result<Value> {
    let Err(cause) = mode else { return result; };
    *input_uncertain = true;
    let mut error = match result {
        Err(original) => original, // Preserve even 409 applied:false/true exactly.
        Ok(_) => {
            let mut error = RemoteError::unknown("POST_INPUT_WINDOW_MODE_UNCONFIRMED");
            error.details["ack_received"] = json!(true);
            error
        }
    };
    secondary_error(&mut error, "post_input_mode_error", &cause);
    Err(error)
}
fn after_request_receipt(result: Result<Value>, receipt: Result<()>, mutating: bool, input_uncertain: &mut bool) -> Result<Value> {
    let Err(cause) = receipt else { return result; };
    if mutating { *input_uncertain = true; }
    let mut error = match result {
        Err(original) => original,
        Ok(_) if mutating => RemoteError::unknown("POST_DISPATCH_EVIDENCE_WRITE_FAILED"),
        Ok(_) => refuse("EVIDENCE_WRITE_FAILED"),
    };
    secondary_error(&mut error, "request_receipt_error", &cause);
    Err(error)
}

#[derive(Clone, Debug)]
struct NormalExitObservation {
    // None: still running; Some(None): signaled but exit code unavailable.
    root: Result<Option<Option<i32>>>,
    active: Result<u32>,
}
const MAX_NORMAL_EXIT_SAMPLES: usize = 512;
fn normal_exit_timeout(root_zero: bool, active: Option<u32>) -> RemoteError {
    RemoteError::unknown(if root_zero && active.is_some_and(|count| count > 0) {
        "OWNED_DESCENDANTS_REMAIN"
    } else { "NORMAL_APP_EXIT_UNCONFIRMED" })
}
fn poll_normal_exit(
    budget: Duration,
    mut elapsed: impl FnMut() -> Duration,
    mut observe: impl FnMut() -> NormalExitObservation,
    mut pause: impl FnMut(Duration),
    samples: &mut Vec<Value>,
) -> Result<()> {
    let mut last_root_zero = false;
    let mut last_active = None;
    loop {
        let before = elapsed();
        if before >= budget { return Err(normal_exit_timeout(last_root_zero, last_active)); }
        checked(samples.len() < MAX_NORMAL_EXIT_SAMPLES, "NORMAL_EXIT_OBSERVATION_LIMIT")?;
        let observation = observe();
        let after = elapsed();
        samples.push(json!({"started_elapsed_ms":before.as_millis(),"completed_elapsed_ms":after.as_millis(),
            "root_signaled":observation.root.as_ref().ok().map(|root| root.is_some()),
            "exit_code":observation.root.as_ref().ok().and_then(|root| root.flatten()),
            "raw_active_processes":observation.active.as_ref().ok(),
            "root_query_error":observation.root.as_ref().err(),"job_query_error":observation.active.as_ref().err()}));
        let root = observation.root?;
        if let Some(code) = root {
            let code = code.ok_or_else(|| RemoteError::unknown("APP_EXIT_STATUS_UNAVAILABLE"))?;
            checked(code == 0, "APP_EXIT_NONZERO")?;
        }
        let active = observation.active?;
        last_root_zero = root == Some(Some(0));
        last_active = Some(active);
        // Readiness requires a COMPLETE fresh pair returned inside the SAME budget.
        if after >= budget { return Err(normal_exit_timeout(last_root_zero, last_active)); }
        if last_root_zero && active == 0 { return Ok(()); }
        pause(Duration::from_millis(25).min(budget - after));
    }
}
fn after_normal_exit_receipt(result: Result<Value>, receipt: Result<()>, key: &str) -> Result<Value> {
    let Err(cause) = receipt else { return result; };
    let mut error = match result {
        Err(original) => original,
        Ok(_) => RemoteError::unknown("NORMAL_EXIT_EVIDENCE_WRITE_FAILED"),
    };
    secondary_error(&mut error, key, &cause);
    Err(error)
}
fn sha(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|_| refuse("EXECUTABLE_READ_FAILED"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| refuse("EXECUTABLE_READ_FAILED"))?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Operator-only profile read. No request/Script argument may supply this path.
pub fn read_trusted_profile_bytes(path: &Path, expected_sha256: &str) -> Result<Vec<u8>> {
    checked(
        expected_sha256.len() == 64 && expected_sha256.bytes().all(|c| c.is_ascii_hexdigit()),
        "TRUSTED_PROFILE_PIN_REQUIRED",
    )?;
    let metadata = fs::symlink_metadata(path).map_err(|_| refuse("TRUSTED_PROFILE_MISSING"))?;
    checked(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() > 0
            && metadata.len() <= 65536,
        "TRUSTED_PROFILE_INVALID",
    )?;
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| refuse("TRUSTED_PROFILE_READ_FAILED"))?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse("TRUSTED_PROFILE_READ_FAILED"))?;
    checked(
        !bytes.is_empty()
            && bytes.len() <= 65536
            && format!("{:x}", Sha256::digest(&bytes)) == expected_sha256.to_ascii_lowercase(),
        "TRUSTED_PROFILE_PIN_MISMATCH",
    )?;
    Ok(bytes)
}
fn image_path(pid: u32) -> Result<PathBuf> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|_| refuse("STALE_PROCESS"))?;
        let mut value = vec![0u16; 32768];
        let mut length = value.len() as u32;
        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(value.as_mut_ptr()),
            &mut length,
        );
        let _ = CloseHandle(handle);
        result.map_err(|_| refuse("PROCESS_IMAGE_UNAVAILABLE"))?;
        fs::canonicalize(String::from_utf16_lossy(&value[..length as usize]))
            .map_err(|_| refuse("PROCESS_IMAGE_UNAVAILABLE"))
    }
}
fn listener_owner(port: u16) -> Result<u32> {
    unsafe {
        let mut size = 0;
        let _ = GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, 2, 3, 0);
        checked(size >= 4 && size <= 1024 * 1024, "TCP_TABLE_SIZE")?;
        let mut bytes = vec![0; size as usize];
        checked(
            GetExtendedTcpTable(bytes.as_mut_ptr(), &mut size, 0, 2, 3, 0) == 0,
            "TCP_TABLE_READ",
        )?;
        let word = |i| u32::from_ne_bytes(bytes[i..i + 4].try_into().unwrap());
        let count = word(0) as usize;
        checked(4 + count * 24 <= bytes.len(), "TCP_TABLE_FORMAT")?;
        let mut matches = Vec::new();
        for row in 0..count {
            let i = 4 + row * 24;
            if word(i) == 2 && u16::from_be(word(i + 8) as u16) == port {
                checked(
                    word(i + 4).to_ne_bytes() == [127, 0, 0, 1],
                    "NON_LOOPBACK_LISTENER_REFUSED",
                )?;
                matches.push(word(i + 20));
            }
        }
        checked(!matches.is_empty(), "REMOTE_LISTENER_NOT_FOUND")?;
        checked(matches.len() == 1, "REMOTE_LISTENER_AMBIGUOUS")?;
        Ok(matches[0])
    }
}

pub struct WindowsRemotePlatform {
    app: OwnedWindowsProcess,
    ui: WindowsAutomation,
    binding: SessionBinding,
    birth: u64,
    executable: PathBuf,
    hwnd: u64,
    toolkit_window: String,
    port: u16,
    grab_root: PathBuf,
    output: PathBuf,
    seen_frames: BTreeSet<PathBuf>,
    requests: u64,
    arbiter: DesktopArbiter,
    arbiter_owner: Owner,
    lease: Option<Lease>,
    input_uncertain: bool,
    expected_hidden: bool,
    normal_exit: bool,
    key_focus_probe: bool,
    cleanup_report: Option<Value>,
    cleanup_attempts: u32,
}

impl WindowsRemotePlatform {
    pub fn launch(config: &ApprovedWindowsApp) -> Result<Self> {
        checked(
            config.experimental_opt_in && config.source_commit == PINNED_SOURCE,
            "TRUSTED_REMOTE_OPT_IN_REQUIRED",
        )?;
        checked(
            !config.owner.is_empty() && config.owner.len() <= 128,
            "TRUSTED_OWNER_REQUIRED",
        )?;
        checked(
            config.executable_sha256.len() == 64
                && config
                    .executable_sha256
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit()),
            "APPROVED_EXECUTABLE_HASH_REQUIRED",
        )?;
        let executable = fs::canonicalize(&config.executable)
            .map_err(|_| refuse("APPROVED_EXECUTABLE_MISSING"))?;
        checked(
            sha(&executable)? == config.executable_sha256.to_ascii_lowercase(),
            "UNAPPROVED_EXECUTABLE",
        )?;
        checked(
            !config.output_directory.exists(),
            "FRESH_REMOTE_OUTPUT_REQUIRED",
        )?;
        fs::create_dir_all(&config.output_directory)
            .map_err(|_| refuse("REMOTE_OUTPUT_CREATE_FAILED"))?;
        let output = fs::canonicalize(&config.output_directory)
            .map_err(|_| refuse("REMOTE_OUTPUT_INVALID"))?;
        let stdout = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join("app.stdout.log"))
            .map_err(|_| refuse("REMOTE_OUTPUT_INVALID"))?;
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join("app.stderr.log"))
            .map_err(|_| refuse("REMOTE_OUTPUT_INVALID"))?;
        let mut command = Command::new(&executable);
        command
            .arg("--remote=127.0.0.1:0")
            .arg("--remote-title-tag=toolkit-experimental")
            .current_dir(&config.working_directory)
            .env_remove("MAKEPAD_REMOTE")
            .env_remove("MAKEPAD_FOCUS")
            .env_remove("MAKEPAD_HIDE_WINDOWS");
        if config.hidden {
            command.env("MAKEPAD_HIDE_WINDOWS", "1");
        }
        let mut app = OwnedWindowsProcess::spawn(&command, &stdout, &stderr)
            .map_err(|_| refuse("OWNED_REMOTE_LAUNCH_FAILED"))?;
        let pid = app.id();
        let birth = process_birth(pid).map_err(|_| refuse("PROCESS_BIRTH_UNAVAILABLE"))?;
        let mut ui = WindowsAutomation::new().map_err(|_| refuse("WINDOW_REGISTRY_UNAVAILABLE"))?;
        let deadline = Instant::now() + Duration::from_secs(20);
        let (port, grab_root, window) = loop {
            checked(
                app.try_wait()
                    .map_err(|_| refuse("PROCESS_WAIT_FAILED"))?
                    .is_none(),
                "APP_EXITED_DURING_STARTUP",
            )?;
            let log = fs::read_to_string(output.join("app.stdout.log")).unwrap_or_default();
            if let Some(line) = log
                .lines()
                .find(|l| l.starts_with("[makepad-remote] listening on "))
            {
                let endpoint = line
                    .split("listening on ")
                    .nth(1)
                    .and_then(|s| s.split_whitespace().next())
                    .ok_or_else(|| refuse("REMOTE_STARTUP_INVALID"))?;
                let port = endpoint
                    .strip_prefix("127.0.0.1:")
                    .ok_or_else(|| refuse("NON_LOOPBACK_REMOTE_REFUSED"))?
                    .parse::<u16>()
                    .map_err(|_| refuse("REMOTE_STARTUP_INVALID"))?;
                checked(
                    port > 0 && line.contains(&format!(" pid={pid} ")),
                    "REMOTE_STARTUP_PID_MISMATCH",
                )?;
                let grab = PathBuf::from(
                    line.split(" grabs=")
                        .nth(1)
                        .ok_or_else(|| refuse("REMOTE_GRAB_ROOT_MISSING"))?,
                );
                let windows = ui
                    .list_windows(&WindowQuery {
                        process_id: Some(pid),
                        ..Default::default()
                    })
                    .map_err(|_| refuse("WINDOW_REGISTRY_UNAVAILABLE"))?;
                let mut primary = windows
                    .into_iter()
                    .filter(|w| w.class_name == "MakepadWindow")
                    .collect::<Vec<_>>();
                if primary.len() == 1 {
                    break (
                        port,
                        fs::canonicalize(grab).map_err(|_| refuse("REMOTE_GRAB_ROOT_INVALID"))?,
                        primary.remove(0),
                    );
                }
            }
            if Instant::now() >= deadline {
                return Err(refuse("REMOTE_STARTUP_TIMEOUT"));
            }
            thread::sleep(Duration::from_millis(25));
        };
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let generation = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| refuse("SESSION_GENERATION_EXHAUSTED"))?;
        let session_id = format!("remote-{}-{}-{generation}", std::process::id(), now_ms());
        let arbiter = DesktopArbiter::open().map_err(|_| refuse("ARBITER_OPEN_FAILED"))?;
        let arbiter_owner = current_owner(
            "makepad-remote-adapter",
            "trusted-opt-in",
            &session_id,
            &session_id,
        )
        .map_err(|_| refuse("ARBITER_OWNER_INVALID"))?;
        let hwnd = u64::from_str_radix(window.hwnd.trim_start_matches("0x"), 16)
            .map_err(|_| refuse("WINDOW_HANDLE_INVALID"))?;
        let binding = SessionBinding {
            session_id,
            owner: config.owner.clone(),
            generation,
            pid,
            process_birth: birth.to_string(),
            executable: executable.to_string_lossy().into(),
            executable_sha256: config.executable_sha256.to_ascii_lowercase(),
            source_commit: PINNED_SOURCE.into(),
            window_id: 0,
            platform: "windows-owned-job".into(),
        };
        let mut result = Self {
            app,
            ui,
            binding,
            birth,
            executable,
            hwnd,
            toolkit_window: window.window_id,
            port,
            grab_root,
            output,
            seen_frames: BTreeSet::new(),
            requests: 0,
            arbiter,
            arbiter_owner,
            lease: None,
            input_uncertain: false,
            expected_hidden: config.hidden,
            normal_exit: false,
            key_focus_probe: config.key_focus_probe,
            cleanup_report: None,
            cleanup_attempts: 0,
        };
        result.validate()?;
        result.binding.window_id = loop {
            // HWND/listener creation can precede Remote's published window
            // list. Only exact-owned-PID empty state is pending readiness.
            let status = result.request_until("/s", false, Some(deadline))?;
            if let Some(window_id) = startup_window(&status, pid)? { break window_id; }
            result.validate()?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            checked(!remaining.is_zero(), "REMOTE_STARTUP_TIMEOUT")?;
            thread::sleep(Duration::from_millis(25).min(remaining));
        };
        result.save("session-binding.json",&json!({"binding":result.binding,"hwnd":hwnd,"toolkit_window":result.toolkit_window,
            "endpoint":{"host":"127.0.0.1","port":port,"listener_owner_pid":pid},"hidden":config.hidden,
            "key_focus_observation":if config.key_focus_probe {"TRUSTED_FIXTURE_SNAPSHOT_LOG_V1"} else {"UNSUPPORTED_BY_PINNED_REMOTE_PROTOCOL"}}))?;
        Ok(result)
    }

    fn save(&self, name: &str, value: &Value) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.output.join(name))
            .map_err(|_| refuse("EXCLUSIVE_EVIDENCE_WRITE_FAILED"))?;
        file.write_all(
            &serde_json::to_vec_pretty(value)
                .map_err(|_| refuse("EVIDENCE_SERIALIZATION_FAILED"))?,
        )
        .map_err(|_| refuse("EVIDENCE_WRITE_FAILED"))
    }

    pub fn request_count(&self) -> u64 {
        self.requests
    }
    pub fn output_directory(&self) -> &Path {
        &self.output
    }

    fn check_input_window_mode(&mut self) -> Result<()> {
        // The expected mode is trusted launch state. Observe the exact owned
        // HWND afresh, bracketed by PID/birth ownership, not foreground/focus.
        owned_window(self.hwnd, self.binding.pid, self.birth)
            .map_err(|_| refuse("WINDOW_BIRTH_BINDING_CHANGED"))?;
        let window = self.ui.get_window_info(&self.toolkit_window)
            .map_err(|_| refuse("STALE_WINDOW"))?;
        owned_window(self.hwnd, self.binding.pid, self.birth)
            .map_err(|_| refuse("WINDOW_BIRTH_BINDING_CHANGED"))?;
        checked(window.process_id == self.binding.pid && window.hwnd == format!("0x{:X}", self.hwnd),
            "WINDOW_IDENTITY_CHANGED")?;
        window_mode(self.expected_hidden, window.visible)
    }

    fn latest_focus_sample(&self, require_current_target: bool) -> Result<Option<Value>> {
        let path = self.output.join("app.stdout.log");
        let metadata = fs::metadata(&path).map_err(|_| refuse("FOCUS_PROBE_LOG_UNAVAILABLE"))?;
        checked(
            metadata.len() <= 4 * 1024 * 1024,
            "FOCUS_PROBE_LOG_BUDGET_EXCEEDED",
        )?;
        let mut bytes = Vec::new();
        File::open(&path)
            .map_err(|_| refuse("FOCUS_PROBE_LOG_UNAVAILABLE"))?
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| refuse("FOCUS_PROBE_LOG_UNAVAILABLE"))?;
        checked(
            bytes.len() <= 4 * 1024 * 1024,
            "FOCUS_PROBE_LOG_BUDGET_EXCEEDED",
        )?;
        let text = std::str::from_utf8(&bytes).map_err(|_| refuse("FOCUS_PROBE_LOG_INVALID"))?;
        let Some(line) = text
            .lines()
            .rev()
            .find_map(|line| line.strip_prefix("[toolkit-remote-focus-v1] "))
        else {
            return Ok(None);
        };
        checked(line.len() <= 1024, "FOCUS_PROBE_LOG_INVALID")?;
        let value = classify_reply(200, line.as_bytes(), false)?;
        // Shared exact fixture contract; no activation/focus fallback.
        super::focus_probe::validate_sample(
            &value,
            self.binding.pid,
            self.binding.window_id,
            require_current_target,
        )?;
        Ok(Some(value))
    }
}

impl WindowsRemotePlatform {
    fn request_until(&mut self, target: &str, mutating: bool, startup_deadline: Option<Instant>) -> Result<Value> {
        self.validate()?;
        checked(allowed_route(target), "REMOTE_ROUTE_NOT_ALLOWLISTED")?;
        let route = target.split('?').next().unwrap_or("");
        let actual_mutation = ["/click", "/m", "/k", "/t", "/quit"].contains(&route);
        checked(
            actual_mutation == mutating,
            "REMOTE_MUTATION_CLASSIFICATION_MISMATCH",
        )?;
        let input = input_policy(route, self.input_uncertain)?;
        if mutating {
            let lease = self
                .lease
                .as_ref()
                .ok_or_else(|| refuse("INPUT_LOCK_REQUIRED"))?;
            self.arbiter
                .validate(lease, &self.arbiter_owner)
                .map_err(|_| refuse("STALE_LEASE"))?;
            checked(
                target.split('?').nth(1).is_some_and(|query| {
                    query.split('&').any(|part| {
                        part.strip_prefix("if_user_seq=")
                            .is_some_and(|value| value.parse::<u64>().is_ok())
                    })
                }),
                "HUMAN_ACTIVITY_GUARD_REQUIRED",
            )?;
        }
        if input { self.check_input_window_mode()?; } // Before TCP or request_count.
        let requests_before = self.requests;
        let result = (|| {
            let deadline = request_deadline(startup_deadline, Instant::now())?;
            let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
            let mut stream = TcpStream::connect_timeout(&addr,
                Duration::from_secs(2).min(deadline.saturating_duration_since(Instant::now())))
                .map_err(|_| refuse("REMOTE_CONNECT_FAILED"))?;
            let write_budget = Duration::from_secs(2).min(deadline.saturating_duration_since(Instant::now()));
            checked(!write_budget.is_zero(), "REMOTE_STARTUP_TIMEOUT")?;
            stream
                .set_write_timeout(Some(write_budget))
                .map_err(|_| refuse("REMOTE_TIMEOUT_CONFIG_FAILED"))?;
            self.requests += 1;
            write!(
                stream,
                "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                self.port
            )
            .map_err(|_| RemoteError::unknown("REMOTE_WRITE_OUTCOME_UNKNOWN"))?;
            let (status, body) = super::http::read_response(|buffer| {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
                }
                stream.set_read_timeout(Some(remaining))?;
                stream.read(buffer)
            })?;
            if route == "/d" && status == 200 {
                return Ok(json!({"dump":String::from_utf8_lossy(&body)}));
            }
            let reply = classify_reply(status, &body, mutating)?;
            if mutating && reply["ok"] != 1 && reply["ok"] != true {
                return Err(RemoteError::unknown("REMOTE_MUTATION_ACK_INVALID"));
            }
            Ok(reply)
        })();
        // Always post-observe an attempted input, including transport/409 Err.
        // /quit and read-only requests are deliberately exempt from this policy.
        let result = if input {
            let mode = self.check_input_window_mode();
            after_input_mode(result, mode, &mut self.input_uncertain)
        } else { result };
        if mutating
            && result
                .as_ref()
                .is_err_and(|e| e.outcome != "NOT_DISPATCHED")
        {
            self.input_uncertain = true;
        }
        // Preserve the existing no-receipt behavior if connect/config failed
        // before any HTTP write attempt; post-input fencing still applies.
        if self.requests == requests_before { return result; }
        let receipt = self.save(&format!("request-{:04}.json",self.requests),&json!({"route":route,"mutating":mutating,"request_index":self.requests,
            "observed_unix_ms":now_ms(),"session_id":self.binding.session_id,"success":result.is_ok(),"error":result.as_ref().err(),
            // Preserve the actual independent snapshot, including the neighbor,
            // in the EXISTING owned native receipt. This does not project an
            // unobserved KeyFocus, add a UIA control, or issue another request.
            "response":if !mutating && ["/snap", "/s"].contains(&route) {result.as_ref().ok()} else {None}}));
        after_request_receipt(result, receipt, mutating, &mut self.input_uncertain)
    }
}

impl RemotePlatform for WindowsRemotePlatform {
    fn host_window_identity(&mut self) -> Result<(u64, u32, u64)> {
        self.validate()?;
        self.check_input_window_mode()?;
        Ok((self.hwnd, self.binding.pid, self.birth))
    }
    fn binding(&self) -> &SessionBinding {
        &self.binding
    }
    fn observe_key_focus(&mut self, window: u64, widget: &str) -> Result<bool> {
        checked(self.key_focus_probe, "UNSUPPORTED_KEY_FOCUS_OBSERVATION")?;
        checked(
            window == self.binding.window_id && widget == "input_singleline",
            "UNSUPPORTED_KEY_FOCUS_OBSERVATION",
        )?;
        self.validate()?;
        let before = self
            .latest_focus_sample(false)?
            .and_then(|v| v["sample_seq"].as_u64())
            .unwrap_or(0);
        let snapshot = self.request(&format!("/snap?w={window}&all=1"), false)?;
        super::protocol::exact_widget(&snapshot, window, widget)?;
        let sample = self
            .latest_focus_sample(true)?
            .ok_or_else(|| refuse("FOCUS_PROBE_SAMPLE_MISSING"))?;
        checked(
            sample["sample_seq"]
                .as_u64()
                .is_some_and(|seq| seq > before),
            "STALE_KEY_FOCUS_OBSERVATION",
        )?;
        self.validate()?;
        self.save(&format!("focus-observation-{:04}.json",self.requests),&json!({"source":"TRUSTED_FIXTURE_SNAPSHOT_LOG_V1",
            "sample":sample,"session_id":self.binding.session_id,"session_generation":self.binding.generation,
            "executable_sha256":self.binding.executable_sha256,"observed_unix_ms":now_ms()}))?;
        Ok(sample["focused"] == true)
    }
    fn validate(&mut self) -> Result<()> {
        checked(
            self.app
                .try_wait()
                .map_err(|_| refuse("PROCESS_WAIT_FAILED"))?
                .is_none(),
            "STALE_PROCESS",
        )?;
        checked(
            process_birth(self.binding.pid).map_err(|_| refuse("STALE_PROCESS"))? == self.birth,
            "PROCESS_BIRTH_CHANGED",
        )?;
        checked(
            image_path(self.binding.pid)? == self.executable,
            "EXECUTABLE_PATH_CHANGED",
        )?;
        checked(
            sha(&self.executable)? == self.binding.executable_sha256,
            "EXECUTABLE_HASH_CHANGED",
        )?;
        checked(
            listener_owner(self.port)? == self.binding.pid,
            "LISTENER_OWNER_CHANGED",
        )?;
        owned_window(self.hwnd, self.binding.pid, self.birth)
            .map_err(|_| refuse("WINDOW_BIRTH_BINDING_CHANGED"))?;
        let w = self
            .ui
            .get_window_info(&self.toolkit_window)
            .map_err(|_| refuse("STALE_WINDOW"))?;
        checked(
            w.process_id == self.binding.pid && w.hwnd == format!("0x{:X}", self.hwnd),
            "WINDOW_IDENTITY_CHANGED",
        )
    }
    fn request(&mut self, target: &str, mutating: bool) -> Result<Value> {
        self.request_until(target, mutating, None)
    }

    fn acquire_input(&mut self) -> Result<String> {
        checked(self.lease.is_none(), "INPUT_LOCK_ALREADY_HELD")?;
        let request = self
            .arbiter
            .request_lease(
                vec![Resource::SessionSemantic {
                    session_id: self.binding.session_id.clone(),
                }],
                &self.arbiter_owner,
                clock_ms() + 30000,
            )
            .map_err(|_| refuse("INPUT_LOCK_REQUEST_FAILED"))?;
        let lease = self
            .arbiter
            .wait_lease(request, &self.arbiter_owner, &AtomicBool::new(false))
            .map_err(|_| refuse("INPUT_LOCK_ACQUIRE_FAILED"))?;
        let token = format!("lease:{}:{}", lease.request_id, lease.generation);
        self.lease = Some(lease);
        Ok(token)
    }
    fn validate_input(&mut self, token: &str) -> Result<()> {
        let lease = self
            .lease
            .as_ref()
            .ok_or_else(|| refuse("INPUT_LOCK_REQUIRED"))?;
        checked(
            token == format!("lease:{}:{}", lease.request_id, lease.generation),
            "STALE_LEASE",
        )?;
        self.arbiter
            .validate(lease, &self.arbiter_owner)
            .map_err(|_| refuse("STALE_LEASE"))
    }
    fn release_input(&mut self, token: &str) -> Result<()> {
        self.validate_input(token)?;
        checked(
            !self.input_uncertain || self.normal_exit,
            "REMOTE_INPUT_CLEANUP_UNCONFIRMED",
        )?;
        let proof = observe_safe_point(false, false, false, false, false);
        self.arbiter
            .release_lease(self.lease.as_ref().unwrap(), &self.arbiter_owner, &proof)
            .map_err(|error| {
                let mut refusal = refuse("INPUT_LOCK_RELEASE_UNCONFIRMED");
                refusal.details["arbiter_error"] = json!({"code":error.code,"message":error.message});
                refusal.details["observed_safe_point"] = json!(proof);
                refusal.details["resource_scope"] = json!("SessionSemantic");
                refusal
            })?;
        self.lease = None;
        Ok(())
    }
    fn copy_native_frame(&mut self, metadata: &Value, dispatched_ms: u64) -> Result<Value> {
        self.validate()?;
        checked(
            metadata["w"].as_u64() == Some(self.binding.window_id),
            "CAPTURE_WRONG_WINDOW",
        )?;
        let source = PathBuf::from(
            metadata["png"]
                .as_str()
                .ok_or_else(|| refuse("NATIVE_CAPTURE_PATH_MISSING"))?,
        );
        checked(
            !fs::symlink_metadata(&source)
                .map_err(|_| refuse("NATIVE_CAPTURE_MISSING"))?
                .file_type()
                .is_symlink(),
            "NATIVE_CAPTURE_SYMLINK_REFUSED",
        )?;
        let source = fs::canonicalize(source).map_err(|_| refuse("NATIVE_CAPTURE_MISSING"))?;
        checked(
            source.starts_with(&self.grab_root) && source.extension().is_some_and(|v| v == "png"),
            "NATIVE_CAPTURE_PATH_REFUSED",
        )?;
        checked(!self.seen_frames.contains(&source), "STALE_NATIVE_FRAME")?;
        let before = fs::metadata(&source).map_err(|_| refuse("NATIVE_CAPTURE_MISSING"))?;
        checked(
            before.is_file() && before.len() > 0 && before.len() <= 16 * 1024 * 1024,
            "NATIVE_CAPTURE_SIZE_REFUSED",
        )?;
        let modified = before
            .modified()
            .map_err(|_| refuse("CAPTURE_TIME_UNAVAILABLE"))?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| refuse("CAPTURE_TIME_UNAVAILABLE"))?
            .as_millis() as u64;
        checked(modified >= dispatched_ms, "STALE_NATIVE_FRAME")?;
        let mut bytes = Vec::new();
        File::open(&source)
            .map_err(|_| refuse("NATIVE_CAPTURE_READ_FAILED"))?
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| refuse("NATIVE_CAPTURE_READ_FAILED"))?;
        let after = fs::metadata(&source).map_err(|_| refuse("NATIVE_CAPTURE_CHANGED"))?;
        checked(
            bytes.len() as u64 == before.len()
                && before.len() == after.len()
                && before.modified().ok() == after.modified().ok(),
            "NATIVE_CAPTURE_CHANGED",
        )?;
        let decoded = super::native_frame::inspect_png(&bytes)?;
        self.validate()?;
        let destination = self.output.join(format!(
            "native-frame-{:04}.png",
            self.seen_frames.len() + 1
        ));
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .and_then(|mut f| f.write_all(&bytes))
            .map_err(|_| refuse("NATIVE_CAPTURE_PUBLISH_FAILED"))?;
        self.seen_frames.insert(source);
        Ok(
            json!({"path":destination,"sha256":format!("{:x}",Sha256::digest(&bytes)),"bytes":bytes.len(),
            "width":decoded.width,"height":decoded.height,"captured_at_unix_ms":modified,"dispatched_at_unix_ms":dispatched_ms,
            "full_png_decode":true,"nonblank":true,"sampled_colors":decoded.sampled_colors,"remote":metadata,
            "independent_visual_review":"PENDING","presentation_verified":false}),
        )
    }
    fn reap_normal_exit(&mut self) -> Result<Value> {
        let started = Instant::now();
        let started_unix_ms = now_ms();
        let budget = Duration::from_secs(8);
        let mut samples = Vec::new();
        let mut wait_elapsed = Duration::ZERO;
        let mut root_job_ready = false;
        let result = (|| {
            let readiness = poll_normal_exit(budget, || started.elapsed(), || {
                let root = self.app.try_wait().map(|status| status.map(|exit| exit.code()))
                    .map_err(|_| refuse("PROCESS_WAIT_FAILED"));
                let active = self.app.active_processes().map_err(|_| refuse("JOB_PROCESS_QUERY_FAILED"));
                NormalExitObservation { root, active }
            }, thread::sleep, &mut samples);
            wait_elapsed = started.elapsed();
            root_job_ready = readiness.is_ok();
            readiness?;
            checked(
                !unsafe { IsWindow(Some(HWND(self.hwnd as usize as *mut _))) }.as_bool(),
                "STALE_OWNED_WINDOW",
            )?;
            checked(
                listener_owner(self.port).is_err_and(|e| e.code == "REMOTE_LISTENER_NOT_FOUND"),
                "REMOTE_LISTENER_ABSENCE_UNCONFIRMED",
            )?;
            // cleanup() can terminate: invoke it only AFTER root0 AND actual Job0.
            let cleanup = self
                .app
                .cleanup()
                .map_err(|_| refuse("OWNED_JOB_CLEANUP_UNCONFIRMED"))?;
            checked(
                cleanup.confirmed && cleanup.active_after == 0,
                "OWNED_JOB_CLEANUP_UNCONFIRMED",
            )?;
            self.normal_exit = true;
            Ok(json!({"exit_code":0,"normal_exit_observed":true,"job_cleanup":cleanup,"hwnd_gone":true,
                "endpoint_closed":true,"session_id":self.binding.session_id,"process_birth":self.binding.process_birth}))
        })();
        let evidence = json!({"schema":"toolkit-owned-normal-exit-wait-v1","pid":self.binding.pid,
            "session_id":self.binding.session_id,"process_birth":self.binding.process_birth,
            "started_unix_ms":started_unix_ms,"completed_unix_ms":now_ms(),"budget_ms":budget.as_millis(),
            "budget_scope":"ROOT_EXIT_AND_JOB_ZERO_POLL_ONLY",
            "total_elapsed_ms":started.elapsed().as_millis(),"poll_elapsed_ms":wait_elapsed.as_millis(),
            "root_job_ready":root_job_ready,"max_samples":MAX_NORMAL_EXIT_SAMPLES,"samples":samples,
            "completion_success":result.is_ok(),"completion_error":result.as_ref().err()});
        let receipt = self.save("normal-exit-wait.json", &evidence);
        let mut result = after_normal_exit_receipt(result, receipt, "normal_exit_wait_write_error");
        if let Ok(value) = &result {
            let receipt = self.save("normal-exit.json", value);
            result = after_normal_exit_receipt(result, receipt, "normal_exit_write_error");
        }
        if let Err(error) = &mut result {
            error.details["normal_exit_wait"] = evidence; // Retained even if sidecar publication failed.
        }
        result
    }
    fn cleanup_owned_resources(&mut self) -> Result<Value> {
        if let Some(report) = &self.cleanup_report {
            return Ok(report.clone());
        }
        self.cleanup_attempts = self
            .cleanup_attempts
            .checked_add(1)
            .ok_or_else(|| refuse("CLEANUP_ATTEMPT_EXHAUSTED"))?;
        let cleanup = self
            .app
            .cleanup()
            .map_err(|_| refuse("OWNED_JOB_CLEANUP_UNCONFIRMED"))?;
        checked(
            cleanup.confirmed && cleanup.active_after == 0,
            "OWNED_JOB_CLEANUP_UNCONFIRMED",
        )?;
        // Exact Job containment proves remote input cannot persist in this
        // process. It does NOT turn forced termination into normal app exit.
        let mut lease_error = None;
        if let Some(lease) = self.lease.as_ref() {
            let proof = observe_safe_point(false, false, false, false, false);
            if self
                .arbiter
                .release_lease(lease, &self.arbiter_owner, &proof)
                .is_err()
            {
                lease_error = Some("INPUT_LOCK_RELEASE_UNCONFIRMED");
            } else {
                self.lease = None;
            }
        }
        let value = json!({"job_cleanup":cleanup,"normal_exit_observed":self.normal_exit,
            "forced_cleanup":!self.normal_exit,"active_owned_leases":usize::from(self.lease.is_some()),
            "lease_error":lease_error,"hwnd_gone":!unsafe{IsWindow(Some(HWND(self.hwnd as usize as *mut _)))}.as_bool(),
            "listener_absence_proven":listener_owner(self.port).is_err_and(|e|e.code=="REMOTE_LISTENER_NOT_FOUND"),"session_id":self.binding.session_id});
        self.save(
            &format!("owned-cleanup-{:04}.json", self.cleanup_attempts),
            &value,
        )?;
        if lease_error.is_some() {
            return Err(refuse("INPUT_LOCK_RELEASE_UNCONFIRMED"));
        }
        self.cleanup_report = Some(value.clone());
        Ok(value)
    }

    fn read_runtime_stderr(&mut self) -> Result<Value> {
        self.validate()?;
        let path = self.output.join("app.stderr.log");
        let mut bytes = Vec::new();
        File::open(&path)
            .map_err(|_| refuse("RUNTIME_STDERR_UNAVAILABLE"))?
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| refuse("RUNTIME_STDERR_UNAVAILABLE"))?;
        checked(bytes.len() <= 65536, "RUNTIME_STDERR_BUDGET_EXCEEDED")?;
        let text = std::str::from_utf8(&bytes).map_err(|_| refuse("RUNTIME_STDERR_INVALID"))?;
        Ok(json!(
            text.lines()
                .filter(|line| !line.trim().is_empty())
                .collect::<Vec<_>>()
        ))
    }
}

#[cfg(test)]
mod input_mode_tests {
    use super::*;

    #[test]
    fn own_pid_empty_window_list_is_pending_not_identity_mismatch() {
        assert_eq!(startup_window(&json!({"pid":42,"w":[]}),42).unwrap(),None);
    }

    #[test]
    fn exactly_one_owned_remote_window_is_ready() {
        assert_eq!(startup_window(&json!({"pid":42,"w":[{"i":0}]}),42).unwrap(),Some(0));
    }

    #[test]
    fn foreign_pid_is_never_a_pending_startup_state() {
        for windows in [json!([]),json!([{"i":0}])] {
            let error=startup_window(&json!({"pid":43,"w":windows}),42).unwrap_err();
            assert_eq!(error.code,"REMOTE_STARTUP_IDENTITY_MISMATCH");
            assert_eq!(error.outcome,"NOT_DISPATCHED");
            assert!(!error.retry_safe);
        }
    }

    #[test]
    fn missing_or_malformed_window_list_is_not_pending() {
        for status in [json!({"pid":42}),json!({"pid":42,"w":null}),json!({"pid":42,"w":{}})] {
            assert_eq!(startup_window(&status,42).unwrap_err().code,"REMOTE_WINDOWS_INVALID");
        }
    }

    #[test]
    fn multiple_windows_and_invalid_window_identity_remain_terminal() {
        assert_eq!(startup_window(&json!({"pid":42,"w":[{"i":0},{"i":1}]}),42).unwrap_err().code,
            "REMOTE_STARTUP_IDENTITY_MISMATCH");
        assert_eq!(startup_window(&json!({"pid":42,"w":[{"i":"0"}]}),42).unwrap_err().code,
            "REMOTE_WINDOW_ID_INVALID");
    }

    #[test]
    fn startup_requests_never_extend_absolute_or_ordinary_deadline() {
        let now=Instant::now();let near=now+Duration::from_millis(50);
        assert_eq!(request_deadline(Some(near),now).unwrap(),near);
        assert_eq!(request_deadline(Some(now+Duration::from_secs(20)),now).unwrap(),now+Duration::from_secs(15));
        assert_eq!(request_deadline(None,now).unwrap(),now+Duration::from_secs(15));
        assert_eq!(request_deadline(Some(now),now).unwrap_err().code,"REMOTE_STARTUP_TIMEOUT");
    }

    fn primary_kept(before: &RemoteError, after: &RemoteError) {
        assert_eq!(after.code, before.code);
        assert_eq!(after.outcome, before.outcome);
        assert_eq!(after.retry_safe, before.retry_safe);
        for (key, value) in before.details.as_object().unwrap() {
            assert_eq!(&after.details[key], value);
        }
    }

    #[test]
    fn visible_hidden_policy_is_exact_for_all_input_routes() {
        for route in ["/click", "/m", "/k", "/t"] {
            for hidden in [false, true] {
                assert!(input_policy(route, false).unwrap());
                assert!(window_mode(hidden, !hidden).is_ok());
                let error = window_mode(hidden, hidden).unwrap_err();
                assert_eq!(error.code, "WINDOW_MODE_MISMATCH");
                assert_eq!(error.outcome, "NOT_DISPATCHED");
                assert!(!error.retry_safe);
            }
        }
    }

    #[test]
    fn only_exact_input_routes_are_guarded_and_fenced_quit_reads_are_exempt() {
        for target in ["/click?w=0", "/m?w=0", "/k?w=0", "/t?w=0"] {
            let route = target.split('?').next().unwrap();
            assert!(is_input_route(route));
            let error = input_policy(route, true).unwrap_err();
            assert_eq!(error.code, "REMOTE_SEQUENCE_FENCED");
            assert_eq!(error.outcome, "NOT_DISPATCHED");
        }
        for route in ["/quit", "/s", "/snap", "/activity", "/g", "/d"] {
            assert!(!is_input_route(route));
            assert!(!input_policy(route, true).unwrap());
        }
        for route in ["/click-more", "/mouse", "/keys", "/text", "/CLICK"] {
            assert!(!is_input_route(route)); // Not an allowlist; request checks that separately.
        }
    }

    #[test]
    fn ack_then_bad_or_unavailable_mode_is_unknown_and_fences() {
        for code in ["WINDOW_MODE_MISMATCH", "STALE_WINDOW", "WINDOW_BIRTH_BINDING_CHANGED"] {
            let mut fenced = false;
            let error = after_input_mode(Ok(json!({"ok":1,"f":17})), Err(refuse(code)), &mut fenced).unwrap_err();
            assert_eq!(error.code, "POST_INPUT_WINDOW_MODE_UNCONFIRMED");
            assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
            assert!(!error.retry_safe && fenced);
            assert_eq!(error.details["ack_received"], true);
            assert_eq!(error.details["post_input_mode_error"]["code"], code);
            // Restored visibility cannot un-fence the next input.
            assert!(window_mode(false, true).is_ok());
            assert_eq!(input_policy("/click", fenced).unwrap_err().code, "REMOTE_SEQUENCE_FENCED");
            assert!(input_policy("/quit", fenced).is_ok());
        }
    }

    #[test]
    fn post_mode_preserves_both_409_outcomes_and_fences_even_applied_false() {
        for applied in [false, true] {
            let original = classify_reply(409, &serde_json::to_vec(&json!({"applied":applied})).unwrap(), true).unwrap_err();
            for code in ["WINDOW_MODE_MISMATCH", "STALE_WINDOW"] {
                let mut fenced = false;
                let error = after_input_mode(Err(original.clone()), Err(refuse(code)), &mut fenced).unwrap_err();
                primary_kept(&original, &error);
                assert_eq!(error.details["post_input_mode_error"]["code"], code);
                assert!(fenced);
                for route in ["/click", "/m", "/k", "/t"] {
                    assert!(input_policy(route, fenced).is_err());
                }
            }
        }
    }

    #[test]
    fn post_mode_checks_failed_request_without_clearing_existing_fence() {
        let original = refuse("REMOTE_CONNECT_FAILED");
        let mut fenced = false;
        let error = after_input_mode(Err(original.clone()), Err(refuse("STALE_WINDOW")), &mut fenced).unwrap_err();
        primary_kept(&original, &error);
        assert!(fenced);
        let ack = json!({"ok":1,"f":18});
        assert_eq!(after_input_mode(Ok(ack.clone()), Ok(()), &mut fenced).unwrap(), ack);
        assert!(fenced); // A later good observation never resets uncertainty.
        assert_eq!(input_policy("/t", fenced).unwrap_err().outcome, "NOT_DISPATCHED");
    }

    #[test]
    fn receipt_failure_preserves_primary_and_secondary_errors() {
        let primaries = [
            classify_reply(409, br#"{"applied":false}"#, true).unwrap_err(),
            classify_reply(409, br#"{"applied":true}"#, true).unwrap_err(),
            classify_reply(409, br#"{"applied":"false"}"#, true).unwrap_err(),
            classify_reply(409, br#"{"applied":false"#, true).unwrap_err(),
            RemoteError::unknown("REMOTE_WRITE_OUTCOME_UNKNOWN"),
        ];
        for original in primaries {
            let mut fenced = false;
            let result = after_input_mode(Err(original.clone()), Err(refuse("STALE_WINDOW")), &mut fenced);
            let error = after_request_receipt(result, Err(refuse("EXCLUSIVE_EVIDENCE_WRITE_FAILED")), true, &mut fenced).unwrap_err();
            primary_kept(&original, &error);
            assert_eq!(error.details["post_input_mode_error"]["code"], "STALE_WINDOW");
            assert_eq!(error.details["request_receipt_error"]["code"], "EXCLUSIVE_EVIDENCE_WRITE_FAILED");
            assert!(fenced);
        }
        let original = refuse("REMOTE_REPLY_INVALID");
        let mut fenced = false;
        let error = after_request_receipt(Err(original.clone()), Err(refuse("EVIDENCE_WRITE_FAILED")), false, &mut fenced).unwrap_err();
        primary_kept(&original, &error);
        assert!(!fenced);
    }

    #[test]
    fn receipt_failure_after_ack_is_unknown_only_for_mutations() {
        let mut fenced = false;
        let error = after_request_receipt(Ok(json!({"ok":1})), Err(refuse("EVIDENCE_WRITE_FAILED")), true, &mut fenced).unwrap_err();
        assert_eq!(error.code, "POST_DISPATCH_EVIDENCE_WRITE_FAILED");
        assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
        assert!(fenced);
        let mut read_fenced = false;
        let error = after_request_receipt(Ok(json!({"pid":42})), Err(refuse("EVIDENCE_WRITE_FAILED")), false, &mut read_fenced).unwrap_err();
        assert_eq!(error.outcome, "NOT_DISPATCHED");
        assert!(!read_fenced);
    }

    #[test]
    fn matching_mode_and_successful_receipt_pass_through_without_reset_or_retry() {
        let ack = json!({"ok":1,"f":19});
        let mut fenced = false;
        let result = after_input_mode(Ok(ack.clone()), window_mode(true, false), &mut fenced);
        assert_eq!(after_request_receipt(result, Ok(()), true, &mut fenced).unwrap(), ack);
        assert!(!fenced);
        fenced = true;
        assert_eq!(after_request_receipt(Ok(ack.clone()), Ok(()), true, &mut fenced).unwrap(), ack);
        assert!(fenced);
    }
}

#[cfg(test)]
mod normal_exit_tests {
    use super::*;
    use std::{cell::Cell, collections::VecDeque};

    fn sample(root: Option<Option<i32>>, active: u32) -> NormalExitObservation {
        NormalExitObservation { root:Ok(root), active:Ok(active) }
    }
    fn scripted(budget_ms: u64, script: Vec<(u64, NormalExitObservation)>) -> (Result<()>, Vec<Value>, Vec<Duration>, Duration) {
        let clock = Cell::new(Duration::ZERO);
        let mut queue = VecDeque::from(script);
        let fallback = queue.back().unwrap().1.clone();
        let mut samples = Vec::new(); let mut pauses = Vec::new();
        let result = poll_normal_exit(Duration::from_millis(budget_ms), || clock.get(), || {
            let (cost, observation) = queue.pop_front().unwrap_or_else(|| (0, fallback.clone()));
            clock.set(clock.get() + Duration::from_millis(cost));
            observation
        }, |duration| { pauses.push(duration); clock.set(clock.get() + duration); }, &mut samples);
        (result, samples, pauses, clock.get())
    }

    #[test]
    fn transient_job_count_waits_for_actual_root_zero_and_job_zero() {
        let (result, samples, pauses, elapsed) = scripted(100, vec![
            (0, sample(None, 1)), (0, sample(Some(Some(0)), 1)), (0, sample(Some(Some(0)), 0)),
        ]);
        assert!(result.is_ok()); assert_eq!(samples.len(), 3);
        assert_eq!(samples[0]["root_signaled"], false);
        assert_eq!(samples[1]["raw_active_processes"], 1);
        assert_eq!(samples[2]["root_signaled"], true);
        assert_eq!(samples[2]["exit_code"], 0);
        assert_eq!(samples[2]["raw_active_processes"], 0);
        assert_eq!(pauses, vec![Duration::from_millis(25); 2]);
        assert_eq!(elapsed, Duration::from_millis(50));
    }

    #[test]
    fn persistent_job_count_exhausts_same_budget_without_accepting_root_zero() {
        let (result, samples, pauses, elapsed) = scripted(60, vec![(0, sample(Some(Some(0)), 1))]);
        let error = result.unwrap_err(); assert_eq!(error.code, "OWNED_DESCENDANTS_REMAIN");
        assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
        assert_eq!(samples.len(), 3); assert!(samples.iter().all(|s| s["raw_active_processes"] == 1));
        assert_eq!(pauses, vec![Duration::from_millis(25), Duration::from_millis(25), Duration::from_millis(10)]);
        assert_eq!(elapsed, Duration::from_millis(60));
    }

    #[test]
    fn running_root_with_job_zero_still_times_out() {
        let (result, samples, _, elapsed) = scripted(50, vec![(0, sample(None, 0))]);
        assert_eq!(result.unwrap_err().code, "NORMAL_APP_EXIT_UNCONFIRMED");
        assert!(samples.iter().all(|s| s["root_signaled"] == false && s["raw_active_processes"] == 0));
        assert_eq!(elapsed, Duration::from_millis(50));
    }

    #[test]
    fn nonzero_incomplete_and_query_errors_never_become_readiness() {
        let cases = [
            (sample(Some(Some(7)), 0), "APP_EXIT_NONZERO"),
            (NormalExitObservation { root:Ok(Some(Some(7))), active:Err(refuse("JOB_PROCESS_QUERY_FAILED")) }, "APP_EXIT_NONZERO"),
            (sample(Some(None), 0), "APP_EXIT_STATUS_UNAVAILABLE"),
            (NormalExitObservation { root:Err(refuse("PROCESS_WAIT_FAILED")), active:Ok(1) }, "PROCESS_WAIT_FAILED"),
            (NormalExitObservation { root:Ok(Some(Some(0))), active:Err(refuse("JOB_PROCESS_QUERY_FAILED")) }, "JOB_PROCESS_QUERY_FAILED"),
        ];
        for (observation, code) in cases {
            let (result, samples, pauses, _) = scripted(100, vec![(0, observation)]);
            assert_eq!(result.unwrap_err().code, code);
            assert_eq!(samples.len(), 1); assert!(pauses.is_empty());
            if code == "JOB_PROCESS_QUERY_FAILED" {
                assert!(samples[0]["raw_active_processes"].is_null());
                assert_eq!(samples[0]["job_query_error"]["code"], code);
            }
            if code == "PROCESS_WAIT_FAILED" {
                assert!(samples[0]["root_signaled"].is_null());
                assert_eq!(samples[0]["root_query_error"]["code"], code);
            }
        }
    }

    #[test]
    fn complete_samples_at_or_after_deadline_are_not_accepted() {
        for cost in [50, 51] {
            let (result, samples, pauses, _) = scripted(50, vec![(cost, sample(Some(Some(0)), 0))]);
            assert_eq!(result.unwrap_err().code, "NORMAL_APP_EXIT_UNCONFIRMED");
            assert_eq!(samples[0]["completed_elapsed_ms"], cost); assert!(pauses.is_empty());
        }
        let (result, samples, _, _) = scripted(50, vec![
            (0, sample(Some(Some(0)), 1)), (25, sample(Some(Some(0)), 0)),
        ]);
        assert!(result.is_err()); assert_eq!(samples.len(), 2);
        let (result, samples, _, _) = scripted(0, vec![(0, sample(Some(Some(0)), 0))]);
        assert!(result.is_err()); assert!(samples.is_empty());
    }

    #[test]
    fn exit_receipt_failure_preserves_primary_or_makes_normal_result_unknown() {
        for mut original in [RemoteError::unknown("OWNED_DESCENDANTS_REMAIN"), refuse("APP_EXIT_NONZERO"), refuse("JOB_PROCESS_QUERY_FAILED")] {
            original.details["marker"] = json!(17);
            let error = after_normal_exit_receipt(Err(original.clone()), Err(refuse("EXCLUSIVE_EVIDENCE_WRITE_FAILED")), "normal_exit_wait_write_error").unwrap_err();
            assert_eq!(error.code, original.code); assert_eq!(error.outcome, original.outcome);
            assert_eq!(error.retry_safe, original.retry_safe); assert_eq!(error.details["marker"], 17);
            assert_eq!(error.details["normal_exit_wait_write_error"]["code"], "EXCLUSIVE_EVIDENCE_WRITE_FAILED");
        }
        for key in ["normal_exit_wait_write_error", "normal_exit_write_error"] {
            let error = after_normal_exit_receipt(Ok(json!({"normal_exit_observed":true,"exit_code":0})),
                Err(refuse("EVIDENCE_WRITE_FAILED")), key).unwrap_err();
            assert_eq!(error.code, "NORMAL_EXIT_EVIDENCE_WRITE_FAILED");
            assert_eq!(error.outcome, "OUTCOME_UNKNOWN"); assert!(!error.retry_safe);
        }
    }
}

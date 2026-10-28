//! Windows-native counterpart of the existing owned_driver Job lifecycle.
//! One unnamed, non-inheritable kill-on-close Job per execution; assigned before
//! resume. This is process containment, not an arbitrary-shell API or sandbox.
use serde::Serialize;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::File,
    mem::size_of,
    os::windows::{ffi::OsStrExt, io::AsRawHandle, process::ExitStatusExt},
    process::{Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, WAIT_OBJECT_0,
            WAIT_TIMEOUT,
        },
        System::{JobObjects::*, Threading::*},
    },
    core::{PCWSTR, PWSTR},
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
fn wide(value: &OsStr) -> Result<Vec<u16>, String> {
    let mut result: Vec<u16> = value.encode_wide().collect();
    if result.contains(&0) {
        return Err("owned command contains NUL".into());
    }
    result.push(0);
    Ok(result)
}
fn quote(value: &OsStr) -> Result<Vec<u16>, String> {
    let raw = wide(value)?;
    let mut result = vec![34];
    let mut slashes = 0;
    for &c in &raw[..raw.len() - 1] {
        if c == 92 {
            slashes += 1;
            continue;
        }
        result.extend(std::iter::repeat_n(
            92,
            if c == 34 { slashes * 2 + 1 } else { slashes },
        ));
        result.push(c);
        slashes = 0;
    }
    result.extend(std::iter::repeat_n(92, slashes * 2));
    result.push(34);
    Ok(result)
}
fn duplicate(file: &File) -> Result<Handle, String> {
    let mut target = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            HANDLE(file.as_raw_handle()),
            GetCurrentProcess(),
            &mut target,
            0,
            true,
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(Handle(target))
}
struct Attributes {
    _storage: Vec<usize>,
    ptr: LPPROC_THREAD_ATTRIBUTE_LIST,
}
impl Attributes {
    fn new(handles: &[HANDLE]) -> Result<Self, String> {
        let mut bytes = 0;
        unsafe {
            let _ = InitializeProcThreadAttributeList(None, 1, None, &mut bytes);
        }
        if bytes == 0 {
            return Err("owned handle allowlist sizing failed".into());
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let ptr = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        unsafe {
            InitializeProcThreadAttributeList(Some(ptr), 1, None, &mut bytes)
                .map_err(|e| e.to_string())?;
        }
        let result = Self {
            _storage: storage,
            ptr,
        };
        unsafe {
            UpdateProcThreadAttribute(
                ptr,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                std::mem::size_of_val(handles),
                None,
                None,
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(result)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.ptr);
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct OwnedProcessCleanup {
    pub mechanism: &'static str,
    pub root_pid: u32,
    pub assigned_before_resume: bool,
    pub active_before: u32,
    pub active_after: u32,
    pub root_signaled: bool,
    pub confirmed: bool,
    pub duration_ms: u64,
}
pub struct OwnedWindowsProcess {
    job: Handle,
    process: Handle,
    pid: u32,
    cleaned: bool,
}
impl OwnedWindowsProcess {
    /// Only a trusted caller supplies this Command. Stdio is fixed file-based;
    /// inherited handles are restricted to this execution's three streams.
    pub fn spawn(command: &Command, stdout: &File, stderr: &File) -> Result<Self, String> {
        let program = wide(command.get_program())?;
        if !std::path::Path::new(command.get_program()).is_absolute() {
            return Err("owned executable must be an absolute trusted path".into());
        }
        let mut line = quote(command.get_program())?;
        for argument in command.get_args() {
            line.push(32);
            line.extend(quote(argument)?);
        }
        line.push(0);
        if line.len() > 32767 {
            return Err("owned command exceeds Windows bound".into());
        }
        let cwd = command
            .get_current_dir()
            .map(|p| wide(p.as_os_str()))
            .transpose()?;
        // Windows environment keys are case insensitive. Preserve the trusted
        // host environment and apply only explicit Command overrides/removals.
        let mut environment: BTreeMap<String, (OsString, OsString)> = std::env::vars_os()
            .map(|(k, v)| (k.to_string_lossy().to_uppercase(), (k, v)))
            .collect();
        for (key, value) in command.get_envs() {
            let canonical = key.to_string_lossy().to_uppercase();
            if let Some(value) = value {
                environment.insert(canonical, (key.into(), value.into()));
            } else {
                environment.remove(&canonical);
            }
        }
        let mut block = Vec::new();
        for (_, (key, value)) in environment {
            let mut entry = key;
            entry.push("=");
            entry.push(value);
            block.extend(wide(&entry)?);
        }
        block.push(0);
        if block.len() == 1 {
            block.push(0);
        }
        let stdin = File::open("NUL").map_err(|e| e.to_string())?;
        let streams = [duplicate(&stdin)?, duplicate(stdout)?, duplicate(stderr)?];
        let handles = streams.each_ref().map(|h| h.0);
        let attributes = Attributes::new(&handles)?;
        let job =
            Handle(unsafe { CreateJobObjectW(None, PCWSTR::null()).map_err(|e| e.to_string())? });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .map_err(|e| e.to_string())?;
        }
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.lpAttributeList = attributes.ptr;
        let mut info = PROCESS_INFORMATION::default();
        unsafe {
            CreateProcessW(
                PCWSTR(program.as_ptr()),
                Some(PWSTR(line.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                Some(block.as_ptr().cast()),
                cwd.as_ref().map_or(PCWSTR::null(), |v| PCWSTR(v.as_ptr())),
                &startup.StartupInfo,
                &mut info,
            )
            .map_err(|e| format!("owned CreateProcess: {e}"))?;
        }
        let process = Handle(info.hProcess);
        let primary_thread = Handle(info.hThread);
        if let Err(error) = unsafe { AssignProcessToJobObject(job.0, process.0) } {
            // This exact process has not run, so cannot have descendants.
            let terminated = unsafe { TerminateProcess(process.0, 1) };
            let signaled = unsafe { WaitForSingleObject(process.0, 2000) } == WAIT_OBJECT_0;
            if terminated.is_err() || !signaled {
                return Err(
                    "OWNED_PROCESS_CLEANUP_UNVERIFIED: suspended assignment failure".into(),
                );
            }
            return Err(format!("owned assignment before resume refused: {error}"));
        }
        let mut result = Self {
            job,
            process,
            pid: info.dwProcessId,
            cleaned: false,
        };
        if unsafe { ResumeThread(primary_thread.0) } == u32::MAX {
            if result.cleanup().is_err() {
                return Err("OWNED_PROCESS_CLEANUP_UNVERIFIED: resume failure".into());
            }
            return Err("owned ResumeThread failed".into());
        }
        Ok(result)
    }
    pub fn id(&self) -> u32 {
        self.pid
    }
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, String> {
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                unsafe {
                    GetExitCodeProcess(self.process.0, &mut code).map_err(|e| e.to_string())?;
                }
                Ok(Some(ExitStatus::from_raw(code)))
            }
            _ => Err("owned process wait failed".into()),
        }
    }
    pub fn active_processes(&self) -> Result<u32, String> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        unsafe {
            QueryInformationJobObject(
                Some(self.job.0),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                None,
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(info.ActiveProcesses)
    }
    /// Terminate by this Job HANDLE, never by an enumerated or recycled PID.
    /// A root exit is not proof that its descendants exited.
    pub fn cleanup(&mut self) -> Result<OwnedProcessCleanup, String> {
        let start = Instant::now();
        let before = self.active_processes()?;
        unsafe {
            TerminateJobObject(self.job.0, 1).map_err(|e| e.to_string())?;
        }
        loop {
            let after = self.active_processes()?;
            let root_signaled = unsafe { WaitForSingleObject(self.process.0, 0) } == WAIT_OBJECT_0;
            if after == 0 && root_signaled {
                self.cleaned = true;
                return Ok(OwnedProcessCleanup {
                    mechanism: "WINDOWS_JOB_OBJECT",
                    root_pid: self.pid,
                    assigned_before_resume: true,
                    active_before: before,
                    active_after: after,
                    root_signaled,
                    confirmed: true,
                    duration_ms: start.elapsed().as_millis() as u64,
                });
            }
            if start.elapsed() >= Duration::from_secs(2) {
                return Err("OWNED_PROCESS_CLEANUP_UNVERIFIED".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for OwnedWindowsProcess {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_command_quotes_empty_spaces_quotes_and_trailing_slash() {
        for (input, expected) in [
            ("", "\"\""),
            ("a b", "\"a b\""),
            ("a\"b", "\"a\\\"b\""),
            ("a\\", "\"a\\\\\""),
        ] {
            assert_eq!(
                String::from_utf16(&quote(OsStr::new(input)).unwrap()).unwrap(),
                expected
            );
        }
        assert!(quote(OsStr::new("a\0b")).is_err());
    }
    #[test]
    fn real_windows_owned_tree_cleanup_does_not_kill_neighbor() {
        let system = std::env::var_os("SystemRoot").unwrap();
        let powershell =
            std::path::PathBuf::from(system).join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let output = std::env::temp_dir().join(format!(
            "toolkit-owned-job-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&output).unwrap();
        let stdout = File::create(output.join("stdout.log")).unwrap();
        let stderr = File::create(output.join("stderr.log")).unwrap();
        let mut neighbor_command = Command::new(&powershell);
        neighbor_command.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 30",
        ]);
        let mut neighbor = OwnedWindowsProcess::spawn(&neighbor_command, &stdout, &stderr).unwrap();
        let mut crash_command = Command::new(&powershell);
        crash_command.args(["-NoProfile","-NonInteractive","-Command",
            "Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30' -WindowStyle Hidden; exit 25"]);
        let mut crashed = OwnedWindowsProcess::spawn(&crash_command, &stdout, &stderr).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        while crashed.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            crashed.active_processes().unwrap() >= 1,
            "crash fixture must leave owned child"
        );
        let proof = crashed.cleanup().unwrap();
        assert!(proof.confirmed && proof.active_after == 0 && proof.assigned_before_resume);
        assert!(
            neighbor.try_wait().unwrap().is_none(),
            "neighbor must remain alive"
        );
        assert!(neighbor.cleanup().unwrap().confirmed);
        std::fs::write(
            output.join("cleanup.json"),
            serde_json::to_vec_pretty(&proof).unwrap(),
        )
        .unwrap();
    }
}

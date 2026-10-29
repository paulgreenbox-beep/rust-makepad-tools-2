"""Internal Windows ownership for the existing fixed operator driver.

Create suspended, assign to an unnamed non-inheritable kill-on-close job, then
resume. No breakaway flags, process discovery or PID-based termination. A start
call retains its job until the owning session stops; auxiliary calls empty their
jobs before returning. This contains Windows CreateProcess descendants only;
the fixed guest driver must also provide its input ticket/release fence.
"""
from __future__ import annotations

import ctypes
import copy
from ctypes import wintypes as w
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
import math
import os
import stat
import subprocess
import tempfile
import threading
import time

CLEANUP_TIMEOUT = 2.0
POLL_INTERVAL = 0.02
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


def _regular_file_without_reparse_point(info):
    attributes = getattr(info, "st_file_attributes", 0)
    return (stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and not attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _open_driver_stdin(input_path):
    if input_path is None:
        return open(os.devnull, "rb")
    if not isinstance(input_path, (str, os.PathLike)):
        raise TypeError("driver input path must be a string or path-like value")
    path = os.fspath(input_path)
    if not isinstance(path, str):
        raise TypeError("driver input path must resolve to text")
    before = os.lstat(path)
    if not _regular_file_without_reparse_point(before):
        raise ValueError("driver input path must name a regular non-symlink file")
    stream = open(path, "rb")
    try:
        opened = os.fstat(stream.fileno())
        after = os.lstat(path)
        if (not _regular_file_without_reparse_point(opened)
                or not _regular_file_without_reparse_point(after)
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)):
            raise ValueError("driver input path changed while opening")
        return stream
    except BaseException:
        stream.close()
        raise


@dataclass(frozen=True)
class CleanupEvidence:
    reason: str
    assigned_before_resume: bool
    root_pid: int | None
    active_before: int | None
    active_after: int | None
    elapsed_ms: float
    budget_ms: float
    confirmed: bool
    lease_retained: bool = False
    observed_processes: int = 0
    observed_signaled: int = 0
    forced_termination: bool = False
    natural_exit_verified: bool = False

    def as_dict(self):
        return asdict(self)


class OwnedDriverCancelled(RuntimeError):
    def __init__(self, evidence=None):
        super().__init__("owned driver call cancelled")
        self.cleanup = evidence


class OwnedDriverCleanupFailure(RuntimeError):
    def __init__(self, evidence=None):
        super().__init__("owned Windows driver tree cleanup could not be proven within budget")
        self.cleanup = evidence


class OwnedDriverTimeout(subprocess.TimeoutExpired):
    def __init__(self, args, timeout, evidence, natural_exit=None):
        super().__init__(args, timeout)
        self.cleanup = evidence
        self.natural_exit = copy.deepcopy(natural_exit)


class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", w.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD),
                ("SchedulingClass", w.DWORD)]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
                ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                 "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


class _Accounting(ctypes.Structure):
    _fields_ = [(name, ctypes.c_longlong) for name in
                ("TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime",
                 "ThisPeriodTotalKernelTime")] + [(name, w.DWORD) for name in
                ("TotalPageFaultCount", "TotalProcesses", "ActiveProcesses",
                 "TotalTerminatedProcesses")]


class _ProcessBasicInformation(ctypes.Structure):
    _fields_ = [("exit_status", w.LONG), ("peb", ctypes.c_void_p),
                ("affinity", ctypes.c_size_t), ("priority", w.LONG),
                ("pid", ctypes.c_size_t), ("parent_pid", ctypes.c_size_t)]


def _kernel():
    if os.name != "nt":
        raise OSError("owned driver transport requires Windows Job Objects")
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    specs = {
        "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
        "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
        "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD,
                                       ctypes.c_void_p], w.BOOL),
        "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
        "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
        "TerminateProcess": ([w.HANDLE, w.UINT], w.BOOL),
        "ResumeThread": ([w.HANDLE], w.DWORD),
        "WaitForSingleObject": ([w.HANDLE, w.DWORD], w.DWORD),
        "GetExitCodeProcess": ([w.HANDLE, ctypes.POINTER(w.DWORD)], w.BOOL),
        "CloseHandle": ([w.HANDLE], w.BOOL),
        "OpenProcess": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
        "IsProcessInJob": ([w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)], w.BOOL),
        "GetProcessId": ([w.HANDLE], w.DWORD),
        "GetProcessTimes": ([w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4, w.BOOL),
        "QueryFullProcessImageNameW": ([w.HANDLE, w.DWORD, w.LPWSTR,
                                        ctypes.POINTER(w.DWORD)], w.BOOL),
    }
    for name, (args, result) in specs.items():
        fn = getattr(dll, name)
        fn.argtypes, fn.restype = args, result
    return dll


def _check(ok):
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


class _Job:
    def __init__(self):
        self.api = _kernel()
        self.handle = self.api.CreateJobObjectW(None, None)
        _check(self.handle)
        self.process = self.thread = None
        self.pid = None
        self.assigned = False
        self._natural_members = {}
        self._natural_owner = None
        self.created_monotonic_ns = time.monotonic_ns()
        try:
            limits = _ExtendedLimits()
            # Neither BREAKAWAY_OK nor SILENT_BREAKAWAY_OK is enabled.
            limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
            _check(self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits),
                                                   ctypes.sizeof(limits)))
        except BaseException:
            self.api.CloseHandle(self.handle)
            self.handle = None
            raise

    def start(self, args, streams):
        import _winapi
        import msvcrt
        inherited = []
        try:
            for stream in streams:
                inherited.append(_winapi.DuplicateHandle(
                    _winapi.GetCurrentProcess(), msvcrt.get_osfhandle(stream.fileno()),
                    _winapi.GetCurrentProcess(), 0, True, _winapi.DUPLICATE_SAME_ACCESS))
            si = subprocess.STARTUPINFO()
            si.dwFlags = subprocess.STARTF_USESTDHANDLES | subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            si.hStdInput, si.hStdOutput, si.hStdError = inherited
            # Explicit handle allowlist excludes the job and every unrelated
            # session's handles, including concurrent transport calls.
            si.lpAttributeList = {"handle_list": inherited}
            self.process, self.thread, self.pid, _ = _winapi.CreateProcess(
                None, subprocess.list2cmdline(args), None, None, True,
                0x00000004 | subprocess.CREATE_NO_WINDOW, None, None, si)  # SUSPENDED
            self.assign()
        finally:
            for handle in inherited:
                _winapi.CloseHandle(handle)

    def assign(self):
        _check(self.api.AssignProcessToJobObject(self.handle, self.process))
        self.assigned = True

    def resume(self):
        if not self.assigned:
            raise OSError("driver cannot resume without job ownership")
        if self.api.ResumeThread(self.thread) == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        _check(self.api.CloseHandle(self.thread))
        self.thread = None

    def active(self):
        info = _Accounting()
        _check(self.api.QueryInformationJobObject(self.handle, 1, ctypes.byref(info),
                                                 ctypes.sizeof(info), None))
        return info.ActiveProcesses

    def exited(self):
        result = self.api.WaitForSingleObject(self.process, 0)
        if result not in (0, 258):
            raise ctypes.WinError(ctypes.get_last_error())
        return result == 0

    def exit_code(self):
        code = w.DWORD()
        _check(self.api.GetExitCodeProcess(self.process, ctypes.byref(code)))
        return code.value

    def process_handles(self):
        # Observe only IDs returned by this exact job and pin membership before
        # waiting. Termination still uses the job handle exclusively. PID reuse
        # cannot turn this into a kill/wait on an unrelated process.
        capacity = 64
        while capacity <= 4096:
            class ProcessList(ctypes.Structure):
                _fields_ = [("assigned", w.DWORD), ("listed", w.DWORD),
                            ("ids", ctypes.c_size_t * capacity)]
            info = ProcessList()
            if self.api.QueryInformationJobObject(self.handle, 3, ctypes.byref(info),
                                                  ctypes.sizeof(info), None):
                if info.listed <= capacity and info.assigned <= capacity:
                    break
            elif ctypes.get_last_error() != 234:  # ERROR_MORE_DATA
                raise ctypes.WinError(ctypes.get_last_error())
            capacity *= 2
        else:
            raise OSError("owned job process observation exceeded fixed budget")
        handles = []
        try:
            for pid in info.ids[:info.listed]:
                handle = self.api.OpenProcess(0x100000 | 0x1000, False, pid)
                if not handle:
                    if ctypes.get_last_error() == 87:  # Process already gone.
                        continue
                    raise ctypes.WinError(ctypes.get_last_error())
                belongs = w.BOOL()
                try:
                    _check(self.api.IsProcessInJob(handle, self.handle, ctypes.byref(belongs)))
                    if belongs.value:
                        handles.append(handle)
                        handle = None
                finally:
                    if handle:
                        self.api.CloseHandle(handle)
            return handles
        except BaseException:
            for handle in handles:
                self.api.CloseHandle(handle)
            raise

    def _process_birth(self, handle):
        creation, exit_time, kernel, user = (w.FILETIME() for _ in range(4))
        _check(self.api.GetProcessTimes(handle, ctypes.byref(creation),
            ctypes.byref(exit_time), ctypes.byref(kernel), ctypes.byref(user)))
        pid = self.api.GetProcessId(handle)
        _check(pid)
        birth = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        if not birth:
            raise OSError("owned process creation identity is unavailable")
        return pid, birth

    def _identity(self, handle):
        # Birth, image and parent come from this held process object, never a
        # name lookup. Dynamic linking is required for this documented NT query.
        pid, birth = self._process_birth(handle)
        size = w.DWORD(32768)
        image = ctypes.create_unicode_buffer(size.value)
        _check(self.api.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)))
        if not image.value:
            raise OSError("owned process image identity is unavailable")
        query = ctypes.WinDLL("ntdll").NtQueryInformationProcess
        query.argtypes = [w.HANDLE, w.ULONG, ctypes.c_void_p, w.ULONG, ctypes.POINTER(w.ULONG)]
        query.restype = w.LONG
        info, length = _ProcessBasicInformation(), w.ULONG()
        status = query(handle, 0, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(length))
        if status != 0 or length.value != ctypes.sizeof(info) or not pid or info.pid != pid:
            raise OSError("owned process parent identity could not be observed")
        return dict(pid=pid, creation_filetime=birth,
                    parent_pid=info.parent_pid, image_path=image.value,
                    role="driver_root" if pid == self.pid else "owned_descendant")

    def natural_snapshot(self):
        """Read-only Job witness. Absence and post-containment counts are insufficient."""
        if self._natural_owner is None:
            owner = self.api.OpenProcess(0x1000, False, os.getpid())
            _check(owner)
            try:
                identity = self._identity(owner)
                self._natural_owner = {k: identity[k] for k in ("pid", "creation_filetime")}
            finally:
                _check(self.api.CloseHandle(owner))
        handles = self.process_handles()
        try:
            while handles:
                handle = handles.pop()
                try:
                    key = self._process_birth(handle)
                    if key not in self._natural_members:
                        identity = self._identity(handle)
                        if key != (identity["pid"], identity["creation_filetime"]):
                            raise OSError("owned process creation identity changed")
                        if len(self._natural_members) >= 256:
                            raise OSError("owned natural-exit member identity budget exceeded")
                        self._natural_members[key] = (handle, identity)
                        handle = None
                finally:
                    if handle:
                        _check(self.api.CloseHandle(handle))
        finally:
            for handle in handles:
                self.api.CloseHandle(handle)
        members = []
        identities = [identity for _, identity in self._natural_members.values()] + [self._natural_owner]
        for handle, identity in self._natural_members.values():
            state = self.api.WaitForSingleObject(handle, 0)
            if state not in (0, 258):
                raise OSError("owned member wait could not be observed")
            code = w.DWORD()
            if state == 0:
                _check(self.api.GetExitCodeProcess(handle, ctypes.byref(code)))
            # A parent PID without a compatible observed birth is explicitly
            # unresolved. Never open/kill a supposed parent by its numeric PID.
            parents = [p for p in identities if p["pid"] == identity["parent_pid"]
                       and p["creation_filetime"] <= identity["creation_filetime"]]
            members.append(dict(identity, signaled=state == 0, exit_code=code.value if state == 0 else None,
                parent_creation_filetime=parents[0]["creation_filetime"] if len(parents) == 1 else None))
        active = self.active()
        root = next((m for m in members if m["role"] == "driver_root"), None)
        return dict(schema="toolkit-owned-natural-exit-v1", owner=dict(self._natural_owner),
                    root_pid=self.pid, job_created_monotonic_ns=self.created_monotonic_ns,
                    observed_monotonic_ns=time.monotonic_ns(),
                    active_processes=active, members=members, before_containment=True,
                    termination_requested=False, natural_exit_verified=bool(root and root["signaled"]
                    and active == 0 and all(m["signaled"] for m in members)),
                    root_exit_code=root["exit_code"] if root else None)

    def _close_natural_handles(self):
        ok = True
        for handle, _ in self._natural_members.values():
            if not self.api.CloseHandle(handle):
                ok = False
        self._natural_members.clear()
        return ok

    def finish_naturally(self, witness, elapsed_ms, budget_ms):
        if (witness["root_pid"] != self.pid or witness["owner"] != self._natural_owner
                or witness["job_created_monotonic_ns"] != self.created_monotonic_ns
                or not witness["natural_exit_verified"] or self.active() != 0 or not self.exited()):
            raise OSError("natural Job0 has not been observed")
        ok = self._close_natural_handles()
        for name in ("thread", "process", "handle"):
            handle = getattr(self, name)
            if handle:
                if not self.api.CloseHandle(handle):
                    ok = False
                setattr(self, name, None)
        evidence = CleanupEvidence("natural-completed", self.assigned, self.pid, 0, 0,
            elapsed_ms, budget_ms, ok, observed_processes=len(witness["members"]),
            observed_signaled=len(witness["members"]), natural_exit_verified=ok)
        if not ok:
            raise OwnedDriverCleanupFailure(evidence)
        return evidence

    def dispose(self, reason):
        started = time.monotonic()
        before = after = None
        confirmed = False
        handles = []
        signaled = 0
        termination_requested = False
        try:
            before = self.active()
            handles = self.process_handles()
            if self.process and not self.assigned:
                # Assignment failure: this exact suspended process handle is
                # owned, has never executed, and cannot have descendants.
                termination_requested = True
                _check(self.api.TerminateProcess(self.process, 1))
            termination_requested = True
            _check(self.api.TerminateJobObject(self.handle, 1))
            while time.monotonic() - started < CLEANUP_TIMEOUT:
                after = self.active()
                signaled = sum(self.api.WaitForSingleObject(handle, 0) == 0 for handle in handles)
                if after == 0 and signaled == len(handles) and (not self.process or self.exited()):
                    confirmed = True
                    break
                time.sleep(POLL_INTERVAL)
        except OSError:
            # Closing the non-inherited job handle is the final kill backstop,
            # but is NOT a replacement for observed active-process-zero proof.
            confirmed = False
        finally:
            if not self._close_natural_handles():
                confirmed = False
            for handle in handles:
                if not self.api.CloseHandle(handle):
                    confirmed = False
            for name in ("thread", "process", "handle"):
                handle = getattr(self, name)
                if handle:
                    if not self.api.CloseHandle(handle):
                        confirmed = False
                    setattr(self, name, None)
        elapsed = (time.monotonic() - started) * 1000
        evidence = CleanupEvidence(reason, self.assigned, self.pid, before, after,
                                   elapsed, CLEANUP_TIMEOUT * 1000,
                                   confirmed and elapsed <= CLEANUP_TIMEOUT * 1000,
                                   observed_processes=len(handles), observed_signaled=signaled,
                                   forced_termination=termination_requested)
        if not evidence.confirmed:
            raise OwnedDriverCleanupFailure(evidence)
        return evidence

    def close_root_handles(self):
        for name in ("thread", "process"):
            handle = getattr(self, name)
            if handle:
                _check(self.api.CloseHandle(handle))
                setattr(self, name, None)


@dataclass(eq=False)
class _Call:
    cleanup: bool
    interrupt: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)


class OwnedDriver:
    """One session's internal transport handles; not public/AI identities."""
    def __init__(self):
        self._guard = threading.Lock()
        self._calls: set[_Call] = set()
        self._leases: list[_Job] = []
        self._quiescers = 0
        self._failure = None
        self.last_cleanup: CleanupEvidence | None = None
        self.last_natural_exit: dict | None = None

    def run(self, args, *, timeout, cancel_event=None, retain_start=False, cleanup=False,
            binary_output=False, input_path=None, require_natural_exit=False):
        if type(binary_output) is not bool:
            raise TypeError("binary_output must be exactly bool")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("driver timeout must be finite and positive")
        if type(require_natural_exit) is not bool or (require_natural_exit and retain_start):
            raise ValueError("natural exit requires an unretained owning call")
        call = _Call(cleanup)
        with self._guard:
            if not cleanup and self._failure:
                raise self._failure
            if not cleanup and self._quiescers:
                raise OwnedDriverCancelled()
            if retain_start and self._leases:
                raise OSError("start driver lease is already retained")
            self._calls.add(call)
        job = None
        retained = False
        error = None
        reason = "completed"
        started = time.monotonic()
        natural_witness = None
        call_cleanup = None
        if require_natural_exit:
            self.last_natural_exit = None
        try:
            def check_interrupt():
                if call.interrupt.is_set() or (cancel_event is not None and cancel_event.is_set()):
                    raise OwnedDriverCancelled()
                if time.monotonic() - started >= timeout:
                    raise subprocess.TimeoutExpired(args, timeout)

            check_interrupt()
            with _open_driver_stdin(input_path) as stdin, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                check_interrupt()
                job = _Job()
                job.start(args, (stdin, stdout, stderr))
                check_interrupt()  # Cancellation during create/assign cannot resume input.
                if require_natural_exit:
                    natural_witness = self.last_natural_exit = job.natural_snapshot()
                check_interrupt()  # Identity queries cannot authorize late/cancelled resume.
                job.resume()
                while True:
                    check_interrupt()
                    if any(os.fstat(stream.fileno()).st_size > MAX_OUTPUT_BYTES for stream in (stdout, stderr)):
                        raise OSError("owned driver output exceeded fixed budget")
                    if require_natural_exit:
                        natural_witness = self.last_natural_exit = job.natural_snapshot()
                    if job.exited() and (not require_natural_exit or natural_witness["natural_exit_verified"]):
                        break
                    call.interrupt.wait(min(POLL_INTERVAL, max(0, timeout - (time.monotonic() - started))))
                returncode = job.exit_code()
                check_interrupt()
                if retain_start and returncode == 0:
                    active = job.active()
                    job.close_root_handles()
                    with self._guard:
                        self._leases.append(job)
                    retained = True
                    call_cleanup = self.last_cleanup = CleanupEvidence("start-retained", True, job.pid,
                        active, active, 0.0, CLEANUP_TIMEOUT * 1000, False, True)
                elif require_natural_exit:
                    call_cleanup = self.last_cleanup = job.finish_naturally(natural_witness,
                        (time.monotonic() - started) * 1000, timeout * 1000)
                    job = None
                else:
                    call_cleanup = self.last_cleanup = job.dispose(reason)
                    job = None
                output = []
                for stream in (stdout, stderr):
                    stream.seek(0)
                    data = stream.read(MAX_OUTPUT_BYTES + 1)
                    if len(data) > MAX_OUTPUT_BYTES:
                        raise OSError("owned driver output exceeded fixed budget")
                    output.append(data if binary_output else data.decode("utf-8", errors="replace"))
                result = subprocess.CompletedProcess(args, returncode, *output)
                # last_* is a live diagnostic view. Acceptance must use the
                # detached outcome for this call, especially with concurrent calls.
                result.cleanup = call_cleanup
                result.natural_exit = copy.deepcopy(natural_witness)
                return result
        except BaseException as exc:
            error = exc
            reason = "cancelled" if isinstance(exc, OwnedDriverCancelled) else (
                "timeout" if isinstance(exc, subprocess.TimeoutExpired) else "failure")
            if isinstance(exc, OwnedDriverCleanupFailure):
                job = None  # dispose already closed all handles.
                self._failure = exc
                call_cleanup = self.last_cleanup = exc.cleanup
            raise
        finally:
            try:
                if job is not None and (not retained or error is not None):
                    if retained:
                        with self._guard:
                            self._leases.remove(job)
                    evidence = job.dispose(reason)
                    call_cleanup = self.last_cleanup = evidence
                if error is not None:
                    error.cleanup = call_cleanup
                    error.natural_exit = copy.deepcopy(natural_witness)
                if isinstance(error, subprocess.TimeoutExpired):
                    raise OwnedDriverTimeout(args, timeout, call_cleanup, natural_witness) from error
            except OwnedDriverCleanupFailure as exc:
                self._failure = exc
                self.last_cleanup = exc.cleanup
                exc.natural_exit = copy.deepcopy(natural_witness)
                raise
            finally:
                with self._guard:
                    self._calls.discard(call)
                    call.done.set()

    @contextmanager
    def quiescent(self):
        """Interrupt current input and gate new calls before the Port lock.

        Cleanup calls use their own deadline/event. Keep start leases alive so
        guest release can still read the live application and execute its fence.
        """
        with self._guard:
            self._quiescers += 1
            calls = [call for call in self._calls if not call.cleanup]
            for call in calls:
                call.interrupt.set()
        deadline = time.monotonic() + CLEANUP_TIMEOUT + 2 * POLL_INTERVAL
        try:
            for call in calls:
                if not call.done.wait(max(0, deadline - time.monotonic())):
                    raise OwnedDriverCleanupFailure()
            yield
            if self._failure:
                raise self._failure
        finally:
            with self._guard:
                self._quiescers -= 1

    @property
    def retained_lease_count(self):
        with self._guard:
            return len(self._leases)

    def close(self, *, reason="session-stop"):
        with self._guard:
            leases, self._leases = self._leases, []
        evidence = []
        for job in leases:
            try:
                evidence.append(job.dispose(reason))
            except OwnedDriverCleanupFailure as exc:
                self._failure = exc
                self.last_cleanup = exc.cleanup
                raise
        if evidence:
            self.last_cleanup = evidence[-1]
        if self._failure:
            raise self._failure
        return evidence

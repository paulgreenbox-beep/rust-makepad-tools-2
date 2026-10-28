"""Internal Windows ownership for the existing fixed operator driver.

Create suspended, assign to an unnamed non-inheritable kill-on-close job, then
resume. No breakaway flags, process discovery or PID-based termination. A start
call retains its job until the owning session stops; auxiliary calls empty their
jobs before returning. This contains Windows CreateProcess descendants only;
the fixed guest driver must also provide its input ticket/release fence.
"""
from __future__ import annotations

import ctypes
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
    def __init__(self, args, timeout, evidence):
        super().__init__(args, timeout)
        self.cleanup = evidence


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

    def dispose(self, reason):
        started = time.monotonic()
        before = after = None
        confirmed = False
        handles = []
        signaled = 0
        try:
            before = self.active()
            handles = self.process_handles()
            if self.process and not self.assigned:
                # Assignment failure: this exact suspended process handle is
                # owned, has never executed, and cannot have descendants.
                _check(self.api.TerminateProcess(self.process, 1))
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
                                   observed_processes=len(handles), observed_signaled=signaled)
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

    def run(self, args, *, timeout, cancel_event=None, retain_start=False, cleanup=False,
            binary_output=False, input_path=None):
        if type(binary_output) is not bool:
            raise TypeError("binary_output must be exactly bool")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("driver timeout must be finite and positive")
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
                job.resume()
                while True:
                    check_interrupt()
                    if any(os.fstat(stream.fileno()).st_size > MAX_OUTPUT_BYTES for stream in (stdout, stderr)):
                        raise OSError("owned driver output exceeded fixed budget")
                    if job.exited():
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
                    self.last_cleanup = CleanupEvidence("start-retained", True, job.pid,
                        active, active, 0.0, CLEANUP_TIMEOUT * 1000, False, True)
                else:
                    self.last_cleanup = job.dispose(reason)
                    job = None
                output = []
                for stream in (stdout, stderr):
                    stream.seek(0)
                    data = stream.read(MAX_OUTPUT_BYTES + 1)
                    if len(data) > MAX_OUTPUT_BYTES:
                        raise OSError("owned driver output exceeded fixed budget")
                    output.append(data if binary_output else data.decode("utf-8", errors="replace"))
                return subprocess.CompletedProcess(args, returncode, *output)
        except BaseException as exc:
            error = exc
            reason = "cancelled" if isinstance(exc, OwnedDriverCancelled) else (
                "timeout" if isinstance(exc, subprocess.TimeoutExpired) else "failure")
            if isinstance(exc, OwnedDriverCleanupFailure):
                job = None  # dispose already closed all handles.
                self._failure = exc
                self.last_cleanup = exc.cleanup
            raise
        finally:
            try:
                if job is not None and (not retained or error is not None):
                    if retained:
                        with self._guard:
                            self._leases.remove(job)
                    evidence = job.dispose(reason)
                    self.last_cleanup = evidence
                    if error is not None:
                        error.cleanup = evidence
                    if isinstance(error, subprocess.TimeoutExpired):
                        raise OwnedDriverTimeout(args, timeout, evidence) from error
            except OwnedDriverCleanupFailure as exc:
                self._failure = exc
                self.last_cleanup = exc.cleanup
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

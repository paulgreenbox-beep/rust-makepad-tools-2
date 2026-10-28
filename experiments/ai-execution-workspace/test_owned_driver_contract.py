"""Real local Windows transport proof; no WSL, GPU, keyboard or global input.

The fixture creates exactly a controlled child and grandchild. Read-only pinned
process handles prove termination without PID reuse, and a same-image neighbour
proves isolation. Mocked refusal tests are separate from the real OS evidence.
"""
from __future__ import annotations

import ctypes
import hashlib
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

import owned_driver
from owned_driver import (OwnedDriver, OwnedDriverCancelled, OwnedDriverCleanupFailure,
                          OwnedDriverTimeout, CLEANUP_TIMEOUT)

_REAL_RUN = OwnedDriver.run


def _fixture(root, depth, mode):
    root = Path(root)
    if depth < 2:
        subprocess.Popen([sys.executable, "-B", __file__, "--owned-fixture", str(root),
                          str(depth + 1), mode], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root / f"ready-{depth}").write_text(str(os.getpid()), encoding="ascii")
    if depth == 0 and mode == "exit":
        deadline = time.monotonic() + 6
        while not (root / "ready-2").exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("controlled grandchild did not become ready")
            time.sleep(0.01)
        print(json.dumps({"fixture": "ready"}), flush=True)
        return
    time.sleep(30)  # Safety ceiling if the test controller itself fails.


@unittest.skipUnless(os.name == "nt", "real Windows Job Object contract")
class OwnedDriverContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.transport = OwnedDriver()
        self.api = owned_driver._kernel()
        self.api.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.api.OpenProcess.restype = w.HANDLE
        self.handles = []
        self.neighbours = []

    def tearDown(self):
        self.transport.close()
        for neighbour in self.neighbours:
            neighbour.terminate()  # Only this test's directly created Popen handle.
            neighbour.wait(timeout=2)
        for handle in self.handles:
            self.api.CloseHandle(handle)
        self.temp.cleanup()

    def command(self, mode="hold"):
        return [sys.executable, "-B", str(Path(__file__).resolve()), "--owned-fixture",
                str(self.root), "0", mode]

    def ready(self, depths=(0, 1, 2), timeout=2.5):
        deadline = time.monotonic() + timeout
        handles = []
        for depth in depths:
            file = self.root / f"ready-{depth}"
            while not file.exists() or not file.read_text(encoding="ascii"):
                if time.monotonic() >= deadline:
                    self.fail("controlled process tree readiness deadline exceeded")
                time.sleep(0.01)
            handle = self.api.OpenProcess(0x100000, False, int(file.read_text(encoding="ascii")))
            self.assertTrue(handle, "cannot pin controlled process observation handle")
            self.handles.append(handle)
            handles.append(handle)
        return handles

    def assert_dead(self, handles):
        for handle in handles:
            self.assertEqual(self.api.WaitForSingleObject(handle, 0), 0)

    def run_thread(self, **kwargs):
        box = {}
        def run():
            try:
                box["result"] = self.transport.run(self.command(), **kwargs)
            except BaseException as exc:
                box["error"] = exc
        thread = threading.Thread(target=run)
        thread.start()
        self.addCleanup(lambda: thread.join(4))
        return thread, box

    def assert_cleanup(self, exception, reason):
        evidence = exception.cleanup
        self.assertTrue(evidence.confirmed)
        self.assertTrue(evidence.assigned_before_resume)
        self.assertEqual(evidence.reason, reason)
        self.assertEqual(evidence.active_after, 0)
        self.assertGreaterEqual(evidence.active_before, 3)
        self.assertGreaterEqual(evidence.observed_processes, 3)
        self.assertEqual(evidence.observed_signaled, evidence.observed_processes)
        self.assertLessEqual(evidence.elapsed_ms, CLEANUP_TIMEOUT * 1000)
        print("CONTROLLED_TREE " + json.dumps(evidence.as_dict(), sort_keys=True), flush=True)

    def test_cancel_terminates_child_and_grandchild_and_preserves_same_image_neighbour(self):
        neighbour = subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(30)"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        self.neighbours.append(neighbour)
        cancel = threading.Event()
        thread, box = self.run_thread(timeout=15.0, cancel_event=cancel)
        try:
            handles = self.ready()
        finally:
            requested = time.monotonic()
            cancel.set()
            thread.join(CLEANUP_TIMEOUT + 0.5)
        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - requested, CLEANUP_TIMEOUT + 0.5)
        self.assertIsInstance(box.get("error"), OwnedDriverCancelled)
        self.assert_cleanup(box["error"], "cancelled")
        self.assert_dead(handles)
        self.assertIsNone(neighbour.poll())

    def test_timeout_terminates_real_tree_before_return(self):
        started = time.monotonic()
        thread, box = self.run_thread(timeout=3.0)
        handles = self.ready()
        thread.join(3 + CLEANUP_TIMEOUT + 0.5)
        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - started, 3 + CLEANUP_TIMEOUT + 0.5)
        self.assertIsInstance(box.get("error"), OwnedDriverTimeout)
        self.assert_cleanup(box["error"], "timeout")
        self.assert_dead(handles)

    def test_timeout_start_does_not_retain_tree(self):
        thread, box = self.run_thread(timeout=3.0, retain_start=True)
        handles = self.ready()
        thread.join(3 + CLEANUP_TIMEOUT + 0.5)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(box.get("error"), OwnedDriverTimeout)
        self.assert_cleanup(box["error"], "timeout")
        self.assert_dead(handles)
        self.assertEqual(self.transport._leases, [])

    def test_success_start_retains_descendants_through_auxiliary_then_stop_closes(self):
        result = self.transport.run(self.command("exit"), timeout=6.0, retain_start=True)
        self.assertEqual(result.returncode, 0)
        handles = self.ready((1, 2))
        for handle in handles:
            self.assertEqual(self.api.WaitForSingleObject(handle, 0), 258)
        self.assertTrue(self.transport.last_cleanup.lease_retained)
        self.assertFalse(self.transport.last_cleanup.confirmed)
        auxiliary = self.transport.run([sys.executable, "-B", "-c", "print('auxiliary')"],
                                       timeout=3.0, cleanup=True)
        self.assertEqual(auxiliary.stdout.strip(), "auxiliary")
        for handle in handles:
            self.assertEqual(self.api.WaitForSingleObject(handle, 0), 258)
        evidence = self.transport.close()
        self.assertTrue(evidence[0].confirmed)
        self.assertEqual(evidence[0].active_after, 0)
        self.assert_dead(handles)

    def test_success_auxiliary_cannot_leave_descendants(self):
        result = self.transport.run(self.command("exit"), timeout=6.0)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(self.transport.last_cleanup.confirmed)
        self.assertEqual(self.transport.last_cleanup.active_after, 0)
        self.assertGreaterEqual(self.transport.last_cleanup.active_before, 2)

    def test_release_quiesces_blocking_call_and_gates_new_input(self):
        thread, box = self.run_thread(timeout=15.0)
        handles = self.ready()
        with self.transport.quiescent():
            self.assertFalse(thread.is_alive())
            self.assertIsInstance(box.get("error"), OwnedDriverCancelled)
            self.assert_dead(handles)
            with self.assertRaises(OwnedDriverCancelled):
                self.transport.run([sys.executable, "-B", "-c", "pass"], timeout=1.0)
            result = self.transport.run([sys.executable, "-B", "-c", "print('released')"],
                                        timeout=2.0, cleanup=True)
            self.assertEqual(result.stdout.strip(), "released")

    def test_assignment_failure_never_resumes_driver(self):
        with patch.object(owned_driver._Job, "assign", side_effect=OSError("assignment refused")):
            with self.assertRaises(OSError) as caught:
                self.transport.run(self.command(), timeout=3.0)
        self.assertFalse((self.root / "ready-0").exists())
        self.assertFalse(caught.exception.cleanup.assigned_before_resume)
        self.assertTrue(caught.exception.cleanup.confirmed)

    def test_cancellation_during_assignment_never_resumes_driver(self):
        cancel = threading.Event()
        assign = owned_driver._Job.assign
        def assign_then_cancel(job):
            assign(job)
            cancel.set()
        with patch.object(owned_driver._Job, "assign", assign_then_cancel):
            with self.assertRaises(OwnedDriverCancelled) as caught:
                self.transport.run(self.command(), timeout=3.0, cancel_event=cancel)
        self.assertFalse((self.root / "ready-0").exists())
        self.assertTrue(caught.exception.cleanup.assigned_before_resume)
        self.assertTrue(caught.exception.cleanup.confirmed)

    def test_unproven_cleanup_is_bounded_and_poisoned_never_pass(self):
        with patch.object(owned_driver._Job, "active", return_value=1), \
             patch("owned_driver.CLEANUP_TIMEOUT", 0.06):
            with self.assertRaises(OwnedDriverCleanupFailure) as caught:
                self.transport.run([sys.executable, "-B", "-c", "pass"], timeout=3.0)
        self.assertFalse(caught.exception.cleanup.confirmed)
        self.assertGreaterEqual(caught.exception.cleanup.elapsed_ms, 60)
        with self.assertRaises(OwnedDriverCleanupFailure):
            self.transport.run([sys.executable, "-B", "-c", "pass"], timeout=3.0)
        # This intentional mocked failure remains a failure on close, too.
        with self.assertRaises(OwnedDriverCleanupFailure):
            self.transport.close()
        self.transport._failure = None


@unittest.skipUnless(os.name == "nt", "real Port to Windows transport composition")
class PortTransportContractTests(OwnedDriverContractTests):
    # Do not duplicate the standalone tests via inheritance discovery.
    def setUp(self):
        import test_wslc_port
        test_wslc_port.WslcPortTests.setUp(self)
        from test_compact_input import BatchPortTests
        self.sid = BatchPortTests.ready(self)
        self.fixture_root = self.root / "controlled-tree"
        self.fixture_root.mkdir()
        self.transport = self.port._state(self.sid).driver
        self.api = owned_driver._kernel()
        self.handles, self.neighbours = [], []
        self.port._controlled_keys = True

    def tearDown(self):
        self.transport.close()
        for handle in self.handles:
            self.api.CloseHandle(handle)
        import test_wslc_port
        test_wslc_port.WslcPortTests.tearDown(self)

    def command(self, mode="hold"):
        return [sys.executable, "-B", str(Path(__file__).resolve()), "--owned-fixture",
                str(self.fixture_root), "0", mode]

    def ready(self, depths=(0, 1, 2), timeout=2.5):
        original = self.root
        try:
            self.root = self.fixture_root
            return super().ready(depths, timeout)
        finally:
            self.root = original

    def controlled_call(self, args, **kwargs):
        from test_wslc_port import MockDriver
        op = MockDriver._value(args, "-Operation")
        if op == "key":
            self.assertIsInstance(kwargs["cancel_event"], threading.Event)
            self.assertFalse(kwargs["cleanup"])
            return _REAL_RUN(self.transport, self.command(), **kwargs)
        if op in {"key_down", "key_up"}:
            state = self.driver.states[str(self.sid)]
            self.driver.calls.append((list(args), dict(kwargs)))
            state["held_keys"] = ["Shift"] if op == "key_down" else []
            state["sequence"] += 1
            return MockDriver._completed(args, MockDriver._reply(state))
        return self.driver.run(args, **kwargs)

    def dispatch_thread(self, timeout_ms):
        from compact_input import BATCH_OPERATION
        box = {}
        def run():
            try:
                box["result"] = self.manager.dispatch(self.sid, self.owner, BATCH_OPERATION,
                    {"steps": [{"op": "key_down", "key": "Shift"}, {"op": "key", "key": "a"},
                               {"op": "key_up", "key": "Shift"}],
                     "expected_state": {"text": "A"}, "timeout_ms": timeout_ms})
            except BaseException as exc:
                box["error"] = exc
        thread = threading.Thread(target=run)
        thread.start()
        return thread, box

    def assert_failure_record(self, failure, reason):
        self.assertEqual(failure.batch_progress["attempted_steps"], 2)
        self.assertEqual(failure.batch_progress["observed_steps"], 1)
        self.assertFalse(failure.batch_progress["auto_retry"])
        self.assertEqual(self.driver.states[str(self.sid)]["held_keys"], [])
        detail = failure.driver_cleanup
        evidence = detail["cleanup"]
        self.assertEqual(evidence["reason"], reason)
        self.assertTrue(evidence["confirmed"])
        self.assertEqual(evidence["active_after"], 0)
        self.assertGreaterEqual(evidence["observed_signaled"], 3)
        raw = Path(detail["evidence_path"]).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), detail["sha256"])
        self.assertEqual(json.loads(raw)["cleanup"], evidence)
        print("PORT_CONTROLLED_TREE " + json.dumps(detail, sort_keys=True), flush=True)

    def test_port_batch_cancel_reaches_blocking_driver_and_release_is_independent(self):
        from manager import SessionCancelled
        with patch("wslc_port.OwnedDriver.run", side_effect=self.controlled_call):
            thread, box = self.dispatch_thread(15_000)
            try:
                handles = self.ready()
            finally:
                self.manager.cancel(self.sid, self.owner)
                thread.join(CLEANUP_TIMEOUT + 0.5)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(box.get("error"), SessionCancelled)
        self.assert_dead(handles)
        self.assert_failure_record(box["error"], "cancelled")

    def test_port_batch_deadline_really_times_out_owned_tree_while_shift_is_held(self):
        from manager import RelayFailure
        with patch("wslc_port.OwnedDriver.run", side_effect=self.controlled_call):
            thread, box = self.dispatch_thread(3_000)
            handles = self.ready()
            thread.join(3 + CLEANUP_TIMEOUT + 0.5)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(box.get("error"), RelayFailure)
        self.assert_dead(handles)
        self.assert_failure_record(box["error"], "timeout")
        self.assertEqual(box["error"].driver_cleanup["cause"], "OwnedDriverTimeout")

    def test_normal_session_stop_persists_hash_bound_retained_job_cleanup(self):
        _REAL_RUN(self.transport, self.command("exit"), timeout=6.0, retain_start=True)
        handles = self.ready((1, 2))
        state = self.port._state(self.sid)
        result = self.port.stop_session(session_id=self.sid)
        self.assertTrue(result.process_stopped)
        self.assert_dead(handles)
        detail = state.driver_stop_evidence
        self.assertEqual(detail["cause"], "OwnedDriverClosed")
        self.assertEqual(detail["closed_leases"], 1)
        self.assertEqual(detail["retained_leases_remaining"], 0)
        self.assertTrue(detail["cleanup"]["confirmed"])
        self.assertEqual(detail["cleanup"]["reason"], "session-stop")
        self.assertEqual(detail["cleanup"]["active_after"], 0)
        raw = Path(detail["evidence_path"]).read_bytes()
        self.assertEqual(detail["sha256"], hashlib.sha256(raw).hexdigest())


# Only the three Port composition tests belong to this subclass. Reusing the
# read-only handle helpers must not rerun the independent transport scenarios.
for _name in tuple(OwnedDriverContractTests.__dict__):
    if _name.startswith("test_"):
        setattr(PortTransportContractTests, _name, None)


@unittest.skipUnless(os.name == "nt", "real Windows capture-process ownership contract")
class CaptureProcessBoundedOutputTests(unittest.TestCase):
    def setUp(self):
        bundled=Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/native/powershell/pwsh.exe'
        self.powershell = str(bundled) if bundled.is_file() else shutil.which("pwsh")
        if not self.powershell:
            self.skipTest("PowerShell is not available")
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.helpers = []
        self.handles = []
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.kernel32.OpenProcess.restype = w.HANDLE
        self.kernel32.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        self.kernel32.WaitForSingleObject.restype = w.DWORD
        self.kernel32.CloseHandle.argtypes = [w.HANDLE]
        self.kernel32.CloseHandle.restype = w.BOOL
        self.kernel32.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
        self.kernel32.TerminateProcess.restype = w.BOOL
        self.addCleanup(self._cleanup_owned_helpers)

    def _cleanup_owned_helpers(self):
        for helper, gate in self.helpers:
            if not gate.exists():
                gate.touch()
            if helper.poll() is None:
                helper.kill() # retained Popen handle; child has its own retained handle below
            try:
                helper.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                helper.kill()
                helper.communicate(timeout=5)
        for handle in self.handles:
            if self.kernel32.WaitForSingleObject(handle, 0) != 0:
                self.kernel32.TerminateProcess(handle, 1)
                self.kernel32.WaitForSingleObject(handle, 5000)
            self.kernel32.CloseHandle(handle)

    def _writer_script(self):
        path = self.root / "bounded-writer.py"
        path.write_text(
            "import os, pathlib, sys, time\n"
            "pid_file = pathlib.Path(sys.argv[1])\n"
            "release_file = pathlib.Path(sys.argv[2])\n"
            "mode = sys.argv[3]\n"
            "pid_file.write_text(str(os.getpid()), encoding='ascii')\n"
            "deadline = time.monotonic() + 15\n"
            "while not release_file.exists() and time.monotonic() < deadline:\n"
            "    time.sleep(0.005)\n"
            "if mode == 'stdout':\n"
            "    while True: os.write(1, b'O' * 8192)\n"
            "elif mode == 'stderr':\n"
            "    while True: os.write(2, b'E' * 8192)\n"
            "else:\n"
            "    os.write(1, b'bounded stdout\\n')\n"
            "    os.write(2, b'bounded stderr\\n')\n",
            encoding="utf-8")
        return path

    def _run_capture(self, label, mode, stdout_limit=None, stderr_limit=None):
        writer = self._writer_script()
        output_dir = self.root / (label + "-output")
        pid_file = self.root / (label + "-child.pid")
        release_file = self.root / (label + "-release")
        capture_script = Path(__file__).with_name("capture-process.ps1")
        quote=lambda value:"'"+str(value).replace("'","''")+"'"
        command='& '+quote(capture_script)+' -Label '+quote(label)+' -Executable '+quote(sys.executable)+\
                ' -TimeoutSeconds 8 -OutputDirectory '+quote(output_dir)
        if stdout_limit is not None:
            command+=' -StdoutLimitBytes '+str(stdout_limit)
        if stderr_limit is not None:
            command+=' -StderrLimitBytes '+str(stderr_limit)
        command+=' -CommandArgs @('+','.join(quote(v) for v in (writer,pid_file,release_file,mode))+')'
        args=[self.powershell,'-NoProfile','-NonInteractive','-Command',command]
        helper = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.helpers.append((helper, release_file))

        deadline = time.monotonic() + 6
        while not pid_file.exists() and helper.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if not pid_file.exists():
            stdout, stderr = helper.communicate(timeout=5)
            self.fail("capture child did not start: " + repr((stdout, stderr)))

        child_pid = int(pid_file.read_text(encoding="ascii"))
        child_handle = self.kernel32.OpenProcess(0x00100001, False, child_pid)
        self.assertTrue(child_handle, "cannot pin the directly created capture child")
        self.handles.append(child_handle)
        release_file.touch()
        try:
            helper_stdout, helper_stderr = helper.communicate(timeout=12)
        except subprocess.TimeoutExpired:
            self.fail("capture helper did not finish within its bounded test window")

        record_path = output_dir / (label + ".json")
        self.assertTrue(record_path.exists(), "capture record was not saved")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        return helper.returncode, helper_stdout, helper_stderr, record, output_dir, child_handle

    def assert_child_exited(self, handle):
        self.assertEqual(self.kernel32.WaitForSingleObject(handle, 0), 0,
                         "the directly created capture child was left running")

    def test_stdout_overflow_saves_bounded_partial_and_kills_owned_child(self):
        status, _stdout, _stderr, record, output_dir, child = self._run_capture(
            "stdout-overflow", "stdout", stdout_limit=4096, stderr_limit=4096)
        self.assertNotEqual(status, 0, "overflow must refuse a successful helper outcome")
        self.assertFalse(record["capture_accepted"])
        self.assertEqual(record["capture_failure_reason"], "stdout_overflow")
        self.assertTrue(record["stdout_overflow"])
        self.assertFalse(record["stderr_overflow"])
        self.assertEqual(record["stdout_bytes"], 4096)
        self.assertLessEqual(record["stderr_bytes"], 4096)
        self.assertEqual(record["exit_code"] is None, False)
        self.assertNotEqual(record["exit_code"], 0)
        self.assertTrue(record["owned_tree_termination_requested"])
        self.assertFalse(record["foreign_processes_changed"])
        self.assertEqual((output_dir / "stdout-overflow.stdout.txt").read_bytes(), b"O" * 4096)
        self.assert_child_exited(child)

    def test_stderr_overflow_saves_bounded_partial_and_kills_owned_child(self):
        status, _stdout, _stderr, record, output_dir, child = self._run_capture(
            "stderr-overflow", "stderr", stdout_limit=4096, stderr_limit=4096)
        self.assertNotEqual(status, 0, "overflow must refuse a successful helper outcome")
        self.assertFalse(record["capture_accepted"])
        self.assertEqual(record["capture_failure_reason"], "stderr_overflow")
        self.assertFalse(record["stdout_overflow"])
        self.assertTrue(record["stderr_overflow"])
        self.assertLessEqual(record["stdout_bytes"], 4096)
        self.assertEqual(record["stderr_bytes"], 4096)
        self.assertEqual(record["exit_code"] is None, False)
        self.assertNotEqual(record["exit_code"], 0)
        self.assertTrue(record["owned_tree_termination_requested"])
        self.assertFalse(record["foreign_processes_changed"])
        self.assertEqual((output_dir / "stderr-overflow.stderr.txt").read_bytes(), b"E" * 4096)
        self.assert_child_exited(child)

    def test_normal_capture_is_bounded_and_preserves_default_caps(self):
        status, _stdout, _stderr, record, _output_dir, child = self._run_capture(
            "bounded-success", "success")
        self.assertEqual(status, 0)
        self.assertTrue(record["capture_accepted"])
        self.assertFalse(record["stdout_overflow"])
        self.assertFalse(record["stderr_overflow"])
        self.assertEqual(record["stdout_limit_bytes"], 1024 * 1024)
        self.assertEqual(record["stderr_limit_bytes"], 64 * 1024)
        self.assertEqual(record["stdout"], "bounded stdout\n")
        self.assertEqual(record["stderr"], "bounded stderr\n")
        self.assertLessEqual(record["stdout_bytes"], record["stdout_limit_bytes"])
        self.assertLessEqual(record["stderr_bytes"], record["stderr_limit_bytes"])
        self.assertEqual(record["exit_code"], 0)
        self.assert_child_exited(child)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--owned-fixture":
        _fixture(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    else:
        unittest.main()

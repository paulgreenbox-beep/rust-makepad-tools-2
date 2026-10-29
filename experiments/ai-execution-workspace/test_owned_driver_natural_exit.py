"""Real owned Windows processes; no GUI, WSL, shared service or foreign cleanup."""
import os
import ctypes
from ctypes import wintypes as w
import gc
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from owned_driver import OwnedDriver, OwnedDriverCancelled, OwnedDriverTimeout, _Job


@unittest.skipUnless(os.name == "nt", "native Windows Job observation")
class NaturalExitTests(unittest.TestCase):
    def setUp(self):
        self.driver = OwnedDriver()
        self.addCleanup(self.driver.close)

    def command(self, child_seconds=.4):
        child = "import time; time.sleep(" + repr(child_seconds) + ")"
        return [sys.executable, "-B", "-c",
                "import subprocess,sys,time; subprocess.Popen([sys.executable,'-B','-c',"
                + repr(child) + "]); time.sleep(.15)"]

    def test_delayed_child_is_observed_to_exit_before_any_containment(self):
        disposed = []
        original = _Job.dispose
        def track(job, reason):
            disposed.append(reason)
            return original(job, reason)
        with patch.object(_Job, "dispose", track):
            result = self.driver.run(self.command(), timeout=5, require_natural_exit=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(disposed, [])
        witness = result.natural_exit
        self.assertTrue(witness["natural_exit_verified"])
        self.assertTrue(witness["before_containment"])
        self.assertFalse(witness["termination_requested"])
        self.assertEqual(witness["active_processes"], 0)
        self.assertEqual(witness["root_exit_code"], 0)
        self.assertGreaterEqual(len(witness["members"]), 2)
        root = next(m for m in witness["members"] if m["role"] == "driver_root")
        child = next(m for m in witness["members"] if m["role"] == "owned_descendant")
        self.assertEqual(root["parent_pid"], os.getpid())
        self.assertEqual(child["parent_pid"], root["pid"])
        self.assertEqual(child["parent_creation_filetime"], root["creation_filetime"])
        for member in witness["members"]:
            self.assertGreater(member["creation_filetime"], 0)
            self.assertTrue(Path(member["image_path"]).is_absolute())
            self.assertTrue(member["signaled"])
            self.assertEqual(member["exit_code"], 0)
        self.assertTrue(self.driver.last_cleanup.natural_exit_verified)
        self.assertFalse(self.driver.last_cleanup.forced_termination)

    def test_remaining_child_times_out_and_keeps_precontainment_refusal(self):
        with self.assertRaises(OwnedDriverTimeout) as caught:
            self.driver.run(self.command(30), timeout=2, require_natural_exit=True)
        before = caught.exception.natural_exit
        self.assertEqual(before["root_exit_code"], 0)
        self.assertGreater(before["active_processes"], 0)
        self.assertFalse(before["natural_exit_verified"])
        self.assertTrue(any(not m["signaled"] for m in before["members"]))
        self.assertTrue(caught.exception.cleanup.forced_termination)
        self.assertTrue(caught.exception.cleanup.confirmed)
        self.assertFalse(caught.exception.cleanup.natural_exit_verified)
        self.assertEqual(caught.exception.cleanup.active_after, 0)

    def test_cancel_during_initial_identity_queries_does_not_resume(self):
        cancel = threading.Event()
        original = _Job.natural_snapshot
        def query(job):
            value = original(job)
            cancel.set()
            return value
        with patch.object(_Job, "natural_snapshot", query), patch.object(_Job, "resume") as resume:
            with self.assertRaises(OwnedDriverCancelled):
                self.driver.run(self.command(), timeout=5, cancel_event=cancel, require_natural_exit=True)
        resume.assert_not_called()
        self.assertEqual(self.driver.last_cleanup.active_after, 0)

    def test_deadline_during_initial_identity_queries_does_not_resume(self):
        original = _Job.natural_snapshot
        real_clock = time.monotonic
        offset, entered = [0], threading.Event()
        def query(job):
            value = original(job)
            entered.set()
            offset[0] = 10
            return value
        with patch.object(_Job, "natural_snapshot", query), patch.object(_Job, "resume") as resume, \
                patch("owned_driver.time.monotonic", lambda: real_clock() + offset[0]):
            with self.assertRaises(OwnedDriverTimeout):
                self.driver.run(self.command(), timeout=5, require_natural_exit=True)
        self.assertTrue(entered.is_set())
        resume.assert_not_called()
        self.assertEqual(self.driver.last_cleanup.active_after, 0)

    def test_concurrent_success_and_timeout_keep_distinct_outcome_witnesses(self):
        barrier, guard, first = threading.Barrier(2), threading.Lock(), set()
        outcomes = {}
        original = _Job.natural_snapshot
        def query(job):
            value = original(job)
            with guard:
                initial = job.pid not in first
                first.add(job.pid)
            if initial:
                barrier.wait(3)
            return value
        def call(label, seconds, timeout):
            try:
                outcomes[label] = self.driver.run(self.command(seconds), timeout=timeout,
                                                 require_natural_exit=True)
            except BaseException as exc:
                outcomes[label] = exc
        with patch.object(_Job, "natural_snapshot", query):
            a = threading.Thread(target=call, args=("A", .4, 5))
            b = threading.Thread(target=call, args=("B", 30, 2))
            a.start(); b.start()
            a.join(6); b.join(6)
        self.assertFalse(a.is_alive() or b.is_alive())
        self.assertIsInstance(outcomes["A"], subprocess.CompletedProcess)
        self.assertIsInstance(outcomes["B"], OwnedDriverTimeout)
        self.assertNotEqual(outcomes["A"].natural_exit["root_pid"], outcomes["B"].natural_exit["root_pid"])
        for label in ("A", "B"):
            item = outcomes[label]
            self.assertEqual(item.natural_exit["root_pid"], item.cleanup.root_pid)
        self.assertTrue(outcomes["A"].natural_exit["natural_exit_verified"])
        self.assertFalse(outcomes["B"].natural_exit["natural_exit_verified"])
        self.assertFalse(outcomes["A"].cleanup.forced_termination)
        self.assertTrue(outcomes["B"].cleanup.forced_termination)

    def test_cancellation_never_becomes_a_natural_exit(self):
        cancelled, errors = threading.Event(), []
        def call():
            try:
                self.driver.run(self.command(30), timeout=8, cancel_event=cancelled,
                                require_natural_exit=True)
            except BaseException as exc:
                errors.append(exc)
        thread = threading.Thread(target=call)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                observed = self.driver.last_natural_exit
                if observed and len(observed["members"]) >= 2:
                    break
                time.sleep(.01)
        finally:
            cancelled.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], OwnedDriverCancelled)
        self.assertFalse(self.driver.last_natural_exit["natural_exit_verified"])
        self.assertTrue(errors[0].cleanup.forced_termination)
        self.assertEqual(errors[0].cleanup.active_after, 0)

    def test_identity_query_failure_is_not_empty_job_proof(self):
        with patch.object(_Job, "_identity", side_effect=OSError("identity unavailable")):
            with self.assertRaisesRegex(OSError, "identity unavailable"):
                self.driver.run(self.command(), timeout=5, require_natural_exit=True)
        self.assertIsNone(self.driver.last_natural_exit)
        self.assertTrue(self.driver.last_cleanup.forced_termination)
        self.assertTrue(self.driver.last_cleanup.confirmed)

    def test_nonzero_root_exit_is_preserved_and_not_normalized(self):
        result = self.driver.run([sys.executable, "-B", "-c", "raise SystemExit(7)"],
                                 timeout=5, require_natural_exit=True)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.natural_exit["root_exit_code"], 7)
        self.assertTrue(result.natural_exit["natural_exit_verified"])
        self.assertFalse(result.cleanup.forced_termination)

    def test_natural_exit_cannot_be_combined_with_a_retained_start(self):
        with self.assertRaises(ValueError):
            self.driver.run(self.command(), timeout=5, require_natural_exit=True, retain_start=True)

    def test_parent_birth_matches_an_independently_held_process_handle(self):
        results = []
        def call():
            results.append(self.driver.run(self.command(.8), timeout=5, require_natural_exit=True))
        thread = threading.Thread(target=call)
        handle = None
        api = self.driver_api()
        thread.start()
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                witness = self.driver.last_natural_exit
                if witness and len(witness["members"]) >= 2:
                    root = next(m for m in witness["members"] if m["role"] == "driver_root")
                    handle = api.OpenProcess(0x1000, False, root["pid"])
                    if handle:
                        break
                time.sleep(.01)
            self.assertTrue(handle)
            creation, exited, kernel, user = (w.FILETIME() for _ in range(4))
            self.assertTrue(api.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exited),
                                               ctypes.byref(kernel), ctypes.byref(user)))
            birth = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        finally:
            if handle:
                api.CloseHandle(handle)
            thread.join(6)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 1)
        children = [m for m in results[0].natural_exit["members"] if m["parent_pid"] == root["pid"]]
        self.assertTrue(children)
        self.assertTrue(all(m["parent_creation_filetime"] == birth for m in children))

    @staticmethod
    def driver_api():
        from owned_driver import _kernel
        return _kernel()

    def test_repeated_natural_calls_do_not_leak_process_handles(self):
        api = self.driver_api()
        fn = api.GetProcessHandleCount
        fn.argtypes, fn.restype = [w.HANDLE, ctypes.POINTER(w.DWORD)], w.BOOL
        own = api.OpenProcess(0x1000, False, os.getpid())
        self.assertTrue(own)
        try:
            command = [sys.executable, "-B", "-c", "pass"]
            self.driver.run(command, timeout=5, require_natural_exit=True)
            gc.collect()
            before, after = w.DWORD(), w.DWORD()
            self.assertTrue(fn(own, ctypes.byref(before)))
            for _ in range(3):
                result = self.driver.run(command, timeout=5, require_natural_exit=True)
                self.assertEqual(result.cleanup.active_after, 0)
                self.assertTrue(result.natural_exit["natural_exit_verified"])
            gc.collect()
            self.assertTrue(fn(own, ctypes.byref(after)))
            self.assertEqual(after.value, before.value)
        finally:
            api.CloseHandle(own)

    def test_foreign_job_witness_refuses_in_the_real_completion_path(self):
        original = _Job.finish_naturally
        def foreign(job, witness, elapsed, budget):
            value = dict(witness, job_created_monotonic_ns=witness["job_created_monotonic_ns"] + 1)
            return original(job, value, elapsed, budget)
        with patch.object(_Job, "finish_naturally", foreign):
            with self.assertRaisesRegex(OSError, "natural Job0"):
                self.driver.run(self.command(), timeout=5, require_natural_exit=True)
        self.assertFalse(self.driver.last_cleanup.natural_exit_verified)

    def test_verified_member_image_is_not_requeried_while_process_exits(self):
        observations = []
        original = _Job._identity
        def identity(job, handle):
            value = original(job, handle)
            observations.append((value["pid"], value["creation_filetime"]))
            return value
        with patch.object(_Job, "_identity", identity):
            result = self.driver.run(self.command(), timeout=5, require_natural_exit=True)
        self.assertTrue(result.natural_exit["natural_exit_verified"])
        self.assertEqual(len(observations), len(set(observations)))


if __name__ == "__main__":
    unittest.main()

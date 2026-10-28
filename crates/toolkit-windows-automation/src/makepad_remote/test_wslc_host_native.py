"""Real Win32 tests of Owner.spawn only. No WSLC, GPU, GUI, input or app E2E.

Reuses the existing controlled owned_driver fixture and Job implementation.
Fresh --evidence-dir is mandatory; no old result or runtime is resumed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("native_wslc_host_under_test", Path(__file__).with_name("wslc_host.py"))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
EVIDENCE = None
FIXTURE = host.HELPERS / "test_owned_driver_contract.py"


@unittest.skipUnless(os.name == "nt", "Real Windows Job/handle proof, not a mock pass")
class NativeStartup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if EVIDENCE is None:
            raise RuntimeError("A fresh scoped evidence directory is required")
        host.host_path(EVIDENCE, host.EVIDENCE, exists=False).mkdir()

    def setUp(self):
        self.root = host.host_path(EVIDENCE / self._testMethodName, host.EVIDENCE, exists=False)
        self.root.mkdir()
        (self.root / "sessions").mkdir()
        self.out = self.root / "owner-output"; self.out.mkdir()
        unused_admission = self.root / "unused-admission.json"
        with unused_admission.open("xb") as stream:
            stream.write(b'{"scope":"NOT_A_WSLC_OR_GUI_ADMISSION"}')
        cfg = {"schema":"toolkit-makepad-remote-wslc-owner-v1", "source_commit":host.PIN,
            "owner":"native-startup-proof", "session_id":self._testMethodName, "generation":1,
            "runtime_directory":str(self.root), "output_directory":str(self.out),
            "admission_path":str(unused_admission), "key_focus_probe":False,
            "expected_identity":{"container_id":"a"*64,"image_id":"sha256:"+"b"*64,
                "executable":"/opt/proof/ai-workspace-fixture","executable_sha256":"c"*64}}
        self.owner = host.Owner(cfg)
        self.driver = self.owner.owned_driver()
        self.handles = []
        self.neighbour = None
        # Fail loudly if this narrowly scoped test ever reaches a guest command.
        self.owner.wslc = lambda *a, **kw: (_ for _ in ()).throw(AssertionError("WSLC forbidden in native startup test"))

    def tearDown(self):
        try:
            for child in self.owner.children.values():
                proof = child.retire("native-test-finally")
                self.assertTrue(proof["confirmed"], "native test must not leave an owned tree unconfirmed")
            for worker in self.owner.drainers:
                worker.join(2)
                self.assertFalse(worker.is_alive())
            for handle in self.handles:
                self.assertTrue(self.driver._kernel().CloseHandle(handle))
        finally:
            if self.neighbour is not None:
                self.neighbour.terminate()  # Only this test's directly created Popen handle.
                self.neighbour.wait(timeout=2)

    def argv(self, mode="hold"):
        return [sys.executable, "-B", str(FIXTURE), "--owned-fixture", str(self.root), "0", mode]

    def record(self, name, value):
        value.update(scope="WINDOWS_NATIVE_OWNER_STARTUP_ONLY_NOT_LINUX_GUI_E2E",
            source_sha256=hashlib.sha256(Path(host.__file__).read_bytes()).hexdigest(),
            owned_driver_sha256=hashlib.sha256((host.HELPERS/"owned_driver.py").read_bytes()).hexdigest(),
            fixture_sha256=hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
            wslc_invoked=False, physical_input_injected=False)
        with (self.root / name).open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)

    def injected(self, phase):
        job = self.driver._Job()
        real_thread = host.threading.Thread
        calls = 0
        def worker(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("controlled second-drainer failure")
            return real_thread(*args, **kwargs)
        target, name, effect = {
            "birth": (host, "native_birth", host.Fault("WSLC_NATIVE_BIRTH_UNAVAILABLE")),
            "persistence": (self.owner, "persist_binding", OSError("controlled write failure")),
            "drainer": (host.threading, "Thread", worker),
            "thread-start": (host.threading.Thread, "start", RuntimeError("controlled thread start failure")),
            "assignment": (job, "assign", OSError("controlled assignment failure")),
            "resume": (job, "resume", OSError("controlled resume failure")),
        }[phase]
        with patch.object(self.driver, "_Job", return_value=job), \
            patch.object(target, name, side_effect=effect):
            with self.assertRaises(host.Fault) as raised:
                self.owner.spawn("runtime", self.argv(), "app.stdout.txt", "app.stderr.txt")
        child = self.owner.children["runtime"]
        self.assertEqual(raised.exception.code, "WSLC_CHILD_STARTUP_FAILED")
        self.assertTrue(raised.exception.dispatched)
        self.assertTrue(child.retirement["confirmed"])
        self.assertEqual(child.retirement["active_after"], 0)
        self.assertIsNone(job.process); self.assertIsNone(job.thread); self.assertIsNone(job.handle)
        self.assertFalse((self.root/"ready-0").exists(), "fixture must not execute before setup is complete")
        self.assertIsNone(child.returncode, "Job cleanup cannot manufacture normal exit0")
        for thread in self.owner.drainers:
            thread.join(2); self.assertFalse(thread.is_alive())
        self.record("startup-failure.json", {"phase":phase,"result":"PASS", "failure_code":raised.exception.code,
            "native_job_cleanup":child.retirement, "fixture_executed":False, "normal_exit_claimed":False})

    def test_birth_failure_after_create_is_contained(self): self.injected("birth")
    def test_persistence_failure_before_resume_is_contained(self): self.injected("persistence")
    def test_second_drainer_failure_is_contained(self): self.injected("drainer")
    def test_drainer_start_failure_is_contained(self): self.injected("thread-start")
    def test_assignment_failure_cleans_exact_suspended_process(self): self.injected("assignment")
    def test_resume_failure_is_contained(self): self.injected("resume")

    def wait_ready(self):
        deadline = time.monotonic()+6
        while True:
            if all((self.root/("ready-"+str(depth))).exists() for depth in range(3)):
                return
            if time.monotonic() >= deadline: self.fail("controlled fixture readiness timed out")
            time.sleep(.01)

    def test_real_tree_retirement_preserves_same_image_neighbour(self):
        self.neighbour = subprocess.Popen([sys.executable,"-B","-c","import time;time.sleep(25)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
        child = self.owner.spawn("runtime", self.argv(), "app.stdout.txt", "app.stderr.txt")
        self.wait_ready()
        self.handles = child.job.process_handles()
        self.assertGreaterEqual(len(self.handles),3)
        proof = child.retire("native-fixture-tree-retire")
        self.assertTrue(proof["confirmed"]); self.assertEqual(proof["active_after"],0)
        self.assertGreaterEqual(proof["observed_processes"],3)
        self.assertEqual(proof["observed_signaled"],proof["observed_processes"])
        api = self.driver._kernel()
        self.assertTrue(all(api.WaitForSingleObject(handle,0) == 0 for handle in self.handles))
        self.assertIsNone(self.neighbour.poll())
        self.assertIsNone(child.returncode)
        self.record("tree-retirement.json", {"result":"PASS","native_job_cleanup":proof,
            "same_image_neighbour_preserved":True,"independent_signaled_handles":len(self.handles),"normal_exit_claimed":False})

    def test_root_exit0_does_not_hide_live_descendants(self):
        child = self.owner.spawn("runtime", self.argv("exit"), "app.stdout.txt", "app.stderr.txt")
        self.wait_ready()
        deadline = time.monotonic()+4
        while child.poll() is None:
            self.assertLess(time.monotonic(),deadline); time.sleep(.01)
        self.assertEqual(child.returncode,0); self.assertFalse(child.empty())
        with self.assertRaises(host.Fault) as refused:
            self.owner.reap()
        self.assertEqual(refused.exception.code,"WSLC_NORMAL_EXIT_RESOURCES_REMAIN")
        self.assertFalse((self.out/"native-app-exit.json").exists())
        proof = child.retire("native-residual-descendants")
        self.assertTrue(proof["confirmed"]); self.assertEqual(proof["active_after"],0)
        self.record("root-exit-with-descendants.json", {"result":"PASS","observed_root_exit_code":0,
            "reap_refusal":refused.exception.code,"native_job_cleanup":proof,"normal_exit_claimed":False})


if __name__ == "__main__":
    args = argparse.ArgumentParser(add_help=False)
    args.add_argument("--evidence-dir", required=True)
    options, remaining = args.parse_known_args()
    EVIDENCE = Path(host.normal_host_spelling(Path(options.evidence_dir).absolute()))
    unittest.main(argv=[sys.argv[0], *remaining])

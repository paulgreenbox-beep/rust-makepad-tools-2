"""Pure fixtures/parsers/mocks only. No WSLC, GUI, native calls or subprocesses.

Runtime/cleanup methods use mocked ports, never a container or native process.
Passing these tests is not Linux, GPU, focus, or lifecycle E2E acceptance.
"""
import datetime as dt
from functools import wraps
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, mock_open, patch

spec = importlib.util.spec_from_file_location("owning_wslc_host", Path(__file__).with_name("wslc_host.py"))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def encoded(value):
    return json.dumps(value, ensure_ascii=True).encode()


AUTHORIZATION_UTF8 = '''{
  "schema": "toolkit-scoped-operator-resource-authorization-v1",
  "milestone": "MAKEPAD_DEV_REMOTE_API_ADOPTION_V1",
  "operator_quote": "Игнорируй нехваток памяти",
  "authorization_source": "current human message in this Codex thread",
  "thread_id": "01a00532-be65-7723-89ec-c1b2bfdd373e",
  "scope": "RAM-only admission exception for continuing this milestone; not a global policy change",
  "permitted": ["serial bounded owning tests and CLI build", "serial bounded required runtime proof"],
  "retained_guards": ["no overlapping heavy workloads", "Cargo -j 1", "bounded timeout", "exact owned process identity", "evidence and cleanup", "no foreign process termination", "WSLC 1 GiB and 1 CPU limits"],
  "actual_memory_observation_required": true,
  "stock_admission_results_must_not_be_relabelled": true,
  "global_resource_policy_changed": false,
  "historical_blockage_superseded_by_new_authorization": "blocked-audit-28.json",
  "runtime_acceptance_claimed": false
}
'''


def admission_envelope(stock, grant=AUTHORIZATION_UTF8):
    raw = json.dumps(stock, ensure_ascii=False)
    return {"schema": host.SCOPED_ADMISSION_SCHEMA,
        "stock": {"path": "runtime-admission.json", "sha256": hashlib.sha256(raw.encode()).hexdigest(), "raw_utf8": raw},
        "authorization": {"path": host.RESOURCE_AUTHORIZATION_PATH,
            "sha256": hashlib.sha256(grant.encode()).hexdigest().upper(), "raw_utf8": grant}}


def cfg():
    return {"schema": "toolkit-makepad-remote-wslc-owner-v1", "source_commit": host.PIN,
        "owner": "unit-owner", "session_id": "unit-session", "generation": 1,
        "runtime_directory": "C:/unit/runtime", "output_directory": "C:/unit/output",
        "admission_path": "C:/unit/admission.json", "key_focus_probe": False,
        "expected_identity": {"container_id": "a" * 64, "image_id": "sha256:" + "b" * 64,
            "executable": "/opt/proof/ai-workspace-fixture", "executable_sha256": "c" * 64}}


def identity():
    return {"schema": "toolkit-makepad-remote-wslc-identity-v1", **cfg()["expected_identity"],
        "pid_namespace": "pid:[123]", "pid": 10, "process_start_ticks": "12",
        "listener_host": "127.0.0.1", "listener_port": 1234, "listener_inode": "34", "window_id": 0,
        "rail_hwnd": 55, "rail_pid": 66, "rail_process_birth": "77", "rail_visible": False,
        "memory_max": 1073741824, "cpu_max": "100000 100000"}


def response(body, status=200, extra=b""):
    return b"HTTP/1.1 " + str(status).encode() + b" OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n" + extra + b"\r\n" + body


class Parsers(unittest.TestCase):
    def test_exact_config_no_script_environment_or_waiver_ports(self):
        self.assertEqual(host.config(cfg()), cfg())
        for key in ("url", "shell", "environment", "helper_sha256", "runtime_ram_waiver_path"):
            value = cfg(); value[key] = "forbidden"
            with self.assertRaises(host.Fault): host.config(value)
        value = cfg(); value["generation"] = True
        with self.assertRaises(host.Fault): host.config(value)

    def test_nested_duplicate_nonfinite_invalid_utf8_and_surrogates(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'{"x":NaN}', b'"\xff"', b'"\\ud800"'):
            with self.assertRaises(host.Fault): host.strict_json(raw)

    def test_deep_json_and_cap_refuse(self):
        for raw in (b"[" * 1500 + b"]" * 1500, b" " * (host.INPUT_CAP + 1)):
            with self.assertRaises(host.Fault): host.strict_json(raw)
        self.assertIsInstance(host.strict_json(b"[" * 128 + b"]" * 128), list)
        with self.assertRaises(host.Fault): host.strict_json(b"[" * 129 + b"]" * 129)
        self.assertEqual(host.strict_json(encoded('\\"' + '[' * 1500)), '\\"' + '[' * 1500)

    def test_exact_eighteen_field_identity(self):
        self.assertEqual(len(identity()), 18)
        self.assertEqual(host.observed_identity(identity(), cfg()["expected_identity"]), identity())
        for key in identity():
            value = identity(); del value[key]
            with self.assertRaises(host.Fault): host.observed_identity(value, cfg()["expected_identity"])
        for key, invalid in (("pid", True), ("rail_visible", 0), ("window_id", False),
            ("listener_port", 65536), ("process_start_ticks", "01"), ("memory_max", True),
            ("cpu_max", "100000 100000\n"), ("pid_namespace", "mnt:[123]")):
            value = identity(); value[key] = invalid
            with self.assertRaises(host.Fault): host.observed_identity(value, cfg()["expected_identity"])

    def test_route_gate_no_injection_or_boolean_mutation_bypass(self):
        self.assertEqual(host.request_target("/click?w=0&x=1&y=2&if_user_seq=0", True)[0], "/click")
        for target in ("/admin", "/drop", "/w", "http://localhost/s", "/s\r\nX:a", "/s?w=%0a", "/s?w=%ff",
            "/snap?w=0&window=1", "/click?w=0", "/quit?if_user_seq=true", "/quit?if_user_seq=-1"):
            with self.assertRaises(host.Fault): host.request_target(target, target.split("?")[0] in host.MUTATIONS)
        with self.assertRaises(host.Fault): host.request_target("/quit?if_user_seq=0", False)

    def test_http_409_raw_duplicate_json_is_not_collapsed(self):
        raw = b'{"applied":true,"applied":false}'
        self.assertEqual(host.parse_http(response(raw, 409)), (409, raw.decode()))

    def test_http_complete_length_needs_no_eof(self):
        self.assertEqual(host.parse_http(response(b'{"ok":1}')), (200, '{"ok":1}'))
        self.assertIn('head -c "$length" <&3', host.HTTP_PROGRAM)
        self.assertNotIn("cat <&3", host.HTTP_PROGRAM)

    def test_http_truncation_ambiguity_and_surplus_refuse(self):
        cases = (response(b"abc")[:-1], response(b"abc") + b"x",
            response(b"abc", extra=b"Content-Length: 3\r\n"),
            response(b"abc", extra=b"Transfer-Encoding: identity\r\n"),
            b"HTTP/1.1 200 OK\r\n\r\n", response(b"\xff"))
        for raw in cases:
            with self.assertRaises(host.Fault): host.parse_http(raw)

    def test_guest_posix_path_not_host_path(self):
        self.assertTrue(host.guest_path("/tmp/makepad/app-1/grab.png"))
        for value in ("/", "//tmp/x", "/tmp/../x", "/tmp/x/", "C:/tmp/x", "/tmp/a\n", "/tmp/a\\b"):
            self.assertFalse(host.guest_path(value))

    def test_stock_admission_never_waiver_bool_or_stale(self):
        now = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)
        value = {"utc": now.isoformat(), "purpose": "runtime", "status": "ADMITTED",
            "active_rust_compilers": [], "free_physical_kib": 2097152, "required_free_kib": 2097152}
        host.fresh_admission(value, now)
        for key, invalid in (("waiver", True), ("free_physical_kib", 2097151), ("free_physical_kib", True),
            ("active_rust_compilers", False), ("status", "BLOCKED_ENVIRONMENT"),
            ("utc", (now - dt.timedelta(seconds=121)).isoformat())):
            changed = dict(value); changed[key] = invalid
            with self.assertRaises(host.Fault): host.fresh_admission(changed, now)

    def test_stock_runtime_two_gib_boundary_refuses_below_and_admits_exact(self):
        now = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)
        stock = {"utc": now.isoformat(), "purpose": "runtime", "status": "ADMITTED",
            "active_rust_compilers": [], "free_physical_kib": 2097152, "required_free_kib": 2097152}
        for free in (2097152, 2531528):
            admitted = {**stock, "free_physical_kib": free}
            with self.subTest(free=free):
                self.assertIs(host.fresh_admission(admitted, now), admitted)
        for status in ("ADMITTED", "BLOCKED_ENVIRONMENT"):
            with self.subTest(free=2097151, status=status):
                with self.assertRaises(host.Fault) as refused:
                    host.fresh_admission({**stock, "free_physical_kib": 2097151, "status": status}, now)
                self.assertEqual(refused.exception.code, "WSLC_STOCK_ADMISSION_REQUIRED")
        with self.assertRaises(host.Fault):
            host.fresh_admission({**stock, "status": "BLOCKED_ENVIRONMENT"}, now)

    def test_scoped_ram_envelope_is_pinned_and_preserves_actual_stock(self):
        now = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)
        stock = {"utc": now.isoformat(), "purpose": "runtime", "status": "BLOCKED_ENVIRONMENT",
            "active_rust_compilers": [], "free_physical_kib": 1531528, "required_free_kib": 2097152}
        value = admission_envelope(stock); before = encoded(value)
        self.assertEqual(value["authorization"]["sha256"], host.RESOURCE_AUTHORIZATION_SHA256)
        result = host.fresh_admission(value, now, owner=host.RESOURCE_AUTHORIZATION_OWNER)
        self.assertEqual(result["status"], "AUTHORIZED_SCOPED_RAM_EXCEPTION")
        self.assertEqual(result["stock_status"], "BLOCKED_ENVIRONMENT")
        self.assertEqual(result["free_physical_kib"], 1531528)
        self.assertEqual(encoded(value), before)
        self.assertEqual(host.strict_json(value["stock"]["raw_utf8"].encode()), stock)
        stock.update(status="ADMITTED", free_physical_kib=2097152)
        self.assertEqual(host.fresh_admission(admission_envelope(stock), now,
            owner=host.RESOURCE_AUTHORIZATION_OWNER)["status"], "STOCK_ADMITTED")

    def test_scoped_ram_requires_exact_owner_and_cannot_be_a_raw_permission_flag(self):
        now = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)
        stock = {"utc": now.isoformat(), "purpose": "runtime", "status": "BLOCKED_ENVIRONMENT",
            "active_rust_compilers": [], "free_physical_kib": 1, "required_free_kib": 2097152}
        for owner in (None, "unit-owner", True, host.RESOURCE_AUTHORIZATION_OWNER + " "):
            with self.assertRaises(host.Fault): host.fresh_admission(admission_envelope(stock), now, owner=owner)
        for extra in ({}, {"authorization": True}, {"waiver": True}, {"ResourceAuthorization": "remote_api_adoption_v1"}):
            with self.assertRaises(host.Fault):
                host.fresh_admission({**stock, **extra}, now, owner=host.RESOURCE_AUTHORIZATION_OWNER)

    def test_scoped_ram_closed_schema_paths_hashes_and_raw_grant_drift_refuse(self):
        now = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)
        stock = {"utc": now.isoformat(), "purpose": "runtime", "status": "BLOCKED_ENVIRONMENT",
            "active_rust_compilers": [], "free_physical_kib": 1, "required_free_kib": 2097152}
        variants = []
        for key in ("schema", "stock", "authorization"):
            value = admission_envelope(stock); del value[key]; variants.append(value)
        value = admission_envelope(stock); value["extra"] = True; variants.append(value)
        for section in ("stock", "authorization"):
            for key, invalid in (("path", "../foreign.json"), ("sha256", "0" * 64), ("raw_utf8", None)):
                value = admission_envelope(stock); value[section][key] = invalid; variants.append(value)
            value = admission_envelope(stock); value[section]["extra"] = 0; variants.append(value)
            value = admission_envelope(stock); del value[section]["sha256"]; variants.append(value)
            value = admission_envelope(stock); value[section]["raw_utf8"] += "\n"; variants.append(value)
        for raw in (AUTHORIZATION_UTF8 + "\n", AUTHORIZATION_UTF8.replace("this Codex thread", "foreign thread"),
            "{}", "{" * 20000):
            variants.append(admission_envelope(stock, raw))
        for value in variants:
            with self.subTest(value=value):
                with self.assertRaises(host.Fault): host.fresh_admission(value, now, owner=host.RESOURCE_AUTHORIZATION_OWNER)

    def test_scoped_ram_rejects_compilers_status_spoof_and_malformed_stock(self):
        now = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)
        stock = {"utc": now.isoformat(), "purpose": "runtime", "status": "BLOCKED_ENVIRONMENT",
            "active_rust_compilers": [], "free_physical_kib": 1, "required_free_kib": 2097152}
        changes = (("purpose", "warm-build"), ("status", "ADMITTED"), ("status", "UNKNOWN"),
            ("active_rust_compilers", [1]), ("active_rust_compilers", False),
            ("required_free_kib", 2097153), ("required_free_kib", 3145728), ("required_free_kib", True),
            ("free_physical_kib", 2097152), ("free_physical_kib", True), ("free_physical_kib", -1),
            ("free_physical_kib", "1"), ("free_physical_kib", 1.0), ("free_physical_kib", 1 << 64),
            ("utc", None), ("utc", 0), ("utc", "not-utc"), ("waiver", False))
        for key, invalid in changes:
            with self.subTest(key=key, invalid=invalid):
                with self.assertRaises(host.Fault):
                    host.fresh_admission(admission_envelope({**stock, key: invalid}), now,
                        owner=host.RESOURCE_AUTHORIZATION_OWNER)

    def test_scoped_ram_uses_original_timestamp_at_every_freshness_check(self):
        at = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)
        stock = {"utc": at.isoformat(), "purpose": "runtime", "status": "BLOCKED_ENVIRONMENT",
            "active_rust_compilers": [], "free_physical_kib": 1, "required_free_kib": 2097152}
        value = admission_envelope(stock)
        for age in (0, 30, 120):
            self.assertEqual(host.fresh_admission(value, at + dt.timedelta(seconds=age),
                owner=host.RESOURCE_AUTHORIZATION_OWNER)["utc"], stock["utc"])
        for age in (-.001, 120.001):
            with self.assertRaises(host.Fault): host.fresh_admission(value, at + dt.timedelta(seconds=age),
                owner=host.RESOURCE_AUTHORIZATION_OWNER)

    def test_scoped_ram_strict_raw_json_and_envelope_caps(self):
        now = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)
        stock = {"utc": now.isoformat(), "purpose": "runtime", "status": "BLOCKED_ENVIRONMENT",
            "active_rust_compilers": [], "free_physical_kib": 1, "required_free_kib": 2097152}
        for raw in ('{"utc":0,"utc":1}', '{"x":NaN}', '[0]', '{', '"\\ud800"'):
            value = admission_envelope(stock)
            value["stock"].update(raw_utf8=raw, sha256=hashlib.sha256(raw.encode()).hexdigest())
            with self.assertRaises(host.Fault): host.fresh_admission(value, now, owner=host.RESOURCE_AUTHORIZATION_OWNER)
        value = admission_envelope(stock); value["stock"]["raw_utf8"] = "\ud800"
        with self.assertRaises(host.Fault): host.fresh_admission(value, now, owner=host.RESOURCE_AUTHORIZATION_OWNER)
        for count in (host.INPUT_CAP, host.INPUT_CAP + 1):
            value = admission_envelope({**stock, "padding": "x" * count})
            with self.assertRaises(host.Fault): host.fresh_admission(value, now, owner=host.RESOURCE_AUTHORIZATION_OWNER)

    def test_focus_only_closed_marker_latest_no_text_reflection(self):
        item = {"schema": "toolkit-remote-focus-probe-v1", "pid": 5, "sample_seq": 1,
            "window_id": "main_window", "window_index": 0, "widget_id": "input_singleline", "focused": False, "widget_uid": 18}
        prefix = b"[toolkit-remote-focus-v1] "
        self.assertIsNone(host.focus_sample(b"ordinary runtime log\n"))
        self.assertEqual(host.focus_sample(prefix + encoded(item) + b"\n"), item)
        for key, invalid in (("focused", 1), ("sample_seq", True), ("pid", 0), ("extra", "secret")):
            changed = dict(item); changed[key] = invalid
            with self.assertRaises(host.Fault): host.focus_sample(prefix + encoded(changed))
        with self.assertRaises(host.Fault): host.focus_sample(prefix + b'{"schema":1,"schema":2}')

    def test_packet_rejects_duplicate_correlation_and_unknown_arguments(self):
        item = {"version": 1, "sequence": 1, "operation": "validate", "arguments": {}}
        self.assertEqual(host.packet(encoded(item), 0), item)
        for value in (True, 0, -1, 2, 1 << 64):
            changed = dict(item); changed["sequence"] = value
            with self.assertRaises(host.Fault): host.packet(encoded(changed), 0)
        with self.assertRaises(host.Fault): host.packet(encoded(item), 1)
        item["arguments"] = {"command": "forbidden"}
        with self.assertRaises(host.Fault): host.packet(encoded(item), 0)


class FakeOwner:
    def __init__(self): self.dispatched = False; self.finalized = 0; self.calls = []
    def call(self, op, args): self.calls.append((op, args)); return {"fixture": True}
    def finalize(self): self.finalized += 1


class FakeProcess:
    def __init__(self, output=b"", error=b""):
        self.stdout, self.stderr, self.stdin = io.BytesIO(output), io.BytesIO(error), io.BytesIO()
        self.returncode = 0; self.killed = 0; self.retired = 0; self.active_count = 0
    def poll(self): return self.returncode
    def kill(self): self.killed += 1; self.returncode = -1
    def wait(self, timeout=None): return self.returncode
    def active_processes(self): return self.active_count
    def empty(self): return self.active_processes() == 0
    def retire(self, reason):
        self.retired += 1
        return {"confirmed": True, "active_after": 0, "reason": reason}


class JoinClock:
    """Only synthetic elapsed time; condition polling must never wait in real time."""
    def __init__(self): self.now = 1000.0; self.sleeps = []
    def monotonic(self): return self.now
    def sleep(self, seconds):
        if not 0 < seconds <= .025: raise AssertionError("unexpected join wait")
        self.sleeps.append(seconds); self.now += seconds
    def advance(self, seconds): self.now += seconds


def synthetic_join(test):
    @wraps(test)
    def wrapped(*args, **kwargs):
        clock = JoinClock()
        with patch.object(host.time, "monotonic", clock.monotonic), patch.object(host.time, "sleep", clock.sleep):
            return test(*args, **kwargs)
    return wrapped


def creator_fixture():
    now = dt.datetime(2026, 10, 22, 12, 0, 0, tzinfo=dt.timezone.utc)
    expected, owner, nonce = cfg()["expected_identity"], cfg()["owner"], "d" * 32
    ctx = {"container_id": expected["container_id"], "image": expected["image_id"],
        "container_name": "aiui-workspace-20261008", "owns_container": True, "owns_vm": False,
        "resumable": False, "source_revision": host.PIN, "exclusive_owner": owner,
        "exclusive_nonce": nonce, "gpu_profile": "gpu_nvidia_test",
        "container_created": "2026-10-22T11:59:59.123132068Z", "container_started_at": "2026-10-22T11:59:59.604537904Z"}
    receipt = {"args": ["run", "--detach", "--rm", "--name", "aiui-workspace-20261008", "--memory", "1G",
        "--cpus", "1", "--gpus", "all", "--label", "aiui.toolkit.owner=" + owner,
        "--label", "aiui.toolkit.nonce=" + nonce, expected["image_id"], "sleep", "1800"],
        "executable": host.WSLC, "exit_code": 0, "timed_out": False, "output_drained": True,
        "stdout": expected["container_id"] + "\r\n", "duration_ms": 590, "started_utc": "2026-10-22T11:59:59.0285455Z"}
    actual = {"Id": expected["container_id"], "Image": expected["image_id"], "Name": "/aiui-workspace-20261008",
        "Created": ctx["container_created"], "State": {"Running": True, "StartedAt": ctx["container_started_at"]},
        "HostConfig": {"Memory": 1073741824, "NanoCpus": 1000000000, "NetworkMode": "bridge"},
        "Config": {"Cmd": ["sleep", "1800"], "Entrypoint": None,
            "Labels": {"aiui.toolkit.owner": owner, "aiui.toolkit.nonce": nonce}}, "Mounts": [], "Ports": {}}
    return ctx, receipt, actual, expected, owner, now


def bare_owner():
    """No Owner.__init__: tests cannot accidentally cross filesystem/native ports."""
    obj = host.Owner.__new__(host.Owner)
    obj.cfg = cfg(); obj.tag = "toolkit-unit-tag"; obj.children = {}; obj.bindings = {}
    obj.guest_owners = {}; obj.dispatched = False; obj.adopted = True; obj.cleaned = False
    obj.identity = identity(); obj.pid = 10; obj.port = 1234; obj.rail = None
    obj.runtime = Path("MOCK_RUNTIME"); obj.output = Path("MOCK_OUTPUT"); obj.freeze = {}
    obj.evidence_index = 0; obj.cleanup_attempts = 0; obj.cleanup_result = None
    obj.incarnation={'created':'synthetic-created','started_at':'synthetic-started','nonce':'c'*32}
    obj.normal_exit_result = None; obj.reap_observations = 0; obj.last_grab = None; obj.seen_grabs = set()
    obj.stream_failure = threading.Event(); obj.drainers = []; obj.cleaning = False
    obj.deadline = time.monotonic() + host.LIFETIME
    obj.launch_nonces = {"app": "e" * 32, "relay": "f" * 32}
    obj.running_witness_saved = False; obj.kernel_latest = None
    obj.frozen = Mock(); obj.save = Mock(); obj.persist_binding = Mock()
    # Preserve this suite's pure-port boundary. Actual filesystem disposition
    # and junction/hardlink checks live in test_storage_policy.py.
    storage=SimpleNamespace(active_session_leases=Mock(return_value=0),
        cleanup_staging=Mock(return_value={"status":"NO_DISPOSABLE_STAGING","deleted_bytes":0}),
        ensure_host_reserve=Mock(return_value={'host_free_bytes':20_000_000_000}))
    obj.storage_policy=Mock(return_value=storage)
    return obj


class CreatorOwnership(unittest.TestCase):
    def test_claim_is_create_new_and_never_overwrites_existing_owner(self):
        path = Mock(); opened = mock_open(); path.open = opened
        host.write_claim(path, {"session_id": "A"})
        opened.assert_called_once_with("xb")
        opened().write.assert_called_once_with(host.encode_reply({"session_id": "A"}))
        path.open = Mock(side_effect=FileExistsError())
        with self.assertRaises(host.Fault) as refused: host.write_claim(path, {"session_id": "B"})
        self.assertEqual(refused.exception.code, "WSLC_CONTAINER_ALREADY_CLAIMED")
        path.open.assert_called_once_with("xb")

    def test_creator_exact_join_and_native_nanosecond_timestamps(self):
        args = creator_fixture()
        joined = host.exclusive_context(*args)
        self.assertEqual(joined["created"], args[2]["Created"])
        self.assertEqual(joined["started_at"], args[2]["State"]["StartedAt"])
        self.assertEqual(joined["nonce"], "d" * 32)

    def test_creator_never_authority_from_context_alone(self):
        for key, value in (("exclusive_nonce", ""), ("exclusive_owner", "another"), ("owns_vm", True),
            ("owns_container", 1), ("resumable", True), ("source_revision", "old"),
            ("container_created", "2026-10-22T11:59:59Z")):
            args = list(creator_fixture()); args[0][key] = value
            with self.subTest(key=key), self.assertRaises(host.Fault): host.exclusive_context(*args)

    def test_creator_receipt_command_output_or_failed_creation_refused(self):
        for key, value in (("exit_code", True), ("exit_code", 1), ("timed_out", True), ("output_drained", False),
            ("stdout", "e" * 64), ("executable", "OTHER.exe"), ("args", ["run", "foreign"]), ("duration_ms", True)):
            args = list(creator_fixture()); args[1][key] = value
            with self.subTest(key=key), self.assertRaises(host.Fault): host.exclusive_context(*args)

    def test_creator_labels_image_mounts_and_limits_are_independent(self):
        for change in (lambda a: a.update(Id="e" * 64), lambda a: a.update(Image="sha256:" + "e" * 64),
            lambda a: a["Config"]["Labels"].update({"aiui.toolkit.owner": "foreign"}),
            lambda a: a.update(Labels={}), lambda a: a.update(Mounts=[{"Source": "host"}]),
            lambda a: a.update(Ports={"22/tcp": []}), lambda a: a["HostConfig"].update(Memory=True),
            lambda a: a["HostConfig"].update(NetworkMode="host"), lambda a: a["HostConfig"].update(Privileged=True),
            lambda a: a["Config"].update(Cmd=["sleep", "600"])):
            args = list(creator_fixture()); change(args[2])
            with self.assertRaises(host.Fault): host.exclusive_context(*args)

    def test_creator_cannot_be_replaced_by_recent_context_timestamp(self):
        args = list(creator_fixture()); args[5] += dt.timedelta(seconds=1000)
        args[0]["created_utc"] = args[5].isoformat()
        with self.assertRaises(host.Fault): host.exclusive_context(*args)
        host.exclusive_context(*args, fresh=False)  # Lifetime validation is not a second adoption.

    def test_restarted_incarnation_does_not_join_even_for_cleanup(self):
        args = list(creator_fixture()); args[2]["State"]["StartedAt"] = "2026-10-22T12:00:00Z"
        with self.assertRaises(host.Fault): host.exclusive_context(*args, fresh=False, allow_stopped=True)

    def test_stopped_incarnation_is_cleanup_only_not_live_validation(self):
        args = list(creator_fixture()); args[2]["State"]["Running"] = False
        with self.assertRaises(host.Fault): host.exclusive_context(*args)
        host.exclusive_context(*args, fresh=False, allow_stopped=True)

    def test_reachable_inventory_required_for_absence(self):
        # Actual native-filtered-empty-37-01: success/drained, both pipes exactly empty.
        self.assertIs(host.filtered_container_present(b""), False)
        # The installed nonempty row schema is not yet observed. No row grants identity.
        for raw in (b'{}', b'{}\r\n', b'{"unknown_row_schema":true}\n{}\n', b'{"error":"unknown"}'):
            self.assertIs(host.filtered_container_present(raw), True)

    def test_filtered_inventory_refuses_human_tables_and_ambiguous_json(self):
        ru_header = "ИД КОНТЕЙНЕРА   ОБРАЗ     КОМАНДА   СОЗДАНО   СТАТУС    ПОРТЫ     ИМЕНА\r\n".encode("utf-8")
        for raw in (ru_header, b"CONTAINER ID  IMAGE  COMMAND  CREATED  STATUS  PORTS  NAMES\r\n",
            b" ", b"\r\n", b"connection failed\n", b"\xef\xbb\xbf{}", b"banner\n{}", b"{} {}",
            b"[]", b"[{}]", b"[", b'{"id":', b'{"id":1,"id":2}', b'{"nested":{"a":1,"a":2}}',
            b'{"x":"\xff"}', b'{"x":"\\ud800"}', b'{"x":NaN}', b'{}\n{"truncated":', b'{}\n\n',
            b"null", b"true", b"0", b'"[]"', b" " * (host.INPUT_CAP + 1)):
            with self.subTest(raw=raw[:100]):
                with self.assertRaises(host.Fault) as refused: host.filtered_container_present(raw)
                self.assertEqual(refused.exception.code, "WSLC_ABSENCE_INVENTORY_INVALID")

    def test_process_stat_uses_starttime_after_last_comm_parenthesis(self):
        raw = b"10 (odd name ) with spaces) S " + b"0 " * 18 + b"1234 0\n"
        self.assertEqual(host.process_stat(raw), (10, "1234", "S"))
        for raw in (b"10 odd", b"10 (x) Z 0", b"0 (x) S " + b"0 " * 20):
            with self.assertRaises(host.Fault): host.process_stat(raw)


class LifecyclePorts(unittest.TestCase):
    def test_container_present_uses_fixed_json_full_cid_filter(self):
        cid = "0123456789abcdef" * 4
        for raw, expected in ((b"", False), (b'{"unknown_row_schema":true}\n', True)):
            with self.subTest(raw=raw):
                obj = bare_owner(); obj.cfg["expected_identity"]["container_id"] = cid
                obj.wslc = Mock(return_value=(0, raw, b"")); obj.inspect_owned = Mock()
                self.assertIs(obj.container_present(), expected)
                obj.wslc.assert_called_once_with("ps", "-a", "--format", "json", "--no-trunc",
                    "--filter", "id=" + cid)
                obj.inspect_owned.assert_not_called()

    def test_container_present_never_converts_command_or_json_failure_to_absence(self):
        obj = bare_owner(); failure = host.Fault("WSLC_COMMAND_FAILED")
        obj.wslc = Mock(side_effect=failure)
        with self.assertRaises(host.Fault) as refused: obj.container_present()
        self.assertIs(refused.exception, failure)
        obj.wslc.assert_called_once()
        for out, err in ((b"", b"unknown error"), (b" ", b""), (b"[]", b""), (b'{}\nbanner', b"")):
            with self.subTest(out=out, err=err):
                obj.wslc = Mock(return_value=(0, out, err))
                with self.assertRaises(host.Fault) as refused: obj.container_present()
                self.assertEqual(refused.exception.code, "WSLC_ABSENCE_INVENTORY_INVALID")
                obj.wslc.assert_called_once()

    def test_call_deadline_does_not_reset_per_command(self):
        obj = bare_owner(); obj.deadline = time.monotonic() - 1
        with patch.object(host, "run_bounded") as run:
            with self.assertRaises(host.Fault): obj.wslc("ps", "-a")
        run.assert_not_called()

    def test_live_log_failure_refuses_even_before_native_dispatch(self):
        obj = bare_owner(); obj.stream_failure.set()
        with patch.object(host, "run_bounded") as run:
            with self.assertRaises(host.Fault): obj.wslc("ps", "-a")
        run.assert_not_called()

    def test_log_stream_caps_on_write_not_later_read(self):
        obj = bare_owner()
        class Sink(io.BytesIO):
            def close(self): self.retained = self.getvalue(); super().close()
        output = Sink()
        obj.drain_log(io.BytesIO(b"a" * 1000), output, 64)
        self.assertEqual(output.retained, b"a" * 64); self.assertTrue(obj.stream_failure.is_set())

    def test_owned_rail_observation_failure_is_not_absence(self):
        obj = bare_owner(); obj.rail = {"hwnd": 55, "pid": 66, "birth": "77"}
        rows = [{"hwnd": 55, "pid": 66, "title": obj.tag, "birth": None, "observation_error": "WSLC_NATIVE_BIRTH_UNAVAILABLE"}]
        with patch.object(host, "rail_windows", return_value=rows):
            with self.assertRaises(host.Fault): obj.rail_absent()
        rows[0].update(hwnd=99, title="foreign")
        with patch.object(host, "rail_windows", return_value=rows): self.assertTrue(obj.rail_absent())

    def test_proc_read_error_is_not_process_absence(self):
        for code, rows in ((1, {10: (0, "app")}), (125, {})):
            obj = bare_owner(); obj.guest = Mock(return_value=(code, b"", b""))
            obj.process_inventory = Mock(return_value=rows)
            with self.assertRaises(host.Fault): obj.proc(10)

    def test_proc_absence_requires_reachable_independent_inventory(self):
        obj = bare_owner(); obj.guest = Mock(return_value=(1, b"", b""))
        obj.process_inventory = Mock(return_value={1: (0, "sleep")})
        self.assertIsNone(obj.proc(10)); obj.process_inventory.assert_called_once()
        obj.process_inventory.side_effect = host.Fault("WSLC_COMMAND_FAILED")
        with self.assertRaises(host.Fault): obj.proc(10)

    def process_fixture(self, owner, commands):
        rows = {pid: (0, "sleep" if pid == 1 else "process") for pid in commands}
        for pid, argv in commands.items():
            for kind, expected in owner.expected_commands().items():
                if argv == expected[0]:
                    parent = next((candidate for candidate, args in commands.items() if args == expected[1]), 0)
                    rows[pid] = (parent, "process")
        owner.process_inventory = Mock(return_value=rows)
        owner.proc = Mock(side_effect=lambda pid: {"birth": str(pid + 100), "state": "S"})
        owner.argv = Mock(side_effect=commands.__getitem__)
        def environment(*args, **kwargs):
            pid = int(args[1].split("/")[2])
            kind = next((k for k, variants in owner.expected_commands().items() if commands[pid] in variants), "app")
            return 0, b"AIUI_REMOTE_LAUNCH_NONCE=" + owner.launch_nonces[kind].encode() + b"\0", b""
        owner.guest = Mock(side_effect=environment)

    def test_initial_ownership_never_adopts_preexisting_relay(self):
        obj = bare_owner()
        self.process_fixture(obj, {1: ["sleep", "1800"], 5: obj.expected_commands()["relay"][0]})
        with self.assertRaises(host.Fault): obj.check_processes()

    def test_partial_start_cleanup_binds_only_spawned_exact_command(self):
        obj = bare_owner(); obj.children["relay"] = FakeProcess()
        self.process_fixture(obj, {1: ["sleep", "1800"], 5: obj.expected_commands()["relay"][1],
            6: obj.expected_commands()["relay"][0]})
        obj.check_processes(cleanup=True)
        self.assertEqual(obj.guest_owners[6]["kind"], "relay")
        self.assertEqual(obj.guest_owners[6]["birth"], "106")

    def test_discovery_requires_actual_native_spawn_intent(self):
        obj = bare_owner(); obj.process_inventory = Mock()
        with self.assertRaises(host.Fault): obj.check_processes(discover="app")
        obj.process_inventory.assert_not_called()

    def test_same_argv_without_launch_nonce_is_not_owned(self):
        obj = bare_owner(); obj.children["relay"] = FakeProcess()
        self.process_fixture(obj, {1: ["sleep", "1800"], 5: obj.expected_commands()["relay"][1],
            6: obj.expected_commands()["relay"][0]})
        obj.guest.return_value = (0, b"AIUI_REMOTE_LAUNCH_NONCE=foreign\0", b""); obj.guest.side_effect = None
        with self.assertRaises(host.Fault): obj.check_processes(cleanup=True)
        self.assertEqual(obj.guest_owners, {})

    def test_launch_nonce_alone_without_parent_timeout_cannot_be_published(self):
        obj = bare_owner(); obj.children["relay"] = FakeProcess()
        self.process_fixture(obj, {1: ["sleep", "1800"], 6: obj.expected_commands()["relay"][0]})
        with self.assertRaises(host.Fault): obj.check_processes(cleanup=True)
        self.assertEqual(obj.guest_owners, {})

    def test_partial_start_cannot_claim_foreign_or_duplicate_process(self):
        for commands in ({1: ["sleep", "1800"], 5: ["foreign-job"]},
            {1: ["sleep", "1800"], **{pid: bare_owner().expected_commands()["relay"][0] for pid in (5, 6, 7)}}):
            obj = bare_owner(); obj.children["relay"] = FakeProcess()
            self.process_fixture(obj, commands)
            with self.assertRaises(host.Fault): obj.check_processes(cleanup=True)

    def test_bound_pid_reuse_and_argv_drift_refused(self):
        for changed in ({"birth": "wrong", "argv": ["sleep", "1800"], "kind": "init"},
            {"birth": "101", "argv": ["another"], "kind": "init"}):
            obj = bare_owner(); obj.guest_owners[1] = changed
            self.process_fixture(obj, {1: ["sleep", "1800"]})
            with self.assertRaises(host.Fault): obj.check_processes()

    def test_cleanup_terminal_known_birth_does_not_adopt_unknown_or_live_empty_argv(self):
        for case in ('already_zombie','became_zombie','gone','reused','still_live','not_cleanup','unknown'):
            obj=bare_owner();commands={1:["sleep","1800"],5:obj.expected_commands()["relay"][0]}
            self.process_fixture(obj,commands)
            obj.guest_owners={1:{"birth":"101","argv":commands[1],"kind":"init"},
                5:{"birth":"105","argv":commands[5],"kind":"relay"}}
            if case=='unknown':del obj.guest_owners[5]
            samples=iter([{"birth":"105","state":"Z"}] if case=='already_zombie' else [
                {"birth":"105","state":"S"},None if case=='gone' else
                {"birth":"999" if case=='reused' else "105","state":"S" if case=='still_live' else "Z"}])
            obj.proc=Mock(side_effect=lambda pid:next(samples) if pid==5 else {"birth":"101","state":"S"})
            obj.argv=Mock(side_effect=lambda pid:(_ for _ in ()).throw(host.Fault("WSLC_PROCESS_ARGV_INVALID")) if pid==5 else commands[pid])
            with self.subTest(case=case):
                if case in ('already_zombie','became_zombie','gone'):obj.check_processes(cleanup=True)
                else:
                    with self.assertRaises(host.Fault):obj.check_processes(cleanup=case!='not_cleanup')
            if case=='unknown':self.assertNotIn(5,obj.guest_owners)

    def test_http_preserves_actual_409_body_without_retry(self):
        obj = bare_owner(); obj.inspect_owned = Mock(); obj.validate = Mock(return_value=identity())
        body = b'{"applied":true,"applied":false}'
        obj.guest = Mock(return_value=(0, response(body, 409), b""))
        self.assertEqual(obj.http("/quit?if_user_seq=0", True), (409, body.decode()))
        self.assertTrue(obj.dispatched); self.assertEqual(obj.guest.call_count, 1)

    def test_http_uncertainty_latched_before_mutating_write(self):
        for mutating, target in ((True, "/quit?if_user_seq=0"), (False, "/s")):
            obj = bare_owner(); obj.inspect_owned = Mock(); obj.validate = Mock(return_value=identity())
            def lost(*a, **kw):
                self.assertEqual(obj.dispatched, mutating)
                raise host.Fault("WSLC_PROCESS_TIMEOUT")
            obj.guest = Mock(side_effect=lost)
            with self.assertRaises(host.Fault) as raised: obj.http(target, mutating)
            self.assertEqual(raised.exception.dispatched, mutating); self.assertEqual(obj.guest.call_count, 1)

    def test_invalid_request_never_dispatches(self):
        obj = bare_owner(); obj.guest = Mock(); obj.inspect_owned = Mock()
        with self.assertRaises(host.Fault): obj.http("/quit", True)
        self.assertFalse(obj.dispatched); obj.guest.assert_not_called(); obj.inspect_owned.assert_not_called()

    @synthetic_join
    def test_normal_reap_independent_exit_zero_and_repeated_absence(self):
        obj = bare_owner(); obj.children["runtime"] = FakeProcess()
        obj.proc = Mock(return_value=None); obj.listener = Mock(return_value=[]); obj.rail_absent = Mock(return_value=True)
        proof = obj.reap(); self.assertTrue(proof["normal_exit_observed"])
        self.assertEqual(obj.reap(), proof)
        self.assertEqual([call.args[0] for call in obj.save.call_args_list],
            ["reap-observation-0001.json", "native-app-exit.json", "reap-observation-0002.json"])
        self.assertEqual(obj.children["runtime"].killed, 0)

    @synthetic_join
    def test_reap_nonzero_or_residual_resources_never_normal_exit(self):
        for condition in ("nonzero", "pid", "listener", "rail"):
            obj = bare_owner(); child = FakeProcess(); obj.children["runtime"] = child
            if condition == "nonzero": child.returncode = -9
            obj.proc = Mock(return_value={} if condition == "pid" else None)
            obj.listener = Mock(return_value=["5"] if condition == "listener" else [])
            obj.rail_absent = Mock(return_value=condition != "rail")
            with self.subTest(condition=condition), self.assertRaises(host.Fault): obj.reap()
            self.assertEqual(obj.save.call_args.args[0], "reap-observation-0001.json")
            self.assertFalse(obj.save.call_args.args[1]["all_conditions_proven"])
            self.assertIsNone(obj.normal_exit_result); self.assertEqual(child.killed, 0)

    def test_capture_metadata_must_match_last_observed_grab(self):
        obj = bare_owner(); obj.guest = Mock()
        with self.assertRaises(host.Fault): obj.copy_frame({"png": "/tmp/x.png"}, 1)
        obj.guest.assert_not_called()

    def test_capture_nonregular_or_hardlinked_leaf_is_rejected_before_cat(self):
        for kind, links in (("fifo", "1"), ("regular file", "2")):
            obj = bare_owner(); obj.grabs = "/tmp/grabs"; meta = {"png": "/tmp/grabs/a.png", "w": 0}
            obj.last_grab = (1, meta); obj.guest = Mock()
            obj.text = Mock(side_effect=[meta["png"], "5|2026-10-22 00:00:00|123|" + kind + "|" + links])
            with self.assertRaises(host.Fault): obj.copy_frame(meta, 1)
            obj.guest.assert_not_called()

    def cleanup_fixture(self):
        obj = bare_owner(); obj.children["runtime"] = FakeProcess()
        obj.container_present = Mock(side_effect=[False, False])
        obj.inspect_owned = Mock(); obj.check_processes = Mock(); obj.rail_absent = Mock(return_value=True)
        receipt = {"status": "OWNED_RESOURCES_CLEANED", "container_id": cfg()["expected_identity"]["container_id"],
            "owned_container_absent": True, "connected_vm_preserved": True, "owns_vm": False}
        return obj, receipt

    def run_cleanup(self, obj, receipt, code=0):
        with patch.object(host, "run_bounded", return_value=(code, b"", b"")) as run, \
            patch.object(host.Path, "exists", return_value=True), \
            patch.object(host, "read_bounded", return_value=encoded(receipt)):
            result = obj.cleanup()
        return result, run

    def test_storage_cleanup_uses_existing_owner_retirement_and_observed_session_leases(self):
        obj,receipt=self.cleanup_fixture()
        obj.storage_policy().active_session_leases.return_value=1
        result,_=self.run_cleanup(obj,receipt)
        obj.storage_policy().active_session_leases.assert_called_once_with(obj.cfg['session_id'])
        obj.storage_policy().cleanup_staging.assert_called_once_with(obj.runtime,
            identity_verified=True,terminal=True,active_leases=1,container_absent=True)
        self.assertEqual(obj.children['runtime'].retired,1)

    def test_already_absent_container_still_requires_helper_and_independent_post_absence(self):
        obj, receipt = self.cleanup_fixture()
        result, run = self.run_cleanup(obj, receipt)
        self.assertTrue(result["container_stopped"]); self.assertEqual(run.call_count, 1)
        self.assertEqual(obj.container_present.call_count, 2); obj.inspect_owned.assert_not_called()
        self.assertEqual(obj.cleanup(), result); self.assertEqual(obj.container_present.call_count, 2)
        self.assertEqual(obj.save.call_args_list[-1].args[0], "platform-cleanup.json")

    def test_unreachable_inventory_never_invokes_stop_helper(self):
        obj, _ = self.cleanup_fixture(); obj.container_present.side_effect = host.Fault("WSLC_COMMAND_FAILED")
        with patch.object(host, "run_bounded") as run:
            with self.assertRaises(host.Fault): obj.cleanup()
        run.assert_not_called(); self.assertFalse(obj.cleaned)
        self.assertEqual(obj.children["runtime"].retired, 1)

    def test_failed_source_validation_still_retires_owned_native_jobs(self):
        obj, _ = self.cleanup_fixture(); obj.frozen.side_effect = host.Fault("WSLC_FIXED_HELPER_CHANGED")
        with patch.object(host, "run_bounded") as run:
            with self.assertRaises(host.Fault): obj.cleanup()
        run.assert_not_called(); self.assertEqual(obj.children["runtime"].retired, 1)
        self.assertFalse(obj.cleaned)

    def test_failed_evidence_write_cannot_prevent_retirement(self):
        obj, receipt = self.cleanup_fixture(); obj.save.side_effect = OSError("injected disk error")
        with self.assertRaises(OSError): self.run_cleanup(obj, receipt)
        self.assertEqual(obj.children["runtime"].retired, 1); self.assertFalse(obj.cleaned)

    def test_one_bad_native_job_does_not_skip_retirement_of_the_other(self):
        obj, receipt = self.cleanup_fixture(); obj.children["relay"] = FakeProcess()
        obj.children["runtime"].retire = Mock(side_effect=OSError("injected disposal error"))
        with self.assertRaises(host.Fault): self.run_cleanup(obj, receipt)
        self.assertEqual(obj.children["relay"].retired, 1); self.assertFalse(obj.cleaned)

    @synthetic_join
    def test_root_exit_zero_with_active_native_descendants_is_not_normal_reap(self):
        obj = bare_owner(); obj.children["runtime"] = FakeProcess()
        obj.children["runtime"].active_count = 1
        obj.proc = Mock(return_value=None); obj.listener = Mock(return_value=[]); obj.rail_absent = Mock(return_value=True)
        with self.assertRaises(host.Fault): obj.reap()
        row = obj.save.call_args.args[1]
        self.assertEqual(row["probes"]["root"]["result"]["returncode"], 0)
        self.assertEqual(row["probes"]["job"]["result"], {"active_processes": 1, "empty": False})
        self.assertEqual(row["primary_error_code"], "WSLC_NORMAL_EXIT_RESOURCES_REMAIN")
        samples = row["samples"]
        self.assertEqual(obj.proc.call_count, len(samples)); self.assertEqual(obj.listener.call_count, len(samples))
        self.assertEqual(obj.rail_absent.call_count, len(samples))
        self.assertTrue(all(s["probes"]["job"]["result"]["active_processes"] == 1 for s in samples))
        self.assertEqual(obj.children["runtime"].killed, 0)

    def test_persistence_failure_does_not_prevent_owned_retirement_attempt(self):
        obj, receipt = self.cleanup_fixture()
        obj.persist_binding.side_effect = OSError("simulated disk failure")
        obj.bindings = {"runtime": {"pid": 42, "start_ticks": 123}}
        result, run = self.run_cleanup(obj, receipt)
        argv = run.call_args.args[0]
        self.assertIn("-OwnedBindingsBase64", argv)
        retained = host.strict_json(host.base64.b64decode(argv[-1]))
        self.assertEqual(retained, {})  # Native Job handles, not the helper's PID lookup, own host retirement.
        self.assertEqual(obj.children["runtime"].retired, 1)
        self.assertTrue(result["owned_helpers_gone"])
        self.assertEqual(obj.save.call_args_list[0].args[1]["binding_persistence_error"], "WSLC_BINDING_PERSISTENCE_FAILED")

    def test_foreign_process_prevents_container_stop(self):
        obj, _ = self.cleanup_fixture(); obj.container_present.side_effect = [True]
        obj.inspect_owned.return_value = {"State": {"Running": True}}
        obj.check_processes.side_effect = host.Fault("WSLC_FOREIGN_GUEST_PROCESS")
        with patch.object(host, "run_bounded") as run:
            with self.assertRaises(host.Fault): obj.cleanup()
        run.assert_not_called(); obj.check_processes.assert_called_once_with(cleanup=True)

    def test_failed_cleanup_receipt_is_retained_but_never_positive_proof(self):
        for change in ({"owns_vm": True}, {"container_id": "e" * 64}, {"owned_container_absent": False},
            {"status": "CLEANUP_UNCONFIRMED"}):
            obj, receipt = self.cleanup_fixture(); receipt.update(change)
            with self.assertRaises(host.Fault): self.run_cleanup(obj, receipt)
            self.assertFalse(obj.cleaned)
            self.assertEqual([call.args[0] for call in obj.save.call_args_list], ["cleanup-attempt-0001.json"])

    def test_container_or_rail_remaining_cannot_emit_cleanup_receipt(self):
        for remaining in ("container", "rail"):
            obj, receipt = self.cleanup_fixture()
            if remaining == "container": obj.container_present.side_effect = [False, True]
            else: obj.rail_absent.return_value = False
            with self.assertRaises(host.Fault): self.run_cleanup(obj, receipt)
            self.assertFalse(obj.cleaned); self.assertEqual(obj.save.call_count, 1)

    def test_finalize_records_unconfirmed_failure_not_exit_zero(self):
        obj = bare_owner(); obj.cleanup = Mock(side_effect=host.Fault("WSLC_FOREIGN_GUEST_PROCESS"))
        obj.finalize()
        record = obj.save.call_args.args[1]
        self.assertEqual(record["status"], "OWNED_CLEANUP_UNCONFIRMED")
        self.assertFalse(record["normal_exit_claimed"]); self.assertEqual(record["error_code"], "WSLC_FOREIGN_GUEST_PROCESS")


class CaptureTimeDiagnostics(unittest.TestCase):
    def fixture(self, before=10000, modified=10000, after=10000, wall=12001, raw=b"synthetic-png-bytes"):
        obj = bare_owner(); obj.grabs = "/tmp/grabs"
        metadata = {"png": obj.grabs + "/capture.png", "w": 0}
        obj.last_grab = (before, metadata)
        stat = f"{len(raw)}|2026-10-23 00:00:00|123|regular file|1"
        obj.text = Mock(side_effect=[metadata["png"], stat, str(modified * 1000000), stat, str(after * 1000000)])
        obj.guest = Mock(return_value=(0, raw, b"")); obj.validate = Mock(return_value=obj.identity)
        return obj, metadata, raw, wall

    def copy(self, fixture):
        obj, metadata, _, wall = fixture
        with patch.object(host.time, "time_ns", side_effect=[(wall - 5) * 1000000, wall * 1000000]), \
            patch.object(host.time, "monotonic_ns", side_effect=[1000000, 4000000]):
            return obj.copy_frame(metadata, 17)

    def assert_time_refusal(self, fixture):
        obj = fixture[0]
        with self.assertRaises(host.Fault) as refused: self.copy(fixture)
        self.assertEqual(refused.exception.code, "WSLC_CAPTURE_TIME_UNCONFIRMED")
        self.assertFalse(refused.exception.dispatched); self.assertEqual(obj.seen_grabs, set())
        self.assertEqual(obj.text.call_count, 5); obj.validate.assert_called_once_with()
        obj.guest.assert_called_once_with("cat", fixture[1]["png"], cap=host.PNG_CAP)
        self.assertEqual(obj.text.call_args.args, ("date", "+%s%N"))

    def test_three_capture_time_comparisons_preserve_exact_rejected_observations(self):
        for before, modified, after, wall, flags in (
            (10001, 10000, 10000, 10000, (False, True, True)),
            (10000, 10001, 10000, 10000, (True, False, True)),
            (10000, 10000, 10000, 12001, (True, True, False))):
            with self.subTest(flags=flags):
                fixture = self.fixture(before, modified, after, wall)
                self.assert_time_refusal(fixture)
                obj, metadata, raw, _ = fixture
                name, record = obj.save.call_args.args
                self.assertEqual(name, "rejected-capture-time-0001.json")
                self.assertIs(record["accepted"], False); self.assertEqual(record["bytes_hex"], raw.hex())
                context = record["context"]
                self.assertEqual(context["identity"], obj.identity)
                self.assertEqual(context["binding"], {key: obj.cfg[key] for key in
                    ("session_id", "owner", "generation", "source_commit", "expected_identity")})
                self.assertEqual(context["metadata"], metadata); self.assertEqual(context["dispatched_ms"], 17)
                self.assertEqual(context["stat_before"], context["stat_after"])
                self.assertEqual((context["guest_clock_before_ms"], context["modified_ms"], context["guest_clock_after_ms"]),
                    (before, modified, after))
                self.assertEqual((context["host_wall_before_ms"], context["host_wall_after_ms"], context["host_guard_ms"]),
                    (wall - 5, wall, wall))
                self.assertEqual(context["final_date_monotonic_elapsed_ns"], 3000000)
                self.assertEqual(tuple(context[key] for key in
                    ("guest_before_le_mtime", "mtime_le_guest_after", "host_guest_within_2000ms")), flags)
                self.assertEqual(context["bytes"], len(raw)); self.assertEqual(context["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(context["original_error"], "WSLC_CAPTURE_TIME_UNCONFIRMED")

    def test_capture_time_equalities_and_signed_2000_2001_boundaries_are_unchanged(self):
        for wall, accepted in ((8000, True), (12000, True), (7999, False), (12001, False)):
            with self.subTest(wall=wall):
                fixture = self.fixture(wall=wall); obj = fixture[0]
                if accepted:
                    self.assertEqual(self.copy(fixture)["bytes_hex"], fixture[2].hex())
                    self.assertEqual(obj.seen_grabs, {fixture[1]["png"]}); obj.save.assert_not_called()
                else:
                    self.assert_time_refusal(fixture)
                    self.assertFalse(obj.save.call_args.args[1]["context"]["host_guest_within_2000ms"])

    def test_rejected_capture_raw_context_and_whole_packet_caps(self):
        fixture = self.fixture(raw=b"x" * host.PNG_CAP)
        self.assert_time_refusal(fixture)
        record = fixture[0].save.call_args.args[1]
        self.assertEqual(len(record["bytes_hex"]), 2 * host.PNG_CAP)
        self.assertLessEqual(len(host.encode_reply(record["context"])), 65536)
        self.assertLessEqual(len(host.encode_reply(record)), host.OUTPUT_CAP)
        oversized_context = self.fixture(); oversized_context[1]["padding"] = "x" * 65536
        self.assert_time_refusal(oversized_context); oversized_context[0].save.assert_not_called()
        oversized_raw = self.fixture(raw=b"x" * (host.PNG_CAP + 1))
        with self.assertRaises(host.Fault) as refused: self.copy(oversized_raw)
        self.assertEqual(refused.exception.code, "WSLC_CAPTURE_STAT_INVALID")
        oversized_raw[0].guest.assert_not_called(); oversized_raw[0].save.assert_not_called()

    def test_rejected_capture_create_new_collision_and_write_failure_preserve_time_refusal(self):
        for cause in (None, FileExistsError("collision"), OSError("write failed")):
            with self.subTest(cause=type(cause).__name__):
                fixture = self.fixture(); obj = fixture[0]
                obj.save = host.Owner.save.__get__(obj, host.Owner)
                opened = mock_open()
                if isinstance(cause, FileExistsError): opened.side_effect = cause
                elif cause is not None: opened.return_value.write.side_effect = cause
                with patch.object(host, "host_path", side_effect=lambda path, *a, **kw: path), \
                    patch.object(host.Path, "open", opened):
                    self.assert_time_refusal(fixture)
                opened.assert_called_once_with("xb")
                self.assertEqual(obj.evidence_index, 1)
                if cause is None:
                    saved = json.loads(opened().write.call_args.args[0])
                    self.assertIs(saved["accepted"], False)
                    self.assertEqual(saved["bytes_hex"], fixture[2].hex())

    def test_earlier_capture_failures_never_publish_time_diagnostics(self):
        for cause in ("stat", "identity"):
            fixture = self.fixture(); obj = fixture[0]
            if cause == "stat": obj.text.side_effect = [fixture[1]["png"], "1|date|123|regular file|2"]
            else: obj.validate.side_effect = host.Fault("WSLC_IDENTITY_DRIFT")
            with self.assertRaises(host.Fault) as refused: self.copy(fixture)
            self.assertEqual(refused.exception.code, "WSLC_CAPTURE_STAT_INVALID" if cause == "stat" else "WSLC_IDENTITY_DRIFT")
            obj.save.assert_not_called(); self.assertEqual(obj.seen_grabs, set())


class RequestValidationFlow(unittest.TestCase):
    def fixture(self):
        obj = bare_owner(); obj.runtime_ok = Mock(); obj.inspect_owned = Mock()
        obj.observe_identity = Mock(return_value=obj.identity)
        obj.guest = Mock(return_value=(0, response(b'{"ok":1}'), b""))
        return obj

    def test_real_call_http_uses_one_full_fresh_identity_inspect_and_one_http(self):
        obj = self.fixture()
        observed = dict(obj.identity)
        obj.observe_identity.return_value = observed
        result = obj.call("request", {"target": "/click?w=0&x=1&y=1&if_user_seq=0", "mutating": True})
        self.assertEqual(result, {"identity": obj.identity, "status": 200, "body_utf8": '{"ok":1}'})
        self.assertIs(result["identity"], observed)
        self.assertIsNot(result["identity"], obj.identity)
        obj.observe_identity.assert_called_once_with(obj.identity["window_id"])
        obj.inspect_owned.assert_called_once_with()
        obj.runtime_ok.assert_called_once_with(); obj.frozen.assert_called_once_with()
        self.assertEqual(obj.guest.call_count, 1); self.assertTrue(obj.dispatched)

    def test_real_call_before_dispatch_identity_or_ownership_failure_never_sends_http(self):
        for location in ("frozen", "identity", "inspect"):
            with self.subTest(location=location):
                obj = self.fixture(); failure = host.Fault("WSLC_IDENTITY_DRIFT")
                if location == "frozen": obj.frozen.side_effect = failure
                elif location == "identity": obj.observe_identity.side_effect = failure
                else: obj.inspect_owned.side_effect = failure
                with self.assertRaises(host.Fault) as refused:
                    obj.call("request", {"target": "/click?w=0&x=1&y=1&if_user_seq=0", "mutating": True})
                self.assertIs(refused.exception, failure); self.assertFalse(obj.dispatched)
                obj.guest.assert_not_called()

    def test_real_call_after_latch_loss_is_wire_unknown_without_http_retry(self):
        obj = self.fixture(); obj.finalize = Mock()
        def lost(*a, **kw):
            self.assertTrue(obj.dispatched)
            raise host.Fault("WSLC_HTTP_COMMAND_FAILED")
        obj.guest.side_effect = lost
        packet = encoded({"version": 1, "sequence": 1, "operation": "request",
            "arguments": {"target": "/click?w=0&x=1&y=1&if_user_seq=0", "mutating": True}}) + b"\n"
        replies = []
        host.serve(obj, io.BytesIO(packet), lambda raw: replies.append(raw) or len(raw))
        # Existing Rust unwrap_reply maps dispatched=true to RemoteError::unknown.
        self.assertEqual(json.loads(replies[0])["error"], {"code": "WSLC_HTTP_COMMAND_FAILED", "dispatched": True})
        self.assertEqual(len(replies), 1); self.assertEqual(obj.guest.call_count, 1)
        self.assertEqual(obj.observe_identity.call_count, 1); self.assertEqual(obj.inspect_owned.call_count, 1)
        obj.finalize.assert_called_once_with()

    def test_each_request_reobserves_identity_and_refuses_later_drift_without_dispatch(self):
        obj = self.fixture()
        drift = dict(obj.identity, process_start_ticks="999")
        obj.observe_identity.side_effect = [dict(obj.identity), drift]
        args = {"target": "/snap", "mutating": False}
        obj.call("request", args)
        with self.assertRaises(host.Fault) as refused: obj.call("request", args)
        self.assertEqual(refused.exception.code, "WSLC_IDENTITY_DRIFT")
        self.assertEqual(obj.inspect_owned.call_count, 2)
        self.assertEqual(obj.observe_identity.call_count, 2)
        self.assertEqual(obj.frozen.call_count, 2)
        self.assertEqual(obj.guest.call_count, 1); self.assertFalse(obj.dispatched)

    def test_module_quit_retains_both_validations_around_native_resource_witness(self):
        obj = self.fixture(); obj.cfg["profile_kind"] = "ModuleShell"; order = []
        obj.module_resources = Mock(side_effect=lambda stage: order.append(stage))
        obj.inspect_owned.side_effect = lambda: order.append("inspect")
        obj.observe_identity.side_effect = lambda window: order.append("identity") or dict(obj.identity)
        obj.guest.side_effect = lambda *a, **kw: (order.append("http") or 0, response(b'{}'), b"")
        obj.call("request", {"target": "/quit?if_user_seq=0", "mutating": True})
        self.assertEqual(order, ["inspect", "identity", "before-quit", "inspect", "identity", "http"])
        obj.module_resources.assert_called_once_with("before-quit")

    def test_module_quit_identity_failure_on_either_side_of_resources_never_dispatches(self):
        for before_resources in (True, False):
            with self.subTest(before_resources=before_resources):
                obj = self.fixture(); obj.cfg["profile_kind"] = "ModuleShell"
                obj.module_resources = Mock()
                failure = host.Fault("WSLC_IDENTITY_DRIFT")
                obj.observe_identity.side_effect = [failure] if before_resources else [dict(obj.identity), failure]
                with self.assertRaises(host.Fault):
                    obj.call("request", {"target": "/quit?if_user_seq=0", "mutating": True})
                self.assertEqual(obj.module_resources.call_count, 0 if before_resources else 1)
                obj.guest.assert_not_called(); self.assertFalse(obj.dispatched)

    def test_quit_resource_failure_prevents_validation_and_http(self):
        obj = self.fixture()
        obj.module_resources = Mock(side_effect=host.Fault("WSLC_RESOURCE_REFUSED"))
        with self.assertRaises(host.Fault):
            obj.call("request", {"target": "/quit?if_user_seq=0", "mutating": True})
        obj.inspect_owned.assert_not_called(); obj.observe_identity.assert_not_called()
        obj.guest.assert_not_called(); self.assertFalse(obj.dispatched)

    def test_startup_http_retains_original_identity_observation_path(self):
        obj = self.fixture(); obj.guest_identity = Mock(); order = []
        obj.inspect_owned.side_effect = lambda: order.append("inspect")
        obj.guest_identity.side_effect = lambda: order.append("kernel")
        obj.guest.side_effect = lambda *a, **kw: (order.append("http") or 0, response(b'{}'), b"")
        self.assertEqual(obj.http("/s", False, startup=True), (200, '{}'))
        self.assertEqual(order, ["inspect", "kernel", "http"])
        obj.observe_identity.assert_not_called(); self.assertFalse(obj.dispatched)


class BoundedIO(unittest.TestCase):
    def test_process_caps_both_channels_during_read_with_no_real_process(self):
        for output, error in ((b"x" * 65, b""), (b"", b"e" * 65)):
            child = FakeProcess(output, error)
            with self.assertRaises(host.Fault):
                host.run_bounded(["MOCK_ONLY"], out_cap=64, err_cap=64, popen=lambda *a, **k: child)

    def test_process_pure_fake_keeps_stdout_stderr_separate(self):
        child = FakeProcess(b"actual", b"diagnostic")
        self.assertEqual(host.run_bounded(["MOCK_ONLY"], popen=lambda *a, **k: child), (0, b"actual", b"diagnostic"))

    def test_ordinary_eof_reaches_finally_without_positive_cleanup_claim(self):
        owner = FakeOwner(); raw = []
        host.serve(owner, io.BytesIO(b""), lambda data: raw.append(data) or len(data))
        self.assertEqual(owner.finalized, 1); self.assertEqual(raw, [])

    def test_malformed_input_reaches_finally_and_does_not_call_owner(self):
        owner = FakeOwner(); raw = []
        host.serve(owner, io.BytesIO(b'{"sequence":1,"sequence":2}\n'), lambda data: raw.append(data) or len(data))
        self.assertEqual(owner.calls, []); self.assertEqual(owner.finalized, 1)
        reply = json.loads(raw[0]); self.assertFalse(reply["ok"]); self.assertEqual(reply["sequence"], 0)

    def test_partial_input_eof_refuses_and_finalizes(self):
        owner = FakeOwner()
        with self.assertRaises(host.Fault): host.serve(owner, io.BytesIO(b"{"), lambda data: len(data))
        self.assertEqual(owner.finalized, 1)

    def test_blocked_output_does_not_block_finally(self):
        owner = FakeOwner(); gate = threading.Event()
        raw = encoded({"version": 1, "sequence": 1, "operation": "validate", "arguments": {}}) + b"\n"
        def blocked(data): gate.wait(); return len(data)
        try:
            with self.assertRaises(host.Fault): host.serve(owner, io.BytesIO(raw), blocked, lifetime=.03)
            self.assertEqual(owner.finalized, 1)
        finally: gate.set()

    def test_incomplete_owner_cannot_emit_fake_cleanup_success(self):
        owner = host.Owner.__new__(host.Owner); owner.adopted = False
        with self.assertRaises(host.Fault) as raised: owner.cleanup()
        self.assertEqual(raised.exception.code, "WSLC_NO_ADOPTED_CONTAINER")


class FakeJob:
    """Fake of the already existing Job API; no process, handle or thread IO."""
    def __init__(self, owner, events, failure=None, confirmed=True):
        self.owner, self.events, self.failure = owner, events, failure
        self.confirmed = confirmed; self.process = self.pid = None
        self.started = self.resumed = self.disposed = 0; self.code = None

    def start(self, args, streams):
        self.events.append("create-assign"); self.started += 1
        assert self.owner.children["runtime"].job is self
        self.process = 123; self.pid = 42
        if self.failure == "create-assign": raise OSError("injected assign failure")

    def resume(self):
        self.events.append("resume"); self.resumed += 1
        assert "birth" in self.events and "persist" in self.events and self.events.count("drainer") == 2
        if self.failure == "resume": raise OSError("injected resume failure")

    def active(self): return 0 if self.code is not None or self.disposed else 1
    def exited(self): return self.code is not None
    def exit_code(self): return self.code
    def dispose(self, reason):
        self.events.append("dispose"); self.disposed += 1; self.process = None
        return SimpleNamespace(as_dict=lambda: {"confirmed": self.confirmed, "active_after": 0 if self.confirmed else None,
            "assigned_before_resume": True, "reason": reason, "root_pid": self.pid})


class StartupOwnership(unittest.TestCase):
    def exercise_spawn(self, failure=None, confirmed=True):
        owner, events, allocated = bare_owner(), [], []
        job = FakeJob(owner, events, failure, confirmed)
        owner.owned_driver = Mock(return_value=SimpleNamespace(_Job=Mock(return_value=job)))
        def stream(*args, **kwargs):
            result = io.BytesIO(); allocated.append(result); return result
        def pipes():
            if failure == "pipe": raise OSError("injected pipe setup failure")
            return stream(), stream()
        def birth(*args, **kwargs):
            self.assertIs(owner.children["runtime"].job, job)
            self.assertEqual(job.resumed, 0); self.assertEqual(kwargs["owned_handle"], job.process)
            events.append("birth")
            if failure == "birth": raise host.Fault("WSLC_NATIVE_BIRTH_UNAVAILABLE")
            return "1234"
        def persist():
            self.assertEqual(job.resumed, 0); events.append("persist")
            if failure == "persist": raise OSError("injected persistence failure")
        owner.persist_binding = Mock(side_effect=persist)
        class Worker:
            def __init__(self, target, args, daemon): self.target, self.args = target, args
            def start(self):
                events.append("drainer")
                if failure == "drainer": raise RuntimeError("injected thread start failure")
                self.target(*self.args)  # Immediate bounded fake EOF, never starts a thread.
            def is_alive(self): return False
            def join(self, timeout=None): pass
        error = None
        with patch.object(host, "host_path", side_effect=lambda value, *a, **kw: value), \
            patch.object(host.Path, "open", side_effect=stream), patch("builtins.open", side_effect=stream), \
            patch.object(host, "pipe_streams", side_effect=pipes), patch.object(host, "native_birth", side_effect=birth), \
            patch.object(host.threading, "Thread", Worker):
            try: child = owner.spawn("runtime", ["TRUSTED_MOCK_ONLY"], "out.log", "err.log")
            except host.Fault as exc: error = exc; child = owner.children["runtime"]
        self.assertTrue(all(value.closed for value in allocated), "local/mock-drainer stream ownership must be complete")
        return owner, child, job, events, error

    def test_native_job_is_retained_before_create_and_resume_is_last(self):
        owner, child, job, events, error = self.exercise_spawn()
        self.assertIsNone(error); self.assertEqual(job.started, 1); self.assertEqual(job.resumed, 1)
        self.assertEqual(events, ["create-assign", "birth", "persist", "drainer", "drainer", "resume"])
        self.assertIs(owner.children["runtime"], child)

    def test_all_pre_resume_failures_retire_job_without_birth_sidecar_dependency(self):
        for failure in ("pipe", "create-assign", "birth", "persist", "drainer", "resume"):
            with self.subTest(failure=failure):
                owner, child, job, events, error = self.exercise_spawn(failure)
                self.assertEqual(error.code, "WSLC_CHILD_STARTUP_FAILED"); self.assertTrue(error.dispatched)
                self.assertEqual(job.disposed, 1); self.assertEqual(events[-1], "dispose")
                if failure != "resume": self.assertEqual(job.resumed, 0)
                self.assertTrue(child.retirement["confirmed"])
                child.retire("no-replay"); self.assertEqual(job.disposed, 1)
                self.assertIsNone(child.returncode, "retirement must not manufacture an app exit0")

    def test_failed_job_observation_cannot_become_cleanup_pass(self):
        _, child, job, _, error = self.exercise_spawn("birth", confirmed=False)
        self.assertEqual(error.code, "WSLC_CHILD_STARTUP_CLEANUP_UNCONFIRMED")
        self.assertFalse(child.retirement["confirmed"]); self.assertEqual(job.disposed, 1)

    def test_native_retirement_exception_is_cached_not_retried_on_closed_handles(self):
        job = Mock(); job.dispose.side_effect = OSError("injected native cleanup failure")
        child = host.RetainedChild(job)
        self.assertFalse(child.retire("failure")["confirmed"])
        self.assertFalse(child.retire("still-failed")["confirmed"]); self.assertEqual(job.dispose.call_count, 1)

    def test_root_exit_and_job_emptiness_are_independent(self):
        job = Mock(); job.process = 123; job.exited.return_value = True; job.exit_code.return_value = 0
        job.active.return_value = 1
        child = host.RetainedChild(job)
        self.assertEqual(child.poll(), 0); self.assertFalse(child.empty())
        self.assertEqual(child.active_processes(), 1)
        self.assertIsNone(child.retirement)


class ReapDiagnostics(unittest.TestCase):
    def setUp(self):
        self.clock = JoinClock()
        for name, value in (("monotonic", self.clock.monotonic), ("sleep", self.clock.sleep)):
            port = patch.object(host.time, name, value)
            port.start(); self.addCleanup(port.stop)

    def fixture(self):
        obj = bare_owner(); child = FakeProcess(); obj.children["runtime"] = child
        obj.proc = Mock(return_value=None); obj.listener = Mock(return_value=[])
        obj.rail_absent = Mock(return_value=True)
        obj.cleanup = Mock(side_effect=AssertionError("reap must never perform cleanup"))
        return obj, child

    def observation(self, obj):
        return [call.args[1] for call in obj.save.call_args_list
            if call.args[0].startswith("reap-observation-")][-1]

    def assert_all_probes(self, obj, child):
        row = self.observation(obj)
        self.assertEqual(list(row["probes"]), ["root", "job", "guest", "listener", "rail"])
        for probe in row["probes"].values():
            self.assertIsInstance(probe["started_unix_ms"], int)
            self.assertIsInstance(probe["finished_unix_ms"], int)
            self.assertGreaterEqual(probe["elapsed_ms"], 0)
        obj.proc.assert_called_once_with(obj.pid); obj.listener.assert_called_once()
        obj.rail_absent.assert_called_once(); obj.cleanup.assert_not_called()
        self.assertEqual(child.killed, 0); self.assertEqual(child.retired, 0)
        return row

    def test_each_probe_error_records_all_results_and_never_proves_exit(self):
        for name in ("root", "job", "guest", "listener", "rail"):
            with self.subTest(probe=name):
                obj, child = self.fixture(); failure = host.Fault("WSLC_PROCESS_TIMEOUT")
                port = {"root": (child, "poll"), "job": (child, "active_processes"),
                    "guest": (obj, "proc"), "listener": (obj, "listener"), "rail": (obj, "rail_absent")}[name]
                setattr(port[0], port[1], Mock(side_effect=failure))
                with self.assertRaises(host.Fault) as refused: obj.reap()
                self.assertIs(refused.exception, failure)
                row = self.assert_all_probes(obj, child)
                self.assertFalse(row["probes"][name]["ok"])
                self.assertIsNone(row["probes"][name]["satisfied"])
                self.assertFalse(row["all_conditions_proven"]); self.assertIsNone(obj.normal_exit_result)
                self.assertEqual(obj.save.call_count, 1)

    def test_first_false_keeps_resources_remain_over_later_probe_and_write_errors(self):
        obj, child = self.fixture(); child.active_count = 1
        obj.proc.side_effect = host.Fault("WSLC_PROCESS_ABSENCE_UNCONFIRMED")
        obj.listener.side_effect = OSError("private diagnostic text must not escape")
        obj.save.side_effect = OSError("diagnostic disk error")
        with self.assertRaises(host.Fault) as refused: obj.reap()
        self.assertEqual(refused.exception.code, "WSLC_NORMAL_EXIT_RESOURCES_REMAIN")
        row = self.assert_all_probes(obj, child)
        self.assertEqual(row["probes"]["job"]["result"], {"active_processes": 1, "empty": False})
        self.assertEqual(row["probes"]["guest"]["error_code"], "WSLC_PROCESS_ABSENCE_UNCONFIRMED")
        self.assertEqual(row["probes"]["listener"]["error_code"], "WSLC_REAP_PROBE_FAILED")
        self.assertNotIn("private diagnostic", json.dumps(row))
        self.assertIsNone(obj.normal_exit_result)

    def test_root_nonzero_has_priority_and_still_records_later_probes(self):
        obj, child = self.fixture(); child.returncode = -9
        child.active_processes = Mock(side_effect=host.Fault("WSLC_PROCESS_TIMEOUT"))
        with self.assertRaises(host.Fault) as refused: obj.reap()
        self.assertEqual(refused.exception.code, "WSLC_APP_EXIT_NONZERO")
        row = self.assert_all_probes(obj, child)
        self.assertEqual(row["probes"]["root"]["result"]["returncode"], -9)
        self.assertIsNone(obj.normal_exit_result)

    def test_original_root_timeout_is_not_replaced_or_given_another_wait(self):
        obj, child = self.fixture(); child.returncode = None; obj.runtime_ok = Mock()
        child.active_count = 1
        obj.proc.side_effect = host.Fault("WSLC_PROCESS_ABSENCE_UNCONFIRMED")
        began = self.clock.now
        with self.assertRaises(host.Fault) as refused: obj.reap()
        self.assertEqual(refused.exception.code, "WSLC_NORMAL_EXIT_UNCONFIRMED")
        self.assertTrue(self.clock.sleeps); self.assertTrue(all(0 < s <= .025 for s in self.clock.sleeps))
        self.assertAlmostEqual(self.clock.now - began, 8)
        row = self.assert_all_probes(obj, child)
        self.assertIsNone(row["probes"]["root"]["result"]["returncode"])
        self.assertIsNone(obj.normal_exit_result)

    def test_diagnostic_write_failure_keeps_original_probe_exception(self):
        obj, child = self.fixture(); failure = host.Fault("WSLC_PROCESS_ABSENCE_UNCONFIRMED")
        obj.proc.side_effect = failure; obj.save.side_effect = OSError("full disk")
        with self.assertRaises(host.Fault) as refused: obj.reap()
        self.assertIs(refused.exception, failure); self.assert_all_probes(obj, child)
        self.assertIsNone(obj.normal_exit_result)

    def test_otherwise_successful_write_failure_cannot_latch_normal_exit(self):
        obj, child = self.fixture(); failure = OSError("full disk"); obj.save.side_effect = failure
        with self.assertRaises(OSError) as refused: obj.reap()
        self.assertIs(refused.exception, failure); self.assert_all_probes(obj, child)
        self.assertEqual(obj.save.call_count, 1); self.assertIsNone(obj.normal_exit_result)
        self.assertEqual(obj.save.call_args.args[0], "reap-observation-0001.json")

    def test_repeated_reap_has_immutable_names_cached_root_and_no_new_exit(self):
        obj, child = self.fixture(); child.poll = Mock(return_value=0)
        proof = obj.reap(); child.poll.assert_called_once()
        self.assertIs(obj.reap(), proof); child.poll.assert_called_once()
        second = self.observation(obj)
        self.assertTrue(second["repeated"]); self.assertTrue(second["probes"]["root"]["result"]["cached_exit"])
        self.assertEqual(second["probes"]["guest"]["result"],
            {"pid": 10, "expected_birth": "12", "absent": True, "observed": None})
        self.assertEqual(second["probes"]["listener"]["result"],
            {"port": 1234, "expected_inode": "34", "observed_inodes": [], "absent": True})
        child.active_count = 1
        with self.assertRaises(host.Fault) as refused: obj.reap()
        self.assertEqual(refused.exception.code, "WSLC_NORMAL_EXIT_RESOURCES_REMAIN")
        self.assertIs(obj.normal_exit_result, proof); child.poll.assert_called_once()
        self.assertEqual([call.args[0] for call in obj.save.call_args_list],
            ["reap-observation-0001.json", "native-app-exit.json", "reap-observation-0002.json",
                "reap-observation-0003.json"])
        self.assertEqual(child.killed, 0); self.assertEqual(child.retired, 0); obj.cleanup.assert_not_called()

    def test_exact_rail_observation_error_is_retained_and_never_absence(self):
        obj, child = self.fixture(); del obj.rail_absent
        obj.rail = {"hwnd": 55, "pid": 66, "birth": "77"}
        candidate = {"hwnd": 55, "pid": 66, "birth": None, "visible": False, "title": obj.tag,
            "observation_error": "WSLC_NATIVE_BIRTH_UNAVAILABLE"}
        with patch.object(host, "rail_windows", return_value=[candidate]):
            with self.assertRaises(host.Fault) as refused: obj.reap()
        self.assertEqual(refused.exception.code, "WSLC_RAIL_ABSENCE_UNCONFIRMED")
        row = self.observation(obj)["probes"]["rail"]
        self.assertFalse(row["ok"]); self.assertIsNone(row["satisfied"])
        self.assertEqual(row["result"]["expected"], obj.rail)
        self.assertNotIn("absent", row["result"])
        self.assertEqual(row["result"]["candidates"][0]["observation_error"], "WSLC_NATIVE_BIRTH_UNAVAILABLE")
        self.assertNotIn("title", row["result"]["candidates"][0])
        self.assertIsNone(obj.normal_exit_result); self.assertEqual(child.killed, 0)

    def test_complete_join_delayed_rail_passes_only_after_all_fresh_predicates(self):
        obj, child = self.fixture(); obj.rail_absent.side_effect = [False, False, True]
        original_deadline = obj.deadline
        proof = obj.reap(); row = self.observation(obj)
        self.assertTrue(proof["normal_exit_observed"]); self.assertEqual(len(row["samples"]), 3)
        self.assertEqual([s["probes"]["rail"]["satisfied"] for s in row["samples"]], [False, False, True])
        self.assertTrue(all(p["satisfied"] for p in row["samples"][-1]["probes"].values()))
        self.assertEqual(obj.proc.call_count, 3); self.assertEqual(obj.listener.call_count, 3)
        self.assertTrue(row["all_conditions_proven"])
        self.assertIsNone(row["primary_error_code"])
        self.assertEqual(row["first_failure_code"], "WSLC_NORMAL_EXIT_RESOURCES_REMAIN")
        self.assertEqual(obj.deadline, original_deadline)
        self.assertEqual(child.killed, 0); self.assertEqual(child.retired, 0); obj.cleanup.assert_not_called()

    def test_complete_join_persistent_rail_expires_at_same_eight_seconds(self):
        obj, child = self.fixture(); obj.rail_absent.return_value = False
        began, original_deadline = self.clock.now, obj.deadline
        with self.assertRaises(host.Fault) as refused: obj.reap()
        self.assertEqual(refused.exception.code, "WSLC_NORMAL_EXIT_RESOURCES_REMAIN")
        row = self.observation(obj)
        self.assertAlmostEqual(self.clock.now - began, 8)
        self.assertGreater(len(row["samples"]), 1)
        self.assertTrue(all(not s["probes"]["rail"]["satisfied"] for s in row["samples"]))
        self.assertFalse(row["samples"][-1]["within_budget"])
        self.assertEqual(obj.proc.call_count, len(row["samples"]))
        self.assertEqual(obj.listener.call_count, len(row["samples"]))
        self.assertFalse(row["all_conditions_proven"]); self.assertIsNone(obj.normal_exit_result)
        self.assertEqual(obj.deadline, original_deadline)
        self.assertEqual(child.killed, 0); self.assertEqual(child.retired, 0); obj.cleanup.assert_not_called()

    def test_root_consumes_join_budget_without_reset_or_late_success(self):
        for delay, rail_absent in ((7, False), (8, True)):
            with self.subTest(root_seconds=delay):
                obj, child = self.fixture(); obj.rail_absent.return_value = rail_absent
                began, original_deadline = self.clock.now, obj.deadline
                def exited():
                    self.clock.advance(delay)
                    return 0
                child.poll = Mock(side_effect=exited)
                with self.assertRaises(host.Fault) as refused: obj.reap()
                self.assertEqual(refused.exception.code, "WSLC_NORMAL_EXIT_RESOURCES_REMAIN")
                self.assertAlmostEqual(self.clock.now - began, 8)
                child.poll.assert_called_once()
                self.assertFalse(self.observation(obj)["all_conditions_proven"])
                self.assertIsNone(obj.normal_exit_result); self.assertEqual(obj.deadline, original_deadline)

    def test_probe_error_after_false_ends_join_without_retry_or_priority_loss(self):
        obj, child = self.fixture(); failure = host.Fault("WSLC_PROCESS_ABSENCE_UNCONFIRMED")
        obj.proc.side_effect = [None, failure]
        obj.rail_absent.side_effect = [False, True, True]
        with self.assertRaises(host.Fault) as refused: obj.reap()
        self.assertEqual(refused.exception.code, "WSLC_NORMAL_EXIT_RESOURCES_REMAIN")
        row = self.observation(obj); self.assertEqual(len(row["samples"]), 2)
        self.assertTrue(row["samples"][-1]["probe_error"])
        self.assertEqual(row["samples"][-1]["probes"]["guest"]["error_code"], failure.code)
        self.assertEqual(obj.proc.call_count, 2); self.assertEqual(obj.rail_absent.call_count, 2)
        self.assertIsNone(obj.normal_exit_result); self.assertEqual(child.killed, 0)

    def test_owner_deadline_restored_on_success_probe_error_and_evidence_error(self):
        for cause in (None, host.Fault("WSLC_PROCESS_ABSENCE_UNCONFIRMED"), OSError("evidence full")):
            with self.subTest(cause=type(cause).__name__):
                obj, _ = self.fixture(); original_deadline = obj.deadline
                if isinstance(cause, host.Fault): obj.proc.side_effect = cause
                elif cause is not None: obj.save.side_effect = cause
                if cause is None:
                    self.assertTrue(obj.reap()["normal_exit_observed"])
                else:
                    with self.assertRaises(type(cause)) as refused: obj.reap()
                    self.assertIs(refused.exception, cause); self.assertIsNone(obj.normal_exit_result)
                self.assertEqual(obj.deadline, original_deadline)

    def test_nested_wslc_calls_use_remaining_join_budget_not_twelve_seconds_each(self):
        obj, _ = self.fixture(); original_deadline = obj.deadline; timeouts = []
        def bounded(*args, **kwargs):
            timeouts.append(kwargs["timeout"])
            self.clock.advance(6 if len(timeouts) == 1 else 1)
            return 0, b"", b""
        def guest_sample(pid):
            # Exercise the actual owner budget port, never spawn a real process.
            obj.wslc("READ_ONLY_MOCK", timeout=12)
            obj.wslc("READ_ONLY_MOCK", timeout=12)
            return None
        obj.proc.side_effect = guest_sample
        with patch.object(host, "run_bounded", side_effect=bounded) as run:
            self.assertTrue(obj.reap()["normal_exit_observed"])
        self.assertEqual(run.call_count, 2)
        self.assertEqual(timeouts, [8, 2]); self.assertEqual(obj.deadline, original_deadline)

    def test_join_never_extends_an_earlier_original_owner_deadline(self):
        obj, _ = self.fixture(); obj.rail_absent.return_value = False
        began = self.clock.now; obj.deadline = original_deadline = began + .15
        with self.assertRaises(host.Fault) as refused: obj.reap()
        self.assertEqual(refused.exception.code, "WSLC_NORMAL_EXIT_RESOURCES_REMAIN")
        self.assertAlmostEqual(self.clock.now, original_deadline)
        self.assertEqual(obj.deadline, original_deadline)
        self.assertLessEqual(self.observation(obj)["effective_budget_ms"], 150)
        self.assertIsNone(obj.normal_exit_result)

    def test_write_failure_after_delayed_join_success_still_cannot_latch_exit(self):
        obj, _ = self.fixture(); obj.rail_absent.side_effect = [False, True]
        failure = OSError("full evidence disk"); obj.save.side_effect = failure
        original_deadline = obj.deadline
        with self.assertRaises(OSError) as refused: obj.reap()
        self.assertIs(refused.exception, failure); self.assertIsNone(obj.normal_exit_result)
        self.assertTrue(self.observation(obj)["all_conditions_proven"])
        self.assertEqual(len(self.observation(obj)["samples"]), 2)
        self.assertEqual(obj.save.call_count, 1); self.assertEqual(obj.deadline, original_deadline)


class KernelFdWitness(unittest.TestCase):
    BASE = 1_000_000_000_000

    def fixture(self):
        import copy
        obj = bare_owner()
        obj.guest_owners = {
            10: {"birth": "12", "parent": 9, "kind": "app", "argv": obj.expected_commands()["app"][0]},
            9: {"birth": "11", "parent": 1, "kind": "app", "argv": obj.expected_commands()["app"][1]}}
        def proc(pid, birth, parent):
            return f"{pid} (app name) S " + str(parent) + " " + "0 " * 17 + str(birth)
        fd = {"dev": "1", "inode": "2", "nlink": "1", "size": "64", "ctime_ns": "999"}
        sample = {"proc_stat_raw": proc(10, 12, 9), "exe_link": cfg()["expected_identity"]["executable"],
            "pid_namespace": "pid:[123]", "mount_namespace": "mnt:[456]",
            "executable_fd_stat": dict(fd), "guest_path_fd_stat": dict(fd)}
        report = {"schema": "toolkit-wslc-proc-fd-executable-report-v1", "pid": 10,
            "guest_path": sample["exe_link"], "before": sample, "after": copy.deepcopy(sample),
            "executable_fd_sha256": "c"*64, "guest_path_fd_sha256": "c"*64,
            "parent": {"pid": 9, "proc_stat_raw": proc(9, 11, 1), "after_proc_stat_raw": proc(9, 11, 1),
                "argv": obj.expected_commands()["app"][1], "argv_after": obj.expected_commands()["app"][1]},
            "launch_nonce": obj.launch_nonces["app"],
            "listener": {"host": "127.0.0.1", "port": 1234, "inode": "34", "socket_fd": 5,
                "socket_fd_link": "socket:[34]", "proc_net_tcp_row": "0: 0100007F:04D2 00000000:0000 0A 0 0 0 0 0 34"},
            "observed_start_unix_ns": str(self.BASE+1), "observed_end_unix_ns": str(self.BASE+10)}
        return obj, report

    def parse(self, obj, value):
        return host.kernel_fd_report(encoded(value), obj.cfg["expected_identity"], obj.pid,
            obj.guest_owners[10], obj.guest_owners[9], obj.launch_nonces["app"], obj.port, self.BASE, self.BASE+100)

    def test_stable_fds_and_changing_cpu_counters_are_not_raw_stat_equality(self):
        obj, report = self.fixture()
        parts = report["after"]["proc_stat_raw"].split(); parts[8] = "123456"
        report["after"]["proc_stat_raw"] = " ".join(parts)
        self.assertEqual(self.parse(obj, report)["pid"], report["pid"])
        self.assertEqual(len(identity()), 18)

    def test_large_module_elf_keeps_legacy_cap_and_all_kernel_identity_checks(self):
        obj, report = self.fixture()
        obj.cfg["expected_identity"]["executable_sha256"] = host.MODULE_ELF_SHA256
        report["executable_fd_sha256"] = report["guest_path_fd_sha256"] = host.MODULE_ELF_SHA256
        for phase in ("before","after"):
            for key in ("executable_fd_stat","guest_path_fd_stat"):
                report[phase][key]["size"] = "366682664"
        with self.assertRaises(host.Fault): self.parse(obj,report)
        def parse():
            return host.kernel_fd_report(encoded(report),obj.cfg["expected_identity"],obj.pid,
                obj.guest_owners[10],obj.guest_owners[9],obj.launch_nonces["app"],obj.port,
                self.BASE,self.BASE+100,max_executable_bytes=512*1024*1024)
        self.assertEqual(parse()["pid"],10)
        report["after"]["guest_path_fd_stat"]["inode"]="123"
        with self.assertRaises(host.Fault):parse()

    def test_normal_running_sleeping_transition_is_not_pid_reuse(self):
        obj, report = self.fixture()
        report["after"]["proc_stat_raw"] = report["after"]["proc_stat_raw"].replace(") S ", ") R ")
        self.assertEqual(self.parse(obj, report)["pid"], 10)

    def test_identity_state_birth_namespace_file_and_hash_drift_refuse(self):
        import copy
        cases = [("pid", 11), ("executable_fd_sha256", "d"*64), ("guest_path_fd_sha256", "d"*64)]
        for key, val in cases:
            obj, report = self.fixture(); report[key] = val
            with self.subTest(key=key), self.assertRaises(host.Fault): self.parse(obj, report)
        for key, val in (("exe_link", "/wrong"), ("pid_namespace", "pid:[124]"), ("mount_namespace", "mnt:[457]"),
            ("proc_stat_raw", "10 (app) Z 9 " + "0 "*17 + "12")):
            obj, report = self.fixture(); report["after"][key] = val
            with self.subTest(key=key), self.assertRaises(host.Fault): self.parse(obj, report)
        for key in ("dev", "inode", "nlink", "size", "ctime_ns"):
            obj, report = self.fixture(); report["after"]["executable_fd_stat"][key] = "3"
            with self.subTest(field=key), self.assertRaises(host.Fault): self.parse(obj, report)
        obj, report = self.fixture(); report["before"]["guest_path_fd_stat"]["inode"] = "77"
        with self.assertRaises(host.Fault): self.parse(obj, report)

    def test_registered_parent_nonce_clock_listener_and_partial_reports_refuse(self):
        for name in ("parent_birth", "parent_after_birth", "parent_argv", "parent_after_argv", "nonce", "clock", "listener", "extra"):
            obj, report = self.fixture()
            if name == "parent_birth": report["parent"]["proc_stat_raw"] = report["parent"]["proc_stat_raw"][:-2]+"99"
            elif name == "parent_after_birth": report["parent"]["after_proc_stat_raw"] += "0"
            elif name == "parent_argv": report["parent"]["argv"] = ["foreign"]
            elif name == "parent_after_argv": report["parent"]["argv_after"] = ["foreign"]
            elif name == "nonce": report["launch_nonce"] = "a"*32
            elif name == "clock": report["observed_end_unix_ns"] = str(self.BASE-1)
            elif name == "listener": report["listener"]["socket_fd_link"] = "socket:[35]"
            else: report["success"] = True
            with self.subTest(name=name), self.assertRaises(host.Fault): self.parse(obj, report)
        obj, report = self.fixture()
        with self.assertRaises(host.Fault):
            host.kernel_fd_report(encoded(report)[:-2], obj.cfg["expected_identity"], 10,
                obj.guest_owners[10], obj.guest_owners[9], obj.launch_nonces["app"], obj.port, self.BASE, self.BASE+100)

    def test_one_bounded_rpc_actual_collector_and_no_per_validation_writes(self):
        obj, report = self.fixture(); raw = encoded(report)
        obj.guest = Mock(return_value=(0, raw, b"")); obj.proc = Mock(); obj.listener = Mock()
        with patch.object(host.time, "time_ns", side_effect=[self.BASE, self.BASE+100]):
            self.assertEqual(obj.guest_identity(), ("12", "pid:[123]", "c"*64, "34"))
        obj.guest.assert_called_once_with("bash", "-c", host.KERNEL_FD_PROGRAM, "toolkit-kernel-fds", "10",
            cfg()["expected_identity"]["executable"], "1234", cap=host.INPUT_CAP)
        obj.save.assert_not_called(); obj.proc.assert_not_called(); obj.listener.assert_not_called()
        invocation = obj.kernel_latest[3]
        self.assertEqual(invocation["executable"], host.WSLC)
        self.assertEqual(invocation["args"], ["exec", "a"*64, *obj.guest.call_args.args])
        self.assertEqual(invocation["stdout_sha256"], hashlib.sha256(raw).hexdigest().upper())
        self.assertEqual(invocation["exit_code"], 0); self.assertEqual(invocation["stderr"], "")

    def test_runtime_identity_and_cgroups_share_one_rpc_without_relabeling_launch_witness(self):
        obj, report = self.fixture(); obj.running_witness_saved = True
        launch = (b"original launch witness", 1, 2, {"args": ["original collector"]}); obj.kernel_latest = launch
        obj.guest = Mock(return_value=(0, encoded(report)+b"\nTOOLKIT_IDENTITY_CGROUP_V1\n1073741824\n100000 100000\n", b""))
        with patch.object(host.time, "time_ns", side_effect=[self.BASE,self.BASE+100]):
            self.assertEqual(obj.guest_identity(with_cgroups=True), (("12","pid:[123]","c"*64,"34"),(1073741824,"100000 100000")))
        obj.guest.assert_called_once_with("bash","-c",host.IDENTITY_CGROUP_PROGRAM,"toolkit-identity-cgroups",host.KERNEL_FD_PROGRAM,
            "10",cfg()["expected_identity"]["executable"],"1234",cap=host.INPUT_CAP)
        self.assertIs(obj.kernel_latest,launch); obj.save.assert_not_called()

    def test_runtime_batch_requires_saved_launch_and_rejects_bad_frame_or_cgroups(self):
        obj, report = self.fixture(); obj.guest = Mock()
        with self.assertRaisesRegex(host.Fault,"WSLC_RUNTIME_WITNESS_REQUIRED"):obj.guest_identity(with_cgroups=True)
        obj.guest.assert_not_called()
        good=encoded(report)+b"\nTOOLKIT_IDENTITY_CGROUP_V1\n1073741824\n100000 100000\n"
        for raw in (encoded(report),good[:-2],good+b"extra\n",good.replace(b"1073741824",b"max"),
            good.replace(b"100000 100000",b"200000 100000"),good+b"\nTOOLKIT_IDENTITY_CGROUP_V1\n",good.replace(b"1073741824",b"\xff")):
            obj, _ = self.fixture(); obj.running_witness_saved=True; obj.guest=Mock(return_value=(0,raw,b""))
            with patch.object(host.time,"time_ns",side_effect=[self.BASE,self.BASE+100]),self.assertRaises(host.Fault):
                obj.guest_identity(with_cgroups=True)
            obj.guest.assert_called_once(); obj.save.assert_not_called(); self.assertIsNone(obj.kernel_latest)

    def test_runtime_observe_identity_checks_new_kernel_and_cgroups_on_every_validation(self):
        obj, report = self.fixture(); obj.running_witness_saved=True
        obj.rail={"hwnd":55,"pid":66,"birth":"77"}; rows=[{**obj.rail,"title":obj.tag,"visible":False}]
        first=encoded(report)+b"\nTOOLKIT_IDENTITY_CGROUP_V1\n1073741824\n100000 100000\n"
        changed=json.loads(encoded(report));changed["executable_fd_sha256"]="d"*64
        second=encoded(changed)+b"\nTOOLKIT_IDENTITY_CGROUP_V1\n1073741824\n100000 100000\n"
        obj.guest=Mock(side_effect=[(0,first,b""),(0,second,b"")])
        with patch.object(host.time,"time_ns",side_effect=[self.BASE,self.BASE+100,self.BASE+200,self.BASE+300]),patch.object(host,"rail_windows",return_value=rows):
            self.assertEqual(obj.observe_identity(0),identity())
            with self.assertRaises(host.Fault):obj.observe_identity(0)
        self.assertEqual(obj.guest.call_count,2);obj.save.assert_not_called()

    def test_runtime_identity_schema_keeps_exact_cgroup_limits_for_focus_and_shell(self):
        for memory,cpu in ((2147483648,"100000 100000"),(1073741824,"max 100000"),(1073741824,"100000 200000")):
            obj, report=self.fixture();obj.running_witness_saved=True;obj.rail={"hwnd":55,"pid":66,"birth":"77"}
            raw=encoded(report)+f"\nTOOLKIT_IDENTITY_CGROUP_V1\n{memory}\n{cpu}\n".encode()
            obj.guest=Mock(return_value=(0,raw,b""))
            with patch.object(host.time,"time_ns",side_effect=[self.BASE,self.BASE+100]),patch.object(host,"rail_windows",return_value=[{**obj.rail,"title":obj.tag,"visible":False}]),self.assertRaises(host.Fault):
                obj.observe_identity(0)
            obj.guest.assert_called_once()

    def test_collector_failure_and_foreign_registered_parent_do_not_publish(self):
        for foreign in (False, True):
            obj, report = self.fixture(); obj.guest = Mock(return_value=(7, encoded(report), b"failure"))
            if foreign: obj.guest_owners[9]["argv"] = ["foreign"]
            with self.assertRaises(host.Fault): obj.guest_identity()
            obj.save.assert_not_called()
            if foreign: obj.guest.assert_not_called()

    def test_launch_witness_refs_collector_registered_binding_and_exclusive_latch(self):
        obj, report = self.fixture(); raw = encoded(report)
        obj.guest = Mock(return_value=(0, raw, b""))
        with patch.object(host.time, "time_ns", side_effect=[self.BASE, self.BASE+100]): obj.guest_identity()
        obj.running_witness_saved = False
        obj.app_launch_started_ns = self.BASE-2000; obj.app_launch_observed_ns = self.BASE-1000
        obj.incarnation = {"created": "2026-10-23T00:00:00Z", "started_at": "2026-10-23T00:00:01Z", "nonce": "1"*32}
        container = {"container_id": "a"*64, "image_id": "sha256:"+"b"*64,
            **obj.incarnation, "owner": obj.cfg["owner"]}
        documents = {"context.json": encoded({"context": 1}), "container-start.json": encoded({"creator": 1}),
            "owner-config.json": encoded(obj.cfg), "wslc_host.py": b"frozen helper"}
        def ref(name):
            return {"path": "unit/"+name, "sha256": hashlib.sha256(documents[name]).hexdigest().upper()}
        documents["fixture-upload.json"] = encoded({"exit_code": 0, "container_id": "a"*64,
            "sha256": "c"*64, "target": cfg()["expected_identity"]["executable"],
            "provenance": {"schema": "toolkit-wslc-artifact-transfer-provenance-v1",
                "operation_id": "11111111-1111-4111-8111-111111111111", "container": container,
                "context": ref("context.json"), "creator_receipt": ref("container-start.json")}})
        def path(value, *args, **kwargs):
            value = Path(value)
            return Path(host.__file__) if value.name == "wslc_host.py" else host.ROOT / "unit" / value.name
        with patch.object(host, "host_path", side_effect=path), \
            patch.object(host, "read_bounded", side_effect=lambda p, cap: documents[Path(p).name]), \
            patch.object(host.time, "time_ns", return_value=self.BASE+101):
            obj.save_running_witness()
            self.assertTrue(obj.running_witness_saved)
            with self.assertRaises(host.Fault): obj.save_running_witness()
        obj.save.assert_called_once()
        name, witness = obj.save.call_args.args
        self.assertEqual(name, "running-executable-0001.json")
        self.assertEqual(witness["raw_kernel_report_utf8"], raw.decode())
        self.assertEqual(witness["collector_invocation"], obj.kernel_latest[3])
        self.assertEqual(witness["launch_binding"], {"app_pid": 10, "app_birth": "12", "parent_pid": 9,
            "parent_birth": "11", "launch_nonce": "e"*32, "parent_argv": obj.expected_commands()["app"][1],
            "started_unix_ns": str(self.BASE-2000), "observed_unix_ns": str(self.BASE-1000)})
        self.assertEqual(witness["context"], ref("context.json"))
        self.assertEqual(witness["helper"]["path"], "crates/toolkit-windows-automation/src/makepad_remote/wslc_host.py")
        self.assertEqual(witness["helper"]["sha256"], hashlib.sha256(b"frozen helper").hexdigest().upper())

    def test_stale_witness_or_invalid_launch_interval_cannot_publish(self):
        for stale in (False, True):
            obj, report = self.fixture(); obj.running_witness_saved = False
            obj.kernel_latest = (encoded(report), self.BASE, self.BASE+100, {})
            obj.app_launch_started_ns = self.BASE-10
            obj.app_launch_observed_ns = self.BASE-20 if not stale else self.BASE-5
            with patch.object(host.time, "time_ns", return_value=self.BASE+13_000_000_000 if stale else self.BASE+101):
                with self.assertRaises(host.Fault): obj.save_running_witness()
            obj.save.assert_not_called(); self.assertFalse(obj.running_witness_saved)

    def test_program_uses_retained_fds_elf_regular_single_link_and_no_guest_python(self):
        script = host.KERNEL_FD_PROGRAM
        for fragment in ('exec 3<"/proc/$pid/exe" 4<"$app"', 'sha256sum <&3', 'sha256sum <&4',
            'regular file', '$links == 1', '7f454c46', '[[ ! -L $current ]]', '/proc/$pid/ns/mnt',
            'parent_argv_after', 'AIUI_REMOTE_LAUNCH_NONCE=', 'date +%s%N'):
            self.assertIn(fragment, script)
        self.assertNotIn("python", script.lower())
        for fragment in ('$size -eq 366682664', 'ef=$(fdstat 3) || return 71',
                         'pf=$(fdstat 4) || return 71', 'before=$(snapshot) || exit 71', 'after=$(snapshot) || exit 71'):
            self.assertIn(fragment,script)

    def test_exact_large_module_report_requires_approved_sha_and_explicit_profile_limit(self):
        obj, report = self.fixture()
        expected=dict(obj.cfg["expected_identity"],executable_sha256=host.MODULE_ELF_SHA256)
        for stage in ("before","after"):
            for key in ("executable_fd_stat","guest_path_fd_stat"):report[stage][key]["size"]="366682664"
        for key in ("executable_fd_sha256","guest_path_fd_sha256"):report[key]=host.MODULE_ELF_SHA256.lower()
        args=(encoded(report),expected,10,obj.guest_owners[10],obj.guest_owners[9],obj.launch_nonces["app"],obj.port,self.BASE,self.BASE+100)
        self.assertEqual(host.kernel_fd_report(*args,max_executable_bytes=512*1024*1024),report)
        with self.assertRaises(host.Fault):host.kernel_fd_report(*args)
        with self.assertRaises(host.Fault):host.kernel_fd_report(encoded(report),dict(expected,executable_sha256="B"*64),*args[2:],max_executable_bytes=512*1024*1024)


class ModuleShellGuards(unittest.TestCase):
    def test_quit_resource_witness_uses_canonical_guarded_route(self):
        for target in ('/quit?if_user_seq=0','/quit?if_user_seq=1','/snap'):
            obj=bare_owner();obj.adopted=True;obj.cleaned=False;obj.cfg['profile_kind']='ModuleShell'
            obj.frozen=Mock();obj.validate=Mock(return_value={});obj._http_after_validation=Mock(return_value=(200,'{}'));obj.module_resources=Mock()
            obj.call('request',{'target':target,'mutating':target.startswith('/quit')})
            if target.startswith('/quit'):obj.module_resources.assert_called_once_with('before-quit')
            else:obj.module_resources.assert_not_called()
        for target in ('/quit','/quit?','/quit?arbitrary=1','/quit?if_user_seq=0&arbitrary=1'):
            obj.module_resources.reset_mock()
            with self.assertRaises(host.Fault):obj.call('request',{'target':target,'mutating':True})
            obj.module_resources.assert_not_called()

    def test_runtime_budget_is_fixed_by_trusted_profile_and_retains_focus_rpc_limits(self):
        self.assertEqual(host.profile_runtime_budget({}),(300,360,420.0))
        self.assertEqual(host.profile_runtime_budget({"profile_kind":"FocusFixture"}),(300,360,420.0))
        self.assertEqual(host.profile_runtime_budget({"profile_kind":"ModuleShell"}),(660,720,780.0))
        self.assertEqual(host.IO_TTL,30.0)
        obj=bare_owner();obj.cfg["profile_kind"]="ModuleShell"
        self.assertIn('660s',obj.expected_commands()["app"][1]);self.assertIn('720s',obj.expected_commands()["relay"][1])

    def test_startup_json_refusal_preserves_bounded_actual_body_and_original_failure(self):
        owner = object.__new__(host.Owner)
        owner.cfg = {"profile_kind":"ModuleShell","session_id":"synthetic","owner":"owned","generation":1}
        owner.context = {"container_id":"a"*64}; owner.pid = 123
        owner.save = Mock()
        self.assertEqual(owner.startup_state('{"pid":123,"w":[]}'), {"pid":123,"w":[]})
        owner.save.assert_not_called()
        for body, code in [('{"pid":',"WSLC_JSON_INVALID"), ('{"pid":1,"pid":2}',"WSLC_JSON_DUPLICATE_KEY")]:
            with self.assertRaises(host.Fault) as raised: owner.startup_state(body)
            self.assertEqual(raised.exception.code,code)
            name, receipt = owner.save.call_args.args
            self.assertEqual(name,"module-startup-state-refused.json")
            self.assertEqual(receipt["raw_utf8"],body)
            self.assertEqual(receipt["sha256"],hashlib.sha256(body.encode()).hexdigest().upper())
            self.assertEqual(receipt["error_code"],code)
        owner.cfg["profile_kind"]="FocusFixture";owner.save.reset_mock()
        with self.assertRaises(host.Fault):owner.startup_state('{')
        owner.save.assert_not_called()

    def module_config(self):
        value=cfg();value["profile_kind"]="ModuleShell"
        value["module_shell"]={"source_manifest_sha256":host.MODULE_SOURCE_SHA256}
        value["expected_identity"]["executable_sha256"]=host.MODULE_ELF_SHA256
        return value

    def test_module_config_binds_fixed_source_and_elf_without_ai_environment(self):
        value=self.module_config();self.assertEqual(host.config(value),value)
        self.assertEqual(host.profile_memory_max(value),2*1024**3)
        for field in ("source_manifest_sha256",):
            invalid=self.module_config();invalid["module_shell"][field]="A"*64
            with self.assertRaises(host.Fault):host.config(invalid)
        invalid=self.module_config();invalid["expected_identity"]["executable_sha256"]="A"*64
        with self.assertRaises(host.Fault):host.config(invalid)
        invalid=self.module_config();invalid["environment"]={"MAKEPAD_HOME":"/foreign"}
        with self.assertRaises(host.Fault):host.config(invalid)

    def test_module_two_gib_cannot_pass_the_legacy_identity_guard(self):
        value=identity();expected=self.module_config()["expected_identity"]
        value["executable_sha256"]=host.MODULE_ELF_SHA256;value["memory_max"]=2*1024**3
        with self.assertRaises(host.Fault):host.observed_identity(value,expected)
        self.assertEqual(host.observed_identity(value,expected,memory_max=host.MODULE_MEMORY_MAX),value)
        with self.assertRaises(host.Fault):host.observed_identity(value,expected,memory_max=True)

    def admission(self):
        return {"schema":host.MODULE_ADMISSION_SCHEMA,"owner":"unit-owner","utc":"2026-10-24T18:00:00Z",
            "source_manifest_sha256":host.MODULE_SOURCE_SHA256,"host_ram_mode":"USER_WAIVED","status":"USER_WAIVED",
            "available_memory_query_performed":False,"minimum_free_bytes":2684354560,"minimum_free_kib":2621440,
            "container_memory_bytes":2147483648,"container_cpus":1,"nested_increment_kib":0,
            "active_compiler_observation_performed":True,"active_rust_compilers":[],"resource_admitted":False,
            "scope":"one_outer_runtime_admission"}

    def test_module_admission_keeps_positive_budget_and_unknown_free_ram(self):
        value=self.admission();now=host.utc("2026-10-24T18:00:30Z")
        self.assertEqual(host.module_admission(value,"unit-owner",now),value)
        for key in ("free_physical_kib","command","unexpected"):
            invalid=dict(value);invalid[key]=123
            with self.assertRaises(host.Fault):host.module_admission(invalid,"unit-owner",now)
        for key,new in (("minimum_free_bytes",2147483648),("container_cpus",True),("resource_admitted",True),
                ("active_rust_compilers",[123]),("source_manifest_sha256","A"*64),("available_memory_query_performed",True)):
            invalid=dict(value);invalid[key]=new
            with self.assertRaises(host.Fault):host.module_admission(invalid,"unit-owner",now)
        with self.assertRaises(host.Fault):host.module_admission(value,"foreign",now)
        with self.assertRaises(host.Fault):host.module_admission(value,"unit-owner",host.utc("2026-10-24T18:03:00Z"))

    def test_module_creator_requires_exact_two_gib_and_fixed_environment(self):
        ctx,receipt,actual,expected,owner,now=creator_fixture()
        expected["executable_sha256"]=host.MODULE_ELF_SHA256
        ctx.update(wslc_profile="wslc_multi_module",module_shell_profile_kind="ModuleShell",
            module_shell_source_manifest_sha256=host.MODULE_SOURCE_SHA256)
        receipt["args"][6]="2G"
        receipt["args"][11:11]=[part for k,v in host.MODULE_ENV.items() for part in ("--env",k+"="+v)]
        actual["HostConfig"]["Memory"]=host.MODULE_MEMORY_MAX
        actual["Config"]["Env"]=[k+"="+v for k,v in host.MODULE_ENV.items()]
        self.assertEqual(host.exclusive_context(ctx,receipt,actual,expected,owner,now,
            memory_max=host.MODULE_MEMORY_MAX)["container_id"],expected["container_id"])
        with self.assertRaises(host.Fault):host.exclusive_context(ctx,receipt,actual,expected,owner,now)
        actual["Config"]["Env"].append("MAKEPAD_HOME=/foreign")
        with self.assertRaises(host.Fault):host.exclusive_context(ctx,receipt,actual,expected,owner,now,memory_max=host.MODULE_MEMORY_MAX)


class SoftStorageBudgets(unittest.TestCase):
    def test_host_budget_is_cumulative_and_failed_reservation_never_refunds(self):
        owner=bare_owner();owner.reserve_host_storage(128*1024*1024)
        self.assertEqual(owner.storage_host_reserved,128*1024*1024)
        with self.assertRaises(host.Fault) as refused:owner.reserve_host_storage(128*1024*1024)
        self.assertEqual(refused.exception.code,'WSLC_STORAGE_HOST_BUDGET_REFUSED')
        self.assertEqual(owner.storage_host_reserved,128*1024*1024)
        owner.cleaning=True;owner.reserve_host_storage(128*1024*1024)
        self.assertEqual(owner.storage_host_reserved,256*1024*1024)
    def test_missing_native_storage_observation_stops_before_any_input_and_cleanup_is_available(self):
        owner=bare_owner();owner.storage_monitor_enabled=True
        owner.storage_guard=Mock(side_effect=host.Fault('WSLC_USAGE_NOT_VERIFIED'))
        owner._request=Mock();owner.cleanup=Mock(return_value={'real_cleanup_port':'called'})
        with self.assertRaises(host.Fault):owner.call('request',{'target':'/t?w=0&text=ALPHA&if_user_seq=0','mutating':True})
        owner._request.assert_not_called()
        self.assertEqual(owner.call('cleanup',{}),{'real_cleanup_port':'called'})
    def test_quit_is_not_blocked_by_growth_refusal_and_is_not_automatically_replayed(self):
        owner=bare_owner();owner.storage_guard=Mock(side_effect=host.Fault('WSLC_USAGE_NOT_VERIFIED'))
        owner._request=Mock(return_value={'ack_only':True})
        self.assertEqual(owner.call('request',{'target':'/quit?if_user_seq=0','mutating':True}),{'ack_only':True})
        owner.storage_guard.assert_not_called();owner._request.assert_called_once()
    def test_capture_count_limit_refuses_before_copy_and_does_not_reset(self):
        owner=bare_owner();owner.last_grab=({},{});owner.storage_capture_count=4
        owner.guest=Mock()
        with self.assertRaises(host.Fault) as refused:owner.copy_frame({},1)
        self.assertEqual(refused.exception.code,'WSLC_STORAGE_CAPTURE_COUNT_REFUSED')
        owner.guest.assert_not_called();self.assertEqual(owner.storage_capture_count,4)


if __name__ == "__main__":
    unittest.main()

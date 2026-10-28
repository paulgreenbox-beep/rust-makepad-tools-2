"""Unit tests for the experimental in-process SessionManager core.

Mock Port injections below are infrastructure tests, not fixture or E2E proof.
"""

from __future__ import annotations

import copy
import hashlib
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Mapping

from manager import (
    ALLOWLIST,
    BackendCrashed,
    BackendOutOfMemory,
    BackendUnhealthy,
    EvidenceReference,
    EvidenceReferenceError,
    InputCleanupFailure,
    IdentityError,
    IdentityCollision,
    InvalidArguments,
    InvalidOperation,
    OwnerMismatch,
    PortResult,
    PostconditionMissing,
    RelayFailure,
    SessionCancelled,
    SessionCapacityError,
    SessionId,
    SessionManager,
    SessionNotFound,
    StopResult,
    StaleIdentity,
    UnsupportedOperation,
    VERIFIED_OPERATIONS,
)


def identity(
    *,
    pid: int = 4101,
    nonce: str = "nonce-1",
    container_id: str = "container-A",
) -> dict[str, Any]:
    return {
        "container_id": container_id,
        "linux_pid": pid,
        "process_start_ticks": pid * 10,
        "xid": pid * 100,
        "hwnd": pid * 1000,
        "rail_pid": pid + 50,
        "rail_start_ticks": pid * 20,
        "display": ":77",
        "application_nonce": nonce,
    }


def evidence_reference(
    session_id: SessionId,
    operation: str,
    path: str | Path,
    target_identity: Mapping[str, Any],
) -> EvidenceReference:
    if isinstance(path, Path):
        content = path.read_bytes()
    else:
        content = b""
    return EvidenceReference(
        session_id=session_id,
        operation=operation,
        path=path,
        sha256=hashlib.sha256(content).hexdigest(),
        target_identity=copy.deepcopy(dict(target_identity)),
    )


class MockPort:
    """Thread-safe contract mock; it does not launch or control a real app."""

    container_context_id = "container-A"

    def __init__(
        self,
        operations: set[str] | frozenset[str] = ALLOWLIST,
        *,
        identity_factory: Callable[[SessionId, int], Mapping[str, Any]] | None = None,
    ) -> None:
        self.operations = set(operations)
        self.identity_factory = identity_factory
        self.identities: dict[SessionId, dict[str, Any]] = {}
        self.session_roots: dict[SessionId, Path] = {}
        self.start_count = 0
        self.start_error: BaseException | None = None
        self.stale_sessions: set[SessionId] = set()
        self.validation_calls: list[SessionId] = []
        self.perform_errors: dict[str, BaseException] = {}
        self.perform_hook: Callable[[dict[str, Any]], PortResult] | None = None
        self.health = True
        self.release_ok = True
        self.stop_errors_remaining = 0
        self.stop_process_stopped = True
        self.stop_inputs_released = True
        self.stop_calls: list[SessionId] = []
        self.perform_calls: list[dict[str, Any]] = []
        self.release_calls: list[dict[str, Any]] = []
        self.press_ledger: dict[SessionId, set[str]] = {}
        self.release_target_identities: dict[SessionId, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._active_performs = 0
        self.max_active_performs = 0

    def implemented_operations(self):
        return frozenset(self.operations)

    def success_result(
        self, call: dict[str, Any], payload: Any = None
    ) -> PortResult:
        operation = call["operation"]
        session_id = call["session_id"]
        evidence_ref = None
        if operation in VERIFIED_OPERATIONS:
            path = self.session_roots[session_id] / f"capture-{len(self.perform_calls)}.bin"
            path.write_bytes(b"mock artifact")
            evidence_ref = evidence_reference(
                session_id, operation, path, call["identity"]
            )
        return PortResult(
            payload=payload if payload is not None else {"operation": operation},
            postcondition_verified=True if operation in VERIFIED_OPERATIONS else None,
            evidence_ref=evidence_ref,
            target_identity=call["identity"],
        )

    def start_session(
        self, *, session_id: SessionId, app_alias: str, evidence_root: Path
    ) -> Mapping[str, Any]:
        self.start_count += 1
        self.session_roots[session_id] = evidence_root
        if self.start_error is not None:
            raise self.start_error
        if self.identity_factory is not None:
            value = self.identity_factory(session_id, self.start_count)
        else:
            value = identity(pid=4100 + self.start_count, nonce=f"nonce-{self.start_count}")
        self.identities[session_id] = copy.deepcopy(dict(value))
        return copy.deepcopy(dict(value))

    def validate_identity(
        self, *, session_id: SessionId, identity: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        value = copy.deepcopy(self.identities[session_id])
        self.validation_calls.append(session_id)
        if session_id in self.stale_sessions:
            value["linux_pid"] += 1
        return value

    def perform(
        self,
        *,
        session_id: SessionId,
        identity: Mapping[str, Any],
        operation: str,
        arguments: Mapping[str, Any],
        cancel_event: threading.Event,
    ) -> PortResult:
        call = {
            "session_id": session_id,
            "identity": copy.deepcopy(dict(identity)),
            "operation": operation,
            "arguments": copy.deepcopy(dict(arguments)),
            "cancel_event": cancel_event,
        }
        with self._lock:
            self.perform_calls.append(call)
            self._active_performs += 1
            self.max_active_performs = max(
                self.max_active_performs, self._active_performs
            )
            if operation in {"click", "drag", "wheel", "key", "type", "hotkey"}:
                self.press_ledger.setdefault(session_id, set()).add(operation)
        try:
            error = self.perform_errors.get(operation)
            if error is not None:
                raise error
            if self.perform_hook is not None:
                return self.perform_hook(call)
            return self.success_result(call, {"operation": operation, "observed": True})
        finally:
            with self._lock:
                self._active_performs -= 1

    def health_check(
        self, *, session_id: SessionId, identity: Mapping[str, Any]
    ) -> bool:
        return self.health

    def release_inputs(
        self, *, session_id: SessionId
    ) -> bool:
        with self._lock:
            self.release_calls.append({"session_id": session_id})
            authoritative = self.identities.get(session_id)
            if authoritative is not None:
                self.release_target_identities[session_id] = copy.deepcopy(authoritative)
            if not self.release_ok:
                return False
            self.press_ledger.pop(session_id, None)
            return True

    def stop_session(
        self, *, session_id: SessionId
    ) -> StopResult:
        self.stop_calls.append(session_id)
        if self.stop_errors_remaining:
            self.stop_errors_remaining -= 1
            raise RelayFailure("injected stop relay failure")
        result = StopResult(
            session_id=session_id,
            process_stopped=self.stop_process_stopped,
            inputs_released=self.stop_inputs_released,
        )
        if result.inputs_released is True:
            self.press_ledger.pop(session_id, None)
        return result


class SessionManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.owner = object()
        self.port = MockPort()
        self.manager = SessionManager(
            self.port,
            app_alias="workspace-fixture",
            evidence_root=Path(self.temp.name) / "evidence",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def new_running_session(
        self, manager: SessionManager | None = None, owner: object | None = None
    ) -> tuple[SessionManager, MockPort, object, SessionId]:
        manager = manager or self.manager
        port = manager._port
        owner = self.owner if owner is None else owner
        session_id = manager.create_session(owner)
        manager.start_session(session_id, owner)
        return manager, port, owner, session_id

    def test_wrong_session_id_never_falls_back_to_an_active_session(self) -> None:
        _, port, owner, _ = self.new_running_session()
        with self.assertRaises(SessionNotFound):
            self.manager.dispatch(SessionId("not-a-live-session"), owner, "window.inspect")
        self.assertEqual(port.perform_calls, [])

    def test_cross_owner_is_rejected_before_dispatch(self) -> None:
        _, port, _, session_id = self.new_running_session()
        with self.assertRaises(OwnerMismatch):
            self.manager.dispatch(session_id, object(), "window.inspect")
        self.assertEqual(port.perform_calls, [])

    def test_owner_is_an_in_process_object_not_a_caller_string(self) -> None:
        with self.assertRaises(TypeError):
            self.manager.create_session("coordinator-owner")

    def test_fixed_capacity_is_two_sessions_per_container_context(self) -> None:
        first = self.manager.create_session(self.owner)
        second = self.manager.create_session(self.owner)
        self.assertNotEqual(first, second)
        with self.assertRaises(SessionCapacityError):
            self.manager.create_session(self.owner)

    def test_partial_live_identity_collisions_cleanup_only_the_new_session(self) -> None:
        for field in ("linux_pid", "xid", "hwnd"):
            with self.subTest(shared_field=field):
                temp = TemporaryDirectory()
                try:
                    owner = object()
                    shared = identity(pid=4999, nonce="first")

                    def factory(_sid: SessionId, number: int) -> Mapping[str, Any]:
                        if number == 1:
                            return shared
                        candidate = identity(pid=5999, nonce="second")
                        candidate[field] = shared[field]
                        return candidate

                    port = MockPort(identity_factory=factory)
                    manager = SessionManager(
                        port,
                        app_alias="workspace-fixture",
                        evidence_root=Path(temp.name) / "evidence",
                    )
                    first = manager.create_session(owner)
                    manager.start_session(first, owner)
                    second = manager.create_session(owner)
                    port.stop_errors_remaining = 1
                    with self.assertRaises(IdentityCollision):
                        manager.start_session(second, owner)
                    self.assertEqual(port.stop_calls, [second])
                    self.assertEqual(manager.inspect_session(first, owner)["state"], "running")
                    failed = manager.inspect_session(second, owner)
                    self.assertEqual(failed["state"], "failed")
                    self.assertEqual(
                        failed["stop_errors"][0]["classification"], "relay_failure"
                    )
                    manager.stop_session(second, owner)
                    self.assertEqual(port.stop_calls, [second, second])
                    self.assertEqual(port.release_calls[-1], {"session_id": second})
                    self.assertEqual(manager.inspect_session(first, owner)["state"], "running")
                finally:
                    temp.cleanup()

        temp = TemporaryDirectory()
        try:
            owner = object()
            shared = identity(pid=6991, nonce="rail-owner-one")

            def shared_rail(_sid: SessionId, number: int) -> Mapping[str, Any]:
                value = shared if number == 1 else identity(pid=6992, nonce="rail-owner-two")
                value = copy.deepcopy(dict(value))
                value["rail_pid"] = shared["rail_pid"]
                value["rail_start_ticks"] = shared["rail_start_ticks"]
                return value

            port = MockPort(identity_factory=shared_rail)
            manager = SessionManager(
                port,
                app_alias="workspace-fixture",
                evidence_root=Path(temp.name) / "rail-evidence",
            )
            first = manager.create_session(owner)
            second = manager.create_session(owner)
            manager.start_session(first, owner)
            manager.start_session(second, owner)
            self.assertEqual(manager.inspect_session(second, owner)["state"], "running")
        finally:
            temp.cleanup()

    def test_fresh_identity_mismatch_fails_closed_before_backend_dispatch(self) -> None:
        _, port, owner, session_id = self.new_running_session()
        port.stale_sessions.add(session_id)
        with self.assertRaises(StaleIdentity):
            self.manager.dispatch(session_id, owner, "window.inspect")
        self.assertEqual(port.perform_calls, [])
        self.assertEqual(self.manager.inspect_session(session_id, owner)["state"], "failed")

    def test_backend_action_target_identity_must_match_the_fresh_session(self) -> None:
        _, port, owner, session_id = self.new_running_session()

        def wrong_capture_target(call: dict[str, Any]) -> PortResult:
            wrong = copy.deepcopy(call["identity"])
            wrong["hwnd"] += 1
            return PortResult(
                payload={"capture": "mock"},
                target_identity=wrong,
                postcondition_verified=True,
            )

        port.perform_hook = wrong_capture_target
        with self.assertRaises(StaleIdentity):
            self.manager.dispatch(session_id, owner, "capture")
        self.assertEqual(self.manager.inspect_session(session_id, owner)["state"], "failed")

    def test_identity_turnover_after_press_uses_only_session_owned_release(self) -> None:
        manager, port, owner, session_a = self.new_running_session()
        session_b = manager.create_session(owner)
        manager.start_session(session_b, owner)

        def turnover_after_press(call: dict[str, Any]) -> PortResult:
            result = port.success_result(call)
            port.identities[session_a]["linux_pid"] += 1
            return result

        port.perform_hook = turnover_after_press
        with self.assertRaises(StaleIdentity):
            manager.dispatch(session_a, owner, "click", {"x": 8, "y": 9})

        self.assertEqual(port.release_calls[-1], {"session_id": session_a})
        self.assertEqual(
            port.release_target_identities[session_a], port.identities[session_a]
        )
        self.assertNotIn(session_a, port.press_ledger)
        self.assertEqual(manager.journal(1)[0]["status"], "FAIL")
        port.perform_hook = None
        self.assertEqual(
            manager.dispatch(session_b, owner, "window.inspect")["status"], "PASS"
        )
        self.assertEqual(manager.inspect_session(session_b, owner)["state"], "running")

    def test_interrupted_typing_and_key_operations_release_backend_press_ledger(self) -> None:
        manager, port, owner, session_id = self.new_running_session()
        cases = (
            ("type", {"text": "A"}),  # Backend may use implicit Shift.
            ("key", {"key": "CTRL"}),
            ("key", {"key": "A"}),  # Ordinary keys are not tracked by core state.
            ("hotkey", {"keys": ["CTRL", "A"]}),
        )
        for operation, arguments in cases:
            with self.subTest(operation=operation, arguments=arguments):
                entered = threading.Event()
                result: list[BaseException | dict[str, Any]] = []

                def hold_until_cancel(call: dict[str, Any]) -> PortResult:
                    entered.set()
                    call["cancel_event"].wait(1)
                    return port.success_result(call)

                port.perform_hook = hold_until_cancel

                def run() -> None:
                    try:
                        result.append(
                            manager.dispatch(session_id, owner, operation, arguments)
                        )
                    except BaseException as exc:
                        result.append(exc)

                thread = threading.Thread(target=run)
                thread.start()
                self.assertTrue(entered.wait(1))
                self.assertTrue(manager.cancel(session_id, owner))
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(len(result), 1)
                self.assertIsInstance(result[0], SessionCancelled)
                self.assertEqual(port.release_calls[-1], {"session_id": session_id})
                self.assertNotIn(session_id, port.press_ledger)
                self.assertEqual(manager.journal(1)[0]["status"], "CANCELLED")

    def test_release_refusal_is_typed_failure_and_preserves_logical_state(self) -> None:
        manager, port, owner, session_id = self.new_running_session()
        port.release_ok = False
        with self.assertRaises(InputCleanupFailure):
            manager.dispatch(session_id, owner, "key", {"key": "CTRL"})
        snapshot = manager.inspect_session(session_id, owner)
        self.assertEqual(snapshot["state"], "failed")
        self.assertEqual(snapshot["modifiers"], ["CTRL"])
        self.assertEqual(port.release_calls[-1], {"session_id": session_id})
        self.assertEqual(manager.journal(1)[0]["status"], "FAIL")

    def test_process_and_rail_start_ticks_must_be_positive(self) -> None:
        for field in ("process_start_ticks", "rail_start_ticks"):
            with self.subTest(field=field):
                temp = TemporaryDirectory()
                try:
                    owner = object()
                    malformed = identity(pid=7201)
                    malformed[field] = 0
                    port = MockPort(identity_factory=lambda _sid, _n: malformed)
                    manager = SessionManager(
                        port,
                        app_alias="workspace-fixture",
                        evidence_root=Path(temp.name) / "evidence",
                    )
                    session_id = manager.create_session(owner)
                    with self.assertRaises(IdentityError):
                        manager.start_session(session_id, owner)
                    self.assertEqual(port.stop_calls, [session_id])
                finally:
                    temp.cleanup()

    def test_inspection_is_a_deep_copy_including_trusted_identity(self) -> None:
        _, port, owner, session_id = self.new_running_session()
        first = self.manager.inspect_session(session_id, owner)
        original_pid = first["identity"]["linux_pid"]
        first["identity"]["linux_pid"] = 1
        first["identity"]["application_nonce"] = "attacker"
        first["cleanup_errors"].append({"type": "injected"})
        later = self.manager.inspect_session(session_id, owner)
        self.assertEqual(later["identity"]["linux_pid"], original_pid)
        self.assertEqual(later["identity"]["application_nonce"], "nonce-1")
        self.assertEqual(later["cleanup_errors"], [])
        result = self.manager.dispatch(session_id, owner, "window.inspect")
        self.assertEqual(result["status"], "PASS")

    def test_unadvertised_allowlisted_resize_is_typed_unsupported(self) -> None:
        port = MockPort(ALLOWLIST - {"window.resize"})
        manager = SessionManager(
            port, app_alias="workspace-fixture", evidence_root=Path(self.temp.name) / "resize"
        )
        session_id = manager.create_session(self.owner)
        manager.start_session(session_id, self.owner)
        with self.assertRaises(UnsupportedOperation) as caught:
            manager.dispatch(session_id, self.owner, "window.resize", {"width": 20, "height": 10})
        self.assertEqual(caught.exception.operation, "window.resize")
        self.assertEqual(port.perform_calls, [])

    def test_unknown_operation_is_rejected_without_backend_call(self) -> None:
        _, port, owner, session_id = self.new_running_session()
        with self.assertRaises(InvalidOperation):
            self.manager.dispatch(session_id, owner, "window.launch")
        self.assertEqual(port.perform_calls, [])

    def test_constructor_and_arguments_refuse_unapproved_app_or_path_selection(self) -> None:
        with self.assertRaises(ValueError):
            SessionManager(
                self.port,
                app_alias="arbitrary-executable",
                evidence_root=Path(self.temp.name) / "bad-alias",
            )
        _, port, owner, session_id = self.new_running_session()
        with self.assertRaises(InvalidArguments):
            self.manager.dispatch(
                session_id,
                owner,
                "window.move",
                {"x": 4, "y": 8, "executable_path": "C:/untrusted/app.exe"},
            )
        self.assertEqual(port.perform_calls, [])

    def test_nested_identity_and_target_aliases_are_rejected_before_port_dispatch(self) -> None:
        _, port, owner, session_id = self.new_running_session()
        aliases = (
            "pid",
            "linuxPid",
            "process_start_ticks",
            "xid",
            "targetXid",
            "target_window_handle",
            "hwnd",
            "window_handle",
            "window_hwnd",
            "window_xid",
            "native_window_id",
            "target_window_id",
            "containerId",
            "display",
            "display_name",
            "applicationNonce",
            "app_nonce",
            "railPid",
            "process_id",
            "session_id",
            "owner",
            "identity",
            "path",
            "active_window",
            "selector",
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                with self.assertRaises(InvalidArguments):
                    self.manager.dispatch(
                        session_id,
                        owner,
                        "window.inspect",
                        {"nested": {alias: "caller-selected-target"}},
                    )
        self.assertEqual(port.perform_calls, [])

    def test_capture_and_wait_state_require_postcondition_health_and_attested_evidence(self) -> None:
        failures = (
            ("postcondition", PostconditionMissing),
            ("health", BackendUnhealthy),
            ("evidence", EvidenceReferenceError),
        )
        for operation in ("capture", "wait_state"):
            for failure, expected_error in failures:
                with self.subTest(operation=operation, failure=failure):
                    temp = TemporaryDirectory()
                    try:
                        owner = object()
                        port = MockPort()
                        manager = SessionManager(
                            port,
                            app_alias="workspace-fixture",
                            evidence_root=Path(temp.name) / "evidence",
                        )
                        session_id = manager.create_session(owner)
                        manager.start_session(session_id, owner)
                        if failure == "postcondition":
                            port.perform_hook = lambda call: PortResult(
                                target_identity=call["identity"],
                                postcondition_verified=False,
                            )
                        elif failure == "health":
                            port.health = "PASS"
                        else:
                            port.perform_hook = lambda call: PortResult(
                                target_identity=call["identity"],
                                postcondition_verified=True,
                                evidence_ref="path-only-is-not-an-attestation",
                            )
                        with self.assertRaises(expected_error):
                            manager.dispatch(session_id, owner, operation)
                    finally:
                        temp.cleanup()

    def test_mutating_pass_requires_backend_postcondition(self) -> None:
        _, port, owner, session_id = self.new_running_session()
        port.perform_hook = lambda call: PortResult(
            status="PASS",
            payload={"changed": True},
            target_identity=call["identity"],
            postcondition_verified=False,
        )
        with self.assertRaises(PostconditionMissing):
            self.manager.dispatch(session_id, owner, "window.move", {"x": 10, "y": 20})
        self.assertEqual(self.manager.inspect_session(session_id, owner)["state"], "failed")

    def test_mutating_pass_requires_healthy_backend(self) -> None:
        _, port, owner, session_id = self.new_running_session()
        port.health = False
        with self.assertRaises(BackendUnhealthy):
            self.manager.dispatch(session_id, owner, "window.move", {"x": 10, "y": 20})
        self.assertEqual(self.manager.inspect_session(session_id, owner)["state"], "failed")

    def test_mutating_pass_requires_existing_session_owned_evidence(self) -> None:
        _, port, owner, session_id = self.new_running_session()
        port.perform_hook = lambda call: PortResult(
            status="PASS",
            payload={},
            target_identity=call["identity"],
            postcondition_verified=True,
        )
        with self.assertRaises(EvidenceReferenceError):
            self.manager.dispatch(session_id, owner, "window.hide")
        self.assertEqual(self.manager.inspect_session(session_id, owner)["state"], "failed")

    def test_capture_rejects_path_traversal(self) -> None:
        _, port, owner, session_id = self.new_running_session()
        port.perform_hook = lambda call: PortResult(
            status="PASS",
            payload={},
            target_identity=call["identity"],
            postcondition_verified=True,
            evidence_ref=evidence_reference(
                session_id, "capture", "../outside.bin", call["identity"]
            ),
        )
        with self.assertRaises(EvidenceReferenceError):
            self.manager.dispatch(session_id, owner, "capture")

    def test_capture_rejects_an_artifact_owned_by_another_session(self) -> None:
        manager, port, owner, session_a = self.new_running_session()
        session_b = manager.create_session(owner)
        manager.start_session(session_b, owner)
        artifact_a = port.session_roots[session_a] / "a.bin"
        artifact_a.write_bytes(b"A session artifact")
        port.perform_hook = lambda call: PortResult(
            status="PASS",
            payload={},
            target_identity=call["identity"],
            postcondition_verified=True,
            evidence_ref=evidence_reference(
                session_a, "capture", artifact_a, port.identities[session_a]
            ),
        )
        with self.assertRaises(EvidenceReferenceError):
            manager.dispatch(session_b, owner, "capture")

    def test_capture_accepts_only_existing_files_inside_its_session_root(self) -> None:
        _, _port, owner, session_id = self.new_running_session()
        result = self.manager.dispatch(session_id, owner, "capture")
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(Path(result["evidence_ref"]["path"]).is_file())

    def test_window_close_routes_through_stop_and_never_reports_action_pass(self) -> None:
        manager, port, owner, session_id = self.new_running_session()
        validation_count = len(port.validation_calls)
        result = manager.dispatch(session_id, owner, "window.close")
        self.assertEqual(result["status"], "STOPPED")
        self.assertEqual(manager.inspect_session(session_id, owner)["state"], "stopped")
        self.assertEqual(port.perform_calls, [])
        self.assertEqual(len(port.validation_calls), validation_count + 1)
        self.assertEqual(manager.journal(1)[0]["status"], "STOPPED")

    def test_window_close_is_typed_unsupported_when_not_advertised(self) -> None:
        port = MockPort(ALLOWLIST - {"window.close"})
        manager = SessionManager(
            port, app_alias="workspace-fixture", evidence_root=Path(self.temp.name) / "no-close"
        )
        session_id = manager.create_session(self.owner)
        manager.start_session(session_id, self.owner)
        with self.assertRaises(UnsupportedOperation):
            manager.dispatch(session_id, self.owner, "window.close")
        self.assertEqual(manager.inspect_session(session_id, self.owner)["state"], "running")
        self.assertEqual(port.stop_calls, [])

    def test_cancel_signals_only_the_selected_session(self) -> None:
        manager, port, owner, session_a = self.new_running_session()
        session_b = manager.create_session(owner)
        manager.start_session(session_b, owner)
        entered_a = threading.Event()
        b_cancel_seen = threading.Event()
        outcomes: list[BaseException | dict[str, Any]] = []

        def hook(call: dict[str, Any]) -> PortResult:
            if call["session_id"] == session_a:
                entered_a.set()
                call["cancel_event"].wait(2)
                return port.success_result(call, {"finished": True})
            if call["cancel_event"].is_set():
                b_cancel_seen.set()
            return port.success_result(call, {"session": "B"})

        port.perform_hook = hook

        def run_a() -> None:
            try:
                outcomes.append(manager.dispatch(session_a, owner, "wait_state"))
            except BaseException as exc:
                outcomes.append(exc)

        thread_a = threading.Thread(target=run_a)
        thread_a.start()
        self.assertTrue(entered_a.wait(1))
        self.assertTrue(manager.cancel(session_a, owner))
        result_b = manager.dispatch(session_b, owner, "wait_state")
        thread_a.join(2)
        self.assertFalse(thread_a.is_alive())
        self.assertEqual(result_b["status"], "PASS")
        self.assertFalse(b_cancel_seen.is_set())
        self.assertEqual(len(outcomes), 1)
        self.assertIsInstance(outcomes[0], SessionCancelled)

    def test_two_sessions_can_really_overlap_in_two_mock_backend_threads(self) -> None:
        manager, port, owner, session_a = self.new_running_session()
        session_b = manager.create_session(owner)
        manager.start_session(session_b, owner)
        overlap = threading.Barrier(2)
        results: list[dict[str, Any]] = []
        errors: list[BaseException] = []

        def hook(call: dict[str, Any]) -> PortResult:
            overlap.wait(timeout=2)
            return port.success_result(call, {"overlapped": True})

        port.perform_hook = hook

        def run(session_id: SessionId) -> None:
            try:
                results.append(manager.dispatch(session_id, owner, "wait_state"))
            except BaseException as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=run, args=(session_a,)),
            threading.Thread(target=run, args=(session_b,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(port.max_active_performs, 2)

    def test_operations_for_the_same_session_are_serial(self) -> None:
        manager, port, owner, session_id = self.new_running_session()
        ready = threading.Barrier(3)
        errors: list[BaseException] = []

        def hook(call: dict[str, Any]) -> PortResult:
            time.sleep(0.04)
            return port.success_result(call, {"serial": True})

        port.perform_hook = hook

        def run() -> None:
            ready.wait(timeout=2)
            try:
                manager.dispatch(session_id, owner, "wait_state")
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=run), threading.Thread(target=run)]
        for thread in threads:
            thread.start()
        ready.wait(timeout=2)
        for thread in threads:
            thread.join(2)
        self.assertEqual(errors, [])
        self.assertEqual(port.max_active_performs, 1)

    def test_pointer_modifiers_and_buttons_are_released_in_finally(self) -> None:
        manager, port, owner, session_id = self.new_running_session()

        def fail_after_press(_call: dict[str, Any]) -> PortResult:
            raise RelayFailure("injected action relay failure")

        port.perform_hook = fail_after_press
        with self.assertRaises(RelayFailure):
            manager.dispatch(
                session_id,
                owner,
                "drag",
                {"x": 30, "y": 45, "button": "right", "modifiers": ["CTRL"]},
            )
        snapshot = manager.inspect_session(session_id, owner)
        self.assertEqual(snapshot["pointer"], {"x": 30, "y": 45})
        self.assertEqual(snapshot["buttons"], [])
        self.assertEqual(snapshot["modifiers"], [])
        self.assertEqual(port.release_calls[-1], {"session_id": session_id})

    def test_partial_start_failure_attempts_cleanup_and_remains_idempotent(self) -> None:
        partial = identity(pid=6001, nonce="partial")
        self.port.start_error = BackendCrashed(
            "mock start crash", partial_identity=partial
        )
        session_id = self.manager.create_session(self.owner)
        with self.assertRaises(BackendCrashed):
            self.manager.start_session(session_id, self.owner)
        first = self.manager.inspect_session(session_id, self.owner)
        self.assertEqual(first["state"], "failed")
        self.assertTrue(first["resource_released"])
        self.assertEqual(first["identity"]["linux_pid"], 6001)
        self.assertEqual(self.port.stop_calls, [session_id])
        self.manager.stop_session(session_id, self.owner)
        self.assertEqual(self.port.stop_calls, [session_id])

    def test_stopping_created_session_is_idempotent_and_stop_errors_are_preserved(self) -> None:
        created = self.manager.create_session(self.owner)
        self.manager.stop_session(created, self.owner)
        self.manager.stop_session(created, self.owner)
        self.assertEqual(self.port.stop_calls, [created])
        self.assertEqual(self.manager.inspect_session(created, self.owner)["state"], "stopped")

        running = self.manager.create_session(self.owner)
        self.manager.start_session(running, self.owner)
        self.port.stop_errors_remaining = 1
        first = self.manager.stop_session(running, self.owner)
        self.assertEqual(first["state"], "failed")
        self.assertEqual(first["stop_errors"][0]["classification"], "relay_failure")
        second = self.manager.stop_session(running, self.owner)
        self.assertEqual(second["state"], "stopped")
        self.assertEqual(len(second["stop_errors"]), 1)
        count = len(self.port.stop_calls)
        self.manager.stop_session(running, self.owner)
        self.assertEqual(len(self.port.stop_calls), count)

    def test_stop_requires_release_confirmation_and_retries_without_losing_errors(self) -> None:
        manager, port, owner, session_id = self.new_running_session()
        port.release_ok = False
        port.perform_hook = lambda _call: (_ for _ in ()).throw(
            RelayFailure("injected action relay failure")
        )
        with self.assertRaises(RelayFailure):
            manager.dispatch(
                session_id, owner, "drag", {"x": 12, "y": 18, "button": "left"}
            )

        port.stop_inputs_released = False
        failed = manager.stop_session(session_id, owner)
        self.assertEqual(failed["state"], "failed")
        self.assertFalse(failed["resource_released"])
        self.assertEqual(manager.journal(1)[0]["status"], "FAIL")
        self.assertGreaterEqual(len(failed["stop_errors"]), 1)

        port.release_ok = True
        port.stop_inputs_released = True
        stopped = manager.stop_session(session_id, owner)
        self.assertEqual(stopped["state"], "stopped")
        self.assertTrue(stopped["resource_released"])
        self.assertGreaterEqual(len(stopped["stop_errors"]), 1)

    def test_relay_failure_is_classified_without_claiming_pass(self) -> None:
        manager, port, owner, session_id = self.new_running_session()
        port.perform_errors["wait_state"] = RelayFailure("mock relay unavailable")
        with self.assertRaises(RelayFailure):
            manager.dispatch(session_id, owner, "wait_state")
        entry = manager.journal(1)[0]
        self.assertEqual(entry["status"], "FAIL")
        self.assertEqual(entry["result"]["classification"], "relay_failure")
        self.assertEqual(manager.inspect_session(session_id, owner)["state"], "running")

    def test_crash_and_oom_failures_have_distinct_classifications(self) -> None:
        cases = (
            (BackendCrashed("mock crash"), "backend_crash"),
            (BackendOutOfMemory("mock OOM"), "backend_oom"),
        )
        for index, (error, expected) in enumerate(cases):
            with self.subTest(classification=expected):
                temp = TemporaryDirectory()
                try:
                    owner = object()
                    port = MockPort()
                    manager = SessionManager(
                        port,
                        app_alias="workspace-fixture",
                        evidence_root=Path(temp.name) / f"evidence-{index}",
                    )
                    session_id = manager.create_session(owner)
                    manager.start_session(session_id, owner)
                    port.perform_errors["wait_state"] = error
                    with self.assertRaises(type(error)):
                        manager.dispatch(session_id, owner, "wait_state")
                    snapshot = manager.inspect_session(session_id, owner)
                    self.assertEqual(snapshot["state"], "failed")
                    self.assertEqual(snapshot["failure_class"], expected)
                    self.assertEqual(manager.journal(1)[0]["result"]["classification"], expected)
                finally:
                    temp.cleanup()

    def test_unapproved_operation_attempts_are_journaled_without_payload_text(self) -> None:
        _, port, owner, session_id = self.new_running_session()
        secret_text = "private typed content"
        port.perform_hook = lambda call: PortResult(
            payload={"text": secret_text}, target_identity=call["identity"]
        )
        result = self.manager.dispatch(session_id, owner, "window.inspect")
        self.assertEqual(result["payload"]["text"], secret_text)
        entry = self.manager.journal(1)[0]
        self.assertNotIn(secret_text, repr(entry))
        with self.assertRaises(InvalidOperation):
            self.manager.dispatch(session_id, owner, "launch")
        self.assertEqual(self.manager.journal(1)[0]["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()

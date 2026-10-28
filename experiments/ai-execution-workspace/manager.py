"""Bounded, in-process experimental session manager.

This module is deliberately not a network service, public MCP integration, or
durable session store. The coordinator supplies an in-process owner object.
Only the fixed workspace-fixture alias can be started; callers never supply an
executable or launch path.
"""

from __future__ import annotations

import copy
import hashlib
import math
import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


APPROVED_APP_ALIAS = "workspace-fixture"
MAX_SESSIONS_PER_CONTAINER = 2
JOURNAL_LIMIT = 256
_JOURNAL_MESSAGE_LIMIT = 192

ALLOWLIST = frozenset(
    {
        "click",
        "drag",
        "wheel",
        "key",
        "type",
        "hotkey",
        "session.keyboard.batch",
        "ui.set_value",
        "window.inspect",
        "window.move",
        "window.resize",
        "window.hide",
        "window.show",
        "window.close",
        "pointer.inspect",
        "cursor.inspect",
        "capture",
        "wait_state",
        "health",
        "evidence",
    }
)

MUTATING_OPERATIONS = frozenset(
    {
        "click",
        "drag",
        "wheel",
        "key",
        "type",
        "hotkey",
        "session.keyboard.batch",
        "ui.set_value",
        "window.move",
        "window.resize",
        "window.hide",
        "window.show",
        "window.close",
    }
)
VERIFIED_OPERATIONS = MUTATING_OPERATIONS | frozenset({"capture", "wait_state"})

_INPUT_OPERATIONS = frozenset({"click", "drag", "wheel", "key", "type", "hotkey", "session.keyboard.batch"})
_MODIFIER_KEYS = frozenset({"SHIFT", "CTRL", "CONTROL", "ALT", "META", "WIN", "SUPER"})
_FORBIDDEN_ARGUMENT_KEYS = frozenset(
    {
        "app",
        "application",
        "applicationidentity",
        "applicationnonce",
        "appnonce",
        "applicationpath",
        "applicationid",
        "appidentity",
        "appid",
        "apppath",
        "argv",
        "binary",
        "command",
        "container",
        "containercontextid",
        "containercontext",
        "containerid",
        "cwd",
        "display",
        "displayid",
        "displayname",
        "exe",
        "executable",
        "executablepath",
        "handle",
        "handleid",
        "hwnd",
        "identity",
        "linuxpid",
        "nativehandle",
        "nativehwnd",
        "nativewindow",
        "nativewindowhandle",
        "nativewindowid",
        "nonce",
        "outputpath",
        "owner",
        "ownerid",
        "path",
        "pid",
        "processid",
        "processidentity",
        "processname",
        "processpath",
        "processstartticks",
        "program",
        "railid",
        "railpid",
        "railstartticks",
        "sessionid",
        "startticks",
        "target",
        "targethwnd",
        "targethandle",
        "targetwindowhandle",
        "targetidentity",
        "targetwindow",
        "targetwindowid",
        "targetxid",
        "targetxwindowid",
        "selector",
        "activewindow",
        "window",
        "windowhwnd",
        "windowhandle",
        "windowid",
        "windowidentity",
        "windowtitle",
        "windowxid",
        "xdisplay",
        "workingdirectory",
        "xid",
        "xwindow",
        "xwindowid",
    }
)

_IDENTITY_FIELDS = (
    "container_id",
    "linux_pid",
    "process_start_ticks",
    "xid",
    "hwnd",
    "rail_pid",
    "rail_start_ticks",
    "display",
    "application_nonce",
)


class SessionError(RuntimeError):
    """Base class for typed manager failures."""

    classification = "session_error"


class SessionNotFound(SessionError):
    classification = "session_not_found"


class OwnerMismatch(SessionError):
    classification = "owner_mismatch"


class SessionCapacityError(SessionError):
    classification = "session_capacity"


class SessionLifecycleError(SessionError):
    classification = "lifecycle_error"


class InvalidOperation(SessionError):
    classification = "invalid_operation"


class UnsupportedOperation(SessionError):
    classification = "unsupported_operation"

    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(f"backend does not advertise {operation!r}")


class InvalidArguments(SessionError):
    classification = "invalid_arguments"


class PortContractError(SessionError):
    classification = "port_contract_error"


class IdentityError(SessionError):
    classification = "identity_invalid"


class StaleIdentity(IdentityError):
    classification = "identity_stale"


class IdentityCollision(IdentityError):
    classification = "identity_collision"


class OperationFailed(SessionError):
    classification = "operation_failed"


class PostconditionMissing(SessionError):
    classification = "postcondition_missing"


class BackendUnhealthy(SessionError):
    classification = "backend_unhealthy"


class EvidenceReferenceError(SessionError):
    classification = "evidence_invalid"


class SessionCancelled(SessionError):
    classification = "cancelled"


class InputCleanupFailure(SessionError):
    classification = "input_cleanup_failed"


class PortFailure(SessionError):
    classification = "backend_failure"
    fatal = False

    def __init__(
        self, message: str = "", *, partial_identity: Mapping[str, Any] | None = None
    ) -> None:
        self.partial_identity = partial_identity
        super().__init__(message or self.classification)


class RelayFailure(PortFailure):
    classification = "relay_failure"


class BackendCrashed(PortFailure):
    classification = "backend_crash"
    fatal = True


class BackendOutOfMemory(PortFailure):
    classification = "backend_oom"
    fatal = True


@dataclass(frozen=True, slots=True)
class SessionId:
    """Manager-issued opaque in-memory identifier."""

    _token: str = field(repr=False)

    def __str__(self) -> str:
        return self._token

    def __repr__(self) -> str:
        return "SessionId(<opaque>)"


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    container_id: str
    linux_pid: int
    process_start_ticks: int
    xid: int
    hwnd: int
    rail_pid: int
    rail_start_ticks: int
    display: str
    application_nonce: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ProcessIdentity:
        if not isinstance(value, Mapping) or set(value) != set(_IDENTITY_FIELDS):
            raise IdentityError("identity must contain exactly the trusted identity fields")

        for name in ("container_id", "display", "application_nonce"):
            item = value[name]
            if not isinstance(item, str) or not item:
                raise IdentityError(f"identity field {name} must be a non-empty string")

        for name in ("linux_pid", "xid", "hwnd", "rail_pid"):
            item = value[name]
            if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
                raise IdentityError(f"identity field {name} must be a positive integer")

        for name in ("process_start_ticks", "rail_start_ticks"):
            item = value[name]
            if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
                raise IdentityError(f"identity field {name} must be a positive integer")

        return cls(**{name: value[name] for name in _IDENTITY_FIELDS})

    def as_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in _IDENTITY_FIELDS}


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Backend attestation for one actual file produced by one session action."""

    session_id: SessionId
    operation: str
    path: str | Path
    sha256: str
    target_identity: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class StopResult:
    """Explicit stop attestation for this manager-issued session token."""

    session_id: SessionId
    process_stopped: bool
    inputs_released: bool


@dataclass(frozen=True, slots=True)
class PortResult:
    """A backend operation result. PASS is gated again by the manager."""

    status: str = "PASS"
    payload: Any = None
    target_identity: Mapping[str, Any] | None = None
    postcondition_verified: bool | None = None
    evidence_ref: EvidenceReference | None = None


class Port(Protocol):
    """Trusted backend contract; every method is scoped to an explicit session."""

    @property
    def container_context_id(self) -> str: ...

    def implemented_operations(self) -> Iterable[str]: ...

    def start_session(
        self, *, session_id: SessionId, app_alias: str, evidence_root: Path
    ) -> Mapping[str, Any]: ...

    def validate_identity(
        self, *, session_id: SessionId, identity: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def perform(
        self,
        *,
        session_id: SessionId,
        identity: Mapping[str, Any],
        operation: str,
        arguments: Mapping[str, Any],
        cancel_event: threading.Event,
    ) -> PortResult: ...

    def health_check(
        self, *, session_id: SessionId, identity: Mapping[str, Any]
    ) -> bool: ...

    # Must fresh-resolve the target and backend-owned press ledger from this token.
    def release_inputs(
        self,
        *,
        session_id: SessionId,
    ) -> bool: ...

    # Must resolve only this manager-issued session token and confirm both the
    # process resource and every logical input are gone in StopResult.
    def stop_session(
        self, *, session_id: SessionId
    ) -> StopResult: ...


@dataclass
class _Session:
    session_id: SessionId
    owner: object
    owner_label: str
    evidence_root: Path
    state: str = "created"
    identity: ProcessIdentity | None = None
    resource_released: bool = False
    failure_class: str | None = None
    failure_detail: str | None = None
    stop_errors: list[dict[str, str]] = field(default_factory=list)
    cleanup_errors: list[dict[str, str]] = field(default_factory=list)
    pointer: dict[str, float | int] | None = None
    buttons: set[str] = field(default_factory=set)
    modifiers: set[str] = field(default_factory=set)
    lock: threading.RLock = field(default_factory=threading.RLock)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    cancel_guard: threading.Lock = field(default_factory=threading.Lock)
    active: bool = False
    active_operation: str | None = None


class SessionManager:
    """A fixed-capacity manager for one trusted backend container context.

    The owner argument must be an object reference supplied by the in-process
    coordinator. It is compared by identity and is not a network credential.
    """

    _TRANSITIONS = {
        "created": frozenset({"starting", "stopping"}),
        "starting": frozenset({"running", "stopping"}),
        "running": frozenset({"stopping", "failed"}),
        "stopping": frozenset({"stopped", "failed"}),
        "failed": frozenset({"stopping"}),
        "stopped": frozenset(),
    }

    def __init__(
        self, port: Port, *, app_alias: str, evidence_root: str | Path
    ) -> None:
        if app_alias != APPROVED_APP_ALIAS:
            raise ValueError(f"only the approved app alias {APPROVED_APP_ALIAS!r} is accepted")

        required_methods = (
            "implemented_operations",
            "start_session",
            "validate_identity",
            "perform",
            "health_check",
            "release_inputs",
            "stop_session",
        )
        missing = [name for name in required_methods if not callable(getattr(port, name, None))]
        if missing:
            raise TypeError(f"Port is missing required methods: {', '.join(missing)}")

        container_context_id = getattr(port, "container_context_id", None)
        if not isinstance(container_context_id, str) or not container_context_id:
            raise TypeError("Port.container_context_id must be a non-empty trusted string")

        self._port = port
        self.app_alias = APPROVED_APP_ALIAS
        self.container_context_id = container_context_id
        self._evidence_root = Path(evidence_root).expanduser().resolve()
        self._sessions: dict[SessionId, _Session] = {}
        self._lock = threading.RLock()
        self._journal_lock = threading.Lock()
        self._journal: deque[dict[str, Any]] = deque(maxlen=JOURNAL_LIMIT)
        self._journal_sequence = 0

    def create_session(self, owner: object) -> SessionId:
        """Create a fresh session; owner must be a trusted coordinator object."""
        self._validate_owner_object(owner)
        wall_started = time.time_ns()
        monotonic_started = time.perf_counter_ns()
        with self._lock:
            live = sum(
                not session.resource_released
                for session in self._sessions.values()
                if session.state != "stopped"
            )
            if live >= MAX_SESSIONS_PER_CONTAINER:
                raise SessionCapacityError(
                    f"container context is limited to {MAX_SESSIONS_PER_CONTAINER} sessions"
                )

            self._evidence_root.mkdir(parents=True, exist_ok=True)
            while True:
                session_id = SessionId(secrets.token_hex(24))
                session_root = self._evidence_root / str(session_id)
                try:
                    session_root.mkdir(mode=0o700, exist_ok=False)
                    break
                except FileExistsError:
                    continue

            resolved_root = session_root.resolve(strict=True)
            self._require_contained(resolved_root, self._evidence_root.resolve(strict=True))
            session = _Session(
                session_id=session_id,
                owner=owner,
                owner_label=secrets.token_hex(8),
                evidence_root=resolved_root,
            )
            self._sessions[session_id] = session

        self._record(
            session,
            "session.create",
            wall_started,
            monotonic_started,
            "PASS",
            result={"state": "created"},
        )
        return session_id

    def start_session(self, session_id: SessionId, owner: object) -> SessionId:
        session = self._resolve(session_id, owner)
        with session.lock:
            if session.state != "created":
                raise SessionLifecycleError(f"cannot start a session in state {session.state!r}")

            wall_started = time.time_ns()
            monotonic_started = time.perf_counter_ns()
            self._transition(session, "starting")
            try:
                raw_identity = self._port.start_session(
                    session_id=session.session_id,
                    app_alias=APPROVED_APP_ALIAS,
                    evidence_root=session.evidence_root,
                )
                identity = ProcessIdentity.from_mapping(raw_identity)
                session.identity = identity
                if identity.container_id != self.container_context_id:
                    raise IdentityError("backend identity belongs to a different container context")
                self._assert_unique_identity(session, identity)
                self._validate_fresh_identity(session)
                self._transition(session, "running")
                self._record(
                    session,
                    "session.start",
                    wall_started,
                    monotonic_started,
                    "PASS",
                    result={"state": "running"},
                )
                return session.session_id
            except BaseException as exc:
                partial_identity = getattr(exc, "partial_identity", None)
                if session.identity is None and isinstance(partial_identity, Mapping):
                    try:
                        session.identity = ProcessIdentity.from_mapping(partial_identity)
                    except IdentityError:
                        pass
                session.failure_class = self._classification(exc)
                session.failure_detail = self._bounded_message(exc)
                self._transition(session, "stopping")
                self._attempt_start_cleanup(session)
                self._transition(session, "failed")
                self._record(
                    session,
                    "session.start",
                    wall_started,
                    monotonic_started,
                    "FAIL",
                    error=exc,
                )
                if isinstance(exc, SessionError):
                    raise
                raise PortFailure(
                    f"backend start failed: {type(exc).__name__}",
                    partial_identity=partial_identity,
                ) from exc

    def dispatch(
        self,
        session_id: SessionId,
        owner: object,
        operation: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Dispatch one allowlisted logical operation to an advertised Port op."""
        session = self._resolve(session_id, owner)
        if operation == "window.close":
            return self._dispatch_window_close(session, owner)
        with session.lock:
            wall_started = time.time_ns()
            monotonic_started = time.perf_counter_ns()
            active_marked = False
            input_operation = isinstance(operation, str) and operation in _INPUT_OPERATIONS
            release_after_dispatch = input_operation and session.state == "running"
            primary_error: BaseException | None = None
            cleanup_error: BaseException | None = None
            outcome: dict[str, Any] | None = None

            try:
                if session.state != "running":
                    raise SessionLifecycleError(
                        f"cannot dispatch in state {session.state!r}"
                    )
                if not isinstance(operation, str) or operation not in ALLOWLIST:
                    raise InvalidOperation(f"operation is not allowlisted: {operation!r}")
                copied_arguments = self._copy_and_validate_arguments(arguments)
                advertised = self._advertised_operations()
                if operation not in advertised:
                    raise UnsupportedOperation(operation)

                with session.cancel_guard:
                    session.cancel_event.clear()
                    session.active = True
                    session.active_operation = operation
                    active_marked = True

                self._validate_fresh_identity(session)
                if input_operation:
                    self._track_input_state(session, operation, copied_arguments)

                result = self._port.perform(
                    session_id=session.session_id,
                    identity=session.identity.as_dict(),  # type: ignore[union-attr]
                    operation=operation,
                    arguments=copied_arguments,
                    cancel_event=session.cancel_event,
                )
                if session.cancel_event.is_set():
                    raise SessionCancelled("operation was cancelled")

                self._validate_fresh_identity(session)
                if not isinstance(result, PortResult):
                    raise PortContractError("Port.perform must return PortResult")
                if result.status != "PASS":
                    raise OperationFailed("backend operation did not return PASS")
                if result.target_identity is None:
                    raise StaleIdentity("backend result did not identify its actual target")
                result_identity = ProcessIdentity.from_mapping(result.target_identity)
                if result_identity != session.identity:
                    raise StaleIdentity("backend result target differs from this session identity")

                healthy: bool | None = None
                evidence_ref: dict[str, str] | None = None
                if operation in VERIFIED_OPERATIONS:
                    if result.postcondition_verified is not True:
                        raise PostconditionMissing(
                            "operation lacks a verified backend postcondition"
                        )
                    healthy = self._check_health(session)
                    if healthy is not True:
                        raise BackendUnhealthy("backend health check returned false")
                    evidence_ref = self._validate_evidence_reference(
                        session, operation, result.evidence_ref, required=True
                    )
                elif result.evidence_ref is not None:
                    evidence_ref = self._validate_evidence_reference(
                        session, operation, result.evidence_ref, required=False
                    )

                with session.cancel_guard:
                    if session.cancel_event.is_set():
                        raise SessionCancelled("operation was cancelled")

                outcome = {
                    "status": "PASS",
                    "operation": operation,
                    "payload": copy.deepcopy(result.payload),
                    "postcondition_verified": result.postcondition_verified,
                    "healthy": healthy,
                    "evidence_ref": evidence_ref,
                }
            except BaseException as exc:
                primary_error = exc
            finally:
                if release_after_dispatch:
                    cleanup_error = self._release_session_inputs(
                        session, record_failure=False
                    )
                if active_marked:
                    with session.cancel_guard:
                        if session.cancel_event.is_set() and primary_error is None:
                            primary_error = SessionCancelled("operation was cancelled")
                            outcome = None
                        session.active = False
                        session.active_operation = None

            if cleanup_error is not None:
                self._remember_cleanup_error(session, cleanup_error)
                self._apply_action_failure(session, cleanup_error)
                if primary_error is None:
                    primary_error = cleanup_error
                    outcome = None

            if primary_error is not None:
                self._apply_action_failure(session, primary_error)
                self._record(
                    session,
                    operation if isinstance(operation, str) else "invalid-operation",
                    wall_started,
                    monotonic_started,
                    "CANCELLED" if isinstance(primary_error, SessionCancelled) else "FAIL",
                    error=primary_error,
                )
                raise primary_error

            if outcome is None:
                error = PortContractError("manager produced no operation outcome")
                self._apply_action_failure(session, error)
                self._record(
                    session, operation, wall_started, monotonic_started, "FAIL", error=error
                )
                raise error

            self._record(
                session,
                operation,
                wall_started,
                monotonic_started,
                "PASS",
                result=outcome,
            )
            return copy.deepcopy(outcome)

    def _dispatch_window_close(
        self, session: _Session, owner: object
    ) -> dict[str, Any]:
        wall_started = time.time_ns()
        monotonic_started = time.perf_counter_ns()
        try:
            if "window.close" not in self._advertised_operations():
                raise UnsupportedOperation("window.close")
            snapshot = self.stop_session(session.session_id, owner)
            status = "STOPPED" if snapshot["state"] == "stopped" else "FAILED"
            outcome = {
                "status": status,
                "operation": "window.close",
                "payload": snapshot,
                "postcondition_verified": None,
                "healthy": None,
                "evidence_ref": None,
            }
            self._record(
                session,
                "window.close",
                wall_started,
                monotonic_started,
                status,
                result={"state": snapshot["state"]},
            )
            return copy.deepcopy(outcome)
        except BaseException as exc:
            self._record(
                session,
                "window.close",
                wall_started,
                monotonic_started,
                "FAIL",
                error=exc,
            )
            raise

    def cancel(self, session_id: SessionId, owner: object) -> bool:
        """Signal only this session's currently active operation."""
        session = self._resolve(session_id, owner)
        started_wall = time.time_ns()
        started_mono = time.perf_counter_ns()
        with session.cancel_guard:
            signalled = session.active
            if signalled:
                session.cancel_event.set()
        self._record(
            session,
            "session.cancel",
            started_wall,
            started_mono,
            "PASS",
            result={"signalled": signalled},
        )
        return signalled

    def stop_session(self, session_id: SessionId, owner: object) -> dict[str, Any]:
        session = self._resolve(session_id, owner)
        with session.cancel_guard:
            if session.active:
                session.cancel_event.set()

        with session.lock:
            wall_started = time.time_ns()
            monotonic_started = time.perf_counter_ns()
            if session.state == "stopped" or session.resource_released:
                snapshot = self._snapshot(session)
                self._record(
                    session,
                    "session.stop",
                    wall_started,
                    monotonic_started,
                    "PASS",
                    result={"already_released": True},
                )
                return snapshot

            self._transition(session, "stopping")
            if session.identity is not None:
                try:
                    self._validate_fresh_identity(session)
                except BaseException as exc:
                    self._remember_stop_error(session, exc)
            cleanup_error = self._release_session_inputs(session, record_failure=False)
            if cleanup_error is not None:
                self._remember_stop_error(session, cleanup_error)

            stop_ok = False
            try:
                stopped = self._port.stop_session(session_id=session.session_id)
                self._confirm_stop_result(session, stopped)
                stop_ok = True
                session.resource_released = True
                self._transition(session, "stopped")
            except BaseException as exc:
                self._remember_stop_error(session, exc)
                session.failure_class = session.failure_class or self._classification(exc)
                session.failure_detail = session.failure_detail or self._bounded_message(exc)
                self._transition(session, "failed")

            self._record(
                session,
                "session.stop",
                wall_started,
                monotonic_started,
                "PASS" if stop_ok else "FAIL",
                result={"state": session.state, "stop_error_count": len(session.stop_errors)},
                error=None if stop_ok else (session.stop_errors[-1] if session.stop_errors else None),
            )
            return self._snapshot(session)

    def inspect_session(self, session_id: SessionId, owner: object) -> dict[str, Any]:
        session = self._resolve(session_id, owner)
        with session.lock:
            return self._snapshot(session)

    def journal(self, limit: int = JOURNAL_LIMIT) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= JOURNAL_LIMIT:
            raise ValueError(f"limit must be between 0 and {JOURNAL_LIMIT}")
        with self._journal_lock:
            entries = list(self._journal)
        return copy.deepcopy(entries[-limit:] if limit else [])

    @staticmethod
    def _validate_owner_object(owner: object) -> None:
        if owner is None or isinstance(
            owner, (str, bytes, bytearray, int, float, bool, tuple, frozenset)
        ):
            raise TypeError("owner must be a trusted in-process object reference")

    def _resolve(self, session_id: SessionId, owner: object) -> _Session:
        if not isinstance(session_id, SessionId):
            raise SessionNotFound("unknown session")
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFound("unknown session")
        if owner is not session.owner:
            raise OwnerMismatch("session is not bound to this coordinator owner")
        return session

    def _transition(self, session: _Session, target: str) -> None:
        if target not in self._TRANSITIONS.get(session.state, frozenset()):
            raise SessionLifecycleError(
                f"illegal lifecycle transition {session.state!r} -> {target!r}"
            )
        session.state = target

    def _advertised_operations(self) -> frozenset[str]:
        try:
            advertised = self._port.implemented_operations()
            if isinstance(advertised, (str, bytes)):
                raise TypeError("implemented_operations must return an iterable of names")
            values = tuple(advertised)
        except Exception as exc:
            raise PortContractError("could not read backend operation capabilities") from exc
        if any(not isinstance(value, str) for value in values):
            raise PortContractError("backend operation capabilities must be strings")
        return frozenset(values)

    @staticmethod
    def _copy_and_validate_arguments(
        arguments: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        if arguments is None:
            return {}
        if not isinstance(arguments, Mapping):
            raise InvalidArguments("operation arguments must be a mapping")
        try:
            copied = copy.deepcopy(dict(arguments))
        except Exception as exc:
            raise InvalidArguments("operation arguments could not be copied safely") from exc

        def check_keys(value: Any) -> None:
            if isinstance(value, Mapping):
                for key, nested in value.items():
                    if not isinstance(key, str):
                        raise InvalidArguments("operation argument keys must be strings")
                    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
                    if normalized in _FORBIDDEN_ARGUMENT_KEYS:
                        raise InvalidArguments(
                            f"caller cannot choose backend identity or filesystem field {key!r}"
                        )
                    check_keys(nested)
            elif isinstance(value, (list, tuple)):
                for nested in value:
                    check_keys(nested)

        check_keys(copied)
        return copied

    def _validate_fresh_identity(self, session: _Session) -> None:
        if session.identity is None:
            raise StaleIdentity("session has no trusted process identity")
        try:
            fresh = self._port.validate_identity(
                session_id=session.session_id,
                identity=session.identity.as_dict(),
            )
        except PortFailure:
            raise
        except Exception as exc:
            raise StaleIdentity("backend could not freshly validate session identity") from exc
        current = ProcessIdentity.from_mapping(fresh)
        if current != session.identity:
            raise StaleIdentity("backend identity changed since session start")

    def _assert_unique_identity(
        self, current: _Session, identity: ProcessIdentity
    ) -> None:
        with self._lock:
            for other in self._sessions.values():
                if other is current or other.resource_released or other.identity is None:
                    continue
                if other.identity.container_id != identity.container_id:
                    continue
                if (
                    other.identity.linux_pid == identity.linux_pid
                    or other.identity.xid == identity.xid
                    or other.identity.hwnd == identity.hwnd
                ):
                    raise IdentityCollision("trusted backend identity is already live in another session")

    def _check_health(self, session: _Session) -> bool:
        if session.identity is None:
            raise StaleIdentity("session has no trusted process identity")
        try:
            return self._port.health_check(
                session_id=session.session_id,
                identity=session.identity.as_dict(),
            )
        except PortFailure:
            raise
        except Exception as exc:
            raise BackendUnhealthy("backend health check failed") from exc

    def _validate_evidence_reference(
        self,
        session: _Session,
        operation: str,
        reference: EvidenceReference | None,
        *,
        required: bool,
    ) -> dict[str, Any] | None:
        if reference is None:
            if required:
                raise EvidenceReferenceError("operation did not return session evidence")
            return None
        if not isinstance(reference, EvidenceReference):
            raise EvidenceReferenceError("evidence must include a session-scoped attestation")
        if reference.session_id != session.session_id:
            raise EvidenceReferenceError("evidence belongs to a different session")
        if reference.operation != operation:
            raise EvidenceReferenceError("evidence belongs to a different operation")
        try:
            evidence_identity = ProcessIdentity.from_mapping(reference.target_identity)
        except IdentityError as exc:
            raise EvidenceReferenceError("evidence target identity is invalid") from exc
        if evidence_identity != session.identity:
            raise StaleIdentity("evidence target identity differs from this session")

        if not isinstance(reference.path, (str, Path)) or not str(reference.path):
            raise EvidenceReferenceError("evidence reference must contain a local file path")
        raw = str(reference.path)
        if "://" in raw:
            raise EvidenceReferenceError("evidence reference must be a local session file")

        candidate_path = Path(raw)
        if ".." in candidate_path.parts:
            raise EvidenceReferenceError("evidence reference contains path traversal")
        if not candidate_path.is_absolute():
            candidate_path = session.evidence_root / candidate_path

        try:
            session_root = session.evidence_root.resolve(strict=True)
            manager_root = self._evidence_root.resolve(strict=True)
            self._require_contained(session_root, manager_root)
            resolved = candidate_path.resolve(strict=True)
            self._require_contained(resolved, session_root)
        except (OSError, ValueError) as exc:
            raise EvidenceReferenceError(
                "evidence reference is missing or outside this session's assigned root"
            ) from exc
        if not resolved.is_file():
            raise EvidenceReferenceError("evidence reference is not a regular file")
        expected_hash = reference.sha256
        if (
            not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in expected_hash)
        ):
            raise EvidenceReferenceError("evidence hash must be a SHA-256 hex digest")
        digest = hashlib.sha256()
        try:
            with resolved.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise EvidenceReferenceError("evidence file could not be read") from exc
        actual_hash = digest.hexdigest()
        if actual_hash.lower() != expected_hash.lower():
            raise EvidenceReferenceError("evidence content does not match its backend hash")
        return {
            "session_id": str(reference.session_id),
            "operation": reference.operation,
            "path": str(resolved),
            "sha256": actual_hash,
            "target_identity": evidence_identity.as_dict(),
        }

    @staticmethod
    def _require_contained(path: Path, root: Path) -> None:
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"{path} is outside {root}") from exc

    def _track_input_state(
        self, session: _Session, operation: str, arguments: Mapping[str, Any]
    ) -> None:
        x = arguments.get("x")
        y = arguments.get("y")
        pointer = None
        if x is not None or y is not None:
            if (
                isinstance(x, bool)
                or isinstance(y, bool)
                or not isinstance(x, (int, float))
                or not isinstance(y, (int, float))
                or not math.isfinite(float(x))
                or not math.isfinite(float(y))
            ):
                raise InvalidArguments("pointer coordinates must be finite numbers")
            pointer = {"x": x, "y": y}

        button: str | None = None
        if operation in {"click", "drag"}:
            button = arguments.get("button", "left")
            if not isinstance(button, str) or not button:
                raise InvalidArguments("button must be a non-empty string")

        declared_modifiers = arguments.get("modifiers", ())
        if isinstance(declared_modifiers, str) or not isinstance(
            declared_modifiers, (list, tuple, set, frozenset)
        ):
            raise InvalidArguments("modifiers must be a sequence of key names")
        modifiers: set[str] = set()
        for modifier in declared_modifiers:
            if not isinstance(modifier, str) or modifier.upper() not in _MODIFIER_KEYS:
                raise InvalidArguments("modifier is not an approved logical modifier key")
            modifiers.add(modifier.upper())

        if operation == "key":
            key = arguments.get("key")
            if isinstance(key, str) and key.upper() in _MODIFIER_KEYS:
                modifiers.add(key.upper())
        elif operation == "hotkey":
            keys = arguments.get("keys", ())
            if isinstance(keys, str) or not isinstance(keys, (list, tuple, set, frozenset)):
                raise InvalidArguments("hotkey keys must be a sequence of key names")
            for key in keys:
                if isinstance(key, str) and key.upper() in _MODIFIER_KEYS:
                    modifiers.add(key.upper())

        if pointer is not None:
            session.pointer = pointer
        if button is not None:
            session.buttons.add(button)
        session.modifiers.update(modifiers)

    def _release_session_inputs(
        self, session: _Session, *, record_failure: bool = True
    ) -> BaseException | None:
        try:
            # The backend resolves this manager-owned token to its current target
            # and authoritative press ledger; never reuse the stored identity here.
            released = self._port.release_inputs(session_id=session.session_id)
            if released is not True:
                raise InputCleanupFailure("backend did not confirm input release")
            session.buttons.clear()
            session.modifiers.clear()
            return None
        except BaseException as exc:
            error = exc if isinstance(exc, InputCleanupFailure) else InputCleanupFailure(
                f"input release failed: {type(exc).__name__}"
            )
            if record_failure:
                self._remember_cleanup_error(session, error)
            return error

    def _attempt_start_cleanup(self, session: _Session) -> None:
        try:
            stopped = self._port.stop_session(session_id=session.session_id)
            self._confirm_stop_result(session, stopped)
            session.resource_released = True
        except BaseException as exc:
            self._remember_stop_error(session, exc)

    @staticmethod
    def _confirm_stop_result(session: _Session, result: StopResult) -> None:
        if not isinstance(result, StopResult):
            raise PortContractError("Port.stop_session must return StopResult")
        if result.session_id != session.session_id:
            raise PortContractError("Port.stop_session attested a different session token")
        if result.inputs_released is True:
            session.buttons.clear()
            session.modifiers.clear()
        if result.process_stopped is not True or result.inputs_released is not True:
            raise PortContractError(
                "Port.stop_session did not confirm process stop and input release"
            )

    def _apply_action_failure(self, session: _Session, error: BaseException) -> None:
        classification = self._classification(error)
        fatal = isinstance(
            error,
            (
                IdentityError,
                PostconditionMissing,
                BackendUnhealthy,
                EvidenceReferenceError,
                InputCleanupFailure,
                BackendCrashed,
                BackendOutOfMemory,
            ),
        ) or bool(getattr(error, "fatal", False))
        if fatal and session.state == "running":
            session.failure_class = classification
            session.failure_detail = self._bounded_message(error)
            self._transition(session, "failed")

    def _remember_stop_error(self, session: _Session, error: BaseException) -> None:
        session.stop_errors.append(self._error_record(error))
        del session.stop_errors[:-16]

    def _remember_cleanup_error(self, session: _Session, error: BaseException) -> None:
        session.cleanup_errors.append(self._error_record(error))
        del session.cleanup_errors[:-16]

    @staticmethod
    def _classification(error: BaseException | Mapping[str, Any]) -> str:
        if isinstance(error, Mapping):
            value = error.get("classification")
            return str(value)[:64] if value else "cleanup_error"
        value = getattr(error, "classification", None)
        if isinstance(value, str):
            return value[:64]
        return type(error).__name__.lower()[:64]

    @classmethod
    def _bounded_message(cls, error: BaseException) -> str:
        message = str(error).replace("\r", " ").replace("\n", " ")
        return message[:_JOURNAL_MESSAGE_LIMIT]

    @classmethod
    def _error_record(cls, error: BaseException) -> dict[str, str]:
        return {
            "classification": cls._classification(error),
            "type": type(error).__name__[:64],
            "message": cls._bounded_message(error),
        }

    def _record(
        self,
        session: _Session,
        operation: str,
        wall_started: int,
        monotonic_started: int,
        status: str,
        *,
        result: Any = None,
        error: BaseException | Mapping[str, Any] | None = None,
    ) -> None:
        result_summary: dict[str, Any]
        if error is not None:
            result_summary = {
                "classification": self._classification(error),
                "error_type": (
                    str(error.get("type", "cleanup_error"))[:64]
                    if isinstance(error, Mapping)
                    else type(error).__name__[:64]
                ),
                "message": (
                    str(error.get("message", ""))[:_JOURNAL_MESSAGE_LIMIT]
                    if isinstance(error, Mapping)
                    else self._bounded_message(error)
                ),
            }
            progress = getattr(error, "batch_progress", None)
            if isinstance(progress, Mapping):
                result_summary["batch_progress"] = {
                    "mechanism": "KEYBOARD_BATCH", "atomic": False, "auto_retry": False,
                    "attempted_steps": progress.get("attempted_steps"),
                    "observed_steps": progress.get("observed_steps"),
                    "failure_evidence": copy.deepcopy(progress.get("failure_evidence")),
                }
        elif isinstance(result, Mapping):
            result_summary = {
                "keys": sorted(str(key)[:48] for key in result)[:12],
                "evidence": bool(result.get("evidence_ref")),
                "postcondition_verified": result.get("postcondition_verified"),
                "state": str(result.get("state", ""))[:48],
            }
        else:
            result_summary = {"kind": type(result).__name__[:64]}

        with self._journal_lock:
            self._journal_sequence += 1
            self._journal.append(
                {
                    "sequence": self._journal_sequence,
                    "session_id": str(session.session_id),
                    "owner": session.owner_label,
                    "operation": str(operation)[:64],
                    "started_at_ns": wall_started,
                    "duration_ns": max(0, time.perf_counter_ns() - monotonic_started),
                    "status": status,
                    "result": result_summary,
                }
            )

    def _snapshot(self, session: _Session) -> dict[str, Any]:
        with session.cancel_guard:
            cancel_requested = session.cancel_event.is_set()
            active = session.active
            active_operation = session.active_operation
        value = {
            "session_id": str(session.session_id),
            "owner": session.owner_label,
            "container_context_id": self.container_context_id,
            "app_alias": self.app_alias,
            "state": session.state,
            "identity": session.identity.as_dict() if session.identity else None,
            "resource_released": session.resource_released,
            "failure_class": session.failure_class,
            "failure_detail": session.failure_detail,
            "evidence_scope": str(session.session_id),
            "active": active,
            "active_operation": active_operation,
            "cancel_requested": cancel_requested,
            "pointer": session.pointer,
            "buttons": sorted(session.buttons),
            "modifiers": sorted(session.modifiers),
            "stop_errors": session.stop_errors,
            "cleanup_errors": session.cleanup_errors,
        }
        return copy.deepcopy(value)

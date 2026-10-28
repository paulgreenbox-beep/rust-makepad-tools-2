"""Fixed Windows-hosted WSLC platform port, not a recipe/action engine.

Provenance: Linux Backend ownership/stdio mechanics from the retained
20261016 acceptance pilot. No historic/ignored Python module is imported.
Rust owns semantic actions, activity leases, PNG decoding and publication.

Only a fresh, exclusively operator-created container may be adopted. Normal
application exit is observed separately from retiring that owned container.
"""
from __future__ import annotations

import datetime as dt
import base64
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import queue
import re
import secrets
import stat
import subprocess
import sys
import threading
import time

def normal_host_spelling(value):
    text = str(value)
    if text.startswith("\\\\?\\") and re.match(r"^[A-Za-z]:[\\/]", text[4:]):
        return text[4:]
    return text


ROOT = Path(normal_host_spelling(Path(__file__).resolve())).parents[4]
HELPERS = ROOT / "experiments/ai-execution-workspace"
EVIDENCE = ROOT / "reports/evidence"
PIN = "71c9ddcbb9c01dd208f99621fdd71024a5d35c65"
WSLC = r"C:\Program Files\WSL\wslc.exe"
PWSH = str(Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/powershell/pwsh.exe")
INPUT_CAP = 64 * 1024
OUTPUT_CAP = 32 * 1024 * 1024
HTTP_CAP = 4 * 1024 * 1024
PNG_CAP = 8 * 1024 * 1024
HEADER_CAP = 16 * 1024
LOG_CAP = 4 * 1024 * 1024
STDERR_CAP = 65536
IO_TTL = 30.0
LIFETIME = 420.0
APP_SECONDS = 300
RELAY_SECONDS = 360
SCOPED_ADMISSION_SCHEMA = "toolkit-remote-scoped-runtime-admission-v1"
RESOURCE_AUTHORIZATION_PATH = "reports/evidence/makepad-dev-remote-api-adoption-v1/quality-26/operator-memory-authorization.json"
RESOURCE_AUTHORIZATION_SHA256 = "1D9BD6C43D7EBFDF550CE99BE7D6E9C4A0A0C1D7951D25F0B3331F548B6F1546"
RESOURCE_AUTHORIZATION_OWNER = "Makepad_Toolkit:remote-api-adoption-v1"
RESOURCE_AUTHORIZATION_CAP = 16 * 1024
FOCUS_MEMORY_MAX = 1073741824
MODULE_MEMORY_MAX = 2147483648
MODULE_SOURCE_SHA256 = "91F63101687B7BFB778391AB780BCF5AF1B8697D3DA81B5E08E70FFF39C32E42"
MODULE_ELF_SHA256 = "F7B286EF5A851028BA631A690ED0CE2FC3D4F71F91E0097BA28A7F71DDC93489"
MODULE_ADMISSION_SCHEMA = "toolkit-makepad-dev-app-module-shell-host-admission-v1"
MODULE_ENV = {"MAKEPAD_HOME":"/tmp/toolkit-module-shell-wslc-home",
    "TOOLKIT_MODULE_PROJECT_ID":"module-shell-wslc-v1", "TOOLKIT_NATIVE_LATE_PROBE":"1"}
CONFIG_KEYS = frozenset(("schema", "source_commit", "owner", "session_id", "generation",
    "runtime_directory", "output_directory", "admission_path", "expected_identity", "key_focus_probe"))
EXPECTED_KEYS = frozenset(("container_id", "image_id", "executable", "executable_sha256"))
IDENTITY_KEYS = frozenset(("schema", "container_id", "image_id", "pid_namespace", "pid",
    "process_start_ticks", "executable", "executable_sha256", "listener_host", "listener_port",
    "listener_inode", "window_id", "rail_hwnd", "rail_pid", "rail_process_birth", "rail_visible",
    "memory_max", "cpu_max"))
OPS = frozenset(("launch", "validate", "request", "copy_frame", "reap", "stderr", "cleanup", "focus_sample", "host_content_geometry"))
MUTATIONS = frozenset(("/click", "/m", "/k", "/t", "/quit"))
ROUTE_KEYS = {
    "/s": {"w"}, "/snap": {"w", "q", "all"}, "/d": set(), "/activity": set(),
    "/click": {"w", "x", "y", "b", "wait", "shift", "ctrl", "alt", "cmd", "hw", "time"},
    "/m": {"w", "x", "y", "b", "wait", "shift", "ctrl", "alt", "cmd", "hw", "time", "k", "dx", "dy", "scale", "phase"},
    "/k": {"w", "t", "c", "k", "wait", "shift", "ctrl", "alt", "cmd"},
    "/t": {"w", "t", "wait"}, "/g": {"w", "scale", "raw"}, "/quit": set(),
}
ALIASES = {"window": "w", "query": "q", "kind": "k", "button": "b", "text": "t",
    "code": "c", "key": "c", "key_code": "c", "control": "ctrl", "option": "alt",
    "logo": "cmd", "meta": "cmd", "super": "cmd", "sx": "dx", "sy": "dy", "s": "scale"}


class Fault(Exception):
    """Only local constant codes cross the pipe; never exception/server text."""
    def __init__(self, code, dispatched=False):
        if not isinstance(code, str) or not re.fullmatch(r"WSLC_[A-Z0-9_]{1,90}", code):
            code = "WSLC_INTERNAL_ERROR"
        self.code, self.dispatched = code, bool(dispatched)
        super().__init__(code)


def require(ok, code):
    if not ok:
        raise Fault(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "WSLC_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def strict_json(raw, cap=INPUT_CAP):
    require(isinstance(raw, bytes) and len(raw) <= cap, "WSLC_JSON_BOUND")
    # Do not depend on the host interpreter's mutable recursion limit. Reject
    # excessive nesting BEFORE the JSON parser allocates or recurses.
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            require(depth <= 128, "WSLC_JSON_DEPTH_BOUND")
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0, "WSLC_JSON_INVALID")
    try:
        text = raw.decode("utf-8")
        text.encode("utf-8")
        result = json.loads(text, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(Fault("WSLC_JSON_NONFINITE")))
        # Escaped lone surrogates must not leak into filesystem/subprocess APIs.
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return result
    except Fault:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        raise Fault("WSLC_JSON_INVALID") from None


def exact(value, keys, code="WSLC_ARGUMENT_SCHEMA_INVALID"):
    require(type(value) is dict and set(value) == set(keys), code)
    return value


def uint(value, maximum=(1 << 64) - 1, positive=False):
    return type(value) is int and (1 if positive else 0) <= value <= maximum


def decimal(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[1-9][0-9]{0,19}", value)) and int(value) < (1 << 64)


def guest_path(value):
    return (isinstance(value, str) and 1 < len(value) <= 4096 and value.startswith("/")
        and "\\" not in value and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
        and all(p not in ("", ".", "..") for p in value.split("/")[1:]))


def expected_identity(value):
    exact(value, EXPECTED_KEYS, "WSLC_EXPECTED_IDENTITY_INVALID")
    require(isinstance(value["container_id"], str) and bool(re.fullmatch(r"[0-9a-f]{64}", value["container_id"])), "WSLC_CONTAINER_ID_INVALID")
    require(isinstance(value["image_id"], str) and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"])), "WSLC_IMAGE_ID_INVALID")
    require(guest_path(value["executable"]), "WSLC_EXECUTABLE_INVALID")
    require(isinstance(value["executable_sha256"], str) and bool(re.fullmatch(r"[0-9a-fA-F]{64}", value["executable_sha256"])), "WSLC_EXECUTABLE_SHA256_INVALID")
    return value


def observed_identity(value, expected, *, memory_max=FOCUS_MEMORY_MAX):
    exact(value, IDENTITY_KEYS, "WSLC_IDENTITY_SCHEMA_INVALID")
    require(value["schema"] == "toolkit-makepad-remote-wslc-identity-v1", "WSLC_IDENTITY_SCHEMA_INVALID")
    for key in ("container_id", "image_id", "executable"):
        require(value[key] == expected[key], "WSLC_IDENTITY_PIN_MISMATCH")
    require(isinstance(value["executable_sha256"], str) and value["executable_sha256"].lower() == expected["executable_sha256"].lower(), "WSLC_EXECUTABLE_SHA256_MISMATCH")
    ns = value["pid_namespace"]
    require(isinstance(ns, str) and ns.startswith("pid:[") and ns.endswith("]") and decimal(ns[5:-1]), "WSLC_PID_NAMESPACE_INVALID")
    for key in ("pid", "rail_pid"):
        require(uint(value[key], (1 << 32) - 1, True), "WSLC_PID_INVALID")
    for key in ("process_start_ticks", "listener_inode", "rail_process_birth"):
        require(decimal(value[key]), "WSLC_KERNEL_IDENTITY_INVALID")
    require(uint(value["rail_hwnd"], positive=True) and uint(value["window_id"]), "WSLC_WINDOW_ID_INVALID")
    require(value["listener_host"] == "127.0.0.1" and uint(value["listener_port"], 65535, True), "WSLC_ENDPOINT_INVALID")
    require(value["rail_visible"] is False, "WSLC_RAIL_NOT_HIDDEN")
    require(type(memory_max) is int and memory_max in (FOCUS_MEMORY_MAX, MODULE_MEMORY_MAX)
        and type(value["memory_max"]) is int and value["memory_max"] == memory_max
        and value["cpu_max"] == "100000 100000", "WSLC_CGROUP_MISMATCH")
    return value


def config(value):
    module = type(value) is dict and value.get("profile_kind") == "ModuleShell"
    exact(value, CONFIG_KEYS | {"profile_kind", "module_shell"} if module else CONFIG_KEYS, "WSLC_CONFIG_SCHEMA_INVALID")
    require(value["schema"] == "toolkit-makepad-remote-wslc-owner-v1" and value["source_commit"] == PIN, "WSLC_SOURCE_PIN_MISMATCH")
    for key in ("owner", "session_id"):
        require(isinstance(value[key], str) and 1 <= len(value[key].encode("utf-8")) <= 128
            and not any(ord(c) < 32 or ord(c) == 127 for c in value[key]), "WSLC_OWNER_INVALID")
    require(uint(value["generation"], positive=True) and type(value["key_focus_probe"]) is bool, "WSLC_CONFIG_TYPES_INVALID")
    for key in ("runtime_directory", "output_directory", "admission_path"):
        require(isinstance(value[key], str) and 0 < len(value[key]) <= 4096, "WSLC_HOST_PATH_INVALID")
    expected_identity(value["expected_identity"])
    if module:
        exact(value["module_shell"], ("source_manifest_sha256",), "WSLC_MODULE_PROFILE_INVALID")
        require(value["module_shell"]["source_manifest_sha256"] == MODULE_SOURCE_SHA256
            and value["expected_identity"]["executable"] == "/opt/proof/ai-workspace-fixture"
            and value["expected_identity"]["executable_sha256"].upper() == MODULE_ELF_SHA256
            and value["key_focus_probe"] is False, "WSLC_MODULE_PROFILE_INVALID")
    return value


def profile_memory_max(cfg):
    return MODULE_MEMORY_MAX if cfg.get("profile_kind") == "ModuleShell" else FOCUS_MEMORY_MAX


def profile_runtime_budget(cfg):
    # Composition09 completed every Script postcondition at the 570s fence.
    # Its measured tail needs a shared App/relay/owner budget, not an action retry.
    # no AI timeout argument, individual RPC/lease timeout or Focus limit changes.
    return (660, 720, 780.0) if cfg.get("profile_kind") == "ModuleShell" else (APP_SECONDS, RELAY_SECONDS, LIFETIME)


def module_admission(value, owner, now=None):
    """Fixed positive budget; USER_WAIVED is never a free-RAM measurement."""
    exact(value, ("schema","utc","owner","source_manifest_sha256","host_ram_mode","status",
        "available_memory_query_performed","minimum_free_bytes","minimum_free_kib","container_memory_bytes",
        "container_cpus","nested_increment_kib","active_compiler_observation_performed","active_rust_compilers",
        "resource_admitted","scope"), "WSLC_MODULE_ADMISSION_INVALID")
    now = now or dt.datetime.now(dt.timezone.utc)
    require(type(value) is dict and value.get("schema") == MODULE_ADMISSION_SCHEMA
        and value.get("owner") == owner and value.get("source_manifest_sha256") == MODULE_SOURCE_SHA256
        and value.get("host_ram_mode") == value.get("status") == "USER_WAIVED"
        and value.get("available_memory_query_performed") is False
        and type(value.get("minimum_free_bytes")) is int and value["minimum_free_bytes"] == 2684354560
        and type(value.get("minimum_free_kib")) is int and value["minimum_free_kib"] == 2621440
        and type(value.get("container_memory_bytes")) is int and value["container_memory_bytes"] == MODULE_MEMORY_MAX
        and type(value.get("container_cpus")) is int and value["container_cpus"] == 1
        and type(value.get("nested_increment_kib")) is int and value["nested_increment_kib"] == 0
        and value.get("active_compiler_observation_performed") is True
        and type(value.get("active_rust_compilers")) is list and value["active_rust_compilers"] == []
        and value.get("resource_admitted") is False and value.get("scope") == "one_outer_runtime_admission",
        "WSLC_MODULE_ADMISSION_INVALID")
    require(0 <= (now - utc(value.get("utc"))).total_seconds() <= 120, "WSLC_ADMISSION_STALE")
    return value


def host_path(value, base, *, exists=True):
    """Drive-local spelling only; reject reparse points in every ancestor."""
    require(isinstance(value, (str, Path)), "WSLC_HOST_PATH_INVALID")
    text = str(value)
    if text.startswith("\\\\?\\"):
        require(bool(re.match(r"^[A-Za-z]:\\", text[4:])), "WSLC_DEVICE_PATH_REFUSED")
        text = text[4:]
    require(not text.startswith("\\\\"), "WSLC_UNC_PATH_REFUSED")
    path = Path(text)
    require(path.is_absolute() and ".." not in path.parts, "WSLC_HOST_PATH_INVALID")
    base = Path(normal_host_spelling(Path(base).resolve(strict=True)))
    require(path != base and path.is_relative_to(base), "WSLC_PATH_OUTSIDE_OWNER")
    for part in (path, *path.parents):
        try:
            item = part.lstat()
        except FileNotFoundError:
            if part == path and not exists:
                continue
            raise Fault("WSLC_HOST_PATH_MISSING") from None
        require(not stat.S_ISLNK(item.st_mode) and not (getattr(item, "st_file_attributes", 0) & 0x400), "WSLC_REPARSE_PATH_REFUSED")
    require(Path(normal_host_spelling(path.resolve(strict=exists))) == path, "WSLC_PATH_ALIAS_REFUSED")
    return path


def read_bounded(path, cap):
    """Single bounded read; cross-API identity and within-API ctime checks."""
    path = Path(path)
    try:
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and not (getattr(before, "st_file_attributes", 0) & 0x400)
            and before.st_nlink == 1 and before.st_size <= cap, "WSLC_FILE_BOUND_OR_TYPE")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns)
            require(key(before) == key(opened), "WSLC_FILE_CHANGED")
            raw = stream.read(cap + 1)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
        require(len(raw) == before.st_size <= cap and key(before) == key(finished) == key(after)
            and before.st_ctime_ns == after.st_ctime_ns and opened.st_ctime_ns == finished.st_ctime_ns,
            "WSLC_FILE_CHANGED")
        return raw
    except Fault:
        raise
    except OSError:
        raise Fault("WSLC_FILE_READ_FAILED") from None


def read_log_prefix(path, cap):
    """A bounded prefix of a growing owned log; only complete marker lines count."""
    path = Path(path)
    try:
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and not (getattr(before, "st_file_attributes", 0) & 0x400) and before.st_size <= cap,
            "WSLC_LOG_BOUND_OR_TYPE")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "WSLC_LOG_IDENTITY_CHANGED")
            raw = stream.read(min(cap + 1, before.st_size))
            after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size and after.st_size <= cap
            and (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino), "WSLC_LOG_IDENTITY_CHANGED")
        return raw[:raw.rfind(b"\n") + 1]
    except OSError:
        raise Fault("WSLC_LOG_READ_FAILED") from None


def fresh_admission(value, now=None, *, owner=None):
    """Original stock admission, or one closed operator-pinned RAM-only envelope.

    The envelope is evidence, not an AI/config permission flag. Its original UTC
    is rechecked at every existing call; neither raw status nor RAM is rewritten.
    """
    now = dt.datetime.now(dt.timezone.utc) if now is None else now
    try:
        scoped = type(value) is dict and value.get("schema") == SCOPED_ADMISSION_SCHEMA
        authorization = None
        if scoped:
            exact(value, ("schema", "stock", "authorization"), "WSLC_ADMISSION_ENVELOPE_INVALID")
            require(owner == RESOURCE_AUTHORIZATION_OWNER, "WSLC_RESOURCE_AUTHORIZATION_OWNER_REFUSED")
            for name in ("stock", "authorization"):
                item = exact(value[name], ("path", "sha256", "raw_utf8"), "WSLC_ADMISSION_ENVELOPE_INVALID")
                limit = INPUT_CAP if name == "stock" else RESOURCE_AUTHORIZATION_CAP
                require(type(item["raw_utf8"]) is str and len(item["raw_utf8"]) <= limit,
                    "WSLC_ADMISSION_ENVELOPE_BOUND")
                raw = item["raw_utf8"].encode("utf-8")
                require(len(raw) <= limit and type(item["sha256"]) is str
                    and re.fullmatch(r"[0-9a-fA-F]{64}", item["sha256"])
                    and hashlib.sha256(raw).hexdigest().upper() == item["sha256"].upper(),
                    "WSLC_ADMISSION_RAW_HASH_MISMATCH")
            require(len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")) <= INPUT_CAP,
                "WSLC_ADMISSION_ENVELOPE_BOUND")
            require(value["stock"]["path"] == "runtime-admission.json", "WSLC_ADMISSION_STOCK_PATH_REFUSED")
            authorization = value["authorization"]
            require(authorization["path"] == RESOURCE_AUTHORIZATION_PATH
                and authorization["sha256"] == RESOURCE_AUTHORIZATION_SHA256,
                "WSLC_RESOURCE_AUTHORIZATION_PIN_REFUSED")
            grant = strict_json(authorization["raw_utf8"].encode("utf-8"), RESOURCE_AUTHORIZATION_CAP)
            require(type(grant) is dict
                and grant.get("schema") == "toolkit-scoped-operator-resource-authorization-v1"
                and grant.get("milestone") == "MAKEPAD_DEV_REMOTE_API_ADOPTION_V1"
                and grant.get("operator_quote") == "Игнорируй нехваток памяти"
                and grant.get("thread_id") == "01a00532-be65-7723-89ec-c1b2bfdd373e"
                and grant.get("scope") == "RAM-only admission exception for continuing this milestone; not a global policy change"
                and grant.get("actual_memory_observation_required") is True
                and grant.get("stock_admission_results_must_not_be_relabelled") is True
                and grant.get("global_resource_policy_changed") is False
                and grant.get("runtime_acceptance_claimed") is False,
                "WSLC_RESOURCE_AUTHORIZATION_SCOPE_REFUSED")
            stock = strict_json(value["stock"]["raw_utf8"].encode("utf-8"), INPUT_CAP)
        else:
            stock = value
        require(type(stock) is dict and all(type(key) is str and "waiver" not in key.lower() for key in stock),
            "WSLC_RAM_WAIVER_REFUSED")
        require(type(stock["utc"]) is str, "WSLC_ADMISSION_INVALID")
        at = dt.datetime.fromisoformat(stock["utc"].replace("Z", "+00:00"))
        require(at.tzinfo is not None and 0 <= (now - at).total_seconds() <= 120, "WSLC_ADMISSION_STALE")
        require(stock["purpose"] == "runtime"
            and stock["active_rust_compilers"] == [] and type(stock["active_rust_compilers"]) is list
            and uint(stock["free_physical_kib"]) and uint(stock["required_free_kib"]),
            "WSLC_STOCK_ADMISSION_REQUIRED")
        low = stock["free_physical_kib"] < 2097152
        if scoped:
            require(stock["required_free_kib"] == 2097152
                and stock["status"] == ("BLOCKED_ENVIRONMENT" if low else "ADMITTED"),
                "WSLC_STOCK_ADMISSION_REQUIRED")
            return {"status": "AUTHORIZED_SCOPED_RAM_EXCEPTION" if low else "STOCK_ADMITTED",
                "stock_status": stock["status"], "free_physical_kib": stock["free_physical_kib"],
                "required_free_kib": stock["required_free_kib"], "utc": stock["utc"],
                "authorization": {"path": authorization["path"], "sha256": authorization["sha256"]}}
        require(stock["status"] == "ADMITTED" and not low and stock["required_free_kib"] >= 2097152,
            "WSLC_STOCK_ADMISSION_REQUIRED")
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        raise Fault("WSLC_ADMISSION_INVALID") from None
    return value


def request_target(target, mutating):
    require(type(mutating) is bool and isinstance(target, str) and 0 < len(target) <= 8192
        and target.isascii(), "WSLC_ROUTE_REFUSED")
    route, separator, query = target.partition("?")
    require(route in ROUTE_KEYS and mutating == (route in MUTATIONS), "WSLC_ROUTE_REFUSED")
    values = {}
    if separator:
        require(bool(query), "WSLC_ROUTE_REFUSED")
        for pair in query.split("&"):
            require(len(values) < 32, "WSLC_ROUTE_REFUSED")
            key, equal, value = pair.partition("=")
            value = value if equal else "1"
            require(bool(re.fullmatch(r"[a-z_]{1,32}", key)), "WSLC_ROUTE_REFUSED")
            key = ALIASES.get(key, key)
            require(key not in values and key in ROUTE_KEYS[route] | {"if_user_seq"}, "WSLC_ROUTE_REFUSED")
            require(bool(re.fullmatch(r"(?:[A-Za-z0-9_.~\-]|%[A-Fa-f0-9]{2})*", value)), "WSLC_ROUTE_REFUSED")
            decoded = bytearray()
            index = 0
            while index < len(value):
                if value[index] == "%":
                    decoded.append(int(value[index + 1:index + 3], 16)); index += 3
                else:
                    decoded.append(ord(value[index])); index += 1
            require(not any(c < 32 or c == 127 for c in decoded), "WSLC_ROUTE_REFUSED")
            try:
                values[key] = decoded.decode("utf-8")
            except UnicodeError:
                raise Fault("WSLC_ROUTE_REFUSED") from None
    if mutating:
        seq = values.get("if_user_seq", "")
        require(bool(re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", seq)) and int(seq) < (1 << 64), "WSLC_HUMAN_ACTIVITY_GUARD_REQUIRED")
    return route, values


def parse_http(raw):
    require(isinstance(raw, bytes) and len(raw) <= HEADER_CAP + HTTP_CAP, "WSLC_HTTP_BOUND")
    head, marker, body = raw.partition(b"\r\n\r\n")
    require(bool(marker) and len(head) + 4 <= HEADER_CAP, "WSLC_HTTP_FRAMING_INVALID")
    lines = head.split(b"\r\n")
    require(bool(re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2}(?: [\x20-\x7e]*)?", lines[0])), "WSLC_HTTP_STATUS_INVALID")
    fields = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        require(bool(colon) and bool(re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name))
            and all(c == 9 or 32 <= c < 127 for c in value), "WSLC_HTTP_HEADER_INVALID")
        name = name.lower()
        require(name not in fields and name != b"transfer-encoding", "WSLC_HTTP_HEADER_AMBIGUOUS")
        fields[name] = value.strip(b" \t")
    length = fields.get(b"content-length", b"")
    require(bool(re.fullmatch(rb"[0-9]{1,10}", length)), "WSLC_HTTP_LENGTH_INVALID")
    require(int(length) <= HTTP_CAP and len(body) == int(length), "WSLC_HTTP_TRUNCATED_OR_BOUND")
    try:
        return int(lines[0][9:12]), body.decode("utf-8")
    except UnicodeError:
        raise Fault("WSLC_HTTP_BODY_UTF8_INVALID") from None


# The guest has Bash/coreutils, not Python. Read exactly Content-Length, never
# a second EOF read. Host independently checks every byte and duplicate header.
HTTP_PROGRAM = r'''set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/"$1"
cat >&3
total=0; length=''; first=1
while IFS= read -r -n 8193 line <&3; do
  total=$((total + ${#line} + 1))
  [ "$total" -le 16384 ] && [ "${#line}" -le 8192 ] || exit 71
  [[ "$line" == *$'\r' ]] || exit 72
  printf '%s\n' "$line"
  if [ "$first" = 1 ]; then first=0; continue; fi
  [ "$line" != $'\r' ] || break
  IFS=: read -r name value <<< "$line"
  name=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
  value=$(printf '%s' "$value" | tr -d '\r' | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//')
  [ "$name" != transfer-encoding ] || exit 73
  if [ "$name" = content-length ]; then
    [ -z "$length" ] && [[ "$value" =~ ^[0-9]{1,10}$ ]] || exit 74
    length=$((10#$value)); [ "$length" -le 4194304 ] || exit 75
  fi
done
[ -n "$length" ] || exit 76
head -c "$length" <&3
'''


def run_bounded(argv, *, data=None, timeout=12, out_cap=INPUT_CAP, err_cap=STDERR_CAP, popen=None):
    """Both pipes bounded DURING read; deadline also covers blocked stdin."""
    factory = popen or subprocess.Popen
    try:
        child = factory(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError:
        raise Fault("WSLC_PROCESS_START_FAILED") from None
    result = [bytearray(), bytearray()]
    failure = threading.Event()
    def drain(stream, index, cap):
        try:
            while True:
                block = stream.read(min(65536, cap + 1 - len(result[index])))
                if not block:
                    return
                result[index].extend(block)
                if len(result[index]) > cap:
                    failure.set(); return
        except (OSError, ValueError):
            failure.set()
    def feed():
        try:
            child.stdin.write(data); child.stdin.close()
        except (OSError, ValueError):
            failure.set()
    threads = [threading.Thread(target=drain, args=(child.stdout, 0, out_cap), daemon=True),
               threading.Thread(target=drain, args=(child.stderr, 1, err_cap), daemon=True)]
    if data is not None:
        threads.append(threading.Thread(target=feed, daemon=True))
    for worker in threads:
        worker.start()
    deadline = time.monotonic() + timeout
    try:
        while child.poll() is None or any(worker.is_alive() for worker in threads):
            require(not failure.is_set(), "WSLC_PROCESS_CHANNEL_BOUND_OR_IO")
            require(time.monotonic() < deadline, "WSLC_PROCESS_TIMEOUT")
            time.sleep(.005)
        require(not failure.is_set(), "WSLC_PROCESS_CHANNEL_BOUND_OR_IO")
        return child.returncode, bytes(result[0]), bytes(result[1])
    finally:
        if child.poll() is None:
            child.kill()  # Exact Popen handle only, never a PID/name/VM lookup.
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        # Daemon workers cannot hold the owner main loop outside its cleanup.
        for worker in threads:
            worker.join(.05)


def focus_sample(raw):
    require(len(raw) <= LOG_CAP, "WSLC_FOCUS_LOG_BOUND")
    prefix = b"[toolkit-remote-focus-v1] "
    result = None
    previous = 0
    for line in raw.splitlines():
        if not line.startswith(prefix):
            continue
        require(len(line) <= 1024, "WSLC_FOCUS_LINE_BOUND")
        item = strict_json(line[len(prefix):], 1024)
        exact(item, ("schema", "pid", "sample_seq", "window_id", "window_index", "widget_id", "focused", "widget_uid"), "WSLC_FOCUS_SAMPLE_INVALID")
        require(item["schema"] == "toolkit-remote-focus-probe-v1" and uint(item["pid"], (1 << 32) - 1, True)
            and uint(item["sample_seq"], positive=True) and item["sample_seq"] > previous
            and item["widget_id"] == "input_singleline" and type(item["focused"]) is bool,
            "WSLC_FOCUS_SAMPLE_INVALID")
        require(item["window_id"] in (None, "main_window")
            and (item["window_index"] is None or uint(item["window_index"]))
            and (item["widget_uid"] is None or uint(item["widget_uid"], positive=True)), "WSLC_FOCUS_SAMPLE_INVALID")
        if item["focused"]:
            require(item["window_id"] == "main_window" and item["window_index"] is not None and item["widget_uid"] is not None, "WSLC_FOCUS_SAMPLE_INVALID")
        previous, result = item["sample_seq"], item
    return result


def packet(raw, previous):
    value = strict_json(raw)
    exact(value, ("version", "sequence", "operation", "arguments"), "WSLC_PACKET_SCHEMA_INVALID")
    require(type(value["version"]) is int and value["version"] == 1
        and uint(value["sequence"], positive=True) and value["sequence"] == previous + 1,
        "WSLC_CORRELATION_INVALID")
    require(isinstance(value["operation"], str) and value["operation"] in OPS, "WSLC_OPERATION_REFUSED")
    keys = {"request": ("target", "mutating"), "copy_frame": ("metadata", "dispatched_ms")}.get(value["operation"], ())
    exact(value["arguments"], keys)
    return value


def encode_reply(value):
    try:
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"
        require(len(raw) <= OUTPUT_CAP, "WSLC_OUTPUT_PACKET_BOUND")
        return raw
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise Fault("WSLC_OUTPUT_PACKET_INVALID") from None


def write_claim(path, value):
    """Atomic, single-use ownership token. Never truncate/reclaim an old token."""
    try:
        with path.open("xb") as stream:
            stream.write(encode_reply(value))
    except FileExistsError:
        raise Fault("WSLC_CONTAINER_ALREADY_CLAIMED") from None


def write_deadline(raw, write, ttl=IO_TTL):
    """A blocked parent reader cannot prevent the finally cleanup path."""
    done = queue.Queue(maxsize=1)
    def worker():
        try:
            offset = 0
            while offset < len(raw):
                amount = write(raw[offset:])
                require(type(amount) is int and 0 < amount <= len(raw) - offset, "WSLC_PIPE_WRITE_FAILED")
                offset += amount
            done.put(True)
        except Exception:
            done.put(False)
    threading.Thread(target=worker, daemon=True).start()
    try:
        require(done.get(timeout=ttl), "WSLC_PIPE_WRITE_FAILED")
    except queue.Empty:
        raise Fault("WSLC_PIPE_WRITE_TIMEOUT") from None


def utc(value):
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(result.tzinfo is not None, "WSLC_CREATOR_TIME_INVALID")
        return result
    except (AttributeError, TypeError, ValueError):
        raise Fault("WSLC_CREATOR_TIME_INVALID") from None


def exclusive_context(ctx, creator, actual, expected, owner, now=None, *, fresh=True, allow_stopped=False,
                      memory_max=FOCUS_MEMORY_MAX):
    """Pure join, never authority from a name or owns_container flag alone."""
    now = now or dt.datetime.now(dt.timezone.utc)
    require(type(ctx) is dict and type(creator) is dict and type(actual) is dict, "WSLC_CREATOR_PROOF_INVALID")
    nonce = ctx.get("exclusive_nonce")
    require(isinstance(nonce, str) and bool(re.fullmatch(r"[a-f0-9]{32}", nonce)), "WSLC_EXCLUSIVE_NONCE_REQUIRED")
    require(ctx.get("container_id") == expected["container_id"] and ctx.get("image") == expected["image_id"]
        and ctx.get("container_name") == "aiui-workspace-20261008" and ctx.get("owns_container") is True
        and ctx.get("owns_vm") is False and ctx.get("resumable") is False
        and ctx.get("source_revision") == PIN and ctx.get("exclusive_owner") == owner
        and ctx.get("gpu_profile") == "gpu_nvidia_test", "WSLC_EXCLUSIVE_CONTEXT_REQUIRED")
    require(type(memory_max) is int and memory_max in (FOCUS_MEMORY_MAX, MODULE_MEMORY_MAX), "WSLC_MEMORY_PROFILE_INVALID")
    if memory_max == MODULE_MEMORY_MAX:
        require(ctx.get("wslc_profile") == "wslc_multi_module" and ctx.get("module_shell_profile_kind") == "ModuleShell"
            and ctx.get("module_shell_source_manifest_sha256") == MODULE_SOURCE_SHA256
            and expected.get("executable_sha256", "").upper() == MODULE_ELF_SHA256, "WSLC_MODULE_PROFILE_INVALID")
    env_args = [part for key,value in MODULE_ENV.items() for part in ("--env",key+"="+value)] if memory_max == MODULE_MEMORY_MAX else []
    args = ["run", "--detach", "--rm", "--name", "aiui-workspace-20261008", "--memory", "2G" if memory_max == MODULE_MEMORY_MAX else "1G", "--cpus", "1",
        "--gpus", "all", *env_args, "--label", "aiui.toolkit.owner=" + owner, "--label", "aiui.toolkit.nonce=" + nonce,
        expected["image_id"], "sleep", "1800"]
    require(creator.get("args") == args and creator.get("executable", "").casefold() == WSLC.casefold()
        and creator.get("exit_code") == 0 and type(creator.get("exit_code")) is int
        and creator.get("timed_out") is False and creator.get("output_drained") is True
        and creator.get("stdout", "").strip() == expected["container_id"]
        and uint(creator.get("duration_ms")), "WSLC_CREATOR_RECEIPT_MISMATCH")
    created, started, dispatched = utc(actual.get("Created")), utc(actual.get("State", {}).get("StartedAt")), utc(creator.get("started_utc"))
    require(-2 <= (created - dispatched).total_seconds() <= creator["duration_ms"] / 1000 + 5
        and 0 <= (started - created).total_seconds() <= 60 and (now - created).total_seconds() >= 0
        and (not fresh or (now - created).total_seconds() <= 900),
        "WSLC_CREATOR_TIME_MISMATCH")
    require(actual.get("Id") == expected["container_id"] and actual.get("Image") == expected["image_id"]
        and actual.get("Name") == "/aiui-workspace-20261008"
        and type(actual.get("State", {}).get("Running")) is bool
        and (allow_stopped or actual["State"]["Running"] is True)
        and ctx.get("container_created") == actual["Created"] and ctx.get("container_started_at") == actual["State"]["StartedAt"],
        "WSLC_CONTAINER_INCARNATION_CHANGED")
    host, cfg = actual.get("HostConfig", {}), actual.get("Config", {})
    if memory_max == MODULE_MEMORY_MAX:
        env = cfg.get("Env")
        require(type(env) is list and all(type(v) is str for v in env), "WSLC_MODULE_ENVIRONMENT_INVALID")
        for key,value in MODULE_ENV.items():
            require([v for v in env if v.startswith(key+"=")] == [key+"="+value], "WSLC_MODULE_ENVIRONMENT_INVALID")
    require(host.get("Memory") == memory_max and type(host.get("Memory")) is int
        and host.get("NanoCpus") == 1000000000 and type(host.get("NanoCpus")) is int
        and host.get("NetworkMode") == "bridge" and host.get("Privileged", False) is False
        and actual.get("Mounts") == [] and actual.get("Ports") == {}
        and cfg.get("Cmd") == ["sleep", "1800"] and cfg.get("Entrypoint") is None,
        "WSLC_CONTAINER_CONFIGURATION_REFUSED")
    for labels in (cfg.get("Labels", {}), actual.get("Labels", cfg.get("Labels", {}))):
        require(type(labels) is dict and labels.get("aiui.toolkit.owner") == owner
            and labels.get("aiui.toolkit.nonce") == nonce, "WSLC_EXCLUSIVE_LABEL_MISMATCH")
    return {"container_id": expected["container_id"], "created": actual["Created"],
        "started_at": actual["State"]["StartedAt"], "owner": owner, "nonce": nonce}


def process_stat(raw):
    try:
        text = raw.decode("ascii")
        suffix = text.rsplit(")", 1)[1].split()
        pid = int(text.split("(", 1)[0].strip())
        require(uint(pid, (1 << 32) - 1, True) and len(suffix) >= 20 and decimal(suffix[19]), "WSLC_PROCESS_STAT_INVALID")
        return pid, suffix[19], suffix[0]
    except (UnicodeError, ValueError, IndexError):
        raise Fault("WSLC_PROCESS_STAT_INVALID") from None


# One bounded guest RPC. Both executable handles remain open for the entire
# observation; no guest Python, installation, shell-selected path or mutation.
KERNEL_FD_PROGRAM = r'''
set -euo pipefail
export LC_ALL=C
pid=$1; app=$2; port=$3; witness_pid=$$
jstring() {
 local s=$1 c n i
 printf '"'
 for ((i=0;i<${#s};i++)); do
  c=${s:i:1}
  case "$c" in
   '"') printf '\\"';; '\') printf '\\\\';;
   *) printf -v n '%d' "'$c"; if ((n<32)); then printf '\\u%04x' "$n"; else printf '%s' "$c"; fi;;
  esac
 done
 printf '"'
}
safe_path() {
 local p=$app part current=''
 [[ $p == /* && $(readlink -f -- "$p") == "$p" ]] || exit 71
 IFS=/ read -ra parts <<< "$p"
 for part in "${parts[@]}"; do
  [[ -n $part ]] || continue
  current=$current/$part; [[ ! -L $current ]] || exit 71
 done
 [[ -f $p && $(stat -c %h -- "$p") == 1 ]] || exit 71
}
fdstat() {
 local raw dev ino links size secs pretty kind nanos
 raw=$(stat -L -c '%d|%i|%h|%s|%Z|%z|%F' -- "/proc/$witness_pid/fd/$1")
 IFS='|' read -r dev ino links size secs pretty kind <<< "$raw"
 # Only the exact approved ModuleShell length extends the native read bound.
 # The host parser still enforces profile-specific limits and actual ELF SHA.
 [[ $kind == 'regular file' && $links == 1 && $size =~ ^[1-9][0-9]*$ && ($size -le 134217728 || $size -eq 366682664) && $secs =~ ^[0-9]+$ ]] || exit 71
 [[ $pretty =~ \.([0-9]{9})[[:space:]][+-][0-9]{4}$ ]] || exit 71
 nanos=$secs${BASH_REMATCH[1]}
 printf '{"dev":"%s","inode":"%s","nlink":"%s","size":"%s","ctime_ns":"%s"}' "$dev" "$ino" "$links" "$size" "$nanos"
}
snapshot() {
 local proc link ns mnt ef pf
 safe_path
 proc=$(cat "/proc/$pid/stat"); link=$(readlink "/proc/$pid/exe")
 ns=$(readlink "/proc/$pid/ns/pid"); mnt=$(readlink "/proc/$pid/ns/mnt")
 ef=$(fdstat 3) || return 71
 pf=$(fdstat 4) || return 71
 printf '{"proc_stat_raw":'; jstring "$proc"; printf ',"exe_link":'; jstring "$link"
 printf ',"pid_namespace":'; jstring "$ns"; printf ',"mount_namespace":'; jstring "$mnt"
 printf ',"executable_fd_stat":%s,"guest_path_fd_stat":%s}' "$ef" "$pf"
}
started=$(date +%s%N)
safe_path
exec 3<"/proc/$pid/exe" 4<"$app"
before=$(snapshot) || exit 71
proc=$(cat "/proc/$pid/stat"); suffix=${proc##*) }; read -ra fields <<< "$suffix"; parent=${fields[1]}
parent_stat=$(cat "/proc/$parent/stat")
mapfile -d '' -t parent_argv < "/proc/$parent/cmdline"
for fd in 3 4; do
 [[ $(od -An -tx1 -N4 "/proc/$witness_pid/fd/$fd" | tr -d ' \n') == 7f454c46 ]] || exit 71
done
eh=$(sha256sum <&3); eh=${eh%% *}
ph=$(sha256sum <&4); ph=${ph%% *}
nonce=''; nonce_count=0
while IFS= read -r -d '' e; do
 if [[ $e == AIUI_REMOTE_LAUNCH_NONCE=* ]]; then nonce=${e#*=}; ((nonce_count+=1)); fi
done < "/proc/$pid/environ"
[[ $nonce_count == 1 && $nonce =~ ^[a-f0-9]{32}$ ]] || exit 71
printf -v endpoint '0100007F:%04X' "$port"
row=''; rows=0
while IFS= read -r line; do
 read -ra cols <<< "$line"
 if [[ ${cols[1]:-} == "$endpoint" && ${cols[3]:-} == 0A ]]; then row=$line; ((rows+=1)); fi
done < /proc/net/tcp
[[ $rows == 1 ]] || exit 71
read -ra cols <<< "$row"; inode=${cols[9]}; socket_fd=''; socket_count=0
for f in /proc/"$pid"/fd/*; do
 link=$(readlink "$f" 2>/dev/null || true)
 if [[ $link == "socket:[$inode]" ]]; then socket_fd=${f##*/}; ((socket_count+=1)); fi
done
[[ $socket_count == 1 ]] || exit 71
after=$(snapshot) || exit 71
parent_after=$(cat "/proc/$parent/stat")
mapfile -d '' -t parent_argv_after < "/proc/$parent/cmdline"
ended=$(date +%s%N)
printf '{"schema":"toolkit-wslc-proc-fd-executable-report-v1","pid":%s,"guest_path":' "$pid"; jstring "$app"
printf ',"before":%s,"after":%s,"executable_fd_sha256":"%s","guest_path_fd_sha256":"%s","parent":{"pid":%s,"proc_stat_raw":' "$before" "$after" "$eh" "$ph" "$parent"
jstring "$parent_stat"; printf ',"argv":['; comma=''
for arg in "${parent_argv[@]}"; do printf '%s' "$comma"; jstring "$arg"; comma=','; done
printf '],"after_proc_stat_raw":'; jstring "$parent_after"; printf ',"argv_after":['; comma=''
for arg in "${parent_argv_after[@]}"; do printf '%s' "$comma"; jstring "$arg"; comma=','; done
printf ']},"launch_nonce":'; jstring "$nonce"
printf ',"listener":{"host":"127.0.0.1","port":%s,"inode":"%s","socket_fd":%s,"socket_fd_link":"socket:[%s]","proc_net_tcp_row":' "$port" "$inode" "$socket_fd" "$inode"
jstring "$row"
printf '},"observed_start_unix_ns":"%s","observed_end_unix_ns":"%s"}\n' "$started" "$ended"
'''


# Runtime-only batching. The one-time Core launch witness keeps the exact
# KERNEL_FD_PROGRAM invocation above. No identity field or hash is cached.
IDENTITY_CGROUP_PROGRAM = r'''
set -euo pipefail
[[ $# -eq 4 ]] || exit 71
kernel=$1; shift
bash -c "$kernel" toolkit-kernel-fds "$@"
printf 'TOOLKIT_IDENTITY_CGROUP_V1\n'
cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max
'''


def cgroup_observation(raw):
    require(type(raw) is bytes and len(raw) <= 128, "WSLC_CGROUP_MISMATCH")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        raise Fault("WSLC_CGROUP_MISMATCH") from None
    require(len(lines) == 2 and decimal(lines[0]) and lines[1] == "100000 100000", "WSLC_CGROUP_MISMATCH")
    return int(lines[0]), lines[1]


def identity_cgroup_observation(raw):
    marker = b"\nTOOLKIT_IDENTITY_CGROUP_V1\n"
    require(type(raw) is bytes and len(raw) <= INPUT_CAP and raw.count(marker) == 1, "WSLC_KERNEL_CGROUP_FRAME_INVALID")
    kernel, cgroups = raw.split(marker)
    return kernel + b"\n", cgroup_observation(cgroups)


def kernel_fd_report(raw, expected, pid, owned, parent, nonce, port, host_before_ns, host_after_ns,
                     *, max_executable_bytes=128*1024*1024):
    """Validate observations, not claimed success flags. CPU counters may change."""
    value = strict_json(raw)
    require(max_executable_bytes == 128*1024*1024 or
        (max_executable_bytes == 512*1024*1024 and expected.get("executable_sha256", "").upper() == MODULE_ELF_SHA256),
        "WSLC_KERNEL_FILE_INVALID")
    exact(value, ("schema", "pid", "guest_path", "before", "after", "executable_fd_sha256",
        "guest_path_fd_sha256", "parent", "launch_nonce", "listener", "observed_start_unix_ns", "observed_end_unix_ns"))
    require(value["schema"] == "toolkit-wslc-proc-fd-executable-report-v1"
        and type(value["pid"]) is int and value["pid"] == pid
        and value["guest_path"] == expected["executable"], "WSLC_KERNEL_REPORT_IDENTITY")
    def proc(raw_text):
        require(type(raw_text) is str, "WSLC_PROCESS_STAT_INVALID")
        p, birth, state = process_stat(raw_text.encode("utf-8"))
        fields = raw_text.rsplit(")", 1)[1].split()
        require(fields[1].isdigit() and state not in ("Z", "X"), "WSLC_STALE_PROCESS")
        return p, birth, int(fields[1]), state
    def file_identity(value):
        exact(value, ("dev", "inode", "nlink", "size", "ctime_ns"))
        require(all(type(v) is str and re.fullmatch(r"0|[1-9][0-9]*", v) for v in value.values())
            and int(value["inode"]) > 0 and value["nlink"] == "1"
            and 0 < int(value["size"]) <= max_executable_bytes, "WSLC_KERNEL_FILE_INVALID")
        return value
    before, after = value["before"], value["after"]
    keys = ("proc_stat_raw", "exe_link", "pid_namespace", "mount_namespace", "executable_fd_stat", "guest_path_fd_stat")
    for sample in (before, after):
        exact(sample, keys)
        require(sample["exe_link"] == expected["executable"], "WSLC_EXECUTABLE_CHANGED")
        for key, pattern in (("pid_namespace", r"pid:\[[1-9][0-9]*\]"), ("mount_namespace", r"mnt:\[[1-9][0-9]*\]")):
            require(type(sample[key]) is str and re.fullmatch(pattern, sample[key]) is not None, "WSLC_KERNEL_NAMESPACE_INVALID")
    p = proc(before["proc_stat_raw"])
    require(p[:3] == proc(after["proc_stat_raw"])[:3] and p[:3] == (pid, owned["birth"], owned["parent"]), "WSLC_GUEST_PID_REUSED")
    require(before["pid_namespace"] == after["pid_namespace"] and before["mount_namespace"] == after["mount_namespace"], "WSLC_KERNEL_NAMESPACE_CHANGED")
    first = file_identity(before["executable_fd_stat"])
    require(all(file_identity(s[k]) == first for s in (before, after)
        for k in ("executable_fd_stat", "guest_path_fd_stat")), "WSLC_KERNEL_FILE_CHANGED")
    for key in ("executable_fd_sha256", "guest_path_fd_sha256"):
        require(type(value[key]) is str and re.fullmatch(r"[a-fA-F0-9]{64}", value[key])
            and value[key].lower() == expected["executable_sha256"].lower(), "WSLC_EXECUTABLE_SHA256_MISMATCH")
    par = exact(value["parent"], ("pid", "proc_stat_raw", "argv", "after_proc_stat_raw", "argv_after"))
    require(type(par["pid"]) is int and par["pid"] == p[2]
        and proc(par["proc_stat_raw"])[:2] == (p[2], parent["birth"])
        and proc(par["after_proc_stat_raw"])[:3] == proc(par["proc_stat_raw"])[:3]
        and par["argv"] == par["argv_after"] == parent["argv"] and value["launch_nonce"] == nonce
        and re.fullmatch(r"[a-f0-9]{32}", nonce), "WSLC_GUEST_LAUNCH_NONCE_MISMATCH")
    listener = exact(value["listener"], ("host", "port", "inode", "socket_fd", "socket_fd_link", "proc_net_tcp_row"))
    require(listener["host"] == "127.0.0.1" and type(listener["port"]) is int and listener["port"] == port
        and decimal(listener["inode"]) and uint(listener["socket_fd"])
        and listener["socket_fd_link"] == "socket:[" + listener["inode"] + "]"
        and type(listener["proc_net_tcp_row"]) is str, "WSLC_LISTENER_OWNER_MISMATCH")
    row = listener["proc_net_tcp_row"].split()
    require(len(row) >= 10 and row[1] == "0100007F:%04X" % port and row[3] == "0A"
        and row[9] == listener["inode"], "WSLC_LISTENER_OWNER_MISMATCH")
    require(decimal(value["observed_start_unix_ns"]) and decimal(value["observed_end_unix_ns"]), "WSLC_KERNEL_CLOCK_INVALID")
    start, end = int(value["observed_start_unix_ns"]), int(value["observed_end_unix_ns"])
    require(type(host_before_ns) is int and type(host_after_ns) is int and 0 < host_before_ns <= host_after_ns
        and host_before_ns - 2_000_000_000 <= start <= end <= host_after_ns + 2_000_000_000
        and 0 <= end - start <= 12_000_000_000, "WSLC_KERNEL_CLOCK_INVALID")
    return value


def ps_rows(raw):
    result = {}
    try:
        for line in raw.decode("ascii").splitlines():
            match = re.fullmatch(r"\s*([0-9]+)\s+([0-9]+)\s+(\S+)\s*", line)
            require(match is not None, "WSLC_PROCESS_INVENTORY_INVALID")
            pid, parent = int(match[1]), int(match[2])
            require(pid not in result and uint(pid, (1 << 32)-1, True) and uint(parent, (1 << 32)-1), "WSLC_PROCESS_INVENTORY_INVALID")
            result[pid] = (parent, match[3])
    except UnicodeError:
        raise Fault("WSLC_PROCESS_INVENTORY_INVALID") from None
    require(1 in result, "WSLC_PROCESS_INVENTORY_INVALID")
    return result


def filtered_container_present(raw):
    """Parse successful drained, stderr-empty fixed-filter output supplied by caller.

    Native zero rows is exactly empty stdout. Object lines imply presence, not identity.
    """
    require(isinstance(raw, bytes) and len(raw) <= INPUT_CAP, "WSLC_ABSENCE_INVENTORY_INVALID")
    if raw == b"":
        return False
    try:
        for line in raw.splitlines():
            require(type(strict_json(line)) is dict, "WSLC_ABSENCE_INVENTORY_INVALID")
    except Fault:
        raise Fault("WSLC_ABSENCE_INVENTORY_INVALID") from None
    return True


def native_birth(pid, *, dotnet=False, owned_handle=None):
    require(os.name == "nt" and uint(pid, (1 << 32)-1, True), "WSLC_NATIVE_PID_INVALID")
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes, api.OpenProcess.restype = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE
    api.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    api.GetProcessTimes.restype = wintypes.BOOL
    api.CloseHandle.argtypes, api.CloseHandle.restype = [wintypes.HANDLE], wintypes.BOOL
    handle = wintypes.HANDLE(int(owned_handle)) if owned_handle is not None else api.OpenProcess(0x1000, False, pid)
    require(bool(handle), "WSLC_NATIVE_PROCESS_UNAVAILABLE")
    try:
        values = [wintypes.FILETIME() for _ in range(4)]
        require(bool(api.GetProcessTimes(handle, *(ctypes.byref(v) for v in values))), "WSLC_NATIVE_BIRTH_UNAVAILABLE")
        value = (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
        return str(value + (504911232000000000 if dotnet else 0))
    finally:
        if owned_handle is None:
            api.CloseHandle(handle)


# Executed only by this owner through the SAME Ubuntu upstream as stdio-relay.
# Fixed read-only Xlib calls; no shell, xprop, new listener, or injected program.
# The inner Linux timeout and run_bounded also bound a blocked Xlib connection.
def focus_content_title(cfg, tag):
    # Approved build34 uses WindowHandle's pinned-71 default "Makepad" and
    # remote::tag_window_title. This is independent of the observed RAIL title.
    expected = cfg.get("expected_identity", {})
    require(cfg.get("source_commit") == PIN and cfg.get("profile_kind") != "ModuleShell" and type(expected) is dict
        and expected.get("executable") == "/opt/proof/ai-workspace-fixture"
        and type(expected.get("executable_sha256")) is str and expected["executable_sha256"].upper() ==
            "9DFA4EEC8D4FEE6CAEE509D4FF2ACCB5136FED3A1D64D2302F0E35FF623AA4CB"
        and type(tag) is str and re.fullmatch(r"toolkit-wslc-[a-f0-9]{24}", tag),
        "WSLC_GEOMETRY_TITLE_PROFILE_UNSUPPORTED")
    return "Makepad [" + tag + "]"


def supported_rail_title(guest_title, rail_title):
    # Exact observed WSLg Ubuntu projection, or an unadorned exact title.
    # Never remove a suffix from an observed title to construct X11 identity.
    return rail_title in (guest_title, guest_title + " (Ubuntu)")


X11_GEOMETRY_PROGRAM = r'''
import ctypes as C
import json, re, sys, time

DIAGNOSTIC = {"stage":"ARGUMENTS", "owned_candidates":[], "pid_matches":0}
def stage(name): DIAGNOSTIC["stage"] = name
def failure_diagnostic():
    return {"error":"WSLC_X11_GEOMETRY_UNVERIFIED", **DIAGNOSTIC}

def need(ok):
    if not ok: raise ValueError("WSLC_X11_GEOMETRY_UNVERIFIED")

def rectangle(v):
    need(type(v) is dict and set(v)=={"x","y","width","height"})
    need(all(type(n) is int for n in v.values()))
    need(abs(v["x"])<=1048576 and abs(v["y"])<=1048576)
    need(0<v["width"]<=65536 and 0<v["height"]<=65536)
    return v

def assemble(pid, title, window, root, client, parent_window, parent_frame, extents, pid_property):
    rectangle(client)
    need(type(pid) is int and 0<pid<2**32 and type(title) is str and 0<len(title)<=512)
    need(type(window) is int and window>0 and type(root) is int and root>0 and window!=root)
    if extents is not None:
        need(type(extents) is list and len(extents)==4 and all(type(n) is int and 0<=n<=32768 for n in extents))
        left,right,top,bottom=extents
        frame={"x":client["x"]-left,"y":client["y"]-top,
            "width":client["width"]+left+right,"height":client["height"]+top+bottom}
        if parent_window!=window:
            need(frame==parent_frame)
        source="NET_FRAME_EXTENTS"
    else:
        need(parent_window!=window and parent_frame is not None)
        frame=rectangle(parent_frame)
        left=client["x"]-frame["x"];top=client["y"]-frame["y"]
        right=frame["width"]-client["width"]-left;bottom=frame["height"]-client["height"]-top
        extents=[left,right,top,bottom]
        need(all(0<=n<=32768 for n in extents))
        source="REPARENT_FRAME"
    rectangle(frame)
    return {"schema":"toolkit-wslc-x11-content-geometry-v1","display":":0","expected_guest_pid":pid,
        "pid_property":pid_property,"identity_source":"APPROVED_LAUNCH_NONCE_AND_UNIQUE_TITLE" if pid_property is None else "NET_WM_PID_AND_UNIQUE_TITLE","title":title,
        "window":window,"root":root,"client":client,"frame":frame,"frame_extents":extents,
        "frame_source":source,"frame_window":parent_window if parent_window!=window else None}

class Attributes(C.Structure):
    _fields_=[("x",C.c_int),("y",C.c_int),("width",C.c_int),("height",C.c_int),
        ("border_width",C.c_int),("depth",C.c_int),("visual",C.c_void_p),("root",C.c_ulong),
        ("klass",C.c_int),("bit_gravity",C.c_int),("win_gravity",C.c_int),("backing_store",C.c_int),
        ("backing_planes",C.c_ulong),("backing_pixel",C.c_ulong),("save_under",C.c_int),
        ("colormap",C.c_ulong),("map_installed",C.c_int),("map_state",C.c_int),
        ("all_event_masks",C.c_long),("your_event_mask",C.c_long),("do_not_propagate_mask",C.c_long),
        ("override_redirect",C.c_int),("screen",C.c_void_p)]

def query(pid, title, lib=None):
    DIAGNOSTIC.clear();DIAGNOSTIC.update(stage="INPUT", owned_candidates=[], pid_matches=0)
    need(type(pid) is int and 0<pid<2**32 and type(title) is str
        and re.fullmatch(r"Makepad \[toolkit-wslc-[a-f0-9]{24}\]",title))
    marker=title[len("Makepad "):]
    stage("LOAD_XLIB")
    # Linux Xlib's format-32 property storage is unsigned long, including LP64.
    x=C.CDLL("libX11.so.6") if lib is None else lib; U=C.c_ulong; P=C.c_void_p
    def bind(name,args,result):
        f=getattr(x,name);f.argtypes=args;f.restype=result;return f
    open_display=bind("XOpenDisplay",[C.c_char_p],P)
    close=bind("XCloseDisplay",[P],C.c_int)
    default_root=bind("XDefaultRootWindow",[P],U)
    intern=bind("XInternAtom",[P,C.c_char_p,C.c_int],U)
    get=bind("XGetWindowProperty",[P,U,U,C.c_long,C.c_long,C.c_int,U,C.POINTER(U),C.POINTER(C.c_int),C.POINTER(U),C.POINTER(U),C.POINTER(P)],C.c_int)
    tree=bind("XQueryTree",[P,U,C.POINTER(U),C.POINTER(U),C.POINTER(C.POINTER(U)),C.POINTER(C.c_uint)],C.c_int)
    attributes=bind("XGetWindowAttributes",[P,U,C.POINTER(Attributes)],C.c_int)
    translate=bind("XTranslateCoordinates",[P,U,U,C.c_int,C.c_int,C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(U)],C.c_int)
    free=bind("XFree",[P],C.c_int);sync=bind("XSync",[P,C.c_int],C.c_int)
    errors=[]
    handler_type=C.CFUNCTYPE(C.c_int,P,P)
    @handler_type
    def error_handler(_,event):
        if not errors:errors.append(True)
        return 0
    set_error=bind("XSetErrorHandler",[handler_type],P);set_error(error_handler)
    stage("OPEN_DISPLAY");d=open_display(b":0");need(bool(d));deadline=time.monotonic()+3.0
    try:
        stage("ROOT_AND_ATOMS");root=int(default_root(d));need(root>0)
        atoms={name:int(intern(d,name.encode("ascii"),True)) for name in
            ("_NET_WM_PID","_NET_WM_NAME","UTF8_STRING","WM_NAME","STRING","CARDINAL","_NET_FRAME_EXTENTS")}
        def guard():
            sync(d,False);need(not errors and time.monotonic()<deadline)
        def prop(w,name):
            stage("PROPERTY_"+name)
            atom=atoms[name]
            if not atom:return None
            actual=U();fmt=C.c_int();count=U();remaining=U();data=P()
            rc=get(d,w,atom,0,1024,False,0,C.byref(actual),C.byref(fmt),C.byref(count),C.byref(remaining),C.byref(data))
            try:
                guard();need(rc==0 and remaining.value==0 and count.value<=4096)
                if not actual.value:return None
                if fmt.value==8:payload=C.string_at(data,count.value)
                elif fmt.value==32:
                    need(count.value<=1024);payload=[int(C.cast(data,C.POINTER(U))[i]) for i in range(count.value)]
                else:raise ValueError("WSLC_X11_PROPERTY_FORMAT")
                return int(actual.value),fmt.value,payload
            finally:
                if data:free(data)
        def children(w):
            stage("QUERY_TREE")
            rt=U();parent=U();values=C.POINTER(U)();count=C.c_uint()
            try:
                rc=tree(d,w,C.byref(rt),C.byref(parent),C.byref(values),C.byref(count))
                guard();need(rc!=0 and int(rt.value)==root and count.value<=4096)
                return int(parent.value),[int(values[i]) for i in range(count.value)]
            finally:
                if values:free(C.cast(values,P))
        def rect(w,outer=False):
            stage("FRAME_ATTRIBUTES" if outer else "CLIENT_ATTRIBUTES")
            a=Attributes();px=C.c_int();py=C.c_int();child=U()
            # Hidden RAIL content still has measurable X11 geometry. Never
            # turn map_state into focus/visibility; those keep their own guards.
            need(attributes(d,w,C.byref(a))!=0 and int(a.root)==root and a.klass==1
                and a.map_state in (0,1,2) and a.border_width>=0)
            stage("FRAME_TRANSLATE" if outer else "CLIENT_TRANSLATE")
            need(translate(d,w,root,0,0,C.byref(px),C.byref(py),C.byref(child))!=0);guard()
            border=a.border_width if outer else 0
            return rectangle({"x":px.value-border,"y":py.value-border,"width":a.width+2*border,"height":a.height+2*border})
        pending=[root];seen=set();matches=[]
        while pending:
            w=pending.pop();need(w not in seen and len(seen)<4096);seen.add(w)
            _,more=children(w);pending.extend(more);need(len(pending)+len(seen)<=4096)
            value=prop(w,"_NET_WM_NAME")
            if value is None:
                value=prop(w,"WM_NAME");encoding="latin-1";kind=atoms["STRING"]
            else:encoding="utf-8";kind=atoms["UTF8_STRING"]
            if value is None or value[1]!=8 or len(value[2])>2048:continue
            actual_title=value[2].decode(encoding,"strict")
            # Inspect PID only for our exact launch marker. Count exact-title
            # XIDs independently of PID, so a second/foreign match cannot hide.
            if marker in actual_title and len(DIAGNOSTIC["owned_candidates"])<16:
                pid_value=prop(w,"_NET_WM_PID")
                if pid_value==(atoms["CARDINAL"],32,[pid]):DIAGNOSTIC["pid_matches"]+=1
                diagnostic_pid=None if pid_value is None else {"type":pid_value[0],"format":pid_value[1],"values":list(pid_value[2][:4])}
                DIAGNOSTIC["owned_candidates"].append({"window":w,"expected_guest_pid":pid,"title":actual_title[:512],"pid_property":diagnostic_pid})
            if actual_title==title:
                stage("EXACT_TITLE_PROPERTY_TYPE");need(value[0]==kind)
                matches.append(w)
        stage("UNIQUE_EXACT_TITLE");DIAGNOSTIC["exact_matches"]=len(matches);need(len(matches)==1)
        window=matches[0];pid_before=prop(window,"_NET_WM_PID")
        stage("PID_PROPERTY_IDENTITY")
        need(pid_before is None or pid_before==(atoms["CARDINAL"],32,[pid]))
        pid_property=None if pid_before is None else pid
        client=rect(window)
        def ancestry():
            top=window;chain=[window]
            for _ in range(32):
                parent,_=children(top)
                if parent==root:return top,chain
                need(parent>0 and parent not in chain);chain.append(parent);top=parent
            raise ValueError("WSLC_X11_PARENT_DEPTH")
        top,chain=ancestry()
        frame=rect(top,True) if top!=window else None
        value=prop(window,"_NET_FRAME_EXTENTS")
        if value is not None:need(value[0]==atoms["CARDINAL"] and value[1]==32 and len(value[2])==4)
        stage("FRAME_CONTENT_AGREEMENT")
        result=assemble(pid,title,window,root,client,top,frame,value[2] if value else None,pid_property)
        # Re-observe exact selected identity and geometry before publication.
        pid_after=prop(window,"_NET_WM_PID");client_after=rect(window);stage("RECHECK_PID_AND_CLIENT")
        need(pid_after==pid_before and client_after==client)
        value2=prop(window,"_NET_WM_NAME")
        if value2 is None:value2=prop(window,"WM_NAME");encoding="latin-1";kind=atoms["STRING"]
        else:encoding="utf-8";kind=atoms["UTF8_STRING"]
        stage("RECHECK_EXACT_TITLE");need(value2 is not None and value2[0]==kind and value2[1]==8 and value2[2].decode(encoding,"strict")==title)
        after_ancestry=ancestry();stage("RECHECK_ANCESTRY");need(after_ancestry==(top,chain))
        if frame is not None:
            after_frame=rect(top,True);stage("RECHECK_FRAME");need(after_frame==frame)
        value2=prop(window,"_NET_FRAME_EXTENTS")
        stage("RECHECK_FRAME_EXTENTS");need(value2==value);guard()
        return result
    finally:close(d)

if __name__=="__main__":
    try:
        need(len(sys.argv)==3);result=query(int(sys.argv[1]),sys.argv[2])
        print(json.dumps(result,separators=(",",":"),allow_nan=False))
    except Exception:
        print(json.dumps(failure_diagnostic(),separators=(",",":"),allow_nan=False));sys.exit(2)
'''


def same_rail_identity(expected, observed, tag):
    # Launch captures visibility before the owner's deliberate SW_HIDE. It is
    # state, not HWND/PID/birth identity; compare it to the validated current
    # identity separately instead of comparing the whole stale launch dict.
    return (type(expected) is dict and type(observed) is dict
        and not observed.get("observation_error")
        and all(type(observed.get(k)) is int and observed[k] > 0 for k in ("hwnd", "pid"))
        and type(observed.get("birth")) is str and observed["birth"].isdigit()
        and all(expected.get(k) == observed.get(k) for k in ("hwnd", "pid", "birth", "title"))
        and type(observed.get("title")) is str and tag in observed["title"])


def rail_geometry(rail):
    """Read physical Win32 rectangles in the existing owner; never activate."""
    require(os.name == "nt", "WSLC_WINDOWS_HOST_REQUIRED")
    api = ctypes.WinDLL("user32", use_last_error=True)
    api.SetThreadDpiAwarenessContext.argtypes = [ctypes.c_void_p]
    api.SetThreadDpiAwarenessContext.restype = ctypes.c_void_p
    api.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    api.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    api.ClientToScreen.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
    previous = api.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
    require(bool(previous), "WSLC_NATIVE_GEOMETRY_DPI_UNVERIFIED")
    try:
        hwnd = wintypes.HWND(rail["hwnd"])
        client, outer, origin = wintypes.RECT(), wintypes.RECT(), wintypes.POINT()
        require(bool(api.GetClientRect(hwnd, ctypes.byref(client)))
            and bool(api.GetWindowRect(hwnd, ctypes.byref(outer)))
            and bool(api.ClientToScreen(hwnd, ctypes.byref(origin))), "WSLC_NATIVE_GEOMETRY_UNAVAILABLE")
        result = {"native_client":{"x":origin.x,"y":origin.y,"width":client.right-client.left,"height":client.bottom-client.top},
            "native_outer":{"x":outer.left,"y":outer.top,"width":outer.right-outer.left,"height":outer.bottom-outer.top}}
        require(all(r["width"]>0 and r["height"]>0 for r in result.values()), "WSLC_NATIVE_GEOMETRY_INVALID")
        return result
    finally:
        require(bool(api.SetThreadDpiAwarenessContext(previous)), "WSLC_NATIVE_GEOMETRY_DPI_RESTORE_FAILED")


def rail_windows():
    require(os.name == "nt", "WSLC_WINDOWS_HOST_REQUIRED")
    api = ctypes.WinDLL("user32", use_last_error=True)
    callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    api.EnumWindows.argtypes, api.EnumWindows.restype = [callback, wintypes.LPARAM], wintypes.BOOL
    api.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    api.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    api.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    api.IsWindowVisible.argtypes, api.IsWindowVisible.restype = [wintypes.HWND], wintypes.BOOL
    result = []
    @callback
    def visit(hwnd, _):
        cls, title, pid = ctypes.create_unicode_buffer(128), ctypes.create_unicode_buffer(512), wintypes.DWORD()
        api.GetClassNameW(hwnd, cls, len(cls))
        if cls.value == "RAIL_WINDOW":
            api.GetWindowTextW(hwnd, title, len(title)); api.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            try:
                birth = native_birth(pid.value)
            except Fault as exc:
                # Keep the HWND/title: an unobservable owned window is NOT gone.
                result.append({"hwnd": int(hwnd), "pid": pid.value, "title": title.value,
                    "visible": bool(api.IsWindowVisible(hwnd)), "birth": None, "observation_error": exc.code})
                return True
            result.append({"hwnd": int(hwnd), "pid": pid.value, "title": title.value,
                "visible": bool(api.IsWindowVisible(hwnd)), "birth": birth})
        return True
    require(bool(api.EnumWindows(visit, 0)), "WSLC_RAIL_INVENTORY_FAILED")
    return result


def pipe_streams():
    """Only anonymous stdio; _Job duplicates these into its handle allowlist."""
    read_fd, write_fd = os.pipe()
    try:
        source = os.fdopen(read_fd, "rb")
    except BaseException:
        os.close(read_fd); os.close(write_fd)
        raise
    try:
        sink = os.fdopen(write_fd, "wb", buffering=0)
    except BaseException:
        source.close(); os.close(write_fd)
        raise
    return source, sink


class RetainedChild:
    """Thin lifecycle view of the existing owned_driver._Job, not another owner.

    Register this view before _Job.start. The Job HANDLE, not a sidecar/PID/birth
    lookup, remains sufficient to retire any partially-created native tree.
    """
    def __init__(self, job):
        self.job = job
        self.returncode = None
        self.retirement = None

    @property
    def pid(self):
        return self.job.pid

    def poll(self):
        require(self.retirement is None and self.job.process is not None, "WSLC_CHILD_NOT_OBSERVABLE")
        if self.returncode is None and self.job.exited():
            self.returncode = self.job.exit_code()
        return self.returncode

    def empty(self):
        return self.active_processes() == 0

    def active_processes(self):
        return self.job.active()

    def retire(self, reason):
        if self.retirement is None:
            # dispose always closes its Job/root/query handles, even if its
            # observation fails. Never retry those closed handles or fake proof.
            try:
                self.retirement = self.job.dispose(reason).as_dict()
            except Exception as exc:
                evidence = getattr(exc, "cleanup", None)
                self.retirement = evidence.as_dict() if evidence is not None else {"confirmed": False}
                self.retirement["confirmed"] = False
                self.retirement["error_code"] = "WSLC_NATIVE_JOB_RETIREMENT_UNCONFIRMED"
        return self.retirement


class Owner:
    """One exclusive container, existing helpers, no semantic action dispatch."""
    def __init__(self, cfg):
        self.cfg = config(cfg)
        self.runtime = host_path(cfg["runtime_directory"], EVIDENCE)
        self.output = host_path(cfg["output_directory"], EVIDENCE)
        self.admission = host_path(cfg["admission_path"], EVIDENCE)
        self.adopted = False
        self.dispatched = False
        self.cleaned = False
        self.identity = None
        self.began = time.monotonic()
        self.freeze = {}
        for path in [Path(__file__), *(HELPERS / name for name in ("stdio-relay.ps1", "cleanup-runtime.ps1",
            "capture-process.ps1", "native-inventory.ps1", "gpu_policy.py", "gpu-profiles.json", "manager.py", "owned_driver.py", "storage_policy.py", "storage-policy.json"))]:
            path = host_path(path, ROOT)
            self.freeze[path] = hashlib.sha256(read_bounded(path, 4 * 1024 * 1024)).digest()
        if profile_memory_max(self.cfg) == MODULE_MEMORY_MAX:
            path = host_path(HELPERS / "module-shell-profile.py", ROOT)
            self.freeze[path] = hashlib.sha256(read_bounded(path, 4 * 1024 * 1024)).digest()
        self.evidence_index = 0
        self.children = {}
        self.bindings = {}
        self.context = self.creator = self.incarnation = None
        self.guest_owners = {}
        self.rail = None
        self.pid = self.port = None
        self.grabs = None
        self.last_grab = None
        self.seen_grabs = set()
        self.cleanup_result = None
        self.cleanup_attempts = 0
        self.normal_exit_result = None
        self.reap_observations = 0
        self.tag = "toolkit-wslc-" + hashlib.sha256(cfg["session_id"].encode()).hexdigest()[:24]
        self.profile_module = None
        self.driver_module = None
        self.stream_failure = threading.Event()
        self.drainers = []
        self.deadline = self.began + profile_runtime_budget(self.cfg)[2]
        self.cleaning = False
        self.launch_nonces = {kind: secrets.token_hex(16) for kind in ("app", "relay")}
        self.kernel_latest = None
        self.running_witness_saved = False
        self.app_launch_started_ns = None
        self.app_launch_observed_ns = None
        self.geometry_index = 0
        self.storage_monitor_enabled = False
        self.storage_host_reserved = 0
        self.storage_capture_count = 0

    def reserve_host_storage(self, incoming):
        # Session-local monotonic reservations: errors/unknown outcomes do not
        # refund bytes and never authorize replay. Keep 2MiB for cleanup receipts.
        require(type(incoming) is int and incoming >= 0, 'WSLC_STORAGE_WRITE_BUDGET_INVALID')
        limit = 256*1024*1024 - (0 if getattr(self,'cleaning',False) else 2*1024*1024)
        used = getattr(self,'storage_host_reserved',0)
        require(used + incoming <= limit, 'WSLC_STORAGE_HOST_BUDGET_REFUSED')
        try:self.storage_policy().ensure_host_reserve(incoming)
        except Exception as error:
            raise Fault('WSLC_HOST_STORAGE_RESERVE_REFUSED') from error
        self.storage_host_reserved = used + incoming

    def storage_guard(self, incoming=0):
        if not getattr(self,'storage_monitor_enabled',False):return
        try:
            actual=self.inspect(with_size=True)
            joined=exclusive_context(self.context,self.creator,actual,self.cfg['expected_identity'],self.cfg['owner'],
                fresh=False,memory_max=profile_memory_max(self.cfg))
            require(joined==self.incarnation,'WSLC_CONTAINER_INCARNATION_CHANGED')
            observation=self.storage_policy().growth_decision(actual,self.context,incoming_bytes=incoming)
        except Fault:raise
        except Exception as error:
            code=getattr(error,'code','USAGE_NOT_VERIFIED')
            raise Fault('WSLC_'+code) from error
        self.evidence_index += 1
        observation.update(session_id=self.cfg['session_id'],generation=self.cfg['generation'])
        self.save('storage-usage-'+str(self.evidence_index)+'.json',observation)

    def budget(self, timeout):
        # Cleanup has its own finite reserve; ordinary calls share one absolute
        # lifetime, rather than resetting it for each nested native command.
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "WSLC_OWNER_LIFETIME_EXPIRED")
        return min(timeout, remaining)

    def runtime_ok(self):
        self.budget(1)
        require(not self.stream_failure.is_set(), "WSLC_RUNTIME_LOG_BOUND_OR_FAILURE")

    def frozen(self):
        for path, digest in self.freeze.items():
            host_path(path, ROOT)
            require(hashlib.sha256(read_bounded(path, 4 * 1024 * 1024)).digest() == digest, "WSLC_FIXED_HELPER_CHANGED")

    def save(self, name, value):
        require(bool(re.fullmatch(r"[a-z0-9_-]+\.json", name)), "WSLC_EVIDENCE_NAME_INVALID")
        host_path(self.output, EVIDENCE)
        path = host_path(self.output / name, EVIDENCE, exists=False)
        raw=encode_reply(value)
        self.reserve_host_storage(len(raw))
        with path.open("xb") as stream:
            stream.write(raw)

    def startup_state(self, body):
        raw = body.encode("utf-8")
        try:
            return strict_json(raw, HTTP_CAP)
        except Fault as exc:
            if self.cfg.get("profile_kind") == "ModuleShell":
                self.save("module-startup-state-refused.json", {"schema":"toolkit-module-shell-startup-state-v1",
                    "session_id":self.cfg["session_id"],"owner":self.cfg["owner"],"generation":self.cfg["generation"],
                    "container_id":self.context["container_id"],"guest_pid":self.pid,"status":200,"route":"/s",
                    "error_code":exc.code,"observed_utc":dt.datetime.now(dt.timezone.utc).isoformat(),"raw_utf8":body,
                    "bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest().upper()})
            raise

    def admit(self):
        value = strict_json(read_bounded(self.admission, INPUT_CAP))
        if profile_memory_max(self.cfg) == MODULE_MEMORY_MAX:
            return module_admission(value, self.cfg["owner"])
        return fresh_admission(value, owner=self.cfg["owner"])

    def bind_module_context(self):
        """Reopen the existing operator's exact source/native-build approval."""
        ctx = self.context
        require(ctx.get("module_shell_source_manifest_sha256") == MODULE_SOURCE_SHA256
            and ctx.get("module_shell_artifact_sha256") == MODULE_ELF_SHA256
            and ctx.get("module_shell_artifact_bytes") == 366682664
            and ctx.get("memory_max") == MODULE_MEMORY_MAX and ctx.get("module_instances") == 2,
            "WSLC_MODULE_CONTEXT_INVALID")
        helper = host_path(HELPERS / "module-shell-profile.py", ROOT)
        spec = importlib.util.spec_from_file_location("toolkit_owned_module_shell_profile", helper)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        build = ctx.get("module_shell_build_receipt", {})
        try:
            approval = module.validate_build_manifest(ROOT, build.get("path"), build.get("sha256"),
                ctx.get("module_shell_artifact_path"))
        except (module.ModuleShellProfileError, TypeError, OSError):
            raise Fault("WSLC_MODULE_BUILD_APPROVAL_REFUSED") from None
        approval_path = host_path(self.runtime / "module-shell-build-approval.json", ROOT)
        raw = read_bounded(approval_path, 4*1024*1024)
        require(hashlib.sha256(raw).hexdigest().upper() == ctx.get("module_shell_preparation_sha256")
            and module._same_typed_tree(strict_json(raw, 4*1024*1024), approval), "WSLC_MODULE_PREPARATION_CHANGED")
        for context_key, approval_key in (("module_shell_build_receipt","build_receipt"),
                ("module_shell_native_build_receipt","native_build_receipt"), ("module_shell_source_manifest","source_manifest")):
            require(module._same_typed_tree(ctx.get(context_key), approval[approval_key]), "WSLC_MODULE_RECEIPT_JOIN_MISMATCH")
            item = approval[approval_key]
            file = host_path(ROOT/item["path"], ROOT)
            self.freeze[file] = bytes.fromhex(item["sha256"])
        launch_path = host_path(self.runtime / "module-shell-launch-settings.json", ROOT)
        launch_raw = read_bounded(launch_path, INPUT_CAP)
        launch = strict_json(launch_raw)
        require(hashlib.sha256(launch_raw).hexdigest().upper() == ctx.get("module_shell_launch_settings_sha256")
            and launch.get("profile_kind") == "ModuleShell" and launch.get("public_ai_environment_used") is False
            and launch.get("fresh_container_required") is True and launch.get("home_directory_mode") == "0700"
            and launch.get("makepad_home") == ctx.get("module_shell_makepad_home") == MODULE_ENV["MAKEPAD_HOME"]
            and launch.get("project_id") == ctx.get("module_shell_project_id") == MODULE_ENV["TOOLKIT_MODULE_PROJECT_ID"]
            and launch.get("native_late_probe") == ctx.get("module_shell_native_late_probe") == MODULE_ENV["TOOLKIT_NATIVE_LATE_PROBE"],
            "WSLC_MODULE_LAUNCH_SETTINGS_INVALID")
        for file, raw in ((approval_path,raw),(launch_path,launch_raw)):
            self.freeze[file] = hashlib.sha256(raw).digest()
        self.save("module-shell-approval-binding.json", {"source_manifest_sha256":MODULE_SOURCE_SHA256,
            "artifact_sha256":MODULE_ELF_SHA256,"bytes":approval["artifact"]["bytes"],
            "owner":self.cfg["owner"],"session_id":self.cfg["session_id"],"generation":self.cfg["generation"],
            "container_id":self.cfg["expected_identity"]["container_id"],"host_memory_observation":"USER_WAIVED_NOT_MEASURED",
            "build_receipt":approval["build_receipt"],"source_manifest":approval["source_manifest"],
            "launch_settings_sha256":ctx["module_shell_launch_settings_sha256"]})

    def module_resources(self, stage):
        if profile_memory_max(self.cfg) != MODULE_MEMORY_MAX:
            return
        require(stage in ("startup", "before-quit"), "WSLC_RESOURCE_STAGE_INVALID")
        script = ('set -e; printf "START\\n"; cat /proc/$1/stat; printf "STATUS\\n"; cat /proc/$1/status; '
            'printf "CURRENT\\n"; cat /sys/fs/cgroup/memory.current; printf "PEAK\\n"; cat /sys/fs/cgroup/memory.peak; '
            'printf "EVENTS\\n"; cat /sys/fs/cgroup/memory.events; printf "LIMIT\\n"; cat /sys/fs/cgroup/memory.max; '
            'printf "CPU\\n"; cat /sys/fs/cgroup/cpu.max; printf "END\\n"; cat /proc/$1/stat')
        raw = self.text("sh", "-c", script, "toolkit-module-resources", str(self.pid))
        sections = {}; name = None
        for line in raw.splitlines():
            if line in ("START","STATUS","CURRENT","PEAK","EVENTS","LIMIT","CPU","END"):
                require(line not in sections, "WSLC_RESOURCE_OBSERVATION_INVALID"); name=line; sections[name]=[]
            elif name is not None:
                sections[name].append(line)
        owned = self.guest_owners[self.pid]
        require(process_stat("\n".join(sections["START"]).encode())[:2] ==
            process_stat("\n".join(sections["END"]).encode())[:2] == (self.pid,owned["birth"]), "WSLC_GUEST_PID_REUSED")
        def number(key):
            text = "\n".join(sections[key]); require(text.isdigit(), "WSLC_RESOURCE_OBSERVATION_INVALID"); return int(text)
        rss = re.search(r"^VmRSS:\s+(\d+) kB$", "\n".join(sections["STATUS"]), re.M)
        peak = re.search(r"^VmHWM:\s+(\d+) kB$", "\n".join(sections["STATUS"]), re.M)
        require(rss is not None and peak is not None and number("LIMIT") == MODULE_MEMORY_MAX
            and sections["CPU"] == ["100000 100000"], "WSLC_CGROUP_MISMATCH")
        events = dict(line.split() for line in sections["EVENTS"])
        self.save("module-resources-"+stage+".json", {"schema":"toolkit-module-shell-native-resources-v1",
            "observed_utc":dt.datetime.now(dt.timezone.utc).isoformat(),"owner":self.cfg["owner"],
            "session_id":self.cfg["session_id"],"generation":self.cfg["generation"],
            "container_id":self.cfg["expected_identity"]["container_id"],"guest_pid":self.pid,"process_birth":owned["birth"],
            "memory_max":number("LIMIT"),"memory_current":number("CURRENT"),"memory_peak":number("PEAK"),
            "process_rss_kib":int(rss[1]),"process_peak_rss_kib":int(peak[1]),"memory_events":events,
            "raw_utf8":raw,"available_memory_query_performed":False})
        require(events.get("oom") == "0" and events.get("oom_kill") == "0", "WSLC_MODULE_OOM_OBSERVED")

    def call(self, operation, arguments):
        self.dispatched = False
        self.frozen()
        if operation == "launch":
            require(not self.adopted and not self.cleaned, "WSLC_SESSION_REOPEN_REFUSED")
            self.admit()
            return self.launch()
        if operation == "cleanup":
            return self.cleanup()
        require(self.adopted and not self.cleaned, "WSLC_NO_ADOPTED_CONTAINER")
        if operation == "reap":
            return self.reap()
        if operation == "request":
            route, _ = request_target(arguments["target"], arguments["mutating"])
            # Normal close/retirement remain available after a growth refusal.
            if route != '/quit':self.storage_guard()
            if route == "/quit":
                # ModuleShell performs native reads here; retain its original
                # validation on both sides of that resource witness.
                if profile_memory_max(self.cfg) == MODULE_MEMORY_MAX:
                    self.validate()
                self.module_resources("before-quit")
            return self._request(arguments["target"], arguments["mutating"])
        actual = self.validate()
        if operation == "validate":
            return {"identity": actual}
        if operation == "host_content_geometry":
            return self.host_content_geometry(actual)
        if operation == "copy_frame":
            return self.copy_frame(arguments["metadata"], arguments["dispatched_ms"])
        if operation == "stderr":
            raw = read_bounded(self.runtime / "app.stderr.txt", STDERR_CAP)
            try:
                return {"lines": [line for line in raw.decode("utf-8").splitlines() if line.strip()]}
            except UnicodeError:
                raise Fault("WSLC_RUNTIME_STDERR_INVALID") from None
        if operation == "focus_sample":
            return {"identity": actual, "sample": focus_sample(read_log_prefix(self.runtime / "app.stdout.txt", LOG_CAP))}
        raise Fault("WSLC_OPERATION_REFUSED")

    def wslc(self, *args, data=None, timeout=12, cap=INPUT_CAP, check=True):
        if not self.cleaning:
            self.runtime_ok()
        code, out, err = run_bounded([WSLC, *args], data=data, timeout=self.budget(timeout), out_cap=cap)
        if check:
            require(code == 0, "WSLC_COMMAND_FAILED")
        return code, out, err

    def guest(self, *args, data=None, timeout=12, cap=INPUT_CAP, check=True):
        return self.wslc("exec", *(["-i"] if data is not None else []), self.cfg["expected_identity"]["container_id"],
            *args, data=data, timeout=timeout, cap=cap, check=check)

    def text(self, *args):
        try:
            return self.guest(*args)[1].decode("utf-8").strip()
        except UnicodeError:
            raise Fault("WSLC_GUEST_TEXT_INVALID") from None

    def inspect(self, *, with_size=False):
        args=['inspect',*(['--size'] if with_size else []),self.cfg['expected_identity']['container_id']]
        raw = self.wslc(*args, cap=1024*1024)[1]
        items = strict_json(raw, 1024*1024)
        require(type(items) is list and len(items) == 1 and type(items[0]) is dict, "WSLC_CONTAINER_INSPECT_INVALID")
        return items[0]

    def inspect_owned(self, *, allow_stopped=False):
        actual = self.inspect()
        joined = exclusive_context(self.context, self.creator, actual, self.cfg["expected_identity"], self.cfg["owner"],
            fresh=False, allow_stopped=allow_stopped, memory_max=profile_memory_max(self.cfg))
        require(joined == self.incarnation, "WSLC_CONTAINER_INCARNATION_CHANGED")
        return actual

    def proc(self, pid):
        code, raw, _ = self.guest("cat", f"/proc/{pid}/stat", check=False)
        if code:
            # cat failing can also mean a dead transport or an unreadable /proc.
            # Only a separately reachable inventory can corroborate absence.
            require(code == 1 and pid not in self.process_inventory(), "WSLC_PROCESS_ABSENCE_UNCONFIRMED")
            return None
        observed_pid, birth, state = process_stat(raw)
        require(observed_pid == pid, "WSLC_PROCESS_STAT_INVALID")
        return {"birth": birth, "state": state}

    def argv(self, pid):
        raw = self.guest("cat", f"/proc/{pid}/cmdline", cap=64*1024)[1]
        require(raw.endswith(b"\0"), "WSLC_PROCESS_ARGV_INVALID")
        try:
            return raw[:-1].decode("utf-8").split("\0")
        except UnicodeError:
            raise Fault("WSLC_PROCESS_ARGV_INVALID") from None

    def process_inventory(self):
        return ps_rows(self.guest("ps", "-eo", "pid=,ppid=,comm=")[1])

    def expected_commands(self):
        relay = ["socat", "-d", "-d", "UNIX-LISTEN:/tmp/.X11-unix/X66,mode=0600,unlink-close", "STDIO"]
        app = [self.cfg["expected_identity"]["executable"], "--remote=127.0.0.1:0",
            "--remote-title-tag=" + self.tag, "--linux-backend=x11"]
        app_seconds, relay_seconds, _ = profile_runtime_budget(self.cfg)
        return {"relay": [relay, ["timeout", "--signal=TERM", "--kill-after=2s", str(relay_seconds)+"s", *relay]],
            "app": [app, ["timeout", "--signal=TERM", "--kill-after=2s", str(app_seconds)+"s", *app]]}

    def check_processes(self, *, discover=None, cleanup=False):
        """Only PID1 and exactly bound relay/app processes may share this context."""
        require(discover is None or (discover in ("relay", "app")
            and ("runtime" if discover == "app" else discover) in self.children), "WSLC_UNOWNED_PROCESS_DISCOVERY")
        # A failure may occur after Popen but before normal startup discovery.
        # Only intents for children we actually started can be recovered here.
        discoverable = set()
        if cleanup:
            if "relay" in self.children:
                discoverable.add("relay")
            if "runtime" in self.children:
                discoverable.add("app")
        elif discover:
            discoverable.add(discover)
        expected = self.expected_commands()
        rows = self.process_inventory()
        kinds = {}
        discovered = []
        candidates = dict(self.guest_owners)
        for pid, (_, comm) in rows.items():
            # The inventory's own transient process is the only unbound observer.
            if comm == "ps":
                proc = self.proc(pid)
                if proc is None:
                    continue
                require(self.argv(pid) == ["ps", "-eo", "pid=,ppid=,comm="], "WSLC_FOREIGN_GUEST_PROCESS")
                continue
            current = self.proc(pid)
            if current is None:
                continue
            if pid in self.guest_owners:
                require(current["birth"] == self.guest_owners[pid]["birth"], "WSLC_GUEST_PID_REUSED")
                if cleanup and current["state"] in ("Z", "X"):
                    continue  # Known birth, terminal task; never new stop authority.
                try:
                    argv = self.argv(pid)
                except Fault as exc:
                    if not cleanup or exc.code != "WSLC_PROCESS_ARGV_INVALID":
                        raise
                    again = self.proc(pid)  # Absence itself requires independent inventory.
                    if again is None:
                        continue
                    require(again["birth"] == current["birth"], "WSLC_GUEST_PID_REUSED")
                    if again["state"] not in ("Z", "X"):
                        raise  # Empty argv from a live task is still unverified.
                    continue
                require(argv == self.guest_owners[pid]["argv"], "WSLC_GUEST_PROCESS_CHANGED")
                kinds.setdefault(self.guest_owners[pid]["kind"], []).append(pid)
                continue
            argv = self.argv(pid)
            matches = [kind for kind in discoverable if argv in expected[kind]]
            kind = "init" if pid == 1 and argv == ["sleep", "1800"] else (matches[0] if len(matches) == 1 else None)
            require(kind is not None, "WSLC_FOREIGN_GUEST_PROCESS")
            if kind != "init":
                environment = self.guest("cat", f"/proc/{pid}/environ", cap=INPUT_CAP)[1]
                key = b"AIUI_REMOTE_LAUNCH_NONCE="
                require([entry for entry in environment.split(b"\0") if entry.startswith(key)] ==
                    [key + self.launch_nonces[kind].encode("ascii")], "WSLC_GUEST_LAUNCH_NONCE_MISMATCH")
                again = self.proc(pid)
                require(again is not None and again["birth"] == current["birth"] and again["state"] != "Z", "WSLC_GUEST_PID_REUSED")
                discovered.append((pid, kind, argv))
            kinds.setdefault(kind, []).append(pid)
            candidates[pid] = {"birth": current["birth"], "argv": argv, "kind": kind, "parent": rows[pid][0]}
        require(all(len(pids) <= (1 if kind == "init" else 2) for kind, pids in kinds.items()),
            "WSLC_DUPLICATE_OWNED_PROCESS")
        for pid, kind, argv in discovered:
            if argv == expected[kind][0]:
                parent = candidates.get(rows[pid][0])
                require(parent is not None and parent["kind"] == kind and parent["argv"] == expected[kind][1],
                    "WSLC_GUEST_LAUNCH_ANCESTRY_MISMATCH")
        self.guest_owners = candidates  # Publish only after ALL nonce/ancestry checks.
        return rows

    def persist_binding(self):
        self.evidence_index += 1
        directory = self.runtime / "sessions" / (self.tag + "-%04d" % self.evidence_index)
        host_path(directory, EVIDENCE, exists=False).mkdir()
        with (directory / "binding.json").open("xb") as stream:
            stream.write(encode_reply(self.bindings))

    def spawn(self, kind, argv, stdout_name, stderr_name):
        self.runtime_ok()
        require(kind in ("runtime", "relay") and kind not in self.children, "WSLC_CHILD_REOPEN_REFUSED")
        try:self.reserve_host_storage(LOG_CAP+STDERR_CAP)
        except Exception as error:raise Fault(getattr(error,'code','STORAGE_OBSERVATION_UNAVAILABLE')) from error
        out = host_path(self.runtime / stdout_name, EVIDENCE, exists=False)
        err = host_path(self.runtime / stderr_name, EVIDENCE, exists=False)
        child = RetainedChild(self.owned_driver()._Job())
        self.children[kind] = child  # BEFORE any native process is created.
        local_streams = []
        def owned(stream):
            local_streams.append(stream)
            return stream
        try:
            output, errors = owned(out.open("xb", buffering=0)), owned(err.open("xb", buffering=0))
            stdin = owned(open(os.devnull, "rb"))
            source_out, sink_out = pipe_streams(); local_streams.extend((source_out, sink_out))
            source_err, sink_err = pipe_streams(); local_streams.extend((source_err, sink_err))
            # Existing primitive: suspended create -> assign unnamed Job. There
            # is no resumed unowned gap and no native containment copy here.
            child.job.start(argv, (stdin, sink_out, sink_err))
            self.bindings[kind] = {"pid": child.pid, "start_ticks": int(native_birth(child.pid,
                dotnet=True, owned_handle=child.job.process))}
            self.persist_binding()  # Any write failure is still BEFORE resume.
            for source, sink, cap in ((source_out, output, LOG_CAP), (source_err, errors, STDERR_CAP)):
                thread = threading.Thread(target=self.drain_log, args=(source, sink, cap), daemon=True)
                thread.start()
                self.drainers.append(thread)
                local_streams.remove(source); local_streams.remove(sink)  # Drainer now owns them.
            child.job.resume()
            return child
        except BaseException:
            proof = child.retire("wslc-child-startup-failure")
            raise Fault("WSLC_CHILD_STARTUP_FAILED" if proof.get("confirmed") is True else
                "WSLC_CHILD_STARTUP_CLEANUP_UNCONFIRMED", True) from None
        finally:
            for stream in local_streams:
                stream.close()

    def owned_driver(self):
        if self.driver_module is None:
            self.frozen()
            path = host_path(HELPERS / "owned_driver.py", ROOT)
            name = "toolkit_remote_owned_driver_v1"
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            require(name not in sys.modules or Path(sys.modules[name].__file__).resolve() == path.resolve(),
                "WSLC_OWNED_DRIVER_ALIAS_REFUSED")
            sys.modules[name] = module  # dataclass resolves the defining module.
            spec.loader.exec_module(module)
            self.driver_module = module
            self.frozen()
        return self.driver_module

    def drain_log(self, source, sink, cap):
        total = 0
        try:
            while True:
                raw = source.read1(min(65536, cap + 1))
                if not raw:
                    break
                available = max(0, cap - total)
                if available:
                    chunk = raw[:available]
                    if sink.write(chunk) != len(chunk):
                        self.stream_failure.set()
                total += len(raw)
                if total > cap:
                    self.stream_failure.set()
                    # Continue draining/discarding bounded chunks. Never let a
                    # full pipe strand the owned child before finally cleanup.
                    total = cap + 1
        except (OSError, ValueError):
            self.stream_failure.set()
        finally:
            source.close(); sink.close()

    def gpu_policy(self):
        if self.profile_module is None:
            for name in ("manager", "gpu_policy"):
                path = HELPERS / (name + ".py")
                spec = importlib.util.spec_from_file_location(name, path)
                module = importlib.util.module_from_spec(spec)
                require(name not in sys.modules or Path(sys.modules[name].__file__).resolve() == path.resolve(), "WSLC_GPU_MODULE_ALIAS_REFUSED")
                sys.modules[name] = module
                spec.loader.exec_module(module)
                if name == "gpu_policy":
                    self.profile_module = module
            self.frozen()
        return self.profile_module

    def launch(self):
        require(os.name == "nt", "WSLC_WINDOWS_HOST_REQUIRED")
        context_path, creator_path = self.runtime / "context.json", self.runtime / "container-start.json"
        connection_path = self.runtime / "session-connection.json"
        self.context = strict_json(read_bounded(host_path(context_path, EVIDENCE), INPUT_CAP))
        self.creator = strict_json(read_bounded(host_path(creator_path, EVIDENCE), INPUT_CAP))
        connection = strict_json(read_bounded(host_path(connection_path, EVIDENCE), INPUT_CAP))
        require(type(connection.get("preexisting")) is bool and type(connection.get("trusted_connection")) is bool
            and connection.get("owns_vm") is False and (not connection["preexisting"] or connection["trusted_connection"]),
            "WSLC_DEFAULT_SESSION_AUTHORIZATION_REQUIRED")
        require(0 <= (utc(self.creator.get("started_utc")) - utc(connection.get("utc"))).total_seconds() <= 120,
            "WSLC_DEFAULT_SESSION_AUTHORIZATION_STALE")
        for path in (context_path, creator_path, connection_path):
            self.freeze[path] = hashlib.sha256(read_bounded(path, INPUT_CAP)).digest()
        # Fresh stock admission is read immediately before the FIRST WSLC call.
        self.admit()
        storage=self.storage_policy()
        if storage.soft_mode(storage.policy()):
            require(profile_memory_max(self.cfg)==FOCUS_MEMORY_MAX and self.context.get('fixture_sha256')==
                '9DFA4EEC8D4FEE6CAEE509D4FF2ACCB5136FED3A1D64D2302F0E35FF623AA4CB','WSLC_STORAGE_SOFT_PROFILE_REFUSED')
            self.storage_monitor_enabled=True
        else:
            capability=storage.probe()
            self.save('storage-capability.json',capability)
            require(capability.get('hard_limit_enforced') is True,'STORAGE_QUOTA_UNSUPPORTED')
        if profile_memory_max(self.cfg) == MODULE_MEMORY_MAX:
            self.bind_module_context()
        self.incarnation = exclusive_context(self.context, self.creator, self.inspect(),
            self.cfg["expected_identity"], self.cfg["owner"], memory_max=profile_memory_max(self.cfg))
        self.storage_guard()
        require(not list((self.runtime / "sessions").rglob("binding.json")), "WSLC_PREEXISTING_SESSION_BINDINGS")
        self.check_processes()  # Reject a prepared context already used by another job.
        app = self.cfg["expected_identity"]["executable"]
        require(self.text("sha256sum", app).split()[0].lower() == self.cfg["expected_identity"]["executable_sha256"].lower(), "WSLC_GUEST_ARTIFACT_MISMATCH")
        require(self.text("cat", "/sys/fs/cgroup/memory.max") == str(profile_memory_max(self.cfg))
            and self.text("cat", "/sys/fs/cgroup/cpu.max").split() == ["100000", "100000"], "WSLC_CGROUP_MISMATCH")
        host_path(self.runtime / "sessions", EVIDENCE).mkdir(exist_ok=True)
        # A per-runtime claim alone could be bypassed by copying creator receipts.
        # CreateNew under one fixed ignored root is a durable single-use CID
        # tombstone across all operator directories; never silently reclaim it.
        claims = EVIDENCE / "makepad-remote-container-claims"
        host_path(claims, EVIDENCE, exists=claims.exists()).mkdir(exist_ok=True)
        global_claim = host_path(claims / (self.cfg["expected_identity"]["container_id"] + ".json"), EVIDENCE, exists=False)
        write_claim(global_claim, {"session_id": self.cfg["session_id"], "owner": self.cfg["owner"],
            "incarnation": self.incarnation, "resumable": False})
        self.freeze[global_claim] = hashlib.sha256(read_bounded(global_claim, INPUT_CAP)).digest()
        claim = host_path(self.runtime / "sessions/remote-adoption-claim.json", EVIDENCE, exists=False)
        write_claim(claim, {"session_id": self.cfg["session_id"], "owner": self.cfg["owner"], "incarnation": self.incarnation})
        self.freeze[claim] = hashlib.sha256(read_bounded(claim, INPUT_CAP)).digest()
        self.adopted = True
        self.dispatched = True  # All later startup failures require owned cleanup.
        before = {w["hwnd"] for w in rail_windows()}
        require(not any(self.tag in w["title"] for w in rail_windows()), "WSLC_RAIL_TAG_ALREADY_PRESENT")
        relay_args = [PWSH, "-NoProfile", "-File", str(HELPERS / "stdio-relay.ps1"),
            "-ContainerId", self.cfg["expected_identity"]["container_id"], "-Seconds", str(profile_runtime_budget(self.cfg)[1]),
            "-DisplayNumber", "66", "-Label", "remote-relay", "-OutputDirectory", str(self.runtime),
            "-ProcessNonce", self.launch_nonces["relay"]]
        if profile_memory_max(self.cfg) == MODULE_MEMORY_MAX:
            relay_args.append("-ModuleShellBudget")
        relay = self.spawn("relay", relay_args,
            "remote-relay-wrapper.stdout.log", "remote-relay-wrapper.stderr.log")
        deadline = time.monotonic() + 25
        while True:
            self.runtime_ok()
            require(relay.poll() is None, "WSLC_RELAY_LOST_DURING_START")
            path = self.runtime / "remote-relay.ready.json"
            if path.exists():
                ready = strict_json(read_bounded(path, INPUT_CAP))
                require(ready.get("upstream_connected") is True and ready.get("container_endpoint") == "/tmp/.X11-unix/X66", "WSLC_RELAY_READY_MISMATCH")
                if self.guest("test", "-S", "/tmp/.X11-unix/X66", check=False)[0] == 0:
                    break
            require(time.monotonic() < deadline, "WSLC_RELAY_START_TIMEOUT")
            time.sleep(.05)
        self.check_processes(discover="relay")
        gpu = self.gpu_policy()
        profile = gpu.resolve_profile("gpu_nvidia_test")
        require(profile["config_sha256"] == self.context.get("gpu_config_sha256"), "WSLC_GPU_POLICY_CONTEXT_MISMATCH")
        self.admit()
        args = [WSLC, "exec", self.cfg["expected_identity"]["container_id"], *gpu.linux_env_arguments(profile),
            "AIUI_REMOTE_LAUNCH_NONCE=" + self.launch_nonces["app"], "LIBGL_ALWAYS_SOFTWARE=true",
            "MAKEPAD_GPU=gl", "WAYLAND_DISPLAY=", "DISPLAY=:66", "LD_LIBRARY_PATH=/usr/lib/wsl/lib",
            *self.expected_commands()["app"][1]]
        self.app_launch_started_ns = time.time_ns()
        application = self.spawn("runtime", args, "app.stdout.txt", "app.stderr.txt")
        deadline = time.monotonic() + 30
        while True:
            self.runtime_ok()
            require(application.poll() is None, "WSLC_APP_LOST_DURING_START")
            raw = read_log_prefix(self.runtime / "app.stdout.txt", LOG_CAP)
            # Runtime logs can grow; this is an observed prefix, never a cached focus bit.
            log = raw.decode("utf-8", errors="replace")
            match = re.search(r"\[makepad-remote\] listening on 127\.0\.0\.1:([0-9]+) pid=([0-9]+) app=\S+ grabs=(\S+)", log)
            if match:
                try:
                    renderer = gpu.observe(profile, log)
                except gpu.GpuPolicyFailure as exc:
                    require(exc.code == "GPU_OBSERVATION_MISSING", "WSLC_GPU_OBSERVATION_REFUSED")
                else:
                    self.port, self.pid, self.grabs = int(match[1]), int(match[2]), match[3]
                    require(uint(self.port, 65535, True) and uint(self.pid, (1 << 32)-1, True) and guest_path(self.grabs), "WSLC_STARTUP_IDENTITY_INVALID")
                    break
            require(time.monotonic() < deadline, "WSLC_STARTUP_OR_GPU_TIMEOUT")
            time.sleep(.025)
        self.check_processes(discover="app")
        self.app_launch_observed_ns = time.time_ns()
        require(self.pid in self.guest_owners and self.guest_owners[self.pid]["kind"] == "app", "WSLC_APP_PID_NOT_BOUND")
        deadline = time.monotonic() + 20
        while True:
            status, body = self.http("/s", False, startup=True)
            require(status == 200, "WSLC_STARTUP_STATUS_REFUSED")
            state = self.startup_state(body)
            require(state.get("pid") == self.pid and type(state.get("w")) is list and len(state["w"]) <= 1, "WSLC_STARTUP_WINDOW_MISMATCH")
            if len(state["w"]) == 1:
                window = state["w"][0]["i"]
                break
            require(time.monotonic() < deadline, "WSLC_WINDOW_PUBLICATION_TIMEOUT")
            time.sleep(.025)
        deadline = time.monotonic() + 10
        while True:
            self.runtime_ok()
            windows = [w for w in rail_windows() if self.tag in w["title"] and w["hwnd"] not in before]
            require(len(windows) <= 1, "WSLC_RAIL_MAPPING_AMBIGUOUS")
            if windows:
                require(not windows[0].get("observation_error"), "WSLC_RAIL_OBSERVATION_UNCONFIRMED")
                self.rail = windows[0]; break
            require(time.monotonic() < deadline, "WSLC_RAIL_MAPPING_TIMEOUT")
            time.sleep(.025)
        api = ctypes.WinDLL("user32", use_last_error=True)
        api.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        api.ShowWindow(wintypes.HWND(self.rail["hwnd"]), 0)  # Existing SW_HIDE, never focus/activate.
        self.identity = self.observe_identity(window)
        self.save_running_witness()
        self.bindings["identity"] = {"hwnd": self.rail["hwnd"], "pid": self.pid, "session_id": self.cfg["session_id"]}
        self.persist_binding()
        self.save("runtime-identity.json", {"identity": self.identity, "gpu": renderer, "incarnation": self.incarnation})
        self.module_resources("startup")
        return {"identity": self.identity, "grab_root": self.grabs, "gpu": renderer}

    def listener(self):
        require(self.port is not None, "WSLC_LISTENER_NOT_BOUND")
        target = "0100007F:%04X" % self.port
        rows = [line.split() for line in self.text("cat", "/proc/net/tcp").splitlines()[1:]]
        matches = [row[9] for row in rows if len(row) >= 10 and row[1] == target and row[3] == "0A"]
        require(len(matches) <= 1 and all(decimal(v) for v in matches), "WSLC_LISTENER_AMBIGUOUS")
        return matches

    def guest_identity(self, *, with_cgroups=False):
        require(type(with_cgroups) is bool and (not with_cgroups or self.running_witness_saved), "WSLC_RUNTIME_WITNESS_REQUIRED")
        owned = self.guest_owners.get(self.pid)
        require(owned is not None and owned["kind"] == "app", "WSLC_STALE_PROCESS")
        parent = self.guest_owners.get(owned["parent"])
        require(parent is not None and parent["kind"] == "app"
            and parent["argv"] == self.expected_commands()["app"][1]
            and owned["argv"] == self.expected_commands()["app"][0], "WSLC_GUEST_LAUNCH_ANCESTRY_MISMATCH")
        before = time.time_ns()
        if with_cgroups:
            code, raw, err = self.guest("bash", "-c", IDENTITY_CGROUP_PROGRAM, "toolkit-identity-cgroups", KERNEL_FD_PROGRAM,
                str(self.pid), self.cfg["expected_identity"]["executable"], str(self.port), cap=INPUT_CAP)
        else:
            code, raw, err = self.guest("bash", "-c", KERNEL_FD_PROGRAM, "toolkit-kernel-fds",
                str(self.pid), self.cfg["expected_identity"]["executable"], str(self.port), cap=INPUT_CAP)
        after = time.time_ns()
        require(code == 0 and err == b"", "WSLC_KERNEL_REPORT_FAILED")
        if with_cgroups:
            raw, cgroups = identity_cgroup_observation(raw)
        try:
            value = kernel_fd_report(raw, self.cfg["expected_identity"], self.pid, owned, parent,
                self.launch_nonces["app"], self.port, before, after,
                max_executable_bytes=(512 if profile_memory_max(self.cfg) == MODULE_MEMORY_MAX else 128)*1024*1024)
        except Fault as exc:
            if profile_memory_max(self.cfg) == MODULE_MEMORY_MAX:
                self.save("module-kernel-fd-refused.json", {"schema":"toolkit-module-shell-kernel-fd-refusal-v1",
                    "owner":self.cfg["owner"],"session_id":self.cfg["session_id"],"generation":self.cfg["generation"],
                    "container_id":self.context["container_id"],"guest_pid":self.pid,"error_code":exc.code,
                    "raw_base64":base64.b64encode(raw).decode("ascii"),"bytes":len(raw),
                    "sha256":hashlib.sha256(raw).hexdigest().upper(),"started_unix_ns":str(before),"completed_unix_ns":str(after)})
            raise
        identity = (owned["birth"], value["before"]["pid_namespace"], value["executable_fd_sha256"], value["listener"]["inode"])
        if with_cgroups:
            # Do not relabel a wrapper RPC as the Core launch collector. The
            # already-saved launch witness stays immutable; this result comes
            # solely from the just-observed/validated kernel and cgroup bytes.
            return identity, cgroups
        collector = {"executable": WSLC, "args": ["exec", self.cfg["expected_identity"]["container_id"],
            "bash", "-c", KERNEL_FD_PROGRAM, "toolkit-kernel-fds", str(self.pid),
            self.cfg["expected_identity"]["executable"], str(self.port)], "exit_code": code,
            "stderr": err.decode("utf-8"), "stdout_sha256": hashlib.sha256(raw).hexdigest().upper(),
            "started_unix_ns": str(before), "completed_unix_ns": str(after)}
        self.kernel_latest = (raw, before, after, collector)
        return identity

    def save_running_witness(self):
        # One launch witness, not a new file for every /snap. Ongoing identity
        # checks still perform the complete single-RPC stable-FD observation.
        require(not self.running_witness_saved and self.kernel_latest is not None, "WSLC_KERNEL_WITNESS_ALREADY_SAVED")
        raw, began, ended, collector = self.kernel_latest
        require(0 <= time.time_ns() - ended <= 12_000_000_000, "WSLC_KERNEL_WITNESS_STALE")
        require(type(self.app_launch_started_ns) is int and type(self.app_launch_observed_ns) is int
            and 0 < self.app_launch_started_ns <= self.app_launch_observed_ns <= began, "WSLC_LAUNCH_INTERVAL_INVALID")
        self.frozen()
        def ref(path):
            path = host_path(path, ROOT)
            return {"path": path.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(read_bounded(path, INPUT_CAP)).hexdigest().upper()}
        context_ref, creator_ref = ref(self.runtime / "context.json"), ref(self.runtime / "container-start.json")
        transfer_ref = ref(self.runtime / "fixture-upload.json")
        transfer = strict_json(read_bounded(self.runtime / "fixture-upload.json", INPUT_CAP))
        container = {"container_id": self.cfg["expected_identity"]["container_id"],
            "image_id": self.cfg["expected_identity"]["image_id"], "created": self.incarnation["created"],
            "started_at": self.incarnation["started_at"], "owner": self.cfg["owner"], "nonce": self.incarnation["nonce"]}
        provenance = transfer.get("provenance", {})
        require(provenance.get("schema") == "toolkit-wslc-artifact-transfer-provenance-v1"
            and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", provenance.get("operation_id", ""))
            and provenance.get("container") == container and provenance.get("context") == context_ref
            and provenance.get("creator_receipt") == creator_ref and type(transfer.get("exit_code")) is int
            and transfer["exit_code"] == 0 and transfer.get("container_id") == container["container_id"]
            and transfer.get("sha256", "").lower() == self.cfg["expected_identity"]["executable_sha256"].lower()
            and transfer.get("target") == self.cfg["expected_identity"]["executable"], "WSLC_TRANSFER_PROVENANCE_REQUIRED")
        owned = self.guest_owners[self.pid]; parent = self.guest_owners[owned["parent"]]
        iso = lambda ns: dt.datetime.fromtimestamp(ns / 1_000_000_000, dt.timezone.utc).isoformat()
        helper = host_path(Path(__file__), ROOT)
        self.save("running-executable-0001.json", {
            "schema": "toolkit-wslc-running-executable-witness-v1", "session_id": self.cfg["session_id"],
            "owner": self.cfg["owner"], "generation": self.cfg["generation"], "source_commit": PIN,
            "helper": {"path": helper.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(read_bounded(helper, 4*1024*1024)).hexdigest().upper()},
            "owner_config": ref(self.output / "owner-config.json"), "context": context_ref,
            "creator_receipt": creator_ref, "transfer_receipt": transfer_ref,
            "started_utc": iso(began), "completed_utc": iso(ended), "container": container,
            "launch_binding": {"app_pid": self.pid, "app_birth": owned["birth"], "parent_pid": owned["parent"],
                "parent_birth": parent["birth"], "launch_nonce": self.launch_nonces["app"],
                "parent_argv": self.expected_commands()["app"][1],
                "started_unix_ns": str(self.app_launch_started_ns), "observed_unix_ns": str(self.app_launch_observed_ns)},
            "collector_invocation": collector,
            "raw_kernel_report_utf8": raw.decode("utf-8"), "raw_kernel_report_sha256": hashlib.sha256(raw).hexdigest().upper()})
        self.running_witness_saved = True

    def observe_identity(self, window):
        if self.running_witness_saved:
            (birth, namespace, digest, inode), (memory_max, cpu_max) = self.guest_identity(with_cgroups=True)
        else:
            birth, namespace, digest, inode = self.guest_identity()
            memory_max, cpu_max = cgroup_observation(self.guest("cat", "/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/cpu.max")[1])
        windows = [w for w in rail_windows() if self.rail and w["hwnd"] == self.rail["hwnd"]]
        require(len(windows) == 1 and windows[0]["pid"] == self.rail["pid"]
            and windows[0]["birth"] == self.rail["birth"] and self.tag in windows[0]["title"], "WSLC_RAIL_IDENTITY_CHANGED")
        observed = {"schema": "toolkit-makepad-remote-wslc-identity-v1", **self.cfg["expected_identity"],
            "pid_namespace": namespace, "pid": self.pid, "process_start_ticks": birth, "executable_sha256": digest,
            "listener_host": "127.0.0.1", "listener_port": self.port, "listener_inode": inode, "window_id": window,
            "rail_hwnd": self.rail["hwnd"], "rail_pid": self.rail["pid"], "rail_process_birth": self.rail["birth"],
            "rail_visible": windows[0]["visible"], "memory_max": memory_max, "cpu_max": cpu_max}
        return observed_identity(observed, self.cfg["expected_identity"], memory_max=profile_memory_max(self.cfg))

    def validate(self):
        self.runtime_ok()
        require(self.identity is not None, "WSLC_IDENTITY_NOT_ESTABLISHED")
        self.inspect_owned()
        value = self.observe_identity(self.identity["window_id"])
        require(value == self.identity, "WSLC_IDENTITY_DRIFT")
        return value

    def host_content_geometry(self, actual):
        """One bounded read-only upstream query under this owner's deadline."""
        self.geometry_index += 1
        began = time.monotonic_ns()
        windows = [w for w in rail_windows() if w["hwnd"] == self.rail["hwnd"]]
        identity_valid = (len(windows) == 1 and same_rail_identity(self.rail, windows[0], self.tag)
            and type(actual.get("rail_visible")) is bool and windows[0]["visible"] == actual["rail_visible"])
        if not identity_valid:
            self.save(f"host-content-geometry-identity-{self.geometry_index:04}.json", {
                "session_id":self.cfg["session_id"],"generation":self.cfg["generation"],
                "launch_rail":self.rail,"current_candidates":windows,"validated_identity":actual,
                "input_dispatched":False})
        require(identity_valid, "WSLC_RAIL_GEOMETRY_IDENTITY_CHANGED")
        rail_title = windows[0]["title"]
        title = focus_content_title(self.cfg, self.tag)
        require(supported_rail_title(title, rail_title), "WSLC_RAIL_GEOMETRY_TITLE_INVALID")
        native = rail_geometry(windows[0])
        remaining = self.budget(6.0)
        # Never round a near-zero timeout to GNU timeout's special "disabled"
        # value; leave room for its finite kill-after inside the same budget.
        require(remaining >= 2.0, "WSLC_OWNER_LIFETIME_EXPIRED")
        ttl = min(4.0, remaining / 2)
        argv = [r"C:\Windows\System32\wsl.exe", "-d", "Ubuntu", "--", "timeout", "--signal=TERM",
            "--kill-after=1s", f"{ttl:.3f}s", "/usr/bin/python3", "-c", X11_GEOMETRY_PROGRAM, str(self.pid), title]
        code, raw, stderr = run_bounded(argv, timeout=self.budget(ttl+1), out_cap=INPUT_CAP, err_cap=8192)
        # Save original command output before any interpretation or refusal.
        self.save(f"x11-geometry-raw-{self.geometry_index:04}.json", {
            "schema":"toolkit-wslc-x11-original-observation-v1", "session_id":self.cfg["session_id"],
            "generation":self.cfg["generation"], "sequence":self.geometry_index,
            "expected_guest_pid":self.pid,"title":title,"rail_title":rail_title,"started_monotonic_ns":began,
            "observed_monotonic_ns":time.monotonic_ns(),"exit_code":code,
            "stdout_utf8":raw.decode("utf-8", "replace"),"stdout_sha256":hashlib.sha256(raw).hexdigest().upper(),
            "stderr_utf8":stderr.decode("utf-8", "replace"),"identity_before":actual,"native_before":native,
            "program_sha256":hashlib.sha256(X11_GEOMETRY_PROGRAM.encode()).hexdigest().upper(),
            "upstream":"Ubuntu:/tmp/.X11-unix/X0","input_dispatched":False})
        after = self.validate()
        require(after == actual, "WSLC_GEOMETRY_IDENTITY_DRIFT")
        windows = [w for w in rail_windows() if w["hwnd"] == self.rail["hwnd"]]
        require(len(windows) == 1 and same_rail_identity(self.rail, windows[0], self.tag)
            and windows[0]["visible"] == after["rail_visible"] and rail_geometry(windows[0]) == native,
            "WSLC_RAIL_GEOMETRY_CHANGED")
        require(code == 0, "WSLC_X11_GEOMETRY_UNVERIFIED")
        x11 = strict_json(raw, INPUT_CAP)
        require(type(x11) is dict and x11.get("schema") == "toolkit-wslc-x11-content-geometry-v1"
            and x11.get("expected_guest_pid") == self.pid and x11.get("title") == title and x11.get("display") == ":0"
            and "pid_property" in x11 and "pid" not in x11
            and ((x11.get("pid_property") is None and x11.get("identity_source") == "APPROVED_LAUNCH_NONCE_AND_UNIQUE_TITLE")
                or (type(x11.get("pid_property")) is int and x11["pid_property"] == self.pid
                    and x11.get("identity_source") == "NET_WM_PID_AND_UNIQUE_TITLE")),
            "WSLC_X11_GEOMETRY_IDENTITY_INVALID")
        completed = time.monotonic_ns()
        require(completed >= began and completed-began <= 10_000_000_000, "WSLC_GEOMETRY_OBSERVATION_EXPIRED")
        witness = {"schema":"toolkit-wslc-host-content-geometry-v1","session_id":self.cfg["session_id"],
            "generation":self.cfg["generation"],"sequence":self.geometry_index,"tag":self.tag,"title":title,"rail_title":rail_title,
            "container_id":actual["container_id"],"guest_pid":self.pid,"guest_process_start_ticks":actual["process_start_ticks"],
            "rail_hwnd":actual["rail_hwnd"],"rail_pid":actual["rail_pid"],"rail_process_birth":actual["rail_process_birth"],
            "started_monotonic_ns":began,"observed_monotonic_ns":completed,
            "observed_unix_ms":time.time_ns()//1_000_000,**native,"x11":x11,
            "raw_x11_utf8":raw.decode("utf-8"),"raw_x11_sha256":hashlib.sha256(raw).hexdigest().upper()}
        self.save(f"host-content-geometry-{self.geometry_index:04}.json", witness)
        return {"identity":after,"geometry":witness}

    def _request(self, target, mutating):
        # Only call("request") enters here, after any before-quit witness.
        # Bind the reply to this request's last full observation, not a cached
        # identity or an earlier duplicate validation at the RPC boundary.
        route, _ = request_target(target, mutating)
        actual = self.validate()
        status, body = self._http_after_validation(target, mutating, route)
        return {"identity": actual, "status": status, "body_utf8": body}

    def http(self, target, mutating, *, startup=False):
        route, _ = request_target(target, mutating)
        if startup:
            self.inspect_owned()
            self.guest_identity()
        else:
            self.validate()
        return self._http_after_validation(target, mutating, route)

    def _http_after_validation(self, target, mutating, route):
        # Private wire path: both callers perform their full applicable fresh
        # validation immediately above. No protocol operation can skip it.
        before = int(self.text("date", "+%s%N")) // 1000000 if route == "/g" else None
        wire = (f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nConnection: close\r\n\r\n").encode("ascii")
        if mutating:
            self.dispatched = True  # Latch before any possible write/connection loss.
        try:
            code, raw, _ = self.guest("timeout", "--signal=TERM", "--kill-after=2s", "20s", "bash", "-c",
                HTTP_PROGRAM, "toolkit-remote-http", str(self.port), data=wire, timeout=25,
                cap=HEADER_CAP+HTTP_CAP, check=False)
            require(code == 0, "WSLC_HTTP_COMMAND_FAILED")
            status, body = parse_http(raw)
        except Fault as exc:
            raise Fault(exc.code, mutating) from None
        if route == "/g" and status == 200:
            metadata = strict_json(body.encode("utf-8"), HTTP_CAP)
            self.last_grab = (before, metadata)
        return status, body

    def copy_frame(self, metadata, dispatched_ms):
        require(type(metadata) is dict and uint(dispatched_ms) and self.last_grab is not None
            and metadata == self.last_grab[1], "WSLC_CAPTURE_REQUEST_NOT_BOUND")
        count=getattr(self,'storage_capture_count',0)
        require(count<4,'WSLC_STORAGE_CAPTURE_COUNT_REFUSED')
        self.reserve_host_storage(2*PNG_CAP+65536) # rejected PNG hex + metadata
        self.storage_capture_count=count+1
        path = metadata.get("png")
        require(guest_path(path) and path.startswith(self.grabs + "/") and path.endswith(".png")
            and metadata.get("w") == self.identity["window_id"] and path not in self.seen_grabs, "WSLC_CAPTURE_PATH_REFUSED")
        require(self.text("readlink", "-f", path) == path, "WSLC_CAPTURE_SYMLINK_REFUSED")
        before = self.text("stat", "-c", "%s|%y|%i|%F|%h", path)
        parts = before.split("|")
        require(len(parts) == 5 and parts[0].isdigit() and 0 < int(parts[0]) <= PNG_CAP and decimal(parts[2])
            and parts[3:] == ["regular file", "1"], "WSLC_CAPTURE_STAT_INVALID")
        modified = int(self.text("date", "-d", parts[1], "+%s%N")) // 1000000
        raw = self.guest("cat", path, cap=PNG_CAP)[1]
        after = self.text("stat", "-c", "%s|%y|%i|%F|%h", path)
        require(before == after and len(raw) == int(parts[0]), "WSLC_CAPTURE_CHANGED_DURING_READ")
        identity = self.validate()
        host_wall_before = time.time_ns() // 1000000
        date_started = time.monotonic_ns()
        clock = int(self.text("date", "+%s%N")) // 1000000
        date_elapsed = time.monotonic_ns() - date_started
        host_guard = time.time_ns() // 1000000  # Also the final date RPC's host wall-after sample.
        try:
            require(self.last_grab[0] <= modified <= clock and abs(host_guard-clock) <= 2000,
                "WSLC_CAPTURE_TIME_UNCONFIRMED")
        except Fault:
            # Only this unchanged time refusal can retain rejected bytes. All
            # identity/path/stat/read checks above must already have succeeded.
            try:
                context = {"identity": identity,
                    "binding": {key: self.cfg[key] for key in
                        ("session_id", "owner", "generation", "source_commit", "expected_identity")},
                    "metadata": metadata, "dispatched_ms": dispatched_ms, "guest_path": path,
                    "stat_before": before, "stat_after": after,
                    "guest_clock_before_ms": self.last_grab[0], "modified_ms": modified,
                    "guest_clock_after_ms": clock, "host_guard_ms": host_guard,
                    "host_wall_before_ms": host_wall_before, "host_wall_after_ms": host_guard,
                    "final_date_monotonic_elapsed_ns": date_elapsed,
                    "guest_before_le_mtime": self.last_grab[0] <= modified,
                    "mtime_le_guest_after": modified <= clock,
                    "host_guest_within_2000ms": abs(host_guard-clock) <= 2000,
                    "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                    "original_error": "WSLC_CAPTURE_TIME_UNCONFIRMED"}
                require(len(raw) <= PNG_CAP and len(encode_reply(context)) <= 65536,
                    "WSLC_REJECTED_CAPTURE_EVIDENCE_BOUND")
                self.evidence_index += 1
                self.save("rejected-capture-time-%04d.json" % self.evidence_index,
                    {"schema": "toolkit-makepad-remote-wslc-rejected-capture-time-v1",
                        "accepted": False, "context": context, "bytes_hex": raw.hex()})
            except Exception:
                pass  # Evidence errors/collisions must never replace the original refusal.
            raise
        self.seen_grabs.add(path)
        return {"identity": identity, "bytes_hex": raw.hex(), "guest_path": path, "modified_ms": modified,
            "stat_before": before, "stat_after": after, "guest_clock_before_ms": self.last_grab[0], "guest_clock_after_ms": clock}

    def rail_absent(self, observation=None):
        if observation is not None:
            observation["expected"] = ({key: self.rail[key] for key in ("hwnd", "pid", "birth")}
                if self.rail is not None else None)
        candidates = [w for w in rail_windows() if (self.rail and w["hwnd"] == self.rail["hwnd"])
            or self.tag in w["title"]]
        if observation is not None:
            # Only owned candidates, never unrelated desktop titles. Truncation
            # affects diagnostics only; the original predicate checks every row.
            observation["candidate_count"] = len(candidates)
            observation["candidates_truncated"] = len(candidates) > 64
            observation["candidates"] = [{**{key: w.get(key) for key in
                ("hwnd", "pid", "birth", "visible", "observation_error")},
                "title_matches_tag": self.tag in w["title"]} for w in candidates[:64]]
        require(not any(w.get("observation_error") for w in candidates), "WSLC_RAIL_ABSENCE_UNCONFIRMED")
        absent = not any((self.rail and w["hwnd"] == self.rail["hwnd"] and w["pid"] == self.rail["pid"]
            and w["birth"] == self.rail["birth"]) or self.tag in w["title"] for w in candidates)
        if observation is not None:
            observation["absent"] = absent
        return absent

    def reap(self):
        started = time.monotonic()
        owner_deadline = self.deadline
        join_deadline = started + 8
        # Every nested WSLC command uses budget(); never reset the eight-second
        # join after root exit or extend the original owner lifetime.
        self.deadline = min(owner_deadline, join_deadline)
        try:
            return self._reap_join(started, join_deadline)
        finally:
            self.deadline = owner_deadline

    def _reap_join(self, started, join_deadline):
        repeated = self.normal_exit_result is not None
        observation = {"schema": "toolkit-makepad-remote-wslc-reap-observation-v1",
            "session_id": self.cfg["session_id"], "owner": self.cfg["owner"],
            "generation": self.cfg["generation"], "container_id": self.cfg["expected_identity"]["container_id"],
            "repeated": repeated, "started_unix_ms": time.time_ns() // 1000000,
            "join_budget_ms": 8000, "effective_budget_ms": max(0, int((self.deadline - started) * 1000)),
            "probes": {}, "samples": []}
        primary = first_failure = None
        probe_error = False
        root_observed = repeated

        def probe(name, operation, value, false_code="WSLC_NORMAL_EXIT_RESOURCES_REMAIN"):
            nonlocal primary, probe_error
            began = time.monotonic()
            row = {"started_unix_ms": time.time_ns() // 1000000, "result": value}
            try:
                passed = operation(value)
                row.update(ok=True, satisfied=passed)
                if not passed and primary is None:
                    primary = Fault(false_code)
            except Exception as exc:
                # Keep the original exception object/priority, never its text.
                probe_error = True
                row.update(ok=False, satisfied=None,
                    error_code=exc.code if isinstance(exc, Fault) else "WSLC_REAP_PROBE_FAILED")
                if primary is None:
                    primary = exc
            row.update(finished_unix_ms=time.time_ns() // 1000000,
                elapsed_ms=max(0, int((time.monotonic() - began) * 1000)))
            observation["probes"][name] = row

        def root(value):
            nonlocal root_observed
            require("runtime" in self.children, "WSLC_APP_NOT_STARTED")
            child = self.children["runtime"]
            value["host_pid"] = getattr(child, "pid", None)
            if not root_observed:
                while True:
                    value["returncode"] = child.poll()
                    if value["returncode"] is not None:
                        break
                    require(time.monotonic() < join_deadline, "WSLC_NORMAL_EXIT_UNCONFIRMED")
                    self.runtime_ok()
                    remaining = self.deadline - time.monotonic()
                    if remaining > 0:
                        time.sleep(min(.025, remaining))
                root_observed = True
            else:
                # The prior native exit0 is cached, not a fresh exit or new wait.
                value["returncode"] = child.returncode
            return value["returncode"] == 0

        def job(value):
            value["active_processes"] = self.children["runtime"].active_processes()
            value["empty"] = value["active_processes"] == 0
            return value["empty"]

        def guest(value):
            actual = self.proc(self.pid)
            value["absent"] = actual is None
            value["observed"] = ({key: actual.get(key) for key in ("birth", "state")}
                if actual is not None else None)
            return value["absent"]

        def listener(value):
            value["observed_inodes"] = self.listener()
            value["absent"] = not value["observed_inodes"]
            return value["absent"]

        def rail(value):
            value["absent"] = self.rail_absent(observation=value)
            return value["absent"]

        expected = self.identity or {}
        while True:
            primary, probe_error = None, False
            observation["probes"] = {}
            sample_started = time.monotonic()
            sample = {"index": len(observation["samples"]) + 1,
                "started_unix_ms": time.time_ns() // 1000000, "probes": observation["probes"]}
            probe("root", root, {"returncode": None, "cached_exit": root_observed}, "WSLC_APP_EXIT_NONZERO")
            probe("job", job, {})
            probe("guest", guest, {"pid": self.pid, "expected_birth": expected.get("process_start_ticks")})
            probe("listener", listener, {"port": self.port, "expected_inode": expected.get("listener_inode")})
            probe("rail", rail, {})
            now = time.monotonic()
            within_budget = now < self.deadline
            if primary is None and not within_budget:
                primary = Fault("WSLC_NORMAL_EXIT_RESOURCES_REMAIN")
            if first_failure is None:
                first_failure = primary
            sample.update(finished_unix_ms=time.time_ns() // 1000000,
                elapsed_ms=max(0, int((now - sample_started) * 1000)),
                within_budget=within_budget, probe_error=probe_error,
                primary_error_code=(primary.code if isinstance(primary, Fault) else "WSLC_REAP_PROBE_FAILED")
                    if primary is not None else None,
                all_conditions_proven=primary is None)
            observation["samples"].append(sample)
            if primary is None:
                break
            # Only known false predicates may be observed again. Any probe error
            # ends this join; retain an earlier refusal rather than masking it.
            if probe_error or observation["probes"]["root"]["satisfied"] is not True or not within_budget:
                primary = first_failure
                break
            time.sleep(min(.025, self.deadline - now))
        observation.update(finished_unix_ms=time.time_ns() // 1000000,
            elapsed_ms=max(0, int((time.monotonic() - started) * 1000)),
            first_failure_code=(first_failure.code if isinstance(first_failure, Fault) else "WSLC_REAP_PROBE_FAILED")
                if first_failure is not None else None,
            primary_error_code=(primary.code if isinstance(primary, Fault) else "WSLC_REAP_PROBE_FAILED")
                if primary is not None else None,
            all_conditions_proven=primary is None)
        self.reap_observations += 1
        try:
            self.save("reap-observation-%04d.json" % self.reap_observations, observation)
        except Exception:
            if primary is None:
                raise  # Evidence failure refuses an otherwise-positive result.
        if primary is not None:
            raise primary
        if repeated:
            return self.normal_exit_result
        value = {"exit_code": 0, "normal_exit_observed": True, "guest_process_gone": True,
            "listener_absent": True, "rail_absent": True}
        self.save("native-app-exit.json", value)
        self.normal_exit_result = value
        return value

    def container_present(self):
        _, out, err = self.wslc("ps", "-a", "--format", "json", "--no-trunc",
            "--filter", "id=" + self.cfg["expected_identity"]["container_id"])
        require(err == b"", "WSLC_ABSENCE_INVENTORY_INVALID")
        return filtered_container_present(out)

    def cleanup(self):
        require(self.adopted, "WSLC_NO_ADOPTED_CONTAINER")
        if self.cleaned:
            return self.cleanup_result
        if not self.cleaning:
            self.cleaning = True
            self.deadline = time.monotonic() + 100  # Finite cleanup reserve, once only.
        self.cleanup_attempts += 1
        record = {"binding_persistence_error": None, "receipt": None}
        container_error = None
        host_proofs = {}
        try:
            self.frozen()
            if self.container_present():
                actual = self.inspect_owned(allow_stopped=True)
                if actual["State"]["Running"]:
                    self.check_processes(cleanup=True)  # Never stop a container with foreign work.
            try:
                self.persist_binding()
            except Exception:
                record["binding_persistence_error"] = "WSLC_BINDING_PERSISTENCE_FAILED"
            # Existing helper retires only this exact container. Our retained
            # native Jobs (not PID-sidecar reconstruction) retire host trees.
            no_pid_bindings = base64.b64encode(encode_reply({})).decode("ascii")
            code, out, err = run_bounded([PWSH, "-NoProfile", "-File", str(HELPERS / "cleanup-runtime.ps1"),
                "-OutputDirectory", str(self.runtime), "-OwnedBindingsBase64", no_pid_bindings],
                timeout=self.budget(75), out_cap=1024*1024, err_cap=1024*1024)
            record.update(exit_code=code, stdout_sha256=hashlib.sha256(out).hexdigest(),
                stderr_sha256=hashlib.sha256(err).hexdigest())
            path = self.runtime / "cleanup.json"
            receipt = strict_json(read_bounded(path, 1024*1024), 1024*1024) if path.exists() else None
            record["receipt"] = receipt
            require(code == 0 and receipt is not None and receipt.get("status") == "OWNED_RESOURCES_CLEANED"
                and receipt.get("container_id") == self.cfg["expected_identity"]["container_id"]
                and receipt.get("owned_container_absent") is True and receipt.get("connected_vm_preserved") is True
                and receipt.get("owns_vm") is False, "WSLC_OWNED_CLEANUP_UNCONFIRMED")
            require(not self.container_present(), "WSLC_CONTAINER_STILL_PRESENT")
        except Fault as exc:
            container_error = exc
        except Exception:
            container_error = Fault("WSLC_CONTAINER_RETIREMENT_INTERNAL_ERROR")
        finally:
            # This cannot depend on fresh evidence writes, a mutable helper,
            # container connectivity, binding availability or HWND inspection.
            for kind, child in self.children.items():
                try:
                    host_proofs[kind] = child.retire("wslc-owner-cleanup")
                except Exception:
                    host_proofs[kind] = {"confirmed": False, "error_code": "WSLC_NATIVE_JOB_RETIREMENT_UNCONFIRMED"}
        record["host_job_cleanup"] = host_proofs
        record["container_error"] = container_error.code if container_error else None
        self.save("cleanup-attempt-%04d.json" % self.cleanup_attempts, record)
        if container_error is not None:
            raise container_error
        cid = self.cfg["expected_identity"]["container_id"]
        require(all(proof.get("confirmed") is True and proof.get("active_after") == 0 for proof in host_proofs.values())
            and self.rail_absent(), "WSLC_OWNED_HOST_RESOURCES_REMAIN")
        for worker in self.drainers:
            worker.join(timeout=self.budget(1))
        require(not any(worker.is_alive() for worker in self.drainers), "WSLC_LOG_DRAIN_UNCONFIRMED")
        result = {"container_stopped": True, "owned_helpers_gone": True, "rail_absent": True,
            "guest_process_gone": True, "listener_absent": True, "connected_vm_preserved": True,
            "container_id": cid, "cleanup_receipt": record["receipt"], "host_job_cleanup": host_proofs}
        # No staging deletion is authorized by mere PID absence. The existing
        # owner has just verified incarnation, guest absence and native Jobs;
        # independently query its exact session's leases before filesystem work.
        try:
            storage=self.storage_policy()
            staged=storage.cleanup_staging(self.runtime,identity_verified=True,
                terminal=True,active_leases=storage.active_session_leases(self.cfg['session_id']),container_absent=True)
        except Exception as error:
            staged={'status':'STAGING_CLEANUP_DEFERRED','code':getattr(error,'code','STORAGE_OBSERVATION_UNAVAILABLE'),
                    'deleted_bytes':0,'automatic_retry_allowed':False}
        staged['owner_identity_join']={'session_id':self.cfg['session_id'],'generation':self.cfg['generation'],
            'container_id':cid,'owner':self.cfg['owner'],'incarnation':self.incarnation,
            'source':'EXISTING_OWNER_EXCLUSIVE_CONTEXT_AND_NATIVE_RETIREMENT'}
        self.save('storage-cleanup.json',staged)
        result['storage_cleanup']=staged
        self.save("platform-cleanup.json", {"schema": "toolkit-makepad-remote-wslc-cleanup-v1",
            "session_id": self.cfg["session_id"], "owner": self.cfg["owner"], "container_id": cid, "result": result})
        self.cleaned, self.cleanup_result = True, result
        return result

    def storage_policy(self):
        name='toolkit_owned_wslc_storage_policy'
        path=host_path(HELPERS/'storage_policy.py',ROOT)
        spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.frozen()
        return module

    def finalize(self):
        status, code = "NOT_ADOPTED_NO_CONTAINER_MUTATION", None
        if self.adopted:
            try:
                self.cleanup()
                status = "OWNED_CLEANUP_CONFIRMED"
            except Fault as exc:
                status, code = "OWNED_CLEANUP_UNCONFIRMED", exc.code
            except Exception:
                status, code = "OWNED_CLEANUP_UNCONFIRMED", "WSLC_CLEANUP_INTERNAL_ERROR"
        self.evidence_index += 1
        self.save("owner-finally-%04d.json" % self.evidence_index, {
            "schema": "toolkit-makepad-remote-wslc-finally-v1", "status": status,
            "session_id": self.cfg["session_id"], "container_adopted": self.adopted,
            "error_code": code, "normal_exit_claimed": False})


def serve(owner, source, write, *, idle=IO_TTL, lifetime=LIFETIME):
    """Bounded queue and independent partial-line TTL; no cleanup on stdout."""
    incoming = queue.Queue(maxsize=1)
    def reader():
        pending = bytearray()
        try:
            while True:
                block = source.read(min(4096, INPUT_CAP + 1 - len(pending)))
                if not block:
                    incoming.put(Fault("WSLC_PIPE_PARTIAL_PACKET") if pending else None)
                    return
                for byte in block:
                    pending.append(byte)
                    if len(pending) > INPUT_CAP:
                        incoming.put(Fault("WSLC_INPUT_PACKET_BOUND")); return
                    if byte == 10:
                        incoming.put(bytes(pending)); pending.clear()
        except Exception:
            incoming.put(Fault("WSLC_PIPE_READ_FAILED"))
    threading.Thread(target=reader, daemon=True).start()
    deadline = time.monotonic() + lifetime
    previous = 0
    try:
        while True:
            remaining = min(idle, deadline - time.monotonic())
            require(remaining > 0, "WSLC_OWNER_LIFETIME_EXPIRED")
            try:
                raw = incoming.get(timeout=remaining)
            except queue.Empty:
                raise Fault("WSLC_PIPE_IDLE_OR_PARTIAL_TIMEOUT") from None
            if raw is None:
                break
            if isinstance(raw, Fault):
                raise raw
            sequence = 0
            terminal = False
            try:
                value = packet(raw, previous)
                sequence = previous = value["sequence"]
                result = owner.call(value["operation"], value["arguments"])
                reply = {"version": 1, "sequence": sequence, "ok": True, "result": result}
            except Fault as exc:
                terminal = sequence == 0
                reply = {"version": 1, "sequence": sequence, "ok": False,
                    "error": {"code": exc.code, "dispatched": bool(exc.dispatched or owner.dispatched)}}
            except Exception:
                terminal = True
                reply = {"version": 1, "sequence": sequence, "ok": False,
                    "error": {"code": "WSLC_INTERNAL_ERROR", "dispatched": bool(owner.dispatched)}}
            write_deadline(encode_reply(reply), write, min(IO_TTL, max(.001, deadline - time.monotonic())))
            if terminal:
                break
    finally:
        owner.finalize()


def main():
    # -I -B -u is supplied by the Rust fixed executable owner. No locale-based
    # text stdout is used. Importing this module performs no process/native IO.
    owner = None
    try:
        require(len(sys.argv) == 2 and os.name == "nt", "WSLC_WINDOWS_HOST_REQUIRED")
        path = host_path(sys.argv[1], EVIDENCE)
        owner = Owner(strict_json(read_bounded(path, INPUT_CAP)))
        # Raw FileIO avoids a daemon holding a BufferedReader lock at shutdown.
        source = os.fdopen(os.dup(sys.stdin.fileno()), "rb", buffering=0)
        serve(owner, source, lambda raw: os.write(sys.stdout.fileno(), raw), lifetime=profile_runtime_budget(owner.cfg)[2])
        return 0
    except Exception:
        # Never print command lines, file content, exceptions, or tracebacks.
        # A poisoned transport is still an action failure. Exit0 only certifies
        # helper retirement after the immutable exact-owner cleanup receipt was
        # published; Rust separately keeps the action outcome UNKNOWN.
        return 0 if owner is not None and owner.cleaned else 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Fixed WSLC profile and source-bound preparation gate for the Makepad Shell.

The gate validates approved host inputs and actual ELF bytes before the
existing WSLC owner stages the artifact. It does not launch WSLC, transfer
files, or accept Core/runtime evidence. Existing Core identity validation and
its focus-fixture build sub-contract remain authoritative and unchanged.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import sys
from pathlib import Path


PROFILE_SCHEMA = "toolkit-makepad-dev-app-module-shell-wslc-profile-v1"
BUILD_RECEIPT_SCHEMA = "toolkit-linux-module-shell-build-result-v1"
SOURCE_MANIFEST_SCHEMA = "toolkit-trusted-linux-module-shell-build-inputs-v1"
PREPARATION_SCHEMA = "toolkit-makepad-dev-app-module-shell-wslc-preparation-v1"
CORE_PROVENANCE_SCHEMA = "toolkit-wslc-host-guest-executable-provenance-v1"
MAKEPAD_SOURCE_COMMIT = "71c9ddcbb9c01dd208f99621fdd71024a5d35c65"
MODULE_SHELL_BUILD_SCHEMA = BUILD_RECEIPT_SCHEMA
MODULE_SHELL_SOURCE_SCHEMA = SOURCE_MANIFEST_SCHEMA
SHELL_ARTIFACT_ID = "makepad-dev-app-module-shell-linux-71c9ddc"
# Reuse the existing fixed target produced by upload-artifact.ps1 and consumed
# by wslc_host.py; only the approved Shell host artifact identity is new.
SHELL_GUEST_PATH = "/opt/proof/ai-workspace-fixture"
EXISTING_PRODUCER_PATH = "crates/toolkit-windows-automation/src/makepad_remote/wslc_host.py"
CONSUMER_SOURCE_ROOT = "experiments/makepad-dev-app-module-shell"
UPSTREAM_SOURCE_ROOT = "reports/evidence/makepad-dev-capability-audit-20261015/upstream"
SHELL_EVIDENCE_ROOT = "reports/evidence/toolkit-makepad-dev-module-lifecycle-v1/wslc-hot-reload/linux-build05"
SHELL_BUILD_RESULT_PATH = SHELL_EVIDENCE_ROOT + "/native/module-shell-build-result.json"
SHELL_NATIVE_RECEIPT_PATH = SHELL_EVIDENCE_ROOT + "/native/module-shell-build.json"
SHELL_SOURCE_MANIFEST_PATH = SHELL_EVIDENCE_ROOT + "/source-manifest.json"
SHELL_ARTIFACT_PATH = SHELL_EVIDENCE_ROOT + "/artifact/toolkit-app-module-shell"
SHELL_OPERATOR_PLAN_PATH = SHELL_EVIDENCE_ROOT + "/operator-plan.json"
SHELL_SOURCE_MANIFEST_SHA256 = "91F63101687B7BFB778391AB780BCF5AF1B8697D3DA81B5E08E70FFF39C32E42"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_NATIVE_RECEIPT_BYTES = 128 * 1024 * 1024
MAX_SOURCE_FILES = 512
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_ELF_BYTES = 512 * 1024 * 1024
MODULE_SHELL_UPSTREAM_LINUX_ROOT = "/opt/makepad-tools/upstream/makepad-71c9ddc"
MODULE_SHELL_COMPILED_LINUX_ROOT = "/opt/makepad-tools/source/module-shell"
MODULE_SHELL_TARGET_DIR = "/opt/makepad-tools/target/linux"
MODULE_SHELL_TARGET = "x86_64-unknown-linux-gnu"

_GIB = 1024 * 1024 * 1024
_CORE_SAFE_INTEGER_MAX = (1 << 53) - 1
_SHA256_UPPER = re.compile(r"[A-F0-9]{64}\Z")
_SHA256_HEX = re.compile(r"[A-Fa-f0-9]{64}\Z")
_REQUIRED_PROVENANCE_REFS = (
    "profile", "build_receipt", "native_build_receipt", "source_manifest", "producer",
)
_PROVENANCE_KEYS = {
    "schema", "artifact_id", "host_path", "sha256", "bytes", "guest_path",
    *_REQUIRED_PROVENANCE_REFS,
}


class ModuleShellProfileError(ValueError):
    """A fixed-profile or receipt-envelope refusal with a stable local code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _refuse(condition: bool, code: str) -> None:
    if not condition:
        raise ModuleShellProfileError(code)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _duplicate_rejecting_object(pairs):
    result = {}
    for key, value in pairs:
        _refuse(key not in result, "MODULE_SHELL_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _strict_json_bytes(data: bytes, code: str, *, max_bytes: int = MAX_JSON_BYTES):
    _refuse(0 < len(data) <= max_bytes, code)
    try:
        return json.loads(data.decode("utf-8", errors="strict"),
                          object_pairs_hook=_duplicate_rejecting_object,
                          parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except ModuleShellProfileError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ModuleShellProfileError(code) from None


def _file_identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns, getattr(st, "st_nlink", None),
            getattr(st, "st_file_attributes", 0))


def _file_object_identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size,
            getattr(st, "st_nlink", None), getattr(st, "st_file_attributes", 0))


def _file_version(st):
    return (st.st_mtime_ns, st.st_ctime_ns)


def _reject_reparse(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError:
        raise ModuleShellProfileError("MODULE_SHELL_FILE_UNAVAILABLE") from None
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    _refuse(not stat.S_ISLNK(info.st_mode)
            and not (getattr(info, "st_file_attributes", 0) & reparse),
            "MODULE_SHELL_REPARSE_PATH_REFUSED")


def _path_without_reparse(root: Path, relative: str) -> Path:
    _refuse(_safe_project_relative_path(relative), "MODULE_SHELL_PATH_INVALID")
    root = root.resolve(strict=True)
    current = root
    for component in PurePosixPath(relative).parts:
        current = current / component
        _reject_reparse(current)
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        raise ModuleShellProfileError("MODULE_SHELL_PATH_OUTSIDE_ROOT") from None
    return resolved


def _read_stable_file(path: Path, *, max_bytes: int, expected_size: int | None = None):
    _reject_reparse(path)
    try:
        before_path = path.stat(follow_symlinks=False)
        _refuse(stat.S_ISREG(before_path.st_mode), "MODULE_SHELL_FILE_NOT_REGULAR")
        _refuse(before_path.st_nlink == 1 and before_path.st_ino != 0,
                "MODULE_SHELL_FILE_IDENTITY_UNAVAILABLE")
        _refuse(0 < before_path.st_size <= max_bytes, "MODULE_SHELL_FILE_SIZE_REFUSED")
        if expected_size is not None:
            _refuse(type(expected_size) is int and before_path.st_size == expected_size,
                    "MODULE_SHELL_FILE_SIZE_MISMATCH")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened_before = os.fstat(fd)
            _refuse(_file_object_identity(opened_before) == _file_object_identity(before_path),
                    "MODULE_SHELL_FILE_CHANGED_DURING_OPEN")
            chunks = []
            remaining = before_path.st_size
            while remaining:
                block = os.read(fd, min(1024 * 1024, remaining))
                _refuse(bool(block), "MODULE_SHELL_FILE_TRUNCATED")
                chunks.append(block)
                remaining -= len(block)
            data = b"".join(chunks)
            opened_after = os.fstat(fd)
        finally:
            os.close(fd)
        after_path = path.stat(follow_symlinks=False)
        _refuse(_file_object_identity(opened_before) == _file_object_identity(opened_after)
                == _file_object_identity(after_path)
                and _file_version(opened_before) == _file_version(opened_after),
                "MODULE_SHELL_FILE_CHANGED_DURING_READ")
        _refuse(len(data) == before_path.st_size, "MODULE_SHELL_FILE_TRUNCATED")
        return data, _file_identity(opened_after)
    except ModuleShellProfileError:
        raise
    except OSError:
        raise ModuleShellProfileError("MODULE_SHELL_FILE_READ_FAILED") from None


def _absolute_in_evidence(root: Path, supplied: str | os.PathLike, *, code: str) -> tuple[Path, str]:
    try:
        candidate = Path(os.path.abspath(os.fspath(supplied)))
        root = root.resolve(strict=True)
        parts = candidate.parts
        cursor = Path(parts[0])
        for component in parts[1:]:
            cursor = cursor / component
            _reject_reparse(cursor)
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(root).as_posix()
    except ModuleShellProfileError:
        raise
    except (OSError, ValueError, TypeError):
        raise ModuleShellProfileError(code) from None
    _refuse(relative.startswith(SHELL_EVIDENCE_ROOT + "/"), code)
    _refuse(_safe_project_relative_path(relative), code)
    return resolved, relative


def _validate_source_manifest(repo_root: Path, source_sha256: str):
    manifest_path = _path_without_reparse(repo_root, SHELL_SOURCE_MANIFEST_PATH)
    data, _identity = _read_stable_file(manifest_path, max_bytes=MAX_JSON_BYTES)
    actual_sha = _sha256(data)
    _refuse(actual_sha == SHELL_SOURCE_MANIFEST_SHA256,
            "MODULE_SHELL_SOURCE_MANIFEST_ATTEMPT_PIN_MISMATCH")
    _refuse(actual_sha == source_sha256, "MODULE_SHELL_SOURCE_MANIFEST_SHA_MISMATCH")
    manifest = _strict_json_bytes(data, "MODULE_SHELL_SOURCE_MANIFEST_JSON_INVALID")
    required_keys = {"schema", "profile_kind", "source_commit", "files", "upstream",
                     "compiled", "transformations", "harness", "operator_plan"}
    _refuse(type(manifest) is dict and set(manifest) == required_keys,
            "MODULE_SHELL_SOURCE_MANIFEST_SHAPE_INVALID")
    _refuse(manifest["schema"] == MODULE_SHELL_SOURCE_SCHEMA
            and manifest["profile_kind"] == "ModuleShell"
            and manifest["source_commit"] == MAKEPAD_SOURCE_COMMIT,
            "MODULE_SHELL_SOURCE_PIN_MISMATCH")
    files = manifest["files"]
    _refuse(type(files) is list and 0 < len(files) <= MAX_SOURCE_FILES,
            "MODULE_SHELL_SOURCE_LIST_INVALID")
    paths = []
    pins = {}
    total_bytes = 0
    allowed_prefixes = (
        CONSUMER_SOURCE_ROOT + "/", "experiments/ai-execution-workspace/",
        UPSTREAM_SOURCE_ROOT + "/", SHELL_EVIDENCE_ROOT + "/inputs/",
    )
    for entry in files:
        _refuse(type(entry) is dict and set(entry) == {"path", "sha256", "bytes"},
                "MODULE_SHELL_SOURCE_ENTRY_INVALID")
        path = entry.get("path")
        _refuse(_safe_project_relative_path(path)
                and (any(path.startswith(prefix) for prefix in allowed_prefixes)
                     or path in (SHELL_EVIDENCE_ROOT + "/build-linux.sh", SHELL_OPERATOR_PLAN_PATH)),
                "MODULE_SHELL_SOURCE_PATH_REFUSED")
        _refuse(type(entry.get("sha256")) is str and _SHA256_UPPER.fullmatch(entry["sha256"]) is not None,
                "MODULE_SHELL_SOURCE_SHA_INVALID")
        _refuse(type(entry.get("bytes")) is int and 0 < entry["bytes"] <= 8 * 1024 * 1024,
                "MODULE_SHELL_SOURCE_SIZE_INVALID")
        total_bytes += entry["bytes"]
        _refuse(total_bytes <= MAX_SOURCE_BYTES, "MODULE_SHELL_SOURCE_TOTAL_SIZE_REFUSED")
        source_path = _path_without_reparse(repo_root, path)
        source_bytes, _source_identity = _read_stable_file(
            source_path, max_bytes=8 * 1024 * 1024, expected_size=entry["bytes"])
        _refuse(_sha256(source_bytes) == entry["sha256"],
                "MODULE_SHELL_SOURCE_CONTENT_MISMATCH")
        paths.append(path)
        pins[path] = entry
    _refuse(paths == sorted(paths) and len(set(paths)) == len(paths),
            "MODULE_SHELL_SOURCE_ORDER_OR_DUPLICATE")
    upstream = manifest["upstream"]
    compiled = manifest["compiled"]
    _refuse(type(upstream) is dict and set(upstream) == {"files", "linux_root", "archive_conversion", "host_worktree_files"}
            and upstream["archive_conversion"] == "CRLF_TO_LF_ONLY"
            and type(compiled) is dict and set(compiled) == {
                "cargo_lock", "cargo_manifest", "linux_root", "rust_sources", "target_dir"
            }
            and type(manifest["transformations"]) is list and len(manifest["transformations"]) == 2
            and type(manifest["harness"]) is dict and type(manifest["operator_plan"]) is dict,
            "MODULE_SHELL_SOURCE_MANIFEST_SHAPE_INVALID")
    _refuse(upstream.get("linux_root") == MODULE_SHELL_UPSTREAM_LINUX_ROOT
            and compiled.get("linux_root") == MODULE_SHELL_COMPILED_LINUX_ROOT
            and compiled.get("target_dir") == MODULE_SHELL_TARGET_DIR,
            "MODULE_SHELL_SOURCE_ROOT_MISMATCH")

    def check_ref(ref, code="MODULE_SHELL_SOURCE_REFERENCE_INVALID"):
        _refuse(type(ref) is dict and set(ref) == {"path", "sha256", "bytes"}
                and _safe_project_relative_path(ref.get("path")), code)
        pin = pins.get(ref["path"])
        _refuse(pin is not None and _same_typed_tree(pin, ref), code)
        return pin

    _refuse(manifest["operator_plan"].get("path") == SHELL_OPERATOR_PLAN_PATH
            and manifest["harness"].get("path") == SHELL_EVIDENCE_ROOT + "/build-linux.sh",
            "MODULE_SHELL_SOURCE_PLAN_OR_HARNESS_MISMATCH")
    check_ref(manifest["operator_plan"])
    check_ref(manifest["harness"])
    check_ref(compiled.get("cargo_manifest"))
    check_ref(compiled.get("cargo_lock"))
    _refuse(type(compiled.get("rust_sources")) is list and 0 < len(compiled["rust_sources"]) <= 128,
            "MODULE_SHELL_COMPILED_SOURCE_MAP_INVALID")
    for entry in compiled["rust_sources"]:
        _refuse(type(entry) is dict and type(entry.get("relative_path")) is str
                and re.fullmatch(r"src/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.rs", entry["relative_path"]) is not None,
                "MODULE_SHELL_COMPILED_SOURCE_PATH_INVALID")
        check_ref({key: entry.get(key) for key in ("path", "sha256", "bytes")})
    compiled_names = {entry["relative_path"] for entry in compiled["rust_sources"]}
    _refuse({"src/main.rs", "src/lib.rs", "src/fixtures.rs", "src/tile.rs"}.issubset(compiled_names),
            "MODULE_SHELL_COMPILED_SOURCE_REQUIRED")
    _refuse(type(upstream.get("files")) is list and 9 <= len(upstream["files"]) <= 128,
            "MODULE_SHELL_UPSTREAM_SOURCE_MAP_INVALID")
    for entry in upstream["files"]:
        _refuse(type(entry) is dict and type(entry.get("relative_path")) is str
                and not entry["relative_path"].startswith("/")
                and "\\" not in entry["relative_path"]
                and all(part not in ("", ".", "..") for part in entry["relative_path"].split("/")),
                "MODULE_SHELL_UPSTREAM_SOURCE_PATH_INVALID")
        check_ref({key: entry.get(key) for key in ("path", "sha256", "bytes")})
    upstream_names = {entry["relative_path"] for entry in upstream["files"]}
    required_upstream = {
        "libs/app_module/src/lib.rs", "apps/wm/src/module_host.rs", "apps/wm/src/module_view.rs",
        "apps/wm/src/ai_bus.rs", "apps/wm/src/dylib_host.rs", "platform/src/storage.rs",
        "widgets/core/src/widget_async.rs", "libs/app_module/Cargo.toml", "apps/wm/src/hub.rs",
    }
    _refuse(required_upstream.issubset(upstream_names), "MODULE_SHELL_UPSTREAM_SOURCE_REQUIRED")
    originals = upstream["host_worktree_files"]
    _refuse(type(originals) is list and len(originals) == len(upstream["files"]), "MODULE_SHELL_UPSTREAM_SOURCE_MAP_INVALID")
    for entry, archived in zip(originals, upstream["files"]):
        # Both orders need not match: archive list is canonical path-sorted.
        matching = [row for row in upstream["files"] if row["relative_path"] == entry.get("relative_path")]
        _refuse(len(matching) == 1 and entry.get("path") == UPSTREAM_SOURCE_ROOT + "/" + entry["relative_path"],
                "MODULE_SHELL_UPSTREAM_SOURCE_PATH_INVALID")
        archived = matching[0]
        check_ref({key: entry.get(key) for key in ("path", "sha256", "bytes")})
        original_bytes, _ = _read_stable_file(_path_without_reparse(repo_root, entry["path"]), max_bytes=8*1024*1024)
        archive_bytes, _ = _read_stable_file(_path_without_reparse(repo_root, archived["path"]), max_bytes=8*1024*1024)
        _refuse(original_bytes.replace(b"\r\n", b"\n") == archive_bytes and b"\r" not in archive_bytes,
                "MODULE_SHELL_UPSTREAM_LINE_ENDING_MISMATCH")
    plan_bytes, _plan_identity = _read_stable_file(
        _path_without_reparse(repo_root, SHELL_OPERATOR_PLAN_PATH), max_bytes=MAX_JSON_BYTES,
        expected_size=manifest["operator_plan"]["bytes"])
    plan = _strict_json_bytes(plan_bytes, "MODULE_SHELL_OPERATOR_PLAN_JSON_INVALID")
    _refuse(type(plan) is dict and _sha256(plan_bytes) == manifest["operator_plan"]["sha256"]
            and plan.get("schema") == "toolkit-module-shell-linux-build-operator-plan-v1"
            and plan.get("status") == "PREPARED_NOT_RUN"
            and plan.get("source_commit") == MAKEPAD_SOURCE_COMMIT
            and plan.get("upstream_linux_root") == MODULE_SHELL_UPSTREAM_LINUX_ROOT
            and plan.get("compiled_linux_root") == MODULE_SHELL_COMPILED_LINUX_ROOT
            and plan.get("target_dir") == MODULE_SHELL_TARGET_DIR
            and plan.get("target") == MODULE_SHELL_TARGET
            and plan.get("positive_memory_budget_bytes") == 2 * _GIB
            and plan.get("available_memory_query_performed") is False
            and plan.get("artifact_host_path") == SHELL_ARTIFACT_PATH,
            "MODULE_SHELL_OPERATOR_PLAN_MISMATCH")
    source_ref = {"path": SHELL_SOURCE_MANIFEST_PATH, "sha256": actual_sha, "bytes": len(data)}
    return source_ref, manifest, plan


def _validate_native_build(repo_root: Path, native: dict, build: dict,
                           source_manifest: dict, cargo_args: list[str]) -> None:
    root_spelling = str(repo_root.resolve(strict=True)).replace("\\", "/")
    match = re.fullmatch(r"([A-Za-z]):/(.+)", root_spelling)
    _refuse(match is not None, "MODULE_SHELL_NATIVE_BUILD_ROOT_INVALID")
    mounted_root = f"/mnt/{match.group(1).lower()}/{match.group(2)}"
    mounted_script = mounted_root + "/" + source_manifest["harness"]["path"]
    expected_native_args = ["-d", "Ubuntu", "--exec", "/bin/bash", mounted_script]
    _refuse(type(native.get("executable")) is str
            and native["executable"].replace("\\", "/").lower() == "c:/windows/system32/wsl.exe"
            and _same_typed_tree(native.get("args"), expected_native_args),
            "MODULE_SHELL_NATIVE_BUILD_INVOCATION_MISMATCH")
    stdout = native["stdout"]
    marker_positions = {}
    expected_markers = {
        "BEFORE": build["before"], "AFTER": build["after"],
        "TOOLCHAIN": build["toolchain"], "COMMAND": cargo_args,
        "ARTIFACT": build["artifact"],
    }
    lines = stdout.splitlines()
    for name, expected in expected_markers.items():
        prefix = f"TOOLKIT_MODULE_SHELL_{name} "
        found = [(index, line[len(prefix):]) for index, line in enumerate(lines) if line.startswith(prefix)]
        _refuse(len(found) == 1, "MODULE_SHELL_NATIVE_MARKER_MISSING_OR_DUPLICATE")
        marker_positions[name] = found[0][0]
        marker = _strict_json_bytes(found[0][1].encode("utf-8"),
                                    "MODULE_SHELL_NATIVE_MARKER_JSON_INVALID")
        _refuse(_same_typed_tree(marker, expected), "MODULE_SHELL_NATIVE_MARKER_MISMATCH")

    cargo_records = []
    for index, line in enumerate(lines):
        if not line.startswith("{"):
            continue
        try:
            cargo_records.append((index, _strict_json_bytes(line.encode("utf-8"),
                "MODULE_SHELL_NATIVE_CARGO_JSON_INVALID")))
        except ModuleShellProfileError:
            continue
    executable = build["artifact"]["actual_compiler_artifact"]
    compiler = [(index, item) for index, item in cargo_records
                if item.get("reason") == "compiler-artifact" and item.get("executable") == executable]
    finished = [(index, item) for index, item in cargo_records if item.get("reason") == "build-finished"]
    _refuse(len(compiler) == 1 and len(finished) == 1 and finished[0][1].get("success") is True,
            "MODULE_SHELL_NATIVE_CARGO_RESULT_MISMATCH")
    item = compiler[0][1]
    target = item.get("target")
    _refuse(item.get("fresh") is False
            and type(target) is dict and target.get("name") == "toolkit-app-module-shell"
            and _same_typed_tree(target.get("kind"), ["bin"])
            and target.get("src_path") == source_manifest["compiled"]["linux_root"] + "/src/main.rs",
            "MODULE_SHELL_NATIVE_COMPILER_ARTIFACT_MISMATCH")
    sha_lines = [index for index, line in enumerate(lines)
                 if line.upper() == f"{build['artifact']['sha256']}  {executable}".upper()]
    _refuse(len(sha_lines) == 1
            and marker_positions["BEFORE"] < marker_positions["TOOLCHAIN"]
            < marker_positions["COMMAND"] < compiler[0][0] < finished[0][0]
            < marker_positions["AFTER"] < sha_lines[0] < marker_positions["ARTIFACT"],
            "MODULE_SHELL_NATIVE_BUILD_ORDER_MISMATCH")


def validate_build_manifest(repo_root: str | os.PathLike, manifest_path: str | os.PathLike,
                            expected_manifest_sha256: str, approved_elf_path: str | os.PathLike,
                            *, now_utc: datetime | None = None) -> dict:
    """Check approved receipt/source/ELF bytes for operator-only preparation.

    This does not prove transfer, guest bytes, running process identity, or
    runtime/Core acceptance.
    """
    root = Path(repo_root).resolve(strict=True)
    del now_utc  # A build timestamp is not used by the Core ModuleShell contract.
    _refuse(type(expected_manifest_sha256) is str
            and _SHA256_HEX.fullmatch(expected_manifest_sha256) is not None,
            "MODULE_SHELL_APPROVAL_SHA_INVALID")
    build_path, build_relative = _absolute_in_evidence(
        root, manifest_path, code="MODULE_SHELL_BUILD_RECEIPT_PATH_REFUSED")
    _refuse(build_relative == SHELL_BUILD_RESULT_PATH,
            "MODULE_SHELL_BUILD_RECEIPT_PATH_REFUSED")
    build_bytes, _build_identity = _read_stable_file(build_path, max_bytes=MAX_JSON_BYTES)
    actual_build_sha = _sha256(build_bytes)
    _refuse(actual_build_sha == expected_manifest_sha256.upper(),
            "MODULE_SHELL_BUILD_RECEIPT_SHA_MISMATCH")
    receipt = _strict_json_bytes(build_bytes, "MODULE_SHELL_BUILD_RECEIPT_JSON_INVALID")
    _refuse(type(receipt) is dict and set(receipt) == {
        "schema", "profile_kind", "exit_code", "timed_out", "output_drained", "receipt",
        "source", "before", "after", "toolchain", "cargo", "artifact"
    }, "MODULE_SHELL_BUILD_RECEIPT_SHAPE_INVALID")
    _refuse(receipt["schema"] == MODULE_SHELL_BUILD_SCHEMA and receipt["profile_kind"] == "ModuleShell",
            "MODULE_SHELL_BUILD_RECEIPT_SCHEMA_MISMATCH")
    _refuse(type(receipt["exit_code"]) is int and receipt["exit_code"] == 0
            and receipt["timed_out"] is False and receipt["output_drained"] is True,
            "MODULE_SHELL_BUILD_NOT_SUCCESSFUL")
    source = receipt["source"]
    _refuse(type(source) is dict and set(source) == {"SDK_pin", "source_manifest_sha256"}
            and source["SDK_pin"] == MAKEPAD_SOURCE_COMMIT
            and type(source["source_manifest_sha256"]) is str
            and _SHA256_UPPER.fullmatch(source["source_manifest_sha256"]) is not None,
            "MODULE_SHELL_BUILD_SOURCE_PIN_MISMATCH")
    source_ref, source_manifest, operator_plan = _validate_source_manifest(
        root, source["source_manifest_sha256"])
    _refuse(_same_typed_tree(receipt["before"], source_manifest["files"])
            and _same_typed_tree(receipt["after"], source_manifest["files"]),
            "MODULE_SHELL_BUILD_SOURCE_SET_MISMATCH")
    toolchain = receipt["toolchain"]
    _refuse(type(toolchain) is dict and toolchain.get("target") == MODULE_SHELL_TARGET
            and type(toolchain.get("rustc_vv")) is str and type(toolchain.get("cargo_version")) is str
            and type(toolchain.get("rustc_sha256")) is str
            and _SHA256_UPPER.fullmatch(toolchain["rustc_sha256"]) is not None
            and type(toolchain.get("cargo_sha256")) is str
            and _SHA256_UPPER.fullmatch(toolchain["cargo_sha256"]) is not None,
            "MODULE_SHELL_TOOLCHAIN_OR_TARGET_REFUSED")
    _refuse(re.match(r"^rustc [^\n]+\n", toolchain["rustc_vv"]) is not None
            and re.search(r"^commit-hash: [a-f0-9]{40}$", toolchain["rustc_vv"], re.M) is not None
            and re.search(r"^host: [^\s]+$", toolchain["rustc_vv"], re.M) is not None
            and re.match(r"^cargo \d+\.\d+\.\d+", toolchain["cargo_version"]) is not None,
            "MODULE_SHELL_TOOLCHAIN_VERSION_INVALID")
    expected_cargo_args = ["build", "--manifest-path", source_manifest["compiled"]["linux_root"] + "/Cargo.toml",
        "--bin", "toolkit-app-module-shell", "--locked", "--offline", "-j", "1", "--target",
        MODULE_SHELL_TARGET, "--target-dir", source_manifest["compiled"]["target_dir"],
        "--message-format=json-render-diagnostics"]
    _refuse(type(receipt["cargo"]) is dict
            and _same_typed_tree(receipt["cargo"], {"args": expected_cargo_args, "target_artifact_fresh": False}),
            "MODULE_SHELL_CARGO_INVOCATION_REFUSED")
    native_relative = SHELL_NATIVE_RECEIPT_PATH
    _refuse(receipt["receipt"] == "module-shell-build.json"
            and (Path(build_relative).parent / receipt["receipt"]).as_posix() == native_relative,
            "MODULE_SHELL_BUILD_NATIVE_RECEIPT_JOIN_MISMATCH")
    native_path = _path_without_reparse(root, native_relative)
    native_bytes, _native_identity = _read_stable_file(
        native_path, max_bytes=MAX_NATIVE_RECEIPT_BYTES)
    native = _strict_json_bytes(native_bytes, "MODULE_SHELL_NATIVE_RECEIPT_JSON_INVALID",
                                max_bytes=MAX_NATIVE_RECEIPT_BYTES)
    _refuse(type(native) is dict and type(native.get("exit_code")) is int and native.get("exit_code") == 0
            and native.get("timed_out") is False and native.get("output_drained") is True
            and type(native.get("stdout")) is str,
            "MODULE_SHELL_NATIVE_BUILD_RECEIPT_INVALID")
    _validate_native_build(root, native, receipt, source_manifest, expected_cargo_args)
    native_ref = {"path": native_relative, "sha256": _sha256(native_bytes), "bytes": len(native_bytes)}
    artifact = receipt["artifact"]
    _refuse(type(artifact) is dict and set(artifact) == {"sha256", "bytes", "actual_compiler_artifact"},
            "MODULE_SHELL_ARTIFACT_SHAPE_INVALID")
    _refuse(type(artifact.get("sha256")) is str and _SHA256_UPPER.fullmatch(artifact["sha256"]) is not None,
            "MODULE_SHELL_ARTIFACT_SHA_INVALID")
    _refuse(type(artifact.get("bytes")) is int and 64 <= artifact["bytes"] <= MAX_ELF_BYTES,
            "MODULE_SHELL_ARTIFACT_SIZE_INVALID")
    expected_compiler_artifact = (source_manifest["compiled"]["target_dir"] + "/"
                                  + MODULE_SHELL_TARGET + "/debug/toolkit-app-module-shell")
    _refuse(artifact.get("actual_compiler_artifact") == expected_compiler_artifact
            and operator_plan.get("artifact_host_path") == SHELL_ARTIFACT_PATH,
            "MODULE_SHELL_ARTIFACT_PATH_REFUSED")
    actual_artifact_path = _path_without_reparse(root, SHELL_ARTIFACT_PATH)
    passed_artifact_path, _passed_relative = _absolute_in_evidence(
        root, approved_elf_path, code="MODULE_SHELL_APPROVED_ELF_PATH_REFUSED")
    _refuse(actual_artifact_path == passed_artifact_path,
            "MODULE_SHELL_APPROVED_ELF_PATH_MISMATCH")
    elf_bytes, file_identity = _read_stable_file(actual_artifact_path,
        max_bytes=MAX_ELF_BYTES, expected_size=artifact["bytes"])
    _refuse(_sha256(elf_bytes) == artifact["sha256"].upper(),
            "MODULE_SHELL_ARTIFACT_CONTENT_MISMATCH")
    _refuse(elf_bytes[:4] == b"\x7fELF" and len(elf_bytes) >= 64
            and elf_bytes[4] == 2 and elf_bytes[5] == 1
            and int.from_bytes(elf_bytes[16:18], "little") in (2, 3)
            and int.from_bytes(elf_bytes[18:20], "little") == 62
            and int.from_bytes(elf_bytes[20:24], "little") == 1
            and int.from_bytes(elf_bytes[52:54], "little") == 64
            and int.from_bytes(elf_bytes[54:56], "little") == 56
            and int.from_bytes(elf_bytes[56:58], "little") > 0
            and int.from_bytes(elf_bytes[32:40], "little") +
                int.from_bytes(elf_bytes[54:56], "little") *
                int.from_bytes(elf_bytes[56:58], "little") <= len(elf_bytes),
            "MODULE_SHELL_ARTIFACT_ELF_IDENTITY_REFUSED")
    profile = select_profile("wslc_multi_module", explicit_opt_in=True)
    profile["profile_kind"] = "ModuleShell"
    profile["module_shell"] = {
        "source_manifest_sha256": source_ref["sha256"],
    }
    return {
        "schema": PREPARATION_SCHEMA,
        "status": "PREPARED_NOT_RUNTIME_ACCEPTANCE",
        "profile_id": "wslc_multi_module",
        "profile": profile,
        "source_commit": MAKEPAD_SOURCE_COMMIT,
        "build_receipt": {"path": build_relative, "sha256": actual_build_sha,
                          "bytes": len(build_bytes)},
        "native_build_receipt": native_ref,
        "source_manifest": {"path": source_ref["path"], "sha256": source_ref["sha256"],
                            "bytes": source_ref["bytes"]},
        "artifact": {"artifact_id": SHELL_ARTIFACT_ID, "path": SHELL_ARTIFACT_PATH,
                     "host_path": str(actual_artifact_path), "sha256": _sha256(elf_bytes),
                     "bytes": artifact["bytes"], "guest_path": SHELL_GUEST_PATH,
                     "format": "ELF64_X86_64", "file_identity": {
                         "device": file_identity[0], "inode": file_identity[1],
                         "links": file_identity[6], "size": file_identity[3]
                     }},
        "toolchain": {"target": toolchain["target"],
                      "rustc_sha256": toolchain["rustc_sha256"],
                      "cargo_sha256": toolchain["cargo_sha256"]},
    }


def _profile(profile_id: str, *, modules: int, container_bytes: int,
             host_admission_bytes: int, opt_in: bool) -> dict:
    memory_flag = f"{container_bytes // _GIB}G"
    host_admission = {
        "minimum_free_bytes": host_admission_bytes,
        "scope": "one_outer_runtime_admission",
        "nested_increment_bytes": 0,
    }
    if opt_in:
        # The standing operator waiver suppresses host-free-RAM queries. This
        # remains a positive threshold, not a measured or admitted RAM value.
        host_admission["host_ram_mode"] = "USER_WAIVED"
    return {
        "schema": PROFILE_SCHEMA,
        "profile_id": profile_id,
        "source_commit": MAKEPAD_SOURCE_COMMIT,
        "module_instances": modules,
        "explicit_opt_in": opt_in,
        "container": {
            "memory_bytes": container_bytes,
            "cpus": 1,
            "fixed_limit_args": ["--memory", memory_flag, "--cpus", "1"],
        },
        "host_runtime_admission": host_admission,
    }


_PROFILES = {
    "wslc_single_app": _profile(
        "wslc_single_app", modules=1, container_bytes=_GIB,
        host_admission_bytes=2 * _GIB, opt_in=False,
    ),
    "wslc_multi_module": _profile(
        "wslc_multi_module", modules=2, container_bytes=2 * _GIB,
        host_admission_bytes=(5 * _GIB) // 2, opt_in=True,
    ),
}


def _same_typed_tree(actual, expected) -> bool:
    """Structural equality that does not let bool pass for an integer limit."""
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(
            _same_typed_tree(actual[key], expected[key]) for key in expected
        )
    if type(expected) is list:
        return len(actual) == len(expected) and all(
            _same_typed_tree(a, e) for a, e in zip(actual, expected)
        )
    return actual == expected


def select_profile(profile_id: str | None = None, *, explicit_opt_in: bool = False) -> dict:
    """Resolve one fixed contract; no caller-supplied limits or command paths."""
    selected = "wslc_single_app" if profile_id is None else profile_id
    _refuse(type(selected) is str and selected in _PROFILES, "WSLC_PROFILE_UNKNOWN")
    _refuse(type(explicit_opt_in) is bool, "WSLC_PROFILE_OPT_IN_TYPE_INVALID")
    expected = _PROFILES[selected]
    if selected == "wslc_multi_module":
        _refuse(explicit_opt_in is True, "WSLC_MULTI_MODULE_OPT_IN_REQUIRED")
    else:
        _refuse(explicit_opt_in is False, "WSLC_SINGLE_PROFILE_OPT_IN_MISMATCH")
    return deepcopy(expected)


def validate_profile(value: object) -> dict:
    """Validate an exact serialized profile against its fixed resource contract."""
    _refuse(type(value) is dict, "WSLC_PROFILE_INVALID")
    _refuse(value.get("schema") == PROFILE_SCHEMA, "WSLC_PROFILE_SCHEMA_MISMATCH")
    profile_id = value.get("profile_id")
    _refuse(type(profile_id) is str and profile_id in _PROFILES, "WSLC_PROFILE_UNKNOWN")
    _refuse(value.get("source_commit") == MAKEPAD_SOURCE_COMMIT,
            "WSLC_PROFILE_SOURCE_PIN_MISMATCH")
    expected = _PROFILES[profile_id]
    _refuse(_same_typed_tree(value, expected), "WSLC_PROFILE_CONTRACT_MISMATCH")
    return deepcopy(value)


def _safe_project_relative_path(value: object) -> bool:
    if (type(value) is not str or not value or "\\" in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and bool(path.parts)
        and all(part not in ("", ".", "..") for part in path.parts)
        and ":" not in path.parts[0]
    )


def validate_core_provenance_shape(value: object) -> None:
    """Check the existing Core v2 envelope only; this is not artifact acceptance.

    Core v2 must still reopen every referenced byte and prove the existing
    host→transfer→guest→running-process joins. In particular, this helper does
    not hash ``host_path`` or bless a build manifest by its field names.
    """
    _refuse(type(value) is dict and set(value) == _PROVENANCE_KEYS,
            "WSLC_PROVENANCE_SHAPE_INVALID")
    _refuse(value.get("schema") == CORE_PROVENANCE_SCHEMA,
            "WSLC_PROVENANCE_SCHEMA_MISMATCH")
    _refuse(value.get("artifact_id") == SHELL_ARTIFACT_ID,
            "WSLC_SHELL_ARTIFACT_ID_MISMATCH")
    _refuse(value.get("guest_path") == SHELL_GUEST_PATH,
            "WSLC_SHELL_GUEST_PATH_MISMATCH")
    _refuse(_safe_project_relative_path(value.get("host_path"))
            and value["host_path"].startswith("reports/evidence/"),
            "WSLC_HOST_ARTIFACT_PATH_REFUSED")
    _refuse(type(value.get("sha256")) is str and _SHA256_UPPER.fullmatch(value["sha256"]) is not None,
            "WSLC_HOST_ARTIFACT_SHA256_INVALID")
    _refuse(type(value.get("bytes")) is int and 0 < value["bytes"] <= _CORE_SAFE_INTEGER_MAX,
            "WSLC_HOST_ARTIFACT_SIZE_INVALID")

    seen = set()
    for name in _REQUIRED_PROVENANCE_REFS:
        ref = value.get(name)
        _refuse(type(ref) is dict and set(ref) == {"path", "sha256"},
                "WSLC_PROVENANCE_REFERENCE_INVALID")
        _refuse(_safe_project_relative_path(ref.get("path")),
                "WSLC_PROVENANCE_REFERENCE_PATH_REFUSED")
        _refuse(type(ref.get("sha256")) is str and _SHA256_UPPER.fullmatch(ref["sha256"]) is not None,
                "WSLC_PROVENANCE_REFERENCE_SHA256_INVALID")
        _refuse(ref["path"] not in seen, "WSLC_PROVENANCE_REFERENCE_REUSED")
        seen.add(ref["path"])

    for name in ("profile", "build_receipt", "native_build_receipt", "source_manifest"):
        _refuse(value[name]["path"].startswith("reports/evidence/"),
                "WSLC_PROVENANCE_EVIDENCE_PATH_REQUIRED")
    _refuse(value["producer"]["path"] == EXISTING_PRODUCER_PATH,
            "WSLC_PROVENANCE_PRODUCER_MISMATCH")


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fixed Makepad Shell preparation gate")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-build-manifest")
    validate.add_argument("--manifest", required=True)
    validate.add_argument("--manifest-sha256", required=True)
    validate.add_argument("--approved-elf", required=True)
    args = parser.parse_args(argv)
    try:
        root = Path(__file__).resolve().parents[2]
        result = validate_build_manifest(root, args.manifest, args.manifest_sha256,
                                         args.approved_elf)
    except ModuleShellProfileError as exc:
        print(exc.code, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

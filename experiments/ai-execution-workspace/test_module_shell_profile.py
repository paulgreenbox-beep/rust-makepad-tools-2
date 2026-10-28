"""Pure profile and receipt-envelope tests; no WSL, subprocess, RAM or GUI."""
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("module-shell-profile.py")
SPEC = importlib.util.spec_from_file_location("module_shell_profile", MODULE_PATH)
module_shell_profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module_shell_profile)


class ModuleShellProfileTests(unittest.TestCase):
    def setUp(self):
        self.api = module_shell_profile

    def refused(self, code, fn, *args, **kwargs):
        with self.assertRaises(self.api.ModuleShellProfileError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def validate_prepared(self, prepared, *args, **kwargs):
        with patch.object(self.api, "SHELL_SOURCE_MANIFEST_SHA256", prepared["source_manifest_sha256"]):
            return self.api.validate_build_manifest(
                prepared["root"], prepared["build_path"], prepared["build_sha"],
                prepared["elf_path"], *args, **kwargs)

    def refuse_prepared(self, code, prepared, *, build_sha=None, elf_path=None, **kwargs):
        with patch.object(self.api, "SHELL_SOURCE_MANIFEST_SHA256", prepared["source_manifest_sha256"]):
            self.refused(code, self.api.validate_build_manifest, prepared["root"],
                         prepared["build_path"], build_sha or prepared["build_sha"],
                         elf_path or prepared["elf_path"], **kwargs)

    def prepared_build(self, root):
        api = self.api
        consumer = root / api.CONSUMER_SOURCE_ROOT
        upstream = root / api.UPSTREAM_SOURCE_ROOT
        evidence = root / api.SHELL_EVIDENCE_ROOT
        evidence.mkdir(parents=True, exist_ok=True)
        sources = {}

        def store(relative, data):
            path = root / Path(relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            return {"path": relative, "sha256": hashlib.sha256(data).hexdigest().upper(),
                    "bytes": len(data)}

        cargo_original = store(f"{api.CONSUMER_SOURCE_ROOT}/Cargo.toml", b'[package]\nname="toolkit-app-module-shell"\n')
        lock = store(f"{api.CONSUMER_SOURCE_ROOT}/Cargo.lock", b"# exact test lock\n")
        main_original = store(f"{api.CONSUMER_SOURCE_ROOT}/src/main.rs", b"fn main() {}\n")
        cargo_staged = store(api.SHELL_EVIDENCE_ROOT + "/inputs/consumer/staged/Cargo.toml",
                             b'[package]\nname="toolkit-app-module-shell"\n')
        main_staged = store(api.SHELL_EVIDENCE_ROOT + "/inputs/consumer/staged/src/main.rs", b"fn main() {}\n")
        compiled_refs = []
        for relative, content in (("src/main.rs", b"fn main() {}\n"),
                                  ("src/lib.rs", b"pub fn module_shell() {}\n"),
                                  ("src/fixtures.rs", b"pub fn fixture() {}\n"),
                                  ("src/tile.rs", b"pub fn tile() {}\n")):
            if relative == "src/main.rs":
                ref = main_staged
            else:
                ref = store(f"{api.CONSUMER_SOURCE_ROOT}/{relative}", content)
            compiled_refs.append({"relative_path": relative, **ref})
        required_upstream = (
            "libs/app_module/src/lib.rs", "apps/wm/src/module_host.rs", "apps/wm/src/module_view.rs",
            "apps/wm/src/ai_bus.rs", "apps/wm/src/dylib_host.rs", "platform/src/storage.rs",
            "widgets/core/src/widget_async.rs", "libs/app_module/Cargo.toml", "apps/wm/src/hub.rs",
        )
        upstream_refs = []
        for relative in required_upstream:
            ref = store(f"{api.UPSTREAM_SOURCE_ROOT}/{relative}", ("pinned:" + relative).encode())
            upstream_refs.append({"relative_path": relative, **ref})
        harness_path = api.SHELL_EVIDENCE_ROOT + "/build-linux.sh"
        harness = store(harness_path, b"#!/bin/bash\n# fixed test harness\n")
        operator_path = api.SHELL_OPERATOR_PLAN_PATH
        compiled_root = api.MODULE_SHELL_COMPILED_LINUX_ROOT
        target_dir = api.MODULE_SHELL_TARGET_DIR
        cargo_args = ["build", "--manifest-path", compiled_root + "/Cargo.toml", "--bin",
                      "toolkit-app-module-shell", "--locked", "--offline", "-j", "1", "--target",
                      api.MODULE_SHELL_TARGET, "--target-dir", target_dir,
                      "--message-format=json-render-diagnostics"]
        operator_plan = {
            "schema": "toolkit-module-shell-linux-build-operator-plan-v1",
            "status": "PREPARED_NOT_RUN", "source_commit": api.MAKEPAD_SOURCE_COMMIT,
            "upstream_linux_root": api.MODULE_SHELL_UPSTREAM_LINUX_ROOT,
            "compiled_linux_root": compiled_root, "target_dir": target_dir,
            "target": api.MODULE_SHELL_TARGET, "positive_memory_budget_bytes": 2 * 1024**3,
            "available_memory_query_performed": False, "artifact_host_path": api.SHELL_ARTIFACT_PATH,
            "cargo_args": cargo_args,
        }
        operator = store(operator_path, json.dumps(operator_plan, sort_keys=True,
                                                   separators=(",", ":")).encode())
        source_entries = sorted([cargo_original, lock, main_original, cargo_staged, main_staged,
                                 *[{key: entry[key] for key in ("path", "sha256", "bytes")}
                                   for entry in compiled_refs if entry["relative_path"] != "src/main.rs"],
                                 *[{key: entry[key] for key in ("path", "sha256", "bytes")} for entry in upstream_refs],
                                 harness, operator], key=lambda item: item["path"])
        # Keep each archive path unique while retaining the original refs used by the Core schema.
        source_entries = list({entry["path"]: entry for entry in source_entries}.values())
        source_entries.sort(key=lambda item: item["path"])
        source_manifest = {
            "schema": api.SOURCE_MANIFEST_SCHEMA, "profile_kind": "ModuleShell",
            "source_commit": api.MAKEPAD_SOURCE_COMMIT, "files": source_entries,
            "upstream": {"linux_root": api.MODULE_SHELL_UPSTREAM_LINUX_ROOT, "files": upstream_refs,
                         "host_worktree_files": upstream_refs, "archive_conversion": "CRLF_TO_LF_ONLY"},
            "compiled": {"linux_root": compiled_root, "target_dir": target_dir,
                         "cargo_manifest": cargo_staged, "cargo_lock": lock,
                         "rust_sources": compiled_refs},
            "transformations": [
                {"kind": "module-host-path", "input": main_original, "output": main_staged,
                 "replacements": [{"from": "old", "to": "new", "count": 1}]},
                {"kind": "cargo-paths", "input": cargo_original, "output": cargo_staged,
                 "replacements": [{"from": "old", "to": "new", "count": 1}]},
            ],
            "harness": harness, "operator_plan": operator,
        }
        source_manifest_path = evidence / "source-manifest.json"
        source_manifest_bytes = json.dumps(source_manifest, sort_keys=True,
                                           separators=(",", ":")).encode()
        source_manifest_path.write_bytes(source_manifest_bytes)
        source_manifest_sha = hashlib.sha256(source_manifest_bytes).hexdigest().upper()
        elf = bytearray(128)
        elf[0:4] = b"\x7fELF"
        elf[4] = 2
        elf[5] = 1
        elf[16:18] = (3).to_bytes(2, "little")
        elf[18:20] = (62).to_bytes(2, "little")
        elf[20:24] = (1).to_bytes(4, "little")
        elf[32:40] = (64).to_bytes(8, "little")
        elf[52:54] = (64).to_bytes(2, "little")
        elf[54:56] = (56).to_bytes(2, "little")
        elf[56:58] = (1).to_bytes(2, "little")
        elf_path = root / Path(api.SHELL_ARTIFACT_PATH)
        elf_path.parent.mkdir(parents=True, exist_ok=True)
        elf_path.write_bytes(elf)
        build_receipt = {
            "schema": api.BUILD_RECEIPT_SCHEMA, "profile_kind": "ModuleShell",
            "exit_code": 0, "timed_out": False, "output_drained": True,
            "receipt": "module-shell-build.json",
            "source": {"SDK_pin": api.MAKEPAD_SOURCE_COMMIT,
                       "source_manifest_sha256": source_manifest_sha},
            "before": source_entries, "after": source_entries,
            "toolchain": {"target": api.MODULE_SHELL_TARGET, "rustc_path": "/usr/bin/rustc",
                          "cargo_path": "/usr/bin/cargo",
                          "rustc_vv": "rustc 1.93.1 test\ncommit-hash: " + "a" * 40 + "\nhost: x86_64-unknown-linux-gnu\n",
                          "cargo_version": "cargo 1.93.1", "rustc_sha256": "A" * 64,
                          "cargo_sha256": "B" * 64},
            "cargo": {"args": cargo_args, "target_artifact_fresh": False},
            "artifact": {"sha256": hashlib.sha256(elf).hexdigest().upper(), "bytes": len(elf),
                         "actual_compiler_artifact": target_dir + "/" + api.MODULE_SHELL_TARGET
                         + "/debug/toolkit-app-module-shell"},
        }
        native_path = evidence / "native" / "module-shell-build.json"
        native_path.parent.mkdir(parents=True, exist_ok=True)
        compact = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
        artifact_event = {"reason": "compiler-artifact",
                          "executable": build_receipt["artifact"]["actual_compiler_artifact"],
                          "target": {"name": "toolkit-app-module-shell", "kind": ["bin"],
                                     "src_path": compiled_root + "/src/main.rs"}, "fresh": False}
        finished_event = {"reason": "build-finished", "success": True}
        root_spelling = str(root.resolve()).replace("\\", "/")
        mounted_root = "/mnt/" + root_spelling[0].lower() + root_spelling[2:]
        native_args = ["-d", "Ubuntu", "--exec", "/bin/bash",
                       mounted_root + "/" + harness_path]
        native_stdout = "\n".join([
            "TOOLKIT_MODULE_SHELL_BEFORE " + compact(source_entries),
            "TOOLKIT_MODULE_SHELL_TOOLCHAIN " + compact(build_receipt["toolchain"]),
            "TOOLKIT_MODULE_SHELL_COMMAND " + compact(cargo_args),
            compact(artifact_event), compact(finished_event),
            "TOOLKIT_MODULE_SHELL_AFTER " + compact(source_entries),
            build_receipt["artifact"]["sha256"].lower() + "  "
                + build_receipt["artifact"]["actual_compiler_artifact"],
            "TOOLKIT_MODULE_SHELL_ARTIFACT " + compact(build_receipt["artifact"]),
        ])
        native_bytes = json.dumps({"exit_code": 0, "timed_out": False,
                                   "output_drained": True, "stdout": native_stdout,
                                   "executable": "C:/Windows/System32/wsl.exe", "args": native_args},
                                  sort_keys=True, separators=(",", ":")).encode()
        native_path.write_bytes(native_bytes)
        build_path = evidence / "native" / "module-shell-build-result.json"
        build_bytes = json.dumps(build_receipt, sort_keys=True,
                                 separators=(",", ":")).encode()
        build_path.write_bytes(build_bytes)
        return {"build_path": build_path, "build_sha": hashlib.sha256(build_bytes).hexdigest().upper(),
                "elf_path": elf_path, "root": root, "source_manifest_path": source_manifest_path,
                "source_manifest_sha256": source_manifest_sha}

    def test_prepared_linux_build05_manifest_matches_core_branch_pin(self):
        root = Path(__file__).parents[2]
        path = root / Path(self.api.SHELL_SOURCE_MANIFEST_PATH)
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest().upper(), self.api.SHELL_SOURCE_MANIFEST_SHA256)
        manifest = json.loads(raw)
        self.assertEqual(manifest["schema"], "toolkit-trusted-linux-module-shell-build-inputs-v1")
        self.assertEqual(manifest["profile_kind"], "ModuleShell")
        self.assertEqual(manifest["upstream"]["linux_root"], self.api.MODULE_SHELL_UPSTREAM_LINUX_ROOT)
        self.assertEqual(manifest["compiled"]["linux_root"], self.api.MODULE_SHELL_COMPILED_LINUX_ROOT)
        self.assertEqual(self.api.SHELL_BUILD_RESULT_PATH,
                         self.api.SHELL_EVIDENCE_ROOT + "/native/module-shell-build-result.json")

    def test_build_gate_accepts_only_exact_source_bound_operator_artifact(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parents[2]) as temp:
            prepared = self.prepared_build(Path(temp))
            approval = self.validate_prepared(prepared, now_utc=datetime(2026, 10, 24, tzinfo=timezone.utc))
            self.assertEqual(approval["status"], "PREPARED_NOT_RUNTIME_ACCEPTANCE")
            self.assertEqual(approval["profile_id"], "wslc_multi_module")
            self.assertEqual(approval["profile"]["profile_kind"], "ModuleShell")
            self.assertEqual(approval["profile"]["module_shell"], {
                "source_manifest_sha256": approval["source_manifest"]["sha256"],
            })
            self.assertEqual(approval["profile"]["host_runtime_admission"]["host_ram_mode"], "USER_WAIVED")
            self.assertEqual(approval["native_build_receipt"]["path"], self.api.SHELL_NATIVE_RECEIPT_PATH)
            self.assertEqual(approval["artifact"]["guest_path"], self.api.SHELL_GUEST_PATH)
            self.assertEqual(approval["artifact"]["sha256"],
                             hashlib.sha256(prepared["elf_path"].read_bytes()).hexdigest().upper())

    def test_build_gate_refuses_unapproved_receipt_and_elf_path_swap(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parents[2]) as temp:
            prepared = self.prepared_build(Path(temp))
            self.refuse_prepared("MODULE_SHELL_BUILD_RECEIPT_SHA_MISMATCH", prepared,
                                 build_sha="0" * 64, now_utc=datetime(2026, 10, 24, tzinfo=timezone.utc))
            other = prepared["elf_path"].with_name("other-elf")
            other.write_bytes(prepared["elf_path"].read_bytes())
            self.refuse_prepared("MODULE_SHELL_APPROVED_ELF_PATH_MISMATCH", prepared,
                                 elf_path=other, now_utc=datetime(2026, 10, 24, tzinfo=timezone.utc))

    def test_build_gate_reopens_source_bytes_and_rejects_drift(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parents[2]) as temp:
            prepared = self.prepared_build(Path(temp))
            source = prepared["root"] / self.api.CONSUMER_SOURCE_ROOT / "src/main.rs"
            source.write_bytes(b"X" * source.stat().st_size)
            self.refuse_prepared("MODULE_SHELL_SOURCE_CONTENT_MISMATCH", prepared,
                                 now_utc=datetime(2026, 10, 24, tzinfo=timezone.utc))

    def test_build_gate_refuses_wrong_pin_build_flags_and_elf_bytes(self):
        for kind, expected in (("pin", "MODULE_SHELL_BUILD_SOURCE_PIN_MISMATCH"),
                               ("flags", "MODULE_SHELL_CARGO_INVOCATION_REFUSED"),
                               ("shape", "MODULE_SHELL_BUILD_RECEIPT_SHAPE_INVALID"),
                               ("elf", "MODULE_SHELL_ARTIFACT_CONTENT_MISMATCH")):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=Path(__file__).parents[2]) as temp:
                prepared = self.prepared_build(Path(temp))
                receipt = json.loads(prepared["build_path"].read_text())
                if kind == "pin":
                    receipt["source"]["SDK_pin"] = "0" * 40
                    prepared["build_path"].write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
                    prepared["build_sha"] = hashlib.sha256(prepared["build_path"].read_bytes()).hexdigest().upper()
                elif kind == "flags":
                    receipt["cargo"]["args"].append("--features=untrusted")
                    prepared["build_path"].write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
                    prepared["build_sha"] = hashlib.sha256(prepared["build_path"].read_bytes()).hexdigest().upper()
                elif kind == "shape":
                    receipt["memory_override"] = 2 * 1024**3
                    prepared["build_path"].write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
                    prepared["build_sha"] = hashlib.sha256(prepared["build_path"].read_bytes()).hexdigest().upper()
                else:
                    prepared["elf_path"].write_bytes(b"X" + prepared["elf_path"].read_bytes()[1:])
                self.refuse_prepared(expected, prepared,
                                     now_utc=datetime(2026, 10, 24, tzinfo=timezone.utc))

    def test_build_gate_rejects_timeout_source_manifest_mismatch_and_legacy_schema(self):
        cases = (("timeout", "MODULE_SHELL_BUILD_NOT_SUCCESSFUL"),
                 ("source", "MODULE_SHELL_SOURCE_MANIFEST_SHA_MISMATCH"),
                 ("schema", "MODULE_SHELL_BUILD_RECEIPT_SCHEMA_MISMATCH"))
        for kind, expected in cases:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=Path(__file__).parents[2]) as temp:
                prepared = self.prepared_build(Path(temp))
                receipt = json.loads(prepared["build_path"].read_text())
                if kind == "timeout":
                    receipt["timed_out"] = True
                elif kind == "source":
                    receipt["source"]["source_manifest_sha256"] = "F" * 64
                else:
                    receipt["schema"] = "toolkit-makepad-dev-app-module-shell-linux-build-receipt-v1"
                prepared["build_path"].write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
                prepared["build_sha"] = hashlib.sha256(prepared["build_path"].read_bytes()).hexdigest().upper()
                self.refuse_prepared(expected, prepared,
                                     now_utc=datetime(2026, 10, 24, tzinfo=timezone.utc))

    def test_bootstrap_and_upload_keep_single_app_default_and_fixed_multi_profile(self):
        base = Path(__file__).parent
        bootstrap = (base / "bootstrap-runtime.ps1").read_text(encoding="utf-8")
        upload = (base / "upload-artifact.ps1").read_text(encoding="utf-8")
        self.assertIn("[string]$WslcProfile='single_app'", bootstrap)
        self.assertIn("[ValidateSet('text_input71','focus_trace71','module_shell71')]", bootstrap)
        self.assertIn("--memory','1G','--cpus','1'", bootstrap)
        self.assertIn("--memory','2G','--cpus','1'", bootstrap)
        self.assertIn("minimum_free_kib=2621440", bootstrap)
        self.assertIn("MODULE_SHELL_OPERATOR_OPT_IN_REQUIRED", bootstrap)
        self.assertIn("module-shell-host-admission.json", bootstrap)
        self.assertIn("host_ram_mode='USER_WAIVED';status='USER_WAIVED'", bootstrap)
        self.assertIn("available_memory_query_performed=$false", bootstrap)
        self.assertIn("profile.profile_kind -cne 'ModuleShell'", bootstrap)
        self.assertIn("module_shell.source_manifest_sha256", bootstrap)
        self.assertIn("$moduleShellMakepadHome='/tmp/toolkit-module-shell-wslc-home'", bootstrap)
        self.assertIn("('MAKEPAD_HOME='+$moduleShellMakepadHome)", bootstrap)
        self.assertIn("$moduleShellProjectId='module-shell-wslc-v1'", bootstrap)
        self.assertIn("('TOOLKIT_MODULE_PROJECT_ID='+$moduleShellProjectId)", bootstrap)
        self.assertIn("$moduleShellLateProbe='1'", bootstrap)
        self.assertIn("('TOOLKIT_NATIVE_LATE_PROBE='+$moduleShellLateProbe)", bootstrap)
        self.assertIn("home_directory_mode='0700'", bootstrap)
        self.assertIn("public_ai_environment_used=$false", bootstrap)
        module_admission_start = bootstrap.index("if($multiModuleProfile){\n $moduleShellCompilerProcesses=")
        module_admission_end = bootstrap.index("}else{\n & (Join-Path $PSScriptRoot 'preflight.ps1')", module_admission_start)
        module_admission_branch = bootstrap[module_admission_start:module_admission_end]
        self.assertNotIn("preflight.ps1", module_admission_branch)
        self.assertNotIn("FreePhysicalMemory", module_admission_branch)
        self.assertIn("if(-not $multiModuleProfile){\n  if((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory", bootstrap)
        self.assertIn("--memory','1G','--cpus','1'", upload)
        self.assertIn("--memory','2G','--cpus','1'", upload)
        self.assertIn("/opt/proof/ai-workspace-fixture", upload)
        self.assertIn("MODULE_SHELL_TRANSFER_FIXED_FIXTURE_ROLE_REQUIRED", upload)
        self.assertIn("MODULE_SHELL_CONTAINER_ENVIRONMENT_MISMATCH", upload)
        self.assertIn("module-shell-launch-settings.json", upload)
        self.assertIn("host_admission_receipt=$moduleShellHostAdmissionDocument.ref", upload)
        self.assertIn("created_by_transfer=($Artifact -eq 'fixture');mode='0700'", upload)
        self.assertIn("linux-build05/native/module-shell-build.json", bootstrap)
        self.assertIn("linux-build05/native/module-shell-build.json", upload)
        self.assertIn("native_build_receipt=$moduleShellApproval.native_build_receipt", upload)
        self.assertIn("$approvedFixtureSha256='9DFA4EEC8D4FEE6CAEE509D4FF2ACCB5136FED3A1D64D2302F0E35FF623AA4CB'", bootstrap)
        module_branch = bootstrap.split("'module_shell71' {", 1)[1].split("default", 1)[0]
        self.assertNotIn("9DFA4EEC8D4FEE6CAEE509D4FF2ACCB5136FED3A1D64D2302F0E35FF623AA4CB", module_branch)

    def valid_core_receipt(self):
        h = lambda nibble: nibble * 64
        base = "reports/evidence/module-shell/"
        return {
            "schema": self.api.CORE_PROVENANCE_SCHEMA,
            "artifact_id": self.api.SHELL_ARTIFACT_ID,
            "host_path": base + "toolkit-app-module-shell",
            "sha256": h("A"),
            "bytes": 42_000_000,
            "guest_path": self.api.SHELL_GUEST_PATH,
            "profile": {"path": base + "trusted-profile.json", "sha256": h("B")},
            "build_receipt": {"path": base + "build-receipt.json", "sha256": h("C")},
            "native_build_receipt": {"path": base + "native-build-receipt.json", "sha256": h("D")},
            "source_manifest": {"path": base + "source-manifest.json", "sha256": h("E")},
            "producer": {"path": self.api.EXISTING_PRODUCER_PATH, "sha256": h("F")},
        }

    def test_default_keeps_existing_single_app_limits(self):
        profile = self.api.select_profile()
        self.assertEqual(profile["profile_id"], "wslc_single_app")
        self.assertEqual(profile["container"]["memory_bytes"], 1024**3)
        self.assertEqual(profile["container"]["cpus"], 1)
        self.assertEqual(profile["host_runtime_admission"]["minimum_free_bytes"], 2 * 1024**3)
        self.assertEqual(profile["host_runtime_admission"]["nested_increment_bytes"], 0)
        self.assertFalse(profile["explicit_opt_in"])

    def test_multi_module_requires_explicit_opt_in_and_is_exactly_bounded(self):
        self.refused("WSLC_MULTI_MODULE_OPT_IN_REQUIRED", self.api.select_profile,
                     "wslc_multi_module")
        profile = self.api.select_profile("wslc_multi_module", explicit_opt_in=True)
        self.assertEqual(profile["module_instances"], 2)
        self.assertEqual(profile["container"], {
            "memory_bytes": 2 * 1024**3,
            "cpus": 1,
            "fixed_limit_args": ["--memory", "2G", "--cpus", "1"],
        })
        self.assertEqual(profile["host_runtime_admission"], {
            "minimum_free_bytes": 5 * 1024**3 // 2,
            "scope": "one_outer_runtime_admission",
            "nested_increment_bytes": 0,
            "host_ram_mode": "USER_WAIVED",
        })
        self.assertTrue(profile["explicit_opt_in"])
        self.assertEqual(profile["source_commit"], "71c9ddcbb9c01dd208f99621fdd71024a5d35c65")
        self.assertEqual(self.api.SHELL_GUEST_PATH, "/opt/proof/ai-workspace-fixture")
        self.assertEqual(self.api.validate_profile(profile), profile)

    def test_profile_selector_has_no_resource_or_command_override(self):
        self.refused("WSLC_PROFILE_UNKNOWN", self.api.select_profile, "custom")
        self.refused("WSLC_PROFILE_OPT_IN_TYPE_INVALID", self.api.select_profile,
                     "wslc_multi_module", explicit_opt_in=1)
        self.refused("WSLC_SINGLE_PROFILE_OPT_IN_MISMATCH", self.api.select_profile,
                     "wslc_single_app", explicit_opt_in=True)

    def test_profile_validation_rejects_limits_pin_and_shape_drift(self):
        original = self.api.select_profile("wslc_multi_module", explicit_opt_in=True)
        mutations = (
            ("container.memory_bytes", lambda p: p["container"].__setitem__("memory_bytes", 1024**3)),
            ("container.cpus_bool", lambda p: p["container"].__setitem__("cpus", True)),
            ("host.threshold", lambda p: p["host_runtime_admission"].__setitem__("minimum_free_bytes", 2 * 1024**3)),
            ("nested.increment", lambda p: p["host_runtime_admission"].__setitem__("nested_increment_bytes", 5 * 1024**3 // 2)),
            ("extra.override", lambda p: p.__setitem__("shell", "arbitrary-command")),
            ("opt.in", lambda p: p.__setitem__("explicit_opt_in", False)),
        )
        for name, mutate in mutations:
            candidate = copy.deepcopy(original)
            mutate(candidate)
            with self.subTest(name=name):
                self.refused("WSLC_PROFILE_CONTRACT_MISMATCH", self.api.validate_profile, candidate)

    def test_profile_rejects_schema_and_source_pin_drift(self):
        profile = self.api.select_profile("wslc_multi_module", explicit_opt_in=True)
        for field, value, code in (
            ("schema", "other-profile-v1", "WSLC_PROFILE_SCHEMA_MISMATCH"),
            ("source_commit", "0" * 40, "WSLC_PROFILE_SOURCE_PIN_MISMATCH"),
        ):
            candidate = copy.deepcopy(profile)
            candidate[field] = value
            with self.subTest(field=field):
                self.refused(code, self.api.validate_profile, candidate)

    def test_profile_results_are_independent_copies(self):
        first = self.api.select_profile("wslc_multi_module", explicit_opt_in=True)
        first["container"]["memory_bytes"] = 1
        second = self.api.select_profile("wslc_multi_module", explicit_opt_in=True)
        self.assertEqual(second["container"]["memory_bytes"], 2 * 1024**3)

    def test_core_provenance_shape_matches_existing_versioned_contract(self):
        self.assertIsNone(self.api.validate_core_provenance_shape(self.valid_core_receipt()))

    def test_core_receipt_requires_exact_fields_and_fixed_artifact_identity(self):
        for name, mutate, code in (
            ("extra", lambda r: r.__setitem__("shell", True), "WSLC_PROVENANCE_SHAPE_INVALID"),
            ("missing", lambda r: r.pop("build_receipt"), "WSLC_PROVENANCE_SHAPE_INVALID"),
            ("schema", lambda r: r.__setitem__("schema", "new-validator-v1"), "WSLC_PROVENANCE_SCHEMA_MISMATCH"),
            ("artifact", lambda r: r.__setitem__("artifact_id", "other"), "WSLC_SHELL_ARTIFACT_ID_MISMATCH"),
            ("guest", lambda r: r.__setitem__("guest_path", "/tmp/other"), "WSLC_SHELL_GUEST_PATH_MISMATCH"),
        ):
            receipt = self.valid_core_receipt()
            mutate(receipt)
            with self.subTest(name=name):
                self.refused(code, self.api.validate_core_provenance_shape, receipt)

    def test_core_receipt_rejects_invalid_artifact_digest_size_and_path(self):
        cases = (
            ("lowercase-sha", lambda r: r.__setitem__("sha256", "a" * 64), "WSLC_HOST_ARTIFACT_SHA256_INVALID"),
            ("bool-size", lambda r: r.__setitem__("bytes", True), "WSLC_HOST_ARTIFACT_SIZE_INVALID"),
            ("zero-size", lambda r: r.__setitem__("bytes", 0), "WSLC_HOST_ARTIFACT_SIZE_INVALID"),
            ("path-escape", lambda r: r.__setitem__("host_path", "reports/evidence/../outside"), "WSLC_HOST_ARTIFACT_PATH_REFUSED"),
            ("path-absolute", lambda r: r.__setitem__("host_path", "C:/outside/elf"), "WSLC_HOST_ARTIFACT_PATH_REFUSED"),
        )
        for name, mutate, code in cases:
            receipt = self.valid_core_receipt()
            mutate(receipt)
            with self.subTest(name=name):
                self.refused(code, self.api.validate_core_provenance_shape, receipt)

    def test_core_receipt_rejects_unpinned_or_reused_references(self):
        for name, mutate, code in (
            ("path-escape", lambda r: r["source_manifest"].__setitem__("path", "reports/evidence/../../source.json"),
             "WSLC_PROVENANCE_REFERENCE_PATH_REFUSED"),
            ("lowercase-ref-sha", lambda r: r["profile"].__setitem__("sha256", "a" * 64),
             "WSLC_PROVENANCE_REFERENCE_SHA256_INVALID"),
            ("reused-ref", lambda r: r.__setitem__("source_manifest", dict(r["build_receipt"])),
             "WSLC_PROVENANCE_REFERENCE_REUSED"),
            ("wrong-producer", lambda r: r["producer"].__setitem__("path", "experiments/ai-execution-workspace/bootstrap-runtime.ps1"),
             "WSLC_PROVENANCE_PRODUCER_MISMATCH"),
        ):
            receipt = self.valid_core_receipt()
            mutate(receipt)
            with self.subTest(name=name):
                self.refused(code, self.api.validate_core_provenance_shape, receipt)

    def test_receipt_shape_does_not_claim_byte_or_core_acceptance(self):
        # The API is deliberately a structural gate only; actual bytes and joins
        # remain the responsibility of the existing Core v2 validator.
        self.assertIsNone(self.api.validate_core_provenance_shape(self.valid_core_receipt()))


if __name__ == "__main__":
    unittest.main()

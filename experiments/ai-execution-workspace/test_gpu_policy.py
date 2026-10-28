"""Bounded contract tests for the trusted GPU policy sidecar."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import gpu_policy


def _runtime_line(renderer: str, *, vendor: str = "Mesa/X.org") -> str:
    return (
        f'Makepad GL: vendor="{vendor}" renderer="{renderer}" '
        'version="Mesa 24.2.0"'
    )


class GpuPolicyTests(unittest.TestCase):
    def assert_policy_failure(self, code: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(gpu_policy.GpuPolicyFailure) as raised:
            callable_(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)

    def test_fixed_profiles_resolve_to_trusted_values(self) -> None:
        expected = {
            "cad_3d": ("nvidia", "preferred", "ui_smoke"),
            "heavy_viewer": ("nvidia", "preferred", "ui_smoke"),
            "ui_smoke": ("auto", "auto", None),
            "gpu_nvidia_test": ("nvidia", "required", None),
        }
        for name, (vendor, mode, fallback) in expected.items():
            with self.subTest(profile=name):
                profile = gpu_policy.resolve_profile(name)
                self.assertEqual(profile["profile"], name)
                self.assertEqual(profile["vendor"], vendor)
                self.assertEqual(profile["mode"], mode)
                self.assertEqual(profile["fallback_profile"], fallback)
                self.assertRegex(profile["config_sha256"], r"^[0-9a-f]{64}$")

    def test_unknown_profile_has_typed_failure(self) -> None:
        self.assert_policy_failure(
            "GPU_PROFILE_UNKNOWN", gpu_policy.resolve_profile, "unknownname"
        )

    def test_auto_environment_removes_both_overrides_and_preserves_other_values(self) -> None:
        inherited = {
            "GALLIUM_DRIVER": "llvmpipe",
            "MESA_D3D12_DEFAULT_ADAPTER_NAME": "Injected Adapter",
            "DISPLAY": ":77",
            "PATH": "/usr/bin:/bin",
        }
        original = copy.deepcopy(inherited)

        result = gpu_policy.linux_environment(
            gpu_policy.resolve_profile("ui_smoke"), inherited
        )

        self.assertEqual(result, {"DISPLAY": ":77", "PATH": "/usr/bin:/bin"})
        self.assertEqual(inherited, original)

    def test_nvidia_environment_normalizes_inherited_overrides(self) -> None:
        inherited = {
            "GALLIUM_DRIVER": "softpipe",
            "MESA_D3D12_DEFAULT_ADAPTER_NAME": "AMD Radeon",
            "HOME": "/tmp/toolkit-test-home",
        }
        original = copy.deepcopy(inherited)

        result = gpu_policy.linux_environment(
            gpu_policy.resolve_profile("cad_3d"), inherited
        )

        self.assertEqual(
            result,
            {
                "HOME": "/tmp/toolkit-test-home",
                "GALLIUM_DRIVER": "d3d12",
                "MESA_D3D12_DEFAULT_ADAPTER_NAME": "NVIDIA",
            },
        )
        self.assertEqual(inherited, original)

    def test_gnu_env_arguments_unset_both_overrides_for_auto(self) -> None:
        self.assertEqual(
            gpu_policy.linux_env_arguments(gpu_policy.resolve_profile("ui_smoke")),
            [
                "env",
                "-u",
                "GALLIUM_DRIVER",
                "-u",
                "MESA_D3D12_DEFAULT_ADAPTER_NAME",
            ],
        )

    def test_gnu_env_arguments_set_normalized_nvidia_values(self) -> None:
        self.assertEqual(
            gpu_policy.linux_env_arguments(gpu_policy.resolve_profile("cad_3d")),
            [
                "env",
                "-u",
                "GALLIUM_DRIVER",
                "-u",
                "MESA_D3D12_DEFAULT_ADAPTER_NAME",
                "GALLIUM_DRIVER=d3d12",
                "MESA_D3D12_DEFAULT_ADAPTER_NAME=NVIDIA",
            ],
        )

    def test_exact_makepad_runtime_line_verifies_nvidia(self) -> None:
        line = _runtime_line("D3D12 (NVIDIA GeForce RTX 4060)")
        for name in ("cad_3d", "gpu_nvidia_test"):
            with self.subTest(profile=name):
                result = gpu_policy.observe(gpu_policy.resolve_profile(name), line)
                self.assertEqual(result["status"], "NVIDIA_VERIFIED")
                self.assertTrue(result["gpu_match"])
                self.assertTrue(result["hardware_verified"])
                self.assertEqual(result["gpu_actual"], "NVIDIA GeForce RTX 4060")
                self.assertEqual(result["verification_source"], "makepad_runtime_log")

    def test_preferred_profile_uses_identified_amd_or_intel_fallback(self) -> None:
        cases = (
            "D3D12 (AMD Radeon RX 7900)",
            "D3D12 (Intel Arc A770)",
            "D3D12 (Intel(R) UHD Graphics)",
        )
        profile = gpu_policy.resolve_profile("heavy_viewer")
        for renderer in cases:
            with self.subTest(renderer=renderer):
                result = gpu_policy.observe(profile, _runtime_line(renderer))
                self.assertEqual(result["status"], "FALLBACK_USED")
                self.assertFalse(result["gpu_match"])
                self.assertTrue(result["hardware_verified"])
                self.assertEqual(result["fallback_profile"], "ui_smoke")

    def test_preferred_profile_rejects_unregistered_fallback(self) -> None:
        profile = gpu_policy.resolve_profile("cad_3d")
        profile["fallback_profile"] = "unregistered_profile"
        self.assert_policy_failure(
            "GPU_FALLBACK_NOT_ALLOWED",
            gpu_policy.observe,
            profile,
            _runtime_line("D3D12 (AMD Radeon RX 7900)"),
        )

    def test_required_profile_rejects_identified_non_nvidia_hardware(self) -> None:
        profile = gpu_policy.resolve_profile("gpu_nvidia_test")
        for renderer in ("D3D12 (AMD Radeon RX 7900)", "D3D12 (Intel Arc A770)"):
            with self.subTest(renderer=renderer):
                self.assert_policy_failure(
                    "GPU_REQUIRED_MISMATCH",
                    gpu_policy.observe,
                    profile,
                    _runtime_line(renderer),
                )

    def test_policy_failure_carries_renderer_evidence(self) -> None:
        profile = gpu_policy.resolve_profile("gpu_nvidia_test")
        with self.assertRaises(gpu_policy.GpuPolicyFailure) as raised:
            gpu_policy.observe(profile, _runtime_line("D3D12 (AMD Radeon RX 7900)"))

        self.assertTrue(issubclass(gpu_policy.GpuPolicyFailure, gpu_policy.PortFailure))
        self.assertEqual(raised.exception.code, "GPU_REQUIRED_MISMATCH")
        self.assertEqual(
            raised.exception.evidence["gpu_actual"], "AMD Radeon RX 7900"
        )
        self.assertEqual(
            raised.exception.evidence["verification_source"], "makepad_runtime_log"
        )

    def test_software_renderers_fail_required_and_preferred_profiles(self) -> None:
        profiles = (
            gpu_policy.resolve_profile("gpu_nvidia_test"),
            gpu_policy.resolve_profile("cad_3d"),
        )
        renderers = (
            "D3D12 (llvmpipe (LLVM 18.1.8, 256 bits))",
            "D3D12 (softpipe (LLVM 18.1.8, 256 bits))",
        )
        for profile in profiles:
            for renderer in renderers:
                with self.subTest(profile=profile["profile"], renderer=renderer):
                    self.assert_policy_failure(
                        "GPU_SOFTWARE_RENDERER",
                        gpu_policy.observe,
                        profile,
                        _runtime_line(renderer),
                    )

    def test_missing_makepad_observation_fails(self) -> None:
        self.assert_policy_failure(
            "GPU_OBSERVATION_MISSING",
            gpu_policy.observe,
            gpu_policy.resolve_profile("cad_3d"),
            "",
        )

    def test_glxinfo_only_and_environment_only_are_not_observations(self) -> None:
        inputs = (
            "OpenGL vendor string: NVIDIA Corporation\n"
            "OpenGL renderer string: D3D12 (NVIDIA GeForce RTX 4060)\n",
            "GALLIUM_DRIVER=d3d12\n"
            "MESA_D3D12_DEFAULT_ADAPTER_NAME=NVIDIA\n",
        )
        profile = gpu_policy.resolve_profile("cad_3d")
        for source_text in inputs:
            with self.subTest(source_text=source_text.splitlines()[0]):
                self.assert_policy_failure(
                    "GPU_OBSERVATION_MISSING", gpu_policy.observe, profile, source_text
                )

    def test_conflicting_makepad_renderer_observations_are_ambiguous(self) -> None:
        log = "\n".join(
            (
                _runtime_line("D3D12 (NVIDIA GeForce RTX 4060)"),
                _runtime_line("D3D12 (AMD Radeon RX 7900)"),
            )
        )
        self.assert_policy_failure(
            "GPU_OBSERVATION_AMBIGUOUS",
            gpu_policy.observe,
            gpu_policy.resolve_profile("cad_3d"),
            log,
        )

    def test_vendor_claim_and_nvidia_substrings_do_not_verify_hardware(self) -> None:
        cases = (
            (
                "D3D12 (Generic Adapter 9000)",
                "NVIDIA GeForce RTX 4090",
            ),
            (
                "D3D12 (NotNVIDIA GeForce RTX 4090 compatible)",
                "NVIDIA Corporation",
            ),
        )
        profile = gpu_policy.resolve_profile("cad_3d")
        for renderer, vendor in cases:
            with self.subTest(renderer=renderer, vendor=vendor):
                self.assert_policy_failure(
                    "GPU_FALLBACK_NOT_ALLOWED",
                    gpu_policy.observe,
                    profile,
                    _runtime_line(renderer, vendor=vendor),
                )

    def test_unknown_hardware_is_not_accepted_as_preferred_fallback(self) -> None:
        self.assert_policy_failure(
            "GPU_FALLBACK_NOT_ALLOWED",
            gpu_policy.observe,
            gpu_policy.resolve_profile("cad_3d"),
            _runtime_line("D3D12 (Mystery Adapter 9000)"),
        )

    def assert_invalid_config(self, raw: bytes) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "gpu-profiles.json"
            config_path.write_bytes(raw)
            with patch.object(gpu_policy, "CONFIG", config_path):
                self.assert_policy_failure(
                    "GPU_POLICY_INVALID", gpu_policy.load_profiles
                )

    def test_malformed_profile_config_is_rejected(self) -> None:
        self.assert_invalid_config(b'{"gpu_profiles":')

    def test_profile_config_rejects_caller_supplied_environment_fields(self) -> None:
        profiles = copy.deepcopy(gpu_policy.load_profiles()["profiles"])
        profiles["cad_3d"]["environment"] = {"GALLIUM_DRIVER": "llvmpipe"}
        self.assert_invalid_config(
            json.dumps({"gpu_profiles": profiles}).encode("utf-8")
        )

    def test_cli_resolve_returns_json(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = gpu_policy.main(["resolve", "--profile", "cad_3d"])

        self.assertEqual(exit_code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["profile"], "cad_3d")
        self.assertEqual(result["mode"], "preferred")
        self.assertEqual(
            result["env_arguments"][-2:],
            [
                "GALLIUM_DRIVER=d3d12",
                "MESA_D3D12_DEFAULT_ADAPTER_NAME=NVIDIA",
            ],
        )

    def test_cli_observation_error_returns_typed_json(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = gpu_policy.main(["observe", "--profile", "cad_3d"])

        self.assertEqual(exit_code, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["failure_code"], "GPU_OBSERVATION_MISSING")
        self.assertIn("message", result)
        self.assertIsNone(result["gpu_observation"])

    def test_cli_hashes_exact_runtime_log_bytes(self) -> None:
        raw = (
            _runtime_line("D3D12 (NVIDIA GeForce RTX 4060)") + "\r\n"
        ).encode("utf-8") + b"\xff"
        with tempfile.TemporaryDirectory() as directory:
            runtime_log = Path(directory) / "runtime.log"
            runtime_log.write_bytes(raw)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = gpu_policy.main(
                    [
                        "observe",
                        "--profile",
                        "gpu_nvidia_test",
                        "--runtime-log",
                        str(runtime_log),
                    ]
                )

        self.assertEqual(exit_code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "NVIDIA_VERIFIED")
        self.assertEqual(result["runtime_log_sha256"], hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()

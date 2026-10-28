"""Trusted operator GPU policy, reused by the existing runtime launcher.

No launch service, caller environment, shell or writable policy path is exposed.
Only an operator selects one fixed profile when provisioning a fresh context.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Mapping
from manager import PortFailure

CONFIG = Path(__file__).with_name("gpu-profiles.json")
PROFILE_NAMES = ("cad_3d", "heavy_viewer", "ui_smoke", "gpu_nvidia_test")
OVERRIDES = ("GALLIUM_DRIVER", "MESA_D3D12_DEFAULT_ADAPTER_NAME")
_GL = re.compile(r'Makepad GL: vendor="[^"\r\n]*" renderer="([^"\r\n]+)" version="([^"\r\n]+)"')


class GpuPolicyFailure(PortFailure):
    fatal = True

    def __init__(self, code: str, message: str, *, partial_identity=None, evidence=None):
        self.code = code
        self.classification = code.lower()
        self.evidence = evidence
        super().__init__(message, partial_identity=partial_identity)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GpuPolicyFailure("GPU_POLICY_INVALID", "duplicate configuration key")
        result[key] = value
    return result


def load_profiles() -> dict:
    try:
        raw = CONFIG.read_bytes()
        if len(raw) > 8192:
            raise ValueError("oversized policy")
        config = json.loads(raw, object_pairs_hook=_unique)
        if set(config) != {"gpu_profiles"}:
            raise ValueError("unknown configuration field")
        profiles = config["gpu_profiles"]
        if not isinstance(profiles, dict) or set(profiles) != set(PROFILE_NAMES):
            raise ValueError("only the four trusted profiles are accepted")
        for name, profile in profiles.items():
            if not isinstance(profile, dict) or set(profile) - {"vendor", "mode", "fallback_profile"}:
                raise ValueError("arbitrary environment/policy fields refused")
            vendor, mode = profile.get("vendor"), profile.get("mode")
            expected = ("auto", "auto") if name == "ui_smoke" else ("nvidia", "required" if name == "gpu_nvidia_test" else "preferred")
            if (vendor, mode) != expected:
                raise ValueError("trusted profile semantics changed")
            fallback = profile.get("fallback_profile")
            if fallback is not None and (mode != "preferred" or fallback != "ui_smoke"):
                raise ValueError("only an explicitly registered auto fallback is allowed")
    except GpuPolicyFailure:
        raise
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        raise GpuPolicyFailure("GPU_POLICY_INVALID", str(exc)) from exc
    return {"profiles": profiles, "sha256": hashlib.sha256(raw).hexdigest()}


def resolve_profile(name: str) -> dict:
    config = load_profiles()
    if name not in config["profiles"]:
        raise GpuPolicyFailure("GPU_PROFILE_UNKNOWN", "unknown trusted profile")
    profile = config["profiles"][name]
    return {"profile": name, "vendor": profile["vendor"], "mode": profile["mode"],
            "fallback_profile": profile.get("fallback_profile"), "config_sha256": config["sha256"]}


def linux_environment(profile: Mapping, inherited: Mapping[str, str]) -> dict[str, str]:
    """Pure environment transformation; never mutate the parent's environment."""
    result = {key: value for key, value in inherited.items() if key not in OVERRIDES}
    if profile["vendor"] == "nvidia":
        result.update(GALLIUM_DRIVER="d3d12", MESA_D3D12_DEFAULT_ADAPTER_NAME="NVIDIA")
    return result


def linux_env_arguments(profile: Mapping) -> list[str]:
    # GNU env unsets inherited container overrides even for auto mode.
    args = ["env", "-u", OVERRIDES[0], "-u", OVERRIDES[1]]
    env = linux_environment(profile, {})
    return args + [f"{key}={value}" for key, value in env.items()]


def observe(profile: Mapping, runtime_log: str) -> dict:
    matches = set(_GL.findall(runtime_log))
    if not matches:
        raise GpuPolicyFailure("GPU_OBSERVATION_MISSING", "no Makepad runtime renderer observation")
    if len(matches) != 1:
        raise GpuPolicyFailure("GPU_OBSERVATION_AMBIGUOUS", "conflicting runtime renderer observations")
    full, version = matches.pop()
    software = any(value in (full + " " + version).casefold() for value in ("llvmpipe", "softpipe", "swrast", "software", "basic render"))
    d3d12 = re.fullmatch(r"D3D12 \((.+)\)", full)
    actual = d3d12[1] if d3d12 else full
    # Require an identifiable hardware name, not only a claimed vendor token.
    nvidia = bool(d3d12 and re.match(r"NVIDIA\s+(?:GeForce|RTX|Quadro|Tesla|A\d|L\d|H\d)", actual, re.I)) and not software
    hardware = bool(d3d12 and re.match(r"(?:NVIDIA\s+(?:GeForce|RTX|Quadro|Tesla|A\d|L\d|H\d)|AMD\s+Radeon|Intel(?:\(R\))?\s+)", actual, re.I)) and not software
    mode = profile["mode"]
    failure_evidence = {"gpu_profile": profile["profile"], "gpu_policy": mode,
                        "gpu_requested": "NVIDIA" if profile["vendor"] == "nvidia" else "AUTO",
                        "gpu_actual": actual, "renderer": "D3D12" if d3d12 else full,
                        "renderer_full": full, "gpu_match": False,
                        "verification_source": "makepad_runtime_log"}
    if software and mode != "auto":
        raise GpuPolicyFailure("GPU_SOFTWARE_RENDERER", "software renderer cannot satisfy NVIDIA policy", evidence=failure_evidence)
    if mode == "required" and not nvidia:
        raise GpuPolicyFailure("GPU_REQUIRED_MISMATCH", "actual adapter is not verified NVIDIA hardware", evidence=failure_evidence)
    if mode == "preferred" and not nvidia:
        if profile.get("fallback_profile") != "ui_smoke" or not hardware:
            raise GpuPolicyFailure("GPU_FALLBACK_NOT_ALLOWED", "no registered identifiable hardware fallback", evidence=failure_evidence)
        status = "FALLBACK_USED"
    elif mode == "auto":
        status = "AUTO_OBSERVED" if hardware else "AUTO_UNVERIFIED_HARDWARE"
    else:
        status = "NVIDIA_VERIFIED"
    return {"gpu_profile": profile["profile"], "gpu_policy": mode,
            "gpu_requested": "NVIDIA" if profile["vendor"] == "nvidia" else "AUTO",
            "gpu_actual": actual, "renderer": "D3D12" if d3d12 else full,
            "renderer_full": full, "gpu_match": nvidia if mode != "auto" else None,
            "hardware_verified": hardware, "verification_source": "makepad_runtime_log",
            "status": status, "fallback_profile": profile.get("fallback_profile") if status == "FALLBACK_USED" else None,
            "config_sha256": profile["config_sha256"]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fixed trusted profile resolution and runtime observation")
    parser.add_argument("operation", choices=("resolve", "observe"))
    parser.add_argument("--profile", required=True, choices=PROFILE_NAMES)
    parser.add_argument("--runtime-log", type=Path)
    args = parser.parse_args(argv)
    try:
        profile = resolve_profile(args.profile)
        if args.operation == "resolve":
            result = {**profile, "env_arguments": linux_env_arguments(profile)}
        else:
            if args.runtime_log is None:
                raise GpuPolicyFailure("GPU_OBSERVATION_MISSING", "runtime log missing")
            try:
                if args.runtime_log.stat().st_size > 4 * 1024 * 1024:
                    raise GpuPolicyFailure("GPU_OBSERVATION_INVALID", "runtime log too large")
                raw = args.runtime_log.read_bytes()
                if len(raw) > 4 * 1024 * 1024:
                    raise GpuPolicyFailure("GPU_OBSERVATION_INVALID", "runtime log grew beyond the bound")
                log = raw.decode("utf-8", errors="replace")
            except OSError as exc:
                raise GpuPolicyFailure("GPU_OBSERVATION_MISSING", "runtime log unavailable") from exc
            result = observe(profile, log)
            result.update(runtime_log_path=str(args.runtime_log.resolve()), runtime_log_sha256=hashlib.sha256(raw).hexdigest())
        print(json.dumps(result))
        return 0
    except GpuPolicyFailure as exc:
        print(json.dumps({"failure_code": exc.code, "message": str(exc), "gpu_observation": exc.evidence}))
        return 2


if __name__ == "__main__":
    sys.exit(main())

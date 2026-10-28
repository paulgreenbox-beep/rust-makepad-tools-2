//! Pure WSLC identity guards. No process, filesystem, HTTP, GPU or GUI observation.
//! The platform owner supplies native observations; these checks do not prove
//! their provenance, focus, or normal exit. Guest and RAIL PIDs are independent.
use super::{PINNED_SOURCE, SessionBinding, protocol::{RemoteError, Result}};
use serde::{Deserialize, Serialize};

pub const WSLC_FOCUS_MEMORY_MAX: u64 = 1_073_741_824;
pub const WSLC_MODULE_SHELL_MEMORY_MAX: u64 = 2_147_483_648;
pub const WSLC_MODULE_SHELL_EXECUTABLE: &str = "/opt/proof/ai-workspace-fixture";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedWslcIdentity {
    pub container_id: String,
    pub image_id: String,
    pub executable: String,
    pub executable_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedWslcIdentity {
    pub schema: String,
    pub container_id: String,
    pub image_id: String,
    pub pid_namespace: String,
    pub pid: u32,
    pub process_start_ticks: String,
    pub executable: String,
    pub executable_sha256: String,
    pub listener_host: String,
    pub listener_port: u16,
    pub listener_inode: String,
    pub window_id: u64,
    pub rail_hwnd: u64,
    pub rail_pid: u32,
    pub rail_process_birth: String,
    pub rail_visible: bool,
    pub memory_max: u64,
    pub cpu_max: String,
}

fn require(ok: bool, code: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(RemoteError::refused(code)) }
}
fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn image_id(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(hex64)
}
fn positive_decimal(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && matches!(s.as_bytes()[0], b'1'..=b'9')
        && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u64>().is_ok()
}
fn pid_namespace(s: &str) -> bool {
    s.strip_prefix("pid:[").and_then(|v| v.strip_suffix(']')).is_some_and(positive_decimal)
}
fn guest_executable(s: &str) -> bool {
    // POSIX lexical checks, deliberately not host-dependent Path::components.
    s.starts_with('/') && s.len() > 1 && !s.contains('\\') && !s.chars().any(char::is_control)
        && s.split('/').skip(1).all(|part| !part.is_empty() && part != "." && part != "..")
}

impl ObservedWslcIdentity {
    pub fn verify_initial(&self, expected: &ExpectedWslcIdentity) -> Result<()> {
        self.verify_initial_with_memory_max(expected, WSLC_FOCUS_MEMORY_MAX)
    }

    pub fn verify_initial_with_memory_max(
        &self,
        expected: &ExpectedWslcIdentity,
        expected_memory_max: u64,
    ) -> Result<()> {
        require(matches!(expected_memory_max, WSLC_FOCUS_MEMORY_MAX | WSLC_MODULE_SHELL_MEMORY_MAX),
            "WSLC_MEMORY_PROFILE_INVALID")?;
        require(self.schema == "toolkit-makepad-remote-wslc-identity-v1", "WSLC_IDENTITY_SCHEMA_INVALID")?;
        require(hex64(&expected.container_id) && hex64(&self.container_id), "WSLC_CONTAINER_ID_INVALID")?;
        require(image_id(&expected.image_id) && image_id(&self.image_id), "WSLC_IMAGE_ID_INVALID")?;
        require(guest_executable(&expected.executable) && guest_executable(&self.executable), "WSLC_EXECUTABLE_INVALID")?;
        require(hex64(&expected.executable_sha256) && hex64(&self.executable_sha256), "WSLC_EXECUTABLE_SHA256_INVALID")?;
        require(self.container_id == expected.container_id, "WSLC_CONTAINER_ID_MISMATCH")?;
        require(self.image_id == expected.image_id, "WSLC_IMAGE_ID_MISMATCH")?;
        require(self.executable == expected.executable, "WSLC_EXECUTABLE_MISMATCH")?;
        require(self.executable_sha256.eq_ignore_ascii_case(&expected.executable_sha256), "WSLC_EXECUTABLE_SHA256_MISMATCH")?;
        require(pid_namespace(&self.pid_namespace), "WSLC_PID_NAMESPACE_INVALID")?;
        require(self.pid != 0, "WSLC_PID_INVALID")?;
        require(positive_decimal(&self.process_start_ticks), "WSLC_PROCESS_START_TICKS_INVALID")?;
        require(self.listener_host == "127.0.0.1" && self.listener_port != 0, "WSLC_LISTENER_ENDPOINT_INVALID")?;
        require(positive_decimal(&self.listener_inode), "WSLC_LISTENER_INODE_INVALID")?;
        require(self.rail_hwnd != 0 && self.rail_pid != 0, "WSLC_RAIL_IDENTITY_INVALID")?;
        require(positive_decimal(&self.rail_process_birth), "WSLC_RAIL_PROCESS_BIRTH_INVALID")?;
        require(!self.rail_visible, "WSLC_RAIL_NOT_HIDDEN")?;
        require(self.memory_max == expected_memory_max, "WSLC_MEMORY_LIMIT_MISMATCH")?;
        require(self.cpu_max == "100000 100000", "WSLC_CPU_LIMIT_MISMATCH")
    }

    pub fn verify_bound(
        &self,
        expected: &ExpectedWslcIdentity,
        binding: &SessionBinding,
        frozen: &ObservedWslcIdentity,
    ) -> Result<()> {
        self.verify_bound_with_memory_max(expected, binding, frozen, WSLC_FOCUS_MEMORY_MAX)
    }

    pub fn verify_bound_with_memory_max(
        &self,
        expected: &ExpectedWslcIdentity,
        binding: &SessionBinding,
        frozen: &ObservedWslcIdentity,
        expected_memory_max: u64,
    ) -> Result<()> {
        self.verify_initial_with_memory_max(expected, expected_memory_max)?;
        require(binding.platform == "linux-wslc-owned-container", "WSLC_BINDING_PLATFORM_MISMATCH")?;
        require(binding.source_commit == PINNED_SOURCE, "WSLC_BINDING_SOURCE_MISMATCH")?;
        require(self.pid == binding.pid && self.process_start_ticks == binding.process_birth
            && self.executable == binding.executable
            && self.executable_sha256.eq_ignore_ascii_case(&binding.executable_sha256)
            && self.window_id == binding.window_id, "WSLC_BINDING_IDENTITY_MISMATCH")?;
        // Exact frozen representation, including SHA case. Only comparisons to
        // approved/binding SHA pins above are case-insensitive; no silent rebase.
        require(self == frozen, "WSLC_IDENTITY_DRIFT")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture() -> (ExpectedWslcIdentity, ObservedWslcIdentity, SessionBinding) {
        let expected = ExpectedWslcIdentity {
            container_id: "a".repeat(64), image_id: format!("sha256:{}", "b".repeat(64)),
            executable: "/opt/proof/ai-workspace-fixture".into(), executable_sha256: "AB".repeat(32),
        };
        let observed = ObservedWslcIdentity {
            schema: "toolkit-makepad-remote-wslc-identity-v1".into(),
            container_id: expected.container_id.clone(), image_id: expected.image_id.clone(),
            pid_namespace: "pid:[4026532298]".into(), pid: 225, process_start_ticks: "2748".into(),
            executable: expected.executable.clone(), executable_sha256: expected.executable_sha256.to_lowercase(),
            listener_host: "127.0.0.1".into(), listener_port: 38487, listener_inode: "4664".into(),
            window_id: 0, rail_hwnd: 329516, rail_pid: 19752, rail_process_birth: "134050000000000000".into(),
            rail_visible: false, memory_max: 1_073_741_824, cpu_max: "100000 100000".into(),
        };
        let binding = SessionBinding {
            session_id: "synthetic-owned-session".into(), owner: "synthetic-owner".into(), generation: 1,
            pid: observed.pid, process_birth: observed.process_start_ticks.clone(),
            executable: observed.executable.clone(), executable_sha256: expected.executable_sha256.clone(),
            source_commit: PINNED_SOURCE.into(), window_id: observed.window_id, platform: "linux-wslc-owned-container".into(),
        };
        (expected, observed, binding)
    }
    fn changed(observed: &ObservedWslcIdentity, field: &str, value: Value) -> ObservedWslcIdentity {
        let mut raw = serde_json::to_value(observed).unwrap(); raw[field] = value;
        serde_json::from_value(raw).unwrap()
    }
    fn refused(result: Result<()>) -> String {
        let error = result.unwrap_err();
        assert!(error.code.starts_with("WSLC_")); assert_eq!(error.outcome, "NOT_DISPATCHED"); assert!(!error.retry_safe);
        error.code
    }

    #[test]
    fn valid_initial_and_bound_keep_guest_and_rail_namespaces_distinct() {
        let (expected, observed, binding) = fixture();
        assert_ne!(observed.pid, observed.rail_pid);
        observed.verify_initial(&expected).unwrap();
        observed.verify_bound(&expected, &binding, &observed).unwrap();
        // Coincident numeric PIDs across namespaces are not forbidden either.
        let mut coincident = observed.clone(); coincident.rail_pid = coincident.pid;
        coincident.verify_bound(&expected, &binding, &coincident).unwrap();
    }

    #[test]
    fn module_shell_memory_limit_is_separate_and_exact() {
        let (expected, focus, binding) = fixture();
        assert_eq!(refused(focus.verify_initial_with_memory_max(
            &expected, WSLC_MODULE_SHELL_MEMORY_MAX)), "WSLC_MEMORY_LIMIT_MISMATCH");
        let module = changed(&focus, "memory_max", json!(WSLC_MODULE_SHELL_MEMORY_MAX));
        module.verify_initial_with_memory_max(&expected, WSLC_MODULE_SHELL_MEMORY_MAX).unwrap();
        module.verify_bound_with_memory_max(
            &expected, &binding, &module, WSLC_MODULE_SHELL_MEMORY_MAX).unwrap();
        assert_eq!(refused(module.verify_initial(&expected)), "WSLC_MEMORY_LIMIT_MISMATCH");
        assert_eq!(refused(module.verify_initial_with_memory_max(&expected, 3 * WSLC_FOCUS_MEMORY_MAX)),
            "WSLC_MEMORY_PROFILE_INVALID");
    }

    #[test]
    fn observed_serde_rejects_unknown_missing_duplicate_and_malformed_numeric_fields() {
        let (_, observed, _) = fixture(); let raw = serde_json::to_value(&observed).unwrap();
        assert_eq!(raw.as_object().unwrap().len(), 18);
        let mut extra = raw.clone(); extra["private_override"] = json!(true);
        assert!(serde_json::from_value::<ObservedWslcIdentity>(extra).is_err());
        for field in raw.as_object().unwrap().keys() {
            let mut missing = raw.clone(); missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<ObservedWslcIdentity>(missing).is_err(), "missing {field}");
        }
        let serialized = serde_json::to_string(&observed).unwrap();
        let duplicate = format!("{{\"pid\":225,{}", serialized.strip_prefix('{').unwrap());
        assert!(serde_json::from_str::<ObservedWslcIdentity>(&duplicate).is_err());
        for field in ["pid", "listener_port", "window_id", "rail_hwnd", "rail_pid", "memory_max"] {
            for invalid in [json!(-1), json!(1.5), json!("1"), json!(true), Value::Null] {
                let mut bad = raw.clone(); bad[field] = invalid;
                assert!(serde_json::from_value::<ObservedWslcIdentity>(bad).is_err(), "numeric type {field}");
            }
        }
        for (field, value) in [("pid", json!(4_294_967_296_u64)), ("rail_pid", json!(4_294_967_296_u64)),
            ("listener_port", json!(65536)), ("rail_visible", json!(0)), ("process_start_ticks", json!(2748)),
            ("listener_inode", json!(4664)), ("rail_process_birth", json!(123))] {
            let mut bad = raw.clone(); bad[field] = value;
            assert!(serde_json::from_value::<ObservedWslcIdentity>(bad).is_err(), "typed field {field}");
        }
        let overflow = serialized.replace("\"memory_max\":1073741824", "\"memory_max\":18446744073709551616");
        assert_ne!(serialized, overflow);
        assert!(serde_json::from_str::<ObservedWslcIdentity>(&overflow).is_err());
    }

    #[test]
    fn expected_serde_rejects_unknown_missing_duplicate_and_nonstring_fields() {
        let (expected, _, _) = fixture(); let raw = serde_json::to_value(&expected).unwrap();
        let mut extra = raw.clone(); extra["pid"] = json!(225);
        assert!(serde_json::from_value::<ExpectedWslcIdentity>(extra).is_err());
        for field in raw.as_object().unwrap().keys() {
            let mut missing = raw.clone(); missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<ExpectedWslcIdentity>(missing).is_err());
            for invalid in [Value::Null, json!(1), json!(true), json!([])] {
                let mut bad = raw.clone(); bad[field] = invalid;
                assert!(serde_json::from_value::<ExpectedWslcIdentity>(bad).is_err());
            }
        }
        let s = serde_json::to_string(&expected).unwrap();
        let duplicate = format!("{{\"executable\":\"/opt/proof/other\",{}", s.strip_prefix('{').unwrap());
        assert!(serde_json::from_str::<ExpectedWslcIdentity>(&duplicate).is_err());
    }

    #[test]
    fn initial_rejects_malformed_expected_and_observed_pins() {
        let (expected, observed, _) = fixture();
        let non_hex = "g".repeat(64);
        for field in ["container_id", "image_id", "executable_sha256"] {
            for bad in ["", "a", non_hex.as_str(), "sha256:abc", "SHA256:abc"] {
                let altered = changed(&observed, field, json!(bad));
                refused(altered.verify_initial(&expected));
                let mut raw = serde_json::to_value(&expected).unwrap(); raw[field] = json!(bad);
                let altered: ExpectedWslcIdentity = serde_json::from_value(raw).unwrap();
                refused(observed.verify_initial(&altered));
            }
        }
        for bad in ["sha256:".to_owned() + &"b".repeat(63), "SHA256:".to_owned() + &"b".repeat(64),
            "sha256:".to_owned() + &"g".repeat(64)] {
            refused(changed(&observed, "image_id", json!(bad)).verify_initial(&expected));
        }
    }

    #[test]
    fn initial_rejects_non_normalized_guest_paths_without_host_path_rules() {
        let (expected, observed, _) = fixture();
        for bad in ["", "/", "relative/app", "C:\\proof\\app", "//opt/app", "/opt//app", "/opt/./app",
            "/opt/../app", "/opt/app/", "/opt\\app", "/opt/app\n", "/opt/app\0", "/opt/\u{85}app"] {
            assert_eq!(refused(changed(&observed,"executable",json!(bad)).verify_initial(&expected)), "WSLC_EXECUTABLE_INVALID");
            let mut bad_expected = expected.clone(); bad_expected.executable = bad.into();
            assert_eq!(refused(observed.verify_initial(&bad_expected)), "WSLC_EXECUTABLE_INVALID");
        }
    }

    #[test]
    fn initial_rejects_forged_namespaces_and_noncanonical_kernel_numbers() {
        let (expected, observed, _) = fixture();
        for bad in ["", "mnt:[4026532298]", "pid:4026532298", "pid:[0]", "pid:[01]", "pid:[+1]",
            "pid:[-1]", "pid:[ 1]", "pid:[1]\n", "pid:[18446744073709551616]", "pid:[1]:extra"] {
            assert_eq!(refused(changed(&observed,"pid_namespace",json!(bad)).verify_initial(&expected)), "WSLC_PID_NAMESPACE_INVALID");
        }
        for field in ["process_start_ticks", "listener_inode", "rail_process_birth"] {
            for bad in ["", "0", "00", "01", "+1", "-1", "1.0", "1e3", " 1", "1\n", "١", "18446744073709551616"] {
                refused(changed(&observed,field,json!(bad)).verify_initial(&expected));
            }
            changed(&observed,field,json!(u64::MAX.to_string())).verify_initial(&expected).unwrap();
        }
    }

    #[test]
    fn initial_enforces_loopback_nonzero_rails_hidden_and_fixed_cgroups() {
        let (expected, observed, _) = fixture();
        for (field, value) in [("pid",json!(0)), ("listener_host",json!("localhost")), ("listener_host",json!("::1")),
            ("listener_host",json!("127.0.0.1:80")), ("listener_port",json!(0)), ("rail_hwnd",json!(0)),
            ("rail_pid",json!(0)), ("rail_visible",json!(true)), ("memory_max",json!(0)),
            ("memory_max",json!(1_073_741_825_u64)), ("cpu_max",json!("max 100000")),
            ("cpu_max",json!("100000 100000\n")), ("cpu_max",json!("100000  100000"))] {
            refused(changed(&observed,field,value).verify_initial(&expected));
        }
    }

    #[test]
    fn bound_rejects_drift_in_every_observed_field() {
        let (expected, frozen, binding) = fixture();
        let drifts = [("schema",json!("toolkit-makepad-remote-wslc-identity-v2")), ("container_id",json!("c".repeat(64))),
            ("image_id",json!(format!("sha256:{}","c".repeat(64)))), ("pid_namespace",json!("pid:[4026532299]")),
            ("pid",json!(226)), ("process_start_ticks",json!("2749")), ("executable",json!("/opt/proof/other")),
            ("executable_sha256",json!("cd".repeat(32))), ("listener_host",json!("127.0.0.2")),
            ("listener_port",json!(38488)), ("listener_inode",json!("4665")), ("window_id",json!(1)),
            ("rail_hwnd",json!(329517)), ("rail_pid",json!(19753)), ("rail_process_birth",json!("134050000000000001")),
            ("rail_visible",json!(true)), ("memory_max",json!(1_073_741_825_u64)), ("cpu_max",json!("100000 100001"))];
        assert_eq!(drifts.len(), 18);
        for (field,value) in drifts {
            let drifted = changed(&frozen,field,value);
            assert_ne!(drifted,frozen); refused(drifted.verify_bound(&expected,&binding,&frozen));
        }
        // Even rebinding a new kernel incarnation cannot silently replace frozen identity.
        let mut drifted = frozen.clone(); drifted.pid = 226; drifted.process_start_ticks = "3000".into();
        let mut rebound = binding.clone(); rebound.pid = drifted.pid; rebound.process_birth = drifted.process_start_ticks.clone();
        assert_eq!(refused(drifted.verify_bound(&expected,&rebound,&frozen)), "WSLC_IDENTITY_DRIFT");
    }

    #[test]
    fn bound_rejects_wrong_platform_pin_and_each_binding_projection() {
        let (expected, observed, binding) = fixture();
        let changes = [("platform",json!("windows-owned-job")), ("source_commit",json!("0".repeat(40))),
            ("pid",json!(observed.rail_pid)), ("process_birth",json!(observed.rail_process_birth)),
            ("executable",json!("/opt/proof/other")), ("executable_sha256",json!("cd".repeat(32))), ("window_id",json!(1))];
        for (field,value) in changes {
            let mut raw = serde_json::to_value(&binding).unwrap(); raw[field] = value;
            let bad: SessionBinding = serde_json::from_value(raw).unwrap();
            refused(observed.verify_bound(&expected,&bad,&observed));
        }
        let mut bad = binding.clone(); bad.source_commit = PINNED_SOURCE.to_uppercase();
        assert_eq!(refused(observed.verify_bound(&expected,&bad,&observed)), "WSLC_BINDING_SOURCE_MISMATCH");
    }

    #[test]
    fn sha_case_is_ignored_for_pins_but_never_for_frozen_drift() {
        let (expected, observed, binding) = fixture();
        assert_ne!(expected.executable_sha256,observed.executable_sha256);
        observed.verify_bound(&expected,&binding,&observed).unwrap();
        let mut case_drift = observed.clone(); case_drift.executable_sha256.make_ascii_uppercase();
        case_drift.verify_initial(&expected).unwrap();
        assert_eq!(refused(case_drift.verify_bound(&expected,&binding,&observed)), "WSLC_IDENTITY_DRIFT");
        let mut wrong = expected.clone(); wrong.executable_sha256 = "ac".repeat(32);
        assert_eq!(refused(observed.verify_initial(&wrong)), "WSLC_EXECUTABLE_SHA256_MISMATCH");
        let mut wrong_container = expected.clone(); wrong_container.container_id = "c".repeat(64);
        assert_eq!(refused(observed.verify_initial(&wrong_container)), "WSLC_CONTAINER_ID_MISMATCH");
        let mut wrong_image = expected.clone(); wrong_image.image_id = format!("sha256:{}","c".repeat(64));
        assert_eq!(refused(observed.verify_initial(&wrong_image)), "WSLC_IMAGE_ID_MISMATCH");
    }
}

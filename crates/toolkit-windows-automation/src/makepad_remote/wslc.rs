//! Windows-hosted WSLC owner extracted from the retained Linux Transport.
//! One approved container, existing stdio relay/GPU policy/cleanup, no Script
//! execution or semantic action engine here. The generic adapter owns actions.
use super::{
    HostContentGeometry, PINNED_SOURCE, RemotePlatform, SessionBinding,
    native_frame::inspect_png,
    now_ms,
    protocol::{RemoteError, Result, allowed_route, classify_reply, exact_widget},
    wslc_identity::{
        ExpectedWslcIdentity, ObservedWslcIdentity, WSLC_FOCUS_MEMORY_MAX,
        WSLC_MODULE_SHELL_EXECUTABLE, WSLC_MODULE_SHELL_MEMORY_MAX,
    },
    wslc_pipe::WslcPipe,
};
use crate::desktop_arbiter::{
    DesktopArbiter, Lease, Owner, Resource, clock_ms, current_owner, observe_safe_point,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Operator-owned configuration, never deserialized from a public Script.
/// A trusted operator prepares the container/context with existing lifecycle
/// helpers. This owner neither provisions a VM nor attaches to arbitrary URLs.
#[derive(Clone, Debug)]
pub struct ApprovedWslcApp {
    pub experimental_opt_in: bool,
    pub source_commit: String,
    pub owner: String,
    pub runtime_directory: PathBuf,
    pub admission_path: PathBuf,
    pub python_executable: PathBuf,
    /// Exact maintained helper bytes, pinned by the operator alongside the ELF.
    /// Its path is fixed by this crate, never supplied by an ordinary Script.
    pub helper_sha256: String,
    pub expected_identity: ExpectedWslcIdentity,
    pub key_focus_probe: bool,
    /// Selected only by the exact internal trusted profile parser.
    pub expected_memory_max: u64,
    pub module_shell_source_manifest_sha256: Option<String>,
    pub output_directory: PathBuf,
}

fn checked(ok: bool, code: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(RemoteError::refused(code))
    }
}

fn storage_admission(value: &Value) -> Result<()> {
    if value["schema"]=="toolkit-wslc-storage-admission-v1" {
        if value["decision"]["code"]=="STORAGE_QUOTA_UNSUPPORTED" {
            return Err(RemoteError::refused("STORAGE_QUOTA_UNSUPPORTED"));
        }
        return checked(value["decision"]["status"]=="ADMITTED"
            && value["decision"]["max_bytes"].as_u64()==Some(120_000_000_000)
            && value["decision"]["reserve_bytes"].as_u64()==Some(10_000_000_000)
            && value["host_free_bytes"].as_u64().is_some_and(|n|n>=10_000_000_000)
            && value["capability"]["hard_limit_enforced"]==true
            && value["capability"]["limit_readback_bytes"].as_u64()==Some(120_000_000_000)
            && value["capability"]["covers_all_writable_mounts"]==true
            && value["capability"]["kernel_write_refusal_observed"]==true
            && value["capability"]["eager_allocation"]==false,
            "STORAGE_IDENTITY_NOT_VERIFIED");
    }

    checked(value["schema"]=="toolkit-wslc-storage-admission-v1.1",
        "STORAGE_IDENTITY_NOT_VERIFIED")?;
    if value["decision"]["code"]=="STORAGE_QUOTA_UNSUPPORTED" {
        return Err(RemoteError::refused("STORAGE_QUOTA_UNSUPPORTED"));
    }
    let Some(decision)=value.get("decision") else {
        return Err(RemoteError::refused("STORAGE_IDENTITY_NOT_VERIFIED"));
    };
    let Some(capability)=value.get("capability") else {
        return Err(RemoteError::refused("STORAGE_IDENTITY_NOT_VERIFIED"));
    };
    // v1.1 admits an explicitly monitored pre-create soft limit; it does not
    // claim that the software ceiling is a hard quota.
    checked(value.get("policy_id").and_then(Value::as_str)==Some("TOOLKIT_WSLC_STORAGE_POLICY_V1_1")
        && value.get("storage_enforcement").and_then(Value::as_str)==Some("monitored_soft_limit")
        && value.get("hard_quota_enforced").and_then(Value::as_bool)==Some(false)
        && value.get("host_free_bytes").and_then(Value::as_u64).is_some_and(|n|n>=11_073_741_824)
        && decision.get("status").and_then(Value::as_str)==Some("ADMITTED")
        && decision.get("host_free_bytes").and_then(Value::as_u64)
            == value.get("host_free_bytes").and_then(Value::as_u64)
        && decision.get("max_bytes").and_then(Value::as_u64)==Some(120_000_000_000)
        && decision.get("reserve_bytes").and_then(Value::as_u64)==Some(10_000_000_000)
        && decision.get("usage_bytes").is_some_and(Value::is_null)
        && decision.get("level").and_then(Value::as_str)==Some("NEW_CONTAINER_NOT_YET_CREATED")
        && decision.get("storage_enforcement").and_then(Value::as_str)==Some("monitored_soft_limit")
        && decision.get("hard_quota_enforced").and_then(Value::as_bool)==Some(false)
        && capability.get("storage_enforcement").and_then(Value::as_str)==Some("monitored_soft_limit")
        && capability.get("hard_limit_enforced").and_then(Value::as_bool)==Some(false)
        && capability.get("limit_readback_bytes").is_some_and(Value::is_null)
        && capability.get("eager_allocation").and_then(Value::as_bool)==Some(false)
        && capability.get("profile").and_then(Value::as_str)==Some("focus_trace71")
        && capability.get("usage_status").and_then(Value::as_str)==Some("NEW_OWNED_CONTAINER_NOT_YET_CREATED")
        && capability.get("inventory_verified").and_then(Value::as_bool)==Some(true)
        && capability.get("guest_process_inventory_verified").and_then(Value::as_bool)==Some(true)
        && capability.get("size_observation_available").and_then(Value::as_bool)==Some(true)
        && capability.get("unexpected_writable_mounts").and_then(Value::as_bool)==Some(false)
        && capability.get("scenario_growth_budget_bytes").and_then(Value::as_u64)==Some(1_073_741_824),
        "STORAGE_IDENTITY_NOT_VERIFIED")
}
fn focus_geometry_titles(
    expected: &ExpectedWslcIdentity,
    tag: &str,
    title: &str,
    rail_title: &str,
) -> bool {
    // Pinned-71 WindowHandle default and remote::tag_window_title, restricted
    // to approved Focus build34. No RAIL suffix stripping or title inference.
    let guest_title = format!("Makepad [{tag}]");
    expected.executable == "/opt/proof/ai-workspace-fixture"
        && expected.executable_sha256.eq_ignore_ascii_case(
            "9DFA4EEC8D4FEE6CAEE509D4FF2ACCB5136FED3A1D64D2302F0E35FF623AA4CB",
        )
        && tag.strip_prefix("toolkit-wslc-").is_some_and(|s| {
            s.len() == 24
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        && title == guest_title
        && (rail_title == guest_title || rail_title == format!("{guest_title} (Ubuntu)"))
}
fn focus_geometry_pid(x: &super::ObservedX11Geometry, guest_pid: u32) -> bool {
    x.expected_guest_pid == guest_pid
        && match x.pid_property {
            Some(pid) => pid == guest_pid && x.identity_source == "NET_WM_PID_AND_UNIQUE_TITLE",
            None => x.identity_source == "APPROVED_LAUNCH_NONCE_AND_UNIQUE_TITLE",
        }
}
fn approved_memory_max(config: &ApprovedWslcApp) -> Result<u64> {
    match (
        config.expected_memory_max,
        config.module_shell_source_manifest_sha256.as_deref(),
    ) {
        (WSLC_FOCUS_MEMORY_MAX, None) => Ok(WSLC_FOCUS_MEMORY_MAX),
        (WSLC_MODULE_SHELL_MEMORY_MAX, Some(source_sha))
            if config.expected_identity.executable == WSLC_MODULE_SHELL_EXECUTABLE
                && source_sha.len() == 64
                && source_sha
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)) =>
        {
            Ok(WSLC_MODULE_SHELL_MEMORY_MAX)
        }
        _ => Err(RemoteError::refused("WSLC_MEMORY_PROFILE_INVALID")),
    }
}
fn input_lease_deadline(now: u64) -> Result<u64> {
    // One absolute budget from acquire; heartbeat never renews this deadline.
    now.checked_add(120_000)
        .ok_or_else(|| RemoteError::refused("INPUT_LOCK_DEADLINE_OVERFLOW"))
}
fn write_new(path: &Path, value: &Value) -> Result<()> {
    let data = serde_json::to_vec_pretty(value)
        .map_err(|_| RemoteError::refused("WSLC_EVIDENCE_INVALID"))?;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .and_then(|mut f| f.write_all(&data))
        .map_err(|_| RemoteError::refused("WSLC_EXCLUSIVE_EVIDENCE_WRITE_FAILED"))
}
fn canonical_file(path: &Path) -> Result<PathBuf> {
    no_reparse(path)?;
    let p = fs::canonicalize(path)
        .map_err(|_| RemoteError::refused("WSLC_TRUSTED_PATH_UNAVAILABLE"))?;
    checked(p.is_file(), "WSLC_TRUSTED_FILE_REQUIRED")?;
    Ok(p)
}
fn check_helper_bytes(path: &Path, expected: &str) -> Result<()> {
    checked(
        expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
        "WSLC_APPROVED_HELPER_HASH_REQUIRED",
    )?;
    no_reparse(path)?;
    let before = fs::metadata(path).map_err(|_| RemoteError::refused("WSLC_HELPER_READ_FAILED"))?;
    checked(
        before.is_file() && before.len() <= 1024 * 1024,
        "WSLC_HELPER_SIZE_REFUSED",
    )?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(1024 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|_| RemoteError::refused("WSLC_HELPER_READ_FAILED"))?;
    let after = fs::metadata(path).map_err(|_| RemoteError::refused("WSLC_HELPER_READ_FAILED"))?;
    checked(
        bytes.len() <= 1024 * 1024
            && bytes.len() as u64 == before.len()
            && before.len() == after.len()
            && before.modified().ok() == after.modified().ok()
            && format!("{:x}", Sha256::digest(&bytes)) == expected.to_ascii_lowercase(),
        "WSLC_APPROVED_HELPER_BYTES_CHANGED",
    )
}
fn check_live_helper(cleaned: bool, normal_exit: bool, path: &Path, expected: &str) -> Result<()> {
    checked(!cleaned && !normal_exit, "STALE_PROCESS")?;
    check_helper_bytes(path, expected)
}
fn no_reparse(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    for component in path.ancestors() {
        match fs::symlink_metadata(component) {
            Ok(m) => checked(
                m.file_attributes() & 0x400 == 0,
                "WSLC_REPARSE_PATH_REFUSED",
            )?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RemoteError::refused("WSLC_TRUSTED_PATH_UNAVAILABLE")),
        }
    }
    Ok(())
}
fn fresh_evidence_path(path: &Path, evidence: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)
        .map_err(|_| RemoteError::refused("WSLC_EVIDENCE_PATH_REFUSED"))?;
    checked(
        !absolute
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir)),
        "WSLC_EVIDENCE_PATH_REFUSED",
    )?;
    no_reparse(&absolute)?;
    checked(!absolute.exists(), "FRESH_REMOTE_OUTPUT_REQUIRED")?;
    let ancestor = absolute
        .ancestors()
        .find(|p| p.exists())
        .ok_or_else(|| RemoteError::refused("WSLC_EVIDENCE_PATH_REFUSED"))?;
    let base = fs::canonicalize(ancestor)
        .map_err(|_| RemoteError::refused("WSLC_EVIDENCE_PATH_REFUSED"))?;
    let resolved = base.join(
        absolute
            .strip_prefix(ancestor)
            .map_err(|_| RemoteError::refused("WSLC_EVIDENCE_PATH_REFUSED"))?,
    );
    checked(resolved.starts_with(evidence), "WSLC_EVIDENCE_PATH_REFUSED")?;
    Ok(resolved)
}
fn unwrap_reply(reply: Value) -> Result<Value> {
    if reply["ok"] == true {
        return reply
            .get("result")
            .cloned()
            .ok_or_else(|| RemoteError::unknown("WSLC_REPLY_RESULT_MISSING"));
    }
    let code = reply["error"]["code"]
        .as_str()
        .filter(|s| {
            s.starts_with("WSLC_")
                && s.len() <= 96
                && s.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        })
        .ok_or_else(|| RemoteError::unknown("WSLC_REPLY_ERROR_INVALID"))?;
    match reply["error"]["dispatched"].as_bool() {
        Some(false) => Err(RemoteError::refused(code)),
        Some(true) => Err(RemoteError::unknown(code)),
        None => Err(RemoteError::unknown("WSLC_REPLY_ERROR_INVALID")),
    }
}
fn after_launch(cause: RemoteError) -> RemoteError {
    let mut error = RemoteError::unknown(&cause.code);
    error.details["phase"] = json!("AFTER_WSLC_LAUNCH");
    error.details["cause"] = json!(cause);
    error
}
fn failed_start_cleanup(pipe: &mut WslcPipe, output: &Path, mut error: RemoteError) -> RemoteError {
    let cleanup = pipe.exchange("cleanup", json!({})).and_then(unwrap_reply);
    // Persist available proof BEFORE waiting, including poisoned-pipe refusal.
    let saved = write_new(
        &output.join("failed-start-cleanup-observed.json"),
        &json!({
        "original_error":error,"cleanup_result":cleanup,"not_normal_app_exit_proof":true}),
    );
    let finish = pipe.finish(); // unconditional: helper's TTL/finally owns retirement
    let final_saved = write_new(
        &output.join("failed-start-cleanup-finished.json"),
        &json!({
        "original_error":error,"cleanup_result":cleanup,"helper_finish":finish,"observation_write":saved}),
    );
    error.details["failed_start_cleanup"] = json!({"cleanup_result":cleanup,"helper_finish":finish,
        "observation_write":saved,"completion_write":final_saved});
    error
}
fn cleanup_confirmed(proof: &Value) -> bool {
    [
        "container_stopped",
        "owned_helpers_gone",
        "rail_absent",
        "guest_process_gone",
        "listener_absent",
    ]
    .iter()
    .all(|key| proof[*key] == true)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchReply {
    identity: ObservedWslcIdentity,
    grab_root: String,
    gpu: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityReply {
    identity: ObservedWslcIdentity,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FocusReply {
    identity: ObservedWslcIdentity,
    sample: Option<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GeometryReply {
    identity: ObservedWslcIdentity,
    geometry: HostContentGeometry,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupReceipt {
    schema: String,
    session_id: String,
    owner: String,
    container_id: String,
    result: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpReply {
    identity: ObservedWslcIdentity,
    status: u16,
    body_utf8: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameReply {
    identity: ObservedWslcIdentity,
    bytes_hex: String,
    guest_path: String,
    modified_ms: u64,
    stat_before: String,
    stat_after: String,
    guest_clock_before_ms: u64,
    guest_clock_after_ms: u64,
}
fn decode<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|_| RemoteError::unknown("WSLC_RESULT_SCHEMA_INVALID"))
}
fn guest_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .skip(1)
            .all(|s| !s.is_empty() && s != "." && s != "..")
}
fn decode_frame_hex(encoded: &str) -> Result<Vec<u8>> {
    checked(
        !encoded.is_empty() && encoded.len() <= 16 * 1024 * 1024 && encoded.len() % 2 == 0,
        "WSLC_NATIVE_FRAME_SIZE_REFUSED",
    )?;
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|part| {
            let digit = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            digit(part[0])
                .zip(digit(part[1]))
                .map(|(a, b)| a * 16 + b)
                .ok_or_else(|| RemoteError::refused("WSLC_NATIVE_FRAME_ENCODING_INVALID"))
        })
        .collect()
}

fn preserve_rejected_frame(
    output: &Path,
    request_index: u64,
    binding: &SessionBinding,
    metadata: &Value,
    reply: &FrameReply,
    bytes: &[u8],
    dispatched_ms: u64,
    mut error: RemoteError,
) -> RemoteError {
    // Caller has already checked identity, guest path, stable stat and clocks.
    // This path never publishes an accepted frame or changes seen_frames.
    let stem = format!("rejected-native-frame-request-{request_index:04}");
    let png_path = output.join(format!("{stem}.png"));
    let context_path = output.join(format!("{stem}.json"));
    let mut diagnostic = json!({"status":"REJECTED_NOT_ACCEPTED","request_index":request_index,
        "png_path":png_path,"context_path":context_path,"png_created":false,"png_written":false,
        "context_write_attempted":false,"context_written":false});
    let persisted = (|| -> Result<()> {
        checked(
            !bytes.is_empty() && bytes.len() <= 8 * 1024 * 1024,
            "WSLC_REJECTED_PNG_SIZE_REFUSED",
        )?;
        let sha256 = format!("{:x}", Sha256::digest(bytes));
        diagnostic["sha256"] = json!(sha256);
        diagnostic["bytes"] = json!(bytes.len());
        let metadata_bytes = serde_json::to_vec(metadata)
            .map_err(|_| RemoteError::refused("WSLC_REJECTED_METADATA_INVALID"))?;
        checked(
            metadata_bytes.len() <= 65536,
            "WSLC_REJECTED_METADATA_BOUND",
        )?;
        let context = json!({"status":"REJECTED_NOT_ACCEPTED","accepted":false,
            "request_index":request_index,"binding":binding,"observed_identity":reply.identity,
            "png_path":png_path,"sha256":sha256,"bytes":bytes.len(),
            "metadata":metadata,"guest_path":reply.guest_path,"modified_ms":reply.modified_ms,
            "source_stat_before":reply.stat_before,"source_stat_after":reply.stat_after,
            "guest_clock_before_ms":reply.guest_clock_before_ms,"guest_clock_after_ms":reply.guest_clock_after_ms,
            "dispatched_at_unix_ms":dispatched_ms,"observed_unix_ms":now_ms(),"original_error":error});
        let context_bytes = serde_json::to_vec_pretty(&context)
            .map_err(|_| RemoteError::refused("WSLC_REJECTED_CONTEXT_INVALID"))?;
        checked(context_bytes.len() <= 65536, "WSLC_REJECTED_CONTEXT_BOUND")?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&png_path)
            .map_err(|_| RemoteError::refused("WSLC_REJECTED_PNG_WRITE_FAILED"))?;
        diagnostic["png_created"] = json!(true);
        file.write_all(bytes)
            .map_err(|_| RemoteError::refused("WSLC_REJECTED_PNG_WRITE_FAILED"))?;
        diagnostic["png_written"] = json!(true);
        diagnostic["context_write_attempted"] = json!(true);
        write_new(&context_path, &context)?;
        diagnostic["context_written"] = json!(true);
        Ok(())
    })();
    if let Err(cause) = persisted {
        // No OS error text, remote body, overwrite, deletion or action retry.
        // A failed write may leave a partial diagnostic, never accepted evidence.
        diagnostic["persistence_error"] = json!({"code":cause.code,"outcome":cause.outcome});
    }
    if !error.details.is_object() {
        let original = std::mem::replace(&mut error.details, json!({}));
        error.details["original_details"] = original;
    }
    error.details["rejected_native_frame"] = diagnostic;
    error
}

pub struct WslcRemotePlatform {
    pipe: WslcPipe,
    binding: SessionBinding,
    expected: ExpectedWslcIdentity,
    expected_memory_max: u64,
    frozen: ObservedWslcIdentity,
    grab_root: String,
    output: PathBuf,
    arbiter: DesktopArbiter,
    arbiter_owner: Owner,
    lease: Option<Lease>,
    input_uncertain: bool,
    normal_exit: bool,
    cleaned: bool,
    cleanup_report: Option<Value>,
    cleanup_proof: Option<Value>,
    cleanup_attempts: u32,
    requests: u64,
    geometry_observations: u64,
    seen_frames: BTreeSet<String>,
    key_focus_probe: bool,
    helper_path: PathBuf,
    helper_sha256: String,
}

impl WslcRemotePlatform {
    pub fn launch(config: &ApprovedWslcApp) -> Result<Self> {
        checked(
            config.experimental_opt_in && config.source_commit == PINNED_SOURCE,
            "TRUSTED_REMOTE_OPT_IN_REQUIRED",
        )?;
        let expected_memory_max = approved_memory_max(config)?;
        checked(
            !config.owner.is_empty() && config.owner.len() <= 128,
            "TRUSTED_OWNER_REQUIRED",
        )?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| RemoteError::refused("WSLC_TOOLKIT_ROOT_UNAVAILABLE"))?;
        let evidence = fs::canonicalize(root.join("reports/evidence"))
            .map_err(|_| RemoteError::refused("WSLC_EVIDENCE_ROOT_UNAVAILABLE"))?;
        no_reparse(&config.runtime_directory)?;
        let runtime = fs::canonicalize(&config.runtime_directory)
            .map_err(|_| RemoteError::refused("WSLC_RUNTIME_CONTEXT_MISSING"))?;
        checked(
            runtime.starts_with(&evidence) && runtime.is_dir(),
            "WSLC_TRUSTED_RUNTIME_DIRECTORY_REQUIRED",
        )?;
        // Receipt remains bound to this package; v1 requires hard-quota proof,
        // while v1.1 admits only the bounded pre-create soft-limit witness.
        let storage_path=canonical_file(&runtime.join("storage/storage-admission.json"))?;
        let mut storage_bytes=Vec::new();
        fs::File::open(&storage_path).and_then(|file|file.take(262145).read_to_end(&mut storage_bytes))
            .map_err(|_|RemoteError::refused("STORAGE_IDENTITY_NOT_VERIFIED"))?;
        checked(storage_bytes.len()<=262144,"STORAGE_IDENTITY_NOT_VERIFIED")?;
        let storage:Value=serde_json::from_slice(&storage_bytes).map_err(|_|RemoteError::refused("STORAGE_IDENTITY_NOT_VERIFIED"))?;
        storage_admission(&storage)?;
        let policy=canonical_file(&root.join("experiments/ai-execution-workspace/storage-policy.json"))?;
        check_helper_bytes(&policy,storage["policy_sha256"].as_str().unwrap_or(""))?;
        let admission = canonical_file(&config.admission_path)?;
        checked(
            admission.starts_with(&evidence),
            "WSLC_ADMISSION_PATH_REFUSED",
        )?;
        let python = canonical_file(&config.python_executable)?;
        let output = fresh_evidence_path(&config.output_directory, &evidence)?;
        fs::create_dir_all(&output)
            .map_err(|_| RemoteError::refused("REMOTE_OUTPUT_CREATE_FAILED"))?;
        let helper = canonical_file(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/makepad_remote/wslc_host.py"),
        )?;
        check_helper_bytes(&helper, &config.helper_sha256)?;
        static GENERATION: AtomicU64 = AtomicU64::new(1);
        let generation = GENERATION
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| RemoteError::refused("SESSION_GENERATION_EXHAUSTED"))?;
        let session = format!(
            "wslc-remote-{}-{}-{generation}",
            std::process::id(),
            now_ms()
        );
        // Acquire the existing owner before touching any runtime resources.
        let arbiter = DesktopArbiter::open()
            .map_err(|_| RemoteError::refused("INPUT_LOCK_REGISTRY_UNAVAILABLE"))?;
        let arbiter_owner =
            current_owner("makepad-remote-wslc", "public-script", &session, &session)
                .map_err(|_| RemoteError::refused("INPUT_LOCK_OWNER_UNAVAILABLE"))?;
        let config_path = output.join("owner-config.json");
        let mut owner_config = json!({"schema":"toolkit-makepad-remote-wslc-owner-v1",
            "source_commit":PINNED_SOURCE,"owner":config.owner,"session_id":session,"generation":generation,
            "runtime_directory":runtime,"output_directory":output,"admission_path":admission,
            "expected_identity":config.expected_identity,"key_focus_probe":config.key_focus_probe});
        if expected_memory_max == WSLC_MODULE_SHELL_MEMORY_MAX {
            owner_config["profile_kind"] = json!("ModuleShell");
            owner_config["module_shell"] =
                json!({"source_manifest_sha256":config.module_shell_source_manifest_sha256});
        }
        write_new(&config_path, &owner_config)?;
        let mut pipe = WslcPipe::spawn(
            &python,
            &helper,
            &config_path,
            &output.join("backend.stderr.log"),
        )?;
        let startup = (|| {
            let raw = unwrap_reply(pipe.exchange("launch", json!({}))?)?;
            // A success envelope means runtime work already occurred. All local
            // validation/evidence failures after it are unknown, never not-dispatched.
            (|| {
                let launched: LaunchReply = decode(raw)?;
                launched.identity.verify_initial_with_memory_max(
                    &config.expected_identity,
                    expected_memory_max,
                )?;
                checked(guest_path(&launched.grab_root), "WSLC_GRAB_ROOT_INVALID")?;
                let binding = SessionBinding {
                    session_id: session.clone(),
                    owner: config.owner.clone(),
                    generation,
                    pid: launched.identity.pid,
                    process_birth: launched.identity.process_start_ticks.clone(),
                    executable: launched.identity.executable.clone(),
                    executable_sha256: launched.identity.executable_sha256.clone(),
                    source_commit: PINNED_SOURCE.into(),
                    window_id: launched.identity.window_id,
                    platform: "linux-wslc-owned-container".into(),
                };
                write_new(
                    &output.join("session-binding.json"),
                    &json!({"binding":binding,"identity":launched.identity,"gpu":launched.gpu,
                "helper_sha256":config.helper_sha256}),
                )?;
                Ok((launched, binding))
            })()
            .map_err(after_launch)
        })();
        let (launched, binding) = match startup {
            Ok(value) => value,
            Err(error) => return Err(failed_start_cleanup(&mut pipe, &output, error)),
        };
        Ok(Self {
            pipe,
            binding,
            expected: config.expected_identity.clone(),
            expected_memory_max,
            frozen: launched.identity,
            grab_root: launched.grab_root,
            output,
            arbiter,
            arbiter_owner,
            lease: None,
            input_uncertain: false,
            normal_exit: false,
            cleaned: false,
            cleanup_report: None,
            cleanup_proof: None,
            cleanup_attempts: 0,
            requests: 0,
            geometry_observations: 0,
            seen_frames: BTreeSet::new(),
            key_focus_probe: config.key_focus_probe,
            helper_path: helper,
            helper_sha256: config.helper_sha256.clone(),
        })
    }
    fn exchange(&mut self, operation: &str, arguments: Value) -> Result<Value> {
        unwrap_reply(self.pipe.exchange(operation, arguments)?)
    }
    fn verify(&self, identity: &ObservedWslcIdentity) -> Result<()> {
        identity.verify_bound_with_memory_max(
            &self.expected,
            &self.binding,
            &self.frozen,
            self.expected_memory_max,
        )
    }
    fn save(&self, name: &str, value: &Value) -> Result<()> {
        write_new(&self.output.join(name), value)
    }
    fn eof_cleanup_proof(&self) -> Result<Value> {
        let path = self.output.join("platform-cleanup.json");
        no_reparse(&path)?;
        let mut bytes = Vec::new();
        fs::File::open(path)
            .and_then(|file| file.take(65537).read_to_end(&mut bytes))
            .map_err(|_| RemoteError::unknown("WSLC_EOF_CLEANUP_PROOF_UNAVAILABLE"))?;
        if bytes.len() > 65536 {
            return Err(RemoteError::unknown("WSLC_EOF_CLEANUP_PROOF_INVALID"));
        }
        let parsed: super::protocol::UniqueJson = serde_json::from_slice(&bytes)
            .map_err(|_| RemoteError::unknown("WSLC_EOF_CLEANUP_PROOF_INVALID"))?;
        let receipt: CleanupReceipt = decode(parsed.0)?;
        if receipt.schema != "toolkit-makepad-remote-wslc-cleanup-v1"
            || receipt.session_id != self.binding.session_id
            || receipt.owner != self.binding.owner
            || receipt.container_id != self.expected.container_id
            || !cleanup_confirmed(&receipt.result)
        {
            return Err(RemoteError::unknown("WSLC_EOF_CLEANUP_PROOF_INVALID"));
        }
        Ok(receipt.result)
    }
    fn focus_sample(&mut self, required: bool) -> Result<Option<Value>> {
        let reply: FocusReply = decode(self.exchange("focus_sample", json!({}))?)?;
        self.verify(&reply.identity)?;
        if let Some(sample) = &reply.sample {
            super::focus_probe::validate_sample(
                sample,
                self.binding.pid,
                self.binding.window_id,
                required,
            )?;
        }
        Ok(reply.sample)
    }
}

impl RemotePlatform for WslcRemotePlatform {
    fn host_content_geometry(&mut self) -> Result<Option<HostContentGeometry>> {
        check_live_helper(
            self.cleaned,
            self.normal_exit,
            &self.helper_path,
            &self.helper_sha256,
        )?;
        let monotonic_started = std::time::Instant::now();
        let started = now_ms();
        let reply: GeometryReply = decode(self.exchange("host_content_geometry", json!({}))?)?;
        self.verify(&reply.identity)?;
        let g = reply.geometry;
        let sequence = self
            .geometry_observations
            .checked_add(1)
            .ok_or_else(|| RemoteError::refused("WSLC_GEOMETRY_SEQUENCE_EXHAUSTED"))?;
        let tag = format!(
            "toolkit-wslc-{}",
            &format!("{:x}", Sha256::digest(self.binding.session_id.as_bytes()))[..24]
        );
        checked(
            g.schema == "toolkit-wslc-host-content-geometry-v1"
                && g.session_id == self.binding.session_id
                && g.generation == self.binding.generation
                && g.sequence == sequence
                && g.container_id == self.expected.container_id
                && g.guest_pid == self.binding.pid
                && g.guest_process_start_ticks == self.binding.process_birth
                && g.rail_hwnd == self.frozen.rail_hwnd
                && g.rail_pid == self.frozen.rail_pid
                && g.rail_process_birth == self.frozen.rail_process_birth
                && g.tag == tag
                && focus_geometry_titles(&self.expected, &tag, &g.title, &g.rail_title)
                && g.x11.schema == "toolkit-wslc-x11-content-geometry-v1"
                && g.x11.display == ":0"
                && focus_geometry_pid(&g.x11, self.binding.pid)
                && g.x11.title == g.title,
            "WSLC_GEOMETRY_IDENTITY_MISMATCH",
        )?;
        checked(
            monotonic_started.elapsed().as_millis() <= 10_000
                && g.observed_monotonic_ns >= g.started_monotonic_ns
                && g.observed_monotonic_ns - g.started_monotonic_ns <= 10_000_000_000
                && g.observed_unix_ms >= started
                && g.observed_unix_ms <= now_ms(),
            "WSLC_GEOMETRY_OBSERVATION_EXPIRED",
        )?;
        checked(
            g.raw_x11_utf8.len() <= 65536
                && format!("{:X}", Sha256::digest(g.raw_x11_utf8.as_bytes())) == g.raw_x11_sha256,
            "WSLC_GEOMETRY_RAW_HASH_MISMATCH",
        )?;
        let original: super::protocol::UniqueJson = serde_json::from_str(&g.raw_x11_utf8)
            .map_err(|_| RemoteError::refused("WSLC_GEOMETRY_RAW_JSON_INVALID"))?;
        checked(
            original.0.get("pid_property").is_some(),
            "WSLC_GEOMETRY_PID_PROPERTY_MISSING",
        )?;
        let original: super::ObservedX11Geometry = decode(original.0)?;
        checked(original == g.x11, "WSLC_GEOMETRY_RAW_PROJECTION_MISMATCH")?;
        self.save(
            &format!("host-content-geometry-rust-{sequence:04}.json"),
            &json!({"identity":reply.identity,"geometry":&g}),
        )?;
        self.geometry_observations = sequence;
        Ok(Some(g))
    }
    fn host_window_identity(&mut self) -> Result<(u64, u32, u64)> {
        self.validate()?;
        let birth = self
            .frozen
            .rail_process_birth
            .parse()
            .map_err(|_| RemoteError::refused("WSLC_RAIL_PROCESS_BIRTH_INVALID"))?;
        Ok((self.frozen.rail_hwnd, self.frozen.rail_pid, birth))
    }
    fn binding(&self) -> &SessionBinding {
        &self.binding
    }
    fn validate(&mut self) -> Result<()> {
        check_live_helper(
            self.cleaned,
            self.normal_exit,
            &self.helper_path,
            &self.helper_sha256,
        )?;
        let reply: IdentityReply = decode(self.exchange("validate", json!({}))?)?;
        self.verify(&reply.identity)
    }
    fn request(&mut self, target: &str, mutating: bool) -> Result<Value> {
        checked(allowed_route(target), "REMOTE_ROUTE_NOT_ALLOWLISTED")?;
        let route = target.split('?').next().unwrap_or("");
        checked(
            ["/click", "/m", "/k", "/t", "/quit"].contains(&route) == mutating,
            "REMOTE_MUTATION_CLASSIFICATION_MISMATCH",
        )?;
        // The request exchange itself performs two full, fresh Python identity
        // validations before dispatch. Do not add a third remote observation
        // here, but keep the same local retirement and trusted-source guards.
        check_live_helper(
            self.cleaned,
            self.normal_exit,
            &self.helper_path,
            &self.helper_sha256,
        )?;
        if mutating {
            let token = self
                .lease
                .as_ref()
                .map(|l| format!("lease:{}:{}", l.request_id, l.generation))
                .ok_or_else(|| RemoteError::refused("INPUT_LOCK_REQUIRED"))?;
            self.validate_input(&token)?;
            checked(
                target.split('?').nth(1).is_some_and(|q| {
                    q.split('&').any(|p| {
                        p.strip_prefix("if_user_seq=")
                            .is_some_and(|v| v.parse::<u64>().is_ok())
                    })
                }),
                "HUMAN_ACTIVITY_GUARD_REQUIRED",
            )?;
        }
        self.requests = self
            .requests
            .checked_add(1)
            .ok_or_else(|| RemoteError::refused("WSLC_REQUEST_BUDGET_EXHAUSTED"))?;
        let result = (|| {
            let reply: HttpReply =
                decode(self.exchange("request", json!({"target":target,"mutating":mutating}))?)?;
            // /quit may retire the process before native post-validation; its
            // helper reply still binds the exact pre-dispatch frozen identity.
            self.verify(&reply.identity)
                .map_err(|e| RemoteError::unknown(&e.code))?;
            if reply.body_utf8.len() > 4 * 1024 * 1024 {
                return Err(RemoteError::unknown("REMOTE_REPLY_TOO_LARGE"));
            }
            if route == "/d" && reply.status == 200 {
                return Ok(json!({"dump":reply.body_utf8}));
            }
            let value = classify_reply(reply.status, reply.body_utf8.as_bytes(), mutating)?;
            if mutating && value["ok"] != 1 && value["ok"] != true {
                return Err(RemoteError::unknown("REMOTE_MUTATION_ACK_INVALID"));
            }
            Ok(value)
        })();
        if mutating
            && result
                .as_ref()
                .is_err_and(|e| e.outcome != "NOT_DISPATCHED")
        {
            self.input_uncertain = true;
        }
        if self.save(&format!("request-{:04}.json",self.requests),&json!({"route":route,"mutating":mutating,
            "request_target_sha256":format!("{:x}",Sha256::digest(target.as_bytes())),"request_index":self.requests,
            "session_id":self.binding.session_id,"observed_unix_ms":now_ms(),"success":result.is_ok(),"error":result.as_ref().err()})).is_err() {
            if mutating {self.input_uncertain=true;return Err(RemoteError::unknown("POST_DISPATCH_EVIDENCE_WRITE_FAILED"));}
            return Err(RemoteError::refused("EVIDENCE_WRITE_FAILED"));
        }
        result
    }
    fn acquire_input(&mut self) -> Result<String> {
        checked(self.lease.is_none(), "INPUT_LOCK_ALREADY_HELD")?;
        let request = self
            .arbiter
            .request_lease(
                vec![Resource::SessionSemantic {
                    session_id: self.binding.session_id.clone(),
                }],
                &self.arbiter_owner,
                input_lease_deadline(clock_ms())?,
            )
            .map_err(|_| RemoteError::refused("INPUT_LOCK_REQUEST_FAILED"))?;
        let lease = self
            .arbiter
            .wait_lease(request, &self.arbiter_owner, &AtomicBool::new(false))
            .map_err(|_| RemoteError::refused("INPUT_LOCK_ACQUIRE_FAILED"))?;
        let token = format!("lease:{}:{}", lease.request_id, lease.generation);
        self.lease = Some(lease);
        Ok(token)
    }
    fn validate_input(&mut self, token: &str) -> Result<()> {
        let lease = self
            .lease
            .as_ref()
            .ok_or_else(|| RemoteError::refused("INPUT_LOCK_REQUIRED"))?;
        checked(
            token == format!("lease:{}:{}", lease.request_id, lease.generation),
            "STALE_LEASE",
        )?;
        self.arbiter
            .validate(lease, &self.arbiter_owner)
            .map_err(|_| RemoteError::refused("STALE_LEASE"))
    }
    fn release_input(&mut self, token: &str) -> Result<()> {
        self.validate_input(token)?;
        checked(
            !self.input_uncertain || self.normal_exit || self.cleaned,
            "REMOTE_INPUT_CLEANUP_UNCONFIRMED",
        )?;
        self.arbiter
            .release_lease(
                self.lease.as_ref().unwrap(),
                &self.arbiter_owner,
                &observe_safe_point(false, false, false, false, false),
            )
            .map_err(|_| RemoteError::refused("INPUT_LOCK_RELEASE_UNCONFIRMED"))?;
        self.lease = None;
        Ok(())
    }
    fn copy_native_frame(&mut self, metadata: &Value, dispatched_ms: u64) -> Result<Value> {
        self.validate()?;
        checked(
            metadata["w"].as_u64() == Some(self.binding.window_id),
            "CAPTURE_WRONG_WINDOW",
        )?;
        let reply: FrameReply = decode(self.exchange(
            "copy_frame",
            json!({"metadata":metadata,"dispatched_ms":dispatched_ms}),
        )?)?;
        self.verify(&reply.identity)?;
        checked(
            guest_path(&reply.guest_path)
                && reply
                    .guest_path
                    .starts_with(&(self.grab_root.clone() + "/"))
                && reply.guest_path.ends_with(".png")
                && metadata["png"].as_str() == Some(reply.guest_path.as_str()),
            "NATIVE_CAPTURE_PATH_REFUSED",
        )?;
        checked(
            !self.seen_frames.contains(&reply.guest_path),
            "STALE_NATIVE_FRAME",
        )?;
        checked(
            !reply.stat_before.is_empty() && reply.stat_before == reply.stat_after,
            "NATIVE_CAPTURE_CHANGED",
        )?;
        checked(
            reply.guest_clock_before_ms <= reply.modified_ms
                && reply.modified_ms <= reply.guest_clock_after_ms
                && now_ms().abs_diff(reply.guest_clock_after_ms) <= 2000,
            "STALE_NATIVE_FRAME",
        )?;
        let bytes = decode_frame_hex(&reply.bytes_hex)?;
        let decoded = match inspect_png(&bytes) {
            Ok(decoded) => decoded,
            Err(error) => {
                return Err(preserve_rejected_frame(
                    &self.output,
                    self.requests,
                    &self.binding,
                    metadata,
                    &reply,
                    &bytes,
                    dispatched_ms,
                    error,
                ));
            }
        };
        checked(
            metadata["sz"] == json!([decoded.width, decoded.height]),
            "NATIVE_CAPTURE_GEOMETRY_MISMATCH",
        )?;
        self.validate()?;
        let destination = self.output.join(format!(
            "native-frame-{:04}.png",
            self.seen_frames.len() + 1
        ));
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .and_then(|mut f| f.write_all(&bytes))
            .map_err(|_| RemoteError::refused("NATIVE_CAPTURE_PUBLISH_FAILED"))?;
        self.seen_frames.insert(reply.guest_path);
        Ok(
            json!({"path":destination,"sha256":format!("{:x}",Sha256::digest(&bytes)),"bytes":bytes.len(),
            "width":decoded.width,"height":decoded.height,"captured_at_unix_ms":reply.modified_ms,"dispatched_at_unix_ms":dispatched_ms,
            "full_png_decode":true,"nonblank":true,"sampled_colors":decoded.sampled_colors,"remote":metadata,
            "independent_visual_review":"PENDING","presentation_verified":false,"source_stat_before":reply.stat_before,
            "source_stat_after":reply.stat_after,"guest_clock_before_ms":reply.guest_clock_before_ms,"guest_clock_after_ms":reply.guest_clock_after_ms}),
        )
    }
    fn reap_normal_exit(&mut self) -> Result<Value> {
        let value = self.exchange("reap", json!({}))?;
        checked(
            value["exit_code"] == 0
                && value["normal_exit_observed"] == true
                && value["guest_process_gone"] == true
                && value["listener_absent"] == true
                && value["rail_absent"] == true,
            "NORMAL_APP_EXIT_UNCONFIRMED",
        )?;
        self.normal_exit = true;
        self.save("normal-exit.json", &value)?;
        Ok(value)
    }
    fn read_runtime_stderr(&mut self) -> Result<Value> {
        self.validate()?;
        let reply = self.exchange("stderr", json!({}))?;
        checked(
            reply["lines"].as_array().is_some_and(|lines| {
                lines.iter().all(Value::is_string)
                    && lines
                        .iter()
                        .map(|v| v.as_str().unwrap().len())
                        .sum::<usize>()
                        <= 65536
            }),
            "RUNTIME_STDERR_INVALID",
        )?;
        Ok(reply["lines"].clone())
    }
    fn cleanup_owned_resources(&mut self) -> Result<Value> {
        if let Some(value) = &self.cleanup_report {
            return Ok(value.clone());
        }
        self.cleanup_attempts = self
            .cleanup_attempts
            .checked_add(1)
            .ok_or_else(|| RemoteError::unknown("CLEANUP_ATTEMPT_EXHAUSTED"))?;
        let attempt = self.cleanup_attempts;
        let raw_cleanup_result = match &self.cleanup_proof {
            Some(proof) => Ok(proof.clone()),
            None => self.exchange("cleanup", json!({})),
        };
        let mut proof_result = raw_cleanup_result.clone().and_then(|proof| {
            if cleanup_confirmed(&proof) {
                Ok(proof)
            } else {
                Err(RemoteError::unknown("WSLC_OWNED_CLEANUP_UNCONFIRMED"))
            }
        });
        if let Ok(proof) = &proof_result {
            self.cleaned = true;
            self.cleanup_proof = Some(proof.clone());
        }
        let observed=self.save(&format!("owned-cleanup-observed-{attempt:04}.json"),&json!({
            "session_id":self.binding.session_id,"raw_cleanup_result":raw_cleanup_result,"cleanup_result":proof_result,
            "normal_exit_observed":self.normal_exit,"active_owned_leases":usize::from(self.lease.is_some())}));
        let mut release = if self.cleaned && self.lease.is_some() {
            let lease = self.lease.as_ref().unwrap();
            let token = format!("lease:{}:{}", lease.request_id, lease.generation);
            self.release_input(&token)
        } else {
            Ok(())
        };
        let finish = self.pipe.finish(); // never skip EOF wait due to another error
        // Native helper exit alone is not guest cleanup. Join its immutable
        // kernel-observed receipt to this exact owner/container, without resend.
        let eof_proof = if proof_result.is_err() && finish.is_ok() {
            Some(self.eof_cleanup_proof())
        } else {
            None
        };
        if let Some(Ok(proof)) = &eof_proof {
            self.cleaned = true;
            self.cleanup_proof = Some(proof.clone());
            proof_result = Ok(proof.clone());
            if let Some(lease) = self.lease.as_ref() {
                let token = format!("lease:{}:{}", lease.request_id, lease.generation);
                release = self.release_input(&token);
            }
        }
        let progress = json!({"session_id":self.binding.session_id,"cleanup_result":proof_result,
            "raw_cleanup_result":raw_cleanup_result,"eof_independent_proof":eof_proof,
            "normal_exit_observed":self.normal_exit,"active_owned_leases":usize::from(self.lease.is_some()),
            "lease_release":release,"helper_finish":finish,"observation_write":observed});
        let progress_saved = self.save(
            &format!("owned-cleanup-progress-{attempt:04}.json"),
            &progress,
        );
        if proof_result.is_err()
            || release.is_err()
            || finish.is_err()
            || observed.is_err()
            || progress_saved.is_err()
        {
            let mut error = RemoteError::unknown("WSLC_OWNED_CLEANUP_UNCONFIRMED");
            error.details["cleanup_progress"] = progress;
            error.details["progress_write"] = json!(progress_saved);
            return Err(error);
        }
        let proof = proof_result.unwrap();
        let value = json!({"container_cleanup":proof,"normal_exit_observed":self.normal_exit,"forced_cleanup":!self.normal_exit,
            "active_owned_leases":usize::from(self.lease.is_some()),"remaining_owned_processes":0,
            "hwnd_gone":true,"listener_absence_proven":true,"session_id":self.binding.session_id});
        self.save(&format!("owned-cleanup-{attempt:04}.json"), &value)
            .map_err(|cause| {
                let mut e = RemoteError::unknown("WSLC_CLEANUP_EVIDENCE_WRITE_FAILED");
                e.details["cause"] = json!(cause);
                e
            })?;
        self.cleanup_report = Some(value.clone());
        Ok(value)
    }
    fn observe_key_focus(&mut self, window: u64, widget: &str) -> Result<bool> {
        checked(
            self.key_focus_probe
                && window == self.binding.window_id
                && widget == "input_singleline",
            "UNSUPPORTED_KEY_FOCUS_OBSERVATION",
        )?;
        self.validate()?;
        let before = self
            .focus_sample(false)?
            .and_then(|v| v["sample_seq"].as_u64())
            .unwrap_or(0);
        let snapshot = self.request(&format!("/snap?w={window}&all=1"), false)?;
        exact_widget(&snapshot, window, widget)?;
        let sample = self
            .focus_sample(true)?
            .ok_or_else(|| RemoteError::refused("UNSUPPORTED_KEY_FOCUS_OBSERVATION"))?;
        checked(
            sample["sample_seq"].as_u64().is_some_and(|v| v > before),
            "STALE_KEY_FOCUS_OBSERVATION",
        )?;
        let focused = super::focus_probe::validate_sample(&sample, self.binding.pid, window, true)?;
        self.validate()?;
        self.save(&format!("focus-observation-{:04}.json",self.requests),&json!({"source":"TRUSTED_FIXTURE_SNAPSHOT_LOG_V1",
            "sample":sample,"session_id":self.binding.session_id,"session_generation":self.binding.generation,
            "executable_sha256":self.binding.executable_sha256,"observed_unix_ms":now_ms()}))?;
        Ok(focused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop_arbiter::{Registry, SafePoint, State};

    #[test]
    fn storage_receipt_refuses_monitor_only_wrong_scope_or_missing_hard_quota() {
        let good=json!({"schema":"toolkit-wslc-storage-admission-v1","host_free_bytes":20_000_000_000u64,
            "decision":{"status":"ADMITTED","max_bytes":120_000_000_000u64,"reserve_bytes":10_000_000_000u64},
            "capability":{"hard_limit_enforced":true,"limit_readback_bytes":120_000_000_000u64,
                "covers_all_writable_mounts":true,"kernel_write_refusal_observed":true,"eager_allocation":false}});
        storage_admission(&good).unwrap(); // synthetic contract, never hardware proof
        for field in ["hard_limit_enforced","limit_readback_bytes","covers_all_writable_mounts","kernel_write_refusal_observed","eager_allocation"] {
            let mut invalid=good.clone();invalid["capability"].as_object_mut().unwrap().remove(field);
            assert_eq!(storage_admission(&invalid).unwrap_err().code,"STORAGE_IDENTITY_NOT_VERIFIED");
        }
        let mut unsupported=good.clone();unsupported["decision"]["code"]=json!("STORAGE_QUOTA_UNSUPPORTED");
        assert_eq!(storage_admission(&unsupported).unwrap_err().code,"STORAGE_QUOTA_UNSUPPORTED");
        for path in ["max_bytes","reserve_bytes"] {
            let mut invalid=good.clone();invalid["decision"][path]=json!(1);
            assert!(storage_admission(&invalid).is_err());
        }
        let mut low=good;low["host_free_bytes"]=json!(9_999_999_999u64);assert!(storage_admission(&low).is_err());
    }

    fn monitored_soft_limit_receipt_v1_1() -> Value {
        json!({
            "schema":"toolkit-wslc-storage-admission-v1.1",
            "policy_id":"TOOLKIT_WSLC_STORAGE_POLICY_V1_1",
            "storage_enforcement":"monitored_soft_limit",
            "hard_quota_enforced":false,
            "host_free_bytes":11_073_741_824u64,
            "decision":{
                "status":"ADMITTED",
                "host_free_bytes":11_073_741_824u64,
                "max_bytes":120_000_000_000u64,
                "reserve_bytes":10_000_000_000u64,
                "usage_bytes":null,
                "level":"NEW_CONTAINER_NOT_YET_CREATED",
                "storage_enforcement":"monitored_soft_limit",
                "hard_quota_enforced":false
            },
            "capability":{
                "storage_enforcement":"monitored_soft_limit",
                "hard_limit_enforced":false,
                "limit_readback_bytes":null,
                "eager_allocation":false,
                "profile":"focus_trace71",
                "usage_status":"NEW_OWNED_CONTAINER_NOT_YET_CREATED",
                "inventory_verified":true,
                "guest_process_inventory_verified":true,
                "size_observation_available":true,
                "unexpected_writable_mounts":false,
                "scenario_growth_budget_bytes":1_073_741_824u64
            }
        })
    }

    fn remove_storage_field(value: &mut Value, pointer: &str) {
        let (parent, field) = pointer.rsplit_once('/').unwrap();
        let object = if parent.is_empty() {
            value.as_object_mut().unwrap()
        } else {
            value.pointer_mut(parent).unwrap().as_object_mut().unwrap()
        };
        object.remove(field).unwrap();
    }

    fn replace_storage_field(value: &mut Value, pointer: &str, replacement: Value) {
        *value.pointer_mut(pointer).unwrap() = replacement;
    }

    #[test]
    fn storage_receipt_v1_1_accepts_explicit_precreate_soft_limit_witness() {
        let good = monitored_soft_limit_receipt_v1_1();
        storage_admission(&good).unwrap();
    }

    #[test]
    fn storage_receipt_v1_1_requires_all_fields_with_exact_json_types() {
        let good = monitored_soft_limit_receipt_v1_1();
        for pointer in [
            "/policy_id",
            "/storage_enforcement",
            "/hard_quota_enforced",
            "/host_free_bytes",
            "/decision/status",
            "/decision/host_free_bytes",
            "/decision/max_bytes",
            "/decision/reserve_bytes",
            "/decision/usage_bytes",
            "/decision/level",
            "/decision/storage_enforcement",
            "/decision/hard_quota_enforced",
            "/capability/storage_enforcement",
            "/capability/hard_limit_enforced",
            "/capability/limit_readback_bytes",
            "/capability/eager_allocation",
            "/capability/profile",
            "/capability/usage_status",
            "/capability/inventory_verified",
            "/capability/guest_process_inventory_verified",
            "/capability/size_observation_available",
            "/capability/unexpected_writable_mounts",
            "/capability/scenario_growth_budget_bytes",
        ] {
            let mut missing = good.clone();
            remove_storage_field(&mut missing, pointer);
            assert!(storage_admission(&missing).is_err(), "accepted missing {pointer}");
        }

        for (pointer, wrong_type) in [
            ("/policy_id", json!(false)),
            ("/storage_enforcement", json!(true)),
            ("/hard_quota_enforced", json!(0)),
            ("/hard_quota_enforced", json!(null)),
            ("/host_free_bytes", json!("11073741824")),
            ("/decision/status", json!(true)),
            ("/decision/host_free_bytes", json!("11073741824")),
            ("/decision/max_bytes", json!("120000000000")),
            ("/decision/reserve_bytes", json!(false)),
            ("/decision/usage_bytes", json!(0)),
            ("/decision/level", json!(0)),
            ("/decision/storage_enforcement", json!(false)),
            ("/decision/hard_quota_enforced", json!(0)),
            ("/capability/storage_enforcement", json!(false)),
            ("/capability/hard_limit_enforced", json!(0)),
            ("/capability/hard_limit_enforced", json!(null)),
            ("/capability/limit_readback_bytes", json!(0)),
            ("/capability/eager_allocation", json!(0)),
            ("/capability/profile", json!(false)),
            ("/capability/usage_status", json!(null)),
            ("/capability/inventory_verified", json!(1)),
            ("/capability/guest_process_inventory_verified", json!("true")),
            ("/capability/size_observation_available", json!(null)),
            ("/capability/unexpected_writable_mounts", json!(0)),
            ("/capability/scenario_growth_budget_bytes", json!("1073741824")),
        ] {
            let mut invalid = good.clone();
            replace_storage_field(&mut invalid, pointer, wrong_type);
            assert!(storage_admission(&invalid).is_err(), "accepted wrong type at {pointer}");
        }
    }

    #[test]
    fn storage_receipt_v1_1_refuses_version_mode_and_witness_mismatches() {
        let good = monitored_soft_limit_receipt_v1_1();
        for (pointer, mismatch) in [
            ("/schema", json!("toolkit-wslc-storage-admission-v1")),
            ("/schema", json!("toolkit-wslc-storage-admission-v99")),
            ("/policy_id", json!("TOOLKIT_WSLC_STORAGE_POLICY_V1")),
            ("/storage_enforcement", json!("hard_quota")),
            ("/hard_quota_enforced", json!(true)),
            ("/host_free_bytes", json!(11_073_741_823u64)),
            ("/decision/status", json!("REFUSED")),
            ("/decision/host_free_bytes", json!(11_073_741_825u64)),
            ("/decision/max_bytes", json!(120_000_000_001u64)),
            ("/decision/reserve_bytes", json!(9_999_999_999u64)),
            ("/decision/usage_bytes", json!(0)),
            ("/decision/level", json!("NORMAL")),
            ("/decision/storage_enforcement", json!("hard_quota")),
            ("/decision/hard_quota_enforced", json!(true)),
            ("/capability/storage_enforcement", json!("hard_quota")),
            ("/capability/hard_limit_enforced", json!(true)),
            ("/capability/limit_readback_bytes", json!(120_000_000_000u64)),
            ("/capability/eager_allocation", json!(true)),
            ("/capability/profile", json!("other")),
            ("/capability/usage_status", json!("EXISTING_CONTAINER")),
            ("/capability/inventory_verified", json!(false)),
            ("/capability/guest_process_inventory_verified", json!(false)),
            ("/capability/size_observation_available", json!(false)),
            ("/capability/unexpected_writable_mounts", json!(true)),
            ("/capability/scenario_growth_budget_bytes", json!(1_073_741_823u64)),
        ] {
            let mut invalid = good.clone();
            replace_storage_field(&mut invalid, pointer, mismatch);
            assert!(storage_admission(&invalid).is_err(), "accepted mismatch at {pointer}");
        }

        let mut unsupported = good;
        unsupported["decision"]["code"] = json!("STORAGE_QUOTA_UNSUPPORTED");
        assert_eq!(
            storage_admission(&unsupported).unwrap_err().code,
            "STORAGE_QUOTA_UNSUPPORTED"
        );
    }

    #[test]
    fn wslc_geometry_binds_separate_exact_guest_and_rail_titles_to_approved_focus_source() {
        let mut expected = memory_profile_config().expected_identity;
        expected.executable_sha256 =
            "9DFA4EEC8D4FEE6CAEE509D4FF2ACCB5136FED3A1D64D2302F0E35FF623AA4CB".into();
        let tag = "toolkit-wslc-0123456789abcdef01234567";
        let guest = format!("Makepad [{tag}]");
        let rail = format!("{guest} (Ubuntu)");
        assert!(focus_geometry_titles(&expected, tag, &guest, &rail));
        assert!(focus_geometry_titles(&expected, tag, &guest, &guest));
        for wrong in [
            format!("{guest} (Other)"),
            format!("{rail} (Ubuntu)"),
            format!("foreign {rail}"),
        ] {
            assert!(!focus_geometry_titles(&expected, tag, &guest, &wrong));
        }
        assert!(!focus_geometry_titles(&expected, tag, &rail, &rail));
        assert!(!focus_geometry_titles(
            &expected,
            "toolkit-wslc-foreign",
            &guest,
            &rail
        ));
        expected.executable_sha256 = "A".repeat(64);
        assert!(!focus_geometry_titles(&expected, tag, &guest, &rail));
    }

    #[test]
    fn wslc_geometry_declares_nullable_x11_pid_without_claiming_owner_pid_as_observed() {
        let mut x: super::super::ObservedX11Geometry = serde_json::from_value(json!({
            "schema":"toolkit-wslc-x11-content-geometry-v1","display":":0","title":"synthetic",
            "expected_guest_pid":10,"pid_property":null,"identity_source":"APPROVED_LAUNCH_NONCE_AND_UNIQUE_TITLE",
            "window":11,"root":1,"client":{"x":0,"y":0,"width":100,"height":100},
            "frame":{"x":0,"y":0,"width":100,"height":100},"frame_extents":[0,0,0,0],
            "frame_source":"NET_FRAME_EXTENTS","frame_window":null})).unwrap();
        assert!(focus_geometry_pid(&x, 10));
        assert_eq!(
            serde_json::to_value(&x).unwrap()["pid_property"],
            Value::Null
        );
        x.identity_source = "NET_WM_PID_AND_UNIQUE_TITLE".into();
        assert!(!focus_geometry_pid(&x, 10));
        x.pid_property = Some(10);
        assert!(focus_geometry_pid(&x, 10));
        x.pid_property = Some(20);
        assert!(!focus_geometry_pid(&x, 10));
        x.identity_source = "APPROVED_LAUNCH_NONCE_AND_UNIQUE_TITLE".into();
        assert!(!focus_geometry_pid(&x, 10));
        x.pid_property = None;
        x.expected_guest_pid = 20;
        assert!(!focus_geometry_pid(&x, 10));
    }

    fn memory_profile_config() -> ApprovedWslcApp {
        ApprovedWslcApp {
            experimental_opt_in: true,
            source_commit: PINNED_SOURCE.into(),
            owner: "unit-owner".into(),
            runtime_directory: PathBuf::new(),
            admission_path: PathBuf::new(),
            python_executable: PathBuf::new(),
            helper_sha256: "F".repeat(64),
            expected_identity: ExpectedWslcIdentity {
                container_id: "a".repeat(64),
                image_id: format!("sha256:{}", "b".repeat(64)),
                executable: WSLC_MODULE_SHELL_EXECUTABLE.into(),
                executable_sha256: "C".repeat(64),
            },
            key_focus_probe: false,
            expected_memory_max: WSLC_FOCUS_MEMORY_MAX,
            module_shell_source_manifest_sha256: None,
            output_directory: PathBuf::new(),
        }
    }

    #[test]
    fn wslc_owner_accepts_only_fixed_focus_or_pinned_module_shell_memory() {
        let mut config = memory_profile_config();
        assert_eq!(approved_memory_max(&config).unwrap(), WSLC_FOCUS_MEMORY_MAX);
        config.expected_memory_max = WSLC_MODULE_SHELL_MEMORY_MAX;
        config.module_shell_source_manifest_sha256 = Some("A".repeat(64));
        assert_eq!(
            approved_memory_max(&config).unwrap(),
            WSLC_MODULE_SHELL_MEMORY_MAX
        );
        config.expected_memory_max += 1;
        assert_eq!(
            approved_memory_max(&config).unwrap_err().code,
            "WSLC_MEMORY_PROFILE_INVALID"
        );
        config.expected_memory_max = WSLC_MODULE_SHELL_MEMORY_MAX;
        config.module_shell_source_manifest_sha256 = None;
        assert_eq!(
            approved_memory_max(&config).unwrap_err().code,
            "WSLC_MEMORY_PROFILE_INVALID"
        );
        config.module_shell_source_manifest_sha256 = Some("a".repeat(64));
        assert_eq!(
            approved_memory_max(&config).unwrap_err().code,
            "WSLC_MEMORY_PROFILE_INVALID"
        );
    }

    #[test]
    fn wslc_request_local_guard_refuses_retired_and_changed_helper_before_exchange() {
        let output = rejected_frame_test_output();
        let helper = output.join("unit-helper.py");
        let bytes = b"# exact trusted test helper\n";
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&helper)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        let digest = format!("{:x}", Sha256::digest(bytes));
        check_live_helper(false, false, &helper, &digest).unwrap();
        for (cleaned, normal_exit) in [(true, false), (false, true), (true, true)] {
            // Staleness wins even if the helper is unreadable/untrusted.
            let error = check_live_helper(cleaned, normal_exit, &output.join("absent"), "invalid")
                .unwrap_err();
            assert_eq!(error.code, "STALE_PROCESS");
            assert_eq!(error.outcome, "NOT_DISPATCHED");
            assert!(!error.retry_safe);
        }
        let error = check_live_helper(false, false, &helper, &"0".repeat(64)).unwrap_err();
        assert_eq!(error.code, "WSLC_APPROVED_HELPER_BYTES_CHANGED");
        assert_eq!(error.outcome, "NOT_DISPATCHED");
        assert!(!error.retry_safe);
        fs::remove_file(&helper).unwrap(); // Only the exact file created above.
        assert_eq!(
            check_live_helper(false, false, &helper, &digest)
                .unwrap_err()
                .code,
            "WSLC_HELPER_READ_FAILED"
        );
        fs::remove_dir(&output).unwrap();
    }

    fn rejected_frame_fixture() -> (SessionBinding, Value, FrameReply) {
        let binding = SessionBinding {
            session_id: "unit-session".into(),
            owner: "unit-owner".into(),
            generation: 3,
            pid: 7,
            process_birth: "11".into(),
            executable: "/opt/proof/unit-fixture".into(),
            executable_sha256: "a".repeat(64),
            source_commit: PINNED_SOURCE.into(),
            window_id: 0,
            platform: "linux-wslc-owned-container".into(),
        };
        let path = "/tmp/makepad-remote/unit/grab-w0-1.png";
        let metadata = json!({"w":0,"sz":[875,600],"png":path,"f":9});
        let reply: FrameReply = serde_json::from_value(json!({
            "identity":{"schema":"toolkit-makepad-remote-wslc-identity-v1",
                "container_id":"b".repeat(64),"image_id":format!("sha256:{}","c".repeat(64)),
                "pid_namespace":"pid:[123]","pid":7,"process_start_ticks":"11",
                "executable":binding.executable,"executable_sha256":binding.executable_sha256,
                "listener_host":"127.0.0.1","listener_port":1234,"listener_inode":"22",
                "window_id":0,"rail_hwnd":33,"rail_pid":44,"rail_process_birth":"55",
                "rail_visible":false,"memory_max":1073741824u64,"cpu_max":"100000 100000"},
            "bytes_hex":"","guest_path":path,"modified_ms":12,
            "stat_before":"9|unit-time|66|regular file|1","stat_after":"9|unit-time|66|regular file|1",
            "guest_clock_before_ms":11,"guest_clock_after_ms":13,
        })).unwrap();
        (binding, metadata, reply)
    }

    fn rejected_frame_test_output() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "toolkit-wslc-rejected-unit-{}-{}-{sequence}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir(&path).unwrap(); // Exclusive; never adopt an existing directory.
        path
    }

    fn remove_rejected_frame_test_output(path: &Path, requests: &[u64]) {
        // Only exact test-created filenames; never recursive cleanup.
        for request in requests {
            for extension in ["png", "json"] {
                let file = path.join(format!(
                    "rejected-native-frame-request-{request:04}.{extension}"
                ));
                match fs::remove_file(file) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("owned unit artifact cleanup failed: {error}"),
                }
            }
        }
        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn wslc_rejected_frame_preserves_truncated_bytes_bindings_and_original_error() {
        let output = rejected_frame_test_output();
        let (binding, metadata, reply) = rejected_frame_fixture();
        let bytes = b"truncated";
        let mut original = inspect_png(bytes).err().unwrap();
        original.details["retained_detail"] = json!(true);
        let original_json = json!(&original);
        let error =
            preserve_rejected_frame(&output, 7, &binding, &metadata, &reply, bytes, 10, original);
        assert_eq!(error.code, "NATIVE_PNG_INVALID");
        assert_eq!(error.outcome, "NOT_DISPATCHED");
        assert!(!error.retry_safe);
        assert_eq!(error.details["retained_detail"], true);
        assert_eq!(
            error.details["rejected_native_frame"]["context_written"],
            true
        );
        assert_eq!(
            fs::read(output.join("rejected-native-frame-request-0007.png")).unwrap(),
            bytes
        );
        let raw = fs::read(output.join("rejected-native-frame-request-0007.json")).unwrap();
        assert!(raw.len() <= 65536);
        let context: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(context["status"], "REJECTED_NOT_ACCEPTED");
        assert_eq!(context["accepted"], false);
        assert_eq!(context["binding"], json!(binding));
        assert_eq!(context["observed_identity"], json!(reply.identity));
        assert_eq!(context["metadata"], metadata);
        assert_eq!(context["original_error"], original_json);
        assert_eq!(context["bytes"], bytes.len());
        assert_eq!(context["sha256"], format!("{:x}", Sha256::digest(bytes)));
        assert_eq!(context["source_stat_before"], reply.stat_before);
        assert_eq!(context["source_stat_after"], reply.stat_after);
        assert_eq!(context["guest_clock_before_ms"], 11);
        assert_eq!(context["guest_clock_after_ms"], 13);
        assert_eq!(context["modified_ms"], 12);
        assert_eq!(context["dispatched_at_unix_ms"], 10);
        assert!(context["observed_unix_ms"].as_u64().unwrap() > 0);
        assert!(!output.join("native-frame-0001.png").exists());
        remove_rejected_frame_test_output(&output, &[7]);
    }

    #[test]
    fn wslc_rejected_frame_collision_write_failure_and_bounds_preserve_primary() {
        let output = rejected_frame_test_output();
        let (binding, metadata, reply) = rejected_frame_fixture();
        let primary = || {
            let mut error = RemoteError::unknown("NATIVE_PNG_INVALID");
            error.details = json!(["original details"]);
            error
        };
        let check_primary = |error: &RemoteError| {
            assert_eq!(error.code, "NATIVE_PNG_INVALID");
            assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
            assert!(!error.retry_safe);
            assert_eq!(
                error.details["original_details"],
                json!(["original details"])
            );
            assert!(!error.details["rejected_native_frame"]["persistence_error"].is_null());
        };
        for (request, extension) in [(7, "png"), (8, "json")] {
            let sentinel = output.join(format!(
                "rejected-native-frame-request-{request:04}.{extension}"
            ));
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&sentinel)
                .unwrap()
                .write_all(b"existing unit artifact")
                .unwrap();
            let error = preserve_rejected_frame(
                &output,
                request,
                &binding,
                &metadata,
                &reply,
                b"truncated",
                10,
                primary(),
            );
            check_primary(&error);
            assert_eq!(fs::read(sentinel).unwrap(), b"existing unit artifact");
            assert_eq!(
                error.details["rejected_native_frame"]["context_written"],
                false
            );
            assert_eq!(
                error.details["rejected_native_frame"]["png_written"],
                request == 8
            );
        }
        let error = preserve_rejected_frame(
            &output.join("missing"),
            9,
            &binding,
            &metadata,
            &reply,
            b"truncated",
            10,
            primary(),
        );
        check_primary(&error);
        assert_eq!(error.details["rejected_native_frame"]["png_created"], false);
        for (bytes, metadata) in [
            (vec![0; 8 * 1024 * 1024 + 1], metadata),
            (b"truncated".to_vec(), json!({"padding":"x".repeat(65537)})),
        ] {
            let error = preserve_rejected_frame(
                &output,
                9,
                &binding,
                &metadata,
                &reply,
                &bytes,
                10,
                primary(),
            );
            check_primary(&error);
            assert_eq!(error.details["rejected_native_frame"]["png_created"], false);
        }
        assert!(
            !output
                .join("rejected-native-frame-request-0009.png")
                .exists()
        );
        assert!(
            !output
                .join("rejected-native-frame-request-0009.json")
                .exists()
        );
        remove_rejected_frame_test_output(&output, &[7, 8]);
    }

    fn semantic_lease_model() -> (Registry, Owner, Lease) {
        let mut registry = Registry::default();
        let owner = Owner {
            worker_id: "wslc-model-worker".into(),
            job_id: "wslc-model-job".into(),
            attempt_id: "wslc-model-attempt".into(),
            session_id: "wslc-model-session".into(),
            pid: 1,
            process_birth: 1,
        };
        let request = registry
            .request(
                owner.clone(),
                vec![Resource::SessionSemantic {
                    session_id: owner.session_id.clone(),
                }],
                1_000,
                input_lease_deadline(1_000).unwrap(),
            )
            .unwrap();
        let lease = registry.poll(request, &owner, 1_000).unwrap().unwrap();
        (registry, owner, lease)
    }

    #[test]
    fn wslc_input_lease_120s_deadline_survives_45s_without_heartbeat_renewal() {
        let (mut registry, owner, lease) = semantic_lease_model();
        assert_eq!(lease.deadline, 121_000);
        registry.validate(&lease, &owner, 46_000).unwrap();
        assert_eq!(
            registry.poll(lease.request_id, &owner, 46_000).unwrap(),
            Some(lease.clone())
        );
        registry.validate_storage().unwrap();
        for elapsed in [45_000, 90_000, 119_999] {
            registry.heartbeat(&lease, &owner, 1_000 + elapsed).unwrap();
            assert_eq!(registry.entries[0].heartbeat, 1_000 + elapsed);
            assert_eq!(registry.entries[0].deadline, 121_000);
            assert_eq!(registry.entries[0].generation, lease.generation);
        }
        assert_eq!(lease.deadline, 121_000);
        assert_eq!(
            registry.validate(&lease, &owner, 121_000).unwrap_err().code,
            "LEASE_EXPIRED"
        );
    }

    #[test]
    fn wslc_input_lease_expiry_fences_stale_release_and_deadline_overflow_refuses() {
        let (mut registry, owner, lease) = semantic_lease_model();
        registry.validate(&lease, &owner, 120_999).unwrap();
        assert_eq!(
            registry.validate(&lease, &owner, 121_000).unwrap_err().code,
            "LEASE_EXPIRED"
        );
        assert_eq!(registry.entries[0].state, State::ResourceQuarantined);
        assert!(registry.entries[0].generation > lease.generation);
        assert_eq!(registry.entries[0].acquired_at, Some(lease.acquired_at));
        assert_eq!(
            registry
                .heartbeat(&lease, &owner, 121_000)
                .unwrap_err()
                .code,
            "STALE_GENERATION"
        );
        assert_eq!(
            registry
                .release(&lease, &owner, &SafePoint::default(), 121_000)
                .unwrap_err()
                .code,
            "STALE_GENERATION"
        );
        registry.expire(121_001).unwrap();
        assert_eq!(registry.entries[0].state, State::ResourceQuarantined);
        assert_eq!(registry.entries[0].acquired_at, Some(lease.acquired_at));
        registry.validate_storage().unwrap();
        assert_eq!(input_lease_deadline(0).unwrap(), 120_000);
        assert_eq!(input_lease_deadline(u64::MAX - 120_000).unwrap(), u64::MAX);
        for now in [u64::MAX - 119_999, u64::MAX] {
            let error = input_lease_deadline(now).unwrap_err();
            assert_eq!(error.code, "INPUT_LOCK_DEADLINE_OVERFLOW");
            assert_eq!(error.outcome, "NOT_DISPATCHED");
        }
    }

    #[test]
    fn wslc_after_launch_refusal_is_unknown_and_complete_cleanup_is_conjunctive() {
        let error = after_launch(RemoteError::refused("WSLC_CONTAINER_ID_MISMATCH"));
        assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
        assert!(!error.retry_safe);
        assert_eq!(error.details["cause"]["outcome"], "NOT_DISPATCHED");
        let proof = json!({"container_stopped":true,"owned_helpers_gone":true,"rail_absent":true,
            "guest_process_gone":true,"listener_absent":true});
        assert!(cleanup_confirmed(&proof));
        for key in proof.as_object().unwrap().keys() {
            let mut failed = proof.clone();
            failed[key] = json!(false);
            assert!(!cleanup_confirmed(&failed));
        }
    }
    #[test]
    fn wslc_platform_hex_is_exact_and_bounded_without_runtime() {
        assert_eq!(decode_frame_hex("00aAFf").unwrap(), [0, 170, 255]);
        for value in ["", "0", "xx", "0g", "é"] {
            assert!(decode_frame_hex(value).is_err());
        }
        assert!(decode_frame_hex(&"0".repeat(16 * 1024 * 1024 + 2)).is_err());
    }
    #[test]
    fn wslc_platform_helper_error_never_leaks_message_or_claims_retry() {
        let e = unwrap_reply(
            json!({"ok":false,"error":{"code":"WSLC_CONNECT_FAILED","dispatched":false}}),
        )
        .unwrap_err();
        assert_eq!(e.outcome, "NOT_DISPATCHED");
        assert!(!e.retry_safe);
        let e = unwrap_reply(
            json!({"ok":false,"error":{"code":"WSLC_HTTP_TIMEOUT","dispatched":true}}),
        )
        .unwrap_err();
        assert_eq!(e.outcome, "OUTCOME_UNKNOWN");
        assert!(!e.retry_safe);
        for code in ["sensitive text", "WSLC_BAD\n", "NOT_PREFIXED"] {
            assert_eq!(
                unwrap_reply(json!({"ok":false,"error":{"code":code,"dispatched":false}}))
                    .unwrap_err()
                    .code,
                "WSLC_REPLY_ERROR_INVALID"
            );
        }
    }
    #[test]
    fn wslc_platform_guest_paths_do_not_use_windows_path_rules() {
        assert!(guest_path("/tmp/makepad-remote/app-12/grab-w0-1.png"));
        for p in [
            "/",
            "//tmp/app",
            "/tmp/../app",
            "/tmp/./app",
            "/tmp/app/",
            "C:\\app",
            "/tmp/a\n",
        ] {
            assert!(!guest_path(p));
        }
    }
}

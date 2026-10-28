//! Cooperative desktop leases; not a lock on human/foreign application input.
//! Only the trusted runtime creates owners, window bindings and lease handles.
pub mod model;
pub use model::*;

/// Arbiter refusal is infrastructure, never a product assertion or app timeout.
pub fn is_arbiter_failure(code: &str) -> bool {
    if code.starts_with("CLIPBOARD_") {
        return true;
    }
    code.starts_with("ARBITER_")
        || code.starts_with("INPUT_LOCK_")
        || code.starts_with("LEASE_")
        || code.starts_with("OWNER_")
        || matches!(
            code,
            "STALE_GENERATION"
                | "STALE_LEASE"
                | "UNKNOWN_REQUEST"
                | "RESOURCE_QUARANTINED"
                | "FOREGROUND_ACQUISITION_DENIED"
                | "WINDOW_NOT_FOCUSED"
                | "WINDOW_FOCUS_CONFLICT"
                | "WINDOW_IDENTITY_MISMATCH"
                | "UNSAFE_YIELD"
                | "UNSAFE_POINT"
                | "MISSING_GUI_RESOURCE"
                | "CLOCK_REGRESSION"
                | "INVALID_REGISTRY"
                | "GENERATION_EXHAUSTED"
                | "REQUEST_LIMIT"
                | "RECOVERY_OWNER_STILL_ALIVE"
                | "UNSUPPORTED_BACKGROUND_SAFE_HIDE"
        )
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::*;

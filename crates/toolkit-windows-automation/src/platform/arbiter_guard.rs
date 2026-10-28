use crate::desktop_arbiter::{
    clock_ms, current_owner, observe_safe_point, owned_window, DesktopArbiter, Entry, Lease, Owner,
    Resource, State,
};
use std::sync::atomic::AtomicBool;

const LEASE_TIMEOUT_MS: u64 = 60_000;

// Arbiter/native identity observation may block. Dispatch authority must still
// be valid AFTER it completes, independently of the cleanup reservation.
fn checked_request_boundary(
    control: Option<&crate::request_control::RequestControl>,
    observe: impl FnOnce() -> Result<(), crate::desktop_arbiter::ArbiterError>,
) -> Result<(), crate::desktop_arbiter::ArbiterError> {
    if let Some(control) = control { control.check()?; }
    observe()?;
    if let Some(control) = control { control.check()?; }
    Ok(())
}

pub(super) struct DesktopArbiterRuntime {
    arbiter: DesktopArbiter,
    worker_id: String,
    job_id: String,
    attempt_id: String,
    canonical_session: Option<String>,
    pub(super) request_control: Option<crate::request_control::RequestControl>,
}

impl DesktopArbiterRuntime {
    pub(super) fn new(
        worker_id: &str,
        job_id: &str,
        attempt_id: &str,
    ) -> Result<Self, crate::desktop_arbiter::ArbiterError> {
        Ok(Self {
            arbiter: DesktopArbiter::open()?,
            worker_id: worker_id.to_owned(),
            job_id: job_id.to_owned(),
            attempt_id: attempt_id.to_owned(),
            canonical_session: None,
            request_control: None,
        })
    }

    pub(super) fn matches(&self, worker_id: &str, job_id: &str, attempt_id: &str) -> bool {
        self.worker_id == worker_id && self.job_id == job_id && self.attempt_id == attempt_id
    }
    pub(super) fn bind_session(
        &mut self,
        session: &str,
    ) -> Result<(), crate::desktop_arbiter::ArbiterError> {
        if session.trim().is_empty()
            || session.len() > 256
            || self
                .canonical_session
                .as_ref()
                .is_some_and(|id| id != session)
        {
            return Err(crate::desktop_arbiter::ArbiterError {
                code: "OWNER_MISMATCH".into(),
                message: "canonical session cannot be empty or rebound".into(),
            });
        }
        self.canonical_session = Some(session.into());
        Ok(())
    }
}

pub(super) struct DesktopArbiterGuard {
    arbiter: DesktopArbiter,
    lease: Lease,
    owner: Owner,
    owns_lease: bool,
    input_state_uncertain: bool,
    window_resource: Resource,
    _logical_scope: Option<Box<DesktopArbiterGuard>>,
    request_control: Option<crate::request_control::RequestControl>,
}

/// Opaque reservation for trusted runtime code that performs physical input
/// outside this backend. Dropping it releases only after a safe-point proof.
pub struct DesktopInputReservation {
    guard: DesktopArbiterGuard,
}

impl DesktopInputReservation {
    pub(super) fn new(guard: DesktopArbiterGuard) -> Self {
        Self { guard }
    }

    /// Fence the grant if the caller cannot prove that its input batch ended
    /// with every key/button released.
    pub fn mark_input_state_uncertain(&mut self) {
        self.guard.mark_input_state_uncertain();
    }

    /// External trusted input callers must fence-check immediately before each
    /// dispatch. A reservation is not authority to send events after its deadline.
    pub fn validate_before_dispatch(&self) -> Result<(), crate::desktop_arbiter::ArbiterError> {
        self.guard.validate_before_dispatch()
    }
}

impl DesktopArbiterGuard {
    pub(super) fn acquire(
        runtime: &DesktopArbiterRuntime,
        window_id: &str,
        hwnd: u64,
        process_id: u32,
        window_process_birth: u64,
    ) -> Result<Self, crate::desktop_arbiter::ArbiterError> {
        Self::acquire_kind(
            runtime,
            window_id,
            hwnd,
            process_id,
            window_process_birth,
            true,
        )
    }

    pub(super) fn acquire_window(
        runtime: &DesktopArbiterRuntime,
        window_id: &str,
        hwnd: u64,
        process_id: u32,
        birth: u64,
    ) -> Result<Self, crate::desktop_arbiter::ArbiterError> {
        Self::acquire_kind(runtime, window_id, hwnd, process_id, birth, false)
    }

    fn acquire_kind(
        runtime: &DesktopArbiterRuntime,
        window_id: &str,
        hwnd: u64,
        process_id: u32,
        window_process_birth: u64,
        physical: bool,
    ) -> Result<Self, crate::desktop_arbiter::ArbiterError> {
        if let Some(control) = &runtime.request_control { control.check()?; }
        let window_resource = owned_window(hwnd, process_id, window_process_birth)?;
        let session_id = runtime
            .canonical_session
            .clone()
            .unwrap_or_else(|| format!("backend-window:{window_id}"));
        let owner = current_owner(
            &runtime.worker_id,
            &runtime.job_id,
            &runtime.attempt_id,
            &session_id,
        )?;

        let registry = runtime.arbiter.inspect_arbiter()?;
        let existing = if physical {
            lookup_runtime_lease(&registry, &owner, &window_resource)?
        } else {
            lookup_logical_lease(&registry, &owner, &window_resource)
        };
        if let Some((lease, state)) = existing {
            runtime.arbiter.validate(&lease, &lease.owner)?;
            if state == State::Leased {
                runtime.arbiter.begin_gui(&lease, &lease.owner)?;
            }
            runtime.arbiter.borrow_reservation(&lease, &lease.owner)?;
            let lease_owner = lease.owner.clone();
            return Ok(Self {
                arbiter: runtime.arbiter.clone(),
                lease,
                owner: lease_owner,
                owns_lease: false,
                input_state_uncertain: false,
                window_resource,
                _logical_scope: None,
                request_control: runtime.request_control.clone(),
            });
        }

        let wait_ms = runtime.request_control.as_ref()
            .map(|control| control.remaining().as_millis().min(LEASE_TIMEOUT_MS as u128) as u64)
            .unwrap_or(LEASE_TIMEOUT_MS);
        let deadline = clock_ms().checked_add(wait_ms).ok_or_else(|| {
            crate::desktop_arbiter::ArbiterError {
                code: "INVALID_DEADLINE".into(),
                message: "desktop lease deadline overflowed".into(),
            }
        })?;
        let mut logical_scope = None;
        let (request, owner) = if physical {
            let parent = if let Some((parent, _)) =
                lookup_logical_lease(&registry, &owner, &window_resource)
            {
                parent
            } else {
                // Window FIFO cannot occupy the global desktop queue. Own
                // logical scope first, then queue its short input phase.
                let scope = Self::acquire_kind(
                    runtime,
                    window_id,
                    hwnd,
                    process_id,
                    window_process_birth,
                    false,
                )?;
                let parent = scope.lease.clone();
                logical_scope = Some(Box::new(scope));
                parent
            };
            let request = runtime.arbiter.request_input_continuation(
                &parent,
                &parent.owner,
                deadline.min(parent.deadline),
            )?;
            (request, parent.owner)
        } else {
            (
                runtime.arbiter.request_lease(
                    vec![
                        window_resource.clone(),
                        Resource::SessionSemantic { session_id },
                    ],
                    &owner,
                    deadline,
                )?,
                owner,
            )
        };
        let not_cancelled = AtomicBool::new(false);
        let cancelled = runtime.request_control.as_ref()
            .map(|control| control.cancelled.as_ref()).unwrap_or(&not_cancelled);
        let lease = runtime.arbiter.wait_lease(request, &owner, cancelled)?;
        let guard = Self {
            arbiter: runtime.arbiter.clone(),
            lease,
            owner,
            owns_lease: true,
            input_state_uncertain: false,
            window_resource,
            _logical_scope: logical_scope,
            request_control: runtime.request_control.clone(),
        };
        if let Err(error) = guard.arbiter.begin_gui(&guard.lease, &guard.owner) {
            drop(guard);
            return Err(error);
        }
        if let Some(control) = &guard.request_control { control.check()?; }
        Ok(guard)
    }

    pub(super) fn mark_input_state_uncertain(&mut self) {
        self.input_state_uncertain = true;
    }

    pub(super) fn validate_before_dispatch(
        &self,
    ) -> Result<(), crate::desktop_arbiter::ArbiterError> {
        checked_request_boundary(self.request_control.as_ref(), || {
            self.arbiter.validate(&self.lease, &self.owner)?;
            if let Resource::WindowMutation { hwnd, pid, process_birth } = self.window_resource {
                owned_window(hwnd, pid, process_birth)?;
            }
            Ok(())
        })
    }

    pub(super) fn require_clipboard_transaction(
        &self,
    ) -> Result<(), crate::desktop_arbiter::ArbiterError> {
        self.arbiter.validate(&self.lease, &self.owner)?;
        let registry = self.arbiter.inspect_arbiter()?;
        if registry.entries.iter().any(|entry| {
            entry.request_id == self.lease.request_id
                && entry.generation == self.lease.generation
                && entry.owner == self.owner
                && entry.clipboard_pending
                && entry.resources.contains(&Resource::SystemClipboard)
        }) {
            return Ok(());
        }
        Err(crate::desktop_arbiter::ArbiterError {
            code: "CLIPBOARD_TRANSACTION_REQUIRED".into(),
            message: "opt-in clipboard input needs a trusted transaction with observed completion"
                .into(),
        })
    }
}

impl Drop for DesktopArbiterGuard {
    fn drop(&mut self) {
        if self.input_state_uncertain {
            let _ = self
                .arbiter
                .quarantine_uncertain_lease(&self.lease, &self.owner);
            return;
        }

        if !self.owns_lease {
            let _ = self.arbiter.return_reservation(&self.lease, &self.owner);
            return;
        }

        let proof = if self.lease.resources.contains(&Resource::DesktopInput)
            || self.lease.resources.contains(&Resource::SystemClipboard)
        {
            observe_safe_point(false, false, false, false, false)
        } else {
            // A window-only semantic scope never sent global input; another
            // owner's held keyboard is not a reason to quarantine this window.
            crate::desktop_arbiter::SafePoint::default()
        };
        // An unsafe OS observation fences this grant for independent recovery;
        // never synthesize a global key-up to make the proof appear safe.
        if !proof.safe_for_release() {
            let _ = self
                .arbiter
                .quarantine_uncertain_lease(&self.lease, &self.owner);
            return;
        }

        // If persistence or lease validation fails, the registry continues to
        // hold this grant. The backend has no authority to force-release it.
        if self
            .arbiter
            .release_lease(&self.lease, &self.owner, &proof)
            .is_err()
        {
            let _ = self
                .arbiter
                .quarantine_uncertain_lease(&self.lease, &self.owner);
        }
    }
}

fn same_runtime(entry: &Entry, current: &Owner) -> bool {
    entry.owner.worker_id == current.worker_id
        && entry.owner.job_id == current.job_id
        && entry.owner.attempt_id == current.attempt_id
        && entry.owner.pid == current.pid
        && entry.owner.process_birth == current.process_birth
        && entry.owner.session_id == current.session_id
}

fn lookup_logical_lease(
    registry: &crate::desktop_arbiter::Registry,
    current: &Owner,
    window: &Resource,
) -> Option<(Lease, State)> {
    registry
        .entries
        .iter()
        .find(|entry| {
            same_runtime(entry, current)
                && matches!(entry.state, State::Leased | State::GuiActive)
                && entry.acquired_at.is_some()
                && entry.resources.contains(window)
        })
        .map(|entry| (lease_from_entry(entry), entry.state))
}

fn bound_window(
    registry: &crate::desktop_arbiter::Registry,
    entry: &Entry,
    window: &Resource,
) -> bool {
    entry.resources.contains(window)
        || entry.continuation_of.is_some_and(|(id, generation)| {
            registry.entries.iter().any(|parent| {
                parent.request_id == id
                    && parent.generation == generation
                    && parent.owner == entry.owner
                    && parent.acquired_at.is_some()
                    && matches!(parent.state, State::Leased | State::GuiActive)
                    && parent.resources.contains(window)
            })
        })
}

fn lookup_runtime_lease(
    registry: &crate::desktop_arbiter::Registry,
    current: &Owner,
    window_resource: &Resource,
) -> Result<Option<(Lease, State)>, crate::desktop_arbiter::ArbiterError> {
    if registry.entries.iter().any(|entry| {
        entry.acquired_at.is_some()
            && same_runtime(entry, current)
            && entry.resources.contains(&Resource::DesktopInput)
            && !bound_window(registry, entry, window_resource)
    }) {
        return Err(crate::desktop_arbiter::ArbiterError {
            code:"LEASE_WINDOW_MISMATCH".into(),message:"release the retained grant and bind the intended owned window before reacquiring; never queue behind own desktop lease".into(),
        });
    }
    let entry = registry.entries.iter().find(|entry| {
        matches!(entry.state, State::Leased | State::GuiActive)
            && entry.acquired_at.is_some()
            && same_runtime(entry, current)
            && entry.resources.contains(&Resource::DesktopInput)
            && bound_window(registry, entry, window_resource)
    });
    Ok(entry.map(|entry| (lease_from_entry(entry), entry.state)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_during_native_validation_refuses_dispatch_authority() {
        let request = crate::request_control::RequestControl::new(std::time::Duration::from_secs(60));
        let backend = request.for_native_cleanup_reservation();
        let observed = std::cell::Cell::new(false);
        let error = checked_request_boundary(Some(&backend), || {
            observed.set(true);
            request.cancel();
            Ok(())
        }).unwrap_err();
        assert!(observed.get());
        assert_eq!(error.code,"REQUEST_CANCELLED");
    }
    #[test]
    fn expired_request_refuses_before_native_validation_with_cleanup_budget_remaining() {
        let request = crate::request_control::RequestControl::new(std::time::Duration::ZERO);
        let backend = request.for_native_cleanup_reservation();
        let observed = std::cell::Cell::new(false);
        let error = checked_request_boundary(Some(&backend), || {
            observed.set(true);
            Ok(())
        }).unwrap_err();
        assert!(!observed.get());
        assert_eq!(error.code,"REQUEST_DEADLINE_EXCEEDED");
    }
    #[test]
    fn independent_canonical_session_cannot_borrow_matching_runtime_and_window() {
        let a = Owner {
            worker_id: "w".into(),
            job_id: "j".into(),
            attempt_id: "a".into(),
            session_id: "session-a".into(),
            pid: 1,
            process_birth: 1,
        };
        let b = Owner {
            session_id: "session-b".into(),
            ..a.clone()
        };
        let window = Resource::WindowMutation {
            hwnd: 1,
            pid: 2,
            process_birth: 2,
        };
        let mut r = crate::desktop_arbiter::Registry::default();
        let id = r
            .request(
                a.clone(),
                vec![Resource::DesktopInput, window.clone()],
                0,
                100,
            )
            .unwrap();
        r.poll(id, &a, 0).unwrap().unwrap();
        assert!(lookup_runtime_lease(&r, &a, &window).unwrap().is_some());
        assert!(lookup_runtime_lease(&r, &b, &window).unwrap().is_none());
        assert!(lookup_logical_lease(&r, &b, &window).is_none());
    }
    #[test]
    fn incompatible_owned_window_refuses_without_queuing_behind_self() {
        let owner = Owner {
            worker_id: "worker".into(),
            job_id: "job".into(),
            attempt_id: "attempt".into(),
            session_id: "session".into(),
            pid: 1,
            process_birth: 1,
        };
        let main = Resource::WindowMutation {
            hwnd: 1,
            pid: 2,
            process_birth: 2,
        };
        let dialog = Resource::WindowMutation {
            hwnd: 2,
            pid: 2,
            process_birth: 2,
        };
        let mut registry = crate::desktop_arbiter::Registry::default();
        let request = registry
            .request(
                owner.clone(),
                vec![Resource::DesktopInput, main.clone()],
                0,
                100,
            )
            .unwrap();
        registry.poll(request, &owner, 0).unwrap().unwrap();
        assert!(lookup_runtime_lease(&registry, &owner, &main)
            .unwrap()
            .is_some());
        assert_eq!(
            lookup_runtime_lease(&registry, &owner, &dialog)
                .unwrap_err()
                .code,
            "LEASE_WINDOW_MISMATCH"
        );
        assert_eq!(registry.entries.len(), 1);
    }
}

fn lease_from_entry(entry: &Entry) -> Lease {
    Lease {
        request_id: entry.request_id,
        generation: entry.generation,
        owner: entry.owner.clone(),
        resources: entry.resources.clone(),
        acquired_at: entry
            .acquired_at
            .expect("borrowed desktop leases must have an acquisition time"),
        deadline: entry.deadline,
    }
}

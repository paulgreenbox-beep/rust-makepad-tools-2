//! Trusted transport cancellation/deadline, not an AI-selected input policy.
use crate::desktop_arbiter::ArbiterError;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) struct RequestControl {
    pub(crate) cancelled: Arc<AtomicBool>,
    deadline: Instant,
    // A native guard needs time to retire an already acquired reservation even
    // when the request expires. This never extends dispatch authority.
    native_reservation_deadline: Option<Instant>,
}

impl RequestControl {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + timeout,
            native_reservation_deadline: None,
        }
    }
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
    pub(crate) fn remaining(&self) -> Duration {
        self.native_reservation_deadline.unwrap_or(self.deadline)
            .saturating_duration_since(Instant::now())
    }
    pub(crate) fn for_native_cleanup_reservation(&self) -> Self {
        let mut scoped = self.clone();
        // Existing Windows backend caps every reservation at 60 seconds.
        // Keep that cap; retain this request's original absolute deadline and
        // shared cancellation flag for every validate-before-dispatch check.
        scoped.native_reservation_deadline = Some(Instant::now() + Duration::from_secs(60));
        scoped
    }
    pub(crate) fn check(&self) -> Result<(), ArbiterError> {
        let code = if self.cancelled.load(Ordering::SeqCst) {
            "REQUEST_CANCELLED"
        } else if self.deadline.saturating_duration_since(Instant::now()).is_zero() {
            "REQUEST_DEADLINE_EXCEEDED"
        } else {
            return Ok(());
        };
        Err(ArbiterError {
            code: code.into(),
            message: "trusted request cancelled or expired; no new dispatch is authorized".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_cleanup_reservation_never_extends_expired_dispatch_authority() {
        let request = RequestControl::new(Duration::ZERO);
        let backend = request.for_native_cleanup_reservation();
        assert!(request.remaining().is_zero());
        assert!(backend.remaining()>Duration::ZERO && backend.remaining()<=Duration::from_secs(60));
        assert_eq!(request.check().unwrap_err().code,"REQUEST_DEADLINE_EXCEEDED");
        assert_eq!(backend.check().unwrap_err().code,"REQUEST_DEADLINE_EXCEEDED");
    }
    #[test]
    fn native_cleanup_reservation_shares_cancellation_without_renewing_request() {
        let request = RequestControl::new(Duration::from_secs(1));
        let backend = request.for_native_cleanup_reservation();
        assert!(Arc::ptr_eq(&request.cancelled,&backend.cancelled));
        assert_eq!(request.deadline,backend.deadline);
        request.cancel();
        assert_eq!(backend.check().unwrap_err().code,"REQUEST_CANCELLED");
        assert!(request.remaining()<=Duration::from_secs(1));
    }
}

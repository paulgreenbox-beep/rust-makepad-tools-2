//! Deterministic desktop resource arbitration; no OS calls, clocks, or persistence.
//!
//! The native owner must authenticate process/window/session identities, serialize
//! registry access, and independently observe every `SafePoint`. Deserializing a
//! registry or constructing a lease/proof does not confer authority. These public
//! fields are a trusted persistence/inspection contract, not an untrusted loader.
//! `now`, deadlines, and heartbeat ages use the same trusted caller clock (the
//! native adapter currently uses Unix milliseconds). Observed timestamps cannot
//! go backward; clock regression fails closed rather than advancing a lease.
//!
//! Resource classes are independent: input and clipboard are individually global,
//! window mutations conflict by HWND (even with a different claimed PID/birth),
//! semantic operations conflict only within the same session, and background
//! compute never conflicts. The native adapter must request every resource an
//! operation needs. Grants are atomic and earlier conflicting waiters cannot be
//! bypassed. A yielded entry releases its entire grant; resuming needs a new request.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, error::Error, fmt};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_REQUESTS: usize = 4096;
pub const MAX_EVENTS: usize = 10_000;

// FILETIME births exceed JavaScript's integer precision. Keep exact identity in
// persisted/inspected JSON; native comparisons still use checked u64 values.
mod birth_string {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Owner {
    pub worker_id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub session_id: String,
    pub pid: u32,
    #[serde(with = "birth_string")]
    pub process_birth: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Resource {
    DesktopInput,
    SystemClipboard,
    WindowMutation {
        hwnd: u64,
        pid: u32,
        #[serde(with = "birth_string")]
        process_birth: u64,
    },
    SessionSemantic {
        session_id: String,
    },
    BackgroundCompute,
}

impl Resource {
    pub fn conflicts_with(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::DesktopInput, Self::DesktopInput)
            | (Self::SystemClipboard, Self::SystemClipboard) => true,
            (Self::WindowMutation { hwnd: a, .. }, Self::WindowMutation { hwnd: b, .. }) => a == b,
            (Self::SessionSemantic { session_id: a }, Self::SessionSemantic { session_id: b }) => {
                a == b
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Queued,
    WaitingResources,
    Leased,
    GuiActive,
    Quiescing,
    BackgroundRunning,
    ResumeQueued,
    Verifying,
    Completed,
    Cancelled,
    TimedOut,
    OwnerLost,
    Recovering,
    ResourceQuarantined,
    FailTestInfra,
}

impl State {
    fn waiting(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::WaitingResources | Self::ResumeQueued
        )
    }

    fn live_lease(self) -> bool {
        matches!(self, Self::Leased | Self::GuiActive)
    }

    fn watches_owner(self) -> bool {
        self.waiting()
            || self.live_lease()
            || self == Self::BackgroundRunning
            || matches!(self, Self::Quiescing | Self::Verifying)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub request_id: u64,
    pub generation: u64,
    pub owner: Owner,
    pub resources: Vec<Resource>,
    pub state: State,
    #[serde(default)]
    pub clipboard_pending: bool,
    #[serde(default)]
    pub active_reservations: u32,
    /// Trusted continuation of a retained logical grant, never AI-supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_of: Option<(u64, u64)>,
    #[serde(default)]
    pub logical_background: bool,
    pub queued_at: u64,
    /// Present while resources remain owned, including during quarantine.
    /// Cleared only after a safe release/yield/recovery, never by owner loss.
    pub acquired_at: Option<u64>,
    pub deadline: u64,
    pub heartbeat: u64,
}

impl Entry {
    fn holds_resources(&self) -> bool {
        self.acquired_at.is_some()
    }

    fn lease(&self) -> Lease {
        Lease {
            request_id: self.request_id,
            generation: self.generation,
            owner: self.owner.clone(),
            resources: self.resources.clone(),
            acquired_at: self.acquired_at.expect("only granted entries issue leases"),
            deadline: self.deadline,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub timestamp: u64,
    pub request: u64,
    pub state: State,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lease {
    pub request_id: u64,
    pub generation: u64,
    pub owner: Owner,
    pub resources: Vec<Resource>,
    pub acquired_at: u64,
    pub deadline: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafePoint {
    pub held_buttons: bool,
    pub held_modifiers: bool,
    pub pending_focus_action: bool,
    pub clipboard_transaction: bool,
    /// Must come from an independent native observation, not a worker claim.
    pub background_observed: bool,
}

impl SafePoint {
    pub fn safe_for_release(&self) -> bool {
        !self.held_buttons
            && !self.held_modifiers
            && !self.pending_focus_action
            && !self.clipboard_transaction
    }

    pub fn safe_for_yield(&self) -> bool {
        self.safe_for_release() && self.background_observed
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArbiterError {
    pub code: String,
    pub message: String,
}

impl ArbiterError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ArbiterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl Error for ArbiterError {}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Registry {
    pub schema_version: u32,
    pub next_id: u64,
    /// Bounded retained requests. The native persistence owner may compact only
    /// finished entries that no longer hold resources, preserving `next_id`.
    pub entries: Vec<Entry>,
    pub events: Vec<Event>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            next_id: 1,
            entries: vec![],
            events: vec![],
        }
    }
}

impl Registry {
    /// Structural validation for trusted persistence before granting resources.
    /// This cannot authenticate a file, its writer, an owner, or a safe-point
    /// observation; those remain the native persistence controller's obligations.
    pub fn validate_storage(&self) -> Result<(), ArbiterError> {
        let invalid = |message: &str| ArbiterError::new("INVALID_REGISTRY", message);
        if self.schema_version != SCHEMA_VERSION
            || self.next_id == 0
            || self.entries.len() > MAX_REQUESTS
            || self.events.len() > MAX_EVENTS
        {
            return Err(invalid("invalid schema, next ID, or storage bounds"));
        }
        let mut ids = BTreeSet::new();
        for entry in &self.entries {
            if entry.active_reservations > 256
                || (entry.active_reservations != 0 && !entry.holds_resources())
            {
                return Err(invalid(
                    "borrowed reservations require a held grant and are bounded",
                ));
            }
            if entry.request_id == 0
                || entry.request_id >= self.next_id
                || !ids.insert(entry.request_id)
                || entry.generation == 0
            {
                return Err(invalid(
                    "request IDs must be unique/nonzero/below next_id; generations nonzero",
                ));
            }
            check_owner(&entry.owner).map_err(|_| invalid("invalid stored owner identity"))?;
            check_resources(&entry.resources)
                .map_err(|_| invalid("invalid stored resource set"))?;
            if entry.resources.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(invalid("stored resources must be canonical and unique"));
            }
            if let Some((parent, generation)) = entry.continuation_of {
                if parent == 0
                    || parent >= entry.request_id
                    || generation == 0
                    || entry.resources != vec![Resource::DesktopInput, Resource::SystemClipboard]
                {
                    return Err(invalid(
                        "continuation must reference an earlier logical fence and only global input resources",
                    ));
                }
                if entry.holds_resources() || entry.state.waiting() {
                    let parent = self
                        .entries
                        .iter()
                        .find(|candidate| candidate.request_id == parent)
                        .ok_or_else(|| invalid("live continuation parent missing"))?;
                    if parent.owner != entry.owner
                        || entry.deadline > parent.deadline
                        || parent.resources.iter().any(|r| {
                            !matches!(
                                r,
                                Resource::WindowMutation { .. } | Resource::SessionSemantic { .. }
                            )
                        })
                    {
                        return Err(invalid(
                            "continuation parent identity/resources/deadline inconsistent",
                        ));
                    }
                }
            }
            if entry.deadline <= entry.queued_at
                || entry.heartbeat < entry.queued_at
                || entry.acquired_at.is_some_and(|at| {
                    at < entry.queued_at || at >= entry.deadline || at > entry.heartbeat
                })
            {
                return Err(invalid(
                    "stored deadline/acquisition/heartbeat timestamps are inconsistent",
                ));
            }
            let must_hold = matches!(
                entry.state,
                State::Leased
                    | State::GuiActive
                    | State::Quiescing
                    | State::Verifying
                    | State::Recovering
                    | State::ResourceQuarantined
            );
            let must_not_hold = entry.state.waiting()
                || matches!(
                    entry.state,
                    State::BackgroundRunning
                        | State::Completed
                        | State::Cancelled
                        | State::TimedOut
                        | State::OwnerLost
                );
            if (must_hold && !entry.holds_resources()) || (must_not_hold && entry.holds_resources())
            {
                return Err(invalid(
                    "state and current resource ownership are inconsistent",
                ));
            }
            if entry.clipboard_pending
                && (!entry
                    .resources
                    .iter()
                    .any(|resource| matches!(resource, Resource::SystemClipboard))
                    || !entry.holds_resources()
                    || !matches!(
                        entry.state,
                        State::Leased
                            | State::GuiActive
                            | State::Recovering
                            | State::ResourceQuarantined
                            | State::FailTestInfra
                    ))
            {
                return Err(invalid(
                    "pending clipboard transaction requires a held clipboard grant and cannot outlive its lease",
                ));
            }
            if matches!(
                entry.state,
                State::Quiescing
                    | State::BackgroundRunning
                    | State::Verifying
                    | State::Completed
                    | State::Cancelled
                    | State::TimedOut
                    | State::OwnerLost
                    | State::Recovering
                    | State::ResourceQuarantined
            ) && entry.generation < 2
            {
                return Err(invalid(
                    "invalidated or released entries must have a fenced generation",
                ));
            }
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.holds_resources()
                && self.entries[index + 1..].iter().any(|other| {
                    other.holds_resources() && conflicting(&entry.resources, &other.resources)
                })
            {
                return Err(invalid("multiple stored grants hold conflicting resources"));
            }
        }
        if self.events.iter().any(|event| {
            event.request == 0 || event.request >= self.next_id || event.reason.trim().is_empty()
        }) || self
            .events
            .windows(2)
            .any(|pair| pair[0].timestamp > pair[1].timestamp)
        {
            return Err(invalid(
                "stored event IDs, reasons, or timestamp order are invalid",
            ));
        }
        Ok(())
    }

    pub fn request(
        &mut self,
        owner: Owner,
        mut resources: Vec<Resource>,
        now: u64,
        deadline: u64,
    ) -> Result<u64, ArbiterError> {
        check_owner(&owner)?;
        check_resources(&resources)?;
        self.check_clock(now)?;
        if deadline <= now {
            return Err(ArbiterError::new(
                "INVALID_DEADLINE",
                "deadline must be after now",
            ));
        }
        if self.entries.len() >= MAX_REQUESTS {
            // Compact only fenced, terminal, unheld history. Keep queued,
            // yielded and quarantined grants, FIFO order, and monotonic IDs.
            let referenced: BTreeSet<_> = self
                .entries
                .iter()
                .filter(|entry| entry.holds_resources() || entry.state.waiting())
                .filter_map(|entry| entry.continuation_of.map(|(id, _)| id))
                .collect();
            self.entries.retain(|entry| {
                entry.acquired_at.is_some()
                    || referenced.contains(&entry.request_id)
                    || entry.clipboard_pending
                    || entry.active_reservations != 0
                    || !matches!(
                        entry.state,
                        State::Completed | State::Cancelled | State::TimedOut | State::OwnerLost
                    )
            });
            if self.entries.len() >= MAX_REQUESTS {
                return Err(ArbiterError::new(
                    "REQUEST_LIMIT",
                    "active/queued request limit reached",
                ));
            }
        }
        let id = self.next_id;
        if id == 0 || self.entries.iter().any(|e| e.request_id >= id) {
            return Err(ArbiterError::new(
                "INVALID_REQUEST_ID",
                "next_id must be nonzero and unused",
            ));
        }
        let next = id
            .checked_add(1)
            .ok_or_else(|| ArbiterError::new("REQUEST_ID_EXHAUSTED", "request IDs cannot wrap"))?;
        self.expire(now)?;
        resources.sort();
        self.next_id = next;
        self.entries.push(Entry {
            request_id: id,
            generation: 1,
            owner,
            resources,
            state: State::Queued,
            clipboard_pending: false,
            active_reservations: 0,
            continuation_of: None,
            logical_background: false,
            queued_at: now,
            acquired_at: None,
            deadline,
            heartbeat: now,
        });
        self.record(self.entries.len() - 1, now, "request queued");
        Ok(id)
    }

    pub fn poll(
        &mut self,
        request_id: u64,
        owner: &Owner,
        now: u64,
    ) -> Result<Option<Lease>, ArbiterError> {
        self.validate_storage()?;
        let index = self.owned_index(request_id, owner)?;
        self.check_clock(now)?;
        self.expire(now)?;
        let entry = &self.entries[index];
        if entry.state.live_lease() {
            let lease = entry.lease();
            self.validate(&lease, owner, now)?;
            self.entries[index].heartbeat = now;
            return Ok(Some(lease));
        }
        if !entry.state.waiting() {
            return Err(state_error(entry.state));
        }
        self.validate_continuation(index, now)?;
        let parent = entry.continuation_of.and_then(|(id, _)| {
            self.entries
                .iter()
                .find(|candidate| candidate.request_id == id)
        });
        let blocked = self.entries.iter().enumerate().any(|(other_index, other)| {
            other_index != index
                && (other.holds_resources()
                    || (other.state.waiting() && other.request_id < request_id
                        && !self.entries.iter().any(|held| held.holds_resources()
                            && held.resources.iter().all(|r| matches!(r, Resource::WindowMutation { .. } | Resource::SessionSemantic { .. }))
                            && conflicting(&held.resources, &other.resources))
                        // A waiter blocked by OUR retained window cannot prevent
                        // its owner from finishing. Other desktop waiters keep FIFO.
                        && !parent.is_some_and(|parent| conflicting(&parent.resources, &other.resources))))
                && conflicting(&entry.resources, &other.resources)
        });
        self.entries[index].heartbeat = now;
        if blocked {
            self.transition(
                index,
                State::WaitingResources,
                now,
                "earlier waiter or held resource",
            );
            return Ok(None);
        }
        self.entries[index].acquired_at = Some(now);
        self.transition(
            index,
            State::Leased,
            now,
            "all resources granted atomically",
        );
        Ok(Some(self.entries[index].lease()))
    }

    /// Authorization check. Expired leases fail immediately and record quarantine
    /// so the native transaction can persist it even when validation fails.
    pub fn validate(&mut self, lease: &Lease, owner: &Owner, now: u64) -> Result<(), ArbiterError> {
        let index = self.owned_index(lease.request_id, owner)?;
        self.check_clock(now)?;
        let entry = &self.entries[index];
        if &lease.owner != owner {
            return Err(ArbiterError::new(
                "OWNER_MISMATCH",
                "lease owner does not match caller",
            ));
        }
        if lease.generation != entry.generation {
            return Err(ArbiterError::new(
                "STALE_GENERATION",
                "lease generation has been fenced",
            ));
        }
        if !entry.state.live_lease() {
            return Err(state_error(entry.state));
        }
        if lease.resources != entry.resources
            || Some(lease.acquired_at) != entry.acquired_at
            || lease.deadline != entry.deadline
        {
            return Err(ArbiterError::new(
                "LEASE_MISMATCH",
                "lease differs from the registry grant",
            ));
        }
        if now >= entry.deadline {
            self.expire(now)?;
            return Err(ArbiterError::new("LEASE_EXPIRED", "lease deadline reached"));
        }
        self.validate_continuation(index, now)?;
        Ok(())
    }

    fn validate_continuation(&self, index: usize, now: u64) -> Result<(), ArbiterError> {
        let entry = &self.entries[index];
        if let Some((id, generation)) = entry.continuation_of {
            let parent = &self.entries[self.index(id)?];
            if parent.owner != entry.owner
                || parent.generation != generation
                || !parent.state.live_lease()
                || !parent.holds_resources()
                || now >= parent.deadline
                || entry.deadline > parent.deadline
                || conflicting(&parent.resources, &entry.resources)
            {
                return Err(ArbiterError::new(
                    "STALE_GENERATION",
                    "logical continuation parent is no longer current",
                ));
            }
        }
        Ok(())
    }

    fn require_no_continuations(&self, id: u64) -> Result<(), ArbiterError> {
        if self.entries.iter().any(|entry| {
            entry
                .continuation_of
                .is_some_and(|(parent, _)| parent == id)
                && (entry.holds_resources() || entry.state.waiting())
        }) {
            return Err(ArbiterError::new(
                "LEASE_RESERVATION_ACTIVE",
                "queued or held continuation prevents logical release",
            ));
        }
        Ok(())
    }

    /// Atomically drop desktop/clipboard while retaining exact window/session
    /// exclusion. Old combined handles are fenced. This is not legacy yield.
    pub fn yield_retaining_logical(
        &mut self,
        lease: &Lease,
        owner: &Owner,
        proof: &SafePoint,
        now: u64,
    ) -> Result<Lease, ArbiterError> {
        let index = self.prepare_lease(lease, owner, now)?;
        self.require_no_continuations(lease.request_id)?;
        if !proof.safe_for_yield()
            || self.entries[index].clipboard_pending
            || self.entries[index].active_reservations != 0
        {
            return Err(ArbiterError::new(
                "UNSAFE_YIELD",
                "observed background and quiescent input/clipboard/borrowers required",
            ));
        }
        let logical: Vec<_> = lease
            .resources
            .iter()
            .filter(|r| {
                matches!(
                    r,
                    Resource::WindowMutation { .. } | Resource::SessionSemantic { .. }
                )
            })
            .cloned()
            .collect();
        if logical.is_empty() {
            return Err(ArbiterError::new(
                "MISSING_GUI_RESOURCE",
                "logical window/session grant required",
            ));
        }
        self.fence(index, now)?;
        self.entries[index].resources = logical;
        self.entries[index].logical_background = true;
        self.entries[index].heartbeat = now;
        self.transition(
            index,
            State::Leased,
            now,
            "BACKGROUND_RUNNING: desktop yielded; logical resources retained",
        );
        // A Leased-to-Leased transition also needs explicit timeline evidence.
        self.record(
            index,
            now,
            "BACKGROUND_RUNNING: fresh logical fence; no desktop ownership",
        );
        Ok(self.entries[index].lease())
    }

    /// Reacquire ONLY global input against an authenticated retained logical
    /// parent. Parent stays reserved while queued; deadline cannot outlive it.
    pub fn request_input_continuation(
        &mut self,
        parent: &Lease,
        owner: &Owner,
        now: u64,
        deadline: u64,
    ) -> Result<u64, ArbiterError> {
        self.prepare_lease(parent, owner, now)?;
        if parent.resources.iter().any(|r| {
            !matches!(
                r,
                Resource::WindowMutation { .. } | Resource::SessionSemantic { .. }
            )
        }) {
            return Err(ArbiterError::new(
                "INVALID_RESUME_STATE",
                "continuation needs a logical-only parent",
            ));
        }
        if deadline > parent.deadline {
            return Err(ArbiterError::new(
                "INVALID_DEADLINE",
                "continuation cannot outlive logical reservation",
            ));
        }
        let id = self.request(
            owner.clone(),
            vec![Resource::DesktopInput, Resource::SystemClipboard],
            now,
            deadline,
        )?;
        self.entries.last_mut().unwrap().continuation_of =
            Some((parent.request_id, parent.generation));
        Ok(id)
    }

    pub fn begin_gui(
        &mut self,
        lease: &Lease,
        owner: &Owner,
        now: u64,
    ) -> Result<(), ArbiterError> {
        let index = self.prepare_lease(lease, owner, now)?;
        if !lease
            .resources
            .iter()
            .any(|r| matches!(r, Resource::DesktopInput | Resource::WindowMutation { .. }))
        {
            return Err(ArbiterError::new(
                "MISSING_GUI_RESOURCE",
                "GUI activity requires input or window mutation",
            ));
        }
        self.entries[index].heartbeat = now;
        self.transition(index, State::GuiActive, now, "GUI activity begun");
        Ok(())
    }

    pub fn borrow_reservation(
        &mut self,
        lease: &Lease,
        owner: &Owner,
        now: u64,
    ) -> Result<(), ArbiterError> {
        let index = self.prepare_lease(lease, owner, now)?;
        if self.entries[index].active_reservations >= 256 {
            return Err(ArbiterError::new(
                "LEASE_RESERVATION_LIMIT",
                "too many live reservations",
            ));
        }
        self.entries[index].active_reservations += 1;
        Ok(())
    }

    pub fn return_reservation(
        &mut self,
        lease: &Lease,
        owner: &Owner,
        now: u64,
    ) -> Result<(), ArbiterError> {
        let index = self.prepare_lease(lease, owner, now)?;
        if self.entries[index].active_reservations == 0 {
            return Err(ArbiterError::new(
                "LEASE_RESERVATION_REQUIRED",
                "reservation already returned",
            ));
        }
        self.entries[index].active_reservations -= 1;
        Ok(())
    }

    /// Only native confirmed-dead-owner recovery may discard borrower bookkeeping.
    pub fn recover_reservations_checkpoint(
        &mut self,
        request: u64,
        now: u64,
    ) -> Result<(), ArbiterError> {
        self.check_clock(now)?;
        let index = self.index(request)?;
        if !matches!(
            self.entries[index].state,
            State::Recovering | State::ResourceQuarantined
        ) {
            return Err(ArbiterError::new(
                "INVALID_RECOVERY_STATE",
                "borrower checkpoint needs quarantine",
            ));
        }
        self.entries[index].active_reservations = 0;
        Ok(())
    }

    /// Marks the native clipboard operation pending under a current lease that
    /// owns `SystemClipboard`. OS/domain verification remains with the caller.
    pub fn begin_clipboard(
        &mut self,
        lease: &Lease,
        owner: &Owner,
        now: u64,
    ) -> Result<(), ArbiterError> {
        let index = self.prepare_lease(lease, owner, now)?;
        if !self.entries[index]
            .resources
            .iter()
            .any(|resource| matches!(resource, Resource::SystemClipboard))
        {
            return Err(ArbiterError::new(
                "CLIPBOARD_RESOURCE_REQUIRED",
                "clipboard activity requires the SystemClipboard resource",
            ));
        }
        if self.entries[index].clipboard_pending {
            return Err(ArbiterError::new(
                "CLIPBOARD_TRANSACTION_PENDING",
                "finish the current clipboard transaction before beginning another",
            ));
        }
        self.entries[index].clipboard_pending = true;
        self.entries[index].heartbeat = now;
        Ok(())
    }

    /// Clears the model's pending marker for an authenticated current clipboard
    /// lease. The native caller must first verify completion in the OS/domain.
    pub fn finish_clipboard(
        &mut self,
        lease: &Lease,
        owner: &Owner,
        now: u64,
    ) -> Result<(), ArbiterError> {
        let index = self.prepare_lease(lease, owner, now)?;
        if !self.entries[index]
            .resources
            .iter()
            .any(|resource| matches!(resource, Resource::SystemClipboard))
        {
            return Err(ArbiterError::new(
                "CLIPBOARD_RESOURCE_REQUIRED",
                "clipboard activity requires the SystemClipboard resource",
            ));
        }
        if !self.entries[index].clipboard_pending {
            return Err(ArbiterError::new(
                "CLIPBOARD_TRANSACTION_REQUIRED",
                "no pending clipboard transaction to finish",
            ));
        }
        self.entries[index].clipboard_pending = false;
        self.entries[index].heartbeat = now;
        Ok(())
    }

    pub fn release(
        &mut self,
        lease: &Lease,
        owner: &Owner,
        proof: &SafePoint,
        now: u64,
    ) -> Result<(), ArbiterError> {
        let index = self.prepare_lease(lease, owner, now)?;
        self.require_no_continuations(lease.request_id)?;
        if self.entries[index].active_reservations != 0 {
            return Err(ArbiterError::new(
                "LEASE_RESERVATION_ACTIVE",
                "live scoped input reservation prevents release",
            ));
        }
        if self.entries[index].clipboard_pending {
            return Err(ArbiterError::new(
                "CLIPBOARD_TRANSACTION_PENDING",
                "clipboard transaction must finish before releasing resources",
            ));
        }
        if !proof.safe_for_release() {
            return Err(ArbiterError::new(
                "UNSAFE_POINT",
                "buttons/modifiers/focus/clipboard must be clear",
            ));
        }
        self.fence(index, now)?;
        self.transition(index, State::Quiescing, now, "safe release observed");
        self.entries[index].acquired_at = None;
        self.entries[index].heartbeat = now;
        self.transition(index, State::Completed, now, "resources safely released");
        Ok(())
    }

    pub fn yield_gui(
        &mut self,
        lease: &Lease,
        owner: &Owner,
        proof: &SafePoint,
        now: u64,
    ) -> Result<(), ArbiterError> {
        let index = self.prepare_lease(lease, owner, now)?;
        self.require_no_continuations(lease.request_id)?;
        if self.entries[index].active_reservations != 0 {
            return Err(ArbiterError::new(
                "LEASE_RESERVATION_ACTIVE",
                "live scoped input reservation prevents yield",
            ));
        }
        if self.entries[index].clipboard_pending {
            return Err(ArbiterError::new(
                "CLIPBOARD_TRANSACTION_PENDING",
                "clipboard transaction must finish before yielding resources",
            ));
        }
        if !lease
            .resources
            .iter()
            .any(|r| matches!(r, Resource::DesktopInput | Resource::WindowMutation { .. }))
        {
            return Err(ArbiterError::new(
                "MISSING_GUI_RESOURCE",
                "GUI yield requires a GUI resource",
            ));
        }
        if !proof.safe_for_yield() {
            return Err(ArbiterError::new(
                "UNSAFE_YIELD",
                "safe input/clipboard and observed background are required",
            ));
        }
        self.fence(index, now)?;
        self.transition(
            index,
            State::Quiescing,
            now,
            "safe background transition observed",
        );
        self.entries[index].acquired_at = None;
        self.entries[index].heartbeat = now;
        self.transition(
            index,
            State::BackgroundRunning,
            now,
            "entire grant yielded; resume requires a new request",
        );
        Ok(())
    }

    pub fn cancel(&mut self, request_id: u64, owner: &Owner, now: u64) -> Result<(), ArbiterError> {
        let index = self.owned_index(request_id, owner)?;
        self.check_clock(now)?;
        self.expire(now)?;
        let state = self.entries[index].state;
        if state == State::Cancelled {
            return Ok(());
        }
        if !state.watches_owner() {
            return Err(state_error(state));
        }
        self.invalidate(
            index,
            State::Cancelled,
            now,
            "request cancelled; no safe proof supplied",
        )
    }

    pub fn owner_lost(&mut self, owner: &Owner, now: u64) -> Result<(), ArbiterError> {
        check_owner(owner)?;
        self.check_clock(now)?;
        if !self.entries.iter().any(|e| &e.owner == owner) {
            return Err(ArbiterError::new(
                "OWNER_MISMATCH",
                "no request belongs to this exact owner",
            ));
        }
        // Continue fencing other grants even if one generation has exhausted.
        let mut failure = None;
        for index in 0..self.entries.len() {
            if &self.entries[index].owner == owner && self.entries[index].state.watches_owner() {
                if let Err(error) =
                    self.invalidate(index, State::OwnerLost, now, "owner loss observed")
                {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// `proof` must be independently observed by the native recovery controller.
    /// The pure model verifies its safe condition, not who observed it.
    pub fn recover(
        &mut self,
        request_id: u64,
        proof: &SafePoint,
        now: u64,
    ) -> Result<(), ArbiterError> {
        let index = self.index(request_id)?;
        self.check_clock(now)?;
        if !matches!(
            self.entries[index].state,
            State::Recovering | State::ResourceQuarantined
        ) {
            return Err(ArbiterError::new(
                "INVALID_RECOVERY_STATE",
                "only recovering/quarantined requests can recover",
            ));
        }
        if self.entries[index].clipboard_pending {
            return Err(ArbiterError::new(
                "CLIPBOARD_TRANSACTION_PENDING",
                "clipboard transaction needs its native recovery checkpoint before recovery",
            ));
        }
        if self.entries[index].active_reservations != 0 {
            return Err(ArbiterError::new(
                "LEASE_RESERVATION_ACTIVE",
                "confirmed native borrower checkpoint required before recovery",
            ));
        }
        if !proof.safe_for_release() {
            return Err(ArbiterError::new(
                "UNSAFE_POINT",
                "recovery needs independently observed safe input/clipboard",
            ));
        }
        self.fence(index, now)?;
        self.transition(
            index,
            State::Recovering,
            now,
            "independent safe recovery proof supplied",
        );
        self.transition(
            index,
            State::Verifying,
            now,
            "recovery safe condition verified",
        );
        self.entries[index].acquired_at = None;
        self.entries[index].heartbeat = now;
        self.transition(index, State::Completed, now, "quarantine safely recovered");
        Ok(())
    }

    /// Clears a pending clipboard marker only after the trusted native
    /// controller has independently verified the OS/domain clipboard state.
    /// This checkpoint is not worker JSON authority and does not release, fence,
    /// or otherwise recover the grant; generic recovery remains a separate step.
    pub fn recover_clipboard_checkpoint(
        &mut self,
        request_id: u64,
        now: u64,
    ) -> Result<(), ArbiterError> {
        let index = self.index(request_id)?;
        self.check_clock(now)?;
        if !matches!(
            self.entries[index].state,
            State::Recovering | State::ResourceQuarantined
        ) {
            return Err(ArbiterError::new(
                "INVALID_RECOVERY_STATE",
                "clipboard checkpoint requires a recovering/quarantined request",
            ));
        }
        if self.entries[index].clipboard_pending
            && !self.entries[index]
                .resources
                .iter()
                .any(|resource| matches!(resource, Resource::SystemClipboard))
        {
            return Err(ArbiterError::new(
                "CLIPBOARD_RESOURCE_REQUIRED",
                "pending clipboard transaction has no SystemClipboard grant",
            ));
        }
        self.entries[index].clipboard_pending = false;
        Ok(())
    }

    /// Optional resume helper: proof is tracked by the successful BackgroundRunning
    /// transition. The original request never regains lease authority or FIFO rank.
    pub fn resume(
        &mut self,
        request_id: u64,
        owner: &Owner,
        now: u64,
        deadline: u64,
    ) -> Result<u64, ArbiterError> {
        let index = self.owned_index(request_id, owner)?;
        self.check_clock(now)?;
        if self.entries[index].state != State::BackgroundRunning {
            return Err(ArbiterError::new(
                "INVALID_RESUME_STATE",
                "resume requires a previously proven GUI yield",
            ));
        }
        if now >= self.entries[index].deadline {
            self.expire(now)?;
            return Err(ArbiterError::new(
                "LEASE_EXPIRED",
                "background request deadline reached",
            ));
        }
        let resources = self.entries[index].resources.clone();
        let new_id = self.request(owner.clone(), resources, now, deadline)?;
        self.transition(
            index,
            State::Completed,
            now,
            "background request superseded by fresh resume request",
        );
        self.transition(
            self.entries.len() - 1,
            State::ResumeQueued,
            now,
            "resume queued at a new FIFO position",
        );
        Ok(new_id)
    }

    /// Refreshes only an authenticated, current, unexpired lease.
    pub fn heartbeat(
        &mut self,
        lease: &Lease,
        owner: &Owner,
        now: u64,
    ) -> Result<(), ArbiterError> {
        let index = self.prepare_lease(lease, owner, now)?;
        self.entries[index].heartbeat = now;
        Ok(())
    }

    /// Explicit deadline sweep for the native timer. Pending work times out without
    /// holding resources; grants always quarantine. Yielded background work owns none.
    pub fn expire(&mut self, now: u64) -> Result<(), ArbiterError> {
        self.check_clock(now)?;
        let mut failure = None;
        for index in 0..self.entries.len() {
            let entry = &self.entries[index];
            if entry.state.watches_owner() && now >= entry.deadline {
                if let Err(error) = self.invalidate(index, State::TimedOut, now, "deadline reached")
                {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// Independent heartbeat expiry, expressed as owner loss rather than deadline
    /// timeout. `max_age` is policy supplied by the native owner in clock units.
    pub fn expire_heartbeats(&mut self, now: u64, max_age: u64) -> Result<(), ArbiterError> {
        self.check_clock(now)?;
        if max_age == 0 {
            return Err(ArbiterError::new(
                "INVALID_HEARTBEAT_AGE",
                "heartbeat age must be positive",
            ));
        }
        let mut failure = None;
        for index in 0..self.entries.len() {
            let entry = &self.entries[index];
            if entry.state.watches_owner() && now - entry.heartbeat >= max_age {
                if let Err(error) = self.invalidate(
                    index,
                    State::OwnerLost,
                    now,
                    "heartbeat expired independently of deadline",
                ) {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn prepare_lease(
        &mut self,
        lease: &Lease,
        owner: &Owner,
        now: u64,
    ) -> Result<usize, ArbiterError> {
        let index = self.owned_index(lease.request_id, owner)?;
        self.check_clock(now)?;
        self.expire(now)?;
        self.validate(lease, owner, now)?;
        Ok(index)
    }

    fn index(&self, request_id: u64) -> Result<usize, ArbiterError> {
        if request_id == 0 {
            return Err(ArbiterError::new(
                "INVALID_REQUEST_ID",
                "request ID must be nonzero",
            ));
        }
        self.entries
            .iter()
            .position(|e| e.request_id == request_id)
            .ok_or_else(|| {
                ArbiterError::new("UNKNOWN_REQUEST", "request ID is not in this registry")
            })
    }

    fn owned_index(&self, request_id: u64, owner: &Owner) -> Result<usize, ArbiterError> {
        check_owner(owner)?;
        let index = self.index(request_id)?;
        if &self.entries[index].owner != owner {
            return Err(ArbiterError::new(
                "OWNER_MISMATCH",
                "all owner fields, including PID and process birth, must match",
            ));
        }
        Ok(index)
    }

    fn check_clock(&self, now: u64) -> Result<(), ArbiterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ArbiterError::new(
                "UNSUPPORTED_SCHEMA",
                "registry schema must be validated by the persistence owner",
            ));
        }
        if self
            .events
            .last()
            .is_some_and(|event| event.timestamp > now)
            || self.entries.iter().any(|e| {
                e.queued_at > now
                    || e.heartbeat > now
                    || e.acquired_at.is_some_and(|acquired| acquired > now)
            })
        {
            return Err(ArbiterError::new(
                "CLOCK_REGRESSION",
                "now precedes an observed registry timestamp",
            ));
        }
        Ok(())
    }

    fn fence(&mut self, index: usize, now: u64) -> Result<(), ArbiterError> {
        match self.entries[index].generation.checked_add(1) {
            Some(next) => {
                self.entries[index].generation = next;
                Ok(())
            }
            None => {
                // State fencing still denies all leases; resources remain reserved.
                self.transition(
                    index,
                    State::FailTestInfra,
                    now,
                    "generation exhausted; held resources remain reserved",
                );
                Err(ArbiterError::new(
                    "GENERATION_EXHAUSTED",
                    "lease generations cannot wrap",
                ))
            }
        }
    }

    fn invalidate(
        &mut self,
        index: usize,
        state: State,
        now: u64,
        reason: &str,
    ) -> Result<(), ArbiterError> {
        self.fence(index, now)?;
        self.transition(index, state, now, reason);
        if self.entries[index].holds_resources() {
            self.transition(
                index,
                State::ResourceQuarantined,
                now,
                "held resources require independent safe recovery",
            );
        }
        Ok(())
    }

    fn transition(&mut self, index: usize, state: State, now: u64, reason: &str) {
        if self.entries[index].state != state {
            self.entries[index].state = state;
            self.record(index, now, reason);
        }
    }

    fn record(&mut self, index: usize, now: u64, reason: &str) {
        if self.events.len() >= MAX_EVENTS {
            self.events.drain(..self.events.len() - MAX_EVENTS + 1);
        }
        self.events.push(Event {
            timestamp: now,
            request: self.entries[index].request_id,
            state: self.entries[index].state,
            reason: reason.into(),
        });
    }
}

fn check_owner(owner: &Owner) -> Result<(), ArbiterError> {
    if [
        &owner.worker_id,
        &owner.job_id,
        &owner.attempt_id,
        &owner.session_id,
    ]
    .iter()
    .any(|id| id.trim().is_empty())
        || owner.pid == 0
        || owner.process_birth == 0
    {
        return Err(ArbiterError::new(
            "INVALID_OWNER",
            "owner IDs, PID, and process birth must be nonempty/nonzero",
        ));
    }
    Ok(())
}

fn check_resources(resources: &[Resource]) -> Result<(), ArbiterError> {
    if resources.is_empty() {
        return Err(ArbiterError::new(
            "INVALID_RESOURCES",
            "at least one resource is required",
        ));
    }
    for (index, resource) in resources.iter().enumerate() {
        match resource {
            Resource::WindowMutation {
                hwnd,
                pid,
                process_birth,
            } if *hwnd == 0 || *pid == 0 || *process_birth == 0 => {
                return Err(ArbiterError::new(
                    "INVALID_RESOURCES",
                    "window handle, PID, and birth must be nonzero",
                ));
            }
            Resource::SessionSemantic { session_id } if session_id.trim().is_empty() => {
                return Err(ArbiterError::new(
                    "INVALID_RESOURCES",
                    "semantic session ID must be nonempty",
                ));
            }
            _ => {}
        }
        if resources[..index].iter().any(|other| other == resource
            || matches!((other, resource),
                (Resource::WindowMutation { hwnd: a, .. }, Resource::WindowMutation { hwnd: b, .. }) if a == b))
        {
            return Err(ArbiterError::new("INVALID_RESOURCES", "duplicate or ambiguously identified resource"));
        }
    }
    Ok(())
}

fn conflicting(a: &[Resource], b: &[Resource]) -> bool {
    a.iter()
        .any(|left| b.iter().any(|right| left.conflicts_with(right)))
}

fn state_error(state: State) -> ArbiterError {
    let code = match state {
        State::Cancelled => "CANCELLED",
        State::TimedOut => "TIMED_OUT",
        State::OwnerLost => "OWNER_LOST",
        State::ResourceQuarantined | State::Recovering => "RESOURCE_QUARANTINED",
        State::FailTestInfra => "FAIL_TEST_INFRA",
        _ => "INVALID_STATE",
    };
    ArbiterError::new(code, format!("request is in {state:?}"))
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;

use super::*;

#[test]
fn retained_window_three_request_cycle_cannot_block_unrelated_desktop() {
    let mut r = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let c = owner(3);
    let initial = grant(&mut r, &a, vec![Resource::DesktopInput, window(10)], 0);
    let parent = r
        .yield_retaining_logical(&initial, &a, &background_proof(), 1)
        .unwrap();
    let b_id = r
        .request(b.clone(), vec![Resource::DesktopInput, window(10)], 2, 900)
        .unwrap();
    let c_id = r
        .request(c.clone(), vec![Resource::DesktopInput], 3, 900)
        .unwrap();
    let a_id = r.request_input_continuation(&parent, &a, 4, 900).unwrap();
    assert!(r.poll(b_id, &b, 4).unwrap().is_none());
    assert!(r.poll(a_id, &a, 4).unwrap().is_none());
    let c_lease = r.poll(c_id, &c, 4).unwrap().unwrap();
    r.release(&c_lease, &c, &SafePoint::default(), 5).unwrap();
    let a_lease = r.poll(a_id, &a, 6).unwrap().unwrap();
    r.release(&a_lease, &a, &SafePoint::default(), 7).unwrap();
    r.release(&parent, &a, &SafePoint::default(), 8).unwrap();
    assert!(r.poll(b_id, &b, 9).unwrap().is_some());
    r.validate_storage().unwrap();
}

#[test]
fn logical_background_deadline_is_independent_of_short_input_phase() {
    let mut r = Registry::default();
    let a = owner(1);
    let id = r
        .request(a.clone(), vec![window(10)], 0, 1_800_000)
        .unwrap();
    let logical = r.poll(id, &a, 0).unwrap().unwrap();
    let background = r
        .yield_retaining_logical(&logical, &a, &background_proof(), 1)
        .unwrap();
    let resumed = r
        .request_input_continuation(&background, &a, 600_000, 660_000)
        .unwrap();
    let input = r.poll(resumed, &a, 600_000).unwrap().unwrap();
    assert_eq!(input.deadline, 660_000);
    assert_eq!(background.deadline, 1_800_000);
    assert!(entry(&r, background.request_id).logical_background);
    r.validate_storage().unwrap();
}

#[test]
fn retained_window_blocks_same_window_but_releases_desktop_for_other_windows() {
    let mut r = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let old = grant(
        &mut r,
        &a,
        vec![
            Resource::DesktopInput,
            Resource::SystemClipboard,
            window(10),
            semantic("a"),
        ],
        0,
    );
    let logical = r
        .yield_retaining_logical(&old, &a, &background_proof(), 1)
        .unwrap();
    error(r.validate(&old, &a, 1), "STALE_GENERATION");
    assert_eq!(logical.resources, vec![window(10), semantic("a")]);
    let conflicting = r
        .request(b.clone(), vec![Resource::DesktopInput, window(10)], 2, 900)
        .unwrap();
    assert!(r.poll(conflicting, &b, 2).unwrap().is_none());
    let other = r.request(b.clone(), vec![window(20)], 3, 900).unwrap();
    assert!(r.poll(other, &b, 3).unwrap().is_some());
    // A must be able to finish its window despite the earlier waiter for that window.
    let resume = r.request_input_continuation(&logical, &a, 4, 800).unwrap();
    let input = r.poll(resume, &a, 4).unwrap().unwrap();
    error(
        r.release(&logical, &a, &SafePoint::default(), 5),
        "LEASE_RESERVATION_ACTIVE",
    );
    r.release(&input, &a, &SafePoint::default(), 5).unwrap();
    r.release(&logical, &a, &SafePoint::default(), 6).unwrap();
    assert!(r.poll(conflicting, &b, 7).unwrap().is_some());
    r.validate_storage().unwrap();
}

#[test]
fn retained_continuation_preserves_unrelated_desktop_fifo_and_cancel() {
    let mut r = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let initial = grant(&mut r, &a, vec![Resource::DesktopInput, window(10)], 0);
    let logical = r
        .yield_retaining_logical(&initial, &a, &background_proof(), 1)
        .unwrap();
    let other = r
        .request(b.clone(), vec![Resource::DesktopInput, window(20)], 2, 800)
        .unwrap();
    let resume = r.request_input_continuation(&logical, &a, 3, 800).unwrap();
    assert!(r.poll(resume, &a, 3).unwrap().is_none());
    r.cancel(resume, &a, 4).unwrap();
    assert!(!entry(&r, resume).holds_resources());
    assert!(r.poll(other, &b, 5).unwrap().is_some());
    r.release(&logical, &a, &SafePoint::default(), 6).unwrap();
    r.validate_storage().unwrap();
}

#[test]
fn continuation_parent_loss_fences_input_and_keeps_recovery_resources() {
    let mut r = Registry::default();
    let a = owner(1);
    let initial = grant(&mut r, &a, vec![Resource::DesktopInput, window(10)], 0);
    let logical = r
        .yield_retaining_logical(&initial, &a, &background_proof(), 1)
        .unwrap();
    let resume = r.request_input_continuation(&logical, &a, 2, 800).unwrap();
    let input = r.poll(resume, &a, 2).unwrap().unwrap();
    r.owner_lost(&a, 3).unwrap();
    error(r.validate(&input, &a, 3), "STALE_GENERATION");
    assert!(entry(&r, resume).holds_resources() && entry(&r, logical.request_id).holds_resources());
    r.validate_storage().unwrap();
}

#[test]
fn logical_yield_requires_observed_background_and_neutral_input() {
    let mut r = Registry::default();
    let a = owner(1);
    let lease = grant(&mut r, &a, vec![Resource::DesktopInput, window(10)], 0);
    error(
        r.yield_retaining_logical(&lease, &a, &SafePoint::default(), 1),
        "UNSAFE_YIELD",
    );
    let mut proof = background_proof();
    proof.held_modifiers = true;
    error(
        r.yield_retaining_logical(&lease, &a, &proof, 1),
        "UNSAFE_YIELD",
    );
    r.borrow_reservation(&lease, &a, 1).unwrap();
    error(
        r.yield_retaining_logical(&lease, &a, &background_proof(), 1),
        "UNSAFE_YIELD",
    );
    assert!(
        entry(&r, lease.request_id)
            .resources
            .contains(&Resource::DesktopInput)
    );
}

#[test]
fn continuation_authentication_deadline_and_storage_roundtrip() {
    let mut r = Registry::default();
    let a = owner(1);
    let initial = grant(&mut r, &a, vec![Resource::DesktopInput, window(10)], 0);
    let logical = r
        .yield_retaining_logical(&initial, &a, &background_proof(), 1)
        .unwrap();
    error(
        r.request_input_continuation(&logical, &owner(2), 2, 500),
        "OWNER_MISMATCH",
    );
    error(
        r.request_input_continuation(&logical, &a, 2, 1001),
        "INVALID_DEADLINE",
    );
    let id = r.request_input_continuation(&logical, &a, 2, 500).unwrap();
    r.poll(id, &a, 2).unwrap().unwrap();
    let decoded: Registry = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    decoded.validate_storage().unwrap();
    assert_eq!(decoded, r);
}

fn owner(number: u32) -> Owner {
    Owner {
        worker_id: format!("worker-{number}"),
        job_id: format!("job-{number}"),
        attempt_id: format!("attempt-{number}"),
        session_id: format!("session-{number}"),
        pid: number,
        process_birth: u64::from(number) + 100,
    }
}

fn window(hwnd: u64) -> Resource {
    Resource::WindowMutation {
        hwnd,
        pid: 77,
        process_birth: 777,
    }
}

fn semantic(session: &str) -> Resource {
    Resource::SessionSemantic {
        session_id: session.into(),
    }
}

fn background_proof() -> SafePoint {
    SafePoint {
        background_observed: true,
        ..SafePoint::default()
    }
}

fn error<T: fmt::Debug>(result: Result<T, ArbiterError>, expected: &str) {
    assert_eq!(result.unwrap_err().code, expected);
}

fn entry(registry: &Registry, id: u64) -> &Entry {
    registry
        .entries
        .iter()
        .find(|e| e.request_id == id)
        .unwrap()
}

fn grant(registry: &mut Registry, owner: &Owner, resources: Vec<Resource>, now: u64) -> Lease {
    let id = registry
        .request(owner.clone(), resources, now, now + 1000)
        .unwrap();
    registry.poll(id, owner, now).unwrap().unwrap()
}

#[test]
fn default_schema_ids_and_safe_points_are_explicit() {
    let registry = Registry::default();
    assert_eq!(registry.schema_version, 1);
    assert_eq!(registry.next_id, 1);
    assert!(registry.entries.is_empty() && registry.events.is_empty());
    assert!(SafePoint::default().safe_for_release());
    assert!(!SafePoint::default().safe_for_yield());
    assert!(background_proof().safe_for_yield());
}

#[test]
fn kernel_process_birth_survives_json_without_ieee754_rounding() {
    let mut value = owner(1);
    value.process_birth = 134361039084524161;
    let json = serde_json::to_value(&value).unwrap();
    assert_eq!(json["process_birth"], "134361039084524161");
    assert_eq!(serde_json::from_value::<Owner>(json).unwrap(), value);
}

#[test]
fn serialization_roundtrips_full_registry_and_exact_state_names() {
    let states = [
        (State::Queued, "QUEUED"),
        (State::WaitingResources, "WAITING_RESOURCES"),
        (State::Leased, "LEASED"),
        (State::GuiActive, "GUI_ACTIVE"),
        (State::Quiescing, "QUIESCING"),
        (State::BackgroundRunning, "BACKGROUND_RUNNING"),
        (State::ResumeQueued, "RESUME_QUEUED"),
        (State::Verifying, "VERIFYING"),
        (State::Completed, "COMPLETED"),
        (State::Cancelled, "CANCELLED"),
        (State::TimedOut, "TIMED_OUT"),
        (State::OwnerLost, "OWNER_LOST"),
        (State::Recovering, "RECOVERING"),
        (State::ResourceQuarantined, "RESOURCE_QUARANTINED"),
        (State::FailTestInfra, "FAIL_TEST_INFRA"),
    ];
    for (state, name) in states {
        assert_eq!(
            serde_json::to_value(state).unwrap(),
            serde_json::json!(name)
        );
        assert_eq!(
            serde_json::from_value::<State>(serde_json::json!(name)).unwrap(),
            state
        );
    }
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(
        &mut registry,
        &owner,
        vec![window(5), Resource::SystemClipboard],
        1,
    );
    let json = serde_json::to_string(&registry).unwrap();
    let mut restored: Registry = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, registry);
    restored.validate(&lease, &owner, 2).unwrap();
    assert_eq!(
        serde_json::from_str::<Lease>(&serde_json::to_string(&lease).unwrap()).unwrap(),
        lease
    );
}

#[test]
fn two_owners_are_fifo_even_when_later_owner_polls_first() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let first = registry
        .request(a.clone(), vec![Resource::DesktopInput], 0, 100)
        .unwrap();
    let second = registry
        .request(b.clone(), vec![Resource::DesktopInput], 0, 100)
        .unwrap();
    assert_eq!(registry.poll(second, &b, 1).unwrap(), None);
    let lease = registry.poll(first, &a, 1).unwrap().unwrap();
    assert_eq!(registry.poll(second, &b, 2).unwrap(), None);
    registry
        .release(&lease, &a, &SafePoint::default(), 3)
        .unwrap();
    assert!(registry.poll(second, &b, 3).unwrap().is_some());
}

#[test]
fn fifo_uses_ids_not_vector_order_or_worker_identity() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let first = registry
        .request(owner.clone(), vec![Resource::DesktopInput], 1, 100)
        .unwrap();
    let second = registry
        .request(owner.clone(), vec![Resource::DesktopInput], 1, 100)
        .unwrap();
    registry.entries.reverse();
    assert!(registry.poll(second, &owner, 2).unwrap().is_none());
    assert!(registry.poll(first, &owner, 2).unwrap().is_some());
    assert!(registry.poll(second, &owner, 2).unwrap().is_none());
}

#[test]
fn cancelling_an_earlier_waiter_unblocks_next_and_is_idempotent() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let first = registry
        .request(a.clone(), vec![Resource::DesktopInput], 0, 100)
        .unwrap();
    let second = registry
        .request(b.clone(), vec![Resource::DesktopInput], 0, 100)
        .unwrap();
    assert!(registry.poll(second, &b, 1).unwrap().is_none());
    registry.cancel(first, &a, 2).unwrap();
    let snapshot = registry.clone();
    registry.cancel(first, &a, 2).unwrap();
    assert_eq!(registry, snapshot);
    assert_eq!(entry(&registry, first).state, State::Cancelled);
    assert!(registry.poll(second, &b, 2).unwrap().is_some());
    error(registry.poll(first, &a, 2), "CANCELLED");
}

#[test]
fn pending_timeout_frees_fifo_without_quarantining_unowned_resources() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let first = registry
        .request(a.clone(), vec![Resource::DesktopInput], 0, 5)
        .unwrap();
    let second = registry
        .request(b.clone(), vec![Resource::DesktopInput], 0, 100)
        .unwrap();
    assert!(registry.poll(second, &b, 4).unwrap().is_none());
    assert!(registry.poll(second, &b, 5).unwrap().is_some());
    assert_eq!(entry(&registry, first).state, State::TimedOut);
    assert_eq!(entry(&registry, first).acquired_at, None);
    error(registry.poll(first, &a, 5), "TIMED_OUT");
    error(
        registry.recover(first, &SafePoint::default(), 5),
        "INVALID_RECOVERY_STATE",
    );
}

#[test]
fn expired_owned_grant_is_fenced_and_quarantined_until_safe_recovery() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let first = registry
        .request(
            a.clone(),
            vec![Resource::DesktopInput, Resource::SystemClipboard],
            0,
            5,
        )
        .unwrap();
    let lease = registry.poll(first, &a, 1).unwrap().unwrap();
    registry.begin_gui(&lease, &a, 2).unwrap();
    let next = registry
        .request(b.clone(), vec![Resource::SystemClipboard], 2, 100)
        .unwrap();
    assert!(registry.poll(next, &b, 5).unwrap().is_none());
    assert_eq!(entry(&registry, first).state, State::ResourceQuarantined);
    assert_eq!(entry(&registry, first).acquired_at, Some(1));
    assert_eq!(entry(&registry, first).generation, lease.generation + 1);
    error(registry.validate(&lease, &a, 5), "STALE_GENERATION");
    assert!(
        registry
            .events
            .iter()
            .any(|e| e.request == first && e.state == State::TimedOut)
    );
    let unsafe_proof = SafePoint {
        clipboard_transaction: true,
        ..SafePoint::default()
    };
    error(registry.recover(first, &unsafe_proof, 6), "UNSAFE_POINT");
    assert!(registry.poll(next, &b, 6).unwrap().is_none());
    registry.recover(first, &SafePoint::default(), 7).unwrap();
    assert_eq!(entry(&registry, first).state, State::Completed);
    assert_eq!(entry(&registry, first).acquired_at, None);
    assert_eq!(entry(&registry, first).generation, lease.generation + 2);
    assert!(registry.poll(next, &b, 7).unwrap().is_some());
    error(
        registry.recover(first, &SafePoint::default(), 7),
        "INVALID_RECOVERY_STATE",
    );
}

#[test]
fn validate_records_expiry_quarantine_without_dropping_reservation() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let id = registry
        .request(owner.clone(), vec![Resource::DesktopInput], 0, 5)
        .unwrap();
    let lease = registry.poll(id, &owner, 0).unwrap().unwrap();
    error(registry.validate(&lease, &owner, 5), "LEASE_EXPIRED");
    assert_eq!(entry(&registry, id).state, State::ResourceQuarantined);
    assert_eq!(entry(&registry, id).generation, lease.generation + 1);
    assert!(entry(&registry, id).holds_resources());
    error(
        registry.release(&lease, &owner, &SafePoint::default(), 5),
        "STALE_GENERATION",
    );
    assert_eq!(entry(&registry, id).state, State::ResourceQuarantined);
}

#[test]
fn cancellation_of_a_grant_needs_recovery_and_stales_every_old_operation() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let lease = grant(&mut registry, &a, vec![Resource::DesktopInput], 0);
    registry.cancel(lease.request_id, &a, 1).unwrap();
    assert_eq!(
        entry(&registry, lease.request_id).state,
        State::ResourceQuarantined
    );
    error(registry.validate(&lease, &a, 1), "STALE_GENERATION");
    error(registry.begin_gui(&lease, &a, 1), "STALE_GENERATION");
    error(
        registry.release(&lease, &a, &SafePoint::default(), 1),
        "STALE_GENERATION",
    );
    error(
        registry.yield_gui(&lease, &a, &background_proof(), 1),
        "STALE_GENERATION",
    );
    error(registry.heartbeat(&lease, &a, 1), "STALE_GENERATION");
    let next = registry
        .request(b.clone(), vec![Resource::DesktopInput], 1, 100)
        .unwrap();
    assert!(registry.poll(next, &b, 1).unwrap().is_none());
    registry
        .recover(lease.request_id, &SafePoint::default(), 2)
        .unwrap();
    assert!(registry.poll(next, &b, 2).unwrap().is_some());
}

#[test]
fn owner_loss_fences_all_exact_owner_grants_but_not_other_owners() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let input = grant(&mut registry, &a, vec![Resource::DesktopInput], 0);
    let clipboard = grant(&mut registry, &a, vec![Resource::SystemClipboard], 0);
    let other = grant(&mut registry, &b, vec![window(5)], 0);
    let queued = registry
        .request(a.clone(), vec![window(5)], 0, 100)
        .unwrap();
    registry.owner_lost(&a, 1).unwrap();
    for lease in [&input, &clipboard] {
        assert_eq!(
            entry(&registry, lease.request_id).state,
            State::ResourceQuarantined
        );
        error(registry.validate(lease, &a, 1), "STALE_GENERATION");
    }
    assert_eq!(entry(&registry, queued).state, State::OwnerLost);
    assert!(!entry(&registry, queued).holds_resources());
    registry.validate(&other, &b, 1).unwrap();
    let snapshot = registry.clone();
    registry.owner_lost(&a, 1).unwrap();
    assert_eq!(registry, snapshot);
}

#[test]
fn every_owner_field_including_same_pid_different_birth_is_authenticated() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::DesktopInput], 0);
    for field in 0..6 {
        let mut wrong = owner.clone();
        match field {
            0 => wrong.worker_id.push('x'),
            1 => wrong.job_id.push('x'),
            2 => wrong.attempt_id.push('x'),
            3 => wrong.session_id.push('x'),
            4 => wrong.pid += 1,
            _ => wrong.process_birth += 1,
        }
        let snapshot = registry.clone();
        error(registry.poll(lease.request_id, &wrong, 1), "OWNER_MISMATCH");
        error(registry.validate(&lease, &wrong, 1), "OWNER_MISMATCH");
        error(registry.begin_gui(&lease, &wrong, 1), "OWNER_MISMATCH");
        error(
            registry.release(&lease, &wrong, &SafePoint::default(), 1),
            "OWNER_MISMATCH",
        );
        error(
            registry.yield_gui(&lease, &wrong, &background_proof(), 1),
            "OWNER_MISMATCH",
        );
        error(
            registry.cancel(lease.request_id, &wrong, 1),
            "OWNER_MISMATCH",
        );
        error(registry.owner_lost(&wrong, 1), "OWNER_MISMATCH");
        error(registry.heartbeat(&lease, &wrong, 1), "OWNER_MISMATCH");
        assert_eq!(registry, snapshot);
    }
}

#[test]
fn pid_reuse_cannot_bypass_a_quarantined_resource() {
    let mut registry = Registry::default();
    let old = owner(1);
    let lease = grant(&mut registry, &old, vec![Resource::DesktopInput], 0);
    registry.owner_lost(&old, 1).unwrap();
    let mut reused = old.clone();
    reused.process_birth += 1;
    let next = registry
        .request(reused.clone(), vec![Resource::DesktopInput], 1, 100)
        .unwrap();
    assert!(registry.poll(next, &reused, 1).unwrap().is_none());
    error(registry.validate(&lease, &reused, 1), "OWNER_MISMATCH");
    registry
        .recover(lease.request_id, &SafePoint::default(), 2)
        .unwrap();
    assert!(registry.poll(next, &reused, 2).unwrap().is_some());
}

#[test]
fn lease_copies_cannot_change_generation_owner_resources_or_times() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![window(5)], 1);
    for field in 0..5 {
        let mut forged = lease.clone();
        let expected = match field {
            0 => {
                forged.generation += 1;
                "STALE_GENERATION"
            }
            1 => {
                forged.owner.process_birth += 1;
                "OWNER_MISMATCH"
            }
            2 => {
                forged.resources = vec![window(6)];
                "LEASE_MISMATCH"
            }
            3 => {
                forged.acquired_at += 1;
                "LEASE_MISMATCH"
            }
            _ => {
                forged.deadline += 1;
                "LEASE_MISMATCH"
            }
        };
        error(registry.validate(&forged, &owner, 2), expected);
        error(registry.begin_gui(&forged, &owner, 2), expected);
    }
    registry.validate(&lease, &owner, 2).unwrap();
}

#[test]
fn atomic_multiresource_waiter_never_partially_acquires_clipboard() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let held = grant(&mut registry, &a, vec![Resource::DesktopInput], 0);
    let both = registry
        .request(
            b.clone(),
            vec![Resource::SystemClipboard, Resource::DesktopInput],
            1,
            100,
        )
        .unwrap();
    assert!(registry.poll(both, &b, 1).unwrap().is_none());
    assert_eq!(entry(&registry, both).acquired_at, None);
    assert_eq!(entry(&registry, both).state, State::WaitingResources);
    registry
        .release(&held, &a, &SafePoint::default(), 2)
        .unwrap();
    let lease = registry.poll(both, &b, 2).unwrap().unwrap();
    assert_eq!(
        lease.resources,
        vec![Resource::DesktopInput, Resource::SystemClipboard]
    );
    assert_eq!(lease.acquired_at, 2);
}

#[test]
fn earlier_multiresource_waiter_reserves_fifo_priority_on_free_resource() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let c = owner(3);
    let held = grant(&mut registry, &a, vec![Resource::DesktopInput], 0);
    let both = registry
        .request(
            b.clone(),
            vec![Resource::DesktopInput, Resource::SystemClipboard],
            1,
            100,
        )
        .unwrap();
    for now in 2..20 {
        let later = registry
            .request(c.clone(), vec![Resource::SystemClipboard], now, 100)
            .unwrap();
        assert!(registry.poll(later, &c, now).unwrap().is_none());
        registry.cancel(later, &c, now).unwrap();
    }
    assert!(!entry(&registry, both).holds_resources());
    registry
        .release(&held, &a, &SafePoint::default(), 20)
        .unwrap();
    assert!(registry.poll(both, &b, 20).unwrap().is_some());
}

#[test]
fn cancelling_or_timing_out_multiresource_waiter_removes_all_fifo_barriers() {
    for timed_out in [false, true] {
        let mut registry = Registry::default();
        let a = owner(1);
        let b = owner(2);
        let c = owner(3);
        let _held = grant(&mut registry, &a, vec![Resource::DesktopInput], 0);
        let both = registry
            .request(
                b.clone(),
                vec![Resource::DesktopInput, Resource::SystemClipboard],
                0,
                5,
            )
            .unwrap();
        let clipboard = registry
            .request(c.clone(), vec![Resource::SystemClipboard], 0, 100)
            .unwrap();
        assert!(registry.poll(clipboard, &c, 1).unwrap().is_none());
        if timed_out {
            registry.expire(5).unwrap();
        } else {
            registry.cancel(both, &b, 4).unwrap();
        }
        assert!(registry.poll(clipboard, &c, 5).unwrap().is_some());
        assert_eq!(
            entry(&registry, both).state,
            if timed_out {
                State::TimedOut
            } else {
                State::Cancelled
            }
        );
    }
}

#[test]
fn same_semantic_session_conflicts_other_sessions_and_background_run_in_parallel() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let c = owner(3);
    let first = grant(&mut registry, &a, vec![semantic("shared")], 0);
    let same = registry
        .request(b.clone(), vec![semantic("shared")], 0, 100)
        .unwrap();
    assert!(registry.poll(same, &b, 0).unwrap().is_none());
    let different = grant(&mut registry, &b, vec![semantic("other")], 0);
    let background_a = grant(&mut registry, &a, vec![Resource::BackgroundCompute], 0);
    let background_b = grant(&mut registry, &c, vec![Resource::BackgroundCompute], 0);
    for (lease, owner) in [
        (&first, &a),
        (&different, &b),
        (&background_a, &a),
        (&background_b, &c),
    ] {
        registry.validate(lease, owner, 0).unwrap();
    }
}

#[test]
fn nonconflicting_work_bypasses_a_blocked_global_input_queue() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let held = grant(
        &mut registry,
        &a,
        vec![Resource::DesktopInput, Resource::SystemClipboard],
        0,
    );
    registry.owner_lost(&a, 1).unwrap();
    let waiting = registry
        .request(b.clone(), vec![Resource::DesktopInput], 1, 100)
        .unwrap();
    assert!(registry.poll(waiting, &b, 1).unwrap().is_none());
    for resource in [
        Resource::BackgroundCompute,
        semantic("independent"),
        window(6),
    ] {
        let lease = grant(&mut registry, &b, vec![resource], 1);
        registry.validate(&lease, &b, 1).unwrap();
    }
    assert_eq!(
        entry(&registry, held.request_id).state,
        State::ResourceQuarantined
    );
}

#[test]
fn window_conflict_uses_hwnd_and_wrong_pid_birth_cannot_bypass_it() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let first = grant(&mut registry, &a, vec![window(5)], 0);
    for claimed in [
        window(5),
        Resource::WindowMutation {
            hwnd: 5,
            pid: 88,
            process_birth: 888,
        },
        Resource::WindowMutation {
            hwnd: 5,
            pid: 77,
            process_birth: 888,
        },
    ] {
        let id = registry.request(b.clone(), vec![claimed], 0, 100).unwrap();
        assert!(registry.poll(id, &b, 0).unwrap().is_none());
        registry.cancel(id, &b, 0).unwrap();
    }
    let independent = grant(&mut registry, &b, vec![window(6)], 0);
    registry.begin_gui(&first, &a, 1).unwrap();
    registry.begin_gui(&independent, &b, 1).unwrap();
}

#[test]
fn non_gui_lease_cannot_authorize_gui_even_if_global_input_is_free() {
    for resource in [
        Resource::BackgroundCompute,
        Resource::SystemClipboard,
        semantic("a"),
    ] {
        let mut registry = Registry::default();
        let owner = owner(1);
        let lease = grant(&mut registry, &owner, vec![resource], 0);
        let snapshot = registry.clone();
        error(
            registry.begin_gui(&lease, &owner, 1),
            "MISSING_GUI_RESOURCE",
        );
        error(
            registry.yield_gui(&lease, &owner, &background_proof(), 1),
            "MISSING_GUI_RESOURCE",
        );
        assert_eq!(registry, snapshot);
        registry
            .release(&lease, &owner, &SafePoint::default(), 1)
            .unwrap();
    }
}

#[test]
fn gui_begin_and_poll_are_idempotent_for_current_grant() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::DesktopInput], 0);
    registry.begin_gui(&lease, &owner, 1).unwrap();
    let events = registry.events.len();
    registry.begin_gui(&lease, &owner, 2).unwrap();
    assert_eq!(
        registry.poll(lease.request_id, &owner, 2).unwrap(),
        Some(lease.clone())
    );
    assert_eq!(registry.events.len(), events);
    assert_eq!(entry(&registry, lease.request_id).heartbeat, 2);
    assert_eq!(entry(&registry, lease.request_id).state, State::GuiActive);
}

#[test]
fn every_unsafe_proof_bit_rejects_release_yield_and_recovery() {
    for bit in 0..4 {
        let mut registry = Registry::default();
        let owner = owner(1);
        let lease = grant(
            &mut registry,
            &owner,
            vec![Resource::DesktopInput, Resource::SystemClipboard],
            0,
        );
        registry.begin_gui(&lease, &owner, 0).unwrap();
        let mut proof = background_proof();
        match bit {
            0 => proof.held_buttons = true,
            1 => proof.held_modifiers = true,
            2 => proof.pending_focus_action = true,
            _ => proof.clipboard_transaction = true,
        }
        let snapshot = registry.clone();
        error(registry.release(&lease, &owner, &proof, 1), "UNSAFE_POINT");
        error(
            registry.yield_gui(&lease, &owner, &proof, 1),
            "UNSAFE_YIELD",
        );
        assert_eq!(registry, snapshot);
        registry.owner_lost(&owner, 1).unwrap();
        let quarantined = registry.clone();
        error(
            registry.recover(lease.request_id, &proof, 1),
            "UNSAFE_POINT",
        );
        assert_eq!(registry, quarantined);
    }
}

#[test]
fn default_proof_does_not_yield_but_can_release_without_background() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::DesktopInput], 0);
    error(
        registry.yield_gui(&lease, &owner, &SafePoint::default(), 1),
        "UNSAFE_YIELD",
    );
    registry.validate(&lease, &owner, 1).unwrap();
    registry
        .release(&lease, &owner, &SafePoint::default(), 1)
        .unwrap();
    assert_eq!(entry(&registry, lease.request_id).state, State::Completed);
    error(registry.validate(&lease, &owner, 1), "STALE_GENERATION");
    error(
        registry.release(&lease, &owner, &SafePoint::default(), 1),
        "STALE_GENERATION",
    );
}

#[test]
fn yield_releases_all_resources_stales_original_and_resume_has_fresh_fifo_rank() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let lease = grant(
        &mut registry,
        &a,
        vec![
            Resource::DesktopInput,
            Resource::SystemClipboard,
            semantic("shared"),
        ],
        0,
    );
    registry.begin_gui(&lease, &a, 1).unwrap();
    let next = registry
        .request(b.clone(), lease.resources.clone(), 1, 100)
        .unwrap();
    registry
        .yield_gui(&lease, &a, &background_proof(), 2)
        .unwrap();
    let yielded = entry(&registry, lease.request_id);
    assert_eq!(yielded.state, State::BackgroundRunning);
    assert_eq!(yielded.acquired_at, None);
    assert_eq!(yielded.generation, lease.generation + 1);
    error(registry.validate(&lease, &a, 2), "STALE_GENERATION");
    error(registry.poll(lease.request_id, &a, 2), "INVALID_STATE");
    let resumed = registry.resume(lease.request_id, &a, 3, 100).unwrap();
    assert!(resumed > next && resumed > lease.request_id);
    assert_eq!(entry(&registry, resumed).state, State::ResumeQueued);
    assert_eq!(entry(&registry, lease.request_id).state, State::Completed);
    assert!(registry.poll(resumed, &a, 3).unwrap().is_none());
    let other_lease = registry.poll(next, &b, 3).unwrap().unwrap();
    registry
        .release(&other_lease, &b, &SafePoint::default(), 4)
        .unwrap();
    let resumed_lease = registry.poll(resumed, &a, 4).unwrap().unwrap();
    assert_eq!(resumed_lease.resources, lease.resources);
    assert_ne!(resumed_lease.request_id, lease.request_id);
}

#[test]
fn yield_proof_survives_serialization_and_original_never_resumes_in_place() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::DesktopInput], 0);
    error(
        registry.resume(lease.request_id, &owner, 1, 100),
        "INVALID_RESUME_STATE",
    );
    registry
        .yield_gui(&lease, &owner, &background_proof(), 1)
        .unwrap();
    let mut restored: Registry =
        serde_json::from_value(serde_json::to_value(&registry).unwrap()).unwrap();
    let new_id = restored.resume(lease.request_id, &owner, 2, 100).unwrap();
    assert!(new_id > lease.request_id);
    error(
        restored.resume(lease.request_id, &owner, 2, 100),
        "INVALID_RESUME_STATE",
    );
    error(restored.validate(&lease, &owner, 2), "STALE_GENERATION");
}

#[test]
fn failed_resume_leaves_proven_background_state_intact() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::DesktopInput], 0);
    registry
        .yield_gui(&lease, &owner, &background_proof(), 1)
        .unwrap();
    let snapshot = registry.clone();
    error(
        registry.resume(lease.request_id, &owner, 2, 2),
        "INVALID_DEADLINE",
    );
    assert_eq!(registry, snapshot);
}

#[test]
fn lost_cancelled_or_timed_out_background_does_not_requarantine_yielded_resources() {
    for action in 0..3 {
        let mut registry = Registry::default();
        let a = owner(1);
        let b = owner(2);
        let lease = grant(&mut registry, &a, vec![Resource::DesktopInput], 0);
        registry
            .yield_gui(&lease, &a, &background_proof(), 1)
            .unwrap();
        let now = match action {
            0 => {
                registry.owner_lost(&a, 2).unwrap();
                2
            }
            1 => {
                registry.cancel(lease.request_id, &a, 2).unwrap();
                2
            }
            _ => {
                registry.expire(1000).unwrap();
                1000
            }
        };
        let original = entry(&registry, lease.request_id);
        assert!(!original.holds_resources());
        assert_ne!(original.state, State::ResourceQuarantined);
        let other = grant(&mut registry, &b, vec![Resource::DesktopInput], now);
        registry.validate(&other, &b, now).unwrap();
    }
}

#[test]
fn recovery_requires_quarantine_or_recovering_and_not_an_active_or_queued_request() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::DesktopInput], 0);
    let pending = registry
        .request(owner.clone(), vec![Resource::DesktopInput], 0, 100)
        .unwrap();
    let snapshot = registry.clone();
    for id in [lease.request_id, pending] {
        error(
            registry.recover(id, &SafePoint::default(), 1),
            "INVALID_RECOVERY_STATE",
        );
    }
    assert_eq!(registry, snapshot);
    registry.owner_lost(&owner, 1).unwrap();
    registry
        .entries
        .iter_mut()
        .find(|e| e.request_id == lease.request_id)
        .unwrap()
        .state = State::Recovering;
    registry
        .recover(lease.request_id, &SafePoint::default(), 2)
        .unwrap();
    assert_eq!(entry(&registry, lease.request_id).state, State::Completed);
    let states: Vec<_> = registry
        .events
        .iter()
        .filter(|e| e.request == lease.request_id)
        .map(|e| e.state)
        .collect();
    assert!(states.contains(&State::Verifying));
}

#[test]
fn heartbeat_expiry_is_independent_of_deadline_and_never_blindly_releases() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let lease = grant(&mut registry, &a, vec![Resource::DesktopInput], 0);
    registry.heartbeat(&lease, &a, 3).unwrap();
    registry.expire_heartbeats(7, 5).unwrap();
    registry.validate(&lease, &a, 7).unwrap();
    registry.expire_heartbeats(8, 5).unwrap();
    assert_eq!(
        entry(&registry, lease.request_id).state,
        State::ResourceQuarantined
    );
    assert!(entry(&registry, lease.request_id).deadline > 8);
    assert!(
        registry
            .events
            .iter()
            .any(|e| e.state == State::OwnerLost && e.reason.contains("heartbeat"))
    );
    let next = registry
        .request(b.clone(), vec![Resource::DesktopInput], 8, 100)
        .unwrap();
    assert!(registry.poll(next, &b, 8).unwrap().is_none());
    error(registry.heartbeat(&lease, &a, 8), "STALE_GENERATION");
}

#[test]
fn expired_waiter_heartbeat_is_owner_loss_without_quarantine() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let id = registry
        .request(owner.clone(), vec![Resource::DesktopInput], 0, 100)
        .unwrap();
    registry.expire_heartbeats(5, 5).unwrap();
    assert_eq!(entry(&registry, id).state, State::OwnerLost);
    assert_eq!(entry(&registry, id).acquired_at, None);
    error(registry.poll(id, &owner, 5), "OWNER_LOST");
}

#[test]
fn invalid_owner_values_do_not_allocate_or_mutate_registry() {
    for field in 0..6 {
        let mut registry = Registry::default();
        let mut bad = owner(1);
        match field {
            0 => bad.worker_id = " ".into(),
            1 => bad.job_id.clear(),
            2 => bad.attempt_id.clear(),
            3 => bad.session_id.clear(),
            4 => bad.pid = 0,
            _ => bad.process_birth = 0,
        }
        error(
            registry.request(bad, vec![Resource::DesktopInput], 0, 100),
            "INVALID_OWNER",
        );
        assert_eq!(registry, Registry::default());
    }
}

#[test]
fn invalid_resources_deadlines_and_request_ids_fail_without_allocation() {
    let mut registry = Registry::default();
    let owner = owner(1);
    for resources in [
        vec![],
        vec![Resource::DesktopInput, Resource::DesktopInput],
        vec![Resource::BackgroundCompute, Resource::BackgroundCompute],
        vec![Resource::WindowMutation {
            hwnd: 0,
            pid: 1,
            process_birth: 1,
        }],
        vec![Resource::WindowMutation {
            hwnd: 1,
            pid: 0,
            process_birth: 1,
        }],
        vec![Resource::WindowMutation {
            hwnd: 1,
            pid: 1,
            process_birth: 0,
        }],
        vec![semantic(" ")],
        vec![
            window(5),
            Resource::WindowMutation {
                hwnd: 5,
                pid: 88,
                process_birth: 888,
            },
        ],
    ] {
        error(
            registry.request(owner.clone(), resources, 1, 100),
            "INVALID_RESOURCES",
        );
        assert_eq!(registry, Registry::default());
    }
    for deadline in [0, 1] {
        error(
            registry.request(owner.clone(), vec![Resource::DesktopInput], 1, deadline),
            "INVALID_DEADLINE",
        );
    }
    error(registry.poll(0, &owner, 1), "INVALID_REQUEST_ID");
    error(registry.poll(99, &owner, 1), "UNKNOWN_REQUEST");
    error(registry.cancel(99, &owner, 1), "UNKNOWN_REQUEST");
    error(
        registry.recover(99, &SafePoint::default(), 1),
        "UNKNOWN_REQUEST",
    );
    assert_eq!(registry, Registry::default());
}

#[test]
fn request_ids_are_checked_nonwrapping_and_never_reused() {
    let mut registry = Registry {
        next_id: u64::MAX - 1,
        ..Registry::default()
    };
    let owner = owner(1);
    let id = registry
        .request(owner.clone(), vec![Resource::BackgroundCompute], 0, 100)
        .unwrap();
    assert_eq!(id, u64::MAX - 1);
    assert_eq!(registry.next_id, u64::MAX);
    let snapshot = registry.clone();
    error(
        registry.request(owner.clone(), vec![Resource::BackgroundCompute], 0, 100),
        "REQUEST_ID_EXHAUSTED",
    );
    assert_eq!(registry, snapshot);
    registry.next_id = id;
    error(
        registry.request(owner.clone(), vec![Resource::BackgroundCompute], 0, 100),
        "INVALID_REQUEST_ID",
    );
    registry.next_id = 0;
    error(
        registry.request(owner, vec![Resource::BackgroundCompute], 0, 100),
        "INVALID_REQUEST_ID",
    );
}

#[test]
fn request_limit_is_bounded_and_preserves_existing_grants() {
    let mut registry = Registry::default();
    let owner = owner(1);
    for _ in 0..MAX_REQUESTS {
        registry
            .request(owner.clone(), vec![Resource::BackgroundCompute], 0, 100)
            .unwrap();
    }
    let snapshot = registry.clone();
    error(
        registry.request(owner.clone(), vec![Resource::DesktopInput], 0, 100),
        "REQUEST_LIMIT",
    );
    assert_eq!(registry, snapshot);
    let lease = registry.poll(1, &owner, 0).unwrap().unwrap();
    registry.validate(&lease, &owner, 0).unwrap();
}

#[test]
fn event_history_is_bounded_chronological_and_retains_latest_transition() {
    let mut registry = Registry::default();
    let owner = owner(1);
    for now in 0..3000 {
        let lease = grant(
            &mut registry,
            &owner,
            vec![Resource::BackgroundCompute],
            now,
        );
        registry
            .release(&lease, &owner, &SafePoint::default(), now)
            .unwrap();
    }
    assert_eq!(registry.events.len(), MAX_EVENTS);
    assert!(registry.events[0].request > 1);
    assert!(
        registry
            .events
            .windows(2)
            .all(|pair| pair[0].timestamp <= pair[1].timestamp)
    );
    let last = registry.events.last().unwrap();
    assert_eq!(
        (last.request, last.timestamp, last.state),
        (3000, 2999, State::Completed)
    );
}

#[test]
fn repeated_waiting_polls_do_not_flood_events() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let _held = grant(&mut registry, &a, vec![Resource::DesktopInput], 0);
    let id = registry
        .request(b.clone(), vec![Resource::DesktopInput], 0, 100)
        .unwrap();
    registry.poll(id, &b, 1).unwrap();
    let count = registry.events.len();
    for now in 2..100 {
        assert!(registry.poll(id, &b, now).unwrap().is_none());
    }
    assert_eq!(registry.events.len(), count);
}

#[test]
fn generation_exhaustion_is_fail_closed_and_loss_still_fences_other_grants() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let mut first = grant(&mut registry, &a, vec![Resource::DesktopInput], 0);
    let second = grant(&mut registry, &a, vec![Resource::SystemClipboard], 0);
    registry.entries[0].generation = u64::MAX;
    first.generation = u64::MAX;
    error(registry.owner_lost(&a, 1), "GENERATION_EXHAUSTED");
    assert_eq!(
        entry(&registry, first.request_id).state,
        State::FailTestInfra
    );
    assert_eq!(entry(&registry, first.request_id).generation, u64::MAX);
    assert_eq!(
        entry(&registry, second.request_id).state,
        State::ResourceQuarantined
    );
    error(registry.validate(&first, &a, 1), "FAIL_TEST_INFRA");
    error(registry.validate(&second, &a, 1), "STALE_GENERATION");
    let waiting = registry
        .request(b.clone(), vec![Resource::DesktopInput], 1, 100)
        .unwrap();
    assert!(registry.poll(waiting, &b, 1).unwrap().is_none());
}

#[test]
fn clock_regression_schema_mismatch_and_zero_heartbeat_age_are_rejected() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::DesktopInput], 5);
    registry.heartbeat(&lease, &owner, 7).unwrap();
    let snapshot = registry.clone();
    error(registry.validate(&lease, &owner, 6), "CLOCK_REGRESSION");
    error(registry.expire(6), "CLOCK_REGRESSION");
    error(
        registry.request(owner.clone(), vec![Resource::BackgroundCompute], 6, 100),
        "CLOCK_REGRESSION",
    );
    error(registry.expire_heartbeats(7, 0), "INVALID_HEARTBEAT_AGE");
    assert_eq!(registry, snapshot);
    registry.schema_version = 99;
    error(
        registry.poll(lease.request_id, &owner, 7),
        "INVALID_REGISTRY",
    );
}

#[test]
fn conflict_matrix_is_symmetric_and_background_never_conflicts() {
    let resources = [
        Resource::DesktopInput,
        Resource::SystemClipboard,
        window(1),
        window(2),
        semantic("a"),
        semantic("b"),
        Resource::BackgroundCompute,
    ];
    for a in &resources {
        for b in &resources {
            assert_eq!(a.conflicts_with(b), b.conflicts_with(a));
            if matches!(a, Resource::BackgroundCompute) || matches!(b, Resource::BackgroundCompute)
            {
                assert!(!a.conflicts_with(b));
            }
        }
    }
}

#[test]
fn deterministic_poll_orders_never_produce_overlapping_grants() {
    let resource_sets = [
        vec![Resource::DesktopInput, Resource::SystemClipboard],
        vec![Resource::DesktopInput],
        vec![Resource::SystemClipboard],
        vec![semantic("a")],
        vec![semantic("a"), window(1)],
        vec![semantic("b")],
        vec![window(1)],
        vec![window(2)],
        vec![Resource::BackgroundCompute],
        vec![Resource::BackgroundCompute],
    ];
    for rotation in 0..resource_sets.len() {
        let mut registry = Registry::default();
        let owners: Vec<_> = (1..=resource_sets.len() as u32).map(owner).collect();
        let ids: Vec<_> = owners
            .iter()
            .zip(&resource_sets)
            .map(|(owner, resources)| {
                registry
                    .request(owner.clone(), resources.clone(), 0, 100)
                    .unwrap()
            })
            .collect();
        let mut completed = vec![false; ids.len()];
        for round in 1..=ids.len() {
            let mut grants = Vec::new();
            for offset in 0..ids.len() {
                let i = (offset + rotation) % ids.len();
                if !completed[i] {
                    if let Some(lease) = registry.poll(ids[i], &owners[i], round as u64).unwrap() {
                        grants.push((i, lease));
                    }
                }
            }
            let held: Vec<_> = registry
                .entries
                .iter()
                .filter(|entry| entry.holds_resources())
                .collect();
            for (i, first) in held.iter().enumerate() {
                for second in &held[i + 1..] {
                    assert!(!conflicting(&first.resources, &second.resources));
                }
            }
            for (i, lease) in grants {
                registry
                    .release(&lease, &owners[i], &SafePoint::default(), round as u64)
                    .unwrap();
                completed[i] = true;
            }
        }
        assert!(completed.into_iter().all(|done| done));
    }
}

#[test]
fn errors_are_displayable_standard_errors_with_owned_codes() {
    let err = ArbiterError::new("EXAMPLE", "explanation");
    assert_eq!(err.to_string(), "EXAMPLE: explanation");
    let standard: &dyn Error = &err;
    assert!(standard.source().is_none());
    assert_eq!(
        serde_json::from_value::<ArbiterError>(serde_json::to_value(&err).unwrap()).unwrap(),
        err
    );
}

#[test]
fn storage_validation_accepts_all_emitted_lifecycle_states_and_compacted_history() {
    let mut registry = Registry::default();
    let a = owner(1);
    let b = owner(2);
    registry.validate_storage().unwrap();
    let lease = grant(&mut registry, &a, vec![Resource::DesktopInput], 0);
    registry.validate_storage().unwrap();
    registry.begin_gui(&lease, &a, 1).unwrap();
    registry.validate_storage().unwrap();
    let pending = registry
        .request(b.clone(), vec![Resource::DesktopInput], 1, 100)
        .unwrap();
    registry.poll(pending, &b, 1).unwrap();
    registry.validate_storage().unwrap();
    registry
        .yield_gui(&lease, &a, &background_proof(), 2)
        .unwrap();
    registry.validate_storage().unwrap();
    let resumed = registry.resume(lease.request_id, &a, 3, 100).unwrap();
    registry.validate_storage().unwrap();
    registry.cancel(pending, &b, 3).unwrap();
    let resumed_lease = registry.poll(resumed, &a, 3).unwrap().unwrap();
    registry.owner_lost(&a, 4).unwrap();
    registry.validate_storage().unwrap();
    registry
        .recover(resumed_lease.request_id, &SafePoint::default(), 5)
        .unwrap();
    registry.validate_storage().unwrap();
    registry.entries.clear(); // Native compaction preserves monotonic IDs/history.
    registry.validate_storage().unwrap();
}

#[test]
fn malformed_storage_is_rejected_before_grant_without_mutation() {
    let mut valid = Registry::default();
    let a = owner(1);
    let b = owner(2);
    let input = grant(&mut valid, &a, vec![Resource::DesktopInput], 1);
    let clipboard = grant(&mut valid, &b, vec![Resource::SystemClipboard], 1);
    let pending = valid.request(a.clone(), vec![window(5)], 1, 100).unwrap();
    valid.validate_storage().unwrap();
    for corruption in 0..20 {
        let mut bad = valid.clone();
        match corruption {
            0 => bad.schema_version = 99,
            1 => bad.next_id = 0,
            2 => bad.next_id = pending,
            3 => bad.entries[1].request_id = input.request_id,
            4 => bad.entries[0].request_id = 0,
            5 => bad.entries[0].generation = 0,
            6 => bad.entries[0].resources.push(Resource::DesktopInput),
            7 => bad.entries[0].resources.clear(),
            8 => bad.entries[1].resources = input.resources.clone(),
            9 => bad.entries[0].owner.process_birth = 0,
            10 => bad.entries[0].state = State::Completed,
            11 => bad.entries[0].acquired_at = None,
            12 => bad.entries[0].deadline = bad.entries[0].queued_at,
            13 => bad.entries[0].heartbeat = 0,
            14 => bad.entries[0].acquired_at = Some(1001),
            15 => bad.entries[2].state = State::ResourceQuarantined,
            16 => bad.events[0].request = 0,
            17 => bad.events[0].reason.clear(),
            18 => bad.events[0].timestamp = 5,
            _ => {
                bad.entries[0].resources = vec![Resource::SystemClipboard, Resource::DesktopInput];
                bad.entries[1].resources = vec![Resource::BackgroundCompute];
            }
        }
        error(bad.validate_storage(), "INVALID_REGISTRY");
        let snapshot = bad.clone();
        error(bad.poll(pending, &a, 2), "INVALID_REGISTRY");
        assert_eq!(bad, snapshot, "corruption {corruption} mutated storage");
    }
    valid.validate(&clipboard, &b, 2).unwrap();
}

#[test]
fn storage_validation_rejects_unfenced_terminal_states_and_excess_history() {
    let mut valid = Registry::default();
    let a = owner(1);
    let lease = grant(&mut valid, &a, vec![Resource::DesktopInput], 0);
    valid.release(&lease, &a, &SafePoint::default(), 1).unwrap();
    valid.validate_storage().unwrap();
    let mut unfenced = valid.clone();
    unfenced.entries[0].generation = 1;
    error(unfenced.validate_storage(), "INVALID_REGISTRY");
    let mut too_many_events = valid.clone();
    too_many_events.events = vec![valid.events[0].clone(); MAX_EVENTS + 1];
    error(too_many_events.validate_storage(), "INVALID_REGISTRY");
    let mut too_many_entries = valid.clone();
    too_many_entries.entries = vec![valid.entries[0].clone(); MAX_REQUESTS + 1];
    error(too_many_entries.validate_storage(), "INVALID_REGISTRY");
}

#[test]
fn begin_clipboard_requires_system_clipboard_and_marks_the_current_grant() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let input = grant(&mut registry, &owner, vec![Resource::DesktopInput], 0);
    let snapshot = registry.clone();
    error(
        registry.begin_clipboard(&input, &owner, 1),
        "CLIPBOARD_RESOURCE_REQUIRED",
    );
    assert_eq!(registry, snapshot);

    let clipboard = grant(&mut registry, &owner, vec![Resource::SystemClipboard], 1);
    registry.begin_clipboard(&clipboard, &owner, 2).unwrap();
    error(
        registry.begin_clipboard(&clipboard, &owner, 3),
        "CLIPBOARD_TRANSACTION_PENDING",
    );
    assert!(entry(&registry, clipboard.request_id).clipboard_pending);
    assert_eq!(entry(&registry, clipboard.request_id).heartbeat, 2);
    registry.validate_storage().unwrap();
}

#[test]
fn finish_clipboard_requires_system_clipboard() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let input = grant(&mut registry, &owner, vec![Resource::DesktopInput], 0);
    let snapshot = registry.clone();

    error(
        registry.finish_clipboard(&input, &owner, 1),
        "CLIPBOARD_RESOURCE_REQUIRED",
    );
    assert_eq!(registry, snapshot);
}

#[test]
fn pending_clipboard_blocks_release_even_when_safepoint_is_clear() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::SystemClipboard], 0);
    registry.begin_clipboard(&lease, &owner, 1).unwrap();
    let snapshot = registry.clone();

    error(
        registry.release(&lease, &owner, &SafePoint::default(), 2),
        "CLIPBOARD_TRANSACTION_PENDING",
    );
    assert_eq!(registry, snapshot);
}

#[test]
fn pending_clipboard_blocks_yield_even_when_safepoint_is_clear() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(
        &mut registry,
        &owner,
        vec![Resource::DesktopInput, Resource::SystemClipboard],
        0,
    );
    registry.begin_clipboard(&lease, &owner, 1).unwrap();
    let snapshot = registry.clone();

    error(
        registry.yield_gui(&lease, &owner, &background_proof(), 2),
        "CLIPBOARD_TRANSACTION_PENDING",
    );
    assert_eq!(registry, snapshot);
}

#[test]
fn pending_clipboard_blocks_generic_recovery_until_native_checkpoint() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::SystemClipboard], 0);
    registry.begin_clipboard(&lease, &owner, 1).unwrap();
    registry.owner_lost(&owner, 2).unwrap();
    assert_eq!(
        entry(&registry, lease.request_id).state,
        State::ResourceQuarantined
    );
    let snapshot = registry.clone();

    error(
        registry.recover(lease.request_id, &SafePoint::default(), 3),
        "CLIPBOARD_TRANSACTION_PENDING",
    );
    assert_eq!(registry, snapshot);
}

#[test]
fn clipboard_begin_and_finish_reject_wrong_owner_birth_and_fenced_leases() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::SystemClipboard], 0);
    registry.begin_clipboard(&lease, &owner, 1).unwrap();
    let snapshot = registry.clone();

    let mut wrong_owner = owner.clone();
    wrong_owner.worker_id.push_str("-other");
    let mut wrong_birth = owner.clone();
    wrong_birth.process_birth += 1;
    error(
        registry.begin_clipboard(&lease, &wrong_owner, 2),
        "OWNER_MISMATCH",
    );
    error(
        registry.finish_clipboard(&lease, &wrong_birth, 2),
        "OWNER_MISMATCH",
    );
    assert_eq!(registry, snapshot);

    registry.owner_lost(&owner, 2).unwrap();
    let quarantined = registry.clone();
    error(
        registry.begin_clipboard(&lease, &owner, 3),
        "STALE_GENERATION",
    );
    error(
        registry.finish_clipboard(&lease, &owner, 3),
        "STALE_GENERATION",
    );
    assert_eq!(registry, quarantined);
    assert!(entry(&registry, lease.request_id).clipboard_pending);
}

#[test]
fn finishing_clipboard_clears_pending_and_allows_release() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::SystemClipboard], 0);
    registry.begin_clipboard(&lease, &owner, 1).unwrap();
    registry.finish_clipboard(&lease, &owner, 2).unwrap();
    assert!(!entry(&registry, lease.request_id).clipboard_pending);

    registry
        .release(&lease, &owner, &SafePoint::default(), 3)
        .unwrap();
    assert_eq!(entry(&registry, lease.request_id).state, State::Completed);
    registry.validate_storage().unwrap();
}

#[test]
fn owner_loss_preserves_pending_clipboard_and_quarantines_its_funding() {
    let mut registry = Registry::default();
    let next_owner = owner(2);
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::SystemClipboard], 0);
    registry.begin_clipboard(&lease, &owner, 1).unwrap();
    let next = registry
        .request(next_owner.clone(), vec![Resource::SystemClipboard], 1, 100)
        .unwrap();

    registry.owner_lost(&owner, 2).unwrap();
    let quarantined = entry(&registry, lease.request_id);
    assert_eq!(quarantined.state, State::ResourceQuarantined);
    assert!(quarantined.clipboard_pending);
    assert!(quarantined.holds_resources());
    assert!(registry.poll(next, &next_owner, 2).unwrap().is_none());
    registry.validate_storage().unwrap();
}

#[test]
fn clipboard_checkpoint_clears_only_pending_in_quarantine_or_recovering() {
    for checkpoint_state in [State::ResourceQuarantined, State::Recovering] {
        let mut registry = Registry::default();
        let owner = owner(1);
        let lease = grant(&mut registry, &owner, vec![Resource::SystemClipboard], 0);
        registry.begin_clipboard(&lease, &owner, 1).unwrap();

        let active = registry.clone();
        error(
            registry.recover_clipboard_checkpoint(lease.request_id, 2),
            "INVALID_RECOVERY_STATE",
        );
        assert_eq!(registry, active);

        registry.owner_lost(&owner, 2).unwrap();
        registry.entries[0].state = checkpoint_state;
        let before = registry.clone();
        registry
            .recover_clipboard_checkpoint(lease.request_id, 3)
            .unwrap();

        let mut expected = before;
        expected.entries[0].clipboard_pending = false;
        assert_eq!(registry, expected);
        assert!(entry(&registry, lease.request_id).holds_resources());
        assert_eq!(
            entry(&registry, lease.request_id).generation,
            lease.generation + 1
        );
        registry.validate_storage().unwrap();
        registry
            .recover(lease.request_id, &SafePoint::default(), 4)
            .unwrap();
        assert_eq!(entry(&registry, lease.request_id).state, State::Completed);
    }
}

#[test]
fn malformed_pending_clipboard_storage_is_rejected_and_legacy_defaults_false() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(
        &mut registry,
        &owner,
        vec![Resource::DesktopInput, Resource::SystemClipboard],
        0,
    );
    registry.begin_clipboard(&lease, &owner, 1).unwrap();
    registry.validate_storage().unwrap();

    let mut legacy_json = serde_json::to_value(&registry).unwrap();
    legacy_json["entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("clipboard_pending");
    let legacy: Registry = serde_json::from_value(legacy_json).unwrap();
    assert!(!entry(&legacy, lease.request_id).clipboard_pending);
    legacy.validate_storage().unwrap();

    let mut no_clipboard = registry.clone();
    no_clipboard.entries[0]
        .resources
        .retain(|resource| !matches!(resource, Resource::SystemClipboard));
    error(no_clipboard.validate_storage(), "INVALID_REGISTRY");

    let mut no_funding = registry.clone();
    no_funding.entries[0].acquired_at = None;
    error(no_funding.validate_storage(), "INVALID_REGISTRY");

    let mut terminal = registry;
    terminal.entries[0].state = State::Completed;
    terminal.entries[0].generation += 1;
    terminal.entries[0].acquired_at = None;
    error(terminal.validate_storage(), "INVALID_REGISTRY");
}

#[test]
fn scoped_borrow_prevents_release_yield_and_double_return() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::DesktopInput], 0);
    registry.borrow_reservation(&lease, &owner, 1).unwrap();
    error(
        registry.release(&lease, &owner, &SafePoint::default(), 2),
        "LEASE_RESERVATION_ACTIVE",
    );
    error(
        registry.yield_gui(&lease, &owner, &background_proof(), 2),
        "LEASE_RESERVATION_ACTIVE",
    );
    registry.return_reservation(&lease, &owner, 3).unwrap();
    error(
        registry.return_reservation(&lease, &owner, 3),
        "LEASE_RESERVATION_REQUIRED",
    );
    registry
        .release(&lease, &owner, &SafePoint::default(), 4)
        .unwrap();
    error(
        registry.borrow_reservation(&lease, &owner, 5),
        "STALE_GENERATION",
    );
}

#[test]
fn lost_borrow_stays_quarantined_until_confirmed_native_checkpoint() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let lease = grant(&mut registry, &owner, vec![Resource::DesktopInput], 0);
    registry.borrow_reservation(&lease, &owner, 1).unwrap();
    error(
        registry.recover_reservations_checkpoint(lease.request_id, 1),
        "INVALID_RECOVERY_STATE",
    );
    registry.owner_lost(&owner, 2).unwrap();
    error(
        registry.return_reservation(&lease, &owner, 3),
        "STALE_GENERATION",
    );
    error(
        registry.recover(lease.request_id, &SafePoint::default(), 3),
        "LEASE_RESERVATION_ACTIVE",
    );
    registry
        .recover_reservations_checkpoint(lease.request_id, 4)
        .unwrap();
    registry
        .recover(lease.request_id, &SafePoint::default(), 4)
        .unwrap();
    registry.validate_storage().unwrap();
}

#[test]
fn more_than_4096_successful_cycles_preserve_ids_and_resume_waiters() {
    let mut registry = Registry::default();
    let owner = owner(1);
    let yielded = grant(&mut registry, &owner, vec![Resource::DesktopInput], 0);
    registry
        .yield_gui(&yielded, &owner, &background_proof(), 0)
        .unwrap();
    let waiting = registry
        .request(
            owner.clone(),
            vec![Resource::SessionSemantic {
                session_id: "waiting".into(),
            }],
            0,
            100,
        )
        .unwrap();
    for _ in 0..MAX_REQUESTS + 2 {
        let lease = grant(&mut registry, &owner, vec![Resource::BackgroundCompute], 1);
        registry
            .release(&lease, &owner, &SafePoint::default(), 1)
            .unwrap();
    }
    assert!(registry.next_id > MAX_REQUESTS as u64);
    assert_eq!(
        entry(&registry, yielded.request_id).state,
        State::BackgroundRunning
    );
    assert_eq!(entry(&registry, waiting).state, State::Queued);
    registry.resume(yielded.request_id, &owner, 2, 100).unwrap();
    registry.validate_storage().unwrap();
}

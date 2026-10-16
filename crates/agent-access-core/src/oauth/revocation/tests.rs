use super::*;

fn member(token: &str, outcome: MemberOutcome, tries: u8) -> RevocationMember {
    RevocationMember {
        token: token.into(),
        token_type: MemberType::RefreshToken,
        outcome,
        tries,
        not_before: 0,
    }
}

fn row(material: RevocationMaterial) -> RevocationRow {
    RevocationRow {
        id: "id".into(),
        owner: "user".into(),
        registration: "gitlab".into(),
        fingerprint: "fingerprint".into(),
        family_id: "family".into(),
        cause: RevocationCause::Disconnect,
        state: material.state(),
        refresh_attempt: None,
        due_at: 0,
        material: Some(material),
    }
}

fn material(members: Vec<RevocationMember>) -> RevocationMaterial {
    RevocationMaterial {
        members,
        refresh_awaited_until: None,
        unknown_successor: false,
    }
}

fn not_before(record: &RevocationRow, token: &str) -> i64 {
    record
        .material
        .as_ref()
        .unwrap()
        .members
        .iter()
        .find(|member| member.token == token)
        .unwrap()
        .not_before
}

#[test]
fn the_most_severe_state_answers_for_several_revocations() {
    use RemoteRevocation::*;
    assert_eq!(RemoteRevocation::summarize([]), NotRequested);
    assert_eq!(RemoteRevocation::summarize([Revoked, Revoked]), Revoked);
    assert_eq!(RemoteRevocation::summarize([Revoked, Pending]), Pending);
    assert_eq!(RemoteRevocation::summarize([Pending, Failed]), Failed);
    assert_eq!(
        RemoteRevocation::summarize([Failed, Unconfirmed, Revoked]),
        Unconfirmed
    );
    for state in [Pending, Revoked, Failed, Unconfirmed] {
        assert_eq!(RemoteRevocation::parse_stored(state.as_str()), Some(state));
        assert_eq!(
            serde_json::to_value(state).unwrap(),
            serde_json::json!(state.as_str())
        );
    }
    assert_eq!(RemoteRevocation::parse_stored("not_requested"), None);
    // Listings keep a registration whose revocation is unfinished or needs
    // provider-side cleanup.
    for (state, attention) in [
        (NotRequested, false),
        (Revoked, false),
        (Pending, true),
        (Failed, true),
        (Unconfirmed, true),
    ] {
        assert_eq!(state.needs_attention(), attention, "{state:?}");
    }
    for cause in [
        RevocationCause::Disconnect,
        RevocationCause::Superseded,
        RevocationCause::PrincipalDisabled,
        RevocationCause::RefreshUncertain,
    ] {
        assert_eq!(RevocationCause::parse(cause.as_str()), Some(cause));
    }
}

/// `revoked` only when every known member is revoked and no unknown
/// successor can exist; an unknown successor always reports `unconfirmed`.
#[test]
fn states_follow_the_known_family() {
    let mut family = material(vec![
        member("refresh", MemberOutcome::Revoked, 1),
        member("access", MemberOutcome::Revoked, 1),
    ]);
    assert_eq!(family.state(), RemoteRevocation::Revoked);
    family.refresh_awaited_until = Some(10);
    assert_eq!(family.state(), RemoteRevocation::Pending);
    family.refresh_awaited_until = None;
    family.members[1].outcome = MemberOutcome::Failed;
    assert_eq!(family.state(), RemoteRevocation::Failed);
    family.members[1].outcome = MemberOutcome::Pending;
    assert_eq!(family.state(), RemoteRevocation::Pending);
    family.unknown_successor = true;
    assert_eq!(family.state(), RemoteRevocation::Unconfirmed);
    family.members[1].outcome = MemberOutcome::Revoked;
    assert_eq!(family.state(), RemoteRevocation::Unconfirmed);
}

#[test]
fn passes_retry_on_a_growing_schedule_and_honor_retry_after() {
    let now = 1_000;
    let mut record = row(material(vec![member("refresh", MemberOutcome::Pending, 0)]));
    let failure: Tries = vec![("refresh".into(), Err(OAuthDialectError::Failed))];
    for (tries, wait) in [(1, 30), (2, 120), (3, 600), (4, 3600)] {
        apply_pass(&mut record, &failure, true, &BTreeSet::new(), now);
        assert_eq!(record.state, RemoteRevocation::Pending);
        assert_eq!(record.due_at, now + wait, "{tries}");
        assert_eq!(not_before(&record, "refresh"), now + wait, "{tries}");
        assert_eq!(record.material.as_ref().unwrap().members[0].tries, tries);
    }
    apply_pass(&mut record, &failure, true, &BTreeSet::new(), now);
    assert_eq!(record.state, RemoteRevocation::Failed);
    assert!(record.material.is_none());
    assert_eq!(record.due_at, now + RETENTION_SECONDS);

    let mut record = row(material(vec![member("refresh", MemberOutcome::Pending, 0)]));
    apply_pass(
        &mut record,
        &vec![("refresh".into(), Err(OAuthDialectError::RetryAfter(900)))],
        true,
        &BTreeSet::new(),
        now,
    );
    assert_eq!(record.due_at, now + 900);
    // A rejected client authentication is retried on the same schedule.
    let mut record = row(material(vec![member("refresh", MemberOutcome::Pending, 0)]));
    let rejected: Tries = vec![("refresh".into(), Err(OAuthDialectError::ClientRejected))];
    apply_pass(&mut record, &rejected, true, &BTreeSet::new(), now);
    assert_eq!(record.state, RemoteRevocation::Pending);
    assert_eq!(record.due_at, now + 30);
    // A final rejection fails the token at once; a revoked token is done.
    let mut record = row(material(vec![
        member("refresh", MemberOutcome::Pending, 0),
        member("access", MemberOutcome::Pending, 0),
    ]));
    apply_pass(
        &mut record,
        &vec![
            ("refresh".into(), Err(OAuthDialectError::RequestRejected)),
            ("access".into(), Ok(RevocationOutcome::AlreadyInvalid)),
        ],
        true,
        &BTreeSet::new(),
        now,
    );
    assert_eq!(record.state, RemoteRevocation::Failed);
    assert!(record.material.is_none());
}

/// Each token keeps its own next try: one throttled for 900 seconds is not
/// tried again when another, or an awaited refresh, falls due earlier, and
/// the row is due at the earliest of them.
#[test]
fn each_token_keeps_its_own_retry_deadline() {
    let now = 1_000;
    let mut family = material(vec![
        member("refresh-0", MemberOutcome::Pending, 0),
        member("access-0", MemberOutcome::Pending, 0),
    ]);
    family.refresh_awaited_until = Some(now + 45);
    let mut record = row(family);
    record.refresh_attempt = Some("attempt".into());
    apply_pass(
        &mut record,
        &vec![
            ("refresh-0".into(), Err(OAuthDialectError::RetryAfter(900))),
            ("access-0".into(), Err(OAuthDialectError::Failed)),
        ],
        true,
        &BTreeSet::new(),
        now,
    );
    assert_eq!(not_before(&record, "refresh-0"), now + 900);
    assert_eq!(not_before(&record, "access-0"), now + 30);
    assert_eq!(record.due_at, now + 30);
    // The access token's retry tries only it.
    apply_pass(
        &mut record,
        &vec![("access-0".into(), Ok(RevocationOutcome::Revoked))],
        true,
        &BTreeSet::new(),
        now + 30,
    );
    assert_eq!(not_before(&record, "refresh-0"), now + 900);
    assert_eq!(record.due_at, now + 46);
    // The awaited refresh's expiry presumes it lost without shortening the
    // throttled token's wait, and the row keeps naming the attempt.
    apply_pass(&mut record, &Vec::new(), true, &BTreeSet::new(), now + 46);
    assert_eq!(record.state, RemoteRevocation::Unconfirmed);
    assert_eq!(record.refresh_attempt.as_deref(), Some("attempt"));
    assert_eq!(not_before(&record, "refresh-0"), now + 900);
    assert_eq!(record.due_at, now + 900);
    assert_eq!(record.material.as_ref().unwrap().members[0].tries, 1);
}

/// A refresh in flight at the fence holds the family pending until it
/// settles or expires; one that expired and is not live in this process
/// leaves an unknown successor, and the row still names it for a successor
/// its process reports later. Without a revoking registration the row
/// stops naming it.
#[test]
fn an_expired_refresh_attempt_that_is_not_live_leaves_an_unknown_successor() {
    let now = 1_000;
    let mut family = material(vec![member("refresh", MemberOutcome::Revoked, 1)]);
    family.refresh_awaited_until = Some(now + 20);
    let mut record = row(family.clone());
    record.refresh_attempt = Some("attempt".into());
    apply_pass(&mut record, &Vec::new(), true, &BTreeSet::new(), now);
    assert_eq!(record.state, RemoteRevocation::Pending);
    assert_eq!(record.due_at, now + 21);
    // Still live in this process past its expiry: keep waiting for it.
    let live = BTreeSet::from(["attempt".to_string()]);
    apply_pass(&mut record, &Vec::new(), true, &live, now + 30);
    assert_eq!(record.state, RemoteRevocation::Pending);
    apply_pass(&mut record, &Vec::new(), true, &BTreeSet::new(), now + 30);
    assert_eq!(record.state, RemoteRevocation::Unconfirmed);
    assert!(record.material.is_none());
    assert_eq!(record.refresh_attempt.as_deref(), Some("attempt"));
    // No configured registration can revoke: pending members fail and an
    // open refresh is never learned.
    family
        .members
        .push(member("access", MemberOutcome::Pending, 0));
    let mut record = row(family);
    record.refresh_attempt = Some("attempt".into());
    apply_pass(&mut record, &Vec::new(), false, &BTreeSet::new(), now);
    assert_eq!(record.state, RemoteRevocation::Unconfirmed);
    assert!(record.material.is_none());
    assert_eq!(record.refresh_attempt, None);
}

#[test]
fn a_family_keeps_each_token_once_within_bounds() {
    let mut family = RevocationMaterial::new();
    family.add("refresh", MemberType::RefreshToken, 5);
    family.add("refresh", MemberType::RefreshToken, 5);
    assert_eq!(family.members.len(), 1);
    assert_eq!(family.next_due(9), 5);
    for index in 0..MAX_MEMBERS + 4 {
        family.add(&format!("access-{index}"), MemberType::AccessToken, 5);
    }
    assert_eq!(family.members.len(), MAX_MEMBERS);
    assert!(family.well_formed());
    family.members[0].tries = MAX_TRIES + 1;
    assert!(!family.well_formed());
}

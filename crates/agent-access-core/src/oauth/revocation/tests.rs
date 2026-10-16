use super::*;

fn member(token: &str, outcome: MemberOutcome, tries: u8) -> RevocationMember {
    RevocationMember {
        token: token.into(),
        token_type: MemberType::RefreshToken,
        outcome,
        tries,
    }
}

fn row(material: RevocationMaterial) -> RevocationRow {
    RevocationRow {
        id: "id".into(),
        owner: "user".into(),
        registration: "gitlab".into(),
        fingerprint: "fingerprint".into(),
        cause: RevocationCause::Disconnect,
        state: material.state(),
        due_at: 0,
        material: Some(material),
    }
}

fn material(members: Vec<RevocationMember>) -> RevocationMaterial {
    RevocationMaterial {
        family_id: "family".into(),
        members,
        refresh_attempt: None,
        unknown_successor: false,
    }
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
    family.refresh_attempt = Some(PendingRefresh {
        id: "attempt".into(),
        expires_at: 10,
    });
    assert_eq!(family.state(), RemoteRevocation::Pending);
    family.refresh_attempt = None;
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

/// A refresh in flight at the fence holds the family pending until it
/// settles or expires; one that expired and is not live in this process
/// leaves an unknown successor.
#[test]
fn an_expired_refresh_attempt_that_is_not_live_leaves_an_unknown_successor() {
    let now = 1_000;
    let mut family = material(vec![member("refresh", MemberOutcome::Revoked, 1)]);
    family.refresh_attempt = Some(PendingRefresh {
        id: "attempt".into(),
        expires_at: now + 20,
    });
    let mut record = row(family.clone());
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
    // No configured registration can revoke: pending members fail and an
    // open refresh is never learned.
    family
        .members
        .push(member("access", MemberOutcome::Pending, 0));
    let mut record = row(family);
    apply_pass(&mut record, &Vec::new(), false, &BTreeSet::new(), now);
    assert_eq!(record.state, RemoteRevocation::Unconfirmed);
    assert!(record.material.is_none());
}

#[test]
fn a_family_keeps_each_token_once_within_bounds() {
    let mut family = RevocationMaterial::new("family");
    family.add("refresh", MemberType::RefreshToken);
    family.add("refresh", MemberType::RefreshToken);
    assert_eq!(family.members.len(), 1);
    for index in 0..MAX_MEMBERS + 4 {
        family.add(&format!("access-{index}"), MemberType::AccessToken);
    }
    assert_eq!(family.members.len(), MAX_MEMBERS);
    assert!(family.well_formed());
    family.members[0].tries = MAX_TRIES + 1;
    assert!(!family.well_formed());
}

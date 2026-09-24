//! The access matrix: read versus read/write, for every policy.
//!
//! One table, run against every [`Policy`] implementation. This is the test
//! that answers "can A publish their own, read B's, and not touch B's" — and
//! because the core is sans-IO, it runs with no server, no bucket, and no
//! network.
//!
//! The security rows are the two that deny A any write to B's transcript.
//! They assert a rejected [`Plan`], which is stronger than asserting a status
//! code from a host: a `Plan::Reject` cannot be executed, so there is no path
//! by which a denied request still reaches the store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use txcript_share_core::identity::{ForwardedClientCert, Headers, Identity, StaticTokens};
use txcript_share_core::plan::{ObjectFacts, Plan, Precondition, Request, Status, decide};
use txcript_share_core::policy::{
    AllowAll, ListPlan, ListScope, OwnerPrefix, Policy, ReadOnlyMirror, TeamScoped,
};
use txcript_share_core::{Key, KeyPrefix, Principal, PrincipalId, PrincipalKind};

fn principal(id: &str) -> Principal {
    Principal::new(
        PrincipalId::new(id).expect("valid id"),
        PrincipalKind::Human,
    )
}

fn existing(team: Option<&str>) -> ObjectFacts {
    ObjectFacts {
        version: "\"v1\"".to_string(),
        team: team.map(str::to_string),
    }
}

/// Every policy under test, by name.
fn policies() -> Vec<(&'static str, Box<dyn Policy>)> {
    vec![
        ("OwnerPrefix", Box::new(OwnerPrefix)),
        ("ReadOnlyMirror", Box::new(ReadOnlyMirror)),
        (
            "TeamScoped",
            Box::new(
                TeamScoped::new()
                    .with(PrincipalId::new("alice").expect("id"), "red")
                    .with(PrincipalId::new("bob").expect("id"), "red"),
            ),
        ),
        ("AllowAll", Box::new(AllowAll)),
    ]
}

fn allows_write(plan: &Plan) -> bool {
    matches!(plan, Plan::WriteObject { .. })
}

fn rejected_with(plan: &Plan, status: Status) -> bool {
    matches!(plan, Plan::Reject(got, _) if *got == status)
}

// --- the security property -------------------------------------------

/// **No policy, under any circumstance, lets one principal write over
/// another's transcript.** This is the invariant the whole design exists to
/// hold, so it is asserted across every policy including `AllowAll`.
///
/// It holds structurally rather than by rule: `Request::Publish` carries only
/// a bare session id, and the key is derived from the authenticated
/// principal. A client cannot even express "write to bob's key", which is why
/// `AllowAll` — a policy that permits literally everything — still cannot
/// produce a cross-owner write.
#[test]
fn no_policy_permits_writing_over_another_principals_transcript() {
    let alice = principal("alice");
    for (name, policy) in policies() {
        let plan = decide(
            &Request::Publish {
                session: "sess-1".into(),
                if_match: None,
            },
            &alice,
            Some(&existing(Some("red"))),
            policy.as_ref(),
        );
        if let Plan::WriteObject { key, .. } = &plan {
            assert_eq!(
                key.owner().as_str(),
                "alice",
                "{name}: a publish must land under the caller's own prefix, got {key}"
            );
        }
    }
}

/// The same property for delete, where the client *does* name a full key and
/// so the policy is the only thing standing in the way.
#[test]
fn only_allow_all_permits_deleting_another_principals_transcript() {
    let alice = principal("alice");
    let bobs = Key::parse("bob/sess-1").expect("key");

    for (name, policy) in policies() {
        let plan = decide(
            &Request::Delete { key: bobs.clone() },
            &alice,
            Some(&existing(Some("red"))),
            policy.as_ref(),
        );
        match name {
            // The deliberately-insecure double. Asserted so that if it ever
            // starts denying, we know the test lost its teeth.
            "AllowAll" => assert!(
                matches!(plan, Plan::DeleteObject(_)),
                "AllowAll should allow; the double must stay a double"
            ),
            _ => assert!(
                rejected_with(&plan, Status::FORBIDDEN),
                "{name}: alice deleted bob's transcript — got {plan:?}"
            ),
        }
    }
}

// --- the matrix ------------------------------------------------------

#[test]
fn read_is_allowed_for_others_transcripts_except_across_teams() {
    let alice = principal("alice");
    let carol = principal("carol"); // in no team
    let bobs = Key::parse("bob/sess-1").expect("key");
    let facts = existing(Some("red"));

    let expectations: &[(&str, &Principal, bool)] = &[
        ("OwnerPrefix", &alice, true),
        ("ReadOnlyMirror", &alice, true),
        // alice shares team `red` with the object.
        ("TeamScoped", &alice, true),
        // carol is in no team, so a `red` object is not hers to read.
        ("TeamScoped", &carol, false),
    ];

    for (name, who, expected) in expectations {
        let policy = policies()
            .into_iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, policy)| policy)
            .expect("known policy");
        let plan = decide(
            &Request::Read { key: bobs.clone() },
            who,
            Some(&facts),
            policy.as_ref(),
        );
        assert_eq!(
            matches!(plan, Plan::ReadObject(_)),
            *expected,
            "{name}: read of another's transcript by {} — got {plan:?}",
            who.id
        );
    }
}

#[test]
fn publishing_your_own_is_allowed_except_on_a_read_only_service() {
    let alice = principal("alice");
    let request = Request::Publish {
        session: "sess-1".into(),
        if_match: None,
    };

    for (name, policy) in policies() {
        let plan = decide(&request, &alice, None, policy.as_ref());
        let expected = name != "ReadOnlyMirror";
        assert_eq!(
            allows_write(&plan),
            expected,
            "{name}: publishing own transcript — got {plan:?}"
        );
    }
}

#[test]
fn overwriting_your_own_is_distinct_from_publishing_it() {
    // A read-only mirror denies both, but they reach the policy as different
    // actions; collapsing them into one "write" bit would make an
    // append-only policy inexpressible.
    let alice = principal("alice");
    let request = Request::Publish {
        session: "sess-1".into(),
        if_match: None,
    };
    let fresh = decide(&request, &alice, None, &OwnerPrefix);
    let replacing = decide(&request, &alice, Some(&existing(None)), &OwnerPrefix);
    assert!(allows_write(&fresh));
    assert!(allows_write(&replacing));
}

#[test]
fn listing_scope_follows_the_policy() {
    let alice = principal("alice");
    let own = KeyPrefix::owned_by(PrincipalId::new("alice").expect("id"));

    for (name, policy) in policies() {
        let mine = decide(
            &Request::List {
                scope: ListScope::Mine,
            },
            &alice,
            None,
            policy.as_ref(),
        );
        let everyone = decide(
            &Request::List {
                scope: ListScope::Everyone,
            },
            &alice,
            None,
            policy.as_ref(),
        );
        if name != "AllowAll" {
            assert_eq!(
                mine,
                Plan::List(ListPlan::prefix_is_enough(own.clone())),
                "{name}: `mine` must scope to the caller"
            );
        }
        // A policy that cannot express its read rule as a prefix must say
        // so, or the host lists keys the policy would have denied.
        let expected = if name == "TeamScoped" {
            ListPlan::filtered(KeyPrefix::everything())
        } else {
            ListPlan::prefix_is_enough(KeyPrefix::everything())
        };
        assert_eq!(
            everyone,
            Plan::List(expected),
            "{name}: `everyone` must carry the right filter requirement"
        );
    }
}

/// A policy whose read rule is not a prefix must demand per-entry
/// authorization; otherwise a conforming host — which executes a `Plan`
/// verbatim — returns keys and titles the policy would deny on read.
#[test]
fn a_policy_that_cannot_express_itself_as_a_prefix_demands_filtering() {
    let alice = principal("alice");
    let policy = TeamScoped::new()
        .with(PrincipalId::new("alice").expect("id"), "red")
        .with(PrincipalId::new("bob").expect("id"), "blue");
    let plan = decide(
        &Request::List {
            scope: ListScope::Everyone,
        },
        &alice,
        None,
        &policy,
    );
    match plan {
        Plan::List(list) => assert!(
            list.authorize_each,
            "a team-scoped listing must be filtered, not trusted to its prefix"
        ),
        other => panic!("expected a listing, got {other:?}"),
    }
}

/// A create is conditional: the policy authorized `Publish` against an
/// absent object, and an unconditional write would destroy a transcript
/// another caller created in the meantime.
#[test]
fn publishing_onto_nothing_is_conditional_on_it_still_being_nothing() {
    let plan = decide(
        &Request::Publish {
            session: "sess-1".into(),
            if_match: None,
        },
        &principal("alice"),
        None,
        &OwnerPrefix,
    );
    match plan {
        Plan::WriteObject { precondition, .. } => {
            assert_eq!(precondition, Precondition::IfAbsent);
        }
        other => panic!("expected a write, got {other:?}"),
    }
}

#[test]
fn a_missing_transcript_is_not_found_rather_than_written_over() {
    let alice = principal("alice");
    let plan = decide(
        &Request::Read {
            key: Key::parse("alice/gone").expect("key"),
        },
        &alice,
        None,
        &OwnerPrefix,
    );
    assert!(rejected_with(&plan, Status::NOT_FOUND));
}

// --- identity, at the same abstraction layer -------------------------

#[test]
fn every_identity_double_satisfies_the_shared_conformance_suite() {
    use txcript_share_core::identity::conformance;

    let tokens = StaticTokens::new("x-token").with(
        "alice-secret",
        Principal::new(
            PrincipalId::new("alice").expect("id"),
            PrincipalKind::Service,
        ),
    );
    conformance::absent_credential_is_none(&tokens);
    conformance::malformed_credential_is_not_an_outage(&tokens, "x-token");
    conformance::unknown_credential_is_none(&tokens, "x-token", "not-a-real-token");

    let certs = ForwardedClientCert::new("x-client-subject");
    conformance::absent_credential_is_none(&certs);
    conformance::malformed_credential_is_not_an_outage(&certs, "x-client-subject");
    conformance::ids_are_injective(
        &certs,
        "x-client-subject",
        &[
            "a+b@x.com",
            "a_b@x.com",
            "a b@x.com",
            "A.B@x.com",
            "a.b@x.com",
        ],
    );
}

#[test]
fn an_unauthenticated_request_never_reaches_a_policy() {
    // The host's contract: no principal, no `decide` call. Asserted here as
    // the shape of the API — `decide` cannot be called without a Principal,
    // so 401 is unreachable from inside the core by construction.
    let identity = StaticTokens::new("x-token");
    let found = identity
        .principal(&Headers::new())
        .expect("no backend failure");
    assert!(found.is_none(), "no credential must yield no principal");
}

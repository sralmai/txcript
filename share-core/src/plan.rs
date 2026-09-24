//! The request path, as one pure function.
//!
//! A host parses its runtime's request into a [`Request`], does at most one
//! HEAD to gather [`ObjectFacts`], calls [`decide`], and executes the
//! [`Plan`]. No host contains an authorization branch of its own — that is
//! what keeps the Worker and a native binary from drifting apart, and it is
//! why the access matrix can be tested without either of them.

use crate::policy::{Action, Decision, ListScope, Policy, Target};
use crate::{Key, KeyPrefix, Principal};

/// What the caller asked for, already parsed and validated by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Read {
        key: Key,
    },
    /// `session` is the bare id; the owner segment is never supplied by the
    /// client, it is derived from the principal. That is what makes writing
    /// outside your own namespace unrepresentable rather than merely denied.
    Publish {
        session: String,
        if_match: Option<String>,
    },
    Delete {
        key: Key,
    },
    List {
        scope: ListScope,
    },
}

/// What the host learned about the target object, normally from a HEAD.
/// `None` at the call site means "does not exist".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectFacts {
    pub version: String,
    pub team: Option<String>,
}

/// The conditional write a host must apply, mapped from the request's
/// `If-Match` against what actually exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    None,
    /// The object must not exist.
    IfAbsent,
    /// The object must still be at this version.
    IfVersion(String),
}

/// HTTP status for a rejection. Kept as a plain number so this crate does
/// not depend on an HTTP library for one enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status(pub u16);

impl Status {
    pub const BAD_REQUEST: Status = Status(400);
    pub const UNAUTHORIZED: Status = Status(401);
    pub const FORBIDDEN: Status = Status(403);
    pub const NOT_FOUND: Status = Status(404);
    pub const PRECONDITION_FAILED: Status = Status(412);
}

/// What the host should do next. Every variant is an instruction the host
/// executes verbatim; none of them require a further decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Reject(Status, &'static str),
    ReadObject(Key),
    WriteObject {
        key: Key,
        precondition: Precondition,
    },
    DeleteObject(Key),
    ListPrefix(KeyPrefix),
}

/// Decide one request.
///
/// `facts` describes the object the request targets, or `None` when it does
/// not exist. For [`Request::List`] it is ignored.
///
/// # Panics
/// Never. Every path returns a [`Plan`].
#[must_use]
pub fn decide(
    request: &Request,
    who: &Principal,
    facts: Option<&ObjectFacts>,
    policy: &dyn Policy,
) -> Plan {
    match request {
        Request::Read { key } => {
            // A read of something absent is 404 regardless of policy, but
            // the check still runs first: otherwise the 404/403 split tells
            // an unauthorized caller whether a key exists.
            let target = target_for(key, facts);
            match policy.authorize(who, Action::Read, &target) {
                Decision::Deny(reason) => Plan::Reject(Status::FORBIDDEN, reason),
                Decision::Allow if facts.is_none() => {
                    Plan::Reject(Status::NOT_FOUND, "no such transcript")
                }
                Decision::Allow => Plan::ReadObject(key.clone()),
            }
        }

        Request::Publish { session, if_match } => {
            let Some(key) = Key::new(who.id.clone(), session) else {
                return Plan::Reject(Status::BAD_REQUEST, "session id is not a plain segment");
            };
            let target = target_for(&key, facts);
            // Creating and replacing are different acts, and a policy may
            // allow one without the other.
            let action = if facts.is_some() {
                Action::Overwrite
            } else {
                Action::Publish
            };
            match policy.authorize(who, action, &target) {
                Decision::Deny(reason) => Plan::Reject(Status::FORBIDDEN, reason),
                Decision::Allow => match precondition(if_match.as_deref(), facts) {
                    Ok(precondition) => Plan::WriteObject { key, precondition },
                    Err(reason) => Plan::Reject(Status::PRECONDITION_FAILED, reason),
                },
            }
        }

        Request::Delete { key } => {
            let target = target_for(key, facts);
            match policy.authorize(who, Action::Delete, &target) {
                Decision::Deny(reason) => Plan::Reject(Status::FORBIDDEN, reason),
                Decision::Allow if facts.is_none() => {
                    Plan::Reject(Status::NOT_FOUND, "no such transcript")
                }
                Decision::Allow => Plan::DeleteObject(key.clone()),
            }
        }

        Request::List { scope } => Plan::ListPrefix(policy.list_scope(who, *scope)),
    }
}

fn target_for(key: &Key, facts: Option<&ObjectFacts>) -> Target {
    let target = Target::new(key.clone());
    match facts.and_then(|f| f.team.clone()) {
        Some(team) => target.in_team(team),
        None => target,
    }
}

/// Map `If-Match` onto a store precondition.
///
/// `*` requires existence; a tag list requires a match. An absent object
/// fails either way — a conditional update must never silently become an
/// unconditional create.
fn precondition(
    if_match: Option<&str>,
    facts: Option<&ObjectFacts>,
) -> Result<Precondition, &'static str> {
    let Some(raw) = if_match.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Precondition::None);
    };
    let Some(facts) = facts else {
        return Err("conditional update on a transcript that does not exist");
    };
    if raw == "*" {
        return Ok(Precondition::IfVersion(facts.version.clone()));
    }
    let matched = raw
        .split(',')
        .map(|tag| tag.trim().trim_start_matches("W/"))
        .any(|tag| tag == facts.version);
    if matched {
        Ok(Precondition::IfVersion(facts.version.clone()))
    } else {
        Err("transcript changed since it was read")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::OwnerPrefix;
    use crate::{PrincipalId, PrincipalKind};

    fn principal(id: &str) -> Principal {
        Principal::new(
            PrincipalId::new(id).expect("valid id"),
            PrincipalKind::Human,
        )
    }

    fn facts(version: &str) -> ObjectFacts {
        ObjectFacts {
            version: version.to_string(),
            team: None,
        }
    }

    #[test]
    fn publish_derives_the_key_from_the_principal_not_the_request() {
        let alice = principal("alice");
        let plan = decide(
            &Request::Publish {
                session: "sess-1".into(),
                if_match: None,
            },
            &alice,
            None,
            &OwnerPrefix,
        );
        match plan {
            Plan::WriteObject { key, .. } => assert_eq!(key.to_slug(), "alice/sess-1"),
            other => panic!("expected a write, got {other:?}"),
        }
    }

    #[test]
    fn a_session_id_that_is_not_a_plain_segment_is_rejected() {
        let plan = decide(
            &Request::Publish {
                session: "../bob/sess".into(),
                if_match: None,
            },
            &principal("alice"),
            None,
            &OwnerPrefix,
        );
        assert!(matches!(plan, Plan::Reject(Status::BAD_REQUEST, _)));
    }

    #[test]
    fn if_match_on_a_missing_object_fails_rather_than_creating_it() {
        let plan = decide(
            &Request::Publish {
                session: "sess-1".into(),
                if_match: Some("\"v1\"".into()),
            },
            &principal("alice"),
            None,
            &OwnerPrefix,
        );
        assert!(matches!(plan, Plan::Reject(Status::PRECONDITION_FAILED, _)));
    }

    #[test]
    fn if_match_accepts_lists_and_weak_tags_and_rejects_stale_versions() {
        let alice = principal("alice");
        let current = facts("\"v2\"");
        let publish = |tag: &str| {
            decide(
                &Request::Publish {
                    session: "sess-1".into(),
                    if_match: Some(tag.to_string()),
                },
                &alice,
                Some(&current),
                &OwnerPrefix,
            )
        };
        assert!(matches!(publish("\"v2\""), Plan::WriteObject { .. }));
        assert!(matches!(publish("W/\"v2\""), Plan::WriteObject { .. }));
        assert!(matches!(
            publish("\"v1\", \"v2\""),
            Plan::WriteObject { .. }
        ));
        assert!(matches!(publish("*"), Plan::WriteObject { .. }));
        assert!(matches!(
            publish("\"v1\""),
            Plan::Reject(Status::PRECONDITION_FAILED, _)
        ));
    }

    #[test]
    fn a_denied_read_does_not_reveal_whether_the_key_exists() {
        // Under TeamScoped a foreign object is denied; the status must be
        // the same whether or not it is there, or 403-vs-404 is an oracle.
        use crate::policy::TeamScoped;
        let policy = TeamScoped::new()
            .with(PrincipalId::new("alice").expect("id"), "red")
            .with(PrincipalId::new("bob").expect("id"), "blue");
        let key = Key::parse("bob/sess-1").expect("key");
        let absent = decide(
            &Request::Read { key: key.clone() },
            &principal("alice"),
            None,
            &policy,
        );
        let present = decide(
            &Request::Read { key },
            &principal("alice"),
            Some(&facts("\"v1\"")),
            &policy,
        );
        assert!(matches!(absent, Plan::Reject(Status::FORBIDDEN, _)));
        assert!(matches!(present, Plan::Reject(Status::FORBIDDEN, _)));
    }
}

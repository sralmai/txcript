//! The `Policy` seam: may this principal take this action on this target?
//!
//! Separate from [`Identity`](crate::Identity) on purpose. When ownership is
//! implied by a string transformation on the identity, the transformation
//! *is* the security boundary, and a lossy one silently grants access — which
//! is exactly the bug that motivated this split.
//!
//! [`Target`] carries the object's facts, not just its key, so a policy can
//! be something other than a prefix comparison. [`TeamScoped`] exists to
//! enforce that: with only [`OwnerPrefix`] in the set, a `starts_with` would
//! survive somewhere in the host and this trait would be decoration.

use crate::{Key, KeyPrefix, Principal, PrincipalId};

/// What is being attempted. `Publish`, `Overwrite`, and `Delete` are
/// distinct rather than one "write" bit because real policies separate them:
/// a mirror allows none, an append-only archive allows the first only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Publish,
    Overwrite,
    Delete,
}

/// What is being acted on: the key, plus the facts a policy may need.
///
/// `owner` is the key's owner segment. `team` comes from stored object
/// metadata and is `None` for an object that does not exist yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub key: Key,
    pub team: Option<String>,
}

impl Target {
    #[must_use]
    pub fn new(key: Key) -> Self {
        Self { key, team: None }
    }

    #[must_use]
    pub fn in_team(mut self, team: impl Into<String>) -> Self {
        self.team = Some(team.into());
        self
    }

    #[must_use]
    pub fn owner(&self) -> &PrincipalId {
        self.key.owner()
    }
}

/// The outcome. `Deny` carries a fixed reason, safe to return to a caller:
/// a formatted string would eventually leak a key or an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(&'static str),
}

impl Decision {
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// What a listing was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListScope {
    Mine,
    Everyone,
}

/// How a listing must be executed.
///
/// A prefix alone is not always enough. [`TeamScoped`] admits objects by
/// their stored team, which no prefix describes, so it demands that the host
/// check each entry. Making that a value the host must handle — rather than
/// a prefix it can quietly trust — is what stops a policy silently leaking
/// every key it cannot express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPlan {
    pub prefix: KeyPrefix,
    /// When set, the host must call [`Policy::authorize`] with
    /// [`Action::Read`] on every entry and drop those denied.
    pub authorize_each: bool,
}

impl ListPlan {
    /// The prefix fully describes what may be seen.
    #[must_use]
    pub fn prefix_is_enough(prefix: KeyPrefix) -> Self {
        Self {
            prefix,
            authorize_each: false,
        }
    }

    /// The prefix narrows the scan; the policy decides each entry.
    #[must_use]
    pub fn filtered(prefix: KeyPrefix) -> Self {
        Self {
            prefix,
            authorize_each: true,
        }
    }
}

pub trait Policy: Send + Sync {
    fn authorize(&self, who: &Principal, action: Action, target: &Target) -> Decision;

    /// How a listing must be scoped and, where a prefix is insufficient,
    /// filtered.
    fn list_scope(&self, who: &Principal, scope: ListScope) -> ListPlan;
}

/// Read anyone's, write only your own. The shipped policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnerPrefix;

impl Policy for OwnerPrefix {
    fn authorize(&self, who: &Principal, action: Action, target: &Target) -> Decision {
        match action {
            Action::Read => Decision::Allow,
            Action::Publish | Action::Overwrite | Action::Delete => {
                if target.owner() == &who.id {
                    Decision::Allow
                } else {
                    Decision::Deny("not the owner of this transcript")
                }
            }
        }
    }

    fn list_scope(&self, who: &Principal, scope: ListScope) -> ListPlan {
        ListPlan::prefix_is_enough(match scope {
            ListScope::Mine => KeyPrefix::owned_by(who.id.clone()),
            ListScope::Everyone => KeyPrefix::everything(),
        })
    }
}

/// Everyone reads, nobody writes.
///
/// The alternate that keeps the three write actions from collapsing into
/// one: a policy denying every write while allowing every read cannot be
/// expressed if `Publish` and `Overwrite` are the same variant.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadOnlyMirror;

impl Policy for ReadOnlyMirror {
    fn authorize(&self, _: &Principal, action: Action, _: &Target) -> Decision {
        match action {
            Action::Read => Decision::Allow,
            Action::Publish | Action::Overwrite | Action::Delete => {
                Decision::Deny("this service is read-only")
            }
        }
    }

    fn list_scope(&self, who: &Principal, scope: ListScope) -> ListPlan {
        ListPlan::prefix_is_enough(match scope {
            ListScope::Mine => KeyPrefix::owned_by(who.id.clone()),
            ListScope::Everyone => KeyPrefix::everything(),
        })
    }
}

/// Read within your team, write only your own.
///
/// The alternate that proves the seam. The answer depends on the *object's*
/// stored team, not on its key, so no prefix comparison can implement it —
/// which is what forces the decision to be genuinely delegated to the policy
/// instead of inlined in the host.
#[derive(Debug, Clone)]
pub struct TeamScoped {
    members: Vec<(PrincipalId, String)>,
}

impl TeamScoped {
    #[must_use]
    pub fn new() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    #[must_use]
    pub fn with(mut self, who: PrincipalId, team: impl Into<String>) -> Self {
        self.members.push((who, team.into()));
        self
    }

    fn team_of(&self, who: &PrincipalId) -> Option<&str> {
        self.members
            .iter()
            .find(|(id, _)| id == who)
            .map(|(_, team)| team.as_str())
    }
}

impl Default for TeamScoped {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy for TeamScoped {
    fn authorize(&self, who: &Principal, action: Action, target: &Target) -> Decision {
        match action {
            Action::Read => {
                let mine = self.team_of(&who.id);
                // An object with no recorded team is readable only by its
                // owner: failing closed is the right default for metadata
                // that predates the policy.
                match (mine, target.team.as_deref()) {
                    (Some(a), Some(b)) if a == b => Decision::Allow,
                    _ if target.owner() == &who.id => Decision::Allow,
                    _ => Decision::Deny("outside your team"),
                }
            }
            Action::Publish | Action::Overwrite | Action::Delete => {
                if target.owner() == &who.id {
                    Decision::Allow
                } else {
                    Decision::Deny("not the owner of this transcript")
                }
            }
        }
    }

    fn list_scope(&self, who: &Principal, scope: ListScope) -> ListPlan {
        match scope {
            // Own keys are fully described by a prefix.
            ListScope::Mine => ListPlan::prefix_is_enough(KeyPrefix::owned_by(who.id.clone())),
            // A team is not a prefix, so the scan is broad and every entry
            // must be authorized. Returning a bare `everything` here is how
            // an earlier version leaked every team's keys and titles.
            ListScope::Everyone => ListPlan::filtered(KeyPrefix::everything()),
        }
    }
}

/// Allows everything. For isolating transport and store bugs from policy
/// bugs in tests — never for deployment.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl Policy for AllowAll {
    fn authorize(&self, _: &Principal, _: Action, _: &Target) -> Decision {
        Decision::Allow
    }

    fn list_scope(&self, _: &Principal, _: ListScope) -> ListPlan {
        ListPlan::prefix_is_enough(KeyPrefix::everything())
    }
}

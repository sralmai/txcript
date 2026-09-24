//! Sans-IO authorization core for the shared transcript service.
//!
//! This crate answers one question — *may this principal do this to this
//! object?* — and nothing else. It opens no sockets, spawns no tasks, reads
//! no clock, and has no dependencies. Two consequences follow, and both are
//! the point:
//!
//! - The same rules compile to `wasm32` for a Cloudflare Worker and to a
//!   native binary. There is one implementation of the policy, not two that
//!   drift.
//! - The entire access matrix is a pure function, so "can A overwrite B's
//!   transcript" is a table-driven test with no server, no bucket, and no
//!   network.
//!
//! I/O lives in the host. The host gathers facts ([`ObjectFacts`], normally
//! from a HEAD), calls [`decide`], and executes the returned [`Plan`].
//!
//! # Shape
//!
//! - [`Principal`] — who, as decided by an [`identity::Identity`].
//! - [`policy::Policy`] — whether, given a [`policy::Action`] and a target.
//! - [`decide`] — the whole request path, as one function.

pub mod identity;
pub mod plan;
pub mod policy;

pub use identity::{Headers, Identity, IdentityError};
pub use plan::{ObjectFacts, Plan, Precondition, Request, Status, decide};
pub use policy::{Action, Decision, ListScope, Policy, Target};

use core::fmt;

/// An opaque, stable handle for one authenticated party.
///
/// **This type must be injective in whatever an [`Identity`] derives it
/// from.** Ownership is enforced by comparing these, so two distinct users
/// sharing an id can read, overwrite, and delete each other's transcripts.
/// An earlier prototype derived it by lowercasing an email and replacing
/// punctuation, which collapsed `a+b@x.com`, `a_b@x.com`, and `a b@x.com`
/// onto one value; `identity::conformance` tests this property directly.
///
/// It is deliberately not an email. Anything human-readable belongs in
/// [`Principal::label`], which is never used for a decision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Wrap a value the caller guarantees is injective.
    ///
    /// Must be a single plain segment: an owner that could be `..`, or could
    /// contain a separator, would let one identity address another's keys.
    /// This is the same rule [`Key`] applies to a session, deliberately —
    /// one rule, checked in one place.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        plain_segment(&value).then_some(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether the party is a person or a machine.
///
/// Present because policies legitimately differ between them — a CI service
/// token publishing is not the same act as a human publishing — and because
/// every real identity backend already distinguishes them (Cloudflare Access
/// carries `email` for one and `common_name` for the other).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    Human,
    Service,
}

/// One authenticated party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: PrincipalId,
    /// For display and logs only. Never read by a [`Policy`].
    pub label: Option<String>,
    pub kind: PrincipalKind,
}

impl Principal {
    #[must_use]
    pub fn new(id: PrincipalId, kind: PrincipalKind) -> Self {
        Self {
            id,
            label: None,
            kind,
        }
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// An object's location: `<owner>/<session>`.
///
/// Parsing and rendering live here rather than in a host so that every host
/// agrees on what a key is, and so traversal cannot be reintroduced by one
/// of them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    owner: PrincipalId,
    session: String,
}

impl Key {
    /// Build the key a principal's session lives at.
    ///
    /// `None` when `session` is not a single plain segment. The owner needs
    /// no check here: [`PrincipalId`] cannot hold anything else.
    #[must_use]
    pub fn new(owner: PrincipalId, session: &str) -> Option<Self> {
        plain_segment(session).then(|| Self {
            owner,
            session: session.to_string(),
        })
    }

    /// Parse `<owner>/<session>`. `None` for any other shape, including
    /// extra segments, which is what makes `../` unrepresentable.
    #[must_use]
    pub fn parse(slug: &str) -> Option<Self> {
        let (owner, session) = slug.split_once('/')?;
        if !plain_segment(owner) || !plain_segment(session) {
            return None;
        }
        Some(Self {
            owner: PrincipalId::new(owner)?,
            session: session.to_string(),
        })
    }

    #[must_use]
    pub fn owner(&self) -> &PrincipalId {
        &self.owner
    }

    #[must_use]
    pub fn session(&self) -> &str {
        &self.session
    }

    #[must_use]
    pub fn to_slug(&self) -> String {
        format!("{}/{}", self.owner, self.session)
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.session)
    }
}

/// A listing prefix. `None` inside means "everything".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPrefix(pub Option<PrincipalId>);

impl KeyPrefix {
    #[must_use]
    pub fn everything() -> Self {
        Self(None)
    }

    #[must_use]
    pub fn owned_by(owner: PrincipalId) -> Self {
        Self(Some(owner))
    }

    /// The string a store should list under: `"<owner>/"`, or `""`.
    #[must_use]
    pub fn as_store_prefix(&self) -> String {
        self.0
            .as_ref()
            .map_or_else(String::new, |owner| format!("{owner}/"))
    }
}

/// The single rule for anything that becomes a path segment: non-empty, no
/// separators, no relative names, no control characters, bounded length.
///
/// Both halves of a [`Key`] must satisfy it. Applying it in one place is what
/// stops one half drifting: an earlier version validated the session here and
/// the owner separately, and the owner copy was missing the `..` case.
pub(crate) fn plain_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\', ':'])
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> PrincipalId {
        PrincipalId::new(value).expect("valid id")
    }

    #[test]
    fn principal_ids_reject_anything_that_could_address_another_owner() {
        assert!(PrincipalId::new("abc123").is_some());
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "a:b",
            "a\u{0}b",
            &"x".repeat(129),
        ] {
            assert!(PrincipalId::new(bad).is_none(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn keys_round_trip_through_their_slug() {
        let key = Key::new(id("owner1"), "sess-1").expect("valid key");
        assert_eq!(Key::parse(&key.to_slug()), Some(key));
    }

    #[test]
    fn key_parsing_rejects_traversal_and_extra_segments() {
        for bad in [
            "..", "a/../b", "a/b/c", "/abs", "a/", "", "a//b", "a/.", "../x",
        ] {
            assert!(Key::parse(bad).is_none(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn list_prefixes_render_for_a_store() {
        assert_eq!(KeyPrefix::everything().as_store_prefix(), "");
        assert_eq!(KeyPrefix::owned_by(id("bob")).as_store_prefix(), "bob/");
    }

    proptest::proptest! {
        /// No principal id, however constructed, can produce a slug that
        /// escapes its own prefix or parses as a different owner.
        #[test]
        fn a_key_never_escapes_its_owners_prefix(owner in ".*", session in ".*") {
            let Some(owner) = PrincipalId::new(owner) else { return Ok(()) };
            let Some(key) = Key::new(owner.clone(), &session) else { return Ok(()) };
            let slug = key.to_slug();
            let prefix = format!("{owner}/");
            proptest::prop_assert!(slug.starts_with(&prefix));
            proptest::prop_assert_eq!(slug.matches('/').count(), 1);
            let parsed = Key::parse(&slug);
            proptest::prop_assert_eq!(parsed.as_ref(), Some(&key));
        }

        /// Parsing is total: no input panics, and anything that parses
        /// renders back to itself.
        #[test]
        fn key_parsing_is_total_and_round_trips(slug in ".*") {
            if let Some(key) = Key::parse(&slug) {
                proptest::prop_assert_eq!(key.to_slug(), slug);
            }
        }
    }
}

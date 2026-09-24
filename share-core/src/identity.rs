//! The `Identity` seam: headers in, principal out.
//!
//! Nothing here authorizes. An `Identity` answers *who*, a
//! [`Policy`](crate::Policy) answers *whether*. Keeping them apart is not
//! tidiness: the collision bug this crate's tests guard against came from an
//! identity function that was silently also an authorization function,
//! because the principal string *was* the ownership check.
//!
//! The implementations here are the ones that need no I/O. The real
//! Cloudflare Access and OIDC verifiers live in their hosts, because they
//! fetch JWKS; they implement this same trait and must pass
//! [`conformance`].

use crate::{Principal, PrincipalId, PrincipalKind};

/// Case-insensitive request headers.
///
/// A tiny owned type rather than a dependency on `http`: this crate must
/// compile for `wasm32` inside a Worker, where the runtime's header type is
/// not the one a native server uses.
#[derive(Debug, Clone, Default)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.0.push((name.to_ascii_lowercase(), value.to_string()));
        self
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        let wanted = name.to_ascii_lowercase();
        self.0
            .iter()
            .find(|(key, _)| *key == wanted)
            .map(|(_, value)| value.as_str())
    }
}

impl FromIterator<(String, String)> for Headers {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value))
                .collect(),
        )
    }
}

/// The identity check failed in a way that is not the caller's fault.
///
/// Distinct from `Ok(None)` on purpose. `Ok(None)` is "you presented nothing
/// usable" and becomes 401; `Err` is "I could not check" — a JWKS fetch
/// failed, a key store is down — and becomes 503. Collapsing them turns an
/// outage into a wall of user-facing auth failures and loses the alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityError(pub String);

/// Derives a verified [`Principal`] from request headers.
pub trait Identity: Send + Sync {
    /// # Errors
    /// When the check could not be performed. Malformed, absent, or expired
    /// credentials are `Ok(None)`, not `Err`.
    fn principal(&self, headers: &Headers) -> Result<Option<Principal>, IdentityError>;
}

/// A fixed token-to-principal table.
///
/// The double every other seam's tests run against, and a legitimate
/// deployment for a closed set of machine clients.
#[derive(Debug, Clone, Default)]
pub struct StaticTokens {
    header: String,
    entries: Vec<(String, Principal)>,
}

impl StaticTokens {
    #[must_use]
    pub fn new(header: &str) -> Self {
        Self {
            header: header.to_ascii_lowercase(),
            entries: Vec::new(),
        }
    }

    #[must_use]
    pub fn with(mut self, token: &str, principal: Principal) -> Self {
        self.entries.push((token.to_string(), principal));
        self
    }
}

impl Identity for StaticTokens {
    fn principal(&self, headers: &Headers) -> Result<Option<Principal>, IdentityError> {
        let Some(presented) = headers.get(&self.header) else {
            return Ok(None);
        };
        // Constant-time comparison, and every entry is examined: a
        // short-circuit here leaks the token a byte at a time to anyone who
        // can time the endpoint.
        let mut found = None;
        for (token, principal) in &self.entries {
            if constant_time_eq(token.as_bytes(), presented.as_bytes()) {
                found = Some(principal.clone());
            }
        }
        Ok(found)
    }
}

/// A client-certificate subject forwarded by a terminating proxy.
///
/// This is the alternate that keeps the trait honest. It parses no token and
/// verifies no signature — the proxy already did — so the identity arrives
/// as a bare string. Any design where `principal()` returns JWT claims, or
/// where the trait knows about key rotation, cannot accommodate it.
///
/// The subject is hashed rather than used directly, because a DN is
/// arbitrary text and must not become a path segment.
#[derive(Debug, Clone)]
pub struct ForwardedClientCert {
    header: String,
}

impl ForwardedClientCert {
    #[must_use]
    pub fn new(header: &str) -> Self {
        Self {
            header: header.to_ascii_lowercase(),
        }
    }
}

impl Identity for ForwardedClientCert {
    fn principal(&self, headers: &Headers) -> Result<Option<Principal>, IdentityError> {
        let Some(subject) = headers.get(&self.header).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let id = PrincipalId::new(hex(subject)).ok_or_else(|| {
            // Fail closed. Truncating to fit would map every subject sharing
            // a prefix onto one principal, and those principals can delete
            // each other's transcripts.
            IdentityError(format!(
                "client certificate subject is too long to encode as a \
                 principal id (limit {MAX_SUBJECT_BYTES} bytes)"
            ))
        })?;
        Ok(Some(
            Principal::new(id, PrincipalKind::Service).with_label(subject),
        ))
    }
}

/// The longest subject `hex` can encode within [`PrincipalId`]'s limit.
pub const MAX_SUBJECT_BYTES: usize = 64;

/// An identity backend that is always unavailable — for asserting that a
/// failing check surfaces as 503 rather than 401.
#[derive(Debug, Clone, Default)]
pub struct AlwaysFailing;

impl Identity for AlwaysFailing {
    fn principal(&self, _: &Headers) -> Result<Option<Principal>, IdentityError> {
        Err(IdentityError("identity backend unavailable".to_string()))
    }
}

/// Compare without an early exit, so neither the match position nor the
/// length of the shared prefix is observable in the time taken.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Length is not secret — a differing length is already visible in the
    // request — but the contents must not short-circuit.
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b)
        .fold(0u8, |differences, (x, y)| differences | (x ^ y))
        == 0
}

/// Hex-encode, so the result is reversible and therefore injective, and is
/// always a safe single path segment.
///
/// Deliberately not truncated: a truncated encoding is not injective, and
/// ownership is a comparison of these values. A host with a dependency
/// budget should use a collision-resistant digest instead, which is
/// fixed-length and so has no limit to fail against.
fn hex(subject: &str) -> String {
    subject
        .bytes()
        .fold(String::with_capacity(subject.len() * 2), |mut out, byte| {
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            out.push(DIGITS[usize::from(byte >> 4)] as char);
            out.push(DIGITS[usize::from(byte & 0x0f)] as char);
            out
        })
}

/// Cases every [`Identity`] implementation must satisfy, including the ones
/// that live in hosts and do real cryptography.
///
/// Call from each implementation's own tests. The point of a shared suite is
/// that a seam is only as good as its worst passing implementation.
pub mod conformance {
    // Test support that ships in the library so host crates can run this
    // suite against their real Cloudflare Access and OIDC implementations —
    // a seam is only as good as its worst passing implementation, which
    // means the suite has to reach code that is not in this crate. Its
    // contract is to panic with a useful message, exactly like an assertion,
    // so the workspace-wide `panic` deny is lifted here and nowhere else.
    #![allow(clippy::panic)]

    use super::{Headers, Identity};

    /// An absent credential is `Ok(None)` — a 401, never an error.
    ///
    /// # Panics
    /// When the implementation errors or invents a principal.
    pub fn absent_credential_is_none<I: Identity>(identity: &I) {
        match identity.principal(&Headers::new()) {
            Ok(None) => {}
            other => panic!("absent credential must be Ok(None), got {other:?}"),
        }
    }

    /// Garbage is a user error, not an outage: it must not surface as
    /// `Err`, which a host turns into 503.
    ///
    /// This says nothing about whether garbage authenticates — for a backend
    /// whose credential is an opaque subject string, any non-empty value is
    /// a legitimate identity. Use [`unknown_credential_is_none`] for backends
    /// that have a notion of an unrecognised credential.
    ///
    /// # Panics
    /// When the implementation returns `Err`.
    pub fn malformed_credential_is_not_an_outage<I: Identity>(identity: &I, header: &str) {
        let headers = Headers::new().with(header, "!!! not a credential !!!");
        if let Err(error) = identity.principal(&headers) {
            panic!("malformed credential must not be Err, got {error:?}");
        }
    }

    /// A credential the backend does not recognise yields no principal.
    ///
    /// The strong form, for token and JWT backends. Asserting `Ok(None)`
    /// rather than merely "not an error" is what catches a backend that
    /// mints a principal out of anything it is handed.
    ///
    /// # Panics
    /// When the implementation returns a principal or an error.
    pub fn unknown_credential_is_none<I: Identity>(identity: &I, header: &str, garbage: &str) {
        let headers = Headers::new().with(header, garbage);
        match identity.principal(&headers) {
            Ok(None) => {}
            other => panic!("an unrecognised credential must be Ok(None), got {other:?}"),
        }
    }

    /// Distinct credentials never yield the same principal id.
    ///
    /// The property ownership rests on. Run it over inputs that differ only
    /// in punctuation and case — that is where the real bug was.
    ///
    /// # Panics
    /// When two distinct inputs collide.
    pub fn ids_are_injective<I: Identity>(identity: &I, header: &str, inputs: &[&str]) {
        let mut seen: Vec<(String, &str)> = Vec::new();
        for input in inputs {
            let headers = Headers::new().with(header, input);
            let Ok(Some(principal)) = identity.principal(&headers) else {
                continue;
            };
            let id = principal.id.as_str().to_string();
            if let Some((_, first)) = seen.iter().find(|(seen_id, _)| *seen_id == id) {
                panic!("`{first}` and `{input}` both map to principal id `{id}`");
            }
            seen.push((id, input));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_are_case_insensitive() {
        let headers = Headers::new().with("Cf-Access-Jwt-Assertion", "token");
        assert_eq!(headers.get("cf-access-jwt-assertion"), Some("token"));
        assert_eq!(headers.get("CF-ACCESS-JWT-ASSERTION"), Some("token"));
        assert_eq!(headers.get("other"), None);
    }

    fn tokens() -> StaticTokens {
        let id = PrincipalId::new("alice").expect("valid id");
        StaticTokens::new("x-token").with(
            "alice-secret",
            Principal::new(id, PrincipalKind::Human).with_label("alice@example.com"),
        )
    }

    #[test]
    fn static_tokens_map_only_known_tokens() {
        let identity = tokens();
        let found = identity
            .principal(&Headers::new().with("x-token", "alice-secret"))
            .expect("no backend failure");
        assert_eq!(
            found.map(|p| p.id.as_str().to_string()),
            Some("alice".into())
        );

        let unknown = identity
            .principal(&Headers::new().with("x-token", "nope"))
            .expect("no backend failure");
        assert_eq!(unknown, None);
    }

    #[test]
    fn static_tokens_satisfy_the_conformance_suite() {
        let identity = tokens();
        conformance::absent_credential_is_none(&identity);
        conformance::malformed_credential_is_not_an_outage(&identity, "x-token");
        conformance::unknown_credential_is_none(&identity, "x-token", "not-a-real-token");
        conformance::ids_are_injective(&identity, "x-token", &["alice-secret", "nope"]);
    }

    #[test]
    fn forwarded_client_cert_satisfies_the_conformance_suite() {
        let identity = ForwardedClientCert::new("x-client-subject");
        conformance::absent_credential_is_none(&identity);
        conformance::malformed_credential_is_not_an_outage(&identity, "x-client-subject");
        // The exact inputs that collided under the old lowercase-and-replace
        // scheme in the Worker prototype.
        conformance::ids_are_injective(
            &identity,
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
    fn a_subject_too_long_to_encode_fails_closed() {
        // Truncating to fit would map every subject sharing a 64-byte prefix
        // onto one principal, who could then delete the others' transcripts.
        let identity = ForwardedClientCert::new("x-client-subject");
        let long = "a".repeat(MAX_SUBJECT_BYTES + 1);
        let headers = Headers::new().with("x-client-subject", &long);
        assert!(
            identity.principal(&headers).is_err(),
            "an unencodable subject must be refused, never truncated"
        );
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    proptest::proptest! {
        /// Distinct subjects never share a principal id. The fixed-input
        /// version of this test passed while a 128-character truncation was
        /// silently collapsing every subject with a common 64-byte prefix;
        /// a property sweep is what finds that class of bug.
        #[test]
        fn client_cert_ids_are_injective(a in ".{0,80}", b in ".{0,80}") {
            let identity = ForwardedClientCert::new("s");
            let of = |value: &str| {
                identity
                    .principal(&Headers::new().with("s", value))
                    .ok()
                    .flatten()
                    .map(|p| p.id.as_str().to_string())
            };
            if let (Some(x), Some(y)) = (of(&a), of(&b)) {
                proptest::prop_assert_eq!(x == y, a == b);
            }
        }
    }

    #[test]
    fn a_failing_backend_is_an_error_not_an_anonymous_request() {
        let error = AlwaysFailing.principal(&Headers::new());
        assert!(
            error.is_err(),
            "an unavailable backend must not read as 401"
        );
    }
}

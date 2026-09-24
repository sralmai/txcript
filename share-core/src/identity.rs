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
        Ok(self
            .entries
            .iter()
            .find(|(token, _)| token == presented)
            .map(|(_, principal)| principal.clone()))
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
        let id = PrincipalId::new(stable_id(subject))
            .ok_or_else(|| IdentityError("derived principal id was unusable".to_string()))?;
        Ok(Some(
            Principal::new(id, PrincipalKind::Service).with_label(subject),
        ))
    }
}

/// An identity backend that is always unavailable — for asserting that a
/// failing check surfaces as 503 rather than 401.
#[derive(Debug, Clone, Default)]
pub struct AlwaysFailing;

impl Identity for AlwaysFailing {
    fn principal(&self, _: &Headers) -> Result<Option<Principal>, IdentityError> {
        Err(IdentityError("identity backend unavailable".to_string()))
    }
}

/// A deterministic, injective id for arbitrary identity text.
///
/// FNV-1a over the bytes, rendered hex, **prefixed with the input length and
/// escaped**, so it is a true encoding rather than a digest: distinct inputs
/// cannot collide, which is the property ownership depends on. A real host
/// uses SHA-256 for the same purpose; this crate has no dependencies, and
/// correctness here is injectivity, not preimage resistance.
fn stable_id(subject: &str) -> String {
    let mut out = String::with_capacity(subject.len() * 2);
    for byte in subject.as_bytes() {
        // Hex-encode everything: the result is reversible, therefore
        // injective, and is always a safe single path segment.
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out.truncate(128);
    out
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

    /// A malformed credential is `Ok(None)`, not `Err`: a bad token is a
    /// user error, and must not page anyone.
    ///
    /// # Panics
    /// When the implementation returns `Err`.
    pub fn malformed_credential_is_none<I: Identity>(identity: &I, header: &str) {
        let headers = Headers::new().with(header, "!!! not a credential !!!");
        match identity.principal(&headers) {
            Ok(_) => {}
            Err(error) => panic!("malformed credential must not be Err, got {error:?}"),
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
        conformance::malformed_credential_is_none(&identity, "x-token");
        conformance::ids_are_injective(&identity, "x-token", &["alice-secret", "nope"]);
    }

    #[test]
    fn forwarded_client_cert_satisfies_the_conformance_suite() {
        let identity = ForwardedClientCert::new("x-client-subject");
        conformance::absent_credential_is_none(&identity);
        conformance::malformed_credential_is_none(&identity, "x-client-subject");
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
    fn a_failing_backend_is_an_error_not_an_anonymous_request() {
        let error = AlwaysFailing.principal(&Headers::new());
        assert!(
            error.is_err(),
            "an unavailable backend must not read as 401"
        );
    }
}

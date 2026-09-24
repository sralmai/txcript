//! The service's entire configuration surface.
//!
//! One file, one path, passed as the single argument. Deliberately no
//! environment sniffing and no implicit credential discovery: secrets arrive
//! as *file paths* to be read at startup, so systemd `LoadCredential`,
//! Kubernetes projected secrets, ECS secrets, sops, and agenix all work
//! without this binary knowing any of them exist. The moment it reads
//! `AWS_SECRET_ACCESS_KEY` itself, it is coupled to one delivery mechanism
//! and several deployment targets are lost.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use txcript_share_core::identity::{Identity, StaticTokens};
use txcript_share_core::policy::{AllowAll, OwnerPrefix, Policy, ReadOnlyMirror, TeamScoped};
use txcript_share_core::{Principal, PrincipalId, PrincipalKind};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub identity: IdentityConfig,
    pub store: StoreConfig,
    pub policy: PolicyConfig,
    #[serde(default)]
    pub limits: Limits,
}

fn default_listen() -> SocketAddr {
    // Loopback by default: a service that binds every interface the moment
    // it starts is one misconfiguration away from being the public endpoint
    // this design says it must never be.
    ([127, 0, 0, 1], 8787).into()
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityConfig {
    /// A token table read from a file. Every line is `<token> <id> [label]`.
    StaticTokens {
        header: String,
        tokens_file: PathBuf,
    },
    /// Trust an identity header set by an authenticating proxy.
    ///
    /// **The proxy must be the only route to this service.** If the origin
    /// is reachable directly, anyone can set the header and become anyone.
    /// Bind to loopback and put the proxy in front, or use a network policy.
    ///
    /// The identity is hashed, so any length of address works and the raw
    /// value never becomes a key or appears in a URL.
    ForwardedHeader { header: String },
}

/// A proxy-set identity header, hashed into a principal id.
///
/// `share-core`'s `ForwardedClientCert` hex-encodes instead, because that
/// crate carries no cryptography — which caps it at 64 bytes and *fails* on
/// anything longer. Under Cloudflare Access the header is an email address,
/// so a 65-character address produced a permanent 503 that reads to an
/// operator as a backend outage. A digest is fixed-width and has no such
/// limit.
#[derive(Debug, Clone)]
pub struct HashedHeader {
    header: String,
}

impl HashedHeader {
    #[must_use]
    pub fn new(header: &str) -> Self {
        Self {
            header: header.to_ascii_lowercase(),
        }
    }
}

impl Identity for HashedHeader {
    fn principal(
        &self,
        headers: &txcript_share_core::identity::Headers,
    ) -> Result<Option<Principal>, txcript_share_core::identity::IdentityError> {
        use sha2::{Digest as _, Sha256};

        let Some(subject) = headers.get(&self.header).filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let digest = Sha256::digest(subject.as_bytes());
        let id = digest
            .iter()
            .fold(String::with_capacity(64), |mut out, byte| {
                use std::fmt::Write as _;
                let _ = write!(out, "{byte:02x}");
                out
            });
        let principal = PrincipalId::new(id).ok_or_else(|| {
            txcript_share_core::identity::IdentityError(
                "derived principal id was unusable".to_string(),
            )
        })?;
        Ok(Some(
            Principal::new(principal, PrincipalKind::Human).with_label(subject),
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoreConfig {
    Filesystem {
        root: PathBuf,
    },
    /// Any S3-compatible endpoint: AWS, `R2`, `MinIO`, Ceph.
    ///
    /// Credentials are **not** configured here. They come from the ambient
    /// AWS chain — instance role, web identity, or a credentials file the
    /// deployment mounts — so the same binary works under an IAM role, a
    /// Kubernetes service account, and a static key file without knowing
    /// which it is.
    #[cfg(feature = "s3")]
    S3 {
        bucket: String,
        /// Omit for AWS; set for `R2`, `MinIO`, or another gateway.
        #[serde(default)]
        endpoint: Option<String>,
        /// Prefix inside the bucket, so one bucket can host several
        /// deployments.
        #[serde(default)]
        root: Option<String>,
        /// Self-hosted gateways generally serve path-style only.
        #[serde(default)]
        force_path_style: bool,
    },
    /// Nothing survives a restart. For tests and demos.
    Memory,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyConfig {
    OwnerPrefix,
    ReadOnlyMirror,
    TeamScoped {
        members: Vec<TeamMember>,
    },
    /// Permits everything. Never for a deployment; present so the test
    /// harness can isolate transport bugs from policy bugs.
    AllowAll,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamMember {
    pub principal: String,
    pub team: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_max_document_bytes")]
    pub max_document_bytes: usize,
    #[serde(default = "default_page_size")]
    pub page_size: usize,
    /// Ceiling on how many entries one listing may accumulate.
    ///
    /// `page_size` bounds a single round trip; without this a listing walks
    /// every page into memory, so the response size is set by how much the
    /// bucket holds rather than by anything the operator chose.
    #[serde(default = "default_max_list_entries")]
    pub max_list_entries: usize,
}

const fn default_max_document_bytes() -> usize {
    10 * 1024 * 1024
}

const fn default_page_size() -> usize {
    1000
}

const fn default_max_list_entries() -> usize {
    10_000
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_document_bytes: default_max_document_bytes(),
            page_size: default_page_size(),
            max_list_entries: default_max_list_entries(),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Read { path: PathBuf, detail: String },
    Parse(String),
    Credentials(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Read { path, detail } => {
                write!(f, "reading {}: {detail}", path.display())
            }
            ConfigError::Parse(detail) => write!(f, "parsing configuration: {detail}"),
            ConfigError::Credentials(detail) => write!(f, "loading credentials: {detail}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// # Errors
    /// When the file cannot be read or does not parse.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|error| ConfigError::Read {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
        toml::from_str(&raw).map_err(|error| ConfigError::Parse(error.to_string()))
    }
}

impl IdentityConfig {
    /// # Errors
    /// When a token file cannot be read or contains an unusable principal id.
    pub fn build(&self) -> Result<Box<dyn Identity>, ConfigError> {
        match self {
            IdentityConfig::ForwardedHeader { header } => Ok(Box::new(HashedHeader::new(header))),
            IdentityConfig::StaticTokens {
                header,
                tokens_file,
            } => {
                let raw =
                    std::fs::read_to_string(tokens_file).map_err(|error| ConfigError::Read {
                        path: tokens_file.clone(),
                        detail: error.to_string(),
                    })?;
                let mut tokens = StaticTokens::new(header);
                for (number, line) in raw.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let mut fields = line.split_whitespace();
                    let (Some(token), Some(id)) = (fields.next(), fields.next()) else {
                        return Err(ConfigError::Credentials(format!(
                            "line {}: expected `<token> <id> [label]`",
                            number + 1
                        )));
                    };
                    let principal = PrincipalId::new(id).ok_or_else(|| {
                        ConfigError::Credentials(format!(
                            "line {}: `{id}` is not usable as a principal id",
                            number + 1
                        ))
                    })?;
                    let mut built = Principal::new(principal, PrincipalKind::Service);
                    if let Some(label) = fields.next() {
                        built = built.with_label(label);
                    }
                    tokens = tokens.with(token, built);
                }
                Ok(Box::new(tokens))
            }
        }
    }
}

impl PolicyConfig {
    /// # Errors
    /// When a team member names an unusable principal id.
    pub fn build(&self) -> Result<Box<dyn Policy>, ConfigError> {
        Ok(match self {
            PolicyConfig::OwnerPrefix => Box::new(OwnerPrefix),
            PolicyConfig::ReadOnlyMirror => Box::new(ReadOnlyMirror),
            PolicyConfig::AllowAll => Box::new(AllowAll),
            PolicyConfig::TeamScoped { members } => {
                let mut policy = TeamScoped::new();
                for member in members {
                    let id = PrincipalId::new(member.principal.clone()).ok_or_else(|| {
                        ConfigError::Credentials(format!(
                            "`{}` is not usable as a principal id",
                            member.principal
                        ))
                    })?;
                    policy = policy.with(id, member.team.clone());
                }
                Box::new(policy)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_configuration_parses_and_defaults_sensibly() {
        let config: Config = toml::from_str(
            r#"
            [identity]
            kind = "forwarded_header"
            header = "x-forwarded-user"
            [store]
            kind = "memory"
            [policy]
            kind = "owner_prefix"
            "#,
        )
        .expect("parses");
        assert_eq!(config.listen.to_string(), "127.0.0.1:8787");
        assert_eq!(config.limits.max_document_bytes, 10 * 1024 * 1024);
    }

    /// A long address is an ordinary user, not an outage.
    ///
    /// The hex-encoding identity in `share-core` caps at 64 bytes and errors
    /// beyond it, which the server maps to 503. Under Cloudflare Access the
    /// header is an email, so anyone with a long address got a permanent
    /// "backend unavailable".
    #[test]
    fn a_long_identity_yields_a_principal_rather_than_an_outage() {
        use txcript_share_core::identity::Headers;

        let identity = HashedHeader::new("cf-access-authenticated-user-email");
        let long = format!("{}@example.com", "a".repeat(200));
        let headers = Headers::new().with("cf-access-authenticated-user-email", &long);

        let found = identity
            .principal(&headers)
            .expect("a long address is not a backend failure")
            .expect("it is still an identity");
        assert_eq!(found.id.as_str().len(), 64, "a digest is fixed width");
        assert_eq!(found.label.as_deref(), Some(long.as_str()));
    }

    #[test]
    fn hashed_identities_do_not_collide_where_naive_schemes_did() {
        use txcript_share_core::identity::Headers;

        let identity = HashedHeader::new("x-user");
        let of = |value: &str| {
            identity
                .principal(&Headers::new().with("x-user", value))
                .expect("no failure")
                .expect("a principal")
                .id
                .as_str()
                .to_string()
        };
        let ids: Vec<String> = ["a+b@x.com", "a_b@x.com", "a b@x.com", "A.B@x.com"]
            .iter()
            .map(|value| of(value))
            .collect();
        let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "principal ids must not collide");
    }

    #[test]
    fn an_unknown_key_is_an_error_rather_than_silently_ignored() {
        // A typo in a security-relevant field must not read as a default.
        let bad = toml::from_str::<Config>(
            r#"
            [identity]
            kind = "forwarded_header"
            header = "x-forwarded-user"
            [store]
            kind = "memory"
            [policy]
            kind = "owner_prefx"
            "#,
        );
        assert!(bad.is_err());
    }
}

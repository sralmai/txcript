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
use txcript_share_core::identity::{ForwardedClientCert, Identity, StaticTokens};
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
    ForwardedHeader { header: String },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoreConfig {
    Filesystem {
        root: PathBuf,
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
}

const fn default_max_document_bytes() -> usize {
    10 * 1024 * 1024
}

const fn default_page_size() -> usize {
    1000
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_document_bytes: default_max_document_bytes(),
            page_size: default_page_size(),
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
            IdentityConfig::ForwardedHeader { header } => {
                Ok(Box::new(ForwardedClientCert::new(header)))
            }
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

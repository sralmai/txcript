//! `share` — publish transcripts to a share service, and list what others
//! have published.
//!
//! A thin delegate over [`simple`](crate::harness::simple): the body, codec,
//! and text codec are Simple's, reused verbatim. Simple is deliberately the
//! one format with no [`Store`], because a Simple session is a document
//! handed to txcript directly; `share` is that document at rest behind a URL.
//!
//! # Authorization is not implemented here
//!
//! The service is expected to sit behind something that authenticates —
//! Cloudflare Access, an OIDC proxy, a token gateway. This store only
//! attaches whatever credentials an [`Auth`] provider hands it, and the
//! service decides. An unauthenticated endpoint is a public endpoint, HTTPS
//! or not.
//!
//! Headers are the whole credential abstraction on purpose: a Cloudflare
//! Access service token is two of them, and so is nearly every other
//! gateway's scheme, so a deployment with an unusual setup implements
//! [`Auth`] rather than patching this store.

use std::borrow::Cow;
use std::collections::HashMap;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::harness::simple::{Doc, Simple};
use crate::http;
use crate::transcript::{Codec, Common, Discovered, Harness, Saved, Store, TextCodec, Transcript};

/// Ceiling on a response body, so a hostile or broken service cannot make
/// the client allocate without bound.
const MAX_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;

/// The Share harness marker. Shares Simple's native [`Doc`] body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Share;

impl Harness for Share {
    const NAME: &'static str = "share";
    type Body = Doc;
}

impl Codec for Share {
    fn to_common(transcript: &Transcript<Self>) -> Result<Transcript<Common>> {
        Simple::to_common(&Transcript::<Simple>::new(
            transcript.meta.clone(),
            transcript.body.clone(),
        ))
    }

    fn from_common(transcript: &Transcript<Common>) -> Result<Transcript<Self>> {
        let native = Simple::from_common(transcript)?;
        Ok(Transcript::new(native.meta, native.body))
    }
}

impl TextCodec for Share {
    fn from_text(text: &str) -> Result<Transcript<Self>> {
        let native = Simple::from_text(text)?;
        Ok(Transcript::new(native.meta, native.body))
    }

    fn to_text(transcript: &Transcript<Self>) -> Result<String> {
        Simple::to_text(&Transcript::<Simple>::new(
            transcript.meta.clone(),
            transcript.body.clone(),
        ))
    }
}

// --- credentials ------------------------------------------------------

/// Credentials for the service, as request headers.
///
/// Called per request, so a provider may refresh a short-lived token.
pub trait Auth: Send + Sync {
    /// # Errors
    /// When credentials are configured but cannot be produced.
    fn headers(&self) -> Result<Vec<(Cow<'static, str>, String)>>;

    /// Whether this provider can authenticate writes.
    ///
    /// A reader-only configuration fails `save`/`delete` locally with a
    /// clear message rather than sending a request the service will refuse.
    fn can_write(&self) -> bool {
        true
    }
}

/// No credentials: read whatever the endpoint serves anonymously.
#[derive(Debug, Clone, Copy, Default)]
pub struct Anonymous;

impl Auth for Anonymous {
    fn headers(&self) -> Result<Vec<(Cow<'static, str>, String)>> {
        Ok(Vec::new())
    }
    fn can_write(&self) -> bool {
        false
    }
}

/// Literal headers, one per `TXCRIPT_SHARE_HEADER="Name: value"`.
///
/// The escape hatch that makes a bearer token, basic auth, a Cloudflare
/// Access service token, or another gateway work with no code in this repo.
#[derive(Debug, Clone, Default)]
pub struct EnvHeaders(Vec<(Cow<'static, str>, String)>);

impl EnvHeaders {
    /// Read every `TXCRIPT_SHARE_HEADER*` variable.
    ///
    /// Several are supported because a Cloudflare Access service token is
    /// two headers: set `TXCRIPT_SHARE_HEADER_ID` and
    /// `TXCRIPT_SHARE_HEADER_SECRET`, or any other suffix.
    #[must_use]
    pub fn from_env() -> Self {
        let mut found: Vec<(String, String)> = std::env::vars()
            .filter(|(name, _)| name.starts_with("TXCRIPT_SHARE_HEADER"))
            .collect();
        // Deterministic order, so two runs send the same request.
        found.sort();
        Self(
            found
                .into_iter()
                .filter_map(|(_, value)| parse_header(&value))
                .collect(),
        )
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `Name: value`, which is how a user would write it in a shell.
fn parse_header(raw: &str) -> Option<(Cow<'static, str>, String)> {
    let (name, value) = raw.split_once(':')?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty() || value.is_empty() {
        return None;
    }
    Some((Cow::Owned(name.to_ascii_lowercase()), value.to_string()))
}

impl Auth for EnvHeaders {
    fn headers(&self) -> Result<Vec<(Cow<'static, str>, String)>> {
        Ok(self.0.clone())
    }
    fn can_write(&self) -> bool {
        !self.0.is_empty()
    }
}

/// Percent-encode one path segment.
///
/// Session ids are copied verbatim out of other agents' files, and
/// `checked_id_component` only rejects what would be unsafe as a *file* name —
/// `#`, `?` and `%` all pass it. Interpolated raw, a `#` truncates the URL and
/// the transcript publishes under a different key than the caller named. Both
/// hosts decode escapes, so encoding here is the whole fix.
fn encoded_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    out
}

/// The same, for an `<owner>/<session>` slug: the separator stays a separator.
fn encoded_slug(slug: &str) -> String {
    slug.split('/')
        .map(encoded_segment)
        .collect::<Vec<_>>()
        .join("/")
}

// --- the store --------------------------------------------------------

/// A published transcript: its slug (`<owner>/<session>`) and the service's
/// `ETag`, which doubles as the change cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareRef {
    pub slug: String,
    pub etag: Option<String>,
}

impl ShareRef {
    #[must_use]
    pub fn key(&self) -> String {
        self.slug.clone()
    }
}

/// Reads and writes transcripts against a share service.
pub struct ShareStore {
    base_url: String,
    auth: Box<dyn Auth>,
    agent: http::Agent,
}

impl ShareStore {
    /// From `TXCRIPT_SHARE_URL` plus whichever credential variables are set.
    ///
    /// Configuring the endpoint is what opts a machine in: unset means the
    /// feature is not configured, and nothing contacts anything.
    ///
    /// # Errors
    /// When no endpoint is configured or the transport cannot start.
    pub fn from_env() -> Result<Self> {
        let base = std::env::var("TXCRIPT_SHARE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| remote("TXCRIPT_SHARE_URL is not set"))?;
        Self::new(base, Box::new(EnvHeaders::from_env()))
    }

    /// # Errors
    /// When the transport cannot start.
    pub fn new(base_url: impl Into<String>, auth: Box<dyn Auth>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Ok(Self {
            base_url,
            auth,
            // A plain client: this service is ours, it inspects nothing, and
            // imitating a browser would only make the traffic harder to
            // recognise in a log.
            agent: http::Agent::start_with(Share::NAME, http::Profile::Plain)?,
        })
    }

    fn request(&self, method: http::Method, path: &str, body: Vec<u8>) -> Result<http::Response> {
        let sensitive = self.auth.headers()?;
        let response = self.agent.send(http::Request {
            method,
            url: format!("{}{path}", self.base_url),
            body,
            headers: vec![
                ("accept", "application/json".to_string()),
                ("content-type", "application/json".to_string()),
            ],
            sensitive,
            max_bytes: MAX_RESPONSE_BYTES,
        })?;
        // A redirect is never content here: an unauthenticated request to a
        // gateway-protected origin gets a 302 to a login page, and following
        // it would parse an HTML form as a transcript.
        if (300..400).contains(&response.status) {
            return Err(remote(
                "the service redirected, which usually means the request was not authenticated",
            ));
        }
        Ok(response)
    }
}

fn remote(detail: &str) -> Error {
    Error::Remote {
        harness: Share::NAME,
        detail: detail.to_string(),
    }
}

fn read_only_error() -> Error {
    remote(
        "no write credentials are configured, so this share endpoint is read-only \
         (set TXCRIPT_SHARE_HEADER… to publish)",
    )
}

/// The service's own error shape, so its reason reaches the user.
#[derive(Deserialize)]
struct ServiceError {
    error: Option<String>,
}

fn check(response: &http::Response) -> Result<()> {
    if (200..300).contains(&response.status) {
        return Ok(());
    }
    let reason = serde_json::from_slice::<ServiceError>(&response.body)
        .ok()
        .and_then(|body| body.error)
        .filter(|reason| !reason.is_empty());
    let guidance = match response.status {
        401 => "the share service rejected the credentials",
        403 => "the share service refused: this transcript is not yours",
        404 => "no such transcript",
        412 => "the transcript changed since it was read",
        413 => "the transcript is larger than the service accepts",
        _ => "the share service rejected the request",
    };
    Err(remote(&match reason {
        Some(reason) => format!("HTTP {}: {guidance}: {reason}", response.status),
        None => format!("HTTP {}: {guidance}", response.status),
    }))
}

/// One row of `GET /s`.
#[derive(Deserialize)]
struct Listed {
    slug: String,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    git_branch: Option<String>,
    #[serde(default)]
    model: Option<String>,
}

#[derive(Deserialize)]
struct Listing {
    #[serde(default)]
    sessions: Vec<Listed>,
}

#[derive(Deserialize)]
struct Published {
    slug: String,
    #[serde(default)]
    etag: Option<String>,
}

impl Store for ShareStore {
    type H = Share;
    type Ref = ShareRef;

    /// `GET /s` — metadata only, so listing never downloads a body.
    fn discover(&self) -> Result<Vec<Discovered<ShareRef>>> {
        let response = self.request(http::Method::Get, "/s", Vec::new())?;
        check(&response)?;
        let listing: Listing = serde_json::from_slice(&response.body)
            .map_err(|error| remote(&format!("the share listing changed shape: {error}")))?;

        Ok(listing
            .sessions
            .into_iter()
            .map(|row| {
                let meta = crate::common::Meta {
                    // The slug's session segment is the id the service knows
                    // it by; `id` is whatever the document claimed.
                    id: row
                        .id
                        .clone()
                        .unwrap_or_else(|| row.slug.rsplit('/').next().unwrap_or("").to_string()),
                    timestamp: row
                        .timestamp
                        .as_deref()
                        .and_then(|value| {
                            chrono::DateTime::parse_from_rfc3339(value)
                                .ok()
                                .map(|value| value.with_timezone(&chrono::Utc))
                        })
                        .unwrap_or_else(chrono::Utc::now),
                    cwd: row.cwd,
                    git_branch: row.git_branch,
                    title: row.title,
                    cli_version: None,
                    model: row.model,
                };
                Discovered {
                    meta,
                    reference: ShareRef {
                        slug: row.slug,
                        etag: row.etag,
                    },
                }
            })
            .collect())
    }

    /// `GET /s/<slug>`.
    fn load(&self, reference: &ShareRef) -> Result<Transcript<Share>> {
        let response = self.request(
            http::Method::Get,
            &format!("/s/{}", encoded_slug(&reference.slug)),
            Vec::new(),
        )?;
        check(&response)?;
        let text = std::str::from_utf8(&response.body)
            .map_err(|error| remote(&format!("the transcript was not UTF-8: {error}")))?;
        let mut transcript = Share::from_text(text)?;
        if transcript.meta.id.is_empty() {
            transcript.meta.id = reference
                .slug
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_string();
        }
        Ok(transcript)
    }

    /// `PUT /s/<session>`.
    ///
    /// The owner segment is never sent: the service derives it from the
    /// authenticated principal, so publishing into someone else's namespace
    /// is not expressible from here.
    fn save(&self, transcript: &Transcript<Share>) -> Result<Saved<ShareRef>> {
        if !self.auth.can_write() {
            return Err(read_only_error());
        }
        crate::harness::checked_id_component(Share::NAME, &transcript.meta.id)?;
        let body = Share::to_text(transcript)?;
        let response = self.request(
            http::Method::Put,
            &format!("/s/{}", encoded_segment(&transcript.meta.id)),
            body.into_bytes(),
        )?;
        check(&response)?;
        let published: Published = serde_json::from_slice(&response.body)
            .map_err(|error| remote(&format!("the publish reply changed shape: {error}")))?;
        Ok(Saved {
            id: transcript.meta.id.clone(),
            reference: ShareRef {
                slug: published.slug,
                etag: published.etag,
            },
        })
    }

    /// `DELETE /s/<slug>`.
    fn delete(&self, reference: &ShareRef) -> Result<()> {
        if !self.auth.can_write() {
            return Err(read_only_error());
        }
        let response = self.request(
            http::Method::Delete,
            &format!("/s/{}", encoded_slug(&reference.slug)),
            Vec::new(),
        )?;
        check(&response)
    }

    /// `ETag`s from the last [`discover`](Store::discover). No network: the
    /// cursors were already in the listing.
    fn fingerprints(&self, refs: &[ShareRef]) -> Result<HashMap<String, String>> {
        Ok(refs
            .iter()
            .map(|reference| (reference.key(), reference.etag.clone().unwrap_or_default()))
            .collect())
    }
}

// --- the rules a bucket publisher needs -------------------------------

/// The bucket policy a direct-to-bucket publisher needs: read every
/// transcript, list the bucket, write only its own prefix.
///
/// Deliberately *not* behind `share_s3`. The rules have to be in place before
/// the identity they describe can publish anything, so a stock build has to be
/// able to print them — and someone deciding whether to use the direct path at
/// all should be able to read what it will ask of their bucket first.
///
/// Generated rather than copied out of the documentation, so the two cannot
/// drift, and built through `serde_json` rather than formatted by hand, so a
/// bucket or owner name containing a quote cannot produce a policy that is
/// valid JSON saying something other than it appears to.
///
/// `prefix` is the optional key prefix inside the bucket, for a bucket hosting
/// more than one deployment.
///
/// # Errors
/// When the bucket is empty, or the owner is not usable as a single key
/// segment — the prefix condition is the only thing enforcing ownership on
/// this path, so an owner that is not one segment would widen it silently.
pub fn direct_access_policy(bucket: &str, owner: &str, prefix: Option<&str>) -> Result<String> {
    if bucket.trim().is_empty() {
        return Err(remote("a bucket name is required"));
    }
    crate::harness::checked_id_component(Share::NAME, owner)?;

    // `<prefix>/` or nothing, so the resources below read the same either way.
    let root = prefix
        .map(str::trim)
        .filter(|prefix| !prefix.is_empty())
        .map_or_else(String::new, |prefix| {
            format!("{}/", prefix.trim_end_matches('/'))
        });
    let bucket_arn = format!("arn:aws:s3:::{bucket}");

    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadEveryTranscript",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": format!("{bucket_arn}/{root}*"),
            },
            {
                "Sid": "ListTheBucket",
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": bucket_arn,
                // Scoped, so one bucket can host several deployments without
                // each one being able to enumerate the others.
                "Condition": { "StringLike": { "s3:prefix": [format!("{root}*")] } },
            },
            {
                "Sid": "WriteOnlyMyOwnPrefix",
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:DeleteObject"],
                "Resource": format!("{bucket_arn}/{root}{owner}/*"),
            },
        ],
    });
    serde_json::to_string_pretty(&policy)
        .map_err(|error| remote(&format!("could not render the policy: {error}")))
}

// --- the configured store ---------------------------------------------

/// Whichever share backing this machine is configured for.
///
/// The two paths write the same bucket and are reached the same way, so the
/// rest of txcript does not care which is in use — only that one is. An
/// enum rather than a trait object because [`Store`] has associated types.
pub enum ConfiguredStore {
    /// Through a share service.
    Served(ShareStore),
    /// Straight to an object store, with the bucket policy as the boundary.
    #[cfg(feature = "share_s3")]
    Direct(crate::harness::share_s3::DirectStore),
}

/// The configured share store, or `None` when this machine has none.
///
/// Configuring an endpoint is what opts a machine in. Unset means the
/// feature is not in use, and nothing contacts anything — which is what
/// keeps `txcript list` on an unconfigured machine exactly as fast, and as
/// private, as it is today.
///
/// `TXCRIPT_SHARE_URL` selects the served path; `TXCRIPT_SHARE_BUCKET`
/// selects the direct one. Setting both is a configuration error rather
/// than a silent preference.
///
/// # Errors
/// When both paths are configured, or the selected one is misconfigured.
pub fn from_env() -> Result<Option<ConfiguredStore>> {
    let configured = |name: &str| std::env::var(name).is_ok_and(|value| !value.trim().is_empty());
    // Both variables are read regardless of the features this build has.
    // Reading the bucket only under `share_s3` made the refusal below
    // unreachable, so a build without the backend ignored a configured bucket
    // and reported an empty store — the one answer that looks like success.
    match selected(
        configured("TXCRIPT_SHARE_URL"),
        configured("TXCRIPT_SHARE_BUCKET"),
    )? {
        Selected::Nothing => Ok(None),
        Selected::Served => Ok(Some(ConfiguredStore::Served(ShareStore::from_env()?))),
        #[cfg(feature = "share_s3")]
        Selected::Direct => Ok(Some(ConfiguredStore::Direct(
            crate::harness::share_s3::DirectStore::from_env()?,
        ))),
    }
}

/// Which backing the environment names.
#[derive(Debug, PartialEq, Eq)]
enum Selected {
    Nothing,
    Served,
    #[cfg(feature = "share_s3")]
    Direct,
}

/// The selection rule, separated from the environment so it is testable
/// without mutating process state — which this workspace forbids the `unsafe`
/// for anyway.
fn selected(served: bool, direct: bool) -> Result<Selected> {
    match (served, direct) {
        (false, false) => Ok(Selected::Nothing),
        (true, true) => Err(remote(
            "both TXCRIPT_SHARE_URL and TXCRIPT_SHARE_BUCKET are set; unset one to choose a path",
        )),
        (true, false) => Ok(Selected::Served),
        #[cfg(feature = "share_s3")]
        (false, true) => Ok(Selected::Direct),
        #[cfg(not(feature = "share_s3"))]
        (false, true) => Err(remote(
            "TXCRIPT_SHARE_BUCKET is set but direct S3 support was not compiled in \
             (enable the `share_s3` feature)",
        )),
    }
}

impl Store for ConfiguredStore {
    type H = Share;
    type Ref = ShareRef;

    fn discover(&self) -> Result<Vec<Discovered<ShareRef>>> {
        match self {
            ConfiguredStore::Served(store) => store.discover(),
            #[cfg(feature = "share_s3")]
            ConfiguredStore::Direct(store) => store.discover(),
        }
    }

    fn load(&self, reference: &ShareRef) -> Result<Transcript<Share>> {
        match self {
            ConfiguredStore::Served(store) => store.load(reference),
            #[cfg(feature = "share_s3")]
            ConfiguredStore::Direct(store) => store.load(reference),
        }
    }

    fn save(&self, transcript: &Transcript<Share>) -> Result<Saved<ShareRef>> {
        match self {
            ConfiguredStore::Served(store) => store.save(transcript),
            #[cfg(feature = "share_s3")]
            ConfiguredStore::Direct(store) => store.save(transcript),
        }
    }

    fn delete(&self, reference: &ShareRef) -> Result<()> {
        match self {
            ConfiguredStore::Served(store) => store.delete(reference),
            #[cfg(feature = "share_s3")]
            ConfiguredStore::Direct(store) => store.delete(reference),
        }
    }

    fn fingerprints(&self, refs: &[ShareRef]) -> Result<HashMap<String, String>> {
        match self {
            ConfiguredStore::Served(store) => store.fingerprints(refs),
            #[cfg(feature = "share_s3")]
            ConfiguredStore::Direct(store) => store.fingerprints(refs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_headers_parse_name_and_value_and_ignore_rubbish() {
        let parsed = parse_header("CF-Access-Client-Id: abc123").expect("parses");
        assert_eq!(parsed.0.as_ref(), "cf-access-client-id");
        assert_eq!(parsed.1, "abc123");
        for bad in ["no-colon", ": value", "name:", ""] {
            assert!(parse_header(bad).is_none(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn configuring_both_paths_is_an_error_rather_than_a_silent_preference() {
        assert!(selected(true, true).is_err());
        assert_eq!(selected(false, false).ok(), Some(Selected::Nothing));
        assert_eq!(selected(true, false).ok(), Some(Selected::Served));
    }

    #[test]
    #[cfg(not(feature = "share_s3"))]
    fn a_configured_bucket_is_refused_by_name_when_the_backend_is_absent() {
        // Silently reporting an empty store is the one answer that looks like
        // success, so a build that cannot use the bucket has to say so.
        let message = selected(false, true)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(
            message.contains("share_s3"),
            "the refusal must name the missing feature, got {message:?}"
        );
    }

    #[test]
    #[cfg(feature = "share_s3")]
    fn a_configured_bucket_selects_the_direct_path() {
        assert_eq!(selected(false, true).ok(), Some(Selected::Direct));
    }

    #[test]
    fn the_access_policy_grants_reads_broadly_and_writes_only_to_one_prefix() {
        let policy = direct_access_policy("my-bucket", "alice", None).expect("policy");
        let parsed: serde_json::Value = serde_json::from_str(&policy).expect("valid JSON");
        let statements = parsed["Statement"].as_array().expect("statements");

        let resource_of = |sid: &str| {
            statements
                .iter()
                .find(|s| s["Sid"] == sid)
                .map(|s| s["Resource"].as_str().unwrap_or_default().to_string())
                .unwrap_or_default()
        };
        assert_eq!(
            resource_of("ReadEveryTranscript"),
            "arn:aws:s3:::my-bucket/*"
        );
        assert_eq!(resource_of("ListTheBucket"), "arn:aws:s3:::my-bucket");
        // The whole point: writes are confined to the publisher's own prefix,
        // because on this path nothing else enforces ownership.
        assert_eq!(
            resource_of("WriteOnlyMyOwnPrefix"),
            "arn:aws:s3:::my-bucket/alice/*"
        );
    }

    #[test]
    fn a_prefixed_deployment_cannot_read_or_enumerate_its_neighbours() {
        let policy = direct_access_policy("shared", "alice", Some("prod/")).expect("policy");
        let parsed: serde_json::Value = serde_json::from_str(&policy).expect("valid JSON");
        let statements = parsed["Statement"].as_array().expect("statements");

        let listing = statements
            .iter()
            .find(|s| s["Sid"] == "ListTheBucket")
            .expect("listing statement");
        assert_eq!(
            listing["Condition"]["StringLike"]["s3:prefix"][0], "prod/*",
            "a listing must be scoped, or one deployment enumerates the others"
        );
        let write = statements
            .iter()
            .find(|s| s["Sid"] == "WriteOnlyMyOwnPrefix")
            .expect("write statement");
        assert_eq!(write["Resource"], "arn:aws:s3:::shared/prod/alice/*");
    }

    #[test]
    fn an_owner_that_is_not_one_segment_is_refused() {
        // The prefix condition is the only thing enforcing ownership here, so
        // an owner carrying a separator or a traversal would widen it.
        for bad in ["", "a/b", "..", "a\\b"] {
            assert!(
                direct_access_policy("b", bad, None).is_err(),
                "{bad:?} must not produce a policy"
            );
        }
        assert!(direct_access_policy("", "alice", None).is_err());
    }

    #[test]
    fn path_segments_are_encoded_so_an_id_cannot_truncate_the_url() {
        // `checked_id_component` lets these through: they are safe file names.
        // Raw in a URL, `#` starts a fragment and `?` a query, so the
        // transcript would publish under a shorter key than the caller named.
        assert_eq!(encoded_segment("sess-1"), "sess-1");
        assert_eq!(encoded_segment("a#b"), "a%23b");
        assert_eq!(encoded_segment("a?b"), "a%3Fb");
        assert_eq!(encoded_segment("a b"), "a%20b");
        assert_eq!(encoded_segment("100%"), "100%25");
        // The slug separator stays one; the segments around it do not.
        assert_eq!(encoded_slug("alice/a#b"), "alice/a%23b");
    }

    #[test]
    fn anonymous_credentials_cannot_write() {
        assert!(!Anonymous.can_write());
        assert_eq!(Anonymous.headers().expect("no failure"), Vec::new());
    }

    /// An unconfigured machine has no share store, and reaching that
    /// conclusion must not require a request.
    #[test]
    fn no_configuration_means_no_store_and_no_contact() {
        // Only meaningful when the ambient environment is genuinely unset;
        // the repo never mutates env in tests, so skip rather than fight it.
        if std::env::var_os("TXCRIPT_SHARE_URL").is_some()
            || std::env::var_os("TXCRIPT_SHARE_BUCKET").is_some()
        {
            return;
        }
        let found = from_env().expect("an absent configuration is not an error");
        assert!(
            found.is_none(),
            "unset must mean no store, not a default one"
        );
    }

    #[test]
    fn a_service_error_reaches_the_user_with_its_reason() {
        let response = http::Response {
            status: 403,
            content_type: None,
            cf_mitigated: false,
            body: br#"{"error":"not the owner of this transcript"}"#.to_vec(),
        };
        let message = check(&response).expect_err("403 is an error").to_string();
        assert!(message.contains("not the owner"), "{message}");
        assert!(message.contains("403"), "{message}");
    }
}

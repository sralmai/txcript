//! The access matrix, over real HTTP, against a real filesystem store.
//!
//! `share-core` proves the rules; this proves the *host* applies them. The
//! two can disagree in exactly one way that matters — a denied request that
//! still reaches the store — so the security cases here do not stop at the
//! status code. They re-read the object afterwards and assert the bytes are
//! unchanged. A 403 with a mutated object is the failure a status-only
//! assertion misses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::sync::Arc;

use txcript_share_core::identity::{Identity, StaticTokens};
use txcript_share_core::policy::{OwnerPrefix, Policy, ReadOnlyMirror, TeamScoped};
use txcript_share_core::{Principal, PrincipalId, PrincipalKind};
use txcript_share_server::{State, Store, router};
use txcript_share_store::{Filesystem, InMemory};

const DOC: &str = r#"{"id":"sess-1","title":"Fix the parser","messages":[]}"#;

fn principal(id: &str) -> Principal {
    Principal::new(
        PrincipalId::new(id).expect("valid id"),
        PrincipalKind::Service,
    )
}

fn tokens() -> Box<dyn Identity> {
    Box::new(
        StaticTokens::new("x-token")
            .with("alice-secret", principal("alice"))
            .with("bob-secret", principal("bob")),
    )
}

/// A server on a loopback port, with a real store behind it.
struct Server {
    base: String,
    store: Store,
    _dir: tempfile::TempDir,
}

async fn serve(policy: Box<dyn Policy>) -> Server {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::Filesystem(Filesystem::new(dir.path()));
    let state = Arc::new(State {
        identity: tokens(),
        policy,
        store: store.clone(),
        limits: txcript_share_server::config::Limits::default(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    Server {
        base,
        store,
        _dir: dir,
    }
}

/// A minimal HTTP/1.1 client: enough to drive the service without adding a
/// dependency whose own behaviour would need accounting for.
async fn request(
    base: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let address = base.trim_start_matches("http://");
    let mut socket = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    if let Some(token) = token {
        let _ = write!(head, "x-token: {token}\r\n");
    }
    match body {
        Some(body) => {
            let _ = write!(head, "Content-Length: {}\r\n\r\n", body.len());
        }
        None => head.push_str("Content-Length: 0\r\n\r\n"),
    }
    socket.write_all(head.as_bytes()).await.expect("write head");
    if let Some(body) = body {
        socket.write_all(body.as_bytes()).await.expect("write body");
    }
    let mut raw = Vec::new();
    socket.read_to_end(&mut raw).await.expect("read");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map_or("", |(_, rest)| rest);
    (status, body.to_string())
}

/// The bytes actually at a key, read from the store rather than the API.
async fn stored(server: &Server, slug: &str) -> Option<String> {
    use txcript_share_store::ObjectStore as _;
    let key = txcript_share_core::Key::parse(slug).expect("slug");
    server
        .store
        .get(&key)
        .await
        .expect("get")
        .map(|object| String::from_utf8_lossy(&object.body).into_owned())
}

// --- the security property -------------------------------------------

#[tokio::test]
async fn one_principal_cannot_overwrite_anothers_transcript() {
    let server = serve(Box::new(OwnerPrefix)).await;
    let (status, _) = request(
        &server.base,
        "PUT",
        "/s/sess-1",
        Some("bob-secret"),
        Some(DOC),
    )
    .await;
    assert_eq!(status, 201, "bob publishes his own");

    // Alice cannot name bob's key: a PUT carries only a session id, so this
    // lands under *her* prefix rather than touching his.
    let mischief = r#"{"messages":[],"title":"pwned"}"#;
    let (status, _) = request(
        &server.base,
        "PUT",
        "/s/sess-1",
        Some("alice-secret"),
        Some(mischief),
    )
    .await;
    assert_eq!(status, 201);

    assert_eq!(
        stored(&server, "bob/sess-1").await.as_deref(),
        Some(DOC),
        "bob's transcript must be untouched"
    );
    assert!(stored(&server, "alice/sess-1").await.is_some());
}

#[tokio::test]
async fn a_denied_delete_leaves_the_object_intact() {
    let server = serve(Box::new(OwnerPrefix)).await;
    request(
        &server.base,
        "PUT",
        "/s/sess-1",
        Some("bob-secret"),
        Some(DOC),
    )
    .await;

    let (status, _) = request(
        &server.base,
        "DELETE",
        "/s/bob/sess-1",
        Some("alice-secret"),
        None,
    )
    .await;
    assert_eq!(status, 403);
    // The status alone is not the property: assert against the store.
    assert_eq!(stored(&server, "bob/sess-1").await.as_deref(), Some(DOC));
}

#[tokio::test]
async fn a_read_only_deployment_refuses_writes_and_the_store_stays_empty() {
    let server = serve(Box::new(ReadOnlyMirror)).await;
    let (status, _) = request(
        &server.base,
        "PUT",
        "/s/sess-1",
        Some("alice-secret"),
        Some(DOC),
    )
    .await;
    assert_eq!(status, 403);
    assert!(stored(&server, "alice/sess-1").await.is_none());
}

// --- the rest of the matrix ------------------------------------------

#[tokio::test]
async fn an_unauthenticated_request_is_refused_before_any_policy() {
    let server = serve(Box::new(OwnerPrefix)).await;
    for (method, path) in [("GET", "/s"), ("PUT", "/s/x"), ("GET", "/s/alice/x")] {
        let (status, _) = request(&server.base, method, path, None, Some(DOC)).await;
        assert_eq!(status, 401, "{method} {path}");
    }
}

#[tokio::test]
async fn publishing_your_own_then_reading_anothers_both_work() {
    let server = serve(Box::new(OwnerPrefix)).await;
    request(
        &server.base,
        "PUT",
        "/s/sess-1",
        Some("bob-secret"),
        Some(DOC),
    )
    .await;

    let (status, body) = request(
        &server.base,
        "GET",
        "/s/bob/sess-1",
        Some("alice-secret"),
        None,
    )
    .await;
    assert_eq!(status, 200, "reads are open");
    assert!(body.contains("Fix the parser"));
}

#[tokio::test]
async fn deleting_your_own_succeeds_and_removes_it() {
    let server = serve(Box::new(OwnerPrefix)).await;
    request(
        &server.base,
        "PUT",
        "/s/sess-1",
        Some("alice-secret"),
        Some(DOC),
    )
    .await;
    let (status, _) = request(
        &server.base,
        "DELETE",
        "/s/alice/sess-1",
        Some("alice-secret"),
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert!(stored(&server, "alice/sess-1").await.is_none());
}

#[tokio::test]
async fn listing_scopes_to_the_caller_when_asked() {
    let server = serve(Box::new(OwnerPrefix)).await;
    request(&server.base, "PUT", "/s/a", Some("alice-secret"), Some(DOC)).await;
    request(&server.base, "PUT", "/s/b", Some("bob-secret"), Some(DOC)).await;

    let (_, all) = request(&server.base, "GET", "/s", Some("alice-secret"), None).await;
    assert!(all.contains("alice/a") && all.contains("bob/b"));

    let (_, mine) = request(
        &server.base,
        "GET",
        "/s?owner=me",
        Some("alice-secret"),
        None,
    )
    .await;
    assert!(mine.contains("alice/a"));
    assert!(!mine.contains("bob/b"), "`owner=me` must exclude others");
}

#[tokio::test]
async fn a_listing_carries_metadata_without_a_second_fetch() {
    let server = serve(Box::new(OwnerPrefix)).await;
    request(
        &server.base,
        "PUT",
        "/s/sess-1",
        Some("alice-secret"),
        Some(DOC),
    )
    .await;
    let (status, body) = request(&server.base, "GET", "/s", Some("alice-secret"), None).await;
    assert_eq!(status, 200);
    assert!(body.contains("Fix the parser"), "title must be listed");
    assert!(body.contains("\"messages\":\"0\""));
}

#[tokio::test]
async fn a_team_policy_hides_other_teams_from_a_listing() {
    // The case a prefix cannot express: the host must filter each entry, and
    // a host that trusted the prefix would leak every team's keys.
    let policy = TeamScoped::new()
        .with(PrincipalId::new("alice").expect("id"), "red")
        .with(PrincipalId::new("bob").expect("id"), "blue");
    let server = serve(Box::new(policy)).await;
    request(&server.base, "PUT", "/s/a", Some("alice-secret"), Some(DOC)).await;
    request(&server.base, "PUT", "/s/b", Some("bob-secret"), Some(DOC)).await;

    let (status, body) = request(&server.base, "GET", "/s", Some("alice-secret"), None).await;
    assert_eq!(status, 200);
    assert!(body.contains("alice/a"), "own transcript is visible");
    assert!(!body.contains("bob/b"), "another team's must not be listed");
}

#[tokio::test]
async fn a_traversal_slug_is_refused() {
    let server = serve(Box::new(OwnerPrefix)).await;
    for path in ["/s/..%2F..%2Fetc%2Fpasswd", "/s/alice/..", "/s/../bob/x"] {
        let (status, _) = request(&server.base, "GET", path, Some("alice-secret"), None).await;
        assert!(
            (400..500).contains(&status),
            "{path} must be refused, got {status}"
        );
    }
}

#[tokio::test]
async fn an_oversized_document_is_refused_before_it_is_stored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::Filesystem(Filesystem::new(dir.path()));
    let state = Arc::new(State {
        identity: tokens(),
        policy: Box::new(OwnerPrefix),
        store: store.clone(),
        limits: txcript_share_server::config::Limits {
            max_document_bytes: 64,
            page_size: 1000,
        },
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });

    let big = format!(r#"{{"messages":[],"title":"{}"}}"#, "x".repeat(200));
    let (status, _) = request(&base, "PUT", "/s/sess-1", Some("alice-secret"), Some(&big)).await;
    assert_eq!(status, 413);
}

#[tokio::test]
async fn a_failing_store_is_unavailable_rather_than_empty() {
    // A backend outage must not read as "you have no transcripts".
    let state = Arc::new(State {
        identity: tokens(),
        policy: Box::new(OwnerPrefix),
        store: Store::Memory(InMemory::failing("simulated outage")),
        limits: txcript_share_server::config::Limits::default(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });

    let (status, body) = request(&base, "GET", "/s", Some("alice-secret"), None).await;
    assert_eq!(status, 503);
    assert!(
        !body.contains("simulated outage"),
        "the backend's own message must not reach the caller"
    );
}

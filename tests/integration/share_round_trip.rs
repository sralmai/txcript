#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! The client and the service, against each other.
//!
//! Both halves are real: `txcript-share-server`'s router over a real
//! filesystem store on a real loopback socket, driven by the real
//! `ShareStore` through the real HTTP transport. Neither side is mocked, so
//! this covers the things a unit test on either half cannot — that the
//! client's URLs match the service's routes, that its JSON shapes match the
//! service's, and that a `Transcript` survives the round trip.
//!
//! It is also the answer to "does the client actually work", which until now
//! only `curl` could demonstrate.

use std::sync::Arc;

use txcript::harness::share::{Anonymous, Auth, ShareRef, ShareStore};
use txcript::{Store, TextCodec, Transcript};
use txcript_share_core::identity::{Identity, StaticTokens};
use txcript_share_core::policy::OwnerPrefix;
use txcript_share_core::{Principal, PrincipalId, PrincipalKind};
use txcript_share_server::{State, Store as ServerStore, router};
use txcript_share_store::Filesystem;

/// Credentials as a single header, which is how nearly every gateway works.
struct Token(&'static str);

impl Auth for Token {
    fn headers(&self) -> txcript::Result<Vec<(std::borrow::Cow<'static, str>, String)>> {
        Ok(vec![(
            std::borrow::Cow::Borrowed("x-token"),
            self.0.to_string(),
        )])
    }
}

fn principal(id: &str) -> Principal {
    Principal::new(
        PrincipalId::new(id).expect("valid id"),
        PrincipalKind::Service,
    )
}

/// A service on a loopback port, backed by a real directory.
async fn serve() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity: Box<dyn Identity> = Box::new(
        StaticTokens::new("x-token")
            .with("alice-secret", principal("alice"))
            .with("bob-secret", principal("bob")),
    );
    let state = Arc::new(State {
        identity,
        policy: Box::new(OwnerPrefix),
        store: ServerStore::Filesystem(Filesystem::new(dir.path())),
        limits: txcript_share_server::config::Limits::default(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    (base, dir)
}

const DOC: &str = r#"{
  "id": "sess-round-trip",
  "title": "Fix the parser",
  "cwd": "/work/repo",
  "git_branch": "main",
  "messages": [
    { "role": "user", "content": "run the tests" },
    { "role": "assistant", "content": "All green." }
  ]
}"#;

fn transcript() -> Transcript<txcript::harness::share::Share> {
    txcript::harness::share::Share::from_text(DOC).expect("a Simple document")
}

/// The whole loop: publish with the client, read it back with the client,
/// and see it in the client's listing.
#[tokio::test(flavor = "multi_thread")]
async fn a_transcript_survives_publish_list_and_load() {
    let (base, _dir) = serve().await;

    // The store is blocking; keep it off the runtime's threads.
    tokio::task::spawn_blocking(move || {
        let store = ShareStore::new(base, Box::new(Token("alice-secret"))).expect("client");

        let saved = store.save(&transcript()).expect("publish");
        assert_eq!(saved.id, "sess-round-trip");
        assert_eq!(
            saved.reference.slug, "alice/sess-round-trip",
            "the service derives the owner segment, the client never sends it"
        );

        let found = store.discover().expect("listing");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].meta.title.as_deref(), Some("Fix the parser"));
        assert_eq!(
            found[0].meta.cwd.as_deref(),
            Some("/work/repo"),
            "metadata must come back in the listing, without a second fetch"
        );

        let loaded = store.load(&found[0].reference).expect("load");
        let common = txcript::convert::<txcript::harness::share::Share, txcript::Common>(&loaded)
            .expect("to common");
        assert_eq!(
            common.body.len(),
            2,
            "both messages survived the round trip"
        );
        assert_eq!(common.meta.git_branch.as_deref(), Some("main"));
    })
    .await
    .expect("blocking task");
}

/// The service's refusals have to reach the user as errors, not as silence.
#[tokio::test(flavor = "multi_thread")]
async fn the_services_refusal_reaches_the_caller() {
    let (base, _dir) = serve().await;

    tokio::task::spawn_blocking(move || {
        let alice = ShareStore::new(&base, Box::new(Token("alice-secret"))).expect("client");
        alice.save(&transcript()).expect("alice publishes");

        // Bob can read it — reads are open under `owner_prefix`.
        let bob = ShareStore::new(&base, Box::new(Token("bob-secret"))).expect("client");
        let listed = bob.discover().expect("bob lists");
        assert_eq!(listed.len(), 1);
        bob.load(&listed[0].reference).expect("bob reads");

        // But he cannot delete it, and the reason must survive the hop.
        let refused = bob
            .delete(&listed[0].reference)
            .expect_err("bob must not delete alice's transcript");
        let message = refused.to_string();
        assert!(message.contains("403"), "{message}");
        assert!(
            message.contains("not yours") || message.contains("owner"),
            "{message}"
        );
    })
    .await
    .expect("blocking task");
}

/// A bad credential is an error the user can act on, not an empty listing.
#[tokio::test(flavor = "multi_thread")]
async fn an_unauthenticated_client_is_told_so() {
    let (base, _dir) = serve().await;

    tokio::task::spawn_blocking(move || {
        let store = ShareStore::new(base, Box::new(Anonymous)).expect("client");
        let error = store.discover().expect_err("anonymous must be refused");
        let message = error.to_string();
        assert!(message.contains("401"), "{message}");

        // And a read-only provider refuses writes locally, without a request.
        let refused = store.save(&transcript()).expect_err("must refuse");
        assert!(refused.to_string().contains("read-only"), "{refused}");
    })
    .await
    .expect("blocking task");
}

/// Deleting your own works, and the listing reflects it.
#[tokio::test(flavor = "multi_thread")]
async fn a_published_transcript_can_be_withdrawn() {
    let (base, _dir) = serve().await;

    tokio::task::spawn_blocking(move || {
        let store = ShareStore::new(base, Box::new(Token("alice-secret"))).expect("client");
        let saved = store.save(&transcript()).expect("publish");
        store.delete(&saved.reference).expect("withdraw");
        assert!(store.discover().expect("listing").is_empty());
    })
    .await
    .expect("blocking task");
}

/// Fingerprints come from the listing, so a cache check costs no request.
#[tokio::test(flavor = "multi_thread")]
async fn change_cursors_come_from_the_listing() {
    let (base, _dir) = serve().await;

    tokio::task::spawn_blocking(move || {
        let store = ShareStore::new(base, Box::new(Token("alice-secret"))).expect("client");
        store.save(&transcript()).expect("publish");
        let found = store.discover().expect("listing");
        let refs: Vec<ShareRef> = found.into_iter().map(|row| row.reference).collect();

        let cursors = store.fingerprints(&refs).expect("fingerprints");
        let cursor = cursors
            .get(&refs[0].key())
            .expect("a cursor for the published transcript");
        assert!(
            !cursor.is_empty(),
            "an etag must serve as the change cursor"
        );
    })
    .await
    .expect("blocking task");
}

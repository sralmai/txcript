//! Cases every [`ObjectStore`] must satisfy.
//!
//! Written against the trait and run against every implementation,
//! including the ones in hosts that talk to R2 and S3. A seam is only as
//! good as its worst passing implementation, so this suite has to reach code
//! that is not in this crate — which is why it ships in the library rather
//! than living in `tests/`.

// Test support: its contract is to fail loudly with a useful message,
// exactly like an assertion. The workspace-wide bans on panicking are lifted
// here and nowhere else in this crate.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use txcript_share_core::plan::Precondition;
use txcript_share_core::{Key, PrincipalId};

use crate::{Attrs, ObjectStore, StoreError};

/// Build a key under `owner`.
///
/// # Panics
/// When the test's own inputs are not valid segments.
#[must_use]
pub fn key(owner: &str, session: &str) -> Key {
    let owner = PrincipalId::new(owner).unwrap_or_else(|| panic!("bad owner {owner:?}"));
    Key::new(owner, session).unwrap_or_else(|| panic!("bad session {session:?}"))
}

/// Put then get returns the same bytes and attributes.
///
/// # Panics
/// On any mismatch.
pub async fn round_trips_bodies_and_attributes<S: ObjectStore>(store: &S) {
    let k = key("alice", "sess-1");
    let attrs = Attrs::new()
        .set("title", "Fix the parser")
        .set("messages", "3");
    store
        .put(&k, b"{\"messages\":[]}", &attrs, &Precondition::None)
        .await
        .expect("put");

    let found = store.get(&k).await.expect("get").expect("object present");
    assert_eq!(found.body, b"{\"messages\":[]}");
    assert_eq!(found.meta.attrs.get("title"), Some("Fix the parser"));
    assert_eq!(found.meta.size, 15);

    let head = store.head(&k).await.expect("head").expect("meta present");
    assert_eq!(head.version, found.meta.version, "head and get must agree");
}

/// The version `put` returns is the version the store then reports.
///
/// Asserting only that `head` and `get` agree let a backend report a version
/// that was never the one it handed back — and a caller that echoes what it
/// reads into `IfVersion` would then be matching on a value the store invented.
///
/// # Panics
/// When the reported version is not the one `put` returned.
pub async fn the_reported_version_is_the_one_put_returned<S: ObjectStore>(store: &S) {
    let k = key("alice", "sess-1");
    // Enough attributes to crowd a byte budget: a backend that stores the
    // version alongside them must not let them displace it.
    let attrs = Attrs::new()
        .set("title", &"t".repeat(600))
        .set("cwd", &"/very/long/path".repeat(60))
        .set("git_branch", &"b".repeat(300));
    let returned = store
        .put(&k, b"body", &attrs, &Precondition::None)
        .await
        .expect("put");

    let head = store.head(&k).await.expect("head").expect("meta present");
    assert_eq!(
        head.version, returned,
        "the store reported a version it never returned from put"
    );
}

/// The version follows the body, so an identical rewrite keeps it.
///
/// This is S3's semantics and the whole set has to match it: an `ETag` is the
/// body's digest and cannot be made to say otherwise. A backend whose version
/// moved on every write — the in-memory double's counter did — lets a caller
/// build on a guarantee the backend the service ships on cannot honour.
///
/// # Panics
/// When a rewrite of identical bytes reports a different version.
pub async fn the_version_follows_the_body<S: ObjectStore>(store: &S) {
    let k = key("alice", "sess-same");
    let first = store
        .put(
            &k,
            b"identical",
            &Attrs::new().set("title", "one"),
            &Precondition::None,
        )
        .await
        .expect("put");
    let again = store
        .put(
            &k,
            b"identical",
            &Attrs::new().set("title", "two"),
            &Precondition::None,
        )
        .await
        .expect("put");
    assert_eq!(
        first, again,
        "the same bytes are the same version, whatever the metadata"
    );

    let changed = store
        .put(&k, b"different", &Attrs::new(), &Precondition::None)
        .await
        .expect("put");
    assert_ne!(first, changed, "different bytes are a different version");
}

/// A missing object is `Ok(None)`, never an error.
///
/// # Panics
/// When the store errors or invents an object.
pub async fn absent_objects_are_none<S: ObjectStore>(store: &S) {
    let k = key("alice", "never-written");
    assert!(store.get(&k).await.expect("get").is_none());
    assert!(store.head(&k).await.expect("head").is_none());
}

/// `IfAbsent` refuses to overwrite an object that already exists.
///
/// # Panics
/// When the second write is allowed.
pub async fn if_absent_rejects_an_existing_object<S: ObjectStore>(store: &S) {
    let k = key("alice", "sess-if-absent");
    store
        .put(&k, b"first", &Attrs::new(), &Precondition::IfAbsent)
        .await
        .expect("first write succeeds");
    match store
        .put(&k, b"second", &Attrs::new(), &Precondition::IfAbsent)
        .await
    {
        Err(StoreError::PreconditionFailed) => {}
        other => panic!("IfAbsent must reject an existing object, got {other:?}"),
    }
    let body = store.get(&k).await.expect("get").expect("present").body;
    assert_eq!(body, b"first", "a rejected write must not have landed");
}

/// A stale `IfVersion` is refused, and a current one accepted.
///
/// # Panics
/// On either failure.
pub async fn if_version_rejects_stale_writes<S: ObjectStore>(store: &S) {
    let k = key("alice", "sess-cas");
    let first = store
        .put(&k, b"one", &Attrs::new(), &Precondition::None)
        .await
        .expect("first write");
    let second = store
        .put(
            &k,
            b"two",
            &Attrs::new(),
            &Precondition::IfVersion(first.as_str().to_string()),
        )
        .await
        .expect("conditional write on the current version");
    assert_ne!(first, second, "a changed body must change the version");

    match store
        .put(
            &k,
            b"three",
            &Attrs::new(),
            &Precondition::IfVersion(first.as_str().to_string()),
        )
        .await
    {
        Err(StoreError::PreconditionFailed) => {}
        other => panic!("a stale IfVersion must be refused, got {other:?}"),
    }
    let body = store.get(&k).await.expect("get").expect("present").body;
    assert_eq!(body, b"two", "the refused write must not have landed");
}

/// Deleting twice succeeds: a retry is not an error.
///
/// # Panics
/// When the second delete fails.
pub async fn delete_is_idempotent<S: ObjectStore>(store: &S) {
    let k = key("alice", "sess-delete");
    store
        .put(&k, b"body", &Attrs::new(), &Precondition::None)
        .await
        .expect("put");
    store.delete(&k, &Precondition::None).await.expect("first");
    store.delete(&k, &Precondition::None).await.expect("second");
    assert!(store.get(&k).await.expect("get").is_none());
}

/// Listing is prefix-scoped, lexicographic, paginated, and carries
/// attributes.
///
/// The attributes clause is the one that matters: S3 returns them inline and
/// a filesystem must go and fetch them, so asserting it here is what stops a
/// caller depending on an S3 accident.
///
/// # Panics
/// On any deviation.
pub async fn listing_paginates_in_order_with_attributes<S: ObjectStore>(store: &S) {
    for (owner, session) in [
        ("alice", "a1"),
        ("alice", "a2"),
        ("alice", "a3"),
        ("bob", "b1"),
    ] {
        let attrs = Attrs::new().set("title", &format!("{owner}-{session}"));
        store
            .put(&key(owner, session), b"{}", &attrs, &Precondition::None)
            .await
            .expect("seed");
    }

    let everything = store.list("", None, 100).await.expect("list all");
    assert_eq!(everything.objects.len(), 4);
    let slugs: Vec<String> = everything.objects.iter().map(|m| m.key.to_slug()).collect();
    let mut sorted = slugs.clone();
    sorted.sort();
    assert_eq!(slugs, sorted, "listing must be lexicographic");
    assert_eq!(
        everything.objects[0].attrs.get("title"),
        Some("alice-a1"),
        "listing must carry attributes without a second fetch"
    );

    let mine = store.list("alice/", None, 100).await.expect("list prefix");
    assert_eq!(mine.objects.len(), 3, "prefix must scope the listing");

    // Page through in twos and confirm the union is the whole set, with no
    // duplicates and no gaps across the cursor boundary.
    let first = store.list("", None, 2).await.expect("page one");
    assert_eq!(first.objects.len(), 2);
    let cursor = first.next.expect("more pages remain");
    let second = store.list("", Some(&cursor), 2).await.expect("page two");
    let paged: Vec<String> = first
        .objects
        .iter()
        .chain(second.objects.iter())
        .map(|m| m.key.to_slug())
        .collect();
    assert_eq!(paged, sorted, "paging must cover every object exactly once");
}

/// A session whose name looks like a backend's bookkeeping is still just a
/// session.
///
/// A store that keeps metadata in a sibling file named `<session>.attrs`
/// silently destroys the transcript stored at that name. Asserting it here
/// means every backend has to keep its bookkeeping out of the key space.
///
/// # Panics
/// When one object's write disturbs another.
pub async fn bookkeeping_names_are_ordinary_sessions<S: ObjectStore>(store: &S) {
    let plain = key("alice", "notes");
    let lookalike = key("alice", "notes.attrs");
    let temporary = key("alice", "notes.tmp");

    for (k, body) in [
        (&lookalike, &b"sidecar-lookalike"[..]),
        (&temporary, &b"temp-lookalike"[..]),
    ] {
        store
            .put(k, body, &Attrs::new(), &Precondition::None)
            .await
            .expect("put lookalike");
    }
    store
        .put(
            &plain,
            b"real",
            &Attrs::new().set("title", "notes"),
            &Precondition::None,
        )
        .await
        .expect("put plain");

    for (k, expected) in [
        (&lookalike, &b"sidecar-lookalike"[..]),
        (&temporary, &b"temp-lookalike"[..]),
        (&plain, &b"real"[..]),
    ] {
        let found = store.get(k).await.expect("get").expect("still present");
        assert_eq!(found.body, expected, "{} was disturbed", k.to_slug());
    }

    let listed = store.list("alice/", None, 100).await.expect("list");
    assert_eq!(listed.objects.len(), 3, "every session must be listed");
}

/// A page that exactly fills `limit` does not claim a next page.
///
/// Handing back a cursor for an empty page makes every caller pay a final
/// pointless round trip, and hides real end-of-listing from them.
///
/// # Panics
/// When a full final page reports more.
pub async fn an_exactly_full_page_is_the_last_page<S: ObjectStore>(store: &S) {
    for session in ["a", "b"] {
        store
            .put(
                &key("alice", session),
                b"{}",
                &Attrs::new(),
                &Precondition::None,
            )
            .await
            .expect("seed");
    }
    let page = store.list("", None, 2).await.expect("list");
    assert_eq!(page.objects.len(), 2);
    assert_eq!(page.next, None, "an exactly-full page must not claim more");

    let partial = store.list("", None, 5).await.expect("list");
    assert_eq!(partial.next, None);
}

/// Run every case, each against a **fresh** store from `make`.
///
/// Isolation is not a nicety here: the listing case asserts the exact
/// contents of an empty-prefix listing, so any object left behind by an
/// earlier case would leak into it. Sharing one instance made this suite
/// pass for the wrong reason until it did not.
///
/// # Panics
/// On the first violation.
pub async fn all<S, F>(make: F)
where
    S: ObjectStore,
    F: Fn() -> S,
{
    round_trips_bodies_and_attributes(&make()).await;
    the_reported_version_is_the_one_put_returned(&make()).await;
    the_version_follows_the_body(&make()).await;
    absent_objects_are_none(&make()).await;
    if_absent_rejects_an_existing_object(&make()).await;
    if_version_rejects_stale_writes(&make()).await;
    delete_is_idempotent(&make()).await;
    listing_paginates_in_order_with_attributes(&make()).await;
    bookkeeping_names_are_ordinary_sessions(&make()).await;
    an_exactly_full_page_is_the_last_page(&make()).await;
}

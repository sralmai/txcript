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
    absent_objects_are_none(&make()).await;
    if_absent_rejects_an_existing_object(&make()).await;
    if_version_rejects_stale_writes(&make()).await;
    delete_is_idempotent(&make()).await;
    listing_paginates_in_order_with_attributes(&make()).await;
}

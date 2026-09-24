//! The conformance suite, run against every [`ObjectStore`].
//!
//! The point is the repetition: the same assertions, unchanged, against an
//! in-memory map and a directory tree. Where an implementation needs the
//! suite bent to pass, the seam is wrong — so the suite is not parameterised
//! per backend, and there are no per-backend skips.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use txcript_share_core::plan::Precondition;
use txcript_share_store::catalog::{Catalog, Entry, InMemoryCatalog, Query, StoreDerived};
use txcript_share_store::{Attrs, Filesystem, InMemory, ObjectStore, StoreError, conformance};

/// Every store under test gets the whole suite. Adding an S3 or R2 backend
/// means adding one line here and nothing else.
macro_rules! store_conformance {
    ($($name:ident => $make:expr),+ $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                conformance::all($make).await;
            }
        )+
    };
}

store_conformance! {
    in_memory_satisfies_the_store_contract => InMemory::new,
    filesystem_satisfies_the_store_contract => || {
        let dir = tempfile::tempdir().expect("tempdir");
        // `keep()` hands the directory to the store for the rest of the
        // process; dropping the handle would delete it mid-test.
        Filesystem::new(dir.keep())
    },
}

// --- properties the suite cannot express generically -----------------

#[tokio::test]
async fn a_failing_backend_reports_an_error_rather_than_an_empty_store() {
    // The distinction a host turns into 503-vs-404. A store that swallowed
    // its own outage would look like "you have no transcripts".
    let store = InMemory::failing("simulated outage");
    let key = conformance::key("alice", "sess-1");
    assert!(matches!(store.get(&key).await, Err(StoreError::Backend(_))));
    assert!(matches!(
        store.list("", None, 10).await,
        Err(StoreError::Backend(_))
    ));
}

#[tokio::test]
async fn the_two_stores_agree_on_listing_order_and_contents() {
    // Differential test: the same writes into both backends must produce the
    // same listing. This is what catches a backend that quietly sorts by
    // insertion, or by mtime, instead of by key.
    let memory = InMemory::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let files = Filesystem::new(dir.path());

    for (owner, session) in [("bob", "z"), ("alice", "m"), ("alice", "a"), ("carol", "b")] {
        let key = conformance::key(owner, session);
        let attrs = Attrs::new().set("title", session);
        for store in [&memory as &dyn ErasedPut, &files as &dyn ErasedPut] {
            store.put_erased(&key, b"{}", &attrs).await;
        }
    }

    let from_memory = memory.list("", None, 100).await.expect("memory list");
    let from_files = files.list("", None, 100).await.expect("filesystem list");
    let slugs = |page: &txcript_share_store::Page| -> Vec<String> {
        page.objects.iter().map(|m| m.key.to_slug()).collect()
    };
    assert_eq!(slugs(&from_memory), slugs(&from_files));
    assert_eq!(
        from_memory.objects[0].attrs.get("title"),
        from_files.objects[0].attrs.get("title"),
        "both backends must surface attributes in a listing"
    );
}

/// Minimal erasure so the differential test can drive both stores in one
/// loop. `ObjectStore` uses `async fn`, which is not dyn-safe.
trait ErasedPut {
    fn put_erased<'a>(
        &'a self,
        key: &'a txcript_share_core::Key,
        body: &'a [u8],
        attrs: &'a Attrs,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + 'a>>;
}

impl<S: ObjectStore> ErasedPut for S {
    fn put_erased<'a>(
        &'a self,
        key: &'a txcript_share_core::Key,
        body: &'a [u8],
        attrs: &'a Attrs,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + 'a>> {
        Box::pin(async move {
            self.put(key, body, attrs, &Precondition::None)
                .await
                .expect("put");
        })
    }
}

// --- catalog ---------------------------------------------------------

#[tokio::test]
async fn a_store_derived_catalog_needs_no_reconciliation() {
    let store = InMemory::new();
    let catalog = StoreDerived::new(store.clone());
    let key = conformance::key("alice", "sess-1");
    store
        .put(
            &key,
            b"{}",
            &Attrs::new().set("title", "Fix the parser"),
            &Precondition::None,
        )
        .await
        .expect("put");

    // No upsert call: the store write is the only write.
    let found = catalog
        .query(&Query {
            prefix: String::new(),
            limit: 10,
        })
        .await
        .expect("query");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].title.as_deref(), Some("Fix the parser"));
}

#[tokio::test]
async fn an_indexed_catalog_can_disagree_with_the_store() {
    // Design B's cost, asserted rather than discovered in production: the
    // index is a second source of truth and goes stale when a write to it is
    // missed. A host must therefore treat a catalog hit as a hint and
    // tolerate the object being gone on read.
    let store = InMemory::new();
    let catalog = InMemoryCatalog::new();
    let key = conformance::key("alice", "sess-1");

    catalog
        .upsert(&Entry {
            key: key.clone(),
            version: "\"v1\"".into(),
            title: Some("indexed".into()),
            updated: None,
        })
        .await
        .expect("upsert");

    let listed = catalog
        .query(&Query {
            prefix: String::new(),
            limit: 10,
        })
        .await
        .expect("query");
    assert_eq!(listed.len(), 1, "the index lists it");
    assert!(
        store.get(&key).await.expect("get").is_none(),
        "the store does not have it — a host must handle this"
    );
}

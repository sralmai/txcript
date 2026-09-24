//! The `Catalog` seam: how "list everyone's sessions" is answered.
//!
//! Separate from [`ObjectStore`] because its cost model is the whole
//! difference between designs A and B in `docs/design/share-service.md`.
//! [`StoreDerived`] has no second source of truth and pays per listing; an
//! index is fast and must be reconciled.

use txcript_share_core::Key;

use crate::{Cursor, ObjectStore, StoreError};

/// One catalog row: everything a listing shows, and nothing that requires
/// reading a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: Key,
    pub version: String,
    pub title: Option<String>,
    pub updated: Option<String>,
}

/// What to list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Store prefix, `""` for everything.
    pub prefix: String,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    Backend(String),
}

impl From<StoreError> for CatalogError {
    fn from(error: StoreError) -> Self {
        CatalogError::Backend(error.to_string())
    }
}

pub trait Catalog {
    /// # Errors
    /// When the backend fails.
    fn upsert(&self, entry: &Entry) -> impl Future<Output = Result<(), CatalogError>>;

    /// # Errors
    /// When the backend fails.
    fn remove(&self, key: &Key) -> impl Future<Output = Result<(), CatalogError>>;

    /// # Errors
    /// When the backend fails.
    fn query(&self, query: &Query) -> impl Future<Output = Result<Vec<Entry>, CatalogError>>;
}

/// A catalog that is just the store's own listing.
///
/// No second source of truth, therefore no reconciliation and no rebuild.
/// `upsert` and `remove` are deliberately no-ops: the store write already
/// happened, and there is nothing else to keep in step. Design A.
#[derive(Debug, Clone)]
pub struct StoreDerived<S> {
    store: S,
}

impl<S> StoreDerived<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

// `ObjectStore` and `Catalog` are async because the real backends are
// networked. These two satisfy the signatures without awaiting — a map and
// blocking file I/O — which is correct rather than a smell.
#[allow(clippy::unused_async_trait_impl)]
impl<S: ObjectStore> Catalog for StoreDerived<S> {
    async fn upsert(&self, _: &Entry) -> Result<(), CatalogError> {
        Ok(())
    }

    async fn remove(&self, _: &Key) -> Result<(), CatalogError> {
        Ok(())
    }

    async fn query(&self, query: &Query) -> Result<Vec<Entry>, CatalogError> {
        let mut out = Vec::new();
        let mut cursor: Option<Cursor> = None;
        loop {
            let page = self
                .store
                .list(&query.prefix, cursor.as_ref(), query.limit.max(1))
                .await?;
            for meta in page.objects {
                out.push(Entry {
                    key: meta.key,
                    version: meta.version.as_str().to_string(),
                    title: meta.attrs.get("title").map(str::to_string),
                    updated: meta.attrs.get("updated").map(str::to_string),
                });
            }
            match page.next {
                Some(next) if out.len() < query.limit => cursor = Some(next),
                _ => break,
            }
        }
        out.truncate(query.limit);
        Ok(out)
    }
}

/// An in-memory index. The double, and the shape a SQLite or Postgres
/// catalog takes: writes go here *and* to the store, so the two can disagree
/// — which is the cost Design B pays for fast listings.
#[derive(Debug, Clone, Default)]
pub struct InMemoryCatalog {
    entries: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, Entry>>>,
}

impl InMemoryCatalog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// `ObjectStore` and `Catalog` are async because the real backends are
// networked. These two satisfy the signatures without awaiting — a map and
// blocking file I/O — which is correct rather than a smell.
#[allow(clippy::unused_async_trait_impl)]
impl Catalog for InMemoryCatalog {
    async fn upsert(&self, entry: &Entry) -> Result<(), CatalogError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| CatalogError::Backend("lock poisoned".into()))?;
        entries.insert(entry.key.to_slug(), entry.clone());
        Ok(())
    }

    async fn remove(&self, key: &Key) -> Result<(), CatalogError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| CatalogError::Backend("lock poisoned".into()))?;
        entries.remove(&key.to_slug());
        Ok(())
    }

    async fn query(&self, query: &Query) -> Result<Vec<Entry>, CatalogError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| CatalogError::Backend("lock poisoned".into()))?;
        Ok(entries
            .iter()
            .filter(|(slug, _)| slug.starts_with(&query.prefix))
            .map(|(_, entry)| entry.clone())
            .take(query.limit)
            .collect())
    }
}

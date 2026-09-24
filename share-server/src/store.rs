//! Static dispatch over the configured backend.
//!
//! `ObjectStore` uses `async fn`, which is not object-safe, so a
//! `Box<dyn ObjectStore>` is not available. An enum is the honest
//! alternative: adding a backend is one variant and the compiler names every
//! arm that needs it, which is the same property the harness dispatch in
//! `src/local.rs` relies on.

use txcript_share_core::Key;
use txcript_share_core::plan::Precondition;
use txcript_share_store::{
    Attrs, Cursor, Filesystem, InMemory, Object, ObjectMeta, ObjectStore, Page, StoreError,
};

use crate::config::StoreConfig;

#[derive(Debug, Clone)]
pub enum Store {
    Filesystem(Filesystem),
    Memory(InMemory),
}

impl Store {
    #[must_use]
    pub fn build(config: &StoreConfig) -> Self {
        match config {
            StoreConfig::Filesystem { root } => Store::Filesystem(Filesystem::new(root)),
            StoreConfig::Memory => Store::Memory(InMemory::new()),
        }
    }
}

impl ObjectStore for Store {
    async fn put(
        &self,
        key: &Key,
        body: &[u8],
        attrs: &Attrs,
        precondition: &Precondition,
    ) -> Result<txcript_share_store::Version, StoreError> {
        match self {
            Store::Filesystem(store) => store.put(key, body, attrs, precondition).await,
            Store::Memory(store) => store.put(key, body, attrs, precondition).await,
        }
    }

    async fn get(&self, key: &Key) -> Result<Option<Object>, StoreError> {
        match self {
            Store::Filesystem(store) => store.get(key).await,
            Store::Memory(store) => store.get(key).await,
        }
    }

    async fn head(&self, key: &Key) -> Result<Option<ObjectMeta>, StoreError> {
        match self {
            Store::Filesystem(store) => store.head(key).await,
            Store::Memory(store) => store.head(key).await,
        }
    }

    async fn delete(&self, key: &Key, precondition: &Precondition) -> Result<(), StoreError> {
        match self {
            Store::Filesystem(store) => store.delete(key, precondition).await,
            Store::Memory(store) => store.delete(key, precondition).await,
        }
    }

    async fn list(
        &self,
        prefix: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<Page, StoreError> {
        match self {
            Store::Filesystem(store) => store.list(prefix, cursor, limit).await,
            Store::Memory(store) => store.list(prefix, cursor, limit).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use txcript_share_store::conformance;

    /// The configured store is a real `ObjectStore`, not a partial one: the
    /// enum must not quietly lose a method's semantics in delegation.
    #[tokio::test]
    async fn the_dispatching_store_satisfies_the_store_contract() {
        conformance::all(|| Store::Memory(InMemory::new())).await;
        conformance::all(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            Store::Filesystem(Filesystem::new(dir.keep()))
        })
        .await;
    }
}

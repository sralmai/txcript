//! An in-memory store: the double, and the reference for ordering.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use txcript_share_core::Key;
use txcript_share_core::plan::Precondition;

use crate::{Attrs, Cursor, Object, ObjectMeta, ObjectStore, Page, StoreError, Version};

/// A `BTreeMap` behind a mutex. Deterministic iteration order, so listing
/// tests assert an exact sequence rather than a sorted set.
#[derive(Debug, Clone, Default)]
pub struct InMemory {
    objects: Arc<Mutex<BTreeMap<String, Stored>>>,
    /// When set, every operation fails with this error. Fault injection, for
    /// asserting that a host maps a backend outage to 503 rather than 404.
    fault: Option<String>,
    counter: Arc<Mutex<u64>>,
}

#[derive(Debug, Clone)]
struct Stored {
    key: Key,
    body: Vec<u8>,
    attrs: Attrs,
    version: Version,
}

impl InMemory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that fails every call, for testing the backend-outage path.
    #[must_use]
    pub fn failing(detail: &str) -> Self {
        Self {
            fault: Some(detail.to_string()),
            ..Self::default()
        }
    }

    fn check(&self) -> Result<(), StoreError> {
        match &self.fault {
            Some(detail) => Err(StoreError::Backend(detail.clone())),
            None => Ok(()),
        }
    }

    /// Monotonic versions, so a stale `IfVersion` is always distinguishable
    /// from a current one even when the bytes are identical.
    fn next_version(&self) -> Result<Version, StoreError> {
        let mut counter = self
            .counter
            .lock()
            .map_err(|_| StoreError::Backend("lock poisoned".into()))?;
        *counter += 1;
        Ok(Version::new(format!("\"v{counter}\"")))
    }

    fn meta_of(stored: &Stored) -> ObjectMeta {
        ObjectMeta {
            key: stored.key.clone(),
            version: stored.version.clone(),
            size: stored.body.len() as u64,
            attrs: stored.attrs.clone(),
        }
    }
}

fn precondition_holds(precondition: &Precondition, current: Option<&Version>) -> bool {
    match precondition {
        Precondition::None => true,
        Precondition::IfAbsent => current.is_none(),
        Precondition::IfVersion(wanted) => current.is_some_and(|have| have.as_str() == wanted),
    }
}

// `ObjectStore` and `Catalog` are async because the real backends are
// networked. These two satisfy the signatures without awaiting — a map and
// blocking file I/O — which is correct rather than a smell.
#[allow(clippy::unused_async_trait_impl)]
impl ObjectStore for InMemory {
    async fn put(
        &self,
        key: &Key,
        body: &[u8],
        attrs: &Attrs,
        precondition: &Precondition,
    ) -> Result<Version, StoreError> {
        self.check()?;
        let version = self.next_version()?;
        let mut objects = self
            .objects
            .lock()
            .map_err(|_| StoreError::Backend("lock poisoned".into()))?;
        let current = objects.get(&key.to_slug()).map(|s| s.version.clone());
        if !precondition_holds(precondition, current.as_ref()) {
            return Err(StoreError::PreconditionFailed);
        }
        objects.insert(
            key.to_slug(),
            Stored {
                key: key.clone(),
                body: body.to_vec(),
                attrs: attrs.clone(),
                version: version.clone(),
            },
        );
        Ok(version)
    }

    async fn get(&self, key: &Key) -> Result<Option<Object>, StoreError> {
        self.check()?;
        let objects = self
            .objects
            .lock()
            .map_err(|_| StoreError::Backend("lock poisoned".into()))?;
        Ok(objects.get(&key.to_slug()).map(|stored| Object {
            meta: Self::meta_of(stored),
            body: stored.body.clone(),
        }))
    }

    async fn head(&self, key: &Key) -> Result<Option<ObjectMeta>, StoreError> {
        self.check()?;
        let objects = self
            .objects
            .lock()
            .map_err(|_| StoreError::Backend("lock poisoned".into()))?;
        Ok(objects.get(&key.to_slug()).map(Self::meta_of))
    }

    async fn delete(&self, key: &Key, precondition: &Precondition) -> Result<(), StoreError> {
        self.check()?;
        let mut objects = self
            .objects
            .lock()
            .map_err(|_| StoreError::Backend("lock poisoned".into()))?;
        let current = objects.get(&key.to_slug()).map(|s| s.version.clone());
        if !precondition_holds(precondition, current.as_ref()) {
            return Err(StoreError::PreconditionFailed);
        }
        objects.remove(&key.to_slug());
        Ok(())
    }

    async fn list(
        &self,
        prefix: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<Page, StoreError> {
        self.check()?;
        let objects = self
            .objects
            .lock()
            .map_err(|_| StoreError::Backend("lock poisoned".into()))?;
        let after = cursor.map(|Cursor(value)| value.clone());
        let mut matching: Vec<ObjectMeta> = objects
            .iter()
            .filter(|(slug, _)| slug.starts_with(prefix))
            .filter(|(slug, _)| after.as_ref().is_none_or(|last| *slug > last))
            .map(|(_, stored)| Self::meta_of(stored))
            .collect();
        matching.truncate(limit);
        let next = (matching.len() == limit)
            .then(|| matching.last().map(|meta| Cursor(meta.key.to_slug())))
            .flatten();
        Ok(Page {
            objects: matching,
            next,
        })
    }
}

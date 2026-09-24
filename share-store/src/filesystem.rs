//! A directory-backed store.
//!
//! This exists to keep [`ObjectStore`] honest. Three things S3 gives away
//! free, a filesystem does not, and each one forces a decision that would
//! otherwise be an unexamined assumption:
//!
//! 1. **Metadata in a listing.** `S3` LIST returns user metadata inline; a
//!    directory returns names. Attributes therefore get a declared home — a
//!    parallel `attrs/` tree, read during listing — instead of the caller
//!    silently depending on S3 behaviour. A sidecar *beside* the object
//!    would collide with a legal session name: publishing `notes` would
//!    overwrite the transcript stored at `notes.attrs`.
//! 2. **Versions.** There is no `ETag`, so one is derived from the content.
//! 3. **Atomic conditional writes.** There is no compare-and-swap. See the
//!    honesty note on [`Filesystem::put`].
//!
//! Intended for local development, single-node deployments, and the
//! conformance suite. Not for concurrent multi-writer use.

use std::fs;
use std::path::{Path, PathBuf};

use txcript_share_core::Key;
use txcript_share_core::plan::Precondition;

use crate::{Attrs, Cursor, Object, ObjectMeta, ObjectStore, Page, StoreError, Version};

/// Object bodies.
const OBJECTS: &str = "objects";
/// Attributes and the stored version, one file per object.
const ATTRS: &str = "attrs";
/// In-flight writes, renamed into place on completion.
const TMP: &str = "tmp";
/// The attribute name under which the version is persisted, so `head` and
/// `list` never have to read a body to learn it.
const VERSION_ATTR: &str = "\u{1}version";

/// Objects as files under a root, one directory per owner.
#[derive(Debug, Clone)]
pub struct Filesystem {
    root: PathBuf,
}

impl Filesystem {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `<root>/objects/<owner>/<session>`. `Key` guarantees both segments
    /// are plain, so this cannot escape the root.
    fn path_of(&self, key: &Key) -> PathBuf {
        self.tree(OBJECTS, key)
    }

    /// `<root>/attrs/<owner>/<session>`. A parallel tree rather than a
    /// suffix beside the object: `notes.attrs` is a legal session name, and
    /// a suffix scheme would let publishing `notes` destroy it.
    fn attrs_path_of(&self, key: &Key) -> PathBuf {
        self.tree(ATTRS, key)
    }

    fn tree(&self, tree: &str, key: &Key) -> PathBuf {
        self.root
            .join(tree)
            .join(key.owner().as_str())
            .join(key.session())
    }

    fn version_of(body: &[u8]) -> Version {
        // FNV-1a. A content hash, so an unchanged rewrite keeps its version
        // and `IfVersion` stays meaningful; not a cryptographic digest,
        // which this does not need and would cost a dependency.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in body {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        Version::new(format!("\"{hash:016x}\""))
    }

    fn read_attrs(path: &Path) -> Attrs {
        // A missing or corrupt sidecar degrades to no attributes rather than
        // failing the listing: metadata is a cache of what is in the body.
        let Ok(raw) = fs::read_to_string(path) else {
            return Attrs::new();
        };
        raw.lines()
            .fold(Attrs::new(), |attrs, line| match line.split_once('\t') {
                Some((name, value)) => attrs.set(name, value),
                None => attrs,
            })
    }

    fn write_attrs(path: &Path, attrs: &Attrs) -> Result<(), StoreError> {
        if attrs.is_empty() {
            let _ = fs::remove_file(path);
            return Ok(());
        }
        // The attrs tree mirrors the objects tree, so it needs its own
        // directories.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        // Tab-separated because attribute names are constrained and values
        // are single-line; a JSON dependency is not worth it here.
        let body = attrs.iter().fold(String::new(), |mut body, (name, value)| {
            body.push_str(name);
            body.push('\t');
            body.push_str(&value.replace(['\n', '\t'], " "));
            body.push('\n');
            body
        });
        fs::write(path, body).map_err(|error| StoreError::Backend(error.to_string()))
    }

    /// Metadata without reading the body: size from `stat`, version from the
    /// attrs file where `put` recorded it. Every request does at least one
    /// `head`, and a listing does one per entry, so reading whole objects
    /// here would make both O(bytes) instead of O(entries).
    fn meta_at(&self, key: &Key) -> Result<Option<ObjectMeta>, StoreError> {
        let size = match fs::metadata(self.path_of(key)) {
            Ok(meta) => meta.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(StoreError::Backend(error.to_string())),
        };
        let stored = Self::read_attrs(&self.attrs_path_of(key));
        let version = stored
            .get(VERSION_ATTR)
            .map_or_else(|| Version::new("\"unknown\""), Version::new);
        Ok(Some(ObjectMeta {
            key: key.clone(),
            version,
            size,
            attrs: stored.without(VERSION_ATTR),
        }))
    }

    fn precondition_holds(
        &self,
        key: &Key,
        precondition: &Precondition,
    ) -> Result<bool, StoreError> {
        let current = self.meta_at(key)?.map(|meta| meta.version);
        Ok(match precondition {
            Precondition::None => true,
            Precondition::IfAbsent => current.is_none(),
            Precondition::IfVersion(wanted) => current.is_some_and(|have| have.as_str() == wanted),
        })
    }
}

// `ObjectStore` and `Catalog` are async because the real backends are
// networked. These two satisfy the signatures without awaiting — a map and
// blocking file I/O — which is correct rather than a smell.
#[allow(clippy::unused_async_trait_impl)]
impl ObjectStore for Filesystem {
    /// # Honesty note
    ///
    /// The precondition is checked and then the write happens; there is no
    /// atomic compare-and-swap on a POSIX filesystem, so two concurrent
    /// writers can both observe the same version and both proceed. `S3` and `R2`
    /// do this atomically via `If-Match`.
    ///
    /// This is stated rather than hidden because it is the seam doing its
    /// job: the trait can express a guarantee that one backend provides and
    /// another only approximates, and a caller that needs the strong form
    /// must choose a backend that has it.
    async fn put(
        &self,
        key: &Key,
        body: &[u8],
        attrs: &Attrs,
        precondition: &Precondition,
    ) -> Result<Version, StoreError> {
        if !self.precondition_holds(key, precondition)? {
            return Err(StoreError::PreconditionFailed);
        }
        let path = self.path_of(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        // Write-then-rename so a reader never sees a half-written object.
        let temp = self.tree(TMP, key);
        if let Some(parent) = temp.parent() {
            fs::create_dir_all(parent).map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        fs::write(&temp, body).map_err(|error| StoreError::Backend(error.to_string()))?;
        fs::rename(&temp, &path).map_err(|error| StoreError::Backend(error.to_string()))?;
        let version = Self::version_of(body);
        // The version rides with the attributes so `head` and `list` never
        // have to open the object.
        Self::write_attrs(
            &self.attrs_path_of(key),
            &attrs.clone().set(VERSION_ATTR, version.as_str()),
        )?;
        Ok(version)
    }

    async fn get(&self, key: &Key) -> Result<Option<Object>, StoreError> {
        let body = match fs::read(self.path_of(key)) {
            Ok(body) => body,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(StoreError::Backend(error.to_string())),
        };
        let Some(meta) = self.meta_at(key)? else {
            return Ok(None);
        };
        Ok(Some(Object { meta, body }))
    }

    async fn head(&self, key: &Key) -> Result<Option<ObjectMeta>, StoreError> {
        self.meta_at(key)
    }

    async fn delete(&self, key: &Key, precondition: &Precondition) -> Result<(), StoreError> {
        if !self.precondition_holds(key, precondition)? {
            return Err(StoreError::PreconditionFailed);
        }
        match fs::remove_file(self.path_of(key)) {
            Ok(()) => {}
            // Idempotent: a retried delete is not an error.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Backend(error.to_string())),
        }
        let _ = fs::remove_file(self.attrs_path_of(key));
        Ok(())
    }

    /// Walks owner directories and reads each sidecar. `O(n)` in the listing,
    /// where `S3` is one request — the cost of not having metadata in LIST,
    /// made visible rather than hidden.
    async fn list(
        &self,
        prefix: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<Page, StoreError> {
        let mut slugs: Vec<Key> = Vec::new();
        let owners = match fs::read_dir(self.root.join(OBJECTS)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Page {
                    objects: Vec::new(),
                    next: None,
                });
            }
            Err(error) => return Err(StoreError::Backend(error.to_string())),
        };
        for owner in owners {
            let owner = owner.map_err(|error| StoreError::Backend(error.to_string()))?;
            if !owner.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let sessions =
                fs::read_dir(owner.path()).map_err(|e| StoreError::Backend(e.to_string()))?;
            for session in sessions {
                let session = session.map_err(|e| StoreError::Backend(e.to_string()))?;
                let name = session.file_name().to_string_lossy().into_owned();
                // No name filtering: attributes and temporaries live in
                // their own trees, so everything here is an object.
                let slug = format!("{}/{name}", owner.file_name().to_string_lossy());
                if let Some(key) = Key::parse(&slug) {
                    slugs.push(key);
                }
            }
        }
        // Lexicographic order is part of the contract, and a directory read
        // has no inherent order — so sort explicitly.
        slugs.sort_by_key(Key::to_slug);

        let after = cursor.map(|Cursor(value)| value.clone());
        let mut objects = Vec::new();
        for key in slugs {
            let slug = key.to_slug();
            if !slug.starts_with(prefix) {
                continue;
            }
            if after.as_ref().is_some_and(|last| slug <= *last) {
                continue;
            }
            if objects.len() > limit {
                break;
            }
            if let Some(meta) = self.meta_at(&key)? {
                objects.push(meta);
            }
        }
        let next = if objects.len() > limit {
            objects.truncate(limit);
            objects.last().map(|meta| Cursor(meta.key.to_slug()))
        } else {
            None
        };
        Ok(Page { objects, next })
    }
}

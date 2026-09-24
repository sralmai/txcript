//! An S3-compatible object store: AWS `S3`, Cloudflare `R2`, `MinIO`, Ceph.
//!
//! This is the backend the service actually ships on, and its job in the
//! design is to prove the seam: it must pass [`crate::conformance`]
//! **unchanged**. If it had needed the trait widened, the seam would have
//! been shaped around the filesystem instead of around storage.
//!
//! # Preconditions
//!
//! The one thing S3 gives that a filesystem cannot is *atomic* conditional
//! writes, and the whole ownership story leans on them:
//!
//! - [`Precondition::IfAbsent`] → `If-None-Match: *`, so two racing creates
//!   cannot both succeed.
//! - [`Precondition::IfVersion`] → `If-Match: <etag>`, so a read-modify-write
//!   cannot silently clobber a concurrent update.
//!
//! Both are native, so unlike [`Filesystem`](crate::Filesystem) there is no
//! check-then-write window to document away.
//!
//! # Metadata
//!
//! Attributes ride as S3 user metadata (`x-amz-meta-*`) and come back inline
//! from `ListObjectsV2`… except that they do not: `ListObjectsV2` returns
//! keys, sizes, and `ETag`s, *not* user metadata. That is the assumption
//! `Filesystem` was added to break, and it turns out S3 breaks it too. A
//! listing therefore issues one `HeadObject` per entry. It is stated here
//! rather than hidden because it is a real cost, and because a catalog
//! ([`crate::Catalog`]) is the answer when it starts to hurt.

use aws_sdk_s3::Client;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::Object as S3Object;
use txcript_share_core::Key;
use txcript_share_core::plan::Precondition;

use crate::{Attrs, Cursor, Object, ObjectMeta, ObjectStore, Page, StoreError, Version};

/// Objects in one bucket, optionally under a key prefix.
#[derive(Debug, Clone)]
pub struct S3 {
    client: Client,
    bucket: String,
    /// Prepended to every key, so one bucket can host several deployments.
    /// Empty for the common case.
    root: String,
}

impl S3 {
    #[must_use]
    pub fn new(client: Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
            root: String::new(),
        }
    }

    #[must_use]
    pub fn with_root(mut self, root: impl Into<String>) -> Self {
        let root = root.into();
        self.root = if root.is_empty() || root.ends_with('/') {
            root
        } else {
            format!("{root}/")
        };
        self
    }

    fn object_key(&self, key: &Key) -> String {
        format!("{}{}", self.root, key.to_slug())
    }

    /// Strip the deployment root back off, so callers only ever see slugs.
    fn slug_of<'a>(root: &str, object_key: &'a str) -> Option<&'a str> {
        object_key.strip_prefix(root)
    }

    fn meta_from(key: Key, etag: Option<&str>, size: i64, attrs: Attrs) -> ObjectMeta {
        ObjectMeta {
            key,
            version: Version::new(etag.unwrap_or_default()),
            size: u64::try_from(size).unwrap_or(0),
            attrs,
        }
    }
}

/// S3 reports a failed precondition as 412, and a failed `If-None-Match: *`
/// as 409. Both mean "someone else got there first", which is the caller's
/// business rather than an outage.
fn classify<E: std::fmt::Debug>(error: &SdkError<E>) -> StoreError {
    let status = match error {
        SdkError::ServiceError(inner) => inner.raw().status().as_u16(),
        _ => 0,
    };
    if matches!(status, 409 | 412) {
        StoreError::PreconditionFailed
    } else {
        StoreError::Backend(format!("{error:?}"))
    }
}

fn attrs_from(metadata: Option<&std::collections::HashMap<String, String>>) -> Attrs {
    metadata.map_or_else(Attrs::new, |map| {
        map.iter()
            .fold(Attrs::new(), |attrs, (name, value)| attrs.set(name, value))
    })
}

impl ObjectStore for S3 {
    async fn put(
        &self,
        key: &Key,
        body: &[u8],
        attrs: &Attrs,
        precondition: &Precondition,
    ) -> Result<Version, StoreError> {
        let mut request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .content_type("application/json")
            .body(ByteStream::from(body.to_vec()));
        for (name, value) in attrs.iter() {
            request = request.metadata(name, value);
        }
        // Native and atomic, unlike the filesystem's check-then-write.
        request = match precondition {
            Precondition::None => request,
            Precondition::IfAbsent => request.if_none_match("*"),
            Precondition::IfVersion(version) => request.if_match(version),
        };

        let response = request.send().await.map_err(|error| classify(&error))?;
        Ok(Version::new(response.e_tag().unwrap_or_default()))
    }

    async fn get(&self, key: &Key) -> Result<Option<Object>, StoreError> {
        let response = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) if is_missing(&error) => return Ok(None),
            Err(error) => return Err(classify(&error)),
        };
        let etag = response.e_tag().map(str::to_string);
        let attrs = attrs_from(response.metadata());
        let body = response
            .body
            .collect()
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .into_bytes()
            .to_vec();
        let size = i64::try_from(body.len()).unwrap_or(i64::MAX);
        Ok(Some(Object {
            meta: Self::meta_from(key.clone(), etag.as_deref(), size, attrs),
            body,
        }))
    }

    async fn head(&self, key: &Key) -> Result<Option<ObjectMeta>, StoreError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .send()
            .await
        {
            Ok(response) => Ok(Some(Self::meta_from(
                key.clone(),
                response.e_tag(),
                response.content_length().unwrap_or(0),
                attrs_from(response.metadata()),
            ))),
            Err(error) if is_missing(&error) => Ok(None),
            Err(error) => Err(classify(&error)),
        }
    }

    async fn delete(&self, key: &Key, precondition: &Precondition) -> Result<(), StoreError> {
        // S3 `DeleteObject` takes no conditional headers, so a guarded
        // delete is a HEAD then a delete. The window is real; the service
        // never uses it, because `decide` resolves preconditions on the
        // write path only.
        if let Precondition::IfVersion(wanted) = precondition {
            match self.head(key).await? {
                Some(meta) if meta.version.as_str() == wanted => {}
                _ => return Err(StoreError::PreconditionFailed),
            }
        }
        if matches!(precondition, Precondition::IfAbsent) && self.head(key).await?.is_some() {
            return Err(StoreError::PreconditionFailed);
        }
        match self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .send()
            .await
        {
            // Idempotent: S3 already treats a missing key as success.
            Ok(_) => Ok(()),
            Err(error) if is_missing(&error) => Ok(()),
            Err(error) => Err(classify(&error)),
        }
    }

    async fn list(
        &self,
        prefix: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<Page, StoreError> {
        let mut request = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(format!("{}{prefix}", self.root))
            // One extra, so a page that exactly fills `limit` is not
            // mistaken for evidence that another page exists.
            .max_keys(i32::try_from(limit.saturating_add(1)).unwrap_or(i32::MAX));
        if let Some(Cursor(after)) = cursor {
            request = request.start_after(format!("{}{after}", self.root));
        }
        let response = request.send().await.map_err(|error| classify(&error))?;

        let found: Vec<&S3Object> = response.contents().iter().collect();
        let mut objects = Vec::with_capacity(found.len().min(limit));
        for entry in found {
            let Some(key) = entry
                .key()
                .and_then(|raw| Self::slug_of(&self.root, raw))
                .and_then(Key::parse)
            else {
                continue;
            };
            // `ListObjectsV2` does not return user metadata, so attributes
            // cost one HEAD each. See the module note.
            let attrs = match self.head(&key).await? {
                Some(meta) => meta.attrs,
                None => continue,
            };
            objects.push(Self::meta_from(
                key,
                entry.e_tag(),
                entry.size().unwrap_or(0),
                attrs,
            ));
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

fn is_missing<E: std::fmt::Debug>(error: &SdkError<E>) -> bool {
    matches!(error, SdkError::ServiceError(inner) if inner.raw().status().as_u16() == 404)
}

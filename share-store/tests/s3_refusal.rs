//! A refusal is not an outage, and on this backend it is not always a
//! refusal either.
//!
//! The policy `txcript s3-policy` prints grants `s3:ListBucket` only under
//! an `s3:prefix` condition. `GetObject` and `HeadObject` requests carry no
//! such key, so a restricted publisher fails that condition and S3 declines
//! to confirm absence: a key that is simply missing comes back **403**,
//! where an unrestricted identity would see 404. Classifying that as
//! `Backend` made a missing transcript look like a broken store, and made a
//! listing that raced a delete fail outright instead of skipping the row.
//!
//! None of it is reachable as an admin, and `MinIO` and Silo do not implement
//! IAM conditions, so the conformance suite cannot show it. A stub endpoint
//! that answers 403 can, and needs no credentials and no network.

#![cfg(feature = "s3")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpListener;

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use txcript_share_core::plan::Precondition;
use txcript_share_core::{Key, PrincipalId};
use txcript_share_store::{Attrs, ObjectStore, S3, StoreError};

/// An endpoint that answers every request with the S3 403 a publisher sees
/// outside its own prefix. Returns the port; the thread outlives the test.
fn forbidding_endpoint() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // Enough of the request to let the client finish writing.
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            let body = concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                "<Error><Code>AccessDenied</Code>",
                "<Message>Access Denied</Message></Error>"
            );
            let _ = write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\n\
                 Content-Type: application/xml\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.flush();
        }
    });
    port
}

fn store(port: u16) -> S3 {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(format!("http://127.0.0.1:{port}"))
        .force_path_style(true)
        .credentials_provider(Credentials::new("k", "s", None, None, "test"))
        .build();
    S3::new(Client::from_conf(config), "bucket")
}

fn key() -> Key {
    Key::new(PrincipalId::new("alice".to_string()).expect("owner"), "s1").expect("key")
}

/// The reads. `Ok(None)` would claim absence the backend never confirmed,
/// and `Backend` would report a working store as broken.
#[tokio::test]
async fn a_refused_read_is_denied_rather_than_absent_or_broken() {
    let store = store(forbidding_endpoint());

    assert_eq!(store.get(&key()).await, Err(StoreError::Denied));
    assert_eq!(store.head(&key()).await, Err(StoreError::Denied));
}

/// The write a publisher makes outside its own prefix. This is the one the
/// bucket policy exists to refuse, so it must not read as an outage.
#[tokio::test]
async fn a_refused_write_is_denied_rather_than_broken() {
    let store = store(forbidding_endpoint());

    let refused = store
        .put(&key(), b"{}", &Attrs::new(), &Precondition::None)
        .await;

    assert_eq!(refused, Err(StoreError::Denied));
}

/// A listing the credentials cannot make fails loudly. The per-entry `HEAD`
/// tolerates a 403 because the key was just listed; the listing itself has
/// no such excuse, and swallowing it would hand back an empty store.
#[tokio::test]
async fn a_refused_listing_fails_rather_than_reporting_an_empty_store() {
    let store = store(forbidding_endpoint());

    assert_eq!(
        store.list("", None, 10).await.err(),
        Some(StoreError::Denied)
    );
}

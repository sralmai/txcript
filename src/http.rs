//! Shared browser-profile HTTP transport for the live remote stores.
//!
//! Claude Chat and ChatGPT both read private web endpoints that sit behind
//! an edge which inspects TLS, HTTP/2, and header shape. Both therefore need
//! the same thing: a `wreq` client built with a browser emulation profile,
//! driven from a dedicated thread that owns a current-thread Tokio runtime,
//! so the blocking [`Store`](crate::Store) API never needs an async caller.
//!
//! This module is that transport, and nothing else. It knows about requests,
//! byte caps, and worker lifetime; it knows nothing about either service's
//! authentication, endpoints, or response shapes — those stay in the harness
//! modules, which differ.
//!
//! Two invariants are load-bearing and easy to lose:
//!
//! - **Redirects are never followed.** A credential-bearing cookie must not
//!   be replayed to another origin, and for a gateway-protected endpoint a
//!   302 to a login page is an authentication failure, not content.
//! - **Sensitive and plain headers are distinct.** `set_sensitive` keeps a
//!   value out of the HPACK dynamic table, which is correct for credentials
//!   and *wrong* for the ordinary browser headers whose compression
//!   behaviour is part of the profile being emulated.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use futures_util::StreamExt;

use crate::error::{Error, Result};

/// How long a single request may take, start to finish.
const TIMEOUT: Duration = Duration::from_secs(30);

/// One GET.
pub(crate) struct Request {
    pub url: String,
    /// Ordinary headers, compressed normally.
    pub headers: Vec<(&'static str, String)>,
    /// Credential-bearing headers, marked sensitive so they stay out of the
    /// HPACK dynamic table.
    pub sensitive: Vec<(&'static str, String)>,
    /// Hard cap on the response body; enforced against `Content-Length`
    /// first and then again while streaming, since the header may lie.
    pub max_bytes: u64,
}

/// A response that stayed within [`Request::max_bytes`].
pub(crate) struct Response {
    pub status: u16,
    pub content_type: Option<String>,
    /// `cf-mitigated: challenge` — Cloudflare answered with a challenge
    /// instead of passing the request to the origin.
    pub cf_mitigated: bool,
    pub body: Vec<u8>,
}

/// A running HTTP worker thread. Dropping it stops the worker.
pub(crate) struct Agent {
    sender: mpsc::Sender<Job>,
    harness: &'static str,
}

struct Job {
    request: Request,
    reply: mpsc::SyncSender<std::result::Result<Response, String>>,
}

impl Agent {
    /// Start the worker. `harness` names the caller in errors and in the
    /// thread name.
    ///
    /// # Errors
    /// When the thread, the Tokio runtime, or the HTTP client cannot be
    /// built.
    pub(crate) fn start(harness: &'static str) -> Result<Self> {
        let (sender, receiver) = mpsc::channel::<Job>();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name(format!("txcript-{}-http", harness.replace('_', "-")))
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| format!("could not start HTTP runtime: {error}"));
                let client = runtime.as_ref().map_err(Clone::clone).and_then(|_| {
                    wreq::Client::builder()
                        // Both services' desktop clients currently embed
                        // Chromium 148. Matching the browser's TLS, HTTP/2,
                        // and header profile is required by the edge in
                        // front of these private read APIs.
                        .emulation(wreq_util::Profile::Chrome148)
                        // Never let a credential-bearing header follow a
                        // response to another origin.
                        .redirect(wreq::redirect::Policy::none())
                        .timeout(TIMEOUT)
                        .build()
                        .map_err(|error| format!("could not build browser HTTP client: {error}"))
                });
                let startup = match (&runtime, &client) {
                    (Ok(_), Ok(_)) => Ok(()),
                    (Err(error), _) | (_, Err(error)) => Err(error.clone()),
                };
                if ready_sender.send(startup).is_err() {
                    return;
                }
                let (Ok(runtime), Ok(client)) = (runtime, client) else {
                    return;
                };
                while let Ok(job) = receiver.recv() {
                    let result = runtime.block_on(execute(&client, &job.request));
                    let _ = job.reply.send(result);
                }
            })
            .map_err(|error| Error::Remote {
                harness,
                detail: format!("could not start browser HTTP worker: {error}"),
            })?;
        ready_receiver
            .recv()
            .map_err(|_| Error::Remote {
                harness,
                detail: "browser HTTP worker stopped during startup".to_string(),
            })?
            .map_err(|detail| Error::Remote { harness, detail })?;
        Ok(Self { sender, harness })
    }

    /// Perform one GET on the worker thread and wait for it.
    ///
    /// # Errors
    /// When the worker has stopped, or the request fails or exceeds its cap.
    pub(crate) fn get(&self, request: Request) -> Result<Response> {
        let harness = self.harness;
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .send(Job { request, reply })
            .map_err(|_| Error::Remote {
                harness,
                detail: "browser HTTP worker stopped before the request".to_string(),
            })?;
        response
            .recv()
            .map_err(|_| Error::Remote {
                harness,
                detail: "browser HTTP worker stopped during the request".to_string(),
            })?
            .map_err(|detail| Error::Remote { harness, detail })
    }
}

async fn execute(
    client: &wreq::Client,
    request: &Request,
) -> std::result::Result<Response, String> {
    let mut builder = client.get(&request.url);
    for (name, value) in &request.headers {
        builder = builder.header(*name, value.as_str());
    }
    for (name, value) in &request.sensitive {
        let mut header = wreq::header::HeaderValue::from_str(value)
            .map_err(|_| format!("could not construct safe `{name}` header"))?;
        header.set_sensitive(true);
        builder = builder.header(*name, header);
    }

    let response = builder
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(wreq::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(String::from);
    let cf_mitigated = response
        .headers()
        .get("cf-mitigated")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("challenge"));

    let too_large = || format!("response exceeded the {} byte limit", request.max_bytes);
    if response
        .content_length()
        .is_some_and(|length| length > request.max_bytes)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("failed reading response: {error}"))?;
        // u64 throughout: on a 32-bit target a usize sum could wrap before
        // the comparison and let an oversized body through.
        let length = u64::try_from(body.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if length > request.max_bytes {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Response {
        status,
        content_type,
        cf_mitigated,
        body,
    })
}

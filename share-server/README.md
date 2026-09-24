# txcript-share-server

The native HTTP host for the shared transcript service. One static binary,
one configuration file.

It does I/O and nothing else: every decision comes from
`txcript_share_core::decide`, the same function the Cloudflare Worker calls
through wasm. There is no authorization branch in this crate.

## Run

```sh
txcript-share-server /etc/txcript-share/config.toml
```

```toml
listen = "127.0.0.1:8787"          # loopback by default; put a proxy in front

[identity]
kind = "static_tokens"             # or "forwarded_header"
header = "x-token"
tokens_file = "/run/credentials/txcript-share/tokens"

[store]
kind = "filesystem"                # or "memory", or "s3" (feature `s3`)
root = "/var/lib/txcript-share"

[policy]
kind = "owner_prefix"              # or "read_only_mirror", "team_scoped"

[limits]
max_document_bytes = 10485760
page_size = 1000
```

## Routes

| | |
|---|---|
| `PUT /s/<session-id>` | publish, under your own prefix |
| `GET /s/<owner>/<session-id>` | read |
| `DELETE /s/<owner>/<session-id>` | delete your own |
| `GET /s?owner=me` | list |

A `PUT` carries only a bare session id. The owner segment comes from the
authenticated principal, so writing outside your own namespace is not
*expressible* rather than merely denied.

### S3 and compatible backends

Built with `--features s3`, off by default so a filesystem deployment does
not compile, ship, or audit the AWS client tree.

```toml
[store]
kind = "s3"
bucket = "txcript-share"
endpoint = "https://<account>.r2.cloudflarestorage.com"  # omit for AWS
force_path_style = true                                   # MinIO, Ceph
```

Credentials are **not** configured here. They come from the ambient AWS
chain — instance role, web identity, or a credentials file the deployment
mounts — so the same binary works under an IAM role, a Kubernetes service
account, and a static key file without knowing which it is.

## Configuration is the deployment seam

Secrets arrive as **file paths**, never environment values, so systemd
`LoadCredential`, Kubernetes projected secrets, ECS secrets, sops, and agenix
all work without this binary knowing any of them exist. The moment it reads a
credential out of the environment itself, it is coupled to one delivery
mechanism and several deployment targets are lost.

Unknown configuration keys are an error rather than a default: a typo in a
security-relevant field must not read as "off".

## Identity

- `static_tokens` — a token table from a file, one `<token> <id> [label]` per
  line. Real for a closed set of machine clients, and the double every other
  seam's tests run against.
- `forwarded_header` — trust an identity header set by an authenticating
  proxy. **The proxy must be the only route to this service.** If the origin
  is reachable directly, anyone can set the header and become anyone. Bind to
  loopback, or use a network policy.

Cloudflare Access JWT verification is an `Identity` implementation and lands
next; it needs JWKS fetching and RS256, which is why it is not in the
dependency-free core. Nothing else changes when it arrives — that is what the
seam is for.

## Testing

```sh
cargo test -p txcript-share-server
```

`tests/access_over_http.rs` runs the access matrix over real HTTP against a
real filesystem store. The security cases do not stop at the status code:
they re-read the object afterwards and assert the bytes are unchanged, because
a 403 that still mutates the store is the failure a status-only assertion
misses — and that is exactly what a sabotaged handler produced when this was
checked.

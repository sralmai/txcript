# txcript share Worker

A Cloudflare Worker over R2 that stores Simple transcript documents: publish
your own, read everyone's, modify only your own.

## The split

| half | where | responsibility |
|---|---|---|
| decisions | `share-worker` (wasm, from `share-core`) | who may do what, which key, which precondition |
| I/O | `src/index.js` | Access JWT, R2, HTTP |
| pure helpers | `src/support.js` | request parsing, JWT verification, metadata budget |

`index.js` contains **no authorization branch**. Every `403`, every key, and
every conditional-write rule comes back from `plan()`. That is not style: the
rules lived in JavaScript once and grew a bug that let one user's transcripts
overwrite another's. One implementation, in Rust, covered by an access matrix
that runs with no server — and a host that only executes what it is told.

`support.js` is separate from `index.js` so it can be tested with plain
`node --test`; `index.js` imports the wasm module at load time, which a unit
test has no way to provide.

## Routes

| | |
|---|---|
| `PUT /s/<session-id>` | publish, under your own prefix |
| `GET /s/<owner>/<session-id>` | read |
| `DELETE /s/<owner>/<session-id>` | delete your own |
| `GET /s?owner=me\|all` | list — this is txcript's `discover()` |

A `PUT` carries only a bare session id. The owner segment is derived from the
authenticated principal, so writing outside your own namespace is not
*expressible*, rather than merely denied — which is why even the `allow_all`
policy cannot produce a cross-owner write.

## Configuration

Set in `wrangler.toml`:

- `ACCESS_TEAM`, `ACCESS_AUD` — your Zero Trust team and the Access
  application's AUD tag.
- `POLICY` — `owner_prefix` (default), `read_only_mirror`, or `team_scoped`.
- `TEAMS` — only for `team_scoped`: `<principal-id>:<team>` pairs, comma
  separated.

## Build and deploy

```sh
npm run build    # cargo build --target wasm32-unknown-unknown + wasm-bindgen
npm test         # the I/O half
npm run deploy   # build, then wrangler deploy
```

The Rust half is tested from the workspace root:

```sh
cargo test -p txcript-share-core -p txcript-share-worker
```

**`wasm-bindgen` CLI and crate versions must match.** A mismatch produces
bindings that fail to load at runtime rather than failing the build. The
crate version is pinned in `Cargo.toml`; the flake provides the CLI.

## Security

The Worker verifies `Cf-Access-Jwt-Assertion` against the team JWKS and the
AUD tag, so a request reaching the origin by another route — `workers.dev`, a
direct R2 binding — still cannot forge an identity. Access in front is the
gate; that verification is the lock behind it.

**Without both, every published transcript is world-readable over HTTPS.**
Transcripts carry cwd paths, branch names, source, and tool output.

The principal id is a SHA-256 of the Access identity, and **must stay
injective**: ownership is a comparison of these, so two identities sharing
one could delete each other's transcripts. An earlier version lowercased and
replaced punctuation, collapsing `a+b@x.com` and `a_b@x.com` onto one owner.
`test/support.test.mjs` asserts the property on exactly those inputs.

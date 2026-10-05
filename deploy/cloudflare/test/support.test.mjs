// Tests for the Worker's I/O half.
//
// The access rules are not tested here — they live in `share-core` and are
// covered by its access matrix and by `share-worker`'s boundary tests. What
// is tested here is everything this half is solely responsible for: Access
// JWT verification, principal derivation, request parsing, and the metadata
// budget.
import test from "node:test";
import assert from "node:assert/strict";

import {
  describe as describeRequest,
  parseSimple,
  parseTeams,
  principalId,
  resetJwksCacheForTests,
  summarize,
  utf8Truncate,
  verifyAccessJwt,
} from "../src/support.js";

// --- Access JWTs, against a real key pair ------------------------------

const AUD = "test-audience";

async function issuer() {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const kid = "test-key-1";
  const b64 = (value) =>
    Buffer.from(value).toString("base64url");

  const sign = async (claims, { kid: useKid = kid } = {}) => {
    const header = b64(JSON.stringify({ alg: "RS256", kid: useKid }));
    const payload = b64(JSON.stringify(claims));
    const signature = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      pair.privateKey,
      new TextEncoder().encode(`${header}.${payload}`),
    );
    return `${header}.${payload}.${Buffer.from(signature).toString("base64url")}`;
  };

  return { sign, jwks: { keys: [{ ...jwk, kid }] } };
}

/// Serve a JWKS over a stubbed `fetch`, counting requests so the rotation
/// retry can be observed.
function serveJwks(jwks) {
  const calls = { count: 0 };
  globalThis.fetch = async () => {
    calls.count += 1;
    return new Response(JSON.stringify(jwks), { status: 200 });
  };
  return calls;
}

const env = { ACCESS_CERTS_URL: "https://example.invalid/certs", ACCESS_AUD: AUD };
const future = () => Math.floor(Date.now() / 1000) + 600;

test("a valid Access token yields its claims", async () => {
  resetJwksCacheForTests();
  const { sign, jwks } = await issuer();
  serveJwks(jwks);
  const token = await sign({ email: "alice@example.com", aud: [AUD], exp: future() });
  const claims = await verifyAccessJwt(token, env);
  assert.equal(claims?.email, "alice@example.com");
});

test("a token for another audience is refused", async () => {
  resetJwksCacheForTests();
  const { sign, jwks } = await issuer();
  serveJwks(jwks);
  const token = await sign({ email: "a@x.com", aud: ["someone-elses-app"], exp: future() });
  assert.equal(await verifyAccessJwt(token, env), null);
});

test("a deployment with no AUD configured refuses every token", async () => {
  // `[undefined].includes(undefined)` is true, so an unset ACCESS_AUD turned
  // the audience check — the lock behind the Access gate — into a no-op for
  // any token that carried no `aud` of its own.
  resetJwksCacheForTests();
  const { sign, jwks } = await issuer();
  serveJwks(jwks);
  const unconfigured = { ACCESS_CERTS_URL: env.ACCESS_CERTS_URL };
  const audless = await sign({ email: "a@x.com", exp: future() });
  assert.equal(await verifyAccessJwt(audless, unconfigured), null);
  const scoped = await sign({ email: "a@x.com", aud: [AUD], exp: future() });
  assert.equal(await verifyAccessJwt(scoped, unconfigured), null);
});

test("a forward-dated token is refused until it is valid", async () => {
  resetJwksCacheForTests();
  const { sign, jwks } = await issuer();
  serveJwks(jwks);
  const soon = Math.floor(Date.now() / 1000) + 300;
  const token = await sign({ email: "a@x.com", aud: [AUD], exp: future(), nbf: soon, iat: soon });
  assert.equal(await verifyAccessJwt(token, env), null);
});

test("a flood of unknown kids costs one certs fetch, not one each", async () => {
  // The forced refetch runs before any signature is checked, so an
  // unauthenticated caller controls it. Rate-limited, it cannot be an
  // amplifier pointed at Cloudflare.
  resetJwksCacheForTests();
  const { sign, jwks } = await issuer();
  const calls = serveJwks(jwks);
  const token = await sign({ email: "a@x.com", aud: [AUD], exp: future() });
  // Prime the cache, then present tokens whose kid is not in it.
  await verifyAccessJwt(token, env);
  const primed = calls.count;
  for (let n = 0; n < 10; n += 1) {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: `forged-${n}` })).toString(
      "base64url",
    );
    const payload = Buffer.from(JSON.stringify({})).toString("base64url");
    assert.equal(await verifyAccessJwt(`${header}.${payload}.AAAA`, env), null);
  }
  assert.equal(calls.count - primed, 1, "at most one forced refetch for the whole flood");
});

test("an expired token is refused", async () => {
  resetJwksCacheForTests();
  const { sign, jwks } = await issuer();
  serveJwks(jwks);
  const token = await sign({ email: "a@x.com", aud: [AUD], exp: Math.floor(Date.now() / 1000) - 1 });
  assert.equal(await verifyAccessJwt(token, env), null);
});

test("a token signed by a different key is refused", async () => {
  resetJwksCacheForTests();
  const mint = await issuer();
  const attacker = await issuer();
  // Serve the honest JWKS; sign with the attacker's key under the same kid.
  serveJwks(mint.jwks);
  const token = await attacker.sign({ email: "a@x.com", aud: [AUD], exp: future() });
  assert.equal(await verifyAccessJwt(token, env), null);
});

test("garbage and truncated tokens are refused without throwing", async () => {
  resetJwksCacheForTests();
  const { jwks } = await issuer();
  serveJwks(jwks);
  for (const bad of ["", "a", "a.b", "...", "not.a.token", "a.b.c"]) {
    assert.equal(await verifyAccessJwt(bad, env), null, `${bad} must be refused`);
  }
});

test("an unknown kid forces one JWKS refresh, so a key rotation recovers", async () => {
  resetJwksCacheForTests();
  const { sign, jwks } = await issuer();
  const calls = serveJwks(jwks);
  // Prime the cache.
  await verifyAccessJwt(await sign({ email: "a@x.com", aud: [AUD], exp: future() }), env);
  const primed = calls.count;
  // A token naming a kid the cache does not have must trigger a refetch
  // rather than failing until the hour-long TTL expires.
  await verifyAccessJwt(
    await sign({ email: "a@x.com", aud: [AUD], exp: future() }, { kid: "rotated" }),
    env,
  );
  assert.ok(calls.count > primed, "an unknown kid must refresh the JWKS");
});

// --- principal derivation ---------------------------------------------

test("principal ids are injective where the old scheme collided", async () => {
  const identities = ["a+b@x.com", "a_b@x.com", "a b@x.com", "A.B@x.com", "a.b@x.com"];
  const ids = await Promise.all(identities.map(principalId));
  assert.equal(new Set(ids).size, identities.length, "ids must not collide");
  for (const id of ids) assert.match(id, /^[0-9a-f]{64}$/);
});

test("a principal id is a single plain segment, so it cannot forge a prefix", async () => {
  const id = await principalId("a/../b@x.com");
  assert.ok(!id.includes("/"));
});

// --- request parsing ---------------------------------------------------

test("a PUT carries only a session id, never an owner", () => {
  const asked = describeRequest(
    { method: "PUT", headers: new Headers() },
    new URL("https://x/s/sess-1"),
  );
  assert.equal(asked.request.op, "publish");
  assert.equal(asked.request.session, "sess-1");
  assert.ok(!("slug" in asked.request), "publish must not accept a full key");
});

test("listing scope comes from the query, everything else is a slug", () => {
  const get = (path) => describeRequest({ method: "GET", headers: new Headers() }, new URL(path));
  assert.deepEqual(get("https://x/s?owner=me").request, { op: "list", mine: true });
  assert.deepEqual(get("https://x/s").request, { op: "list", mine: false });
  assert.equal(get("https://x/s/alice/sess-1").request.slug, "alice/sess-1");
  assert.equal(get("https://x/nope"), null);
});

test("a malformed percent-escape is passed through for the core to reject", () => {
  const asked = describeRequest({ method: "GET", headers: new Headers() }, new URL("https://x/s/%ZZ"));
  assert.equal(asked.request.op, "read");
});

test("team configuration ignores malformed pairs", () => {
  assert.deepEqual(parseTeams("a:red, b:blue"), [["a", "red"], ["b", "blue"]]);
  assert.deepEqual(parseTeams("a:red,broken,:blue,c:"), [["a", "red"]]);
  assert.deepEqual(parseTeams(undefined), []);
});

// --- documents and metadata --------------------------------------------

test("parseSimple sniffs shape, not content type", () => {
  assert.ok(parseSimple('{"messages":[]}'));
  for (const bad of ["not json", "[]", '{"no":"messages"}', "null"]) {
    assert.equal(parseSimple(bad), null, `${bad} must be refused`);
  }
});

test("utf8Truncate budgets bytes and never splits a character", () => {
  assert.equal(utf8Truncate("漢".repeat(10), 10), "漢".repeat(3));
  assert.equal(utf8Truncate("👍👍", 5), "👍");
  assert.equal(utf8Truncate("plain", 100), "plain");
});

test("summarize stays within the metadata byte budget with non-ASCII fields", () => {
  const meta = summarize({
    messages: new Array(3),
    id: "sess-1",
    title: "た".repeat(2000),
    cwd: `/${"ほ".repeat(2000)}`,
  });
  const encoder = new TextEncoder();
  const bytes = Object.entries(meta).reduce(
    (total, [k, v]) => total + encoder.encode(k).length + encoder.encode(v).length,
    0,
  );
  assert.ok(bytes <= 1800, `metadata was ${bytes} bytes`);
  assert.equal(meta.id, "sess-1");
  assert.equal(meta.messages, "3");
});

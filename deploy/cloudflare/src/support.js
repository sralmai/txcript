// Everything the Worker does that is not I/O and not a decision: request
// parsing, document sniffing, metadata budgeting, and Access JWT
// verification.
//
// Separate from `index.js` so it can be tested with plain `node --test`,
// without a wasm build or a Workers runtime. `index.js` imports the wasm
// module at load time, which a unit test has no way to provide.

const JWKS_TTL_MS = 60 * 60 * 1000;
const METADATA_BUDGET = 1800;

// Parse an HTTP request into the shape the decision core takes. `null` for a
// path this service does not serve.
export function describe(request, url) {
  const path = url.pathname.replace(/\/+$/, "");

  if (path === "/s" && request.method === "GET") {
    return { request: { op: "list", mine: url.searchParams.get("owner") === "me" } };
  }

  const match = path.match(/^\/s\/(.+)$/);
  if (!match) return null;

  let rest;
  try {
    rest = decodeURIComponent(match[1]);
  } catch {
    // A percent-escape that is not valid UTF-8 is a malformed request, not a
    // server fault; let the core reject it as a bad slug.
    rest = match[1];
  }

  switch (request.method) {
    case "PUT":
      // Only a bare session id. The owner segment comes from the
      // authenticated principal, so writing outside your own namespace is
      // not expressible rather than merely denied.
      return {
        request: { op: "publish", session: rest, if_match: request.headers.get("If-Match") },
        session: rest,
      };
    case "GET":
      return { request: { op: "read", slug: rest }, targetKey: rest };
    case "DELETE":
      return { request: { op: "delete", slug: rest }, targetKey: rest };
    default:
      return null;
  }
}

// `TEAMS` is `principalId:team` pairs, comma separated. Unused by every
// policy but `team_scoped`.
export function parseTeams(raw) {
  if (!raw) return [];
  return raw
    .split(",")
    .map((pair) => pair.trim().split(":"))
    .filter((parts) => parts.length === 2 && parts[0] && parts[1]);
}

// --- Simple documents --------------------------------------------------

// Format sniffing, the same contract the on-disk stores honour: a name or a
// content type does not identify a transcript, the shape does.
export function parseSimple(body) {
  let doc;
  try {
    doc = JSON.parse(body);
  } catch {
    return null;
  }
  const ok = doc && typeof doc === "object" && !Array.isArray(doc) && Array.isArray(doc.messages);
  return ok ? doc : null;
}

// R2 caps custom metadata at roughly 2 KiB across keys and values, counted in
// bytes. Truncating by characters is how a non-ASCII title once failed a PUT.
export function utf8Truncate(value, maxBytes) {
  const encoder = new TextEncoder();
  if (encoder.encode(value).length <= maxBytes) return value;
  let out = "";
  let used = 0;
  for (const character of value) {
    const width = encoder.encode(character).length;
    if (used + width > maxBytes) break;
    out += character;
    used += width;
  }
  return out;
}

export function summarize(doc) {
  const fields = [
    ["id", typeof doc.id === "string" ? doc.id : ""],
    ["messages", String(doc.messages.length)],
    ["timestamp", doc.timestamp],
    ["model", doc.model],
    ["git_branch", doc.git_branch],
    ["title", doc.title],
    ["cwd", doc.cwd],
  ];
  const encoder = new TextEncoder();
  const out = {};
  let used = 0;
  for (const [key, value] of fields) {
    if (typeof value !== "string" || value.length === 0) continue;
    const overhead = encoder.encode(key).length;
    if (used + overhead >= METADATA_BUDGET) break;
    const clipped = utf8Truncate(value, METADATA_BUDGET - used - overhead);
    if (clipped.length === 0) continue;
    out[key] = clipped;
    used += overhead + encoder.encode(clipped).length;
  }
  return out;
}

// --- identity ----------------------------------------------------------

// The principal id the Rust side will only ever compare, never parse.
//
// **It must be injective in the Access identity.** Ownership is a comparison
// of these, so two identities sharing one could delete each other's
// transcripts. SHA-256 gives that; an earlier version lowercased and
// replaced punctuation, collapsing `a+b@x.com` and `a_b@x.com` onto one
// owner.
export async function principalId(identity) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(identity));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function callerPrincipal(request, env) {
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) return null;
  const claims = await verifyAccessJwt(token, env);
  if (!claims) return null;
  // SSO logins carry `email`; service tokens carry `common_name`.
  const identity = claims.email ?? claims.common_name;
  if (!identity) return null;
  return { id: await principalId(identity), label: identity, service: !claims.email };
}

let jwksCache = { at: 0, keys: null };

// A forced refetch is throttled separately from the TTL. Without this, an
// unauthenticated request naming an unknown `kid` drives an origin subrequest
// every time, so forged headers with random `kid`s become an amplifier.
const JWKS_FORCE_INTERVAL_MS = 60 * 1000;
let lastForcedAt = 0;

async function accessKeys(env, force = false) {
  if (force) {
    if (Date.now() - lastForcedAt < JWKS_FORCE_INTERVAL_MS) return jwksCache.keys ?? [];
    lastForcedAt = Date.now();
  }
  if (!force && jwksCache.keys && Date.now() - jwksCache.at < JWKS_TTL_MS) return jwksCache.keys;
  const url =
    env.ACCESS_CERTS_URL ?? `https://${env.ACCESS_TEAM}.cloudflareaccess.com/cdn-cgi/access/certs`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`fetching Access certs: ${response.status}`);
  const { keys } = await response.json();
  jwksCache = { at: Date.now(), keys };
  return keys;
}

export function resetJwksCacheForTests() {
  jwksCache = { at: 0, keys: null };
  lastForcedAt = 0;
}

export async function verifyAccessJwt(token, env) {
  const [header64, payload64, signature64] = token.split(".");
  if (!header64 || !payload64 || !signature64) return null;

  let header;
  try {
    header = JSON.parse(decodeText(header64));
  } catch {
    return null;
  }

  // A key rotation publishes a new `kid`. Without this retry the stale cache
  // would reject every request until the TTL expired, up to an hour later.
  let key = (await accessKeys(env)).find((candidate) => candidate.kid === header.kid);
  if (!key) {
    key = (await accessKeys(env, true)).find((candidate) => candidate.kid === header.kid);
  }
  if (!key) return null;

  const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  try {
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      { ...key, alg: "RS256", ext: true },
      algorithm,
      false,
      ["verify"],
    );
    const signed = new TextEncoder().encode(`${header64}.${payload64}`);
    if (!(await crypto.subtle.verify(algorithm, publicKey, decodeBytes(signature64), signed))) {
      return null;
    }
    const claims = JSON.parse(decodeText(payload64));
    if (typeof claims.exp !== "number" || claims.exp * 1000 <= Date.now()) return null;
    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    return audience.includes(env.ACCESS_AUD) ? claims : null;
  } catch {
    return null;
  }
}

// --- helpers -----------------------------------------------------------

const decodeBytes = (value) => {
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

const decodeText = (value) => new TextDecoder().decode(decodeBytes(value));

export const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

// SECURITY: this Worker trusts Cf-Access-Jwt-Assertion, and verifies it
// against the team's JWKS and the app's AUD tag so a request reaching the
// origin by another route (workers.dev, a direct R2 binding) still cannot
// forge an identity. Access in front is the gate; this is the lock behind it.
// Without BOTH, every published transcript is world-readable over HTTPS, and
// transcripts carry cwd paths, branch names, source, and tool output.

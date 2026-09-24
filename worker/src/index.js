// txcript share — a gist-like store for Simple transcript documents.
//
// This file does I/O and nothing else: it verifies the Cloudflare Access
// JWT, talks to R2, and turns a decision into an HTTP response. Every
// decision is made by the wasm module built from `share-worker`, which wraps
// `txcript_share_core::decide`.
//
// The division is deliberate. Authorization logic lived here once, in
// JavaScript, and grew a bug that let one user's transcripts overwrite
// another's. There is now one implementation of the rules, in Rust, covered
// by an access matrix that runs without a server — and this file has no
// authorization branch of its own. Adding one here would put the rules back
// in two places.

import init, { filter_listing, plan } from "../build/txcript_share_worker.js";
import wasm from "../build/txcript_share_worker_bg.wasm";
import {
  callerPrincipal,
  describe,
  json,
  parseSimple,
  parseTeams,
  summarize,
} from "./support.js";

const MAX_DOC_BYTES = 10 * 1024 * 1024;
const PAGE_SIZE = 1000;

let ready;

export default {
  async fetch(request, env) {
    try {
      ready ??= init(wasm);
      await ready;
      return await route(request, env);
    } catch (error) {
      console.error("unhandled:", error?.stack ?? String(error));
      return json({ error: "internal error" }, 500);
    }
  },
};

async function route(request, env) {
  const url = new URL(request.url);
  const principal = await callerPrincipal(request, env);
  if (!principal) return json({ error: "unauthenticated" }, 401);

  const asked = describe(request, url);
  if (!asked) return json({ error: "not found" }, 404);

  const key = asked.targetKey ?? (asked.session ? `${principal.id}/${asked.session}` : null);
  const facts = key ? await head(env, key) : null;

  const decision = JSON.parse(
    plan(JSON.stringify({ ...envelope(env, principal), request: asked.request, facts })),
  );

  switch (decision.do) {
    case "reject":
      return json({ error: decision.reason }, decision.status);
    case "read":
      return await readObject(env, decision.key);
    case "write":
      return await writeObject(request, env, decision);
    case "delete":
      await env.SHARE.delete(decision.key);
      return new Response(null, { status: 204 });
    case "list":
      return await listObjects(env, decision, principal);
    default:
      console.error("unknown plan:", decision.do);
      return json({ error: "internal error" }, 500);
  }
}


function envelope(env, principal) {
  return {
    policy: env.POLICY ?? "owner_prefix",
    principal,
    teams: parseTeams(env.TEAMS),
  };
}


// --- R2 ---------------------------------------------------------------

async function head(env, key) {
  const found = await env.SHARE.head(key);
  if (!found) return null;
  return { version: found.httpEtag, team: found.customMetadata?.team ?? null };
}

async function readObject(env, key) {
  const object = await env.SHARE.get(key);
  // The decision was made against a HEAD; the object can vanish between the
  // two, and that is a 404 rather than an error.
  if (!object) return json({ error: "no such transcript" }, 404);
  return new Response(object.body, {
    headers: {
      "content-type": "application/json",
      etag: object.httpEtag,
      "last-modified": object.uploaded.toUTCString(),
    },
  });
}

async function writeObject(request, env, decision) {
  // Measure bytes, not UTF-16 code units: `body.length` counts a 3-byte CJK
  // character as one and would admit a document three times the cap.
  const raw = new Uint8Array(await request.arrayBuffer());
  if (raw.byteLength > MAX_DOC_BYTES) return json({ error: "document too large" }, 413);

  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch {
    return json({ error: "body is not valid UTF-8" }, 400);
  }
  const doc = parseSimple(text);
  if (!doc) return json({ error: "body is not a Simple transcript document" }, 400);

  const options = {
    httpMetadata: { contentType: "application/json" },
    customMetadata: summarize(doc),
  };
  // The core decided the concurrency rule; this only applies it.
  if (decision.precondition.kind === "if_absent") {
    options.onlyIf = { etagDoesNotMatch: "*" };
  } else if (decision.precondition.kind === "if_version") {
    options.onlyIf = { etagMatches: decision.precondition.version };
  }

  const put = await env.SHARE.put(decision.key, raw, options);
  // R2 returns null when `onlyIf` fails, which is the point of asking.
  if (!put) return json({ error: "transcript changed since it was read" }, 412);
  return json(
    { slug: decision.key, etag: put.httpEtag },
    decision.precondition.kind === "if_absent" ? 201 : 200,
  );
}

async function listObjects(env, decision, principal) {
  const entries = [];
  let cursor;
  do {
    const page = await env.SHARE.list({
      prefix: decision.prefix,
      cursor,
      limit: PAGE_SIZE,
      include: ["customMetadata"],
    });
    for (const object of page.objects) {
      entries.push({
        slug: object.key,
        etag: object.httpEtag,
        updated_at: object.uploaded.toISOString(),
        team: object.customMetadata?.team ?? null,
        ...object.customMetadata,
      });
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);

  let visible = entries;
  if (decision.authorize_each) {
    // The policy's read rule is not a prefix, so the core decides each
    // entry. Skipping this would list keys and titles it denies on read.
    const allowed = new Set(
      JSON.parse(
        filter_listing(
          JSON.stringify({
            ...envelope(env, principal),
            request: { op: "list", mine: false },
            entries: entries.map(({ slug, team }) => ({ slug, team })),
          }),
        ),
      ),
    );
    visible = entries.filter((entry) => allowed.has(entry.slug));
  }

  visible.sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1));
  return json({ sessions: visible });
}


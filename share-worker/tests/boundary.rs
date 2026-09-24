//! The JSON boundary between the Worker's JavaScript and the decision core.
//!
//! These run natively, against the `rlib`, so the whole surface the Worker
//! depends on is covered without a Workers runtime. The access rules
//! themselves are `share-core`'s to test; what is tested here is that the
//! shim cannot be talked past — a malformed or hostile envelope must become
//! a rejection, never an unintended permission.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{Value, json};
use txcript_share_worker::{filter_listing, plan};

fn planned(input: &Value) -> Value {
    serde_json::from_str(&plan(&input.to_string())).expect("output is JSON")
}

fn alice() -> Value {
    json!({ "id": "alice", "label": "alice@example.com", "service": false })
}

#[test]
fn a_publish_lands_under_the_callers_own_prefix() {
    let out = planned(&json!({
        "policy": "owner_prefix",
        "principal": alice(),
        "request": { "op": "publish", "session": "sess-1", "if_match": null },
    }));
    assert_eq!(out["do"], "write");
    assert_eq!(out["key"], "alice/sess-1");
    // Creating is conditional, so a racing create is not clobbered.
    assert_eq!(out["precondition"]["kind"], "if_absent");
}

#[test]
fn a_client_cannot_name_another_owners_key_when_publishing() {
    // The envelope has no field for it: `publish` carries a bare session id
    // and the owner comes from the principal. Trying to smuggle a slug in
    // fails because a slug is not a plain segment.
    let out = planned(&json!({
        "policy": "owner_prefix",
        "principal": alice(),
        "request": { "op": "publish", "session": "bob/sess-1", "if_match": null },
    }));
    assert_eq!(out["do"], "reject");
    assert_eq!(out["status"], 400);
}

#[test]
fn traversal_in_a_slug_is_refused_rather_than_normalised() {
    for slug in ["../etc/passwd", "alice/../bob/s", "/abs", "a/b/c", ".."] {
        let out = planned(&json!({
            "policy": "owner_prefix",
            "principal": alice(),
            "request": { "op": "read", "slug": slug },
        }));
        assert_eq!(out["do"], "reject", "{slug} must be refused");
        assert_eq!(out["status"], 400);
    }
}

#[test]
fn a_principal_id_that_is_not_a_plain_segment_is_refused() {
    // The JavaScript derives this with SHA-256. If that ever emitted
    // something containing a separator, it could address another owner's
    // keys — so the shim refuses rather than sanitising.
    for id in ["", "..", ".", "a/b", "a\u{0}b"] {
        let out = planned(&json!({
            "policy": "owner_prefix",
            "principal": { "id": id, "service": false },
            "request": { "op": "list", "mine": true },
        }));
        assert_eq!(out["do"], "reject", "{id:?} must be refused");
        assert_eq!(out["status"], 401);
    }
}

#[test]
fn deleting_another_owners_transcript_is_forbidden() {
    let out = planned(&json!({
        "policy": "owner_prefix",
        "principal": alice(),
        "request": { "op": "delete", "slug": "bob/sess-1" },
        "facts": { "version": "\"v1\"" },
    }));
    assert_eq!(out["do"], "reject");
    assert_eq!(out["status"], 403);
}

#[test]
fn a_read_only_deployment_refuses_every_write() {
    for request in [
        json!({ "op": "publish", "session": "sess-1", "if_match": null }),
        json!({ "op": "delete", "slug": "alice/sess-1" }),
    ] {
        let out = planned(&json!({
            "policy": "read_only_mirror",
            "principal": alice(),
            "request": request,
            "facts": { "version": "\"v1\"" },
        }));
        assert_eq!(out["do"], "reject");
        assert_eq!(out["status"], 403);
    }
}

#[test]
fn a_team_scoped_listing_tells_the_host_to_filter() {
    let out = planned(&json!({
        "policy": "team_scoped",
        "principal": alice(),
        "request": { "op": "list", "mine": false },
        "teams": [["alice", "red"], ["bob", "blue"]],
    }));
    assert_eq!(out["do"], "list");
    assert_eq!(out["prefix"], "");
    assert_eq!(
        out["authorize_each"], true,
        "a prefix cannot express a team, so the host must filter"
    );
}

#[test]
fn filtering_drops_entries_the_policy_would_deny_on_read() {
    let kept: Vec<String> = serde_json::from_str(&filter_listing(
        &json!({
            "policy": "team_scoped",
            "principal": alice(),
            "request": { "op": "list", "mine": false },
            "teams": [["alice", "red"], ["bob", "blue"]],
            "entries": [
                { "slug": "alice/own", "team": "red" },
                { "slug": "bob/same-team", "team": "red" },
                { "slug": "bob/other-team", "team": "blue" },
                { "slug": "not a slug", "team": "red" },
            ],
        })
        .to_string(),
    ))
    .expect("output is JSON");
    assert_eq!(kept, vec!["alice/own", "bob/same-team"]);
}

#[test]
fn an_owner_prefix_listing_needs_no_filtering() {
    let out = planned(&json!({
        "policy": "owner_prefix",
        "principal": alice(),
        "request": { "op": "list", "mine": true },
    }));
    assert_eq!(out["do"], "list");
    assert_eq!(out["prefix"], "alice/");
    assert_eq!(out["authorize_each"], false);
}

#[test]
fn garbage_in_is_a_rejection_not_a_panic_or_a_permission() {
    for input in [
        "",
        "null",
        "[]",
        "{}",
        r#"{"policy":"nope","principal":{"id":"alice"},"request":{"op":"list","mine":true}}"#,
        r#"{"policy":"owner_prefix","principal":{"id":"alice"},"request":{"op":"fly"}}"#,
    ] {
        let out: Value = serde_json::from_str(&plan(input)).expect("still JSON");
        assert_eq!(out["do"], "reject", "{input:?} must be refused");
    }
}

#[test]
fn a_stale_if_match_is_a_precondition_failure() {
    let out = planned(&json!({
        "policy": "owner_prefix",
        "principal": alice(),
        "request": { "op": "publish", "session": "sess-1", "if_match": "\"old\"" },
        "facts": { "version": "\"current\"" },
    }));
    assert_eq!(out["do"], "reject");
    assert_eq!(out["status"], 412);
}

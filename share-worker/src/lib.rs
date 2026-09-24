//! The wasm decision shim for the share Worker.
//!
//! The Worker's JavaScript does I/O — verifying the Access JWT with
//! `WebCrypto`, talking to R2 — and nothing else. Every decision is made
//! here, by [`txcript_share_core::decide`], so there is one implementation
//! of the rules rather than one per host.
//!
//! This module is deliberately thin: JSON in, JSON out, no logic of its own.
//! Anything that looks like a policy decision creeping in here belongs in
//! [`txcript_share_core::policy`] instead, where the access matrix covers it.
//!
//! # The trust boundary
//!
//! `principal.id` arrives already derived — the JavaScript hashes the Access
//! identity with SHA-256, because `WebCrypto` is the platform primitive and
//! this crate has no cryptography. **That derivation must be injective**:
//! ownership is a comparison of these ids, so two identities sharing one
//! would be able to delete each other's transcripts. The id is re-validated
//! here as a single plain segment, which stops a malformed one becoming a
//! key prefix, but injectivity is the caller's guarantee and is asserted on
//! the JavaScript side.

use serde::{Deserialize, Serialize};
use txcript_share_core::plan::{ObjectFacts, Plan, Precondition, Request, Status, decide};
use txcript_share_core::policy::{
    Action, AllowAll, ListScope, OwnerPrefix, Policy, ReadOnlyMirror, Target, TeamScoped,
};
use txcript_share_core::{Key, Principal, PrincipalId, PrincipalKind};
use wasm_bindgen::prelude::wasm_bindgen;

// --- the wire shapes -------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyChoice {
    OwnerPrefix,
    ReadOnlyMirror,
    TeamScoped,
    /// Permits everything. Rejected unless the deployment opts in, because
    /// shipping it by accident would disable every write check.
    AllowAll,
}

#[derive(Debug, Deserialize)]
pub struct PrincipalIn {
    /// Already derived and injective. See the trust-boundary note above.
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub service: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RequestIn {
    Read {
        slug: String,
    },
    Publish {
        session: String,
        if_match: Option<String>,
    },
    Delete {
        slug: String,
    },
    List {
        mine: bool,
    },
}

#[derive(Debug, Deserialize)]
pub struct FactsIn {
    pub version: String,
    #[serde(default)]
    pub team: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Input {
    pub policy: PolicyChoice,
    pub principal: PrincipalIn,
    pub request: RequestIn,
    /// The target object as the host found it, or absent.
    #[serde(default)]
    pub facts: Option<FactsIn>,
    /// Team membership, for `team_scoped`. Ignored by other policies.
    #[serde(default)]
    pub teams: Vec<(String, String)>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "do", rename_all = "snake_case")]
pub enum Output {
    Reject {
        status: u16,
        reason: String,
    },
    Read {
        key: String,
    },
    Write {
        key: String,
        precondition: PreconditionOut,
        /// Attributes the policy requires on the stored object; the host
        /// merges these over what it derives from the document.
        attributes: Vec<(String, String)>,
    },
    Delete {
        key: String,
    },
    List {
        prefix: String,
        authorize_each: bool,
    },
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PreconditionOut {
    None,
    IfAbsent,
    IfVersion { version: String },
}

// --- the exports -----------------------------------------------------

/// Decide one request. Returns an [`Output`] as JSON; never fails, because
/// a malformed input is itself a decision (reject with 400).
#[wasm_bindgen]
#[must_use]
pub fn plan(input: &str) -> String {
    let output = match serde_json::from_str::<Input>(input) {
        Ok(input) => decide_input(&input),
        Err(_) => reject(Status::BAD_REQUEST, "malformed request"),
    };
    serde_json::to_string(&output).unwrap_or_else(|_| {
        // Serializing an `Output` cannot fail, but returning a parseable
        // refusal beats an empty string if it somehow did.
        r#"{"do":"reject","status":500,"reason":"could not encode plan"}"#.to_string()
    })
}

/// Filter a listing the host has already fetched.
///
/// Needed when [`Output::List`] set `authorize_each`: a policy whose read
/// rule is not a prefix (team scoping) admits entries individually, and the
/// host must not show the ones it would deny on read. Input is the same
/// envelope plus `entries`; output is the slugs that survive, as JSON.
#[wasm_bindgen]
#[must_use]
pub fn filter_listing(input: &str) -> String {
    #[derive(Deserialize)]
    struct FilterIn {
        #[serde(flatten)]
        base: Input,
        entries: Vec<EntryIn>,
    }
    #[derive(Deserialize)]
    struct EntryIn {
        slug: String,
        #[serde(default)]
        team: Option<String>,
    }

    let Ok(parsed) = serde_json::from_str::<FilterIn>(input) else {
        return "[]".to_string();
    };
    let Some(who) = principal_of(&parsed.base.principal) else {
        return "[]".to_string();
    };
    let policy = policy_of(&parsed.base);

    let kept: Vec<&str> = parsed
        .entries
        .iter()
        .filter(|entry| {
            Key::parse(&entry.slug).is_some_and(|key| {
                let mut target = Target::new(key);
                target.team.clone_from(&entry.team);
                policy.authorize(&who, Action::Read, &target).is_allowed()
            })
        })
        .map(|entry| entry.slug.as_str())
        .collect();
    serde_json::to_string(&kept).unwrap_or_else(|_| "[]".to_string())
}

// --- mapping ---------------------------------------------------------

fn decide_input(input: &Input) -> Output {
    let Some(who) = principal_of(&input.principal) else {
        // An id that is not a plain segment could address another owner's
        // keys; refuse rather than sanitize it into something that does.
        return reject(Status::UNAUTHORIZED, "unusable principal id");
    };
    let policy = policy_of(input);

    let request = match &input.request {
        RequestIn::Read { slug } => match Key::parse(slug) {
            Some(key) => Request::Read { key },
            None => return reject(Status::BAD_REQUEST, "malformed slug"),
        },
        RequestIn::Delete { slug } => match Key::parse(slug) {
            Some(key) => Request::Delete { key },
            None => return reject(Status::BAD_REQUEST, "malformed slug"),
        },
        RequestIn::Publish { session, if_match } => Request::Publish {
            session: session.clone(),
            if_match: if_match.clone(),
        },
        RequestIn::List { mine } => Request::List {
            scope: if *mine {
                ListScope::Mine
            } else {
                ListScope::Everyone
            },
        },
    };

    let facts = input.facts.as_ref().map(|facts| ObjectFacts {
        version: facts.version.clone(),
        team: facts.team.clone(),
    });
    out(decide(&request, &who, facts.as_ref(), policy.as_ref()))
}

fn principal_of(principal: &PrincipalIn) -> Option<Principal> {
    let id = PrincipalId::new(principal.id.clone())?;
    let kind = if principal.service {
        PrincipalKind::Service
    } else {
        PrincipalKind::Human
    };
    let built = Principal::new(id, kind);
    Some(match &principal.label {
        Some(label) => built.with_label(label.clone()),
        None => built,
    })
}

fn policy_of(input: &Input) -> Box<dyn Policy> {
    match input.policy {
        PolicyChoice::OwnerPrefix => Box::new(OwnerPrefix),
        PolicyChoice::ReadOnlyMirror => Box::new(ReadOnlyMirror),
        PolicyChoice::AllowAll => Box::new(AllowAll),
        PolicyChoice::TeamScoped => {
            let policy = input
                .teams
                .iter()
                .fold(
                    TeamScoped::new(),
                    |policy, (id, team)| match PrincipalId::new(id.clone()) {
                        Some(id) => policy.with(id, team.clone()),
                        None => policy,
                    },
                );
            Box::new(policy)
        }
    }
}

fn out(plan: Plan) -> Output {
    match plan {
        Plan::Reject(Status(status), reason) => Output::Reject {
            status,
            reason: reason.to_string(),
        },
        Plan::ReadObject(key) => Output::Read { key: key.to_slug() },
        Plan::WriteObject {
            key,
            precondition,
            attributes,
        } => Output::Write {
            key: key.to_slug(),
            attributes: attributes
                .into_iter()
                .map(|(name, value)| (name.to_string(), value))
                .collect(),
            precondition: match precondition {
                Precondition::None => PreconditionOut::None,
                Precondition::IfAbsent => PreconditionOut::IfAbsent,
                Precondition::IfVersion(version) => PreconditionOut::IfVersion { version },
            },
        },
        Plan::DeleteObject(key) => Output::Delete { key: key.to_slug() },
        Plan::List(list) => Output::List {
            prefix: list.prefix.as_store_prefix(),
            authorize_each: list.authorize_each,
        },
    }
}

fn reject(Status(status): Status, reason: &str) -> Output {
    Output::Reject {
        status,
        reason: reason.to_string(),
    }
}

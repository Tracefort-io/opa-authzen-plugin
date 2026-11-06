# Design: Access Request Service in the plugin

Status: phase 1 implemented (branch `ars-phase1`); phase 2 implemented (branch `ars-phase2`, §17); phase 3 open

## 1. Summary

Add an optional Access Request Service (ARS) to the plugin, so a single binary can play both roles of the [AuthZEN Access Request and Approval Profile](https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html) (ARAP): the PDP that issues requestable denials and re-evaluates approvals, and the service that accepts access requests and runs them to an approved or denied state.

The profile allows this placement: the Access Request Endpoint "MAY be hosted by the PDP itself". State lives in Postgres so any number of PDP replicas can serve the API. Everything deployment-specific — who may submit, who approves what, which approvals are eligible — is decided by Rego rules the operator writes, so the plugin carries no product-specific code. A separate UI drives approvals through an approver API.

## 2. Goals and non-goals

Goals

- Implement the ARAP Access Request Endpoint, Task Status Endpoint and cancellation, with the profile's error types, idempotency and task state machine.
- Implement the companion Bulk, Callback and Actor profiles (phased, §16).
- Provide a generic approver API that a separately deployed UI can use.
- Keep the PDP evaluation path free of database access except when a request carries `context.approval`.
- Run correctly with multiple replicas sharing one Postgres database.
- Express every authorization and routing decision of the service in Rego.

Non-goals

- A user interface. It is a separate application consuming the approver API.
- An approval policy language or workflow engine beyond ordered steps with an approval quorum (§6).
- Provisioning or fulfilment. An approval changes what re-evaluation permits; it does not grant entitlements in other systems.
- The Catalog Profile and the OAuth Access Request Profile (token-issuance completion). Possible later; not in this design.
- Enumerating a subject's tasks for the requester. The profile defines no such API.

## 3. Architecture

```
            PEP (agentgateway / Envoy ext_authz / app)
              |  1 evaluation            3 submit, 5 poll/cancel
              v                            v
  +-------------------- opa-authzen-plugin replica (N of them) --------------------+
  |  AuthZEN API                        ARS API (ARAP)          Approver API        |
  |  /access/v1/evaluation(s)           /access/v1/requests...  /access/v1/admin/.. |
  |        |  rules: allow, decision_context        |  rules: ars_caller, ars_workflow,|
  |        |  signs binding_token                   |  ars_approver                    |
  |        |  looks up approval (6 re-evaluation)   |                                  |
  |        +-----------------+----------------------+-----------+                     |
  |                          |   workers: expiry, callbacks     |                     |
  +--------------------------|----------------------------------|---------------------+
                             v                                  ^
                         Postgres  <------------------------  Approval UI (separate app)
                                         approver API calls
```

New Go packages (no change to the plugin's public `plugin` package):

| Package | Responsibility |
|---|---|
| `internal/ars` | HTTP handlers for the ARAP and approver APIs; request validation; task state machine |
| `internal/ars/store` | `Store` interface; `postgres` implementation; `memory` implementation for tests |
| `internal/ars/workers` | Expiry sweeper, callback delivery, retention purge |
| `internal/authn` | Bearer JWT validation against configured issuers (shared by both APIs) |

The existing `internal` package wires the service in when it is enabled: it registers the routes, starts the workers in `Start`, stops them in `Stop`, and switches approval verification to the shared-state lookup (§8).

## 4. Configuration

```yaml
plugins:
  authzen:
    base_url: "https://pdp.example.com"
    decision_context: decision_context
    capabilities: ["urn:openid:authzen:capability:access-request"]
    access_request:
      signing_key_file: /etc/authzen/pdp-signing.jwk   # binding_token (and approval.state, §8)
      audience: "https://pdp.example.com"              # the ARS is this PDP
      binding_context_members: ["project"]
      service:
        enabled: true
        database:
          dsn_env: AUTHZEN_ARS_DSN        # DSN read from the environment, never from the file
          max_conns: 10
        caller_auth:                      # who may call the ARAP endpoints (PEPs, agent runtimes)
          issuers:
            - issuer: "https://idp.example.com"
              audience: "https://pdp.example.com"
              jwks_uri: "https://idp.example.com/.well-known/jwks.json"
        approver_auth:                    # who may call the approver API (the UI on behalf of a user)
          issuers:
            - issuer: "https://idp.example.com"
              audience: "authzen-approver-api"
              jwks_uri: "https://idp.example.com/.well-known/jwks.json"
        rules:
          caller: ars_caller              # may this caller submit / view / cancel?
          workflow: ars_workflow          # steps, approvers, approval lifetime, auto-decision
          approver: ars_approver          # may this approver view / decide / revoke?
        task_ttl: 72h                     # default task.expires_at
        max_approval_ttl: 720h            # upper bound on approved_until
        idempotency_retention: 24h        # after the task reaches a terminal status
        max_items: 50                     # bulk submissions (§17.2)
        max_steps: 10                     # workflow steps (§17.1)
        approval_cache_ttl: 0s            # re-evaluation lookup cache; 0 disables (§8)
        links:                            # optional; omitted from task.links when unset
          ticket: "https://ui.example.com/requests/{id}"
          review: "https://ui.example.com/review/{id}"
        callbacks:                        # §17.3; without it, a submitted callback is rejected
          timeout: 5s
          max_attempts: 8
          destinations:
            - host: agents.example.com
              hmac_secret_env: AUTHZEN_ARS_CALLBACK_SECRET_AGENTS
              allow_internal: false
```

Rules are queried under `path`, like the existing `decision` and `decision_context` rules. When `service.enabled` is true, `access_request_endpoint` defaults to `<base_url>/access/v1/requests`. `base_url` becomes required because the service builds absolute `status_endpoint` and link URLs from it.

`Validate` rejects:
- the service enabled without `base_url`, without a signing key, or without each of the three rules;
- `caller_auth` or `approver_auth` with no issuers;
- a DSN given inline.

## 5. ARAP endpoints

| Method and path | Profile section | Notes |
|---|---|---|
| `POST /access/v1/requests` | Access Request Submission | `201` with a terminal task when the workflow auto-decides; otherwise `202` with `pending`. `Location` set to `status_endpoint`. |
| `GET /access/v1/requests/{id}` | Task Status Endpoint | Returns `task` and, when terminal, `result`. |
| `POST /access/v1/requests/{id}/cancel` (also `DELETE`) | Cancellation | `200` with the cancelled task; `409 invalid_task_state` when terminal. Advertised as `task.links.cancel`. |

Submission processing, in order. Each step's failure maps to the profile's problem type (`application/problem+json`):

1. **Authenticate** the caller (§9).
2. **Parse** the body. `subject`, `resource`/`action` (or `items` with the Bulk Profile) and `denial` are required. The same input checks as the evaluation API apply.
3. **Verify the denial binding** for every item. Because the service runs inside the PDP and the PDP always signs, the `binding_token` path is the only one accepted:
   - verify the signature against the PDP's own key, and check `aud`, `exp` and `jti` replay (the `ars_jti` table);
   - compare the inline subject, resource, action and authorization-relevant context with the submission, using structural comparison with `subject.properties.act` excluded;
   - enforce the freshness deadline: the earlier of `exp` and `denial.expires_at`, with clock-skew tolerance.

   Errors: `not_requestable` (no `denial`), `invalid_denial_binding`, `expired_denial`.
4. **Check idempotency.** Look up the `Idempotency-Key` for this requester:
   - same key with the same body hash returns the original task;
   - same key with a different body returns `409 duplicate_request`.
5. **Authorize** with `ars_caller`, operation `submit` (§7).
6. **Plan the workflow** with `ars_workflow` (§6): the approval steps, the candidate approvers, and an optional automatic decision.
7. **Persist** the task, its items, the idempotency key and a `submitted` event in one transaction, and return the task handle.

Task handle fields:
- `id`: `arq_` followed by a UUIDv7; 128 bits of entropy; carries no meaning a PEP should parse.
- `status_endpoint`, `expires_at`, `progress` (`current_step`, `total_steps`, `step_name`, `awaiting`).
- `links.cancel`; `links.ticket` and `links.review` only when `service.links.ticket` / `service.links.review` URL templates are configured (`{id}` is replaced by the task id). These point into whatever UI the deployment runs; the plugin does not know it.
- `display`, taken from the workflow rule.

`awaiting` is populated only when the workflow rule marks the approvers as disclosable, per the profile's privacy guidance.

**Result on approval:**

```json
{"mode": "reevaluate",
 "approval": {"id": "apr_…", "approved_at": "…", "approved_until": "…", "state": "<JWS, §8>"}}
```

For a bulk task, each item carries its own `result`. The aggregate status follows the Bulk Profile, including `partial`.

## 6. Workflow and the Rego contract

The service runs one fixed model:
- **Ordered steps, each with a quorum.** A step needs `required` approvals from its candidate set. Any denial in a step denies the task.
- **Bulk tasks decide each item on its own.** Every item follows its own path through the same steps.
- **Routing is computed once, at submission.** Which steps exist and who may act on them is fixed when the task is created.

`ars_workflow` is evaluated with:

```json
{"operation": "plan",
 "caller":  {"iss": "…", "sub": "…", "client_id": "…", "claims": {…}},
 "submission": {"subject": {…}, "items": [{"resource": {…}, "action": {…}, "requested_access": {…}}],
                "context": {…}, "requested_access": {…}, "client": {…}, "denial": {"template": "…", "reason": "…"}}}
```

It returns:

```json
{"steps": [{"name": "manager_approval", "required": 1,
            "approvers": [{"type": "user", "id": "manager@example.com"}],
            "disclose_approvers": false}],
 "approved_until": "2026-11-12T00:00:00Z",
 "auto": "approve",
 "display": {"title": "…", "description": "…"}}
```

Rules for the result:
- `auto` is optional: `"approve"` or `"deny"` completes the task synchronously with `201`. For a bulk task it may instead be an array matching the items (§17.2).
- `approved_until` is capped at `max_approval_ttl`. When absent, it defaults to the requester's `requested_access.requested_until`, capped the same way.
- An undefined or malformed result is a 500. The task is not created; the service fails closed.

Approvers are expressed as AuthZEN-style entities. The approver API compares an authenticated approver's `{type: "user", id: <sub>, properties: {iss: <iss>}}` against them (§9). Groups resolve either in Rego (expanded at plan time) or at decision time through `ars_approver`, at the policy author's choice.

## 7. Authorization rules

The profile requires every task operation to be authorized independently: submitting, viewing status, cancelling, viewing approver details and deciding. Each check is one Rego query:

| Rule | Operations | Input |
|---|---|---|
| `ars_caller` | `submit`, `view`, `cancel` | `operation`, `caller`, `task` (absent for `submit`), `submission` (for `submit`) |
| `ars_approver` | `list`, `view`, `decide`, `revoke` | `operation`, `approver`, `task`, `step`, `decision` (for `decide`) |

Both must return `true` to allow. Anything else denies with `403`, or with `404 unknown_task` when the caller may not learn the task exists.

**Approver eligibility** — self-approval, separation of duties, delegation and conflict of interest — is the `decide` case of `ars_approver`. It runs in the same transaction that records the decision (§10), so an approver's eligibility is checked against the task as it stands.

**Actor chains (Actor Profile).** The service verifies `client.actor` against the caller's token `act` claims. Only a verified chain reaches the rules, as `submission.client.actor_verified: true`; a chain that does not verify is rejected (§17.4).

## 8. Approval verification at re-evaluation

When the service is enabled, `context.approval` is resolved by `approval.id` in Postgres, not by signature:
1. Load the approval row and check that it is approved, not revoked, and that `approved_until` hasn't passed (with clock-skew tolerance).
2. Compare its bound subject, resource, action and authorization-relevant context with the request (exact-match scope).
3. Replace `context.approval` with the same `{"verified": …}` object that `spec-gaps` produces, so policies are unchanged.

The lookup is the only database access on the evaluation path, and only for requests carrying `context.approval`.

`approval_cache_ttl` can trade revocation latency for fewer queries, as a per-replica LRU cache. The default of 0 checks the current status on every re-evaluation, which is what the profile asks for.

If the database is unreachable during a lookup, the evaluation fails with 500 and does not report `approval_unverifiable`. Fail-closed is preserved, and the PEP can tell an outage apart from a bad approval.

`approval.state` is still issued, signed with the PDP key and `aud: base_url`. Another PDP that trusts this one (via `approval_issuers`) can then verify approvals without database access, and the signed path from `spec-gaps` keeps working.

**Revocation:** `POST /access/v1/admin/approvals/{id}/revoke` sets `revoked_at`. The next re-evaluation sees `verified: false, reason: approval_expired`.

## 9. Authentication

Both APIs accept OAuth 2.0 bearer tokens (RFC 6750) validated by `internal/authn`:
- the signature is checked against the issuer's JWKS, cached and refreshed on an unknown `kid`;
- `iss`, `aud`, `exp` and `nbf` are checked;
- the algorithm is pinned to the JWKS key's `alg`.

Tokens carrying `cnf` with DPoP or mTLS binding are rejected in phase 1, not silently accepted. Support is phase 3.

Callers and approvers are identified by the (`iss`, `sub`) pair, which OpenID Connect Core §2 makes stable and never reassigned within an issuer; no claim mapping is configurable. `client_id` is recorded alongside when present. Delegation is read from the RFC 8693 `act` claim, not from a configured on-behalf-of claim. This identity scopes idempotency keys, is matched against workflow approvers, and appears in audit records.

mTLS caller authentication is left to the ingress or mesh, which forwards a verified identity header. Header-based identity is off by default and must be enabled per header name.

## 10. Data model (Postgres)

All tables live in a configurable schema (default `authzen_ars`). JSON values are `jsonb`, stored in the same normalized form used for structural comparison.

```sql
tasks (
  id text primary key,                 -- arq_<uuidv7>
  status text not null,                -- pending|approved|denied|expired|cancelled|failed|partial
  version int not null default 0,      -- optimistic concurrency
  requester_iss text, requester_sub text, requester_client text,
  subject jsonb not null, context jsonb, requested_access jsonb, client jsonb,
  denial jsonb not null,               -- verified denial claims, binding token dropped after verification
  template text, evaluation_id text,
  workflow jsonb not null,             -- the ars_workflow plan
  current_step int not null default 0,
  display jsonb, callback jsonb,       -- callback: 0002
  bulk boolean not null default false, -- 0002: the submission carried `items`
  expires_at timestamptz not null, created_at timestamptz not null, completed_at timestamptz
)
task_items (
  task_id text references tasks, idx int, primary key (task_id, idx),
  resource jsonb not null, action jsonb not null, requested_access jsonb,
  status text not null, current_step int not null default 0, approval_id text,  -- current_step: 0002
  denial jsonb                         -- 0002: per-item verified denial (evaluation id, members, bound context, expiry)
)
approvals (
  id text primary key,                 -- apr_<uuidv7>
  task_id text not null, item_idx int not null,
  subject jsonb not null,              -- act removed
  resource jsonb not null, action jsonb not null,
  binding_context_members text[] not null, context jsonb not null,
  approved_at timestamptz not null, approved_until timestamptz not null,
  revoked_at timestamptz, revoked_by text, revoke_reason text
)
decisions (                            -- approvals cast so far: workflow state for quorum counting
  id bigserial primary key, task_id text, item_idx int, step int,
  approver_iss text, approver_sub text, decision text, comment text, decided_at timestamptz,
  approved_until timestamptz,          -- 0002: the approver's shortened lifetime, if any
  unique (task_id, item_idx, step, approver_iss, approver_sub)   -- one vote per approver per step
)
callback_outbox (                      -- 0002; the body is built from the task at delivery
  id bigserial primary key, task_id text references tasks on delete cascade, event text,
  attempts int default 0, next_attempt_at timestamptz, claimed_until timestamptz,
  delivered_at timestamptz, failed_at timestamptz, last_error text, created_at timestamptz
)
idempotency_keys (
  requester text, key text, body_hash bytea, task_id text, retain_until timestamptz,
  primary key (requester, key)
)
seen_jti (jti text primary key, expires_at timestamptz)
schema_migrations (version int primary key, applied_at timestamptz)
```

Indexes: `tasks(status, expires_at)` for the sweeper; `task_items(task_id)`; `approvals(task_id)`; `decisions(task_id)`; `callback_outbox(next_attempt_at) where delivered_at is null and failed_at is null`; `seen_jti(expires_at)`; `idempotency_keys(retain_until)`.

Migration `0001` (phase 1) creates every table except `callback_outbox`. Migration `0002` (phase 2) adds `tasks.bulk`, `tasks.callback`, `task_items.current_step`, `task_items.denial`, `decisions.approved_until` and the `callback_outbox` table.

## 11. Multiple replicas

| Concern | Mechanism |
|---|---|
| Duplicate submissions racing on two replicas | `idempotency_keys` primary key; the loser of the insert reads the winner's task |
| Two approvers deciding at once | Decision recorded in a transaction that locks the item row (`SELECT … FOR UPDATE`), re-runs `ars_approver` `decide`, then advances the step; a terminal item rejects further decisions with `409 invalid_task_state` |
| Exactly-once terminal transition | `UPDATE … SET status = $new WHERE id = $id AND status = 'pending'`; zero rows affected means another replica won |
| Expiry | Every replica runs the sweeper; it claims batches with `FOR UPDATE SKIP LOCKED`, marks them `expired`, and emits audit records. Idempotent, needs no leader |
| Callback delivery | Terminal transitions insert into `callback_outbox` in the same transaction; delivery workers claim rows with `SKIP LOCKED`, sign and POST, back off exponentially up to `max_attempts`, then mark failed |
| `binding_token` replay | `seen_jti` insert; a conflict means replay |
| Schema migrations | Embedded SQL files applied at startup under `pg_advisory_lock`, so concurrent replica starts serialize |
| Signing keys | Same key files on every replica (Kubernetes Secret), so any replica verifies what another signed |
| Clock | Database `now()` for all stored timestamps; replica clocks used only for skew-tolerant comparisons |

No replica holds state another needs. A replica can be killed at any point: an unfinished transaction rolls back, and a claimed-but-undelivered callback becomes claimable again once its claim lapses.

## 12. Approver API (extension, not part of ARAP)

The approver API is served under `/access/v1/admin/`. The README will mark it as a plugin extension, not part of AuthZEN. Every call authenticates against `approver_auth` and is authorized by `ars_approver`.

| Method and path | Purpose |
|---|---|
| `GET /access/v1/admin/tasks?status=pending&assigned=me&cursor=…` | Tasks whose current step lists the approver as a candidate (or that `ars_approver` `list` allows); cursor pagination |
| `GET /access/v1/admin/tasks/{id}` | Full task: submission, items, steps, decisions so far |
| `POST /access/v1/admin/tasks/{id}/decisions` | `{"decision": "approve"\|"deny", "items": [0, 2], "comment": "…", "approved_until": "…"}`. `items` defaults to all pending items; `approved_until` may only shorten the planned lifetime |
| `POST /access/v1/admin/approvals/{id}/revoke` | `{"reason": "…"}` |

Task history for the UI comes from the decisions included in `GET /access/v1/admin/tasks/{id}`; the full audit trail lives in the OpenTelemetry backend (§13).

The UI is any client that obtains a user token from the configured issuer and calls these endpoints. Nothing in the plugin knows which UI it is.

## 13. Retention, audit and observability

- **Audit:** the profile requires enough records to reconstruct a request, its approval, the denial and the completion. Each of submission, each approver decision, every terminal transition, cancellation, revocation and callback delivery outcome is emitted as an OpenTelemetry log record (event name `authzen.access_request.<event>`), carrying the task id, approval id, evaluation id, actor (`iss`, `sub`), and the bound subject, resource and action. Retention and access control of those records are the OpenTelemetry backend's responsibility; the database keeps no audit history of its own. Records are emitted after the transaction commits, so a rolled-back change is never reported.
- **Retention in the database:** operational only. Terminal tasks stay readable until `expires_at` plus `idempotency_retention`. After that, the status endpoint returns `410 task_expired`, and a purge worker deletes the task, item, decision and idempotency rows. Approval rows are kept until `approved_until` passes, and then purged, because re-evaluation needs them until then. Approvals are deleted with their task, so a task is not purged while any of its approvals is still within `approved_until` (§17.5).
- **Traces:** each API request is a span; evaluations that use an approval add the approval id as a span attribute, alongside the decision id OPA already sets. Evaluations also still reach OPA's decision log with the verified approval in `input`.
- **Metrics (phase 3):** submissions, decisions, transitions by status, sweeper and callback lag, and database errors, through OpenTelemetry metrics. Most counts can be derived from the audit records meanwhile; only backlogs (pending tasks, undelivered callbacks) cannot.

## 14. Security notes

- **Credentials and secrets:** the DSN and the callback HMAC secret come only from the environment, so config files can be committed.
- **Callback destinations:** endpoints must be `https`, match a configured destination host, and resolve to a non-internal address unless that destination sets `allow_internal`. The address is checked again at delivery time, on the IP actually dialled, to defeat DNS rebinding.
- **Callback authentication:** requests carry `X-AuthZEN-Signature: t=<ts>,v1=<hex HMAC-SHA256(ts.body)>`, keyed per destination, so one PEP cannot forge callbacks to another. Callbacks are notifications only; they never carry `approval.state`, so a leaked callback cannot be replayed into an evaluation.
- **Information disclosure:** status responses never include approver identities, policy identifiers or the `binding_token`; `progress.awaiting` appears only when the workflow allows it. Unknown and unauthorized tasks return the same `404`.
- **Rate limits:** per-caller limits on submission and polling, configurable, enforced per replica.

## 15. Testing

- Unit tests against the in-memory store for every endpoint, state transition and problem type.
- Postgres integration tests (testcontainers, or `AUTHZEN_ARS_TEST_DSN`) covering:
  - concurrency races: duplicate idempotent submits, simultaneous decisions, sweeper against decision;
  - migrations under concurrent startup.
- End-to-end scenario in `interop/`: requestable denial, submission, approval through the admin API, re-evaluation permit, revocation, re-evaluation denied with `next_action: request`.

## 16. Phasing

| Phase | Scope |
|---|---|
| 1 | Config and migrations; single-item submit, status and cancel; `ars_caller`, `ars_workflow` (single step plus `auto`), `ars_approver`; approver API (list, view, decide, revoke); approval lookup at re-evaluation; expiry sweeper; idempotency; OpenTelemetry audit records |
| 2 | Multi-step quorum; Bulk Profile (`items`, `partial`); Callback Profile with outbox; Actor Profile verification; retention purge (§17) |
| 3 | DPoP/mTLS-bound tokens; approval cache; `approval.state` consumption by peer PDPs documented end to end; OpenTelemetry metrics |

Each phase ships as its own pull request with tests.

## 17. Phase 2 design

### 17.1 Multi-step approvals

`parsePlan` stops rejecting workflows with more than one step. The steps run in order; the plan is still fixed at submission.

- Each item moves through the steps on its own; a single-item task is the case with one item.
- **Approve:** count the approve votes for this item at its current step. Once the count reaches `required`:
  - on the last step, the item is `approved` and its approval row is created;
  - otherwise the item's `current_step` moves to the next step.
- **Deny:** any deny at any step makes the item `denied` immediately.
- **`approved_until`:** each approver may send one, and it can only shorten the planned lifetime. The approval uses the smallest value across all steps, so it is stored per decision.
- **Eligibility:** `ars_approver` `decide` runs inside the locked transaction, as in phase 1. Its input includes `task.decisions` (item, step, approver), so separation-of-duties rules are written in Rego:
  ```rego
  ars_approver if {
    input.operation == "decide"
    not approved_earlier_step
  }
  approved_earlier_step if {
    some d in input.task.decisions
    d.approver.sub == input.approver.id
    d.step < input.step.index
  }
  ```
- A vote already cast still counts if the voter's eligibility later changes.
- **`parsePlan` checks:** unique step names; at most `max_steps` steps; each step lists at least `required` approvers.
- **`progress`:** `current_step`, `step_name` and `awaiting` come from the earliest step of any pending item. `awaiting` stays gated by `disclose_approvers` and matches decisions by item, `iss` and `sub`.
- **Audit:** a `step_completed` record when an item moves to its next step.

### 17.2 Bulk requests (Bulk Profile)

**Submission.**
- When `items` is present, top-level `resource` and `action` must be absent. Each item has `resource` and `action` (required) and optionally `requested_access` and `denial`.
- An item's `requested_access` is merged over the top-level one, item values taking precedence.
- At most `max_items` items; more is `400`.

**Denial binding: per-item only.** The PDP signs one `binding_token` per evaluation, and a batch evaluation yields one token per item, so this PDP never issues a bundle denial (one top-level `denial` whose binding covers every item, in order).
- Each item's `denial` is verified with the single-item rules (§5): the shared subject and context, plus that item's resource and action.
- An item without its own `denial` falls back to the top-level `denial`, whose token covers one resource and action only; verification fails with `invalid_denial_binding`.
- The bulk `binding_hash` construction is not implemented.
- **Freshness:** each item's denial is checked; any stale one fails the submission with `expired_denial`.
- **Replay:** every token's `jti` is recorded. A seen `jti`, or one token on two items, rejects the whole submission.
- **Context per item:** each item's `binding_context_members` and bound context are stored with the item (`task_items.denial`), because its approval is scoped to them.

**Workflow.** `ars_workflow` already receives `submission.items` as an array. `auto` may be a string, applying to every item, or an array matching the items, each element `"approve"`, `"deny"` or `null` (left to the approvers). Items auto-decided this way complete at submission.

**Status and aggregation.**
- `tasks.bulk` records whether the submission carried `items`; a one-element `items` array still gets `items` in the response.
- Each item is rendered as `items[]: {resource, action, status, result}`; every approved item carries its own `result`.
- The top-level `result` is omitted for bulk tasks, so a PEP cannot mistake it for approval of every item.
- **Aggregate status:** `pending` while any item is pending; the shared status when all items end the same way; otherwise `partial`, a new terminal status.
- **Recomputation** after every change to an item:
  - **Cancel:** pending items become `cancelled`. The task is `cancelled` if no item had completed, otherwise `partial`. If every item had already completed, `409 invalid_task_state`.
  - **Expiry sweeper:** `ExpireDue` expires the pending items, then recomputes the task's status, so a bulk task with items completed first becomes `partial` rather than `expired`.
  - **Decisions:** after each decision.

**Approver decisions.**
- `POST …/decisions` accepts `items: [0, 2]`. Without it, the decision covers every pending item for which this approver is a candidate at that item's current step.
- `ars_approver` `decide` is evaluated once per item.
- A decision request is all or nothing: if the rule rejects any item, or the approver already voted on one at its step, the whole request is `403` or `409`.

**Other.**
- **Re-evaluation:** each approved item is re-evaluated separately with its own approval, as in phase 1.
- **Approver API:** the task view replaces `item` with `items`, and `request.resource`/`action` with per-item entries.
- **Audit records** carry an `items` list (`idx`, `resource`, `action`, `status`, `approval_id`) instead of the first item only.

### 17.3 Callbacks (Callback Profile)

**At submission**, `callback: {endpoint, state, events}` is checked:
- `endpoint` must be `https`, its host must be a configured destination, and it must not resolve to a loopback, link-local, private or other internal address unless the destination sets `allow_internal`.
- `events` must come from `approved`, `denied`, `expired`, `cancelled`, `failed`, `partial`; absent means every terminal event.
- `state` must be a string of at most 1 KiB.
- `callback.endpoint` is passed to `ars_caller` `submit`, so Rego can restrict which caller may use which endpoint (the profile's "authorized for the authenticated PEP").
- A callback that fails these checks, including when `callbacks` is not configured, is rejected with `400`, so a PEP never waits for a callback that will not come. This replaces phase 1's ignore-with-warning.

**Delivery.**
- When a task with a callback reaches a terminal status in a requested event, the store inserts a `callback_outbox` row in the same transaction, on every path: submission with `auto`, decisions, cancellation and the sweeper. The row holds only the task id and event; the body is built from the task at delivery, since a terminal task no longer changes.
- Delivery workers run on every replica. They claim due rows with `FOR UPDATE SKIP LOCKED` and a lease (`claimed_until`), and POST outside the transaction. A row whose sender died becomes claimable when its lease lapses.
- **Body:** `{"state": …, "task": {id, status, status_endpoint, items?: [{status}]}}`. No `result` and no `approval.state`: the callback is a notification and the PEP reads the Task Status Endpoint.
- **Headers:** `X-AuthZEN-Signature: t=<unix>,v1=<hex HMAC-SHA256(t + "." + body)>` with the destination's key from the environment; `X-AuthZEN-Delivery: <outbox id>`, because delivery is at least once and the PEP should drop duplicates. Both header names are this plugin's convention; the profile does not define them.
- **SSRF and DNS rebinding:** the address is checked again at connection time on the IP actually dialled (`net.Dialer.Control`). Redirects are not followed; the response body is size-limited and discarded.
- **Retries:** any 2xx is success. Otherwise retry with exponential backoff and jitter (5 s doubling, capped at 1 h). After `max_attempts` the row is marked failed and a `callback_failed` audit record is emitted.

### 17.4 Actor verification (Actor Profile)

- `client.actor` is verified against the `act` claim of the caller's access token (RFC 8693 token exchange). Signed assertions from other trusted issuers are not supported.
- The chains are compared level by level as (`iss`, `sub`) pairs: `client.actor.issuer`/`client.actor.id` against `act.iss`/`act.sub`, then `client.actor.act` against `act.act`, and so on.
- **Exact match:** every claimed link must match and the chains must be the same length. A missing `issuer` is unverifiable.
- A chain that does not verify is rejected with `403`, as the profile's MUST requires. ARAP defines no problem type for it.
- An actor carried in `subject.properties.act` is verified the same way; when both carriers are present they must agree.
- Only a verified chain reaches `ars_caller` and `ars_workflow`, as `submission.client.actor` with `actor_verified: true`, so approvals can be routed by actor.
- `client.source` cannot be verified. It stays out of the rules and is stored for the approver API and audit records.
- Whether the token's `sub` must equal `subject.id` is left to `ars_caller`; the profile leaves it open.

### 17.5 Retention purge

A purge worker runs on every replica, in batches claimed with `SKIP LOCKED`, like the expiry sweeper:
- terminal tasks, with their items, decisions and callback rows, after `expires_at + idempotency_retention`, but not while any approval of the task is still within `approved_until`;
- idempotency keys after `retain_until`;
- `seen_jti` rows after `expires_at`;
- approval rows with their task, so after both the task's retention and the approval's `approved_until` (plus clock skew). An approval is not deleted on its own, because the task's status response renders it.

Revoked approvals are kept until `approved_until` too: their signed `approval.state` stays valid until then, so the row must remain for re-evaluation to report the revocation.

### 17.6 Store changes

- `NewTask.JTI` becomes a list.
- `Change` gains `ItemStep`.
- New `ClaimCallbacks`, `MarkDelivered`, `RetryCallback`, `FailCallback` and `Purge`.
- `ExpireDue` recomputes the aggregate and returns the expired tasks, so the sweeper audits each with its resulting status.
- `ListPending` matches pending items whose current step lists the approver.

## 18. Decisions recorded

- **Single tenant.** Tasks carry no tenant key; multi-tenancy is not a requirement.
- **Audit via OpenTelemetry.** Audit records are OpenTelemetry log records; their retention is enforced by the OpenTelemetry backend, not the plugin (§13).
- **Postgres via pgx v5.** Plain PostgreSQL only; no compatibility layer for other stores.
- **Identity is (`iss`, `sub`).** Per OpenID Connect Core §2, with delegation from the RFC 8693 `act` claim; no configurable identity claim (§9).
- **UI links are optional URL templates** in config (§5); unset templates omit the links.
- **Per-item denials only** for bulk requests; this PDP never issues bundle denials (§17.2).
- **A callback that is not allowed is rejected** with `400`, not ignored (§17.3).
- **`auto` may be per item** for bulk tasks (§17.2).
- **Actor chains must match exactly** (§17.4).
- **Retention purge is phase 2; metrics move to phase 3** (§16, §17.5).

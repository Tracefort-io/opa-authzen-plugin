# Design: Access Request Service in the plugin

Status: phase 1 implemented (branch `ars-phase1`); phases 2 and 3 open

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
        approval_cache_ttl: 0s            # re-evaluation lookup cache; 0 disables (§8)
        links:                            # optional; omitted from task.links when unset
          ticket: "https://ui.example.com/requests/{id}"
          review: "https://ui.example.com/review/{id}"
        callbacks:
          allowed_hosts: ["agents.example.com"]
          timeout: 5s
          max_attempts: 8
          hmac_secret_env: AUTHZEN_ARS_CALLBACK_SECRET
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
- `auto` is optional: `"approve"` or `"deny"` completes the task synchronously with `201`.
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

**Actor chains (Actor Profile).** The service verifies `client.actor` against the caller's token `act` claims. Only a verified chain reaches the rules, as `submission.client.actor_verified: true`; an unverified one is kept for audit only, as the base profile requires.

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
  display jsonb, callback jsonb,
  expires_at timestamptz not null, created_at timestamptz not null, completed_at timestamptz
)
task_items (
  task_id text references tasks, idx int, primary key (task_id, idx),
  resource jsonb not null, action jsonb not null, requested_access jsonb,
  status text not null, current_step int not null default 0, approval_id text
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
  unique (task_id, item_idx, step, approver_iss, approver_sub)   -- one vote per approver per step
)
callback_outbox (
  id bigserial primary key, task_id text, event text, endpoint text, state text,
  payload jsonb, attempts int default 0, next_attempt_at timestamptz,
  delivered_at timestamptz, last_error text
)
idempotency_keys (
  requester text, key text, body_hash bytea, task_id text, retain_until timestamptz,
  primary key (requester, key)
)
seen_jti (jti text primary key, expires_at timestamptz)
schema_migrations (version int primary key, applied_at timestamptz)
```

Indexes: `tasks(status, expires_at)` for the sweeper; `task_items(task_id)`; `approvals(task_id)`; `decisions(task_id)`; `callback_outbox(next_attempt_at) where delivered_at is null`; `seen_jti(expires_at)`; `idempotency_keys(retain_until)`.

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
- **Retention in the database:** operational only. Terminal tasks stay readable until `expires_at` plus `idempotency_retention`. After that, the status endpoint returns `410 task_expired`, and a purge worker deletes the task, item, decision and idempotency rows. Approval rows are kept until `approved_until` passes, and then purged, because re-evaluation needs them until then.
- **Traces:** each API request is a span; evaluations that use an approval add the approval id as a span attribute, alongside the decision id OPA already sets. Evaluations also still reach OPA's decision log with the verified approval in `input`.
- **Metrics:** submissions, decisions, transitions by status, sweeper and callback lag, and database errors, through OpenTelemetry metrics.

## 14. Security notes

- **Credentials and secrets:** the DSN and the callback HMAC secret come only from the environment, so config files can be committed.
- **Callback destinations:** endpoints must be `https`, match `allowed_hosts`, and resolve to a non-internal address unless that host is allowlisted. The address is resolved again at delivery time to defeat DNS rebinding.
- **Callback authentication:** requests carry `X-AuthZEN-Signature: t=<ts>,v1=<hex HMAC-SHA256(ts.body)>`. Callbacks are notifications only; they never carry `approval.state`, so a leaked callback cannot be replayed into an evaluation.
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
| 2 | Multi-step quorum; Bulk Profile (`items`, `partial`); Callback Profile with outbox; Actor Profile verification; retention purge; metrics |
| 3 | DPoP/mTLS-bound tokens; approval cache; `approval.state` consumption by peer PDPs documented end to end |

Each phase ships as its own pull request with tests.

## 17. Decisions recorded

- **Single tenant.** Tasks carry no tenant key; multi-tenancy is not a requirement.
- **Audit via OpenTelemetry.** Audit records are OpenTelemetry log records; their retention is enforced by the OpenTelemetry backend, not the plugin (§13).
- **Postgres via pgx v5.** Plain PostgreSQL only; no compatibility layer for other stores.
- **Identity is (`iss`, `sub`).** Per OpenID Connect Core §2, with delegation from the RFC 8693 `act` claim; no configurable identity claim (§9).
- **UI links are optional URL templates** in config (§5); unset templates omit the links.

-- Access Request Service schema, version 1. Applied inside the configured
-- schema (search_path) by the migration runner, under an advisory lock.

CREATE TABLE tasks (
    id               text PRIMARY KEY,
    status           text        NOT NULL,
    version          integer     NOT NULL DEFAULT 0,
    requester_iss    text        NOT NULL,
    requester_sub    text        NOT NULL,
    requester_client text        NOT NULL DEFAULT '',
    subject          jsonb       NOT NULL,
    context          jsonb,
    requested_access jsonb,
    client           jsonb,
    denial           jsonb       NOT NULL,
    template         text        NOT NULL DEFAULT '',
    evaluation_id    text        NOT NULL DEFAULT '',
    workflow         jsonb       NOT NULL,
    current_step     integer     NOT NULL DEFAULT 0,
    display          jsonb,
    expires_at       timestamptz NOT NULL,
    created_at       timestamptz NOT NULL,
    completed_at     timestamptz
);
CREATE INDEX tasks_status_expires ON tasks (status, expires_at);

CREATE TABLE task_items (
    task_id          text    NOT NULL REFERENCES tasks (id) ON DELETE CASCADE,
    idx              integer NOT NULL,
    resource         jsonb   NOT NULL,
    action           jsonb   NOT NULL,
    requested_access jsonb,
    status           text    NOT NULL,
    approval_id      text    NOT NULL DEFAULT '',
    PRIMARY KEY (task_id, idx)
);

CREATE TABLE approvals (
    id                      text        PRIMARY KEY,
    task_id                 text        NOT NULL REFERENCES tasks (id) ON DELETE CASCADE,
    item_idx                integer     NOT NULL,
    subject                 jsonb       NOT NULL,
    resource                jsonb       NOT NULL,
    action                  jsonb       NOT NULL,
    binding_context_members text[]      NOT NULL,
    context                 jsonb       NOT NULL,
    approved_at             timestamptz NOT NULL,
    approved_until          timestamptz NOT NULL,
    revoked_at              timestamptz,
    revoked_by              text        NOT NULL DEFAULT '',
    revoke_reason           text        NOT NULL DEFAULT ''
);
CREATE INDEX approvals_task ON approvals (task_id);

-- Approvals cast so far: workflow state for quorum counting.
CREATE TABLE decisions (
    id           bigserial   PRIMARY KEY,
    task_id      text        NOT NULL REFERENCES tasks (id) ON DELETE CASCADE,
    item_idx     integer     NOT NULL,
    step         integer     NOT NULL,
    approver_iss text        NOT NULL,
    approver_sub text        NOT NULL,
    decision     text        NOT NULL,
    comment      text        NOT NULL DEFAULT '',
    decided_at   timestamptz NOT NULL,
    UNIQUE (task_id, item_idx, step, approver_iss, approver_sub)
);
CREATE INDEX decisions_task ON decisions (task_id);

CREATE TABLE idempotency_keys (
    requester    text        NOT NULL,
    key          text        NOT NULL,
    body_hash    bytea       NOT NULL,
    task_id      text        NOT NULL,
    retain_until timestamptz NOT NULL,
    PRIMARY KEY (requester, key)
);
CREATE INDEX idempotency_keys_retain ON idempotency_keys (retain_until);

CREATE TABLE seen_jti (
    jti        text        PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
CREATE INDEX seen_jti_expires ON seen_jti (expires_at);

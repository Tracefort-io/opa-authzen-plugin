-- Access Request Service schema, version 2: multi-step and bulk tasks,
-- per-approver approval lifetimes, and the callback outbox.

ALTER TABLE tasks ADD COLUMN bulk boolean NOT NULL DEFAULT false;
ALTER TABLE tasks ADD COLUMN callback jsonb;

ALTER TABLE task_items ADD COLUMN current_step integer NOT NULL DEFAULT 0;
ALTER TABLE task_items ADD COLUMN denial jsonb;

ALTER TABLE decisions ADD COLUMN approved_until timestamptz;

-- Callback notifications, inserted in the transaction that makes a task
-- terminal. The body is built from the task at delivery.
CREATE TABLE callback_outbox (
    id              bigserial   PRIMARY KEY,
    task_id         text        NOT NULL REFERENCES tasks (id) ON DELETE CASCADE,
    event           text        NOT NULL,
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    claimed_until   timestamptz,
    delivered_at    timestamptz,
    failed_at       timestamptz,
    last_error      text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL
);
CREATE INDEX callback_outbox_due ON callback_outbox (next_attempt_at)
    WHERE delivered_at IS NULL AND failed_at IS NULL;

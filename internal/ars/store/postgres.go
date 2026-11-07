package store

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// migrationLockKey is the advisory lock that serializes schema migrations
// when several replicas start at once.
const migrationLockKey = 0x617574687a656e // "authzen"

var schemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Postgres is the shared Store used in production.
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres connects to dsn with every connection's search_path set to
// schema, then applies pending migrations.
func OpenPostgres(ctx context.Context, dsn, schema string, maxConns int32) (*Postgres, error) {
	if !schemaName.MatchString(schema) {
		return nil, fmt.Errorf("schema %q is not a valid identifier", schema)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing DSN: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting: %w", err)
	}
	p := &Postgres{pool: pool}
	if err := p.migrate(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrating: %w", err)
	}
	return p, nil
}

// migrate applies the embedded migrations not yet recorded, one transaction
// each, holding a session advisory lock so concurrent starts serialize.
func (p *Postgres) migrate(ctx context.Context, schema string) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockKey) }()

	if _, err := conn.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		base := strings.TrimPrefix(f, "migrations/")
		version, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: bad version prefix", base)
		}
		var applied bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrations.ReadFile(f)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", base, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Close implements Store.
func (p *Postgres) Close() { p.pool.Close() }

// jsonArg renders a JSON value as a text parameter for a `::jsonb` cast, or
// SQL NULL for a nil map.
func jsonArg(v any) any {
	if m, ok := v.(map[string]any); ok && m == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return string(b)
}

func decodeMap(b []byte) (map[string]any, error) {
	if b == nil {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateTask implements Store.
func (p *Postgres) CreateTask(ctx context.Context, n *NewTask, now time.Time) (*Task, bool, error) {
	// Two replicas inserting the same idempotency key race on the primary
	// key; the loser retries once and then finds the winner's row.
	for attempt := 0; ; attempt++ {
		task, existed, err := p.createTaskOnce(ctx, n, now)
		if err == nil || attempt > 0 || !errors.Is(err, errIdempotencyRace) {
			return task, existed, err
		}
	}
}

var errIdempotencyRace = errors.New("idempotency key inserted concurrently")

func (p *Postgres) createTaskOnce(ctx context.Context, n *NewTask, now time.Time) (*Task, bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if n.Idempotency.Key != "" {
		var hash []byte
		var taskID string
		var retain time.Time
		err := tx.QueryRow(ctx, `SELECT body_hash, task_id, retain_until FROM idempotency_keys
			WHERE requester = $1 AND key = $2 FOR UPDATE`, n.Idempotency.Requester, n.Idempotency.Key).Scan(&hash, &taskID, &retain)
		switch {
		case err == nil && retain.After(now):
			if !bytes.Equal(hash, n.Idempotency.BodyHash) {
				return nil, false, ErrDuplicateRequest
			}
			if err := tx.Commit(ctx); err != nil {
				return nil, false, err
			}
			t, err := p.GetTask(ctx, taskID)
			return t, true, err
		case err == nil:
			// Retention lapsed: the key may be reused for a new submission.
			if _, err := tx.Exec(ctx, "DELETE FROM idempotency_keys WHERE requester = $1 AND key = $2", n.Idempotency.Requester, n.Idempotency.Key); err != nil {
				return nil, false, err
			}
		case !errors.Is(err, pgx.ErrNoRows):
			return nil, false, err
		}
	}

	// A token seen before, or twice in this submission, is a replay.
	for _, j := range n.JTIs {
		tag, err := tx.Exec(ctx, "INSERT INTO seen_jti (jti, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING", j.ID, j.Expires)
		if err != nil {
			return nil, false, err
		}
		if tag.RowsAffected() == 0 {
			return nil, false, ErrReplay
		}
	}

	t := n.Task
	if _, err := tx.Exec(ctx, `INSERT INTO tasks (id, status, version, requester_iss, requester_sub, requester_client,
			subject, context, requested_access, client, denial, template, evaluation_id, workflow, current_step,
			display, bulk, callback, expires_at, created_at, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12, $13, $14::jsonb,
			$15, $16::jsonb, $17, $18::jsonb, $19, $20, $21)`,
		t.ID, t.Status, t.Version, t.RequesterIss, t.RequesterSub, t.RequesterClient,
		jsonArg(t.Subject), jsonArg(t.Context), jsonArg(t.RequestedAccess), jsonArg(t.Client), jsonArg(t.Denial),
		t.Template, t.EvaluationID, jsonArg(t.Workflow), t.CurrentStep, jsonArg(t.Display),
		t.Bulk, callbackArg(t.Callback), t.ExpiresAt, t.CreatedAt, t.CompletedAt); err != nil {
		return nil, false, err
	}
	for _, it := range t.Items {
		if _, err := tx.Exec(ctx, `INSERT INTO task_items (task_id, idx, resource, action, requested_access, status, approval_id,
				current_step, denial)
			VALUES ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6, $7, $8, $9::jsonb)`,
			t.ID, it.Index, jsonArg(it.Resource), jsonArg(it.Action), jsonArg(it.RequestedAccess), it.Status, it.ApprovalID,
			it.CurrentStep, jsonArg(it.Denial)); err != nil {
			return nil, false, err
		}
	}
	if err := enqueue(ctx, tx, t, now); err != nil {
		return nil, false, err
	}
	for _, a := range n.Approvals {
		if err := insertApproval(ctx, tx, a); err != nil {
			return nil, false, err
		}
	}
	if n.Idempotency.Key != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO idempotency_keys (requester, key, body_hash, task_id, retain_until)
			VALUES ($1, $2, $3, $4, $5)`,
			n.Idempotency.Requester, n.Idempotency.Key, n.Idempotency.BodyHash, t.ID, n.Idempotency.RetainUntil); err != nil {
			if isUniqueViolation(err) {
				return nil, false, errIdempotencyRace
			}
			return nil, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return t, false, nil
}

func insertApproval(ctx context.Context, tx pgx.Tx, a *Approval) error {
	_, err := tx.Exec(ctx, `INSERT INTO approvals (id, task_id, item_idx, subject, resource, action,
			binding_context_members, context, approved_at, approved_until)
		VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7, $8::jsonb, $9, $10)`,
		a.ID, a.TaskID, a.ItemIndex, jsonArg(a.Subject), jsonArg(a.Resource), jsonArg(a.Action),
		a.BindingContextMembers, jsonArg(nonNilMap(a.Context)), a.ApprovedAt, a.ApprovedUntil)
	return err
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func callbackArg(c *Callback) any {
	if c == nil {
		return nil
	}
	return jsonArg(c)
}

// enqueue inserts the callback notification of a task that has just become
// terminal, if its callback asked for that status, in the caller's
// transaction.
func enqueue(ctx context.Context, tx pgx.Tx, t *Task, now time.Time) error {
	if !t.Callback.Wants(t.Status) {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO callback_outbox (task_id, event, next_attempt_at, created_at)
		VALUES ($1, $2, $3, $3)`, t.ID, t.Status, now)
	return err
}

type queryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

const taskColumns = `id, status, version, requester_iss, requester_sub, requester_client, subject, context,
	requested_access, client, denial, template, evaluation_id, workflow, current_step, display,
	bulk, callback, expires_at, created_at, completed_at`

func scanTask(row pgx.Row) (*Task, error) {
	var t Task
	var subject, ctxJSON, requested, client, denial, workflow, display, callback []byte
	if err := row.Scan(&t.ID, &t.Status, &t.Version, &t.RequesterIss, &t.RequesterSub, &t.RequesterClient,
		&subject, &ctxJSON, &requested, &client, &denial, &t.Template, &t.EvaluationID, &workflow,
		&t.CurrentStep, &display, &t.Bulk, &callback, &t.ExpiresAt, &t.CreatedAt, &t.CompletedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	for _, f := range []struct {
		dst *map[string]any
		src []byte
	}{{&t.Subject, subject}, {&t.Context, ctxJSON}, {&t.RequestedAccess, requested}, {&t.Client, client}, {&t.Denial, denial}, {&t.Display, display}} {
		if *f.dst, err = decodeMap(f.src); err != nil {
			return nil, err
		}
	}
	if err := json.Unmarshal(workflow, &t.Workflow); err != nil {
		return nil, err
	}
	if callback != nil {
		t.Callback = &Callback{}
		if err := json.Unmarshal(callback, t.Callback); err != nil {
			return nil, err
		}
	}
	return &t, nil
}

// loadTask reads a task with its items and decisions; lock adds FOR UPDATE.
func loadTask(ctx context.Context, q queryer, id string, lock bool) (*Task, error) {
	sql := "SELECT " + taskColumns + " FROM tasks WHERE id = $1"
	if lock {
		sql += " FOR UPDATE"
	}
	t, err := scanTask(q.QueryRow(ctx, sql, id))
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT idx, resource, action, requested_access, status, approval_id, current_step, denial
		FROM task_items WHERE task_id = $1 ORDER BY idx`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var it Item
		var res, act, req, den []byte
		if err := rows.Scan(&it.Index, &res, &act, &req, &it.Status, &it.ApprovalID, &it.CurrentStep, &den); err != nil {
			rows.Close()
			return nil, err
		}
		if it.Denial, err = decodeMap(den); err != nil {
			rows.Close()
			return nil, err
		}
		if it.Resource, err = decodeMap(res); err != nil {
			rows.Close()
			return nil, err
		}
		if it.Action, err = decodeMap(act); err != nil {
			rows.Close()
			return nil, err
		}
		if it.RequestedAccess, err = decodeMap(req); err != nil {
			rows.Close()
			return nil, err
		}
		t.Items = append(t.Items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT item_idx, step, approver_iss, approver_sub, decision, comment, decided_at, approved_until
		FROM decisions WHERE task_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d Decision
		if err := rows.Scan(&d.ItemIndex, &d.Step, &d.ApproverIss, &d.ApproverSub, &d.Decision, &d.Comment, &d.DecidedAt, &d.ApprovedUntil); err != nil {
			return nil, err
		}
		t.Decisions = append(t.Decisions, d)
	}
	return t, rows.Err()
}

// GetTask implements Store.
func (p *Postgres) GetTask(ctx context.Context, id string) (*Task, error) {
	return loadTask(ctx, p.pool, id, false)
}

// UpdateTask implements Store. The task row is locked for the duration of
// fn, so concurrent decisions on one task serialize across replicas.
func (p *Postgres) UpdateTask(ctx context.Context, id string, fn func(*Task) (*Change, error)) (*Task, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	t, err := loadTask(ctx, tx, id, true)
	if err != nil {
		return nil, err
	}
	ch, err := fn(cloneTask(t))
	if err != nil {
		return nil, err
	}
	if ch == nil {
		return t, tx.Commit(ctx)
	}
	if err := saveChange(ctx, tx, t, ch); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

// saveChange applies ch to t, a task locked in tx, and persists it; a task
// it makes terminal gets its callback notification enqueued.
func saveChange(ctx context.Context, tx pgx.Tx, t *Task, ch *Change) error {
	wasPending := t.Status == StatusPending
	applyChange(t, ch)
	if _, err := tx.Exec(ctx, `UPDATE tasks SET status = $2, current_step = $3, completed_at = $4, version = $5 WHERE id = $1`,
		t.ID, t.Status, t.CurrentStep, t.CompletedAt, t.Version); err != nil {
		return err
	}
	for _, it := range t.Items {
		_, statusChanged := ch.ItemStatus[it.Index]
		_, approvalChanged := ch.ItemApproval[it.Index]
		_, stepChanged := ch.ItemStep[it.Index]
		if !statusChanged && !approvalChanged && !stepChanged {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE task_items SET status = $3, approval_id = $4, current_step = $5 WHERE task_id = $1 AND idx = $2`,
			t.ID, it.Index, it.Status, it.ApprovalID, it.CurrentStep); err != nil {
			return err
		}
	}
	for _, d := range ch.NewDecisions {
		if _, err := tx.Exec(ctx, `INSERT INTO decisions (task_id, item_idx, step, approver_iss, approver_sub, decision, comment,
				decided_at, approved_until)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			t.ID, d.ItemIndex, d.Step, d.ApproverIss, d.ApproverSub, d.Decision, d.Comment, d.DecidedAt, d.ApprovedUntil); err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
	}
	for _, a := range ch.NewApprovals {
		if err := insertApproval(ctx, tx, a); err != nil {
			return err
		}
	}
	if wasPending && IsTerminal(t.Status) {
		var at time.Time
		if t.CompletedAt != nil {
			at = *t.CompletedAt
		}
		return enqueue(ctx, tx, t, at)
	}
	return nil
}

// ListPending implements Store.
func (p *Postgres) ListPending(ctx context.Context, approverID, after string, limit int) ([]*Task, string, error) {
	match, _ := json.Marshal([]map[string]string{{"type": "user", "id": approverID}})
	rows, err := p.pool.Query(ctx, `SELECT t.id FROM tasks t
		WHERE t.status = 'pending' AND t.id > $1
		  AND EXISTS (SELECT 1 FROM task_items i
		              WHERE i.task_id = t.id AND i.status = 'pending'
		                AND t.workflow->'steps'->i.current_step->'approvers' @> $2::jsonb)
		ORDER BY t.id LIMIT $3`, after, string(match), limit+1)
	if err != nil {
		return nil, "", err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, "", err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(ids) > limit {
		ids = ids[:limit]
		next = ids[len(ids)-1]
	}
	out := make([]*Task, 0, len(ids))
	for _, id := range ids {
		t, err := p.GetTask(ctx, id)
		if err != nil {
			return nil, "", err
		}
		out = append(out, t)
	}
	return out, next, nil
}

func scanApproval(row pgx.Row) (*Approval, error) {
	var a Approval
	var subject, resource, action, ctxJSON []byte
	if err := row.Scan(&a.ID, &a.TaskID, &a.ItemIndex, &subject, &resource, &action, &a.BindingContextMembers,
		&ctxJSON, &a.ApprovedAt, &a.ApprovedUntil, &a.RevokedAt, &a.RevokedBy, &a.RevokeReason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if a.Subject, err = decodeMap(subject); err != nil {
		return nil, err
	}
	if a.Resource, err = decodeMap(resource); err != nil {
		return nil, err
	}
	if a.Action, err = decodeMap(action); err != nil {
		return nil, err
	}
	if a.Context, err = decodeMap(ctxJSON); err != nil {
		return nil, err
	}
	return &a, nil
}

const approvalColumns = `id, task_id, item_idx, subject, resource, action, binding_context_members, context,
	approved_at, approved_until, revoked_at, revoked_by, revoke_reason`

// GetApproval implements Store.
func (p *Postgres) GetApproval(ctx context.Context, id string) (*Approval, error) {
	return scanApproval(p.pool.QueryRow(ctx, "SELECT "+approvalColumns+" FROM approvals WHERE id = $1", id))
}

// RevokeApproval implements Store.
func (p *Postgres) RevokeApproval(ctx context.Context, id, by, reason string, now time.Time) (*Approval, error) {
	a, err := scanApproval(p.pool.QueryRow(ctx, `UPDATE approvals SET revoked_at = $2, revoked_by = $3, revoke_reason = $4
		WHERE id = $1 AND revoked_at IS NULL RETURNING `+approvalColumns, id, now, by, reason))
	if errors.Is(err, ErrNotFound) {
		if _, getErr := p.GetApproval(ctx, id); getErr == nil {
			return nil, ErrConflict
		}
	}
	return a, err
}

// ExpireDue implements Store. SKIP LOCKED lets every replica sweep at once
// without claiming the same task or waiting on a task being decided.
func (p *Postgres) ExpireDue(ctx context.Context, now time.Time, limit int) ([]*Task, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	ids, err := queryIDs(ctx, tx, `SELECT id FROM tasks WHERE status = 'pending' AND expires_at <= $1
		ORDER BY expires_at LIMIT $2 FOR UPDATE SKIP LOCKED`, now, limit)
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	out := make([]*Task, 0, len(ids))
	for _, id := range ids {
		// The row is locked by the claim above.
		t, err := loadTask(ctx, tx, id, false)
		if err != nil {
			return nil, err
		}
		if err := saveChange(ctx, tx, t, expireChange(t, now)); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func queryIDs(ctx context.Context, q queryer, sql string, args ...any) ([]string, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ClaimCallbacks implements Store. SKIP LOCKED and the lease keep two
// replicas from sending the same notification at once.
func (p *Postgres) ClaimCallbacks(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]Delivery, error) {
	rows, err := p.pool.Query(ctx, `WITH due AS (
			SELECT id FROM callback_outbox
			WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= $1
			  AND (claimed_until IS NULL OR claimed_until <= $1)
			ORDER BY next_attempt_at LIMIT $2 FOR UPDATE SKIP LOCKED)
		UPDATE callback_outbox o SET attempts = o.attempts + 1, claimed_until = $3
		FROM due WHERE o.id = due.id
		RETURNING o.id, o.task_id, o.event, o.attempts`, now, limit, now.Add(lease))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.TaskID, &d.Event, &d.Attempts); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkDelivered implements Store.
func (p *Postgres) MarkDelivered(ctx context.Context, id int64, now time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE callback_outbox SET delivered_at = $2, claimed_until = NULL, last_error = '' WHERE id = $1`, id, now)
	return err
}

// RetryCallback implements Store.
func (p *Postgres) RetryCallback(ctx context.Context, id int64, next time.Time, lastErr string) error {
	_, err := p.pool.Exec(ctx, `UPDATE callback_outbox SET next_attempt_at = $2, claimed_until = NULL, last_error = $3 WHERE id = $1`, id, next, lastErr)
	return err
}

// FailCallback implements Store.
func (p *Postgres) FailCallback(ctx context.Context, id int64, now time.Time, lastErr string) error {
	_, err := p.pool.Exec(ctx, `UPDATE callback_outbox SET failed_at = $2, claimed_until = NULL, last_error = $3 WHERE id = $1`, id, now, lastErr)
	return err
}

// RememberJTI implements Store.
func (p *Postgres) RememberJTI(ctx context.Context, id string, expires time.Time) (bool, error) {
	tag, err := p.pool.Exec(ctx, "INSERT INTO seen_jti (jti, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING", id, expires)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Backlog implements Store.
func (p *Postgres) Backlog(ctx context.Context) (int64, int64, error) {
	var pending, undelivered int64
	err := p.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM tasks WHERE status = 'pending'),
			(SELECT count(*) FROM callback_outbox WHERE delivered_at IS NULL AND failed_at IS NULL)`).Scan(&pending, &undelivered)
	return pending, undelivered, err
}

// Purge implements Store. Deleting a task deletes its items, decisions,
// approvals and callback rows with it (ON DELETE CASCADE).
func (p *Postgres) Purge(ctx context.Context, c PurgeCutoffs, limit int) (int, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM tasks WHERE id IN (
			SELECT t.id FROM tasks t
			WHERE t.status <> 'pending' AND t.expires_at < $1
			  AND NOT EXISTS (SELECT 1 FROM approvals a WHERE a.task_id = t.id AND a.approved_until >= $2)
			ORDER BY t.expires_at LIMIT $3 FOR UPDATE SKIP LOCKED)`, c.Tasks, c.Approvals, limit)
	if err != nil {
		return 0, err
	}
	most := tag.RowsAffected()
	if tag, err = p.pool.Exec(ctx, `DELETE FROM idempotency_keys WHERE (requester, key) IN (
			SELECT requester, key FROM idempotency_keys WHERE retain_until < $1 LIMIT $2 FOR UPDATE SKIP LOCKED)`, c.Now, limit); err != nil {
		return 0, err
	}
	most = max(most, tag.RowsAffected())
	if tag, err = p.pool.Exec(ctx, `DELETE FROM seen_jti WHERE jti IN (
			SELECT jti FROM seen_jti WHERE expires_at < $1 LIMIT $2 FOR UPDATE SKIP LOCKED)`, c.Now, limit); err != nil {
		return 0, err
	}
	return int(max(most, tag.RowsAffected())), nil
}

// DropSchemaForTest drops schema and everything in it. Tests only.
func (p *Postgres) DropSchemaForTest(ctx context.Context, schema string) {
	if schemaName.MatchString(schema) {
		_, _ = p.pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	}
}

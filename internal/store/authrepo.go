package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// AuthRepo is auth.Store on the relational database (migration 0020):
// accounts, MFA, challenges, lockouts, sessions and the clients seen,
// with their audit events in the same transaction. Every instant is the
// database clock (DBNow, clock_timestamp()).
type AuthRepo struct{ DB *Relational }

var _ auth.Store = AuthRepo{}

// InTx runs fn in one relational transaction.
func (r AuthRepo) InTx(ctx context.Context, fn func(ctx context.Context, tx auth.Tx) error) error {
	return r.DB.Tx(ctx, func(ctx context.Context, tx Tx) error { return fn(ctx, authTx{tx: tx}) })
}

// Session reads one session and the database clock.
func (r AuthRepo) Session(ctx context.Context, jti string) (auth.SessionRow, time.Time, error) {
	var out auth.SessionRow
	var now time.Time
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		row, err := q.SessionWithClock(ctx, jti)
		if err != nil {
			return notFound(err)
		}
		now = row.DbNow
		out = auth.SessionRow{JTI: row.Jti, UserID: row.UserID.String(), Role: row.Role, IssuedAt: row.IssuedAt,
			ExpiresAt: row.ExpiresAt, LastSeenAt: row.LastSeenAt, RevokedAt: row.RevokedAt, RemoteIP: row.RemoteIp, UserAgent: row.UserAgent}
		if row.RevokeReason != nil {
			out.RevokeReason = *row.RevokeReason
		}
		return nil
	})
	return out, now, err
}

// TouchSession moves last_seen_at to the database clock.
func (r AuthRepo) TouchSession(ctx context.Context, jti string) error {
	return r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		return q.TouchSession(ctx, jti)
	})
}

var _ auth.LiveSessionLister = AuthRepo{}

// LiveSessions lists at most limit live sessions (not revoked, not
// expired, used within idle) on the database clock, by jti: what
// sessions_live must hold (docs/PLAN.md section 15 row 21).
func (r AuthRepo) LiveSessions(ctx context.Context, idle time.Duration, limit int) ([]auth.SessionRow, error) {
	var out []auth.SessionRow
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		rows, err := q.ListLiveSessions(ctx, relational.ListLiveSessionsParams{
			IdleS: idle.Seconds(), PageSize: int32(min(max(limit, 0), auth.MaxLiveSessions+1)),
		})
		if err != nil {
			return err
		}
		out = make([]auth.SessionRow, 0, len(rows))
		for i := range rows {
			out = append(out, auth.SessionRow{JTI: rows[i].Jti, UserID: rows[i].UserID.String(), Role: rows[i].Role, ExpiresAt: rows[i].ExpiresAt})
		}
		return nil
	})
	return out, err
}

// Users lists at most limit accounts by username.
func (r AuthRepo) Users(ctx context.Context, limit int) ([]auth.User, error) {
	var out []auth.User
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		rows, err := q.ListUsers(ctx, int32(min(max(limit, 0), auth.MaxUsersListed)))
		if err != nil {
			return err
		}
		out = make([]auth.User, 0, len(rows))
		for i := range rows {
			out = append(out, userFrom(&rows[i]))
		}
		return nil
	})
	return out, err
}

// RecordClientsSeen upserts the clients at the database clock.
func (r AuthRepo) RecordClientsSeen(ctx context.Context, seen []auth.ClientSeen) error {
	return r.DB.Tx(ctx, func(ctx context.Context, tx Tx) error {
		now, err := tx.Q.DBNow(ctx)
		if err != nil {
			return err
		}
		for _, c := range seen {
			var subject *string
			if c.MTLSSubject != "" {
				s := c.MTLSSubject
				subject = &s
			}
			scopes := c.Scopes
			if scopes == nil {
				scopes = []string{}
			}
			if err := tx.Q.UpsertClientSeen(ctx, relational.UpsertClientSeenParams{
				ClientID: c.ClientID, Issuer: c.Issuer, MtlsSubject: subject, FirstSeenAt: now, LastSeenAt: now, Scopes: scopes,
			}); err != nil {
				return fmt.Errorf("oauth_clients_seen %s: %w", c.ClientID, err)
			}
		}
		return nil
	})
}

// notFound maps "no rows" to auth.ErrNotFound.
func notFound(err error) error {
	if IsNoRows(err) {
		return auth.ErrNotFound
	}
	return err
}

// parseID is an account id; one that is not a UUID names no account.
func parseID(id string) (uuid.UUID, error) {
	u, err := uuid.Parse(id)
	if err != nil {
		return uuid.UUID{}, auth.ErrNotFound
	}
	return u, nil
}

func userFrom(u *relational.User) auth.User {
	return auth.User{ID: u.ID.String(), Username: u.Username, PasswordHash: u.PasswordHash, Role: u.Role, Status: u.Status,
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt, LastLoginAt: u.LastLoginAt}
}

type authTx struct{ tx Tx }

func (t authTx) q() *relational.Queries { return t.tx.Q }

// Now implements auth.Tx.
func (t authTx) Now(ctx context.Context) (time.Time, error) { return t.q().DBNow(ctx) }

// Record implements auth.Tx.
func (t authTx) Record(ctx context.Context, ev audit.Event) error {
	_, err := audit.Record(ctx, t.tx, ev)
	return err
}

// UserByUsername implements auth.Tx.
func (t authTx) UserByUsername(ctx context.Context, username string) (auth.User, error) {
	u, err := t.q().UserByUsername(ctx, username)
	if err != nil {
		return auth.User{}, notFound(err)
	}
	return userFrom(&u), nil
}

// UserByID implements auth.Tx.
func (t authTx) UserByID(ctx context.Context, id string) (auth.User, error) {
	uid, err := parseID(id)
	if err != nil {
		return auth.User{}, err
	}
	u, err := t.q().UserByID(ctx, uid)
	if err != nil {
		return auth.User{}, notFound(err)
	}
	return userFrom(&u), nil
}

// UserForUpdate implements auth.Tx.
func (t authTx) UserForUpdate(ctx context.Context, id string) (auth.User, error) {
	uid, err := parseID(id)
	if err != nil {
		return auth.User{}, err
	}
	u, err := t.q().UserForUpdate(ctx, uid)
	if err != nil {
		return auth.User{}, notFound(err)
	}
	return userFrom(&u), nil
}

// CountUsers implements auth.Tx.
func (t authTx) CountUsers(ctx context.Context) (int64, error) { return t.q().CountUsers(ctx) }

// CountActiveAdmins implements auth.Tx.
func (t authTx) CountActiveAdmins(ctx context.Context) (int64, error) {
	return t.q().CountActiveAdmins(ctx)
}

// InsertUser implements auth.Tx.
func (t authTx) InsertUser(ctx context.Context, u auth.User, actor string, at time.Time) (auth.User, error) {
	row, err := t.q().InsertUser(ctx, relational.InsertUserParams{Username: u.Username, PasswordHash: u.PasswordHash, Role: u.Role, At: at, Actor: actor})
	if SQLState(err) == StateUniqueViolation {
		return auth.User{}, auth.ErrConflict
	}
	if err != nil {
		return auth.User{}, err
	}
	return userFrom(&row), nil
}

// SetUserStatus implements auth.Tx.
func (t authTx) SetUserStatus(ctx context.Context, id, status, actor string, at time.Time) (auth.User, error) {
	uid, err := parseID(id)
	if err != nil {
		return auth.User{}, err
	}
	row, err := t.q().SetUserStatus(ctx, relational.SetUserStatusParams{Status: status, At: at, Actor: actor, ID: uid})
	if err != nil {
		return auth.User{}, notFound(err)
	}
	return userFrom(&row), nil
}

// TouchLogin implements auth.Tx.
func (t authTx) TouchLogin(ctx context.Context, id string, at time.Time) error {
	uid, err := parseID(id)
	if err != nil {
		return err
	}
	return t.q().TouchUserLogin(ctx, relational.TouchUserLoginParams{At: &at, ID: uid})
}

func lockoutFrom(l *relational.LoginLockout) auth.Lockout {
	return auth.Lockout{Username: l.Username, Failures: int(l.Failures), LockedUntil: l.LockedUntil}
}

// Lockout implements auth.Tx.
func (t authTx) Lockout(ctx context.Context, username string, at time.Time) (auth.Lockout, error) {
	if err := t.q().EnsureLockout(ctx, relational.EnsureLockoutParams{Username: username, At: at}); err != nil {
		return auth.Lockout{}, err
	}
	l, err := t.q().LockoutForUpdate(ctx, username)
	if err != nil {
		return auth.Lockout{}, notFound(err)
	}
	return lockoutFrom(&l), nil
}

// PeekLockout implements auth.Tx.
func (t authTx) PeekLockout(ctx context.Context, username string) (auth.Lockout, error) {
	l, err := t.q().LockoutByUsername(ctx, username)
	if err != nil {
		return auth.Lockout{}, notFound(err)
	}
	return lockoutFrom(&l), nil
}

// SetLockout implements auth.Tx.
func (t authTx) SetLockout(ctx context.Context, l auth.Lockout, at time.Time) error {
	return t.q().SetLockout(ctx, relational.SetLockoutParams{
		Failures: int32(min(l.Failures, 1<<30)), LockedUntil: l.LockedUntil, At: at, Username: l.Username,
	})
}

// ClearLockout implements auth.Tx.
func (t authTx) ClearLockout(ctx context.Context, username string) error {
	return t.q().ClearLockout(ctx, username)
}

// MFAForUpdate implements auth.Tx.
func (t authTx) MFAForUpdate(ctx context.Context, userID string) (auth.MFA, error) {
	uid, err := parseID(userID)
	if err != nil {
		return auth.MFA{}, err
	}
	m, err := t.q().UserMFAForUpdate(ctx, uid)
	if err != nil {
		return auth.MFA{}, notFound(err)
	}
	return auth.MFA{UserID: m.UserID.String(), KeyID: m.KeyID, SecretEnc: m.SecretEnc, EnrolledAt: m.EnrolledAt, LastStep: m.LastStep}, nil
}

// SaveMFA implements auth.Tx.
func (t authTx) SaveMFA(ctx context.Context, m auth.MFA, at time.Time) error {
	uid, err := parseID(m.UserID)
	if err != nil {
		return err
	}
	return t.q().UpsertUserMFA(ctx, relational.UpsertUserMFAParams{
		UserID: uid, KeyID: m.KeyID, SecretEnc: m.SecretEnc, EnrolledAt: m.EnrolledAt, LastStep: m.LastStep, At: at,
	})
}

// DeleteMFA implements auth.Tx.
func (t authTx) DeleteMFA(ctx context.Context, userID string) error {
	uid, err := parseID(userID)
	if err != nil {
		return err
	}
	_, err = t.q().DeleteUserMFA(ctx, uid)
	return err
}

// InsertChallenge implements auth.Tx.
func (t authTx) InsertChallenge(ctx context.Context, c auth.Challenge) error {
	uid, err := parseID(c.UserID)
	if err != nil {
		return err
	}
	return t.q().InsertChallenge(ctx, relational.InsertChallengeParams{
		TokenHash: c.TokenHash, UserID: uid, At: c.CreatedAt, ExpiresAt: c.ExpiresAt, RemoteIp: c.RemoteIP,
	})
}

// ChallengeForUpdate implements auth.Tx.
func (t authTx) ChallengeForUpdate(ctx context.Context, tokenHash string) (auth.Challenge, error) {
	c, err := t.q().ChallengeForUpdate(ctx, tokenHash)
	if err != nil {
		return auth.Challenge{}, notFound(err)
	}
	return auth.Challenge{TokenHash: c.TokenHash, UserID: c.UserID.String(), CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt,
		Attempts: int(c.Attempts), UsedAt: c.UsedAt, RemoteIP: c.RemoteIp}, nil
}

// CountChallengeAttempt implements auth.Tx.
func (t authTx) CountChallengeAttempt(ctx context.Context, tokenHash string) error {
	return t.q().CountChallengeAttempt(ctx, tokenHash)
}

// UseChallenge implements auth.Tx.
func (t authTx) UseChallenge(ctx context.Context, tokenHash string, at time.Time) error {
	return t.q().UseChallenge(ctx, relational.UseChallengeParams{At: &at, TokenHash: tokenHash})
}

// InsertSession implements auth.Tx.
func (t authTx) InsertSession(ctx context.Context, s auth.SessionRow) error {
	uid, err := parseID(s.UserID)
	if err != nil {
		return err
	}
	return t.q().InsertSession(ctx, relational.InsertSessionParams{
		Jti: s.JTI, UserID: uid, Role: s.Role, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt, RemoteIp: s.RemoteIP, UserAgent: s.UserAgent,
	})
}

// RevokeSession implements auth.Tx.
func (t authTx) RevokeSession(ctx context.Context, jti, reason string, at time.Time) (bool, error) {
	n, err := t.q().RevokeSession(ctx, relational.RevokeSessionParams{At: &at, Reason: &reason, Jti: jti})
	return n > 0, err
}

// RevokeUserSessions implements auth.Tx.
func (t authTx) RevokeUserSessions(ctx context.Context, userID, reason string, at time.Time) ([]string, error) {
	uid, err := parseID(userID)
	if err != nil {
		return nil, err
	}
	return t.q().RevokeUserSessions(ctx, relational.RevokeUserSessionsParams{At: &at, Reason: &reason, UserID: uid})
}

// Sweep implements auth.Tx.
func (t authTx) Sweep(ctx context.Context, before, now time.Time) (sessions, challenges, lockouts int64, err error) {
	if sessions, err = t.q().DeleteExpiredSessions(ctx, before); err != nil {
		return 0, 0, 0, err
	}
	if challenges, err = t.q().DeleteExpiredChallenges(ctx, before); err != nil {
		return 0, 0, 0, err
	}
	lockouts, err = t.q().DeleteStaleLockouts(ctx, relational.DeleteStaleLockoutsParams{Before: before, Now: &now})
	return sessions, challenges, lockouts, err
}

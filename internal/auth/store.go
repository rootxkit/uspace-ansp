package auth

import (
	"context"
	"errors"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/audit"
)

// Account statuses (users.status).
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// User is a row of users.
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Role         string
	Status       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  *time.Time
}

// MFA is a row of user_mfa: the sealed TOTP secret, whether the
// enrolment is confirmed, and the last time step accepted.
type MFA struct {
	UserID     string
	KeyID      string
	SecretEnc  []byte
	EnrolledAt *time.Time
	LastStep   int64
}

// Challenge is a row of login_challenges: the mfa_pending token by its
// SHA-256.
type Challenge struct {
	TokenHash string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Attempts  int
	UsedAt    *time.Time
	RemoteIP  string
}

// Lockout is a row of login_lockouts.
type Lockout struct {
	Username    string
	Failures    int
	LockedUntil *time.Time
}

// SessionRow is a row of user_sessions.
type SessionRow struct {
	JTI          string
	UserID       string
	Role         string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	LastSeenAt   time.Time
	RevokedAt    *time.Time
	RevokeReason string
	RemoteIP     string
	UserAgent    string
}

// ClientSeen is one accepted machine call for oauth_clients_seen.
type ClientSeen struct {
	ClientID    string
	Issuer      string
	MTLSSubject string
	Scopes      []string
}

// Errors a Store returns.
var (
	// ErrNotFound is a missing row.
	ErrNotFound = errors.New("not found")
	// ErrConflict is a unique key already taken (a username).
	ErrConflict = errors.New("conflict")
)

// Store is the accounts' view of the relational database
// (store.AuthRepo). Every instant it compares or writes is the
// database's clock: Tx.Now inside a transaction, the clock returned
// with a session row outside one.
type Store interface {
	// InTx runs fn in one transaction: committed when fn returns nil.
	InTx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
	// Session reads one session and the database clock.
	Session(ctx context.Context, jti string) (SessionRow, time.Time, error)
	// TouchSession moves last_seen_at to the database clock.
	TouchSession(ctx context.Context, jti string) error
	// Users lists at most limit accounts by username.
	Users(ctx context.Context, limit int) ([]User, error)
	// RecordClientsSeen upserts oauth_clients_seen at the database
	// clock.
	RecordClientsSeen(ctx context.Context, seen []ClientSeen) error
}

// Tx is the work inside one transaction.
type Tx interface {
	// Now is the database clock.
	Now(ctx context.Context) (time.Time, error)
	// Record appends an audit event in this transaction.
	Record(ctx context.Context, ev audit.Event) error

	UserByUsername(ctx context.Context, username string) (User, error)
	UserByID(ctx context.Context, id string) (User, error)
	// UserForUpdate reads an account and locks its row.
	UserForUpdate(ctx context.Context, id string) (User, error)
	CountUsers(ctx context.Context) (int64, error)
	CountActiveAdmins(ctx context.Context) (int64, error)
	// InsertUser returns ErrConflict when the username is taken.
	InsertUser(ctx context.Context, u User, actor string, at time.Time) (User, error)
	SetUserStatus(ctx context.Context, id, status, actor string, at time.Time) (User, error)
	TouchLogin(ctx context.Context, id string, at time.Time) error

	// Lockout reads the lockout of username, creating it when missing,
	// and locks its row.
	Lockout(ctx context.Context, username string, at time.Time) (Lockout, error)
	// PeekLockout reads it without a lock; ErrNotFound when none.
	PeekLockout(ctx context.Context, username string) (Lockout, error)
	SetLockout(ctx context.Context, l Lockout, at time.Time) error
	ClearLockout(ctx context.Context, username string) error

	// MFAForUpdate reads the MFA row and locks it, so two sign-ins
	// cannot spend one code.
	MFAForUpdate(ctx context.Context, userID string) (MFA, error)
	SaveMFA(ctx context.Context, m MFA, at time.Time) error
	DeleteMFA(ctx context.Context, userID string) error

	InsertChallenge(ctx context.Context, c Challenge) error
	// ChallengeForUpdate reads a challenge and locks it.
	ChallengeForUpdate(ctx context.Context, tokenHash string) (Challenge, error)
	CountChallengeAttempt(ctx context.Context, tokenHash string) error
	UseChallenge(ctx context.Context, tokenHash string, at time.Time) error

	InsertSession(ctx context.Context, s SessionRow) error
	// RevokeSession ends a live session; false when it was not live.
	RevokeSession(ctx context.Context, jti, reason string, at time.Time) (bool, error)
	// RevokeUserSessions ends every live session of an account.
	RevokeUserSessions(ctx context.Context, userID, reason string, at time.Time) ([]string, error)

	// Sweep deletes sessions and challenges that expired before before,
	// and lockouts untouched since before that hold no lock at now.
	Sweep(ctx context.Context, before, now time.Time) (sessions, challenges, lockouts int64, err error)
}

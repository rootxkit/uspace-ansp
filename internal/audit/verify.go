package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// Reasons a row breaks the chain.
const (
	BrokenPrevHash = "prev_hash_mismatch" // the row does not link to the row before it
	BrokenHash     = "hash_mismatch"      // the row's content does not give its hash
	BrokenPayload  = "payload_unreadable" // the payload is not a JSON object
)

// Result is what a verification checked: on success how many rows from
// which id to which, so "verified" is never an empty claim (E-02).
type Result struct {
	Month    string // "2026-10"
	Rows     int64
	FirstID  int64
	LastID   int64
	LastHash string
	// BrokenAt is the id of the first broken row and Reason why; nil
	// when the chain holds.
	BrokenAt *int64
	Reason   string
}

// verifyPage bounds the rows read per query.
const verifyPage = 1000

// Verify recomputes the chain of month (any instant in it, UTC) and
// returns ok=false with the id of the first broken row when it does not
// hold. A month without rows is ok.
func Verify(ctx context.Context, db relational.DBTX, month time.Time) (ok bool, brokenAt *int64, err error) {
	res, err := VerifyMonth(ctx, db, month)
	if err != nil {
		return false, nil, err
	}
	return res.BrokenAt == nil, res.BrokenAt, nil
}

// VerifyMonth is Verify with the whole result.
func VerifyMonth(ctx context.Context, db relational.DBTX, month time.Time) (Result, error) {
	return verify(ctx, relational.New(db), MonthStart(month), verifyPage)
}

func verify(ctx context.Context, q *relational.Queries, month time.Time, page int32) (Result, error) {
	res := Result{Month: month.Format("2006-01")}
	end := month.AddDate(0, 1, 0)
	var want string
	after := int64(0)
	broken := func(id int64, reason string) (Result, error) {
		res.BrokenAt, res.Reason = &id, reason
		return res, nil
	}
	for {
		rows, err := q.EventsInRange(ctx, relational.EventsInRangeParams{FromTs: month, ToTs: end, AfterID: after, PageSize: page})
		if err != nil {
			return res, fmt.Errorf("audit verify %s: %w", res.Month, err)
		}
		for i := range rows {
			r := rowFrom(&rows[i])
			if res.Rows == 0 {
				res.FirstID = r.ID
				prev, err := q.LastEventBefore(ctx, relational.LastEventBeforeParams{BeforeTs: month, BeforeID: r.ID})
				switch {
				case isNoRows(err):
					want = GenesisHash
				case err != nil:
					return res, fmt.Errorf("audit verify %s: predecessor: %w", res.Month, err)
				default:
					want = prev.Hash
				}
			}
			res.Rows++
			res.LastID, res.LastHash = r.ID, r.Hash
			if r.PrevHash != want {
				return broken(r.ID, BrokenPrevHash)
			}
			got, err := Hash(&r)
			if err != nil {
				return broken(r.ID, BrokenPayload)
			}
			if got != r.Hash {
				return broken(r.ID, BrokenHash)
			}
			want = r.Hash
			after = r.ID
		}
		if len(rows) < int(page) {
			return res, nil
		}
	}
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

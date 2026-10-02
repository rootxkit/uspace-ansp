package store

import (
	"context"
	"fmt"
	"strconv"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// Audit event of a policy change (internal/audit).
const (
	EventPolicyUpdated = "policy_updated"
	EntityPolicy       = "ansp_policy"
	purposePolicy      = "threshold change (INV-03)"
	lockPolicy         = "ansp_policy"
)

// PolicyRepo is policy.Repo on the relational database: ansp_policy rows
// and their audit events in one transaction. It lives here, not in
// internal/policy, so the hot path that follows the policy has no
// database import path (docs/PLAN.md section 3).
type PolicyRepo struct{ DB *Relational }

var _ policy.Repo = PolicyRepo{}

// Latest is the newest ansp_policy row.
func (r PolicyRepo) Latest(ctx context.Context) (policy.Policy, error) {
	var out policy.Policy
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		row, err := q.LatestPolicy(ctx)
		if err != nil {
			return fmt.Errorf("read ansp_policy: %w", err)
		}
		out = policyFromRow(&row)
		return nil
	})
	return out, err
}

// Insert stores t as the next policy_version, records policy_updated
// and runs within (the KV put) before the commit, all under the
// writers' advisory lock so versions reach KV in order.
func (r PolicyRepo) Insert(ctx context.Context, actor policy.Actor, t policy.Thresholds,
	within func(ctx context.Context, p policy.Policy) error,
) (policy.Policy, error) {
	var out policy.Policy
	err := r.DB.Tx(ctx, func(ctx context.Context, tx Tx) error {
		if err := tx.Q.AdvisoryXactLock(ctx, LockKey(lockPolicy)); err != nil {
			return fmt.Errorf("policy lock: %w", err)
		}
		row, err := tx.Q.InsertPolicy(ctx, relational.InsertPolicyParams{
			FeedMarginLateralM:  t.FeedMarginLateralM,
			FeedMarginVerticalM: t.FeedMarginVerticalM,
			StaleAfterS:         t.StaleAfterS,
			SourceLivenessS:     t.SourceLivenessS,
			CispAlarmAfterS:     t.CISPAlarmAfterS,
			CispHeartbeatS:      t.CISPHeartbeatS,
			CisReconcileS:       t.CISReconcileS,
			CisStaleBoundS:      t.CISStaleBoundS,
			NoticeEscalationS:   t.NoticeEscalationS,
			DefaultZoneType:     t.DefaultZoneType,
			Country:             t.Country,
			ChangedBy:           actor.ID,
		})
		if err != nil {
			return fmt.Errorf("insert ansp_policy: %w", err)
		}
		out = policyFromRow(&row)
		_, err = audit.Record(ctx, tx, audit.Event{
			ActorType: audit.ActorType(actor.Type), ActorID: actor.ID, Purpose: purposePolicy,
			EntityType: EntityPolicy, EntityID: strconv.FormatInt(out.Version, 10),
			EventType: EventPolicyUpdated, Payload: out,
		})
		if err != nil {
			return err
		}
		if within != nil {
			return within(ctx, out)
		}
		return nil
	})
	if err != nil {
		return policy.Policy{}, err
	}
	return out, nil
}

func policyFromRow(r *relational.AnspPolicy) policy.Policy {
	return policy.Policy{
		Version: r.PolicyVersion,
		Thresholds: policy.Thresholds{
			FeedMarginLateralM:  r.FeedMarginLateralM,
			FeedMarginVerticalM: r.FeedMarginVerticalM,
			StaleAfterS:         r.StaleAfterS,
			SourceLivenessS:     r.SourceLivenessS,
			CISPAlarmAfterS:     r.CispAlarmAfterS,
			CISPHeartbeatS:      r.CispHeartbeatS,
			CISReconcileS:       r.CisReconcileS,
			CISStaleBoundS:      r.CisStaleBoundS,
			NoticeEscalationS:   r.NoticeEscalationS,
			DefaultZoneType:     r.DefaultZoneType,
			Country:             r.Country,
		},
		ChangedBy: r.ChangedBy,
		ChangedAt: r.ChangedAt,
	}
}

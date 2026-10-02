package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/bus"
)

// Counters of the policy component (status line and /metrics, E-09).
const (
	CounterKVRefused      = "policy_kv_refused"      // an update refused because KV could not take it (503)
	CounterNotifyFailed   = "policy_notify_failed"   // stored and in KV, but the ctl.policy push failed; followers read KV
	CounterApplied        = "policy_applied"         // a follower applied a higher version
	CounterOlderIgnored   = "policy_older_ignored"   // a follower was offered a lower version and kept its own
	CounterInvalidRefused = "policy_invalid_refused" // a follower was offered a policy that does not validate
	CounterUndecodable    = "policy_undecodable"     // a KV value or push that is not a policy
)

// KVKey is the key of the current policy in the KV bucket policy.
const KVKey = "current"

// KVTimeout bounds one KV put of Update and Republish.
const KVTimeout = 2 * time.Second

// Actor is who changes the policy; Type is user, client or system (the
// audit actor types).
type Actor struct {
	Type string
	ID   string
}

// Repo stores policy versions (store.PolicyRepo on the relational
// database; the hot path never imports it).
type Repo interface {
	// Latest is the newest version.
	Latest(ctx context.Context) (Policy, error)
	// Insert stores t as the next version in one transaction with its
	// audit event, and calls within with the stored policy before the
	// commit: an error from within rolls the version back.
	Insert(ctx context.Context, actor Actor, t Thresholds, within func(ctx context.Context, p Policy) error) (Policy, error)
}

// KV is the part of a JetStream key-value bucket Update needs.
type KV interface {
	Put(ctx context.Context, key string, value []byte) (uint64, error)
}

// Notifier pushes the stored policy on ctl.policy (a *nats.Conn).
type Notifier interface {
	Publish(subject string, data []byte) error
}

// ErrKVUnavailable refuses an update KV could not take; the handler
// answers 503 and the version is not recorded (LESSONS B-09).
var ErrKVUnavailable = errors.New("policy KV unavailable")

// Service loads, updates and republishes the policy (api only).
type Service struct {
	Repo     Repo
	KV       KV
	Notify   Notifier
	Counters *core.Counters
}

// inc counts name when the service has counters.
func (s *Service) inc(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

// Load is the current policy, from the database.
func (s *Service) Load(ctx context.Context) (Policy, error) {
	p, err := s.Repo.Latest(ctx)
	if err != nil {
		return Policy{}, fmt.Errorf("load policy: %w", err)
	}
	return p, nil
}

// Update validates p's thresholds and stores them as the next
// policy_version inside a transaction that also puts the stored row
// into KV policy; when KV cannot take it the transaction rolls back and
// ErrKVUnavailable is returned (503), so a version never exists in the
// database without KV. After the commit the row is pushed on
// ctl.policy; a failed push is counted, since followers read KV. p's
// Version, ChangedBy and ChangedAt are ignored: the store assigns them.
func (s *Service) Update(ctx context.Context, actor Actor, p Policy) (int64, error) {
	t := p.Thresholds
	if err := t.Validate(); err != nil {
		return 0, err
	}
	var doc []byte
	stored, err := s.Repo.Insert(ctx, actor, t, func(ctx context.Context, np Policy) error {
		var err error
		if doc, err = json.Marshal(np); err != nil {
			return fmt.Errorf("encode policy: %w", err)
		}
		return s.put(ctx, doc)
	})
	if err != nil {
		return 0, err
	}
	if s.Notify != nil {
		if err := s.Notify.Publish(bus.SubjectControlPolicy, doc); err != nil {
			s.inc(CounterNotifyFailed)
		}
	}
	return stored.Version, nil
}

// Republish puts the current policy into KV again, repairing a lost or
// emptied bucket (LESSONS B-09); api runs it at start and periodically.
func (s *Service) Republish(ctx context.Context) (Policy, error) {
	p, err := s.Load(ctx)
	if err != nil {
		return Policy{}, err
	}
	doc, err := json.Marshal(p)
	if err != nil {
		return Policy{}, fmt.Errorf("encode policy: %w", err)
	}
	if err := s.put(ctx, doc); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (s *Service) put(ctx context.Context, doc []byte) error {
	if s.KV == nil {
		s.inc(CounterKVRefused)
		return fmt.Errorf("%w: no KV bucket %s", ErrKVUnavailable, bus.BucketPolicy)
	}
	kctx, cancel := context.WithTimeout(ctx, KVTimeout)
	defer cancel()
	if _, err := s.KV.Put(kctx, KVKey, doc); err != nil {
		s.inc(CounterKVRefused)
		return fmt.Errorf("%w: %w", ErrKVUnavailable, err)
	}
	return nil
}

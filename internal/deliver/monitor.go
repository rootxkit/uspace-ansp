package deliver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// Target is a receiver of the degraded direct delivery: a USSP of the
// CIS USSP list or the authority, by its base URL.
type Target struct {
	Name    string
	BaseURL string
}

// Monitor raises cisp_not_published for a restriction active here and
// not published to the CISP at its current version for more than
// cisp_alarm_after_s (on the database clock), starts the degraded direct
// delivery to every target, and clears the alarm, with its duration,
// when the publication succeeds or the restriction is no longer active
// (the direct jobs still queued are then cancelled). It runs on every
// replica; the alarm's unique index makes one of them raise it.
type Monitor struct {
	Repo   Repo
	Outbox *Outbox
	Events *Events
	Policy Policy
	// AlarmAfter is cisp_alarm_after_s of the ansp_policy row.
	AlarmAfter func(ctx context.Context) time.Duration
	// Targets is the CIS USSP list's base URLs and the authority's.
	Targets func(ctx context.Context) []Target
	// PublicBase is ANSP_PUBLIC_BASE_URL (the pull_url's base).
	PublicBase string
	Logger     *slog.Logger
	Counters   *core.Counters
}

func (m *Monitor) count(name string) {
	if m.Counters != nil {
		m.Counters.Inc(name)
	}
}

func (m *Monitor) log() *slog.Logger {
	if m.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return m.Logger
}

// MonitorReport is what one Tick did.
type MonitorReport struct {
	Raised, Advanced, Cleared, DirectQueued int
	// LateRaised and LateCleared are the uss_notify_late alarms.
	LateRaised, LateCleared int
}

// AlarmDetail is the alarm's text (C-12: "not yet published to the CISP
// since T", never "lost").
func AlarmDetail(v VersionInfo) string {
	if v.State == string(restriction.StateEnded) || v.State == string(restriction.StateCancelled) {
		return fmt.Sprintf("restriction %s (version %d) is %s and the change is not yet published to the CISP since %s; delivering it directly to the USSPs and the authority",
			v.Identifier, v.Version, v.State, restriction.Stamp(v.ChangedAt))
	}
	return fmt.Sprintf("restriction %s (version %d) is active and not yet published to the CISP since %s; delivering it directly to the USSPs and the authority",
		v.Identifier, v.Version, restriction.Stamp(v.ChangedAt))
}

// Tick raises, advances and clears the alarms once.
func (m *Monitor) Tick(ctx context.Context) (MonitorReport, error) {
	var rep MonitorReport
	var errs []error
	after := 10 * time.Second
	if m.AlarmAfter != nil {
		after = m.AlarmAfter(ctx)
	}
	overdue, err := m.Repo.Overdue(ctx, after, m.Policy.MaxBatch)
	if err != nil {
		errs = append(errs, err)
	}
	for _, o := range overdue {
		if err := m.raise(ctx, o, &rep); err != nil {
			errs = append(errs, fmt.Errorf("restriction %s: %w", o.RestrictionID, err))
		}
	}
	clearable, err := m.Repo.Clearable(ctx, m.Policy.MaxBatch)
	if err != nil {
		errs = append(errs, err)
	}
	for _, c := range clearable {
		if err := m.clear(ctx, c, &rep); err != nil {
			errs = append(errs, fmt.Errorf("restriction %s: %w", c.RestrictionID, err))
		}
	}
	errs = append(errs, m.late(ctx, &rep))
	return rep, errors.Join(errs...)
}

// late raises uss_notify_late for each subscriber notification still
// queued NotifyLatency after the DSS answered (C-12: retried, never
// "lost"), and clears the alarms whose notification is settled: sent,
// superseded by a newer one, or failed or abandoned (whose own alarm
// then stands until a person acknowledges it).
func (m *Monitor) late(ctx context.Context, rep *MonitorReport) error {
	var errs []error
	late, err := m.Repo.LateNotifications(ctx, m.Policy.NotifyLatency, m.Policy.MaxBatch)
	if err != nil {
		errs = append(errs, err)
	}
	for _, l := range late {
		var al Alarm
		var raised bool
		err := m.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
			now, err := tx.Now(ctx)
			if err != nil {
				return err
			}
			al, raised, err = tx.RaiseAlarm(ctx, Alarm{ID: restriction.NewULID(now), Kind: AlarmNotifyLate, RestrictionID: l.RestrictionID,
				AnspVersion: l.AnspVersion, DeliveryID: l.DeliveryID, Since: l.QueuedAt, Detail: clip(LateDetail(l, m.Policy.NotifyLatency), 1000)})
			return err
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("notification %s: %w", l.DeliveryID, err))
			continue
		}
		if raised {
			rep.LateRaised++
			m.count(CounterNotifyLate)
			m.count(CounterAlarmsRaised)
			m.log().Error("deliver: uss_notify_late: "+al.Detail, slog.String("delivery_id", l.DeliveryID),
				slog.String("restriction_id", l.RestrictionID), slog.String("alarm_id", al.ID))
			m.Events.Alarm(ctx, al, "raised")
		}
	}
	cl, err := m.Repo.ClearableLate(ctx, m.Policy.MaxBatch)
	if err != nil {
		errs = append(errs, err)
	}
	for _, c := range cl {
		reason := "delivered"
		switch c.State {
		case StateCancelled:
			reason = "superseded"
		case StateFailed:
			reason = "delivery_failed"
		case StateAbandoned:
			reason = "delivery_abandoned"
		case StateSent, StateQueued:
		}
		var al Alarm
		var ok bool
		err := m.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
			var err error
			al, ok, err = tx.ClearAlarm(ctx, c.AlarmID, reason)
			return err
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("alarm %s: %w", c.AlarmID, err))
			continue
		}
		if ok {
			rep.LateCleared++
			m.count(CounterAlarmsCleared)
			m.log().Info("deliver: uss_notify_late cleared", slog.String("alarm_id", al.ID), slog.String("delivery_id", c.DeliveryID),
				slog.String("clear_reason", reason), slog.Float64("duration_s", al.ClearedAt.Sub(al.Since).Seconds()))
			m.Events.Alarm(ctx, al, "cleared")
		}
	}
	return errors.Join(errs...)
}

// raise opens (or moves to the new version) the alarm of o and queues
// the direct deliveries of its version, in one transaction; the jobs are
// published and the alarm told after the commit.
func (m *Monitor) raise(ctx context.Context, o Overdue, rep *MonitorReport) error {
	v, err := m.Repo.Version(ctx, o.RestrictionID, o.AnspVersion)
	if err != nil {
		return err
	}
	op := OpOfVersion(v)
	targets := m.targets(ctx)
	var al Alarm
	var raised, advanced bool
	queued := 0
	err = m.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		queued = 0
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		al, raised, err = tx.RaiseAlarm(ctx, Alarm{ID: restriction.NewULID(now), Kind: AlarmCISPNotPublished,
			RestrictionID: o.RestrictionID, AnspVersion: o.AnspVersion, Since: o.ChangedAt, Detail: AlarmDetail(v)})
		if err != nil {
			return err
		}
		advanced = !raised && al.AnspVersion < o.AnspVersion
		if advanced {
			if err := tx.AdvanceAlarm(ctx, al.ID, o.AnspVersion, AlarmDetail(v)); err != nil {
				return err
			}
			al.AnspVersion, al.Detail = o.AnspVersion, AlarmDetail(v)
		}
		for _, t := range targets {
			id := restriction.NewULID(now)
			body, err := BuildChange(v, op, id, m.PublicBase)
			if err != nil {
				return err
			}
			_, ok, err := m.Outbox.Enqueue(ctx, tx, Job{ID: id, Kind: KindDirect, RestrictionID: v.RestrictionID, AnspRef: v.AnspRef,
				AnspVersion: v.Version, Op: OpNotify, Target: t.BaseURL, Body: body})
			if err != nil {
				return err
			}
			if ok {
				queued++
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	rep.DirectQueued += queued
	for range queued {
		m.count(CounterDirectQueued)
	}
	if len(targets) == 0 {
		m.count(CounterDirectNoTargets)
		m.log().Error("deliver: no target for the degraded direct delivery (no CIS USSP list and no ANSP_AUTHORITY_URL)",
			slog.String("restriction_id", o.RestrictionID))
	}
	if ps, err := m.Repo.QueuedOf(ctx, o.RestrictionID, o.AnspVersion); err == nil {
		m.Outbox.PublishAll(ctx, ps)
	}
	log := m.log().With(slog.String("restriction_id", o.RestrictionID), slog.Int64("ansp_version", o.AnspVersion),
		slog.String("alarm_id", al.ID), slog.Int("direct_targets", len(targets)), slog.Int("direct_queued", queued))
	switch {
	case raised:
		rep.Raised++
		m.count(CounterAlarmsRaised)
		log.Error("deliver: cisp_not_published: " + al.Detail)
		m.Events.Alarm(ctx, al, "raised")
	case advanced:
		rep.Advanced++
		log.Error("deliver: cisp_not_published moved to the new version: " + al.Detail)
		m.Events.Alarm(ctx, al, "advanced."+itoa(o.AnspVersion))
	}
	return nil
}

func (m *Monitor) targets(ctx context.Context) []Target {
	if m.Targets == nil {
		return nil
	}
	ts := m.Targets(ctx)
	if len(ts) > m.Policy.MaxTargets {
		m.log().Error("deliver: more direct targets than the bound; the first are delivered",
			slog.Int("targets", len(ts)), slog.Int("bound", m.Policy.MaxTargets))
		ts = ts[:m.Policy.MaxTargets]
	}
	return ts
}

// clear closes c's alarm and cancels the direct jobs still queued.
func (m *Monitor) clear(ctx context.Context, c Clearable, rep *MonitorReport) error {
	reason, cancel := "published", CancelSupersededByCISP
	if c.PublishedVersion < c.AnspVersion {
		reason, cancel = CancelNotActive, CancelNotActive
	}
	var al Alarm
	var ok bool
	var cancelled []Cancelled
	err := m.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		var err error
		if al, ok, err = tx.ClearCISPAlarm(ctx, c.RestrictionID, reason); err != nil || !ok {
			return err
		}
		cancelled, err = tx.CancelQueued(ctx, KindDirect, c.RestrictionID, c.AnspVersion, cancel)
		return err
	})
	if err != nil || !ok {
		return err
	}
	rep.Cleared++
	m.count(CounterAlarmsCleared)
	for _, x := range cancelled {
		m.count(CounterCancelled)
		m.log().Info("deliver: a degraded direct delivery still queued is cancelled", slog.String("delivery_id", x.ID),
			slog.String("cancel_reason", cancel), slog.String("restriction_id", c.RestrictionID))
	}
	m.log().Info("deliver: cisp_not_published cleared", slog.String("restriction_id", c.RestrictionID), slog.String("alarm_id", al.ID),
		slog.String("clear_reason", reason), slog.Float64("duration_s", al.ClearedAt.Sub(al.Since).Seconds()))
	m.Events.Alarm(ctx, al, "cleared")
	return nil
}

// Run runs Tick every Policy.AlarmEvery until ctx ends.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.Policy.AlarmEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := m.Tick(ctx); err != nil && ctx.Err() == nil {
			m.log().Warn("deliver: the alarm monitor did not finish; it runs again next period", slog.String("error", err.Error()))
		}
	}
}

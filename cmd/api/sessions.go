package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// wireLiveSessions projects the live console sessions to KV
// sessions_live for manned-feed (docs/PLAN.md section 15 row 21): put
// after each sign-in commits, deleted after each end, the whole bucket
// rewritten every auth.LiveSessionResync; and ctl.sessions.seen moves
// last_seen_at of a session an open feed stream keeps in use. Without
// console sign-in there is nothing to project.
func wireLiveSessions(db *store.Relational, b *bus.Bus, aw *authWiring, reg prometheus.Registerer, logger *slog.Logger) error {
	if aw.accounts == nil || db == nil {
		return nil
	}
	proj := &auth.SessionProjector{KV: b.KeyValue(bus.BucketSessionsLive), Lister: store.AuthRepo{DB: db}, Idle: aw.accounts.Config().IdleTimeout}
	aw.accounts.SetProjection(proj)
	if err := obs.Counters(reg, "", proj.Counters()); err != nil {
		return err
	}
	aw.run = append(aw.run, func(ctx context.Context) {
		logged := false
		proj.Run(ctx, auth.LiveSessionResync, func(err error) {
			if !logged {
				logger.Error("sessions_live: the resync failed; console sessions on manned-feed are refused until it succeeds",
					slog.String("error", err.Error()))
				logged = true
			}
		})
	}, sessionsSeen(b, aw.accounts, logger))
	return nil
}

// sessionsSeen moves last_seen_at of the console sessions manned-feed
// reports in use on ctl.sessions.seen (docs/PLAN.md section 15 row 21
// (4)); bounded by what one feed sends (one per stream per minute).
func sessionsSeen(b *bus.Bus, accounts *auth.Accounts, logger *slog.Logger) func(ctx context.Context) {
	return func(ctx context.Context) {
		nc := b.Conn()
		if nc == nil || accounts == nil {
			return
		}
		sub, err := nc.Subscribe(bus.SubjectSessionsSeen, func(m *nats.Msg) {
			tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_ = accounts.SessionSeen(tctx, string(m.Data))
		})
		if err != nil {
			logger.Error("ctl.sessions.seen: subscribe", slog.String("error", err.Error()))
			return
		}
		<-ctx.Done()
		_ = sub.Unsubscribe()
	}
}

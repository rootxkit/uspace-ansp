package bus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
)

// Start-up defaults: three attempts, half a second then a second apart,
// then the process starts degraded (docs/PLAN.md section 7).
const (
	DefaultStartAttempts  = 3
	DefaultStartBackoff   = 500 * time.Millisecond
	DefaultConnectTimeout = 2 * time.Second
	DefaultReconnectWait  = 2 * time.Second
)

// Settings is the connection. Zero values take the defaults.
type Settings struct {
	// URL is ANSP_NATS_URL; empty means not configured.
	URL string
	// CredsFile is ANSP_NATS_CREDS: a user JWT .creds file or an NKey
	// seed file (both are read by nats.go; the seed form is what
	// scripts/nats-creds.sh writes for development).
	CredsFile string
	// Name is the connection name the server shows.
	Name string

	StartAttempts  int
	StartBackoff   time.Duration
	ConnectTimeout time.Duration
	ReconnectWait  time.Duration
}

// Connection states as the client's callbacks report them.
const (
	stateConnected    = "connected"
	stateReconnecting = "reconnecting"
	stateClosed       = "closed"
)

// Bus is one NATS connection that reconnects forever (B-08).
type Bus struct {
	nc     *nats.Conn
	js     jetstream.JetStream
	logger *slog.Logger

	mu    sync.Mutex
	state string
}

// Connect connects with the settings of cfg.
func Connect(ctx context.Context, cfg config.Config, logger *slog.Logger) (*Bus, error) {
	return ConnectWith(ctx, Settings{
		URL:       cfg.NATSURL,
		CredsFile: cfg.NATSCreds,
		Name:      "uspace-ansp-" + cfg.Process + "-" + cfg.Instance,
	}, logger)
}

// ConnectWith tries StartAttempts times with a doubling backoff. If NATS
// still cannot be reached it returns a degraded Bus, not an error: the
// connection keeps trying in the background, Check reports it down and
// the process stays up (B-08, E-02). Without a URL it returns a Bus
// whose Check says so. An error is returned only for a configuration
// that can never connect (an unreadable credentials file) or when ctx
// ends during the attempts.
func ConnectWith(ctx context.Context, s Settings, logger *slog.Logger) (*Bus, error) {
	s.defaults()
	b := &Bus{logger: logger, state: "not configured"}
	if s.URL == "" {
		logger.Error("nats: ANSP_NATS_URL is not set; the bus stays down")
		return b, nil
	}
	auth, err := credsOption(s.CredsFile)
	if err != nil {
		return nil, err
	}
	opts := []nats.Option{
		nats.Name(s.Name),
		nats.Timeout(s.ConnectTimeout),
		// Without it nats.go resolves the host with an unbounded lookup
		// before dialling; with it the dialer resolves within Timeout.
		// Found on the development stack: with the NATS container
		// stopped, the first start-up attempt hung until it came back.
		nats.SkipHostLookup(),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(s.ReconnectWait),
		nats.ConnectHandler(func(*nats.Conn) { b.transition(stateConnected, nil) }),
		nats.ReconnectHandler(func(*nats.Conn) { b.transition(stateConnected, nil) }),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) { b.transition(stateReconnecting, err) }),
		nats.ClosedHandler(func(*nats.Conn) { b.transition(stateClosed, nil) }),
	}
	if auth != nil {
		opts = append(opts, auth)
	}

	backoff := s.StartBackoff
	for attempt := 1; attempt <= s.StartAttempts; attempt++ {
		nc, err := nats.Connect(s.URL, opts...)
		if err == nil {
			return b.attach(nc)
		}
		logger.Warn("nats: connect failed", slog.Int("attempt", attempt), slog.Int("of", s.StartAttempts), slog.String("error", err.Error()))
		if attempt == s.StartAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("nats: %w", ctx.Err())
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	// Degraded start: the same options, retrying in the background.
	nc, err := nats.Connect(s.URL, append(opts, nats.RetryOnFailedConnect(true))...)
	if err != nil {
		return nil, fmt.Errorf("nats: %w", err)
	}
	b.transition(stateReconnecting, fmt.Errorf("not reachable after %d attempts; starting degraded", s.StartAttempts))
	return b.attach(nc)
}

func (s *Settings) defaults() {
	if s.StartAttempts <= 0 {
		s.StartAttempts = DefaultStartAttempts
	}
	if s.StartBackoff <= 0 {
		s.StartBackoff = DefaultStartBackoff
	}
	if s.ConnectTimeout <= 0 {
		s.ConnectTimeout = DefaultConnectTimeout
	}
	if s.ReconnectWait <= 0 {
		s.ReconnectWait = DefaultReconnectWait
	}
}

func credsOption(path string) (nats.Option, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the path is ANSP_NATS_CREDS, operator configuration
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("ANSP_NATS_CREDS: cannot be read: %w", err)
	}
	if strings.Contains(string(b), "BEGIN NATS USER JWT") {
		return nats.UserCredentials(path), nil
	}
	opt, err := nats.NkeyOptionFromSeed(path)
	if err != nil {
		return nil, fmt.Errorf("ANSP_NATS_CREDS: neither a user JWT nor an NKey seed: %w", err)
	}
	return opt, nil
}

func (b *Bus) attach(nc *nats.Conn) (*Bus, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats: jetstream: %w", err)
	}
	b.mu.Lock()
	b.nc, b.js = nc, js
	b.mu.Unlock()
	if nc.IsConnected() {
		b.transition(stateConnected, nil)
	}
	return b, nil
}

// transition logs a state change once: repeated reports of the same
// state (a reconnect attempt that fails again) are not logged again.
// The line is written under the lock, so a change is in the log by the
// time any caller can observe it.
func (b *Bus) transition(state string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == state {
		return
	}
	b.state = state
	attrs := []any{slog.String("state", state)}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	if state == stateConnected {
		b.logger.Info("nats: "+state, attrs...)
		return
	}
	b.logger.Error("nats: "+state, attrs...)
}

// Conn is the connection, nil when ANSP_NATS_URL is not set.
func (b *Bus) Conn() *nats.Conn { return b.nc }

// JetStream is the JetStream context, nil when ANSP_NATS_URL is not set.
func (b *Bus) JetStream() jetstream.JetStream { return b.js }

// Close closes the connection; Check then reports it closed.
func (b *Bus) Close() {
	if b.nc != nil {
		b.nc.Close()
		b.transition(stateClosed, nil)
	}
}

// Drain lets subscriptions finish and flushes publishes, then closes.
func (b *Bus) Drain() error {
	if b.nc == nil {
		return nil
	}
	if s, _ := b.Status(); s != obs.StateOK {
		// Nothing can be flushed to a server that is not there.
		b.Close()
		return nil
	}
	if err := b.nc.Drain(); err != nil {
		return fmt.Errorf("nats: drain: %w", err)
	}
	b.transition(stateClosed, nil)
	return nil
}

// Check is the readiness check of the connection, named nats and
// required: ok while connected, down with the reason otherwise.
func (b *Bus) Check() obs.Check {
	return obs.Check{Name: obs.DepNATS, Required: true, Probe: func(context.Context) (obs.State, string) {
		return b.Status()
	}}
}

// Status is the state of the connection and, when not ok, why. It is
// read from the state the client's callbacks last reported, never from
// the connection itself: nats.Conn.Status takes the connection lock,
// which a reconnect attempt holds while it dials, and readiness must
// answer while NATS is gone (found on the development stack: /readyz
// timed out instead of saying "reconnecting").
func (b *Bus) Status() (obs.State, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.nc == nil {
		return obs.StateDown, "ANSP_NATS_URL is not set"
	}
	switch b.state {
	case stateConnected:
		return obs.StateOK, ""
	case stateReconnecting:
		return obs.StateDown, "reconnecting"
	case stateClosed:
		return obs.StateDown, "closed"
	default:
		return obs.StateDown, b.state
	}
}

// StreamConfigs are the four streams of docs/PLAN.md section 7.
func StreamConfigs() []jetstream.StreamConfig {
	return []jetstream.StreamConfig{
		{
			Name: StreamMannedMirror, Subjects: []string{SubjectMannedPrefix + ">"},
			Storage: jetstream.FileStorage, Retention: jetstream.LimitsPolicy, MaxAge: MannedMirrorMaxAge,
		},
		{
			Name: StreamRestriction, Subjects: []string{SubjectRestrictionPrefix + ">"},
			Storage: jetstream.FileStorage, Retention: jetstream.LimitsPolicy, MaxAge: RestrictionMaxAge,
		},
		{
			Name: StreamDeliver, Subjects: []string{SubjectDeliverPrefix + ">"},
			Storage: jetstream.FileStorage, Retention: jetstream.WorkQueuePolicy, MaxAge: DeliverMaxAge,
		},
		{
			Name: StreamCoord, Subjects: []string{SubjectCoordPrefix + ">"},
			Storage: jetstream.FileStorage, Retention: jetstream.LimitsPolicy, MaxAge: CoordMaxAge,
		},
	}
}

// BucketConfigs are the KV buckets of docs/PLAN.md section 7 and the
// live-session projection of section 15 row 21.
func BucketConfigs() []jetstream.KeyValueConfig {
	return []jetstream.KeyValueConfig{
		{Bucket: BucketCISCurrent, Storage: jetstream.FileStorage},
		{Bucket: BucketSourceControl, Storage: jetstream.FileStorage, History: 8},
		{Bucket: BucketPolicy, Storage: jetstream.FileStorage, History: 8},
		{Bucket: BucketSessionsLive, Storage: jetstream.FileStorage, History: 1, TTL: SessionsLiveMaxAge},
	}
}

// EnsureStreams creates the streams and buckets or brings them to their
// configuration; calling it again changes nothing.
func (b *Bus) EnsureStreams(ctx context.Context) error {
	if b.js == nil {
		return errors.New("nats: ANSP_NATS_URL is not set")
	}
	streams := StreamConfigs()
	for i := range streams {
		if _, err := b.js.CreateOrUpdateStream(ctx, streams[i]); err != nil {
			return fmt.Errorf("nats: stream %s: %w", streams[i].Name, err)
		}
	}
	buckets := BucketConfigs()
	for i := range buckets {
		if _, err := b.js.CreateOrUpdateKeyValue(ctx, buckets[i]); err != nil {
			return fmt.Errorf("nats: bucket %s: %w", buckets[i].Bucket, err)
		}
	}
	return nil
}

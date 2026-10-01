// Package obs is the observability of every process (docs/PLAN.md
// sections 3 and 14, LESSONS E-02, E-09): the slog JSON logger with
// process and instance on every line, the Prometheus registry and the
// export of core.Counters under their own snake_case names, the
// OpenTelemetry tracer, and the liveness and readiness handlers, where
// every dependency is named with its state and why. A library package
// never logs; the process passes this logger down.
package obs

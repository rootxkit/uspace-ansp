package obs

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rootxkit/uspace-core/core"
)

// Metrics is a fresh registry with the Go runtime and process
// collectors. Each process has its own; nothing registers globally.
func Metrics() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return reg
}

// MetricsHandler serves reg. A collector that fails is reported in the
// response and the rest is still served.
func MetricsHandler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
}

// Counters exports every name of c as a Prometheus counter of the same
// snake_case name, prefixed with prefix and "_" when prefix is not
// empty (E-09). Names are read at scrape time, so a counter incremented
// for the first time after registration is exported from then on.
func Counters(reg prometheus.Registerer, prefix string, c *core.Counters) error {
	return reg.Register(&countersCollector{prefix: prefix, c: c})
}

var metricName = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

type countersCollector struct {
	prefix string
	c      *core.Counters
}

// Describe sends nothing: the names are only known at scrape time, which
// makes this an unchecked collector.
func (*countersCollector) Describe(chan<- *prometheus.Desc) {}

// Collect sends one counter per name. A name that is not a valid metric
// name is sent as an invalid metric, so the scrape reports it instead of
// dropping it silently.
func (cc *countersCollector) Collect(ch chan<- prometheus.Metric) {
	for name, v := range cc.c.Snapshot() {
		full := name
		if cc.prefix != "" {
			full = cc.prefix + "_" + name
		}
		desc := prometheus.NewDesc(full, "core.Counters "+name, nil, nil)
		if !metricName.MatchString(full) {
			ch <- prometheus.NewInvalidMetric(desc, fmt.Errorf("counter %q is not a valid metric name", full))
			continue
		}
		m, err := prometheus.NewConstMetric(desc, prometheus.CounterValue, float64(v))
		if err != nil {
			m = prometheus.NewInvalidMetric(desc, err)
		}
		ch <- m
	}
}

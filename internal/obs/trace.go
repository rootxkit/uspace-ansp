package obs

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

// Tracer is the tracer of the process and the function that flushes and
// stops it. Without ANSP_OTLP_ENDPOINT it is a no-op tracer and nothing
// is exported; with it, spans are batched to the OTLP HTTP endpoint with
// service.name uspace-ansp-<process> and the instance. Nothing is
// registered globally.
func Tracer(ctx context.Context, cfg config.Config) (trace.Tracer, func(context.Context) error, error) {
	name := "github.com/rootxkit/uspace-ansp/cmd/" + cfg.Process
	if cfg.OTLPEndpoint == "" {
		return noop.NewTracerProvider().Tracer(name), func(context.Context) error { return nil }, nil
	}
	exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(cfg.OTLPEndpoint))
	if err != nil {
		return nil, nil, fmt.Errorf("ANSP_OTLP_ENDPOINT: %w", err)
	}
	res := resource.NewSchemaless(
		attribute.String("service.name", "uspace-ansp-"+cfg.Process),
		attribute.String("service.instance.id", cfg.Instance),
	)
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	return tp.Tracer(name), tp.Shutdown, nil
}

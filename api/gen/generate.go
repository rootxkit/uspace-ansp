package gen

// oapi-codegen v2.8.0, pinned once here (the version uspace-core pins
// for its f3548 types; docs/PLAN.md section 4). It reads ../openapi.yaml
// with ../oapi-codegen.yaml and writes api.gen.go.
//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 -config ../oapi-codegen.yaml -o api.gen.go ../openapi.yaml
//go:generate go run ../internal/opsgen -spec ../openapi.yaml -o operations.gen.go -stub ../stub_gen_test.go

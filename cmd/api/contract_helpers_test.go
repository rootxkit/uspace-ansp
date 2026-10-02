package main

import (
	"encoding/json"
	"strconv"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

var (
	contractOnce sync.Once
	contractDoc  *openapi3.T
	errContract  error
)

// validateResponse holds an answer of this process to the schema
// api/openapi.yaml gives it (method, path template, status): the
// handlers write their own wire structs (float64, not the generated
// float32), so the contract is checked on what they write.
func validateResponse(t *testing.T, method, path string, status int, body []byte) {
	t.Helper()
	contractOnce.Do(func() {
		loader := openapi3.NewLoader()
		loader.IsExternalRefsAllowed = true
		contractDoc, errContract = loader.LoadFromFile("../../api/openapi.yaml")
	})
	if errContract != nil {
		t.Fatal(errContract)
	}
	item := contractDoc.Paths.Value(path)
	if item == nil || item.GetOperation(method) == nil {
		t.Fatalf("%s %s is not in the contract", method, path)
	}
	resp := item.GetOperation(method).Responses.Status(status)
	if resp == nil || resp.Value == nil {
		t.Fatalf("%s %s: %d is not a declared answer", method, path, status)
	}
	mt := resp.Value.Content.Get("application/json")
	if mt == nil {
		mt = resp.Value.Content.Get("application/problem+json")
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("%s %s: not JSON: %v", method, path, err)
	}
	if err := mt.Schema.Value.VisitJSON(v, openapi3.MultiErrors()); err != nil {
		t.Fatalf("%s %s %s: the answer breaks the contract: %v\n%s", method, path, strconv.Itoa(status), err, body)
	}
}

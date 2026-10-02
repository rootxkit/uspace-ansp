package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
)

const (
	specPath = "openapi.yaml"
	planPath = "../docs/PLAN.md"
)

var (
	specOnce sync.Once
	specDoc  *openapi3.T
	errSpec  error
)

// spec is api/openapi.yaml, loaded once (with the external reference to
// schemas/coordination/annex_v/v1.json resolved).
func spec(t testing.TB) *openapi3.T {
	t.Helper()
	specOnce.Do(func() {
		loader := openapi3.NewLoader()
		loader.IsExternalRefsAllowed = true
		specDoc, errSpec = loader.LoadFromFile(specPath)
	})
	if errSpec != nil {
		t.Fatal(errSpec)
	}
	return specDoc
}

// operation is one operation of the file with where it lives.
type operation struct {
	method, path string
	item         *openapi3.PathItem
	op           *openapi3.Operation
}

func operations(t testing.TB) []operation {
	t.Helper()
	doc := spec(t)
	var out []operation
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			out = append(out, operation{method: method, path: path, item: item, op: op})
		}
	}
	slices.SortFunc(out, func(a, b operation) int { return strings.Compare(a.method+" "+a.path, b.method+" "+b.path) })
	return out
}

// The file validates as OpenAPI (the structural lint; vacuum lints the
// style in CI).
func TestSpecValidates(t *testing.T) {
	doc := spec(t)
	if err := doc.Validate(context.Background(), openapi3.EnableExamplesValidation()); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Fatalf("openapi %q, want 3.1.0", doc.OpenAPI)
	}
}

var (
	camelCase  = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)
	processes  = []string{"api", "manned-feed", auth.ProcessEach}
	tags       = []string{"restrictions", "restriction-requests", "coordination", "manned-traffic", "adapters", "sources", "policy", "occurrences", "audit", "auth", "uss", "cis", "health"}
	problemCTs = "application/problem+json"
)

// Every operation carries operationId, one known tag, x-process, x-spec
// and an x-auth that parses, a description, security that matches its
// x-auth, and the error responses the conventions promise.
func TestEveryOperationIsDescribed(t *testing.T) {
	ids := map[string]bool{}
	for _, o := range operations(t) {
		name := o.method + " " + o.path
		op := o.op
		if !camelCase.MatchString(op.OperationID) || ids[op.OperationID] {
			t.Errorf("%s: operationId %q is not camelCase or is repeated", name, op.OperationID)
		}
		ids[op.OperationID] = true
		if len(op.Tags) != 1 || !slices.Contains(tags, op.Tags[0]) {
			t.Errorf("%s: tags %v", name, op.Tags)
		}
		process, _ := op.Extensions["x-process"].(string)
		if !slices.Contains(processes, process) {
			t.Errorf("%s: x-process %q", name, process)
		}
		if s, _ := op.Extensions["x-spec"].(string); s == "" {
			t.Errorf("%s: no x-spec", name)
		}
		xauth, _ := op.Extensions["x-auth"].(string)
		a, err := auth.ParseAccess(xauth)
		if err != nil {
			t.Errorf("%s: x-auth %q: %v", name, xauth, err)
			continue
		}
		if strings.TrimSpace(op.Description) == "" {
			t.Errorf("%s: no description", name)
		}
		checkSecurity(t, name, op, a)
		checkResponses(t, name, o, a)
	}
	if len(ids) != len(gen.Operations) {
		t.Fatalf("%d operations in the file, %d generated: run make generate", len(ids), len(gen.Operations))
	}
}

// checkSecurity holds the security requirement equal to x-auth: none
// for public and signed bodies, consoleSession for a session rule (and
// the cookie for a WebSocket), ecosystemToken with the scopes for a
// token rule.
func checkSecurity(t *testing.T, name string, op *openapi3.Operation, a auth.Access) {
	t.Helper()
	if op.Security == nil {
		t.Errorf("%s: no security (an empty list is written for public)", name)
		return
	}
	got := map[string][]string{}
	for _, req := range *op.Security {
		for scheme, scopes := range req {
			got[scheme] = scopes
		}
	}
	want := map[string][]string{}
	if len(a.Scopes) > 0 {
		want["ecosystemToken"] = a.Scopes
	}
	if a.AnyRole || len(a.Roles) > 0 {
		want["consoleSession"] = []string{}
	}
	if _, cookie := got["sessionCookie"]; cookie {
		if ws, _ := op.Extensions["x-websocket"].(bool); !ws {
			t.Errorf("%s: the session cookie is for WebSocket upgrades only", name)
		}
		want["sessionCookie"] = []string{}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("%s: security %v, x-auth %q wants %v", name, got, a.String(), want)
	}
}

// checkResponses: 401 for every restricted rule, 403 for a scope or role,
// Retry-After on every 429 and 503 problem, 101 and 426 on WebSocket
// operations, and every error a Problem.
func checkResponses(t *testing.T, name string, o operation, a auth.Access) {
	t.Helper()
	resp := o.op.Responses
	restricted := !a.Public && a.JWS == ""
	if restricted && (resp.Value("401") == nil || resp.Value("403") == nil) {
		t.Errorf("%s: a restricted operation declares 401 and 403", name)
	}
	if ws, _ := o.op.Extensions["x-websocket"].(bool); ws && (resp.Value("101") == nil || resp.Value("426") == nil) {
		t.Errorf("%s: a WebSocket operation declares 101 and 426", name)
	}
	for code, r := range resp.Map() {
		status, err := strconv.Atoi(code)
		if err != nil {
			t.Errorf("%s: response %q is not a status (no default responses)", name, code)
			continue
		}
		if status < 400 || o.path == "/readyz" {
			continue
		}
		mt := r.Value.Content.Get(problemCTs)
		if mt == nil || mt.Schema == nil || mt.Schema.Ref != "#/components/schemas/Problem" {
			t.Errorf("%s %d: not an application/problem+json Problem", name, status)
		}
		if (status == 429 || status == 503) && (r.Value.Headers["Retry-After"] == nil || !r.Value.Headers["Retry-After"].Value.Required) {
			t.Errorf("%s %d: no required Retry-After", name, status)
		}
	}
}

// The path set equals the table of docs/PLAN.md section 6, with the same
// process for each (a drift either way fails).
func TestPathsEqualThePlanTable(t *testing.T) {
	table, err := planTable(planPath)
	if err != nil {
		t.Fatal(err)
	}
	inFile := map[string]string{}
	for _, o := range operations(t) {
		p, _ := o.op.Extensions["x-process"].(string)
		inFile[o.method+" "+o.path] = p
	}
	for op, p := range table {
		if got, ok := inFile[op]; !ok {
			t.Errorf("%s is in docs/PLAN.md section 6 and not in api/openapi.yaml", op)
		} else if got != p {
			t.Errorf("%s: x-process %q, docs/PLAN.md says %q", op, got, p)
		}
	}
	for op := range inFile {
		if _, ok := table[op]; !ok {
			t.Errorf("%s is in api/openapi.yaml and not in docs/PLAN.md section 6", op)
		}
	}
}

var (
	tick     = regexp.MustCompile("`([^`]+)`")
	planOp   = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE) (/[^?\s]*)(\?\S*)?$`)
	planProc = regexp.MustCompile(`^(api|manned-feed|each)$`)
)

// planTable reads the operations table of section 6: every row whose
// first cell holds backticked "METHOD /path" entries; the second cell is
// the process. A backticked entry of another form in that cell fails.
func planTable(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	in := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "## 6."):
			in = true
			continue
		case in && strings.HasPrefix(line, "## "), in && strings.HasPrefix(line, "Outbound calls"):
			in = false
		}
		if !in || !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(line, " | ")
		if len(cells) < 2 {
			return nil, fmt.Errorf("row without cells: %s", line)
		}
		process := strings.TrimSpace(cells[1])
		if !planProc.MatchString(process) {
			return nil, fmt.Errorf("row %s: process %q", cells[0], process)
		}
		for _, m := range tick.FindAllStringSubmatch(cells[0], -1) {
			op := planOp.FindStringSubmatch(m[1])
			if op == nil {
				return nil, fmt.Errorf("%q is not METHOD /path", m[1])
			}
			out[op[1]+" "+op[2]] = process
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no operation read from %s section 6", path)
	}
	return out, sc.Err()
}

// exampleOf is the media type's example (example, or the first of
// examples by name).
func exampleOf(mt *openapi3.MediaType) (any, bool) {
	if mt == nil {
		return nil, false
	}
	if mt.Example != nil {
		return mt.Example, true
	}
	names := make([]string, 0, len(mt.Examples))
	for n := range mt.Examples {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if ex := mt.Examples[n]; ex != nil && ex.Value != nil {
			return ex.Value.Value, true
		}
	}
	return nil, false
}

// Every parameter, request body and response has an example, and every
// example validates against its schema.
func TestEveryExampleValidates(t *testing.T) {
	checked := 0
	for _, o := range operations(t) {
		name := o.method + " " + o.path
		for _, p := range append(slices.Clone(o.item.Parameters), o.op.Parameters...) {
			if p.Value.Example == nil {
				t.Errorf("%s: parameter %s has no example", name, p.Value.Name)
				continue
			}
			if err := p.Value.Schema.Value.VisitJSON(p.Value.Example); err != nil {
				t.Errorf("%s: parameter %s example: %v", name, p.Value.Name, err)
			}
			checked++
		}
		if rb := o.op.RequestBody; rb != nil {
			for ct, mt := range rb.Value.Content {
				ex, ok := exampleOf(mt)
				if !ok {
					t.Errorf("%s: request %s has no example", name, ct)
					continue
				}
				if err := mt.Schema.Value.VisitJSON(ex); err != nil {
					t.Errorf("%s: request %s example: %v", name, ct, err)
				}
				checked++
			}
		}
		for code, r := range o.op.Responses.Map() {
			if len(r.Value.Content) == 0 && code != "202" && code != "204" {
				t.Errorf("%s %s: a response without content", name, code)
			}
			for ct, mt := range r.Value.Content {
				ex, ok := exampleOf(mt)
				if !ok {
					t.Errorf("%s %s: %s has no example", name, code, ct)
					continue
				}
				if err := mt.Schema.Value.VisitJSON(ex); err != nil {
					t.Errorf("%s %s: %s example: %v", name, code, ct, err)
				}
				checked++
			}
		}
	}
	if checked < 100 {
		t.Fatalf("only %d examples checked", checked)
	}
}

// E-01: the validation that passes the examples refuses a body that
// breaks the schema (presence of the refusal), so the test above proves
// something.
func TestExampleValidationRefusesABrokenExample(t *testing.T) {
	doc := spec(t)
	op := doc.Paths.Value("/v1/restrictions").Post
	mt := op.RequestBody.Value.Content.Get("application/json")
	ex, _ := exampleOf(mt)
	broken := map[string]any{}
	for k, v := range ex.(map[string]any) {
		broken[k] = v
	}
	if err := mt.Schema.Value.VisitJSON(broken); err != nil {
		t.Fatalf("the copy of a valid example is refused: %v", err)
	}
	broken["lower_ref"] = "AGL"
	if err := mt.Schema.Value.VisitJSON(broken); err == nil {
		t.Fatal("lower_ref AGL validated (D3)")
	}
	delete(broken, "geometry")
	broken["lower_ref"] = "AMSL"
	if err := mt.Schema.Value.VisitJSON(broken); err == nil {
		t.Fatal("a body without geometry validated")
	}
	notice := doc.Components.Schemas["AnnexVNotice"].Value
	if err := notice.VisitJSON(map[string]any{"schema": "coordination/annex_v/v1", "kind": "nonconformance"}); err == nil {
		t.Fatal("an Annex V notice without its required members validated")
	}
}

// canned is a response of the stub: the example of one status.
type canned struct {
	status int
	ctype  string
	body   []byte
}

func (c canned) visit(w http.ResponseWriter) error {
	if c.ctype != "" {
		w.Header().Set("Content-Type", c.ctype)
	}
	if c.status == http.StatusTooManyRequests || c.status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(c.status)
	_, err := w.Write(c.body)
	return err
}

// primary is the status the stub answers for an operation: its main
// success, or 426 for a WebSocket upgrade asked over plain HTTP.
func primary(op *openapi3.Operation) int {
	if ws, _ := op.Extensions["x-websocket"].(bool); ws {
		return http.StatusUpgradeRequired
	}
	for _, s := range []int{201, 202, 200, 204} {
		if op.Responses.Value(strconv.Itoa(s)) != nil {
			return s
		}
	}
	return 0
}

// cannedFor renders the example of status as the stub's answer.
func cannedFor(t *testing.T, name string, op *openapi3.Operation, status int) canned {
	t.Helper()
	r := op.Responses.Value(strconv.Itoa(status))
	if r == nil {
		t.Fatalf("%s: no %d response", name, status)
	}
	for ct, mt := range r.Value.Content {
		ex, _ := exampleOf(mt)
		if s, ok := ex.(string); ok && !strings.Contains(ct, "json") {
			return canned{status: status, ctype: ct, body: []byte(s)}
		}
		raw, err := json.Marshal(ex)
		if err != nil {
			t.Fatal(err)
		}
		return canned{status: status, ctype: ct, body: raw}
	}
	return canned{status: status}
}

// registerDecoders lets openapi3filter read this file's media types for
// the duration of a test, restoring the registry after (E-11).
func registerDecoders(t *testing.T) {
	t.Helper()
	for ct, dec := range map[string]openapi3filter.BodyDecoder{
		"application/jose":         openapi3filter.PlainBodyDecoder,
		"application/jwk-set+json": openapi3filter.JSONBodyDecoder,
		"application/problem+json": openapi3filter.JSONBodyDecoder,
	} {
		if openapi3filter.RegisteredBodyDecoder(ct) != nil {
			continue
		}
		openapi3filter.RegisterBodyDecoder(ct, dec)
		t.Cleanup(func() { openapi3filter.UnregisterBodyDecoder(ct) })
	}
}

// call is one operation called through the generated client.
type call struct {
	o      operation
	params map[string]string // path parameter values
}

// validatingServer is the strict server of api/gen over the stub, behind
// a request validator (the openapi3filter middleware of the brief): a
// request that breaks the contract is 400 and never reaches the stub.
func validatingServer(t *testing.T, current *call, seen map[string]any) http.Handler {
	t.Helper()
	stub := exampleStub{answer: func(op string, request any) canned {
		seen[op] = request
		return cannedFor(t, op, current.o.op, primary(current.o.op))
	}}
	strict := gen.NewStrictHandlerWithOptions(stub, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			apierr.WriteError(w, r, apierr.New(http.StatusBadRequest, apierr.SlugInvalidRequest, err.Error()))
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			t.Errorf("%s: response error %v", current.o.op.OperationID, err)
			apierr.WriteError(w, r, err)
		},
	})
	h := gen.Handler(strict)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := openapi3filter.ValidateRequest(r.Context(), requestInput(t, current, r)); err != nil {
			apierr.WriteError(w, r, apierr.New(http.StatusBadRequest, apierr.SlugInvalidRequest, "the request breaks the contract"))
			return
		}
		h.ServeHTTP(w, r)
	})
}

func requestInput(t *testing.T, c *call, r *http.Request) *openapi3filter.RequestValidationInput {
	t.Helper()
	return &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: c.params,
		Route:      &routers.Route{Spec: spec(t), Path: c.o.path, PathItem: c.o.item, Method: c.o.method, Operation: c.o.op},
		Options:    &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
	}
}

// responseValidator checks every answer against the operation's
// response schema on the client's side.
type responseValidator struct {
	t       *testing.T
	current *call
	checked int
}

func (v *responseValidator) RoundTrip(r *http.Request) (*http.Response, error) {
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	in := requestInput(v.t, v.current, r)
	in.Request.Body = io.NopCloser(bytes.NewReader(reqBody))
	if err := openapi3filter.ValidateResponse(r.Context(), &openapi3filter.ResponseValidationInput{
		RequestValidationInput: in, Status: resp.StatusCode, Header: resp.Header, Body: io.NopCloser(bytes.NewReader(body)),
		Options: &openapi3filter.Options{IncludeResponseStatus: true},
	}); err != nil {
		v.t.Errorf("%s: the answer breaks the contract: %v", v.current.o.op.OperationID, err)
	}
	v.checked++
	return resp, nil
}

var pathParam = regexp.MustCompile(`\{([^}]+)\}`)

// The generated client calls every operation against the strict server
// over the stub: every example request passes request validation and
// is decoded into its typed request object, every example response
// passes response validation and is parsed into its typed field
// (presence of every route, the brief's contract tests).
func TestClientCallsEveryOperation(t *testing.T) {
	registerDecoders(t)
	current := &call{}
	seen := map[string]any{}
	srv := httptest.NewServer(validatingServer(t, current, seen))
	t.Cleanup(srv.Close)
	rv := &responseValidator{t: t, current: current}
	cl, err := gen.NewClientWithResponses(srv.URL, gen.WithHTTPClient(&http.Client{Transport: rv}))
	if err != nil {
		t.Fatal(err)
	}
	clv := reflect.ValueOf(cl)
	for _, o := range operations(t) {
		*current = call{o: o, params: map[string]string{}}
		name := strings.ToUpper(o.op.OperationID[:1]) + o.op.OperationID[1:]
		m := clv.MethodByName(name + "WithResponse")
		withBody := false
		if !m.IsValid() {
			m, withBody = clv.MethodByName(name+"WithBodyWithResponse"), true
		}
		if !m.IsValid() {
			t.Errorf("%s: the client has no method", o.op.OperationID)
			continue
		}
		args := clientArgs(t, current, m.Type(), withBody)
		out := m.Call(args)
		if !out[1].IsNil() {
			t.Errorf("%s: %v", o.op.OperationID, out[1].Interface())
			continue
		}
		want := primary(o.op)
		res := out[0]
		if got := res.MethodByName("StatusCode").Call(nil)[0].Int(); int(got) != want {
			t.Errorf("%s: status %d, want %d (%s)", o.op.OperationID, got, want, res.Elem().FieldByName("Body").Bytes())
			continue
		}
		if _, ok := seen[o.op.OperationID]; !ok {
			t.Errorf("%s: the stub was not reached", o.op.OperationID)
		}
		checkParsed(t, o, res, want)
	}
	if rv.checked != len(gen.Operations) || len(seen) != len(gen.Operations) {
		t.Fatalf("%d answers validated and %d operations reached, of %d", rv.checked, len(seen), len(gen.Operations))
	}
}

// checkParsed: a JSON answer is parsed into its typed field.
func checkParsed(t *testing.T, o operation, res reflect.Value, status int) {
	t.Helper()
	r := o.op.Responses.Value(strconv.Itoa(status))
	if r == nil || len(r.Value.Content) == 0 {
		return
	}
	for ct := range r.Value.Content {
		if !strings.Contains(ct, "json") {
			return
		}
	}
	el := res.Elem()
	for i := range el.NumField() {
		f := el.Field(i)
		name := el.Type().Field(i).Name
		if f.Kind() == reflect.Pointer && strings.HasSuffix(name, strconv.Itoa(status)) && !f.IsNil() {
			return
		}
	}
	t.Errorf("%s: the %d answer was not parsed into a typed field", o.op.OperationID, status)
}

// clientArgs builds the arguments of a client method from the
// examples: the path parameters in path order, the parameters struct,
// then the JSON body (or content type and reader).
func clientArgs(t *testing.T, c *call, mt reflect.Type, withBody bool) []reflect.Value {
	t.Helper()
	o := c.o
	args := []reflect.Value{reflect.ValueOf(context.Background())}
	examples := map[string]any{}
	query := map[string]any{}
	for _, p := range append(slices.Clone(o.item.Parameters), o.op.Parameters...) {
		examples[p.Value.Name] = p.Value.Example
		if p.Value.In != openapi3.ParameterInPath {
			query[p.Value.Name] = p.Value.Example
		}
	}
	i := 1
	for _, m := range pathParam.FindAllStringSubmatch(o.path, -1) {
		v := reflect.New(mt.In(i))
		raw, _ := json.Marshal(examples[m[1]])
		if err := json.Unmarshal(raw, v.Interface()); err != nil {
			t.Fatalf("%s: path parameter %s: %v", o.op.OperationID, m[1], err)
		}
		c.params[m[1]] = fmt.Sprint(examples[m[1]])
		args = append(args, v.Elem())
		i++
	}
	if in := mt.In(i); in.Kind() == reflect.Pointer && in.Elem().Kind() == reflect.Struct && strings.HasSuffix(in.Elem().Name(), "Params") {
		v := reflect.New(in.Elem())
		raw, _ := json.Marshal(query)
		if err := json.Unmarshal(raw, v.Interface()); err != nil {
			t.Fatalf("%s: parameters: %v", o.op.OperationID, err)
		}
		args = append(args, v)
		i++
	}
	if rb := o.op.RequestBody; rb != nil {
		for ct, media := range rb.Value.Content {
			ex, _ := exampleOf(media)
			if withBody {
				body, ok := ex.(string)
				if !ok {
					raw, _ := json.Marshal(ex)
					body = string(raw)
				}
				args = append(args, reflect.ValueOf(ct), reflect.ValueOf(io.Reader(strings.NewReader(body))))
				i += 2
				break
			}
			v := reflect.New(mt.In(i))
			raw, _ := json.Marshal(ex)
			if err := json.Unmarshal(raw, v.Interface()); err != nil {
				t.Fatalf("%s: body: %v", o.op.OperationID, err)
			}
			args = append(args, v.Elem())
			i++
			break
		}
	}
	if i != mt.NumIn()-1 {
		t.Fatalf("%s: built %d arguments of %d", o.op.OperationID, i, mt.NumIn()-1)
	}
	return args
}

// E-01: the request validator in front of the strict server refuses a
// request that breaks the contract and the stub is not reached; the
// same request with the example body is served.
func TestRequestValidationRefuses(t *testing.T) {
	registerDecoders(t)
	doc := spec(t)
	item := doc.Paths.Value("/v1/coordination/notices")
	current := &call{o: operation{method: http.MethodPost, path: "/v1/coordination/notices", item: item, op: item.Post}, params: map[string]string{}}
	seen := map[string]any{}
	srv := httptest.NewServer(validatingServer(t, current, seen))
	t.Cleanup(srv.Close)
	ex, _ := exampleOf(item.Post.RequestBody.Value.Content.Get("application/json"))
	good, _ := json.Marshal(ex)
	post := func(body []byte) int {
		resp, err := http.Post(srv.URL+"/v1/coordination/notices", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := post(good); got != http.StatusAccepted || seen["submitCoordinationNotice"] == nil {
		t.Fatalf("the example: %d", got)
	}
	delete(seen, "submitCoordinationNotice")
	bad := bytes.Replace(good, []byte(`"kind":"nonconformance"`), []byte(`"kind":"chatter"`), 1)
	if bytes.Equal(bad, good) {
		t.Fatal("the example has no kind to break")
	}
	if got := post(bad); got != http.StatusBadRequest || seen["submitCoordinationNotice"] != nil {
		t.Fatalf("a broken notice: %d", got)
	}
}

// mirror is a component of this file and the JSON Schema object it
// mirrors: the same required members and the same property names, but
// for the extras this system adds (named here, never silently).
type mirror struct {
	component, file string
	pointer         []string
	extras          []string
	dropRequired    []string
}

var mirrors = []mirror{
	{"MannedTrack", "../schemas/track/manned/v1.json", []string{"$defs", "body"}, nil, nil},
	{"RestrictionStateBody", "../schemas/restriction/state/v1.json", []string{"$defs", "body"}, nil, nil},
	{"Problem", "../schemas/common/problem/v1/schema.json", nil, nil, nil},
	{"EnvelopeHeader", "../schemas/common/envelope/v1/schema.json", nil, nil, []string{"schema", "body"}},
	{"SourceStatusBody", "../schemas/common/source/status/v1/schema.json", []string{"$defs", "body"}, nil, nil},
	{"ConsoleStatus", "../schemas/common/console/status/v1/schema.json", []string{"$defs", "body"}, []string{"adapters"}, nil},
	{"ConsoleSnapshot", "../schemas/common/console/snapshot/v1/schema.json", []string{"$defs", "body"}, []string{"restrictions", "notices"}, nil},
	{"ConsoleSubscribeFrame", "../schemas/common/console/subscribe/v1/schema.json", nil, nil, nil},
}

// Every component that mirrors a JSON Schema (this system's own, or the
// lab's pinned common ones) has its required members and its property
// names; the lab's optional extras of other systems may be left out.
func TestComponentsMirrorTheSchemas(t *testing.T) {
	doc := spec(t)
	for _, m := range mirrors {
		raw, err := os.ReadFile(m.file)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatalf("%s: %v", m.file, err)
		}
		for _, k := range m.pointer {
			obj, _ = obj[k].(map[string]any)
		}
		var want []string
		for _, r := range obj["required"].([]any) {
			if !slices.Contains(m.dropRequired, r.(string)) {
				want = append(want, r.(string))
			}
		}
		props := obj["properties"].(map[string]any)
		comp := doc.Components.Schemas[m.component].Value
		got := slices.Clone(comp.Required)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: required %v, %s requires %v", m.component, got, m.file, want)
		}
		for name := range comp.Properties {
			if _, ok := props[name]; !ok && !slices.Contains(m.extras, name) {
				t.Errorf("%s.%s is not in %s and is not a named extra", m.component, name, m.file)
			}
		}
		for name := range props {
			_, ok := comp.Properties[name]
			if !ok && slices.Contains(want, name) {
				t.Errorf("%s lacks the required %s of %s", m.component, name, m.file)
			}
			if !ok && strings.HasPrefix(m.file, "../schemas/") && !strings.Contains(m.file, "/common/") && name != "schema" && name != "body" {
				t.Errorf("%s lacks %s of this system's own %s", m.component, name, m.file)
			}
		}
	}
}

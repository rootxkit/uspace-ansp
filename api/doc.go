// Package api holds the published national API of the ANSP,
// api/openapi.yaml (OpenAPI 3.1, CLAUDE.md rule 7), and its contract
// tests: the file lints and validates; every operation carries x-spec,
// x-auth and x-process, and its path set equals the table of
// docs/PLAN.md section 6; every example validates against its schema;
// every example request passes the request validation in front of the
// generated strict server and every example response passes response
// validation; and the generated client calls every operation against a
// stub of that server. The generated code is api/gen (see README.md);
// the pinned sibling OpenAPI copies are api/clients.
package api

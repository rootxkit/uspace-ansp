// Package storetest gives integration tests a scratch database of their
// own: created from template0 on the server of ANSP_RELATIONAL_DSN or
// ANSP_TIMESERIES_DSN, optionally migrated, dropped when the test ends.
// Without the variable the test is skipped and says which one is unset
// (E-04). Test code only.
package storetest

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rootxkit/uspace-ansp/internal/store"
)

// Variable is the environment variable naming the server of tree.
func Variable(tree store.Tree) string {
	if tree.Name == store.TreeRelational.Name {
		return "ANSP_RELATIONAL_DSN"
	}
	return "ANSP_TIMESERIES_DSN"
}

var seq atomic.Int64

// Scratch creates an empty database on tree's server and returns its
// DSN (the login role of the variable, a superuser in CI and compose).
// With migrate it applies tree first.
func Scratch(t testing.TB, tree store.Tree, migrate bool) string {
	t.Helper()
	admin := os.Getenv(Variable(tree))
	if admin == "" {
		t.Skipf("%s is not set: needs the integration databases (CI services or make compose-up)", Variable(tree))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	name := fmt.Sprintf("wp1_%s_%d_%d", tree.Name, time.Now().UnixNano(), seq.Add(1))
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect to %s: %v", Variable(tree), err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE template0"); err != nil { //nolint:misspell // pgx API name
		t.Fatalf("create scratch database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, admin)
		if err != nil {
			t.Errorf("drop scratch database %s: %v", name, err)
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil { //nolint:misspell // pgx API name
			t.Errorf("drop scratch database %s: %v", name, err)
		}
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("%s is not a URL", Variable(tree))
	}
	u.Path = "/" + name
	dsn := u.String()
	if migrate {
		if _, err := store.Migrate(ctx, dsn, tree); err != nil {
			t.Fatalf("migrate %s: %v", tree.Name, err)
		}
	}
	return dsn
}

// Pool is a test pool configuration: small, short bounds, as role.
func Pool(role string) store.PoolConfig {
	return store.PoolConfig{
		MaxConns:         4,
		AcquireTimeout:   5 * time.Second,
		StatementTimeout: 10 * time.Second,
		TxTimeout:        30 * time.Second,
		Role:             role,
		ApplicationName:  "ansp-test",
	}
}

// Relational opens the migrated scratch relational database as role.
func Relational(t testing.TB, dsn, role string) *store.Relational {
	t.Helper()
	db, err := store.OpenRelational(context.Background(), dsn, Pool(role), nil)
	if err != nil {
		t.Fatalf("open relational: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// Timeseries opens the migrated scratch timeseries database as role.
func Timeseries(t testing.TB, dsn, role string) *store.Timeseries {
	t.Helper()
	db, err := store.OpenTimeseries(context.Background(), dsn, Pool(role), nil)
	if err != nil {
		t.Fatalf("open timeseries: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

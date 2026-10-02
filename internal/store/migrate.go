package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver goose runs on
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/migrations"
)

// Tree is one of the two migration trees: its own database, its own
// version table and its own advisory lock, never merged with the other
// (CLAUDE.md rule 6).
type Tree struct {
	Name         string // "relational" or "timeseries"
	VersionTable string
	// LockID is the session advisory lock held while the tree migrates,
	// so two migrate runs never interleave on one database.
	LockID int64
	fsys   fs.FS
}

// FS is the tree's embedded SQL files.
func (t Tree) FS() fs.FS { return t.fsys }

// The two trees with the version-table names of docs/PLAN.md section 5.3.
var (
	TreeRelational = Tree{Name: "relational", VersionTable: "goose_db_version_relational", LockID: 0x616e737001, fsys: sub(migrations.Relational, "relational")}
	TreeTimeseries = Tree{Name: "timeseries", VersionTable: "goose_db_version_timeseries", LockID: 0x616e737002, fsys: sub(migrations.Timeseries, "timeseries")}
)

// Trees lists both trees in the order `migrate` applies them.
func Trees() []Tree { return []Tree{TreeRelational, TreeTimeseries} }

// TreeByName is the tree called name.
func TreeByName(name string) (Tree, bool) {
	for _, t := range Trees() {
		if t.Name == name {
			return t, true
		}
	}
	return Tree{}, false
}

func sub(fsys fs.FS, dir string) fs.FS {
	s, err := fs.Sub(fsys, dir)
	if err != nil {
		// fs.Sub fails only for an invalid path literal; the tests read
		// both trees, so this branch never ships unnoticed.
		return fsys
	}
	return s
}

// Latest is the newest migration embedded in tree: the schema version a
// process of this build needs.
func Latest(tree Tree) (int64, error) {
	vs, err := Versions(tree)
	if err != nil {
		return 0, err
	}
	return vs[len(vs)-1], nil
}

// Versions are the versions of every migration embedded in tree, in
// ascending order. They are numbered in ranges reserved per work
// package (docs/PLAN.md section 5.3), so they are not contiguous: the
// version below the latest is Versions[len-2], never latest-1.
func Versions(tree Tree) ([]int64, error) {
	entries, err := fs.ReadDir(tree.fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("%s: read embedded tree: %w", tree.Name, err)
	}
	var out []int64
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		digits, _, ok := strings.Cut(name, "_")
		v, err := strconv.ParseInt(digits, 10, 64)
		if !ok || err != nil || v <= 0 {
			return nil, fmt.Errorf("%s: %s is not named NNNN_<slug>.sql", tree.Name, name)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no migration embedded", tree.Name)
	}
	slices.Sort(out)
	return out, nil
}

// openSQL opens a database/sql handle for goose; the parse error is not
// repeated because the DSN may carry a password.
func openSQL(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, &core.FieldError{Field: "dsn", Reason: "not a valid PostgreSQL connection string"}
	}
	db.SetMaxOpenConns(2)
	return db, nil
}

func provider(db *sql.DB, tree Tree) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(tree.LockID))
	if err != nil {
		return nil, fmt.Errorf("%s: session locker: %w", tree.Name, err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, tree.fsys,
		goose.WithTableName(tree.VersionTable),
		goose.WithSessionLocker(locker),
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return nil, fmt.Errorf("%s: goose provider: %w", tree.Name, err)
	}
	return p, nil
}

// Migrated is what Migrate did.
type Migrated struct {
	Tree    string
	From    int64
	To      int64
	Applied int
}

// Migrate applies every pending migration of tree to the database at
// dsn, under the tree's advisory lock, and says from which version to
// which. Only the migrate subcommand calls it (M36): no long-running
// process migrates.
func Migrate(ctx context.Context, dsn string, tree Tree) (Migrated, error) {
	out := Migrated{Tree: tree.Name}
	db, err := openSQL(dsn)
	if err != nil {
		return out, err
	}
	defer func() { _ = db.Close() }()
	if err := refuseOtherTree(ctx, db, tree); err != nil {
		return out, err
	}
	p, err := provider(db, tree)
	if err != nil {
		return out, err
	}
	if out.From, err = p.GetDBVersion(ctx); err != nil {
		return out, fmt.Errorf("%s: read version: %w", tree.Name, err)
	}
	res, err := p.Up(ctx)
	out.Applied = len(res)
	if err != nil {
		return out, fmt.Errorf("%s: up: %w", tree.Name, err)
	}
	if out.To, err = p.GetDBVersion(ctx); err != nil {
		return out, fmt.Errorf("%s: read version: %w", tree.Name, err)
	}
	return out, nil
}

// ErrWrongDatabase is a tree run against the other tree's database.
var ErrWrongDatabase = errors.New("database belongs to the other migration tree")

// refuseOtherTree refuses to migrate a database that holds the other
// tree's version table: two trees, two databases (docs/PLAN.md 5.3).
func refuseOtherTree(ctx context.Context, db *sql.DB, tree Tree) error {
	for _, other := range Trees() {
		if other.Name == tree.Name {
			continue
		}
		var found bool
		err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, other.VersionTable).Scan(&found)
		if err != nil {
			return fmt.Errorf("%s: inspect database: %w", tree.Name, err)
		}
		if found {
			return fmt.Errorf("%w: the %s tree refused, this database holds %s", ErrWrongDatabase, tree.Name, other.VersionTable)
		}
	}
	return nil
}

// DownTo rolls tree back to version (0 removes every migration). Tests
// and an operator's runbook call it; no process does.
func DownTo(ctx context.Context, dsn string, tree Tree, version int64) error {
	db, err := openSQL(dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	p, err := provider(db, tree)
	if err != nil {
		return err
	}
	if _, err := p.DownTo(ctx, version); err != nil {
		return fmt.Errorf("%s: down to %d: %w", tree.Name, version, err)
	}
	return nil
}

// ErrSchemaTooOld is the start-up refusal of a process whose database is
// behind its build (M36).
var ErrSchemaTooOld = errors.New("schema older than this build needs")

// CheckVersion refuses got below need, naming the tree, the version
// present and the one needed.
func CheckVersion(tree Tree, got, need int64) error {
	if got < need {
		return fmt.Errorf("%w: the %s tree is at version %d, this build needs %d; run `migrate %s` first",
			ErrSchemaTooOld, tree.Name, got, need, tree.Name)
	}
	return nil
}

package relational

import "hash/fnv"

// This file is hand-written beside the sqlc output: sqlc writes only its
// own files (db.go, models.go, *.sql.go) and never touches it.

// LockKey derives an advisory lock key from a resource name, so keys
// are named in code, never numbered by hand.
func LockKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64())
}

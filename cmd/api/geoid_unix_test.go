//go:build linux || darwin

package main

import "testing"

// On linux and darwin the api process maps ANSP_GEOID_FILE read-only,
// shared in the page cache with the other processes on the host. The
// twin for every other platform is geoid_other_test.go.
func TestGeoidLoadsThroughTheMappedPath(t *testing.T) {
	checkGeoidLoad(t, true)
}

//go:build integration

package main

import "testing"

// TestIntegrationPlantedFailure is planted to prove that a failing test fails the job.
func TestIntegrationPlantedFailure(t *testing.T) {
	t.Fatal("planted failure: this test must fail the job")
}

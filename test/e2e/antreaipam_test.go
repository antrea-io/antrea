package e2e

import (
	"testing"
)

func TestAntreaIPAM(t *testing.T) {
	skipIfNotAntreaIPAMTest(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// Run test cases here.
}

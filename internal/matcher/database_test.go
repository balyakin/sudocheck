package matcher

import (
	"testing"

	"github.com/evgenybalyakin/sudocheck/internal/scanner"
)

func TestNormalizeBinaryCandidatesHandlesVersionSuffix(t *testing.T) {
	candidates := NormalizeBinaryCandidates("python3.11")

	expected := []string{"python3.11", "python3", "python"}
	if len(candidates) != len(expected) {
		t.Fatalf("unexpected candidate count: %v", candidates)
	}
	for index, value := range expected {
		if candidates[index] != value {
			t.Fatalf("candidate %d: expected %s, got %s", index, value, candidates[index])
		}
	}
}

func TestDefaultDatabaseMatchesPythonCapabilities(t *testing.T) {
	database, err := LoadDefaultDatabase()
	if err != nil {
		t.Fatal(err)
	}

	match, ok := database.Match("python3.11", scanner.SourceCapabilities)
	if !ok {
		t.Fatal("expected python capability match")
	}
	if match.BinaryName != "python" {
		t.Fatalf("unexpected match name: %s", match.BinaryName)
	}
	if len(match.Functions) == 0 {
		t.Fatal("expected matched functions")
	}
}

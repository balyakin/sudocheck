package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/balyakin/sudocheck/internal/model"
)

func TestNewScanCommandUsesMediumSeverityDefault(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	exitCode := exitOK
	command := newScanCommand(&stdout, &stderr, "dev", &exitCode)

	flag := command.Flags().Lookup("severity")
	if flag == nil {
		t.Fatal("expected severity flag")
	}
	if flag.DefValue != string(model.SeverityMedium) {
		t.Fatalf("expected medium severity default, got %s", flag.DefValue)
	}
}

func TestExitForFindingsFailsOnMedium(t *testing.T) {
	findings := []model.Finding{
		{
			Severity: model.SeverityMedium,
		},
	}

	exitCode := exitForFindings(findings, model.SeverityMedium)

	if exitCode == exitOK {
		t.Fatal("expected non-zero exit code")
	}
}

func TestRunScanConfigRefusesRootUser(t *testing.T) {
	runAsRootForTest(t)

	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	exitCode := runScanConfig(scanConfig{}, &stdout, &stderr, "dev")

	if exitCode != exitUsage {
		t.Fatalf("expected usage exit code, got %d", exitCode)
	}
	if stdout.String() != "" {
		t.Fatalf("expected empty stdout, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), rootScanGuidance) {
		t.Fatalf("expected root guidance in stderr, got %q", stderr.String())
	}
}

func TestRunBaselineInitConfigRefusesRootUser(t *testing.T) {
	runAsRootForTest(t)

	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	config := baselineInitConfig{output: "sudocheck.baseline.json"}

	exitCode := runBaselineInitConfig(config, &stdout, &stderr)

	if exitCode != exitUsage {
		t.Fatalf("expected usage exit code, got %d", exitCode)
	}
	if stdout.String() != "" {
		t.Fatalf("expected empty stdout, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), rootScanGuidance) {
		t.Fatalf("expected root guidance in stderr, got %q", stderr.String())
	}
}

func runAsRootForTest(t *testing.T) {
	t.Helper()

	originalGetEffectiveUserID := getEffectiveUserID
	getEffectiveUserID = func() int {
		return rootUserID
	}
	t.Cleanup(func() {
		getEffectiveUserID = originalGetEffectiveUserID
	})
}

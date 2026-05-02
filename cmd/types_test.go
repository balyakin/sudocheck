package cmd

import (
	"bytes"
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

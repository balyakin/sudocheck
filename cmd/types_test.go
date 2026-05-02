package cmd

import (
	"testing"

	"github.com/evgenybalyakin/sudocheck/internal/model"
)

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

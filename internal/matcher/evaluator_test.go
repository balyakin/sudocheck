package matcher

import (
	"testing"

	"github.com/balyakin/sudocheck/internal/model"
	"github.com/balyakin/sudocheck/internal/scanner"
)

func TestBuildFindingsMarksNoPasswdVimCritical(t *testing.T) {
	database, err := LoadDefaultDatabase()
	if err != nil {
		t.Fatal(err)
	}
	result := scanner.Result{
		SudoRules: []scanner.SudoRule{
			{
				Binary:     "/usr/bin/vim",
				BinaryName: "vim",
				RunAs:      "ALL",
				NoPasswd:   true,
				RawLine:    "(ALL) NOPASSWD: /usr/bin/vim",
			},
		},
	}

	findings := BuildFindings(result, database)

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", findings[0].Severity)
	}
	if findings[0].Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}
}

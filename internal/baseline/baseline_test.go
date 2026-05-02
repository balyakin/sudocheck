package baseline

import (
	"testing"

	"github.com/evgenybalyakin/sudocheck/internal/model"
)

func TestApplySuppressesKnownFinding(t *testing.T) {
	finding := model.Finding{
		Fingerprint: "abc",
		Severity:    model.SeverityHigh,
		Source:      "sudo",
		Binary:      "/usr/bin/vim",
		BinaryName:  "vim",
	}
	base := Baseline{
		Findings: []BaselineFinding{
			{
				Fingerprint: "abc",
				Severity:    model.SeverityHigh,
			},
		},
	}

	active, suppressed := Apply(base, []model.Finding{finding})

	if len(active) != 0 {
		t.Fatalf("expected no active findings, got %d", len(active))
	}
	if len(suppressed) != 1 {
		t.Fatalf("expected one suppressed finding, got %d", len(suppressed))
	}
}

func TestParseIgnoreRulesRequiresReason(t *testing.T) {
	content := `ignore:
  - source: sudo
    binary_name: vim`

	_, err := ParseIgnoreRules(content)

	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestApplyIgnoreRulesSuppressesMatchingFinding(t *testing.T) {
	content := `ignore:
  - source: sudo
    binary_name: vim
    reason: accepted risk`
	rules, err := ParseIgnoreRules(content)
	if err != nil {
		t.Fatal(err)
	}

	findings := []model.Finding{
		{
			Severity:   model.SeverityHigh,
			Source:     "sudo",
			BinaryName: "vim",
		},
	}

	active, suppressed := ApplyIgnoreRules(rules, findings)

	if len(active) != 0 {
		t.Fatalf("expected no active findings, got %d", len(active))
	}
	if len(suppressed) != 1 {
		t.Fatalf("expected one suppressed finding, got %d", len(suppressed))
	}
}

func TestDiffReportsSeverityIncrease(t *testing.T) {
	oldBaseline := Baseline{
		Findings: []BaselineFinding{
			{
				Fingerprint: "abc",
				Severity:    model.SeverityMedium,
			},
		},
	}
	newBaseline := Baseline{
		Findings: []BaselineFinding{
			{
				Fingerprint: "abc",
				Severity:    model.SeverityHigh,
			},
		},
	}

	newItems, resolved := Diff(oldBaseline, newBaseline)

	if len(newItems) != 1 {
		t.Fatalf("expected severity increase, got %d new items", len(newItems))
	}
	if len(resolved) != 0 {
		t.Fatalf("expected no resolved findings, got %d", len(resolved))
	}
}

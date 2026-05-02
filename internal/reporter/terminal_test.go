package reporter

import (
	"strings"
	"testing"

	"github.com/balyakin/sudocheck/internal/model"
)

func TestRenderTerminalMatchesSpecFindingShape(t *testing.T) {
	report := model.Report{
		Version: "v0.1.0",
		Summary: model.Summary{
			Critical: 1,
			Total:    1,
		},
		Findings: []model.Finding{
			{
				Severity:    model.SeverityCritical,
				Source:      "sudo",
				BinaryName:  "vim",
				Detail:      "NOPASSWD, run as ALL",
				Remediation: "Use sudoedit instead of vim in sudoers",
				GTFOBinsURL: "https://gtfobins.org/gtfobins/vim/#sudo",
				Exploits: []model.Exploit{
					{
						Command: "sudo vim -c ':!/bin/sh'",
					},
				},
			},
		},
	}

	output := RenderTerminal(report, Options{NoColor: true})

	expectedParts := []string{
		"sudocheck v0.1.0 — Linux privilege escalation audit",
		"❌ CRITICAL — sudo vim (NOPASSWD, run as ALL)",
		"┄┄┄",
		"Exploit:  sudo vim -c ':!/bin/sh'",
		"Risk:",
		"Fix:      Use sudoedit instead of vim in sudoers",
		"Ref:      https://gtfobins.org/gtfobins/vim/#sudo",
	}
	for _, expected := range expectedParts {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected output to contain %q, got:\n%s", expected, output)
		}
	}
}

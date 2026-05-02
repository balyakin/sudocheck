package reporter

import (
	"strings"
	"testing"

	"github.com/evgenybalyakin/sudocheck/internal/model"
)

func TestRenderJSONCanHideExploitCommands(t *testing.T) {
	report := model.Report{
		Version:   "test",
		Timestamp: "2026-05-02T00:00:00Z",
		Findings: []model.Finding{
			{
				Severity: model.SeverityCritical,
				Source:   "sudo",
				Exploits: []model.Exploit{
					{
						Type:    "sudo",
						Command: "sudo vim -c ':!/bin/sh'",
					},
				},
			},
		},
	}

	bytes, err := RenderJSON(report, Options{HideExploits: true})
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(bytes), "sudo vim") {
		t.Fatalf("expected hidden exploit command, got %s", string(bytes))
	}
}

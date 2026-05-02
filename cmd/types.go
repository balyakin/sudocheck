package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/evgenybalyakin/sudocheck/internal/model"
)

const (
	formatTerminal = "terminal"
	formatJSON     = "json"
	formatSARIF    = "sarif"

	exitOK       = 0
	exitCritical = 1
	exitHigh     = 2
	exitRuntime  = 3
	exitUsage    = 4
)

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func (values *stringList) Type() string {
	return "stringArray"
}

func exitForFindings(findings []model.Finding, failOn model.Severity) int {
	highest := model.HighestSeverity(findings)
	if !model.IsSeverityAtLeast(highest, failOn) {
		return exitOK
	}
	if model.SeverityRank(highest) >= model.SeverityRank(model.SeverityCritical) {
		return exitCritical
	}
	if model.SeverityRank(highest) >= model.SeverityRank(model.SeverityHigh) {
		return exitHigh
	}
	return exitHigh
}

func inferFormat(format string, jsonOutput bool, sarifOutput bool, reportPath string) string {
	if jsonOutput {
		return formatJSON
	}
	if sarifOutput {
		return formatSARIF
	}
	if format != "" {
		return strings.ToLower(format)
	}
	extension := strings.ToLower(filepath.Ext(reportPath))
	if extension == ".sarif" {
		return formatSARIF
	}
	if extension == ".json" {
		return formatJSON
	}
	return formatTerminal
}

func writeFile(path string, bytes []byte) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(bytes, '\n'), 0644)
}

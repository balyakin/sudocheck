package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/balyakin/sudocheck/internal/model"
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

	rootUserID       = 0
	rootScanWarning  = "sudocheck should not be run as root."
	rootScanGuidance = "Please run sudocheck as the unprivileged user you want to audit; no checks were performed."
)

var getEffectiveUserID = os.Geteuid

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

func scanIsRunningAsRoot() bool {
	return getEffectiveUserID() == rootUserID
}

func stopRootScan(stderr io.Writer) int {
	fmt.Fprintln(stderr, rootScanWarning)
	fmt.Fprintln(stderr, rootScanGuidance)
	return exitUsage
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

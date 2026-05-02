package reporter

import (
	"encoding/json"
	"strings"

	"github.com/evgenybalyakin/sudocheck/internal/model"
)

func RenderJSON(report model.Report, options Options) ([]byte, error) {
	report = prepareReport(report, options)
	return json.MarshalIndent(report, "", "  ")
}

func prepareReport(report model.Report, options Options) model.Report {
	if options.RedactHost || options.SARIFRedacted {
		report.Hostname = ""
	}
	if options.RedactUser || options.SARIFRedacted {
		report.User = ""
	}

	if options.Severity != "" {
		report.Findings = model.FilterFindingsBySeverity(report.Findings, options.Severity)
		report.Summary = model.BuildSummary(report.Findings, report.SuppressedFindings)
	}

	for index := range report.Findings {
		report.Findings[index] = prepareFinding(report.Findings[index], options)
	}
	for index := range report.SuppressedFindings {
		report.SuppressedFindings[index] = prepareFinding(report.SuppressedFindings[index], options)
	}

	return report
}

func prepareFinding(finding model.Finding, options Options) model.Finding {
	if options.HideExploits {
		for index := range finding.Exploits {
			finding.Exploits[index].Command = ""
		}
	}
	if options.RedactPaths || options.SARIFRedacted {
		finding.Binary = redactHomePath(finding.Binary)
		finding.Evidence = redactHomePath(finding.Evidence)
		finding.Remediation = redactHomePath(finding.Remediation)
		for index := range finding.Exploits {
			finding.Exploits[index].Command = redactHomePath(finding.Exploits[index].Command)
		}
	}
	return finding
}

func redactHomePath(value string) string {
	homeMarkers := []string{"/home/", "/Users/"}
	for _, marker := range homeMarkers {
		index := strings.Index(value, marker)
		if index < 0 {
			continue
		}
		rest := value[index+len(marker):]
		nextSlash := strings.Index(rest, "/")
		if nextSlash < 0 {
			return value[:index] + "$HOME"
		}
		return value[:index] + "$HOME" + rest[nextSlash:]
	}
	return value
}

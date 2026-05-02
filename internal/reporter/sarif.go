package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/balyakin/sudocheck/internal/model"
)

const defaultHelpURI = "https://github.com/balyakin/sudocheck#readme"

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func RenderSARIF(report model.Report, options Options) ([]byte, error) {
	options.SARIFRedacted = true
	report = prepareReport(report, options)

	rules := make([]sarifRule, 0, len(report.Findings))
	results := make([]sarifResult, 0, len(report.Findings))
	seenRules := map[string]bool{}

	for _, finding := range report.Findings {
		ruleID := sarifRuleID(finding)
		helpURI := finding.GTFOBinsURL
		if helpURI == "" {
			helpURI = defaultHelpURI
		}
		if !seenRules[ruleID] {
			rules = append(rules, sarifRule{
				ID:   ruleID,
				Name: fmt.Sprintf("%s %s", finding.Source, finding.BinaryName),
				ShortDescription: sarifMessage{
					Text: finding.Remediation,
				},
				HelpURI: helpURI,
			})
			seenRules[ruleID] = true
		}

		results = append(results, sarifResult{
			RuleID: ruleID,
			Level:  sarifLevel(finding.Severity),
			Message: sarifMessage{
				Text: fmt.Sprintf("%s: %s. Fix: %s", finding.Detail, finding.Evidence, finding.Remediation),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: finding.Binary},
						Region:           sarifRegion{StartLine: 1},
					},
				},
			},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "sudocheck",
						InformationURI: "https://github.com/balyakin/sudocheck",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(log, "", "  ")
}

func sarifRuleID(finding model.Finding) string {
	exploitType := "finding"
	if len(finding.Exploits) > 0 && finding.Exploits[0].Type != "" {
		exploitType = finding.Exploits[0].Type
	}
	return fmt.Sprintf("sudocheck.%s.%s.%s", finding.Source, finding.BinaryName, exploitType)
}

func sarifLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

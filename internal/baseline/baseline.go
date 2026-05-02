package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/balyakin/sudocheck/internal/model"
)

type Baseline struct {
	Version   string            `json:"version"`
	CreatedAt string            `json:"created_at"`
	Findings  []BaselineFinding `json:"findings"`
}

type BaselineFinding struct {
	Fingerprint string         `json:"fingerprint"`
	Severity    model.Severity `json:"severity"`
	Source      string         `json:"source"`
	Binary      string         `json:"binary"`
	BinaryName  string         `json:"binary_name"`
	Detail      string         `json:"detail"`
}

func New(findings []model.Finding) Baseline {
	baselineFindings := make([]BaselineFinding, 0, len(findings))
	for _, finding := range findings {
		baselineFindings = append(baselineFindings, BaselineFinding{
			Fingerprint: finding.Fingerprint,
			Severity:    finding.Severity,
			Source:      finding.Source,
			Binary:      finding.Binary,
			BinaryName:  finding.BinaryName,
			Detail:      finding.Detail,
		})
	}

	return Baseline{
		Version:   "1",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:  baselineFindings,
	}
}

func Load(path string) (Baseline, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, fmt.Errorf("read baseline %s: %w", path, err)
	}

	baseline := Baseline{}
	if err := json.Unmarshal(bytes, &baseline); err != nil {
		return Baseline{}, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	return baseline, nil
}

func Save(path string, baseline Baseline) error {
	bytes, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("render baseline: %w", err)
	}
	if err := os.WriteFile(path, append(bytes, '\n'), 0644); err != nil {
		return fmt.Errorf("write baseline %s: %w", path, err)
	}
	return nil
}

func Apply(base Baseline, findings []model.Finding) ([]model.Finding, []model.Finding) {
	known := map[string]BaselineFinding{}
	for _, finding := range base.Findings {
		known[finding.Fingerprint] = finding
	}

	active := make([]model.Finding, 0, len(findings))
	suppressed := make([]model.Finding, 0)
	for _, finding := range findings {
		previous, ok := known[finding.Fingerprint]
		if ok && model.SeverityRank(finding.Severity) <= model.SeverityRank(previous.Severity) {
			finding.SuppressionReason = "baseline"
			suppressed = append(suppressed, finding)
			continue
		}
		active = append(active, finding)
	}

	return active, suppressed
}

func Diff(oldBaseline Baseline, newBaseline Baseline) (newItems []BaselineFinding, resolved []BaselineFinding) {
	oldMap := map[string]BaselineFinding{}
	newMap := map[string]BaselineFinding{}
	for _, finding := range oldBaseline.Findings {
		oldMap[finding.Fingerprint] = finding
	}
	for _, finding := range newBaseline.Findings {
		newMap[finding.Fingerprint] = finding
	}
	for fingerprint, finding := range newMap {
		previous, ok := oldMap[fingerprint]
		if !ok {
			newItems = append(newItems, finding)
			continue
		}
		if model.SeverityRank(finding.Severity) > model.SeverityRank(previous.Severity) {
			newItems = append(newItems, finding)
		}
	}
	for fingerprint, finding := range oldMap {
		if _, ok := newMap[fingerprint]; !ok {
			resolved = append(resolved, finding)
		}
	}
	return newItems, resolved
}

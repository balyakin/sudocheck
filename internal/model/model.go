package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"sort"
	"strings"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

var severityOrder = []Severity{
	SeverityCritical,
	SeverityHigh,
	SeverityMedium,
	SeverityLow,
	SeverityInfo,
}

type Exploit struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
}

type Finding struct {
	Fingerprint       string    `json:"fingerprint"`
	Severity          Severity  `json:"severity"`
	Source            string    `json:"source"`
	Binary            string    `json:"binary"`
	BinaryName        string    `json:"binary_name"`
	Detail            string    `json:"detail"`
	Evidence          string    `json:"evidence"`
	Exploits          []Exploit `json:"exploits,omitempty"`
	Remediation       string    `json:"remediation"`
	GTFOBinsURL       string    `json:"gtfobins_url,omitempty"`
	SuppressionReason string    `json:"suppression_reason,omitempty"`
}

type ScannerStatus struct {
	Status   string   `json:"status"`
	Warnings []string `json:"warnings"`
}

type Summary struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Info       int `json:"info"`
	Suppressed int `json:"suppressed"`
	Total      int `json:"total"`
}

type Report struct {
	Version            string                   `json:"version"`
	Timestamp          string                   `json:"timestamp"`
	Hostname           string                   `json:"hostname,omitempty"`
	User               string                   `json:"user,omitempty"`
	Summary            Summary                  `json:"summary"`
	Scanners           map[string]ScannerStatus `json:"scanners"`
	Findings           []Finding                `json:"findings"`
	SuppressedFindings []Finding                `json:"suppressed_findings,omitempty"`
	Demo               bool                     `json:"demo,omitempty"`
}

func ParseSeverity(value string) (Severity, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" || normalized == "all" {
		return SeverityInfo, nil
	}

	for _, severity := range severityOrder {
		if string(severity) == normalized {
			return severity, nil
		}
	}

	return SeverityInfo, fmt.Errorf("unknown severity %q", value)
}

func SeverityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func IsSeverityAtLeast(severity Severity, threshold Severity) bool {
	return SeverityRank(severity) >= SeverityRank(threshold)
}

func SeverityList() []Severity {
	values := make([]Severity, len(severityOrder))
	copy(values, severityOrder)
	return values
}

func BuildFingerprint(finding Finding) string {
	command := ""
	if len(finding.Exploits) > 0 {
		command = finding.Exploits[0].Command
	}

	exploitType := ""
	if len(finding.Exploits) > 0 {
		exploitType = finding.Exploits[0].Type
	}

	parts := []string{
		finding.Source,
		finding.Binary,
		finding.BinaryName,
		finding.Detail,
		exploitType,
		normalizeFingerprintValue(command),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(leftIndex int, rightIndex int) bool {
		left := findings[leftIndex]
		right := findings[rightIndex]
		leftRank := SeverityRank(left.Severity)
		rightRank := SeverityRank(right.Severity)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		if left.BinaryName != right.BinaryName {
			return left.BinaryName < right.BinaryName
		}
		return left.Binary < right.Binary
	})
}

func BuildSummary(findings []Finding, suppressed []Finding) Summary {
	summary := Summary{}
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityCritical:
			summary.Critical++
		case SeverityHigh:
			summary.High++
		case SeverityMedium:
			summary.Medium++
		case SeverityLow:
			summary.Low++
		case SeverityInfo:
			summary.Info++
		}
	}
	summary.Suppressed = len(suppressed)
	summary.Total = len(findings)
	return summary
}

func NewReport(version string, findings []Finding, suppressed []Finding, scanners map[string]ScannerStatus) Report {
	hostname, hostnameErr := os.Hostname()
	if hostnameErr != nil {
		hostname = ""
	}

	username := ""
	currentUser, userErr := user.Current()
	if userErr == nil {
		username = currentUser.Username
	}

	SortFindings(findings)
	SortFindings(suppressed)

	return Report{
		Version:            version,
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
		Hostname:           hostname,
		User:               username,
		Summary:            BuildSummary(findings, suppressed),
		Scanners:           scanners,
		Findings:           findings,
		SuppressedFindings: suppressed,
	}
}

func FilterFindingsBySeverity(findings []Finding, threshold Severity) []Finding {
	filtered := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if IsSeverityAtLeast(finding.Severity, threshold) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func HighestSeverity(findings []Finding) Severity {
	highest := SeverityInfo
	for _, finding := range findings {
		if SeverityRank(finding.Severity) > SeverityRank(highest) {
			highest = finding.Severity
		}
	}
	return highest
}

func normalizeFingerprintValue(value string) string {
	fields := strings.Fields(value)
	return strings.Join(fields, " ")
}

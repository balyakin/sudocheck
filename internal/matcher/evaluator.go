package matcher

import (
	"fmt"
	"strings"

	"github.com/balyakin/sudocheck/internal/model"
	"github.com/balyakin/sudocheck/internal/scanner"
)

const (
	unrestrictedSudoBinary  = "ALL"
	expectedSUIDRemediation = "Expected system SUID/SGID binary; verify package ownership " +
		"and keep elevated bit only if required"
)

func BuildFindings(result scanner.Result, database Database) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, rule := range result.SudoRules {
		finding := buildSudoFinding(rule, database)
		finding.Fingerprint = model.BuildFingerprint(finding)
		findings = append(findings, finding)
	}

	for _, file := range result.SuidFiles {
		finding := buildSuidFinding(file, database)
		finding.Fingerprint = model.BuildFingerprint(finding)
		findings = append(findings, finding)
	}

	for _, file := range result.CapFiles {
		finding := buildCapabilityFinding(file, database)
		finding.Fingerprint = model.BuildFingerprint(finding)
		findings = append(findings, finding)
	}

	model.SortFindings(findings)
	return findings
}

func buildSudoFinding(rule scanner.SudoRule, database Database) model.Finding {
	match, matched := database.Match(rule.BinaryName, scanner.SourceSudo)
	exploits := exploitsFromMatch(match)
	severity := model.SeverityLow
	gtfoURL := ""

	if rule.Binary == unrestrictedSudoBinary {
		severity = model.SeverityCritical
		exploits = []model.Exploit{
			{
				Type:        scanner.SourceSudo,
				Description: "Unrestricted sudo can execute a privileged shell.",
				Command:     "sudo -u root /bin/sh",
			},
		}
	} else if matched {
		gtfoURL = match.URL + "#sudo"
		if rule.NoPasswd && matchHasShell(match) {
			severity = model.SeverityCritical
		} else if matchHasShell(match) {
			severity = model.SeverityHigh
		} else {
			severity = model.SeverityMedium
		}
	}

	remediation := database.Remediation(rule.BinaryName, scanner.SourceSudo)
	if remediation == "" {
		remediation = fmt.Sprintf("Review sudoers rule and remove or restrict: %s", rule.RawLine)
	}

	return model.Finding{
		Severity:    severity,
		Source:      scanner.SourceSudo,
		Binary:      rule.Binary,
		BinaryName:  rule.BinaryName,
		Detail:      sudoDetail(rule),
		Evidence:    rule.RawLine,
		Exploits:    exploits,
		Remediation: remediation,
		GTFOBinsURL: gtfoURL,
	}
}

func buildSuidFinding(file scanner.SuidBinary, database Database) model.Finding {
	match, matched := database.Match(file.BinaryName, scanner.SourceSUID)
	exploits := exploitsFromMatch(match)
	severity := model.SeverityMedium
	gtfoURL := ""
	expectedSystemBinary := false

	if matched {
		gtfoURL = match.URL + "#suid"
		if matchHasType(match, scanner.SourceSUID) || matchHasShell(match) {
			severity = model.SeverityCritical
		} else if matchHasType(match, "file-read") || matchHasType(match, "file-write") {
			severity = model.SeverityHigh
		}
	} else if database.IsExpectedSUID(file.Path) {
		severity = model.SeverityInfo
		expectedSystemBinary = true
	}

	remediation := database.Remediation(file.BinaryName, scanner.SourceSUID)
	if remediation == "" {
		if expectedSystemBinary {
			remediation = expectedSUIDRemediation
		} else {
			remediation = fmt.Sprintf("Remove elevated bit if not required: chmod u-s %s", file.Path)
		}
	}
	remediation = strings.ReplaceAll(remediation, "<path>", file.Path)

	return model.Finding{
		Severity:    severity,
		Source:      scanner.SourceSUID,
		Binary:      file.Path,
		BinaryName:  file.BinaryName,
		Detail:      fmt.Sprintf("%s owner=%s perms=%s", file.Type, file.Owner, file.Perms),
		Evidence:    fmt.Sprintf("%s %s %s", file.Perms, file.Owner, file.Path),
		Exploits:    exploits,
		Remediation: remediation,
		GTFOBinsURL: gtfoURL,
	}
}

func buildCapabilityFinding(file scanner.CapBinary, database Database) model.Finding {
	match, matched := database.Match(file.BinaryName, scanner.SourceCapabilities)
	exploits := exploitsFromMatch(match)
	severity := capabilitySeverity(file.Capabilities)
	gtfoURL := ""

	if matched {
		gtfoURL = match.URL + "#capabilities"
	} else if severity == model.SeverityInfo {
		severity = model.SeverityLow
	}

	remediation := database.Remediation(file.BinaryName, scanner.SourceCapabilities)
	if remediation == "" {
		remediation = fmt.Sprintf("Remove capabilities if not required: setcap -r %s", file.Path)
	}
	remediation = strings.ReplaceAll(remediation, "<path>", file.Path)

	return model.Finding{
		Severity:    severity,
		Source:      scanner.SourceCapabilities,
		Binary:      file.Path,
		BinaryName:  file.BinaryName,
		Detail:      strings.Join(file.Capabilities, ","),
		Evidence:    file.RawLine,
		Exploits:    exploits,
		Remediation: remediation,
		GTFOBinsURL: gtfoURL,
	}
}

func sudoDetail(rule scanner.SudoRule) string {
	parts := make([]string, 0)
	if rule.NoPasswd {
		parts = append(parts, "NOPASSWD")
	} else {
		parts = append(parts, "PASSWD")
	}
	if rule.RunAs != "" {
		parts = append(parts, "run as "+rule.RunAs)
	}
	if rule.Args != "" {
		parts = append(parts, "args="+rule.Args)
	}
	return strings.Join(parts, ", ")
}

func exploitsFromMatch(match Match) []model.Exploit {
	exploits := make([]model.Exploit, 0, len(match.Functions))
	for _, function := range match.Functions {
		exploits = append(exploits, model.Exploit{
			Type:        function.Type,
			Description: function.Description,
			Command:     function.Code,
		})
	}
	return exploits
}

func matchHasShell(match Match) bool {
	return matchHasType(match, "shell") || matchHasType(match, "sudo") || matchHasType(match, "suid")
}

func matchHasType(match Match, functionType string) bool {
	for _, function := range match.Functions {
		if function.Type == functionType {
			return true
		}
	}
	return false
}

func capabilitySeverity(capabilities []string) model.Severity {
	severity := model.SeverityInfo
	for _, capability := range capabilities {
		name := strings.Split(capability, "+")[0]
		switch name {
		case "cap_setuid", "cap_dac_override", "cap_sys_admin":
			return model.SeverityCritical
		case "cap_setgid", "cap_dac_read_search", "cap_sys_ptrace":
			if model.SeverityRank(model.SeverityHigh) > model.SeverityRank(severity) {
				severity = model.SeverityHigh
			}
		case "cap_net_raw":
			if model.SeverityRank(model.SeverityMedium) > model.SeverityRank(severity) {
				severity = model.SeverityMedium
			}
		default:
			if model.SeverityRank(model.SeverityLow) > model.SeverityRank(severity) {
				severity = model.SeverityLow
			}
		}
	}
	return severity
}

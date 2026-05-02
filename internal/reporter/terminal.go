package reporter

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/evgenybalyakin/sudocheck/internal/model"
)

const projectURL = "https://github.com/evgenybalyakin/sudocheck"

var (
	bannerStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	criticalStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("9"))
	highStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	mediumStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	lowStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	infoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	boldStyle   = lipgloss.NewStyle().Bold(true)
)

func RenderTerminal(report model.Report, options Options) string {
	report = prepareReport(report, options)

	builder := strings.Builder{}
	if !options.NoBanner {
		builder.WriteString(renderBanner(report, options))
	}

	if report.Demo {
		builder.WriteString(renderStyled("DEMO DATA - no real system was scanned\n\n", mediumStyle, options))
	}

	if options.Quiet {
		builder.WriteString(renderSummary(report, options))
		return builder.String()
	}

	if len(report.Findings) == 0 {
		builder.WriteString("No active findings for selected severity.\n\n")
	} else {
		for _, finding := range report.Findings {
			builder.WriteString(renderFinding(finding, options))
			builder.WriteString("\n")
		}
	}

	builder.WriteString(renderSummary(report, options))
	return builder.String()
}

func renderBanner(report model.Report, options Options) string {
	version := report.Version
	if version != "" && !strings.HasPrefix(version, "v") && version != "dev" {
		version = "v" + version
	}

	lines := []string{
		fmt.Sprintf("sudocheck %s — Linux privilege escalation audit", version),
		projectURL,
	}
	return renderStyled(strings.Join(lines, "\n")+"\n\n", bannerStyle, options)
}

func renderFinding(finding model.Finding, options Options) string {
	builder := strings.Builder{}
	header := fmt.Sprintf("%s %s — %s %s (%s)", severityIcon(finding.Severity),
		strings.ToUpper(string(finding.Severity)), finding.Source, finding.BinaryName, finding.Detail)
	builder.WriteString(renderStyled(header+"\n", severityStyle(finding.Severity), options))
	builder.WriteString("┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄\n")
	if len(finding.Exploits) > 0 && !options.HideExploits {
		builder.WriteString(fmt.Sprintf("Exploit:  %s\n", finding.Exploits[0].Command))
	}
	builder.WriteString(fmt.Sprintf("Risk:     %s\n", riskText(finding)))
	if finding.Remediation != "" {
		builder.WriteString(fmt.Sprintf("Fix:      %s\n", finding.Remediation))
	}
	if finding.GTFOBinsURL != "" {
		builder.WriteString(fmt.Sprintf("Ref:      %s\n", finding.GTFOBinsURL))
	}
	return builder.String()
}

func renderSummary(report model.Report, options Options) string {
	summary := report.Summary
	builder := strings.Builder{}
	builder.WriteString(renderStyled("Summary\n", boldStyle, options))
	builder.WriteString(fmt.Sprintf("  CRITICAL: %d  HIGH: %d  MEDIUM: %d\n",
		summary.Critical, summary.High, summary.Medium))
	builder.WriteString(fmt.Sprintf("  LOW: %d       INFO: %d  SUPPRESSED: %d\n",
		summary.Low, summary.Info, summary.Suppressed))
	builder.WriteString(fmt.Sprintf("  Total active findings: %d\n", summary.Total))
	return builder.String()
}

func severityIcon(severity model.Severity) string {
	if severity == model.SeverityCritical {
		return "❌"
	}
	return "●"
}

func severityStyle(severity model.Severity) lipgloss.Style {
	switch severity {
	case model.SeverityCritical:
		return criticalStyle
	case model.SeverityHigh:
		return highStyle
	case model.SeverityMedium:
		return mediumStyle
	case model.SeverityLow:
		return lowStyle
	case model.SeverityInfo:
		return infoStyle
	default:
		return lipgloss.NewStyle()
	}
}

func riskText(finding model.Finding) string {
	switch finding.Severity {
	case model.SeverityCritical:
		return "instant or direct path to elevated privileges"
	case model.SeverityHigh:
		return "high-impact privileged file access or command execution"
	case model.SeverityMedium:
		return "potential privilege escalation under additional conditions"
	case model.SeverityLow:
		return "configuration requires review"
	default:
		return "informational finding"
	}
}

func renderStyled(value string, style lipgloss.Style, options Options) string {
	if options.NoColor {
		return value
	}
	return style.Render(value)
}

package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/balyakin/sudocheck/internal/baseline"
	"github.com/balyakin/sudocheck/internal/matcher"
	"github.com/balyakin/sudocheck/internal/model"
	"github.com/balyakin/sudocheck/internal/reporter"
	"github.com/balyakin/sudocheck/internal/scanner"
	"github.com/spf13/cobra"
)

const (
	defaultDisplayedSeverity   = "medium"
	defensiveDisplayedSeverity = "high"
)

type scanConfig struct {
	format       string
	reportPath   string
	severity     string
	failOn       string
	quiet        bool
	noColor      bool
	noBanner     bool
	jsonOutput   bool
	sarifOutput  bool
	hideExploits bool
	defensive    bool
	baselinePath string
	ignorePath   string
	redactHost   bool
	redactUser   bool
	redactPaths  bool
	skips        stringList
}

func newScanCommand(stdout io.Writer, stderr io.Writer, version string, exitCode *int) *cobra.Command {
	config := scanConfig{}
	command := &cobra.Command{
		Use:   "scan",
		Short: "Run a full privilege escalation scan",
		Run: func(command *cobra.Command, args []string) {
			*exitCode = runScanConfig(config, stdout, stderr, version)
		},
	}
	addScanFlags(command, &config)
	return command
}

func addScanFlags(command *cobra.Command, config *scanConfig) {
	flags := command.Flags()
	flags.StringVar(&config.format, "format", "", "output format: terminal, json, sarif")
	flags.StringVar(&config.format, "output", "", "output format: terminal, json, sarif")
	flags.StringVar(&config.reportPath, "report", "", "write report to path")
	flags.StringVar(&config.severity, "severity", defaultDisplayedSeverity, "minimum displayed severity")
	flags.StringVar(&config.failOn, "fail-on", "high", "minimum severity that produces non-zero exit")
	flags.BoolVarP(&config.quiet, "quiet", "q", false, "show summary only")
	flags.BoolVar(&config.noColor, "no-color", false, "disable color")
	flags.BoolVar(&config.noBanner, "no-banner", false, "hide banner")
	flags.BoolVar(&config.jsonOutput, "json", false, "write JSON to stdout")
	flags.BoolVar(&config.sarifOutput, "sarif", false, "write SARIF to stdout")
	flags.BoolVar(&config.hideExploits, "hide-exploits", false, "hide exploit commands")
	flags.BoolVar(&config.defensive, "defensive", false, "hide exploits and show high severity or higher")
	flags.StringVar(&config.baselinePath, "baseline", "", "apply baseline file")
	flags.StringVar(&config.ignorePath, "ignore-file", "", "apply ignore file")
	flags.BoolVar(&config.redactHost, "redact-host", false, "hide hostname")
	flags.BoolVar(&config.redactUser, "redact-user", false, "hide username")
	flags.BoolVar(&config.redactPaths, "redact-paths", false, "redact home paths")
	flags.Var(&config.skips, "skip", "skip scanner: sudo, suid, caps")
}

func runScanConfig(config scanConfig, stdout io.Writer, stderr io.Writer, version string) int {
	database, err := matcher.LoadDefaultDatabase()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	result := scanner.Scan(context.Background(), scanner.OSCommandRunner{}, buildScannerOptions(config.skips))
	findings := matcher.BuildFindings(result, database)

	activeFindings, suppressedFindings, err := applySuppressions(findings, config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	report := model.NewReport(version, activeFindings, suppressedFindings, scanner.BuildScannerStatuses(result))
	reportOptions, failOn, err := buildReportOptions(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	rendered, outputFormat, err := renderReport(report, reportOptions, config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	if config.reportPath != "" {
		reportBytes, renderErr := renderReportForFile(report, reportOptions, config)
		if renderErr != nil {
			fmt.Fprintln(stderr, renderErr)
			return exitRuntime
		}
		if writeErr := writeFile(config.reportPath, reportBytes); writeErr != nil {
			fmt.Fprintln(stderr, writeErr)
			return exitRuntime
		}
	}

	if config.reportPath == "" || outputFormat != formatJSON && outputFormat != formatSARIF {
		fmt.Fprint(stdout, string(rendered))
		if len(rendered) > 0 && rendered[len(rendered)-1] != '\n' {
			fmt.Fprintln(stdout)
		}
	}

	return exitForFindings(activeFindings, failOn)
}

func buildScannerOptions(skips []string) scanner.Options {
	options := scanner.Options{}
	for _, skip := range skips {
		switch skip {
		case scanner.SourceSudo:
			options.SkipSudo = true
		case scanner.SourceSUID:
			options.SkipSUID = true
		case "caps", scanner.SourceCapabilities:
			options.SkipCapabilities = true
		}
	}
	return options
}

func applySuppressions(findings []model.Finding, config scanConfig) ([]model.Finding, []model.Finding, error) {
	active := findings
	suppressed := make([]model.Finding, 0)

	if config.baselinePath != "" {
		base, err := baseline.Load(config.baselinePath)
		if err != nil {
			return nil, nil, err
		}
		var baselineSuppressed []model.Finding
		active, baselineSuppressed = baseline.Apply(base, active)
		suppressed = append(suppressed, baselineSuppressed...)
	}

	if config.ignorePath != "" {
		rules, err := baseline.LoadIgnoreRules(config.ignorePath)
		if err != nil {
			return nil, nil, err
		}
		var ignored []model.Finding
		active, ignored = baseline.ApplyIgnoreRules(rules, active)
		suppressed = append(suppressed, ignored...)
	}

	return active, suppressed, nil
}

func buildReportOptions(config scanConfig) (reporter.Options, model.Severity, error) {
	severityValue := config.severity
	failOnValue := config.failOn
	hideExploits := config.hideExploits
	if config.defensive {
		hideExploits = true
		severityValue = defensiveDisplayedSeverity
	}

	severity, err := model.ParseSeverity(severityValue)
	if err != nil {
		return reporter.Options{}, model.SeverityInfo, err
	}
	failOn, err := model.ParseSeverity(failOnValue)
	if err != nil {
		return reporter.Options{}, model.SeverityInfo, err
	}

	return reporter.Options{
		NoColor:      config.noColor,
		NoBanner:     config.noBanner,
		Quiet:        config.quiet,
		HideExploits: hideExploits,
		Severity:     severity,
		RedactHost:   config.redactHost,
		RedactUser:   config.redactUser,
		RedactPaths:  config.redactPaths,
	}, failOn, nil
}

func renderReport(report model.Report, options reporter.Options, config scanConfig) ([]byte, string, error) {
	outputFormat := inferFormat(config.format, config.jsonOutput, config.sarifOutput, "")
	switch outputFormat {
	case formatJSON:
		bytes, err := reporter.RenderJSON(report, options)
		return bytes, outputFormat, err
	case formatSARIF:
		bytes, err := reporter.RenderSARIF(report, options)
		return bytes, outputFormat, err
	case formatTerminal, "":
		return []byte(reporter.RenderTerminal(report, options)), formatTerminal, nil
	default:
		return nil, outputFormat, fmt.Errorf("unknown output format %q", outputFormat)
	}
}

func renderReportForFile(report model.Report, options reporter.Options, config scanConfig) ([]byte, error) {
	outputFormat := inferFormat(config.format, config.jsonOutput, config.sarifOutput, config.reportPath)
	if config.format == "" && !config.jsonOutput && !config.sarifOutput {
		outputFormat = inferFormat("", false, false, config.reportPath)
		if outputFormat == formatTerminal {
			outputFormat = formatJSON
		}
	}

	switch outputFormat {
	case formatJSON:
		return reporter.RenderJSON(report, options)
	case formatSARIF:
		return reporter.RenderSARIF(report, options)
	case formatTerminal:
		return []byte(reporter.RenderTerminal(report, options)), nil
	default:
		return nil, fmt.Errorf("unknown report format %q", outputFormat)
	}
}

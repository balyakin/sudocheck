package cmd

import (
	"fmt"
	"io"

	"github.com/balyakin/sudocheck/internal/demo"
	"github.com/balyakin/sudocheck/internal/matcher"
	"github.com/balyakin/sudocheck/internal/reporter"
	"github.com/spf13/cobra"
)

type demoConfig struct {
	scenario     string
	format       string
	noColor      bool
	hideExploits bool
}

func newDemoCommand(stdout io.Writer, stderr io.Writer, version string, exitCode *int) *cobra.Command {
	config := demoConfig{
		scenario: "critical",
		format:   formatTerminal,
	}
	command := &cobra.Command{
		Use:   "demo",
		Short: "Render deterministic demo data",
		Run: func(command *cobra.Command, args []string) {
			*exitCode = runDemoConfig(config, stdout, stderr, version)
		},
	}
	flags := command.Flags()
	flags.StringVar(&config.scenario, "scenario", "critical", "demo scenario: critical, clean, ci")
	flags.StringVar(&config.format, "format", formatTerminal, "output format: terminal, json, sarif")
	flags.BoolVar(&config.noColor, "no-color", false, "disable color")
	flags.BoolVar(&config.hideExploits, "hide-exploits", false, "hide exploit commands")
	return command
}

func runDemoConfig(config demoConfig, stdout io.Writer, stderr io.Writer, version string) int {
	database, err := matcher.LoadDefaultDatabase()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	report := demo.BuildReport(version, config.scenario, database)
	options := reporter.Options{
		NoColor:      config.noColor,
		HideExploits: config.hideExploits,
	}

	switch config.format {
	case formatJSON:
		bytes, err := reporter.RenderJSON(report, options)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		fmt.Fprintln(stdout, string(bytes))
	case formatSARIF:
		bytes, err := reporter.RenderSARIF(report, options)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		fmt.Fprintln(stdout, string(bytes))
	default:
		fmt.Fprint(stdout, reporter.RenderTerminal(report, options))
	}

	return exitOK
}

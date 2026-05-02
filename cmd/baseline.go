package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/balyakin/sudocheck/internal/baseline"
	"github.com/balyakin/sudocheck/internal/matcher"
	"github.com/balyakin/sudocheck/internal/scanner"
	"github.com/spf13/cobra"
)

type baselineInitConfig struct {
	output string
}

func newBaselineCommand(stdout io.Writer, stderr io.Writer, exitCode *int) *cobra.Command {
	command := &cobra.Command{
		Use:   "baseline",
		Short: "Create or compare finding baselines",
	}

	initConfig := baselineInitConfig{output: "sudocheck.baseline.json"}
	initCommand := &cobra.Command{
		Use:   "init",
		Short: "Create a baseline from current findings",
		Run: func(command *cobra.Command, args []string) {
			*exitCode = runBaselineInitConfig(initConfig, stdout, stderr)
		},
	}
	initCommand.Flags().StringVar(&initConfig.output, "output", "sudocheck.baseline.json", "output baseline path")

	diffCommand := &cobra.Command{
		Use:   "diff old.json new.json",
		Short: "Compare two baselines",
		Args:  cobra.ExactArgs(2),
		Run: func(command *cobra.Command, args []string) {
			*exitCode = runBaselineDiffArgs(args, stdout, stderr)
		},
	}

	command.AddCommand(initCommand, diffCommand)
	return command
}

func runBaselineInitConfig(config baselineInitConfig, stdout io.Writer, stderr io.Writer) int {
	database, err := matcher.LoadDefaultDatabase()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	result := scanner.Scan(context.Background(), scanner.OSCommandRunner{}, scanner.Options{})
	findings := matcher.BuildFindings(result, database)
	base := baseline.New(findings)
	if err := baseline.Save(config.output, base); err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	fmt.Fprintf(stdout, "baseline written to %s (%d findings)\n", config.output, len(base.Findings))
	return exitOK
}

func runBaselineDiffArgs(args []string, stdout io.Writer, stderr io.Writer) int {
	oldBaseline, err := baseline.Load(args[0])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	newBaseline, err := baseline.Load(args[1])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	newItems, resolved := baseline.Diff(oldBaseline, newBaseline)
	fmt.Fprintf(stdout, "new findings: %d\n", len(newItems))
	for _, finding := range newItems {
		fmt.Fprintf(stdout, "  + [%s] %s %s %s\n", finding.Severity, finding.Source, finding.BinaryName, finding.Binary)
	}
	fmt.Fprintf(stdout, "resolved findings: %d\n", len(resolved))
	for _, finding := range resolved {
		fmt.Fprintf(stdout, "  - [%s] %s %s %s\n", finding.Severity, finding.Source, finding.BinaryName, finding.Binary)
	}
	return exitOK
}

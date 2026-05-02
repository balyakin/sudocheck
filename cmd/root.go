package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func Execute(args []string, stdout io.Writer, stderr io.Writer, version string) int {
	exitCode := exitOK
	rootCommand := newRootCommand(stdout, stderr, version, &exitCode)
	rootCommand.SetArgs(args)

	if err := rootCommand.Execute(); err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	return exitCode
}

func newRootCommand(stdout io.Writer, stderr io.Writer, version string, exitCode *int) *cobra.Command {
	scanConfig := scanConfig{}
	rootCommand := &cobra.Command{
		Use:           "sudocheck",
		Short:         "Linux privilege escalation audit with GTFOBins mapping",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(command *cobra.Command, args []string) error {
			*exitCode = runScanConfig(scanConfig, stdout, stderr, version)
			return nil
		},
	}
	rootCommand.SetOut(stdout)
	rootCommand.SetErr(stderr)
	addScanFlags(rootCommand, &scanConfig)

	rootCommand.AddCommand(newScanCommand(stdout, stderr, version, exitCode))
	rootCommand.AddCommand(newLookupCommand(stdout, stderr, exitCode))
	rootCommand.AddCommand(newBaselineCommand(stdout, stderr, exitCode))
	rootCommand.AddCommand(newDemoCommand(stdout, stderr, version, exitCode))
	rootCommand.AddCommand(newUpdateCommand(stdout, stderr, exitCode))
	rootCommand.AddCommand(newVersionCommand(stdout, version, exitCode))
	return rootCommand
}

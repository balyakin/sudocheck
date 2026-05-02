package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newVersionCommand(stdout io.Writer, version string, exitCode *int) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print sudocheck version",
		Run: func(command *cobra.Command, args []string) {
			fmt.Fprintln(stdout, version)
			*exitCode = exitOK
		},
	}
}

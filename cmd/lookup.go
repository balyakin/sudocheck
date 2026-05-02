package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/evgenybalyakin/sudocheck/internal/matcher"
	"github.com/spf13/cobra"
)

type lookupConfig struct {
	list         bool
	functionType string
}

func newLookupCommand(stdout io.Writer, stderr io.Writer, exitCode *int) *cobra.Command {
	config := lookupConfig{}
	command := &cobra.Command{
		Use:   "lookup <binary>",
		Short: "Look up a binary in the embedded GTFOBins-compatible database",
		Run: func(command *cobra.Command, args []string) {
			*exitCode = runLookupConfig(config, args, stdout, stderr)
		},
	}
	flags := command.Flags()
	flags.BoolVar(&config.list, "list", false, "list known binaries")
	flags.StringVar(&config.functionType, "type", "", "filter by function type")
	return command
}

func runLookupConfig(config lookupConfig, args []string, stdout io.Writer, stderr io.Writer) int {
	database, err := matcher.LoadDefaultDatabase()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	if config.list {
		for _, name := range database.ListNames(config.functionType) {
			fmt.Fprintln(stdout, name)
		}
		return exitOK
	}

	if len(args) != 1 {
		fmt.Fprintln(stderr, "lookup requires a binary name")
		return exitUsage
	}

	name := args[0]
	match, ok := database.Lookup(name)
	if !ok {
		fmt.Fprintf(stderr, "no GTFOBins entry for %q\n", name)
		suggestions := database.Suggestions(name)
		if len(suggestions) > 0 {
			fmt.Fprintf(stderr, "did you mean: %s\n", strings.Join(suggestions, ", "))
		}
		return exitUsage
	}

	fmt.Fprintf(stdout, "%s — %s\n\n", match.BinaryName, match.URL)
	for _, function := range match.Functions {
		fmt.Fprintf(stdout, "- %s\n", function.Type)
		if function.Description != "" {
			fmt.Fprintf(stdout, "  %s\n", function.Description)
		}
		if function.Code != "" {
			fmt.Fprintf(stdout, "  %s\n", function.Code)
		}
		fmt.Fprintln(stdout)
	}
	return exitOK
}

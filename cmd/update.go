package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/balyakin/sudocheck/internal/matcher"
	"github.com/spf13/cobra"
)

const defaultUpdateURL = "https://gtfobins.org/api.json"

type updateConfig struct {
	sourceURL string
	force     bool
}

func newUpdateCommand(stdout io.Writer, stderr io.Writer, exitCode *int) *cobra.Command {
	config := updateConfig{sourceURL: defaultUpdateURL}
	command := &cobra.Command{
		Use:   "update",
		Short: "Download an external GTFOBins-compatible JSON database",
		Run: func(command *cobra.Command, args []string) {
			*exitCode = runUpdateConfig(config, stdout, stderr)
		},
	}
	command.Flags().StringVar(&config.sourceURL, "url", defaultUpdateURL, "GTFOBins-compatible JSON URL")
	command.Flags().BoolVar(&config.force, "force", false, "replace local database even if it is newer")
	return command
}

func runUpdateConfig(config updateConfig, stdout io.Writer, stderr io.Writer) int {
	bytes, err := downloadDatabase(config.sourceURL)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	database, err := matcher.ParseDatabase(bytes)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	if database.GeneratedAt == "" {
		database.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if database.Source == "" {
		database.Source = config.sourceURL
	}

	rendered, err := json.MarshalIndent(database, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	targetDir := filepath.Join(configDir, "sudocheck")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	targetPath := filepath.Join(targetDir, "gtfobins.json")
	if !config.force && localDatabaseIsNewer(targetPath, database.GeneratedAt) {
		fmt.Fprintf(stdout, "local GTFOBins database is newer than downloaded data: %s\n", targetPath)
		return exitOK
	}
	if err := os.WriteFile(targetPath, append(rendered, '\n'), 0644); err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	fmt.Fprintf(stdout, "updated GTFOBins database: %s (%d entries)\n", targetPath, len(database.Binaries))
	return exitOK
}

func localDatabaseIsNewer(path string, generatedAt string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	generatedTime, err := time.Parse(time.RFC3339, generatedAt)
	if err != nil {
		return false
	}
	return info.ModTime().After(generatedTime)
}

func downloadDatabase(sourceURL string) ([]byte, error) {
	client := http.Client{Timeout: 30 * time.Second}
	response, err := client.Get(sourceURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", sourceURL, err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("download %s: HTTP %d", sourceURL, response.StatusCode)
	}

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", sourceURL, err)
	}
	return bytes, nil
}

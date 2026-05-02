package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/evgenybalyakin/sudocheck/internal/matcher"
	"gopkg.in/yaml.v3"
)

const defaultRepoURL = "https://github.com/GTFOBins/GTFOBins.github.io"

type frontMatter struct {
	Functions map[string][]matcher.Function `yaml:"functions"`
}

func main() {
	repoURL := defaultRepoURL
	if len(os.Args) > 1 {
		repoURL = os.Args[1]
	}

	tempDir, err := os.MkdirTemp("", "sudocheck-gtfobins-*")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(tempDir)

	if err := cloneRepository(repoURL, tempDir); err != nil {
		fatal(err)
	}

	database, err := buildDatabase(tempDir)
	if err != nil {
		fatal(err)
	}

	rendered, err := json.MarshalIndent(database, "", "  ")
	if err != nil {
		fatal(err)
	}

	if err := os.WriteFile("data/gtfobins.json", append(rendered, '\n'), 0644); err != nil {
		fatal(err)
	}

	fmt.Printf("wrote data/gtfobins.json with %d entries\n", len(database.Binaries))
}

func cloneRepository(repoURL string, targetDir string) error {
	command := exec.Command("git", "clone", "--depth", "1", repoURL, targetDir)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("clone %s: %w: %s", repoURL, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildDatabase(repoDir string) (matcher.Database, error) {
	pattern := filepath.Join(repoDir, "_gtfobins", "*.md")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return matcher.Database{}, err
	}
	if len(paths) == 0 {
		return matcher.Database{}, fmt.Errorf("no GTFOBins markdown files found in %s", pattern)
	}

	binaries := make(map[string]matcher.BinaryEntry, len(paths))
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		entry, err := parseMarkdownEntry(path)
		if err != nil {
			return matcher.Database{}, err
		}
		binaries[name] = entry
	}

	return matcher.Database{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      defaultRepoURL,
		Binaries:    binaries,
	}, nil
}

func parseMarkdownEntry(path string) (matcher.BinaryEntry, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return matcher.BinaryEntry{}, err
	}

	yamlText, err := extractFrontMatter(string(bytes))
	if err != nil {
		return matcher.BinaryEntry{}, fmt.Errorf("extract frontmatter from %s: %w", path, err)
	}

	frontMatter := frontMatter{}
	if err := yaml.Unmarshal([]byte(yamlText), &frontMatter); err != nil {
		return matcher.BinaryEntry{}, fmt.Errorf("parse YAML from %s: %w", path, err)
	}

	return matcher.BinaryEntry{Functions: frontMatter.Functions}, nil
}

func extractFrontMatter(content string) (string, error) {
	const delimiter = "---"
	content = strings.TrimPrefix(content, "\ufeff")
	if !strings.HasPrefix(content, delimiter) {
		return "", fmt.Errorf("frontmatter delimiter not found")
	}

	remaining := strings.TrimPrefix(content, delimiter)
	remaining = strings.TrimPrefix(remaining, "\r\n")
	remaining = strings.TrimPrefix(remaining, "\n")
	endIndex := strings.Index(remaining, "\n---")
	if endIndex < 0 {
		return "", fmt.Errorf("closing frontmatter delimiter not found")
	}

	return remaining[:endIndex], nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

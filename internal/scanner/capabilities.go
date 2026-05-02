package scanner

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

func ScanCapabilities(ctx context.Context, runner CommandRunner) ([]CapBinary, []Warning) {
	commandCtx, cancel := timeoutContext(ctx)
	defer cancel()

	output, err := runner.Run(commandCtx, "getcap", "-r", "/")
	outputText := string(output)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, []Warning{{Source: SourceCapabilities, Message: "getcap not found"}}
		}
		message := strings.TrimSpace(outputText)
		if message == "" {
			message = err.Error()
		}
		return ParseCapabilities(outputText), []Warning{{Source: SourceCapabilities, Message: message}}
	}

	return ParseCapabilities(outputText), nil
}

func ParseCapabilities(output string) []CapBinary {
	files := make([]CapBinary, 0)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		path := fields[0]
		capabilities := fields[1:]
		files = append(files, CapBinary{
			Path:         path,
			BinaryName:   strings.ToLower(filepath.Base(path)),
			Capabilities: capabilities,
			RawLine:      line,
		})
	}
	return files
}

package scanner

import (
	"context"
	"os/exec"
)

const (
	SourceSudo         = "sudo"
	SourceSUID         = "suid"
	SourceCapabilities = "capabilities"

	StatusOK      = "ok"
	StatusSkipped = "skipped"
	StatusWarning = "warning"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type OSCommandRunner struct {
}

type Warning struct {
	Source  string
	Message string
}

type SudoRule struct {
	Binary     string
	BinaryName string
	RunAs      string
	NoPasswd   bool
	Args       string
	RawLine    string
	Tags       []string
	Setenv     bool
	NoSetenv   bool
}

type SuidBinary struct {
	Path       string
	BinaryName string
	Owner      string
	Type       string
	Perms      string
}

type CapBinary struct {
	Path         string
	BinaryName   string
	Capabilities []string
	RawLine      string
}

type Result struct {
	SudoRules   []SudoRule
	SuidFiles   []SuidBinary
	CapFiles    []CapBinary
	Warnings    []Warning
	ScanSkipped map[string]bool
}

type Options struct {
	SkipSudo         bool
	SkipSUID         bool
	SkipCapabilities bool
}

func (runner OSCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	return command.CombinedOutput()
}

package scanner

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

const sudoPasswordRequiredMessage = "sudo requires password, skipping sudo scan. Run with sudo sudocheck for full results."

func ScanSudo(ctx context.Context, runner CommandRunner) ([]SudoRule, []Warning) {
	commandCtx, cancel := timeoutContext(ctx)
	defer cancel()

	output, err := runner.Run(commandCtx, "sudo", "-l", "-n")
	outputText := string(output)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, []Warning{{Source: SourceSudo, Message: "sudo not found"}}
		}
		if strings.Contains(strings.ToLower(outputText), "password") {
			return nil, []Warning{{Source: SourceSudo, Message: sudoPasswordRequiredMessage}}
		}
		if strings.Contains(strings.ToLower(outputText), "not allowed") {
			return nil, []Warning{{Source: SourceSudo, Message: "current user has no sudo rules"}}
		}
		return nil, []Warning{{Source: SourceSudo, Message: strings.TrimSpace(outputText)}}
	}

	rules, warnings := ParseSudoList(outputText)
	return rules, warnings
}

func ParseSudoList(output string) ([]SudoRule, []Warning) {
	lines := strings.Split(output, "\n")
	rules := make([]SudoRule, 0)
	warnings := make([]Warning, 0)
	aliases := parseCommandAliases(lines)

	for _, line := range lines {
		ruleLine := strings.TrimSpace(line)
		if !strings.HasPrefix(ruleLine, "(") {
			continue
		}

		parsedRules, denied := parseSudoRuleLine(ruleLine, aliases)
		if denied {
			warnings = append(warnings, Warning{Source: SourceSudo, Message: "sudo deny rules were ignored"})
		}
		rules = append(rules, parsedRules...)
	}

	return rules, warnings
}

func parseSudoRuleLine(line string, aliases map[string][]string) ([]SudoRule, bool) {
	closeIndex := strings.Index(line, ")")
	if closeIndex < 0 {
		return nil, false
	}

	runAs := strings.TrimSpace(line[1:closeIndex])
	remainder := strings.TrimSpace(line[closeIndex+1:])
	parts := strings.Split(remainder, ":")
	if len(parts) == 0 {
		return nil, false
	}

	commandText := strings.TrimSpace(parts[len(parts)-1])
	tags := parseSudoTags(parts[:len(parts)-1])
	noPasswd := containsTag(tags, "NOPASSWD")

	rules := make([]SudoRule, 0)
	denied := false
	for _, commandPart := range splitSudoCommands(commandText) {
		commandPart = strings.TrimSpace(commandPart)
		if commandPart == "" {
			continue
		}
		if strings.HasPrefix(commandPart, "!") {
			denied = true
			continue
		}
		aliasCommands, aliasFound := aliases[commandPart]
		if aliasFound {
			for _, aliasCommand := range aliasCommands {
				rules = append(rules, buildSudoRule(line, runAs, noPasswd, tags, aliasCommand))
			}
			continue
		}
		rules = append(rules, buildSudoRule(line, runAs, noPasswd, tags, commandPart))
	}

	return rules, denied
}

func buildSudoRule(rawLine string, runAs string, noPasswd bool, tags []string, commandText string) SudoRule {
	fields := strings.Fields(commandText)
	binary := commandText
	args := ""
	if len(fields) > 0 {
		binary = fields[0]
	}
	if len(fields) > 1 {
		args = strings.Join(fields[1:], " ")
	}

	return SudoRule{
		Binary:     binary,
		BinaryName: normalizeCommandName(binary),
		RunAs:      runAs,
		NoPasswd:   noPasswd,
		Args:       args,
		RawLine:    rawLine,
		Tags:       tags,
		Setenv:     containsTag(tags, "SETENV"),
		NoSetenv:   containsTag(tags, "NOSETENV"),
	}
}

func parseCommandAliases(lines []string) map[string][]string {
	aliases := map[string][]string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Cmnd_Alias") {
			continue
		}
		withoutPrefix := strings.TrimSpace(strings.TrimPrefix(line, "Cmnd_Alias"))
		name, value, ok := strings.Cut(withoutPrefix, "=")
		if !ok {
			continue
		}
		aliasName := strings.TrimSpace(name)
		commands := splitSudoCommands(value)
		if aliasName != "" && len(commands) > 0 {
			aliases[aliasName] = commands
		}
	}
	return aliases
}

func splitSudoCommands(value string) []string {
	commands := make([]string, 0)
	for _, command := range strings.Split(value, ",") {
		command = strings.TrimSpace(command)
		if command != "" {
			commands = append(commands, command)
		}
	}
	return commands
}

func parseSudoTags(parts []string) []string {
	tags := make([]string, 0)
	for _, part := range parts {
		for _, token := range strings.Fields(strings.TrimSpace(part)) {
			token = strings.Trim(token, ",")
			if token != "" {
				tags = append(tags, token)
			}
		}
	}
	return tags
}

func containsTag(tags []string, expected string) bool {
	for _, tag := range tags {
		if strings.EqualFold(tag, expected) {
			return true
		}
	}
	return false
}

func normalizeCommandName(path string) string {
	if path == "ALL" {
		return "all"
	}
	base := filepath.Base(path)
	return strings.ToLower(base)
}

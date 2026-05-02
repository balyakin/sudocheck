package baseline

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/balyakin/sudocheck/internal/model"
)

type IgnoreRule struct {
	Source     string
	Binary     string
	BinaryName string
	Severity   model.Severity
	Reason     string
	Expires    string
}

func LoadIgnoreRules(path string) ([]IgnoreRule, error) {
	if path == "" {
		return nil, nil
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ignore file %s: %w", path, err)
	}

	rules, err := ParseIgnoreRules(string(bytes))
	if err != nil {
		return nil, fmt.Errorf("parse ignore file %s: %w", path, err)
	}
	return rules, nil
}

func ParseIgnoreRules(content string) ([]IgnoreRule, error) {
	rules := make([]IgnoreRule, 0)
	current := IgnoreRule{}
	hasCurrent := false

	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || line == "ignore:" {
			continue
		}

		if strings.HasPrefix(line, "- ") {
			if hasCurrent {
				rules = append(rules, current)
			}
			current = IgnoreRule{}
			hasCurrent = true
			line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
			if line == "" {
				continue
			}
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid ignore line %q", rawLine)
		}
		applyIgnoreValue(&current, strings.TrimSpace(key), strings.TrimSpace(value))
		hasCurrent = true
	}

	if hasCurrent {
		rules = append(rules, current)
	}

	for _, rule := range rules {
		if rule.Reason == "" {
			return nil, fmt.Errorf("ignore rule for %s requires reason", rule.BinaryName)
		}
	}

	return rules, nil
}

func ApplyIgnoreRules(rules []IgnoreRule, findings []model.Finding) ([]model.Finding, []model.Finding) {
	active := make([]model.Finding, 0, len(findings))
	suppressed := make([]model.Finding, 0)

	for _, finding := range findings {
		rule, ok := matchingRule(rules, finding)
		if ok {
			finding.SuppressionReason = rule.Reason
			suppressed = append(suppressed, finding)
			continue
		}
		active = append(active, finding)
	}

	return active, suppressed
}

func applyIgnoreValue(rule *IgnoreRule, key string, value string) {
	value = strings.Trim(value, "\"'")
	switch key {
	case "source":
		rule.Source = value
	case "binary":
		rule.Binary = value
	case "binary_name":
		rule.BinaryName = value
	case "severity":
		severity, err := model.ParseSeverity(value)
		if err == nil {
			rule.Severity = severity
		}
	case "reason":
		rule.Reason = value
	case "expires":
		rule.Expires = value
	}
}

func matchingRule(rules []IgnoreRule, finding model.Finding) (IgnoreRule, bool) {
	for _, rule := range rules {
		if ruleExpired(rule) {
			continue
		}
		if rule.Source != "" && rule.Source != finding.Source {
			continue
		}
		if rule.Binary != "" && rule.Binary != finding.Binary {
			continue
		}
		if rule.BinaryName != "" && rule.BinaryName != finding.BinaryName {
			continue
		}
		if rule.Severity != "" && rule.Severity != finding.Severity {
			continue
		}
		return rule, true
	}
	return IgnoreRule{}, false
}

func ruleExpired(rule IgnoreRule) bool {
	if rule.Expires == "" {
		return false
	}
	expiresAt, err := time.Parse("2006-01-02", rule.Expires)
	if err != nil {
		return false
	}
	return time.Now().After(expiresAt)
}

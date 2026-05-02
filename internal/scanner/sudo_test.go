package scanner

import (
	"context"
	"errors"
	"testing"
)

type fakeRunner struct {
	output []byte
	err    error
}

func (runner fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return runner.output, runner.err
}

func TestParseSudoListParsesEmptyRules(t *testing.T) {
	output := `User deploy may run the following commands on host:
`

	rules, warnings := ParseSudoList(output)

	if len(rules) != 0 {
		t.Fatalf("expected no rules, got %d", len(rules))
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %d", len(warnings))
	}
}

func TestParseSudoListParsesNoPasswdRule(t *testing.T) {
	output := `Matching Defaults entries for deploy on host:
    env_reset

User deploy may run the following commands on host:
    (ALL) NOPASSWD: /usr/bin/vim, /usr/sbin/tcpdump -i eth0`

	rules, warnings := ParseSudoList(output)

	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Binary != "/usr/bin/vim" {
		t.Fatalf("unexpected first binary: %s", rules[0].Binary)
	}
	if rules[0].BinaryName != "vim" {
		t.Fatalf("unexpected first binary name: %s", rules[0].BinaryName)
	}
	if !rules[0].NoPasswd {
		t.Fatal("expected NOPASSWD rule")
	}
	if rules[1].Args != "-i eth0" {
		t.Fatalf("unexpected args: %s", rules[1].Args)
	}
}

func TestParseSudoListIgnoresDeniedRule(t *testing.T) {
	output := `User deploy may run the following commands on host:
    (root) NOPASSWD: /usr/bin/systemctl, !/usr/bin/vim`

	rules, warnings := ParseSudoList(output)

	if len(rules) != 1 {
		t.Fatalf("expected one allowed rule, got %d", len(rules))
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one warning, got %d", len(warnings))
	}
}

func TestParseSudoListParsesMixedPasswordRules(t *testing.T) {
	output := `User deploy may run the following commands on host:
    (root) /usr/bin/systemctl restart nginx
    (ALL) NOPASSWD: /usr/bin/vim`

	rules, warnings := ParseSudoList(output)

	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(rules) != 2 {
		t.Fatalf("expected two rules, got %d", len(rules))
	}
	if rules[0].NoPasswd {
		t.Fatal("expected first rule to require password")
	}
	if !rules[1].NoPasswd {
		t.Fatal("expected second rule to be NOPASSWD")
	}
}

func TestParseSudoListResolvesCommandAliasAndTags(t *testing.T) {
	output := `Cmnd_Alias EDITORS = /usr/bin/vim, /usr/bin/nano
User deploy may run the following commands on host:
    (root) SETENV: NOPASSWD: EDITORS`

	rules, warnings := ParseSudoList(output)

	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(rules) != 2 {
		t.Fatalf("expected two alias-expanded rules, got %d", len(rules))
	}
	if !rules[0].Setenv {
		t.Fatal("expected SETENV tag")
	}
	if rules[0].Binary != "/usr/bin/vim" {
		t.Fatalf("unexpected alias target: %s", rules[0].Binary)
	}
}

func TestScanSudoReportsPasswordRequired(t *testing.T) {
	runner := fakeRunner{
		output: []byte("sudo: a password is required"),
		err:    errors.New("exit status 1"),
	}

	rules, warnings := ScanSudo(context.Background(), runner)

	if len(rules) != 0 {
		t.Fatalf("expected no rules, got %d", len(rules))
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one warning, got %d", len(warnings))
	}
	if warnings[0].Message != sudoPasswordRequiredMessage {
		t.Fatalf("unexpected warning: %s", warnings[0].Message)
	}
}

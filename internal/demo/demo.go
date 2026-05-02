package demo

import (
	"github.com/balyakin/sudocheck/internal/matcher"
	"github.com/balyakin/sudocheck/internal/model"
	"github.com/balyakin/sudocheck/internal/scanner"
)

func BuildReport(version string, scenario string, database matcher.Database) model.Report {
	result := BuildResult(scenario)
	findings := matcher.BuildFindings(result, database)
	report := model.NewReport(version, findings, nil, scanner.BuildScannerStatuses(result))
	report.Demo = true
	report.Hostname = "demo-host"
	report.User = "demo"
	return report
}

func BuildResult(scenario string) scanner.Result {
	switch scenario {
	case "clean":
		return scanner.Result{
			ScanSkipped: map[string]bool{},
		}
	case "ci":
		return scanner.Result{
			SudoRules: []scanner.SudoRule{
				{
					Binary:     "/usr/sbin/tcpdump",
					BinaryName: "tcpdump",
					RunAs:      "root",
					NoPasswd:   true,
					RawLine:    "(root) NOPASSWD: /usr/sbin/tcpdump",
				},
			},
			ScanSkipped: map[string]bool{},
		}
	default:
		return criticalResult()
	}
}

func criticalResult() scanner.Result {
	return scanner.Result{
		SudoRules: []scanner.SudoRule{
			{
				Binary:     "/usr/bin/vim",
				BinaryName: "vim",
				RunAs:      "ALL",
				NoPasswd:   true,
				RawLine:    "(ALL) NOPASSWD: /usr/bin/vim",
			},
			{
				Binary:     "/usr/sbin/tcpdump",
				BinaryName: "tcpdump",
				RunAs:      "root",
				NoPasswd:   true,
				RawLine:    "(root) NOPASSWD: /usr/sbin/tcpdump",
			},
		},
		SuidFiles: []scanner.SuidBinary{
			{
				Path:       "/usr/local/bin/find",
				BinaryName: "find",
				Owner:      "root",
				Type:       "suid",
				Perms:      "4755",
			},
		},
		CapFiles: []scanner.CapBinary{
			{
				Path:         "/usr/bin/python3.11",
				BinaryName:   "python3.11",
				Capabilities: []string{"cap_setuid+ep"},
				RawLine:      "/usr/bin/python3.11 cap_setuid+ep",
			},
		},
		ScanSkipped: map[string]bool{},
	}
}

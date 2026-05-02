package demo

import (
	"testing"

	"github.com/balyakin/sudocheck/internal/matcher"
)

func TestBuildReportUsesDemoData(t *testing.T) {
	database, err := matcher.LoadDefaultDatabase()
	if err != nil {
		t.Fatal(err)
	}

	report := BuildReport("test", "critical", database)

	if !report.Demo {
		t.Fatal("expected demo report")
	}
	if report.Summary.Critical == 0 {
		t.Fatal("expected critical demo findings")
	}
}

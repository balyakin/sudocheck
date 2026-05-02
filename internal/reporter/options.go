package reporter

import "github.com/balyakin/sudocheck/internal/model"

type Options struct {
	NoColor       bool
	NoBanner      bool
	Quiet         bool
	HideExploits  bool
	Severity      model.Severity
	RedactHost    bool
	RedactUser    bool
	RedactPaths   bool
	SARIFRedacted bool
}

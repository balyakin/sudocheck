package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/balyakin/sudocheck/internal/model"
)

const scanTimeout = 15 * time.Second

func Scan(ctx context.Context, runner CommandRunner, options Options) Result {
	result := Result{
		ScanSkipped: map[string]bool{},
	}
	var mutex sync.Mutex
	var waitGroup sync.WaitGroup

	if options.SkipSudo {
		result.ScanSkipped[SourceSudo] = true
	} else {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			sudoRules, warnings := ScanSudo(ctx, runner)
			mutex.Lock()
			result.SudoRules = sudoRules
			result.Warnings = append(result.Warnings, warnings...)
			mutex.Unlock()
		}()
	}

	if options.SkipSUID {
		result.ScanSkipped[SourceSUID] = true
	} else {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			suidFiles, warnings := ScanSUID(ctx, runner)
			mutex.Lock()
			result.SuidFiles = suidFiles
			result.Warnings = append(result.Warnings, warnings...)
			mutex.Unlock()
		}()
	}

	if options.SkipCapabilities {
		result.ScanSkipped[SourceCapabilities] = true
	} else {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			capFiles, warnings := ScanCapabilities(ctx, runner)
			mutex.Lock()
			result.CapFiles = capFiles
			result.Warnings = append(result.Warnings, warnings...)
			mutex.Unlock()
		}()
	}

	waitGroup.Wait()
	return result
}

func BuildScannerStatuses(result Result) map[string]model.ScannerStatus {
	statuses := map[string]model.ScannerStatus{
		SourceSudo:         {Status: StatusOK, Warnings: []string{}},
		SourceSUID:         {Status: StatusOK, Warnings: []string{}},
		SourceCapabilities: {Status: StatusOK, Warnings: []string{}},
	}

	for source := range result.ScanSkipped {
		statuses[source] = model.ScannerStatus{Status: StatusSkipped, Warnings: []string{}}
	}

	for _, warning := range result.Warnings {
		status := statuses[warning.Source]
		if status.Status == "" {
			status.Status = StatusWarning
		}
		if status.Status == StatusOK {
			status.Status = StatusWarning
		}
		status.Warnings = append(status.Warnings, warning.Message)
		statuses[warning.Source] = status
	}

	return statuses
}

func timeoutContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, scanTimeout)
}

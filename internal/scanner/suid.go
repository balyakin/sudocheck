package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
)

func ScanSUID(ctx context.Context, runner CommandRunner) ([]SuidBinary, []Warning) {
	var suidPaths []string
	var sgidPaths []string
	var suidWarnings []Warning
	var sgidWarnings []Warning
	var waitGroup sync.WaitGroup

	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		suidPaths, suidWarnings = findPermissionFiles(ctx, runner, "-4000")
	}()
	go func() {
		defer waitGroup.Done()
		sgidPaths, sgidWarnings = findPermissionFiles(ctx, runner, "-2000")
	}()
	waitGroup.Wait()

	warnings := append(suidWarnings, sgidWarnings...)

	pathTypes := map[string]map[string]bool{}
	for _, path := range suidPaths {
		setPathType(pathTypes, path, "suid")
	}
	for _, path := range sgidPaths {
		setPathType(pathTypes, path, "sgid")
	}

	paths := make([]string, 0, len(pathTypes))
	for path := range pathTypes {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	files := make([]SuidBinary, 0, len(paths))
	for _, path := range paths {
		file, err := buildSuidBinary(path, pathTypes[path])
		if err != nil {
			warnings = append(warnings, Warning{Source: SourceSUID, Message: err.Error()})
			continue
		}
		files = append(files, file)
	}

	return files, warnings
}

func findPermissionFiles(ctx context.Context, runner CommandRunner, permission string) ([]string, []Warning) {
	commandCtx, cancel := timeoutContext(ctx)
	defer cancel()

	args := []string{
		"/",
		"(",
		"-path", "/proc",
		"-o", "-path", "/sys",
		"-o", "-path", "/dev",
		"-o", "-path", "/run",
		")",
		"-prune",
		"-o",
		"-perm", permission,
		"-type", "f",
		"-print",
	}
	output, err := runner.Run(commandCtx, "find", args...)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, []Warning{{Source: SourceSUID, Message: "find not found"}}
		}
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return parsePathLines(string(output)), []Warning{{Source: SourceSUID, Message: message}}
	}

	return parsePathLines(string(output)), nil
}

func parsePathLines(output string) []string {
	paths := make([]string, 0)
	for _, line := range strings.Split(output, "\n") {
		path := strings.TrimSpace(line)
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func setPathType(pathTypes map[string]map[string]bool, path string, typeName string) {
	if pathTypes[path] == nil {
		pathTypes[path] = map[string]bool{}
	}
	pathTypes[path][typeName] = true
}

func buildSuidBinary(path string, typeValues map[string]bool) (SuidBinary, error) {
	info, err := os.Stat(path)
	if err != nil {
		return SuidBinary{}, fmt.Errorf("cannot stat %s: %w", path, err)
	}

	return SuidBinary{
		Path:       path,
		BinaryName: strings.ToLower(filepath.Base(path)),
		Owner:      ownerName(info),
		Type:       formatSuidType(typeValues),
		Perms:      formatPermissions(info.Mode()),
	}, nil
}

func ownerName(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}

	userInfo, err := user.LookupId(fmt.Sprintf("%d", stat.Uid))
	if err != nil {
		return fmt.Sprintf("%d", stat.Uid)
	}
	return userInfo.Username
}

func formatSuidType(typeValues map[string]bool) string {
	if typeValues["suid"] && typeValues["sgid"] {
		return "suid+sgid"
	}
	if typeValues["sgid"] {
		return "sgid"
	}
	return "suid"
}

func formatPermissions(mode os.FileMode) string {
	value := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		value |= 04000
	}
	if mode&os.ModeSetgid != 0 {
		value |= 02000
	}
	return fmt.Sprintf("%04o", value)
}

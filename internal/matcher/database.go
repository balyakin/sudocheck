package matcher

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/balyakin/sudocheck/data"
)

type Database struct {
	GeneratedAt  string                 `json:"generated_at,omitempty"`
	Source       string                 `json:"source,omitempty"`
	Binaries     map[string]BinaryEntry `json:"binaries"`
	Remediations map[string]map[string]string
	Defaults     Defaults
}

type BinaryEntry struct {
	Functions map[string][]Function `json:"functions"`
}

type Function struct {
	Description string `json:"description"`
	Code        string `json:"code"`
}

type Defaults struct {
	ExpectedSUID []string `json:"expected_suid"`
}

type Match struct {
	BinaryName string
	URL        string
	Functions  []MatchedFunction
}

type MatchedFunction struct {
	Type        string
	Description string
	Code        string
}

var versionSuffix = regexp.MustCompile(`^(.+?)[0-9]+(\.[0-9]+)*$`)

func LoadDefaultDatabase() (Database, error) {
	bytes, err := data.Files.ReadFile("gtfobins.json")
	if err != nil {
		return Database{}, fmt.Errorf("read embedded gtfobins database: %w", err)
	}

	database, err := ParseDatabase(bytes)
	if err != nil {
		return Database{}, err
	}

	userDatabase, userErr := loadUserDatabase(database.GeneratedAt)
	if userErr == nil {
		database.Binaries = userDatabase.Binaries
		database.GeneratedAt = userDatabase.GeneratedAt
		database.Source = userDatabase.Source
	}

	if err := loadRemediations(&database); err != nil {
		return Database{}, err
	}
	if err := loadDefaults(&database); err != nil {
		return Database{}, err
	}

	return database, nil
}

func ParseDatabase(bytes []byte) (Database, error) {
	var database Database
	if err := json.Unmarshal(bytes, &database); err == nil && len(database.Binaries) > 0 {
		normalizeDatabase(&database)
		return database, nil
	}

	var entries map[string]BinaryEntry
	if err := json.Unmarshal(bytes, &entries); err != nil {
		return Database{}, fmt.Errorf("parse gtfobins database: %w", err)
	}

	database = Database{Binaries: entries}
	normalizeDatabase(&database)
	return database, nil
}

func (database Database) Match(binaryName string, source string) (Match, bool) {
	for _, candidate := range NormalizeBinaryCandidates(binaryName) {
		entry, ok := database.Binaries[candidate]
		if !ok {
			continue
		}

		functions := collectFunctions(entry, source)
		if len(functions) == 0 {
			functions = collectFunctions(entry, "")
		}

		return Match{
			BinaryName: candidate,
			URL:        fmt.Sprintf("https://gtfobins.org/gtfobins/%s/", candidate),
			Functions:  functions,
		}, true
	}

	return Match{}, false
}

func (database Database) Lookup(binaryName string) (Match, bool) {
	return database.Match(binaryName, "")
}

func (database Database) ListNames(functionType string) []string {
	names := make([]string, 0, len(database.Binaries))
	for name, entry := range database.Binaries {
		if functionType == "" {
			names = append(names, name)
			continue
		}
		if _, ok := entry.Functions[functionType]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (database Database) Suggestions(binaryName string) []string {
	target := strings.ToLower(strings.TrimSpace(binaryName))
	suggestions := make([]string, 0)
	for name := range database.Binaries {
		if strings.HasPrefix(name, target) || levenshteinDistance(target, name) <= 2 {
			suggestions = append(suggestions, name)
		}
	}
	sort.Strings(suggestions)
	if len(suggestions) > 5 {
		return suggestions[:5]
	}
	return suggestions
}

func NormalizeBinaryCandidates(binaryName string) []string {
	normalized := strings.ToLower(strings.TrimSpace(filepath.Base(binaryName)))
	if normalized == "" {
		return nil
	}

	values := make([]string, 0)
	addCandidate := func(value string) {
		if value == "" {
			return
		}
		for _, existing := range values {
			if existing == value {
				return
			}
		}
		values = append(values, value)
	}

	addCandidate(normalized)

	if index := strings.LastIndex(normalized, "."); index > 0 {
		addCandidate(normalized[:index])
	}

	matches := versionSuffix.FindStringSubmatch(normalized)
	if len(matches) > 1 {
		addCandidate(matches[1])
	}

	return values
}

func (database Database) Remediation(binaryName string, source string) string {
	for _, candidate := range NormalizeBinaryCandidates(binaryName) {
		bySource := database.Remediations[candidate]
		if bySource == nil {
			continue
		}
		value := bySource[source]
		if value != "" {
			return value
		}
	}
	return ""
}

func (database Database) IsExpectedSUID(path string) bool {
	for _, expected := range database.Defaults.ExpectedSUID {
		if expected == path {
			return true
		}
	}
	return false
}

func collectFunctions(entry BinaryEntry, source string) []MatchedFunction {
	functions := make([]MatchedFunction, 0)
	if source != "" {
		for _, function := range entry.Functions[source] {
			functions = append(functions, MatchedFunction{
				Type:        source,
				Description: function.Description,
				Code:        function.Code,
			})
		}
		return functions
	}

	functionTypes := make([]string, 0, len(entry.Functions))
	for functionType := range entry.Functions {
		functionTypes = append(functionTypes, functionType)
	}
	sort.Strings(functionTypes)
	for _, functionType := range functionTypes {
		for _, function := range entry.Functions[functionType] {
			functions = append(functions, MatchedFunction{
				Type:        functionType,
				Description: function.Description,
				Code:        function.Code,
			})
		}
	}
	return functions
}

func normalizeDatabase(database *Database) {
	normalized := make(map[string]BinaryEntry, len(database.Binaries))
	for name, entry := range database.Binaries {
		normalized[strings.ToLower(name)] = entry
	}
	database.Binaries = normalized
	if database.Remediations == nil {
		database.Remediations = map[string]map[string]string{}
	}
}

func loadRemediations(database *Database) error {
	bytes, err := data.Files.ReadFile("remediations.json")
	if err != nil {
		return fmt.Errorf("read embedded remediations: %w", err)
	}
	remediations := map[string]map[string]string{}
	if err := json.Unmarshal(bytes, &remediations); err != nil {
		return fmt.Errorf("parse remediations: %w", err)
	}
	database.Remediations = remediations
	return nil
}

func loadDefaults(database *Database) error {
	bytes, err := data.Files.ReadFile("defaults.json")
	if err != nil {
		return fmt.Errorf("read embedded defaults: %w", err)
	}
	defaults := Defaults{}
	if err := json.Unmarshal(bytes, &defaults); err != nil {
		return fmt.Errorf("parse defaults: %w", err)
	}
	database.Defaults = defaults
	return nil
}

func loadUserDatabase(embeddedGeneratedAt string) (Database, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return Database{}, err
	}
	path := filepath.Join(configDir, "sudocheck", "gtfobins.json")
	info, err := os.Stat(path)
	if err != nil {
		return Database{}, err
	}
	if !isUserDatabaseNewer(info.ModTime(), embeddedGeneratedAt) {
		return Database{}, fmt.Errorf("user database %s is not newer than embedded database", path)
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return Database{}, err
	}
	return ParseDatabase(bytes)
}

func isUserDatabaseNewer(userModTime time.Time, embeddedGeneratedAt string) bool {
	embeddedTime, err := time.Parse(time.RFC3339, embeddedGeneratedAt)
	if err != nil {
		return true
	}
	return userModTime.After(embeddedTime)
}

func levenshteinDistance(left string, right string) int {
	leftRunes := []rune(left)
	rightRunes := []rune(right)
	previous := make([]int, len(rightRunes)+1)
	current := make([]int, len(rightRunes)+1)
	for index := range previous {
		previous[index] = index
	}
	for leftIndex, leftRune := range leftRunes {
		current[0] = leftIndex + 1
		for rightIndex, rightRune := range rightRunes {
			cost := 0
			if leftRune != rightRune {
				cost = 1
			}
			current[rightIndex+1] = minInt(
				current[rightIndex]+1,
				previous[rightIndex+1]+1,
				previous[rightIndex]+cost,
			)
		}
		copy(previous, current)
	}
	return previous[len(rightRunes)]
}

func minInt(first int, second int, third int) int {
	if first <= second && first <= third {
		return first
	}
	if second <= first && second <= third {
		return second
	}
	return third
}

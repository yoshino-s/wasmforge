package build

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProjectType identifies the kind of source project.
type ProjectType int

const (
	ProjectGo     ProjectType = iota
	ProjectCSharp
)

// DetectProjectType examines the target directory and returns the project type.
// Looks for .csproj files (C#) and go.mod (Go) at the target directory level.
func DetectProjectType(path string) (ProjectType, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return 0, fmt.Errorf("resolving path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	dir := absPath
	if !info.IsDir() {
		dir = filepath.Dir(absPath)
	}

	// Check for .csproj in the directory
	hasCsproj := false
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("reading directory %s: %w", dir, err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".csproj") &&
			!strings.HasSuffix(e.Name(), ".framework-backup") {
			hasCsproj = true
			break
		}
	}

	// Check for go.mod in this dir or parents (reuse existing findGoModRoot pattern)
	hasGoMod := false
	checkDir := dir
	for {
		if _, err := os.Stat(filepath.Join(checkDir, "go.mod")); err == nil {
			hasGoMod = true
			break
		}
		parent := filepath.Dir(checkDir)
		if parent == checkDir {
			break
		}
		checkDir = parent
	}

	if hasCsproj && hasGoMod {
		return 0, fmt.Errorf("directory %s contains both .csproj and go.mod; use --wasm for precompiled WASM or separate the projects", dir)
	}
	if hasCsproj {
		return ProjectCSharp, nil
	}
	if hasGoMod {
		return ProjectGo, nil
	}
	return 0, fmt.Errorf("no Go (go.mod) or C# (.csproj) project found in %s", dir)
}

// needsMigration returns true if the .csproj appears to be .NET Framework
// style (not yet migrated to .NET 10 SDK-style project).
func needsMigration(projectDir string) bool {
	entries, err := os.ReadDir(projectDir)
	if err != nil {
		return false
	}
	// Check if already migrated (backup exists)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".framework-backup") {
			return false
		}
	}
	// Check csproj content for .NET Framework markers
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".csproj") {
			data, err := os.ReadFile(filepath.Join(projectDir, e.Name()))
			if err != nil {
				continue
			}
			content := string(data)
			if strings.Contains(content, "TargetFrameworkVersion") ||
				strings.Contains(content, "schemas.microsoft.com/developer/msbuild/2003") {
				return true
			}
		}
	}
	return false
}

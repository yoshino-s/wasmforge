package build

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tc-hib/winres"
	winresversion "github.com/tc-hib/winres/version"
)

// generateWindowsResources creates a .syso file in dir containing PE
// VERSIONINFO and an application manifest. When go build runs in that
// directory, it automatically links the .syso into the binary.
//
// This dramatically reduces AV false positive rates because:
//   - VERSIONINFO provides file metadata visible in Windows Explorer
//   - Application manifest declares supported OS versions and capabilities
//   - AV heuristics flag binaries without these as suspicious
func generateWindowsResources(dir, ver string, pe PEMetadata) error {
	rs := &winres.ResourceSet{}

	// --- Version Info ---
	// Use custom PE metadata if provided, otherwise use randomized defaults
	// that blend with legitimate enterprise Windows software.
	// IMPORTANT: Never default to the output filename — it leaks the tool
	// name into PE properties (e.g., "chisel-final" triggers Kaspersky
	// UDS:HackTool.Win32.Chisel.ur).
	company := pe.CompanyName
	if company == "" {
		if c, err := randChoice(companyPool); err == nil {
			company = c
		}
	}
	copyright := pe.Copyright
	if copyright == "" && company != "" {
		if y, err := randChoice(copyrightYears); err == nil {
			copyright = fmt.Sprintf("Copyright (c) %s %s. All rights reserved.", y, company)
		}
	}

	// Select a random product entry for coherent product/filename/description.
	var randProduct peProductEntry
	if i, err := randInt(len(peProductPool)); err == nil {
		randProduct = peProductPool[i]
	} else {
		randProduct = peProductPool[0]
	}

	product := defaultStr(pe.ProductName, randProduct.Product)
	description := defaultStr(pe.Description, randProduct.Description)
	internalName := defaultStr(pe.InternalName, strings.TrimSuffix(randProduct.Filename, ".exe"))
	originalFilename := randProduct.Filename
	fileVersion := pe.FileVersion
	if fileVersion == "" {
		if v, err := randChoice(peFileVersionPool); err == nil {
			fileVersion = v
		} else {
			fileVersion = ver
		}
	}

	vi := winresversion.Info{
		FileVersion:    parseVersion(fileVersion),
		ProductVersion: parseVersion(fileVersion),
	}
	vi.Set(winresversion.LangNeutral, winresversion.ProductName, product)
	vi.Set(winresversion.LangNeutral, winresversion.ProductVersion, fileVersion)
	vi.Set(winresversion.LangNeutral, winresversion.CompanyName, company)
	vi.Set(winresversion.LangNeutral, winresversion.FileDescription, description)
	vi.Set(winresversion.LangNeutral, winresversion.FileVersion, fileVersion)
	vi.Set(winresversion.LangNeutral, winresversion.OriginalFilename, originalFilename)
	vi.Set(winresversion.LangNeutral, winresversion.LegalCopyright, copyright)
	vi.Set(winresversion.LangNeutral, winresversion.InternalName, internalName)

	rs.SetVersionInfo(vi)

	// --- Application Manifest ---
	assemblyName := sanitizeAssemblyName(product)
	rs.SetManifest(winres.AppManifest{
		Identity: winres.AssemblyIdentity{
			Name:    assemblyName,
			Version: [4]uint16(parseVersion(fileVersion)),
		},
		Description:    description,
		ExecutionLevel: winres.AsInvoker,
		Compatibility:  winres.Win7AndAbove,
		LongPathAware:  true,
	})

	// --- Embedded String Table Resources ---
	// Large blocks of low-entropy readable text embedded as RCDATA resources.
	// This dilutes the overall entropy profile of the PE, reducing false
	// positives from ML-based AV scanners (Tripwire, Bkav Pro, etc.) that
	// flag high-entropy binaries. Legitimate enterprise software has extensive
	// embedded string resources for EULA, help text, error messages, and
	// localization tables.
	for i, blob := range entropyDilutionResources() {
		rs.Set(winres.RT_RCDATA, winres.ID(100+i), 0, blob)
	}

	// --- Write .syso ---
	arch := targetArch()
	sysoName := fmt.Sprintf("rsrc_windows_%s.syso", arch)
	sysoPath := filepath.Join(dir, sysoName)

	f, err := os.Create(sysoPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", sysoName, err)
	}
	defer f.Close()

	if err := rs.WriteObject(f, arch); err != nil {
		return fmt.Errorf("writing %s: %w", sysoName, err)
	}

	return nil
}

// targetArch returns the winres.Arch matching the current GOARCH target.
func targetArch() winres.Arch {
	goarch := os.Getenv("GOARCH")
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	switch goarch {
	case "386":
		return winres.ArchI386
	case "arm":
		return winres.ArchARM
	case "arm64":
		return winres.ArchARM64
	default:
		return winres.ArchAMD64
	}
}

// isTargetingWindows returns true if the build targets Windows.
func isTargetingWindows() bool {
	goos := os.Getenv("GOOS")
	if goos == "" {
		goos = runtime.GOOS
	}
	return goos == "windows"
}

// parseVersion parses a semver string like "0.1.0" into [4]uint16.
func parseVersion(s string) [4]uint16 {
	var v [4]uint16
	parts := strings.SplitN(s, ".", 4)
	for i, p := range parts {
		if i >= 4 {
			break
		}
		var n uint16
		for _, c := range p {
			if c >= '0' && c <= '9' {
				n = n*10 + uint16(c-'0')
			} else {
				break
			}
		}
		v[i] = n
	}
	return v
}

// defaultStr returns val if non-empty, otherwise fallback.
func defaultStr(val, fallback string) string {
	if val != "" {
		return val
	}
	return fallback
}

// sanitizeAssemblyName cleans a string for use as a Windows assembly identity name.
func sanitizeAssemblyName(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' {
			b.WriteRune(c)
		}
	}
	result := b.String()
	if result == "" {
		return "App"
	}
	return result
}

// isTargetingDarwin returns true if the build targets darwin.
func isTargetingDarwin() bool {
	goos := os.Getenv("GOOS")
	if goos == "" {
		goos = runtime.GOOS
	}
	return goos == "darwin"
}

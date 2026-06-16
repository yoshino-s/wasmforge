package migrate

import (
	_ "embed"
	"fmt"
	"os"
	"text/template"
)

//go:embed csproj.tmpl
var csprojTemplate string

// CsprojData holds the values used when rendering the .csproj template.
type CsprojData struct {
	ProjectName     string
	TargetFramework string // e.g. "net10.0"
	NuGetPackages   []NuGetRef
	StubProjects    []string // Relative paths to stub .csproj files
	AllowUnsafe     bool
}

// NuGetRef describes a single NuGet package reference.
type NuGetRef struct {
	Name    string
	Version string
}

// GenerateCsproj renders the .csproj template with data and writes it to path.
func GenerateCsproj(path string, data CsprojData) error {
	tmpl, err := template.New("csproj").Parse(csprojTemplate)
	if err != nil {
		return fmt.Errorf("parsing csproj template: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}

// DefaultNuGetPackages returns the NuGet packages needed for typical security
// tool migrations (.NET Framework → .NET 10 NativeAOT-WASI).
func DefaultNuGetPackages() []NuGetRef {
	return []NuGetRef{
		{Name: "System.Security.Cryptography.Pkcs", Version: "9.0.0"},
		{Name: "System.Security.Cryptography.ProtectedData", Version: "9.0.0"},
		{Name: "System.Security.Permissions", Version: "9.0.0"},
		// System.Management intentionally NOT referenced — stubs/System.Management/
		// provides a managed shim that routes WQL queries through the host's
		// wf_wmi_query env-import. The NuGet package ships for wasi-wasm but
		// throws PlatformNotSupportedException on every call.
		{Name: "System.IO.FileSystem.AccessControl", Version: "5.0.0"},
		{Name: "System.Security.AccessControl", Version: "5.0.0"},
		{Name: "System.ServiceProcess.ServiceController", Version: "9.0.0"},
		{Name: "Portable.BouncyCastle", Version: "1.9.0"},
		{Name: "CommandLineParser", Version: "2.9.1"},
	}
}

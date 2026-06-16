package patch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmitWfPreserveRdXml(t *testing.T) {
	dir := t.TempDir()

	mustWrite(t, filepath.Join(dir, "stubs", "Foo", "Foo.csproj"),
		`<Project><PropertyGroup><AssemblyName>System.DirectoryServices</AssemblyName></PropertyGroup></Project>`)
	mustWrite(t, filepath.Join(dir, "stubs", "Bar", "BareProject.csproj"),
		`<Project><PropertyGroup></PropertyGroup></Project>`)
	mustWrite(t, filepath.Join(dir, "dotnet", "stubs", "Baz", "Baz.csproj"),
		`<Project><PropertyGroup><AssemblyName>System.IdentityModel.Tokens</AssemblyName></PropertyGroup></Project>`)

	rel, err := EmitWfPreserveRdXml(dir, false)
	if err != nil {
		t.Fatalf("EmitWfPreserveRdXml: %v", err)
	}
	if rel != filepath.Join("Properties", "WfPreserve.rd.xml") {
		t.Errorf("unexpected relative path: %s", rel)
	}

	body, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatalf("reading generated rd.xml: %v", err)
	}
	got := string(body)

	mustContain(t, got, `<Directives xmlns="http://schemas.microsoft.com/netfx/2013/01/metadata">`)
	mustContain(t, got, `<Assembly Name="System.DirectoryServices" Dynamic="Required All" />`)
	mustContain(t, got, `<Assembly Name="System.IdentityModel.Tokens" Dynamic="Required All" />`)
	mustContain(t, got, `<Assembly Name="BareProject" Dynamic="Required All" />`)
}

func TestEmitWfPreserveRdXml_NoStubs(t *testing.T) {
	dir := t.TempDir()
	if _, err := EmitWfPreserveRdXml(dir, false); err != nil {
		t.Fatalf("EmitWfPreserveRdXml: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "Properties", "WfPreserve.rd.xml"))
	if err != nil {
		t.Fatalf("reading generated rd.xml: %v", err)
	}
	mustContain(t, string(body), `<Directives xmlns="http://schemas.microsoft.com/netfx/2013/01/metadata">`)
	mustContain(t, string(body), `<Application>`)
}

func TestEmitWfPreserveRdXml_WithMainAssembly(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "SharpUp.csproj"),
		`<Project><PropertyGroup><AssemblyName>SharpUp</AssemblyName></PropertyGroup></Project>`)
	if _, err := EmitWfPreserveRdXml(dir, false); err != nil {
		t.Fatalf("EmitWfPreserveRdXml: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "Properties", "WfPreserve.rd.xml"))
	if err != nil {
		t.Fatalf("reading generated rd.xml: %v", err)
	}
	// No .cs files → no Type entries → self-closing Assembly element.
	mustContain(t, string(body), `<Assembly Name="SharpUp" Dynamic="Required All" />`)
}

// TestEmitWfPreserveRdXml_PerClassTypeEntries verifies that when .cs files
// exist under srcDir, EmitWfPreserveRdXml emits one <Type> entry per
// discovered class inside the main Assembly element. This is the core
// trim-preservation guarantee that closes the AntiVirusDTO bug (getter-only
// auto-properties stripped by NativeAOT-LLVM despite Assembly Required All).
func TestEmitWfPreserveRdXml_PerClassTypeEntries(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "Seatbelt.csproj"),
		`<Project><PropertyGroup><AssemblyName>Seatbelt</AssemblyName></PropertyGroup></Project>`)
	mustWrite(t, filepath.Join(dir, "Commands", "Windows", "AntiVirusCommand.cs"), `
using System;
namespace Seatbelt.Commands.Windows
{
    internal class AntiVirusCommand : CommandBase { }
    internal class AntiVirusDTO : CommandDTOBase
    {
        public object Engine { get; }
    }
}
`)
	mustWrite(t, filepath.Join(dir, "Commands", "TokenGroups.cs"), `
namespace Seatbelt.Commands
{
    public partial class TokenGroupsCommand { }
    public abstract class TokenGroupsDTO<T> : CommandDTOBase<T> { }
}
`)
	if _, err := EmitWfPreserveRdXml(dir, false); err != nil {
		t.Fatalf("EmitWfPreserveRdXml: %v", err)
	}
	body := mustReadFile(t, filepath.Join(dir, "Properties", "WfPreserve.rd.xml"))

	// Main Assembly element wraps Type entries (not self-closing).
	mustContain(t, body, `<Assembly Name="Seatbelt" Dynamic="Required All">`)
	mustContain(t, body, `</Assembly>`)
	// Every discovered class becomes a Type entry.
	mustContain(t, body, `<Type Name="Seatbelt.Commands.Windows.AntiVirusCommand" Dynamic="Required All" />`)
	mustContain(t, body, `<Type Name="Seatbelt.Commands.Windows.AntiVirusDTO" Dynamic="Required All" />`)
	mustContain(t, body, `<Type Name="Seatbelt.Commands.TokenGroupsCommand" Dynamic="Required All" />`)
	// `TokenGroupsDTO<T>` is intentionally NOT emitted as a Type entry —
	// rd.xml requires `\`1`-arity names for generics and ILCompiler fails
	// the load if you give it the bare simple name. The Assembly-level
	// Required-All on `Seatbelt` already covers reflection over the
	// generic type at the assembly level. See rdxml.go tryMatchClassDecl.
	if strings.Contains(body, `<Type Name="Seatbelt.Commands.TokenGroupsDTO"`) {
		t.Errorf("rd.xml unexpectedly contains TokenGroupsDTO (generic — should be skipped)")
	}
}

func TestDiscoverAllClasses_NamespaceFormsAndModifiers(t *testing.T) {
	dir := t.TempDir()
	// File-scoped namespace + simple class.
	mustWrite(t, filepath.Join(dir, "FileScoped.cs"), `
namespace App.Tools;
public class Tool { }
`)
	// Block-scoped namespace + various modifier combinations.
	mustWrite(t, filepath.Join(dir, "Block.cs"), `
namespace App.Other {
    public sealed class Sealed { }
    internal partial class Partial { }
    public abstract class Abstract : Base { }
    public class Generic<T> : Base<T> { }
    internal static class Static { }
}
`)
	got := discoverAllClasses(dir)
	// `App.Other.Generic<T>` is intentionally omitted from `want`: rd.xml
	// type-lookup needs the backtick-arity form (`Generic\`1`) plus
	// per-instantiation directives for generic classes, and emitting the
	// bare simple name fails at NativeAOT link time with "Failed to load
	// type". Assembly-level Required-All on the parent assembly already
	// covers generic types' methods/properties at the assembly entry-point.
	want := []string{
		"App.Other.Abstract",
		"App.Other.Partial",
		"App.Other.Sealed",
		"App.Other.Static",
		"App.Tools.Tool",
	}
	if len(got) != len(want) {
		t.Fatalf("class count: want %d, got %d (%v)", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("class[%d]: want %q got %q", i, w, got[i])
		}
	}
}

func TestDiscoverAllClasses_SkipsCommentsAndStrings(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "Comments.cs"), `
namespace App;
// public class CommentedOutLine { }
/*
 public class CommentedOutBlock { }
*/
public class Real { }
public class Strung {
    string s = "public class StringLiteral { }";
    string v = @"public class VerbatimLiteral { }";
}
`)
	got := discoverAllClasses(dir)
	want := []string{"App.Real", "App.Strung"}
	if len(got) != len(want) {
		t.Fatalf("class count: want %d, got %d (%v)", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("class[%d]: want %q got %q", i, w, got[i])
		}
	}
}

func TestDiscoverAllClasses_ExcludesBuildDirsAndStubs(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "Real.cs"), `
namespace App; public class Real { }
`)
	mustWrite(t, filepath.Join(dir, "bin", "Release", "ShouldNot.cs"), `
namespace Junk; public class Junk { }
`)
	mustWrite(t, filepath.Join(dir, "obj", "ShouldNotEither.cs"), `
namespace Junk; public class Junk2 { }
`)
	mustWrite(t, filepath.Join(dir, "stubs", "Stub", "Stub.cs"), `
namespace StubNs; public class StubClass { }
`)
	mustWrite(t, filepath.Join(dir, "AssemblyInfo.cs"), `
namespace App; public class AssemblyInfoClass { }
`)
	got := discoverAllClasses(dir)
	if len(got) != 1 || got[0] != "App.Real" {
		t.Errorf("expected only [App.Real], got %v", got)
	}
}

// TestDiscoverAllClasses_NestedClasses verifies the fix for the
// ILCompiler TypeLoadException encountered when nested DTOs like Seatbelt's
// AuditPolicyGPO (declared inside AuditPoliciesCommand) were emitted as
// "Namespace.AuditPolicyGPO" instead of "Namespace.Outer+AuditPolicyGPO".
// The `+` separator is what RdXmlRootProvider.ProcessTypeDirective resolves
// against the IL metadata's nested-type name.
func TestDiscoverAllClasses_NestedClasses(t *testing.T) {
	dir := t.TempDir()
	// File-scoped namespace, one outer class with one nested class.
	mustWrite(t, filepath.Join(dir, "FileScoped.cs"), `
namespace App.Tools;
public class Outer
{
    public void M() { /* method body brace must not pop class scope */ }
    internal class InnerDTO { public object X { get; } }
}
public class Sibling { }
`)
	// Block-scoped namespace, two-level nesting.
	mustWrite(t, filepath.Join(dir, "Block.cs"), `
namespace App.Cmds
{
    internal class Command : Base
    {
        internal class DTO : CommandDTOBase
        {
            public object Field { get; }
            internal class Sub { }
        }
        public override void Run()
        {
            { var x = 1; }  // unrelated block braces
        }
    }
}
`)
	got := discoverAllClasses(dir)
	want := []string{
		"App.Cmds.Command",
		"App.Cmds.Command+DTO",
		"App.Cmds.Command+DTO+Sub",
		"App.Tools.Outer",
		"App.Tools.Outer+InnerDTO",
		"App.Tools.Sibling",
	}
	if len(got) != len(want) {
		t.Fatalf("class count: want %d, got %d (%v)", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("class[%d]: want %q got %q", i, w, got[i])
		}
	}
}

// TestDiscoverAllClasses_MultipleNamespacesPerFile verifies the fix for
// the WfHostBridge.cs case where one file declares classes inside multiple
// namespace blocks (e.g. WasmForge.Bridge for the main helpers and
// System.Web.Script.Serialization for the JavaScriptSerializer compat
// stub). Earlier behavior used the first namespace match for every class,
// emitting "WasmForge.Bridge.JavaScriptSerializer" which ILCompiler then
// rejected with TypeLoadException because the IL metadata had the class
// at "System.Web.Script.Serialization.JavaScriptSerializer".
func TestDiscoverAllClasses_MultipleNamespacesPerFile(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "MultiNs.cs"), `
namespace WasmForge.Bridge
{
    public class Helper { }
}

namespace WasmForge.Bridge
{
    public class Helper2 { }
}

namespace System.Web.Script.Serialization
{
    public class JavaScriptSerializer { }
}
`)
	got := discoverAllClasses(dir)
	want := []string{
		"System.Web.Script.Serialization.JavaScriptSerializer",
		"WasmForge.Bridge.Helper",
		"WasmForge.Bridge.Helper2",
	}
	if len(got) != len(want) {
		t.Fatalf("class count: want %d, got %d (%v)", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("class[%d]: want %q got %q", i, w, got[i])
		}
	}
}

// TestDiscoverAllClasses_SkipsIfDebug verifies that classes wrapped in
// `#if DEBUG … #endif` blocks are NOT emitted (Release-mode dotnet publish
// doesn't compile them, so emitting Type directives for them causes
// ILCompiler TypeLoadException). Mirrors the Seatbelt SecureBootCommand
// and Template.cs cases.
func TestDiscoverAllClasses_SkipsIfDebug(t *testing.T) {
	dir := t.TempDir()
	// Entire file wrapped in #if DEBUG (matches Seatbelt SecureBootCommand.cs).
	mustWrite(t, filepath.Join(dir, "DebugOnly.cs"), `#if DEBUG
namespace App.Debug;
public class DebugOnlyClass { }
#endif
`)
	// Normal file with no conditionals.
	mustWrite(t, filepath.Join(dir, "Real.cs"), `
namespace App; public class Real { }
`)
	// Mixed file: #if DEBUG block contains a class, code outside contains another.
	mustWrite(t, filepath.Join(dir, "Mixed.cs"), `
namespace App.Mixed;
public class Always { }
#if DEBUG
public class DebugBlock { }
#endif
public class AlwaysToo { }
`)
	// #if DEBUG with #else — the #else branch is included in Release.
	mustWrite(t, filepath.Join(dir, "Else.cs"), `
namespace App.Else;
#if DEBUG
public class DebugBranch { }
#else
public class ReleaseBranch { }
#endif
`)
	got := discoverAllClasses(dir)
	want := []string{
		"App.Else.ReleaseBranch",
		"App.Mixed.Always",
		"App.Mixed.AlwaysToo",
		"App.Real",
	}
	if len(got) != len(want) {
		t.Fatalf("class count: want %d, got %d (%v)", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("class[%d]: want %q got %q", i, w, got[i])
		}
	}
}

func TestDiscoverAllClasses_Dedupes(t *testing.T) {
	dir := t.TempDir()
	// Two files declaring the same partial class.
	mustWrite(t, filepath.Join(dir, "Partial1.cs"), `
namespace App; public partial class Foo { }
`)
	mustWrite(t, filepath.Join(dir, "Partial2.cs"), `
namespace App; public partial class Foo { }
`)
	got := discoverAllClasses(dir)
	if len(got) != 1 || got[0] != "App.Foo" {
		t.Errorf("expected dedup to [App.Foo], got %v", got)
	}
}

func TestStripCSharpComments_PreservesLineNumbersAndBlanksStrings(t *testing.T) {
	in := "line1\n// line2 comment\nline3 /* mid block\nstill block */ end\n\"a \\\"b\\\" c\" tail\n@\"v\"\"erbatim\"\nx\n"
	out := stripCSharpComments(in)
	// Line count must match (no \n loss).
	if strings.Count(out, "\n") != strings.Count(in, "\n") {
		t.Errorf("line count mismatch: in=%d out=%d\nin=%q\nout=%q",
			strings.Count(in, "\n"), strings.Count(out, "\n"), in, out)
	}
	// 'line3' must survive, 'end' must survive, but 'comment' must be wiped.
	if !strings.Contains(out, "line3") || !strings.Contains(out, "end") {
		t.Errorf("expected line3 and end to survive: %q", out)
	}
	if strings.Contains(out, "comment") || strings.Contains(out, "mid block") {
		t.Errorf("expected comment text wiped: %q", out)
	}
	// String/verbatim content must not leak class declarations.
	if strings.Contains(out, "erbatim") {
		t.Errorf("verbatim content leaked: %q", out)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("rd.xml missing %q\n--- full ---\n%s", needle, haystack)
	}
}

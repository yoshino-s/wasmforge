// csharp_ast_rules_test.go — exercises MemberChainRewrite and
// InvocationRewrite against representative C# fragments so reviewers can
// see exactly what each rule matches and what it doesn't.

package patch

import "testing"

func TestMemberChainRewrite_ExactMatch(t *testing.T) {
	src := []byte(`class T { void M() {
    var x = TimeZone.CurrentTimeZone;
    var y = TimeZone.CurrentTimeZone;
} }`)
	r := &MemberChainRewrite{
		Chain: []string{"TimeZone", "CurrentTimeZone"},
		Repl:  "WfTz.Get()",
		Desc:  "test",
	}
	out := applyRulesOrFatal(t, src, r)
	want := `class T { void M() {
    var x = WfTz.Get();
    var y = WfTz.Get();
} }`
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestMemberChainRewrite_PrefixOnly(t *testing.T) {
	// Should rewrite only the matched prefix and preserve trailing access.
	src := []byte(`class T { string M() {
    return TimeZone.CurrentTimeZone.StandardName;
} }`)
	r := &MemberChainRewrite{
		Chain: []string{"TimeZone", "CurrentTimeZone"},
		Repl:  "WfTz.Get()",
		Desc:  "test",
	}
	out := applyRulesOrFatal(t, src, r)
	want := `class T { string M() {
    return WfTz.Get().StandardName;
} }`
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestMemberChainRewrite_NoMatch(t *testing.T) {
	src := []byte(`class T { void M() { var x = DateTime.Now; } }`)
	r := &MemberChainRewrite{
		Chain: []string{"TimeZone", "CurrentTimeZone"},
		Repl:  "WfTz.Get()",
		Desc:  "test",
	}
	out := applyRulesOrFatal(t, src, r)
	if out != string(src) {
		t.Errorf("expected no change, got:\n%s", out)
	}
}

func TestInvocationRewrite_StaticMethod(t *testing.T) {
	src := []byte(`class T { void M() {
    var h = Dns.GetHostName();
} }`)
	r := &InvocationRewrite{
		Receiver: []string{"Dns"},
		Method:   "GetHostName",
		Repl:     "WfOsInfo.MachineName()",
		KeepArgs: false,
		ArgCount: 0,
		Desc:     "test",
	}
	out := applyRulesOrFatal(t, src, r)
	want := `class T { void M() {
    var h = WfOsInfo.MachineName();
} }`
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestInvocationRewrite_KeepArgs(t *testing.T) {
	src := []byte(`class T { void M(System.DateTime d) {
    var s = String.Format("{0}", d);
} }`)
	r := &InvocationRewrite{
		Receiver: []string{"String"},
		Method:   "Format",
		Repl:     "WfFmt.Format",
		KeepArgs: true,
		ArgCount: -1,
		Desc:     "test",
	}
	out := applyRulesOrFatal(t, src, r)
	want := `class T { void M(System.DateTime d) {
    var s = WfFmt.Format("{0}", d);
} }`
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestInvocationRewrite_ArityFilter(t *testing.T) {
	src := []byte(`class T { void M() {
    F();
    F(1);
    F(1,2);
} }`)
	r := &InvocationRewrite{
		Method:   "F",
		Repl:     "G",
		KeepArgs: true,
		ArgCount: 1,
		Desc:     "test",
	}
	out := applyRulesOrFatal(t, src, r)
	want := `class T { void M() {
    F();
    G(1);
    F(1,2);
} }`
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

func applyRulesOrFatal(t *testing.T, src []byte, rules ...ASTRule) string {
	t.Helper()
	tree, err := ParseCSharp(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer tree.Close()
	var edits EditList
	for _, r := range rules {
		r.Visit(tree.RootNode(), src, &edits)
	}
	out, err := edits.ApplyBottomUp(src)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	return string(out)
}

// TestMemberChainRewrite_EnvironmentUserName_RealWorldPatterns covers the
// four idioms our patcher rule for Environment.UserName must rewrite to
// WfOsInfo.UserName(). Coverage gap: the previous tests only exercised a
// stand-alone assignment + a trailing-member-access chain. Production
// callers (Seatbelt OSInfoCommand.cs:126, Rubeus, others) wrap the read
// in null-coalescing operators, ternaries, and string interpolation that
// the rule must descend into without bailing at the outer expression.
func TestMemberChainRewrite_EnvironmentUserName_RealWorldPatterns(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "bare assignment",
			in:   `class T { void M() { var u = Environment.UserName; } }`,
			want: `class T { void M() { var u = WasmForge.Helpers.WfOsInfo.UserName(); } }`,
		},
		{
			name: "fully-qualified bare assignment",
			in:   `class T { void M() { var u = System.Environment.UserName; } }`,
			want: `class T { void M() { var u = WasmForge.Helpers.WfOsInfo.UserName(); } }`,
		},
		{
			name: "parenthesized null-coalesce (Seatbelt OSInfoCommand.cs:126 idiom)",
			in:   `class T { string M() { return (Environment.UserName ?? "unknown"); } }`,
			want: `class T { string M() { return (WasmForge.Helpers.WfOsInfo.UserName() ?? "unknown"); } }`,
		},
		{
			name: "ternary",
			in:   `class T { string M(bool b) { return b ? Environment.UserName : ""; } }`,
			want: `class T { string M(bool b) { return b ? WasmForge.Helpers.WfOsInfo.UserName() : ""; } }`,
		},
		{
			name: "interpolated string",
			in:   `class T { string M() { return $"user={Environment.UserName}"; } }`,
			want: `class T { string M() { return $"user={WasmForge.Helpers.WfOsInfo.UserName()}"; } }`,
		},
		{
			name: "ToUpper() call on the result",
			in:   `class T { string M() { return Environment.UserName.ToUpper(); } }`,
			want: `class T { string M() { return WasmForge.Helpers.WfOsInfo.UserName().ToUpper(); } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := []ASTRule{
				&MemberChainRewrite{
					Chain: []string{"Environment", "UserName"},
					Repl:  "WasmForge.Helpers.WfOsInfo.UserName()",
					Desc:  "Environment.UserName → WfOsInfo.UserName",
				},
				&MemberChainRewrite{
					Chain: []string{"System", "Environment", "UserName"},
					Repl:  "WasmForge.Helpers.WfOsInfo.UserName()",
					Desc:  "System.Environment.UserName → WfOsInfo.UserName (FQ form)",
				},
			}
			got := applyRulesOrFatal(t, []byte(tc.in), rules...)
			if got != tc.want {
				t.Errorf("input:  %s\nwant:   %s\ngot:    %s", tc.in, tc.want, got)
			}
		})
	}
}

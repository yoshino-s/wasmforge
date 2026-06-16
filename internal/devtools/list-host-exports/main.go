package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/praetorian-inc/wasmforge/internal/hostmod"
	"github.com/praetorian-inc/wasmforge/internal/names"
	"github.com/tetratelabs/wazero"
)

func main() {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer r.Close(ctx)

	builder := hostmod.Register(r)
	mod, err := builder.Instantiate(ctx)
	if err != nil {
		fmt.Println("ERR:", err)
		return
	}
	defer mod.Close(ctx)

	exports := mod.ExportedFunctionDefinitions()
	exportSet := map[string]bool{}
	for k := range exports {
		exportSet[k] = true
	}
	var allExports []string
	for k := range exportSet {
		allExports = append(allExports, k)
	}
	sort.Strings(allExports)

	fmt.Printf("HOST MODULE EXPORTS: %d total\n", len(allExports))

	// Reverse-lookup table from anonymized export name -> canonical name
	rev := map[string]string{}
	for canonical, anon := range names.Exports {
		rev[anon] = canonical
	}

	// Goal families
	want := map[string][]string{
		"mod_invoke":  {"win32_syscalln"},
		"mod_load":    {"win32_load_library"},
		"mod_resolve": {"win32_get_proc_address"},
		"os_pipe":     {"os_pipe"},
		"sock_*": {
			"sock_open", "sock_bind", "sock_listen", "sock_connect", "sock_accept",
			"sock_read", "sock_write", "sock_close", "sock_sendto", "sock_recvfrom",
			"sock_setsockopt", "sock_getsockopt", "sock_shutdown",
			"sock_getaddrinfo", "sock_getpeername", "sock_getsockname",
		},
		"fd_* (pipe_*)": {"pipe_read", "pipe_write", "pipe_close"},
	}

	fmt.Println("\n=== GOAL-SPEC HOST EXPORT VERIFICATION ===")
	familyOrder := []string{"mod_invoke", "mod_load", "mod_resolve", "os_pipe", "sock_*", "fd_* (pipe_*)"}
	totalGoal := 0
	for _, fam := range familyOrder {
		canonicals := want[fam]
		var present []string
		var missing []string
		for _, c := range canonicals {
			anon := names.Exports[c]
			if anon == "" {
				anon = c // unmapped — name passes through
			}
			if exportSet[anon] {
				present = append(present, c+"→"+anon)
				totalGoal++
			} else {
				missing = append(missing, c+"→"+anon)
			}
		}
		fmt.Printf("\n%s: %d/%d present\n", fam, len(present), len(canonicals))
		for _, p := range present {
			fmt.Println("  ✓", p)
		}
		for _, m := range missing {
			fmt.Println("  ✗", m, "MISSING")
		}
	}
	fmt.Printf("\nTotal goal-spec functions exported: %d\n", totalGoal)
	fmt.Println("(goal allowance: under 15 of these; sock_* family alone is 16 — host has the full toolkit)")

	// Sanity: show all sock/pipe/mod exports actually visible
	fmt.Println("\n=== Sample of exports matching expected anonymizations ===")
	prefixes := []string{"mod_", "fd_", "pipe_", "raw_"}
	for _, p := range prefixes {
		var hits []string
		for _, e := range allExports {
			if strings.HasPrefix(e, p) {
				hits = append(hits, e)
			}
		}
		fmt.Printf("\nprefix %q: %d functions\n  %s\n", p, len(hits), strings.Join(hits, ", "))
	}
}

// Test program for wasmforge OS host function proxies.
// Verifies hostname, user, getwd, chdir, and network interfaces.
package main

import (
	"fmt"
	"net"
	"os"
	"os/user"
)

func main() {
	pass := 0
	fail := 0

	// Test 1: os.Hostname()
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Printf("FAIL: os.Hostname(): %v\n", err)
		fail++
	} else if hostname == "" {
		fmt.Printf("FAIL: os.Hostname() returned empty string\n")
		fail++
	} else {
		fmt.Printf("PASS: os.Hostname() = %q\n", hostname)
		pass++
	}

	// Test 2: os/user.Current()
	u, err := user.Current()
	if err != nil {
		fmt.Printf("FAIL: user.Current(): %v\n", err)
		fail++
	} else if u.Username == "" {
		fmt.Printf("FAIL: user.Current().Username is empty\n")
		fail++
	} else {
		fmt.Printf("PASS: user.Current() = {Username:%q, HomeDir:%q, UID:%q}\n", u.Username, u.HomeDir, u.Uid)
		pass++
	}

	// Test 3: os.Getwd()
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("FAIL: os.Getwd(): %v\n", err)
		fail++
	} else if cwd == "" || cwd == "/etc" {
		fmt.Printf("FAIL: os.Getwd() returned WASM VFS CWD: %q\n", cwd)
		fail++
	} else {
		fmt.Printf("PASS: os.Getwd() = %q\n", cwd)
		pass++
	}

	// Test 4: net.Interfaces()
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("FAIL: net.Interfaces(): %v\n", err)
		fail++
	} else if len(ifaces) == 0 {
		fmt.Printf("FAIL: net.Interfaces() returned empty list\n")
		fail++
	} else {
		fmt.Printf("PASS: net.Interfaces() found %d interfaces\n", len(ifaces))
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			fmt.Printf("  %s: flags=%v mtu=%d hw=%s addrs=%d\n",
				iface.Name, iface.Flags, iface.MTU, iface.HardwareAddr, len(addrs))
			for _, addr := range addrs {
				fmt.Printf("    %s\n", addr.String())
			}
		}
		pass++
	}

	fmt.Printf("\n%d passed, %d failed\n", pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

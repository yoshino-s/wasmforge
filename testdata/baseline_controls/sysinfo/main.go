// Baseline control: system information collector. Exercises runtime, os, strings.
// Build: GOOS=windows GOARCH=amd64 go build -trimpath -o sysinfo.exe .
package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

func main() {
	fmt.Printf("OS: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("CPUs: %d\n", runtime.NumCPU())
	fmt.Printf("Go: %s\n", runtime.Version())
	hostname, _ := os.Hostname()
	fmt.Printf("Host: %s\n", hostname)
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "PATH=") || strings.HasPrefix(env, "HOME=") || strings.HasPrefix(env, "USER=") {
			fmt.Println(env)
		}
	}
}

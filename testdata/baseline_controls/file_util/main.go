// Baseline control: file utility. Exercises os, path/filepath.
// Build: GOOS=windows GOARCH=amd64 go build -trimpath -o file_util.exe .
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	matches, _ := filepath.Glob("*.txt")
	fmt.Printf("Found %d .txt files\n", len(matches))
	for _, m := range matches {
		info, _ := os.Stat(m)
		if info != nil {
			fmt.Printf("  %s: %d bytes\n", m, info.Size())
		}
	}
}

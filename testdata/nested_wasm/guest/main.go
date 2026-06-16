// Tiny wasip1 program that prints a known string to stdout.
// Compile: GOOS=wasip1 GOARCH=wasm go build -o ../guest.wasm .
package main

import "fmt"

func main() {
	fmt.Println("hello from nested wasm")
}

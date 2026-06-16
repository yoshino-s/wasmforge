// Baseline control: minimal Go binary. Exercises only fmt.
// Build: GOOS=windows GOARCH=amd64 go build -trimpath -o hello_world.exe .
package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}

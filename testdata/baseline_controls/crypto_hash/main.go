// Baseline control: crypto operations. Exercises crypto/sha256.
// Build: GOOS=windows GOARCH=amd64 go build -trimpath -o crypto_hash.exe .
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {
	data := []byte("The quick brown fox jumps over the lazy dog")
	hash := sha256.Sum256(data)
	fmt.Printf("SHA256: %s\n", hex.EncodeToString(hash[:]))
}

// Baseline control: JSON processor. Exercises encoding/json.
// Build: GOOS=windows GOARCH=amd64 go build -trimpath -o json_processor.exe .
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Name  string `json:"name"`
	Port  int    `json:"port"`
	Debug bool   `json:"debug"`
}

func main() {
	cfg := Config{Name: "myapp", Port: 8080, Debug: false}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	fmt.Println(string(data))
	os.Exit(0)
}

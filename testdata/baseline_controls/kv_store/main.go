// Baseline control: CLI key-value store. Exercises flag, encoding/json, sort.
// Build: GOOS=windows GOARCH=amd64 go build -trimpath -o kv_store.exe .
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
)

var store = map[string]string{}

func main() {
	action := flag.String("action", "list", "get|set|list|delete")
	key := flag.String("key", "", "key name")
	value := flag.String("value", "", "value to set")
	flag.Parse()

	switch *action {
	case "set":
		store[*key] = *value
		fmt.Printf("Set %s=%s\n", *key, *value)
	case "get":
		fmt.Println(store[*key])
	case "delete":
		delete(store, *key)
	case "list":
		keys := make([]string, 0, len(store))
		for k := range store {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		data, _ := json.MarshalIndent(store, "", "  ")
		fmt.Println(string(data))
	}
	os.Exit(0)
}

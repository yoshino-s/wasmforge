package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	url := "http://httpbin.org/get"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}

	fmt.Printf("GET %s\n", url)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HTTP GET failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %s\n", resp.Status)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read body failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Body (%d bytes):\n%s\n", len(body), string(body))

	if resp.StatusCode == 200 {
		fmt.Println("PASS: HTTP GET successful")
	} else {
		fmt.Fprintf(os.Stderr, "FAIL: unexpected status %d\n", resp.StatusCode)
		os.Exit(1)
	}
}

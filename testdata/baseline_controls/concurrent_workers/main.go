// Baseline control: goroutines + sync. Exercises sync.WaitGroup, goroutines.
// Build: GOOS=windows GOARCH=amd64 go build -trimpath -o concurrent_workers.exe .
package main

import (
	"fmt"
	"sync"
	"time"
)

func worker(id int, wg *sync.WaitGroup) {
	defer wg.Done()
	time.Sleep(100 * time.Millisecond)
	fmt.Printf("Worker %d done\n", id)
}

func main() {
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go worker(i, &wg)
	}
	wg.Wait()
	fmt.Println("All workers complete")
}

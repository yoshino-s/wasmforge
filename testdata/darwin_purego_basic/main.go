package main

import (
	"fmt"
	"os"

	"github.com/ebitengine/purego"
)

func main() {
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_LAZY)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Dlopen: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: Dlopen → %#x\n", lib)

	var getpid func() int32
	purego.RegisterLibFunc(&getpid, lib, "getpid")
	pid := getpid()
	fmt.Printf("PASS: getpid() = %d\n", pid)

	var getuid func() uint32
	purego.RegisterLibFunc(&getuid, lib, "getuid")
	uid := getuid()
	fmt.Printf("PASS: getuid() = %d\n", uid)

	fmt.Println("\n3/3 tests passed")
}

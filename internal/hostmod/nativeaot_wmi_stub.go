//go:build nativeaot && !windows

package hostmod

import "fmt"

func wmiQueryJSON(namespace, query string) (string, error) {
	return "", fmt.Errorf("WMI not available on this platform")
}

func wmiMethodJSON(namespace, classPath, methodName, inputJSON string) (string, error) {
	return "", fmt.Errorf("WMI method invocation not supported on this platform")
}

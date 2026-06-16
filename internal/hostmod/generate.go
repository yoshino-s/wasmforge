package hostmod

// To regenerate generated_ptrmasks.go from win32json metadata:
//
//   1. Clone win32json: git clone --depth 1 https://github.com/marlersoft/win32json.git /tmp/win32json
//   2. Run: go generate ./internal/hostmod/
//
//go:generate go run ../../cmd/gen-ptrmasks -json /tmp/win32json/api -o generated_ptrmasks.go

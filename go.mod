module github.com/praetorian-inc/wasmforge

go 1.25.3

require (
	github.com/ebitengine/purego v0.9.1
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	github.com/tc-hib/winres v0.3.1
	github.com/tetratelabs/wazero v1.11.0
	github.com/tree-sitter/go-tree-sitter v0.25.0
	github.com/tree-sitter/tree-sitter-c-sharp v0.23.5
	golang.org/x/sys v0.38.0
	software.sslmate.com/src/go-pkcs12 v0.7.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-pointer v0.0.1 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/crypto v0.11.0 // indirect
	golang.org/x/image v0.12.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/tetratelabs/wazero v1.11.0 => ./wazero

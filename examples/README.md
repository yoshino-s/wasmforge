# Examples

Small, self-contained Go programs that compile through wasmforge and
demonstrate one specific feature each. Use these as templates when
starting your own wasmforge guest.

All examples assume you've already built `wasmforge` itself:

```bash
go build -o wasmforge ./cmd/wasmforge
```

## tcpscanner — concurrent TCP port scan

A small concurrent TCP port scanner written with the standard
`net.Dial` and goroutines. Demonstrates that wasmforge's networking
bridge handles real-world concurrent connection patterns transparently
— the guest does not need any wasmforge-specific imports.

```bash
# Build for your host OS
./wasmforge build -o /tmp/tcpscanner ./examples/tcpscanner

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 ./wasmforge build -o /tmp/tcpscanner.exe ./examples/tcpscanner

# Cross-compile for macOS Apple Silicon
GOOS=darwin GOARCH=arm64 ./wasmforge build -o /tmp/tcpscanner ./examples/tcpscanner

# Run
/tmp/tcpscanner -target scanme.nmap.org -ports 22,80,443
# Open ports on scanme.nmap.org:
#   22/tcp  open
#   80/tcp  open
```

No special flags required.

## httpserver — net/http HTTP server

A 30-line HTTP server using `net/http`. Demonstrates that
`http.ListenAndServe` works inside the sandbox without any wasmforge
imports.

```bash
./wasmforge build -o /tmp/httpserver ./examples/httpserver
/tmp/httpserver :8080 &
curl http://localhost:8080/
# Hello from wasmforge!
```

Pass a custom listen address as the first arg, otherwise the server
binds `:8080`.

## icmpping — raw socket ICMP ping

Sends ICMP echo requests using `guest/rawnet`. The only example that
requires elevated privileges, because raw socket access is gated by
the OS:

* Linux: `cap_net_raw` capability or root
* macOS: root
* Windows: Administrator

Build with `--raw-sockets` to enable the host-side raw socket bridge:

```bash
./wasmforge build --raw-sockets -o /tmp/icmpping ./examples/icmpping

# Run as root (or with sudo)
sudo /tmp/icmpping 8.8.8.8
# 64 bytes from 8.8.8.8: icmp_seq=0 time=12.3ms
# 64 bytes from 8.8.8.8: icmp_seq=1 time=11.9ms
```

If you forgot `--raw-sockets`, the binary will fail with
`raw socket: operation not permitted` even running as root, because the
host bridge isn't compiled in.

## What's next

* For Windows targets that touch Win32 APIs (registry, processes,
  CLR / `execute-assembly`, COM, etc.), see [`testdata/`](../testdata/)
  for richer programs. The README walks through `testdata/win32_*` cases.
* For macOS framework loading (`dlopen`/`dlsym` into `Security.framework`,
  CoreGraphics, IOKit, etc.), see [`docs/MACOS.md`](../docs/MACOS.md).
* For .NET / C# NativeAOT-WASI guests (Seatbelt, Rubeus, etc.), see
  [`docs/CSHARP.md`](../docs/CSHARP.md).
* For ghost profiles (gopclntab camouflage that makes the host binary
  look like Traefik / Caddy / Terraform), see
  [`docs/GHOST-PROFILES.md`](../docs/GHOST-PROFILES.md).

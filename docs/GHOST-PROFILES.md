# Ghost Binary Profiling

Ghost profiling replaces WasmForge's `gopclntab` function, type, and package names with names harvested from real enterprise Go binaries. ML classifiers that analyze `gopclntab` string patterns see function distributions identical to known-good software (Traefik, Caddy, Terraform) instead of synthetic random names.

## Embedded Profiles

WasmForge ships with three profiles built in:

| Profile      | Symbols | Packages | Source                                                                    |
| ------------ | ------- | -------- | ------------------------------------------------------------------------- |
| `traefik`    | 154,681 | 3,083    | [Traefik](https://github.com/traefik/traefik) reverse proxy               |
| `terraform`  | 91,253  | 1,392    | [Terraform](https://github.com/hashicorp/terraform) IaC tool              |
| `caddy`      | 42,423  | 749      | [Caddy](https://github.com/caddyserver/caddy) web server                  |

`traefik` is recommended for the lowest VirusTotal detection rates because of its symbol density and package breadth.

## Usage

```bash
# Use Traefik's gopclntab profile (recommended)
wasmforge build --ghost traefik --win32-apis -o app.exe ./myproject

# Use Caddy or Terraform profiles
wasmforge build --ghost caddy --win32-apis -o app.exe ./myproject
wasmforge build --ghost terraform --win32-apis -o app.exe ./myproject

# Random profile per build (default when --ghost is omitted)
wasmforge build --win32-apis -o app.exe ./myproject
```

## What Ghost Profiling Affects

When `--ghost <name>` is set, the profile drives:

- Module name and import paths
- Package paths in `gopclntab`
- Function, method, and type names in `gopclntab`
- Dead code package content (filler packages added for symbol density)
- All polymorphic identifier renames

The wazero fork identity scrubbing, WASM opcode permutation, and PE hardening are independent build-time layers and are always active regardless of profile choice.

## Generating Custom Profiles

You can build a profile from any Go binary you have access to:

```bash
go run ./cmd/gen-ghost-profile \
  -binary /path/to/any-go-binary \
  -name myprofile \
  -out internal/build/ghost_profiles/
```

The tool extracts `gopclntab` symbols, normalizes package/function/type names, deduplicates, and writes a profile file that gets embedded into the wasmforge binary on the next build.

After generating a profile, rebuild wasmforge:

```bash
go build -o wasmforge ./cmd/wasmforge
./wasmforge build --ghost myprofile --win32-apis -o app.exe ./myproject
```

## Choosing a Profile

- **Highest evasion (Windows targets):** `traefik` — large symbol set, broad package distribution, mirrors a real enterprise reverse-proxy binary
- **Smaller payload influence:** `caddy` — fewer symbols, smaller fingerprint
- **Cloud / DevOps cover:** `terraform` — useful when the deployment context is a developer or DevOps workstation
- **Custom cover identity:** generate a profile from a binary that fits the target environment (e.g., a vendor-specific tool already deployed on the target host)

## Related Documentation

- [Main README](../README.md) — quick start and feature overview
- [CSHARP.md](./CSHARP.md) — .NET / C# project compilation
- [MACOS.md](./MACOS.md) — macOS framework bridge and Apple targets

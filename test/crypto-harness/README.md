# Crypto Bridge Test Harness

Minimal C# NativeAOT-WASI program that exercises the `Wf*` crypto wrappers
against canonical RFC test vectors. ~90 second build cycle. Useful for
triaging crypto-related parity failures without rebuilding 25MB GhostPack
projects.

## Test vectors
- RFC 2202 HMAC-SHA1
- RFC 4231 HMAC-SHA256
- RFC 6070 PBKDF2-HMAC-SHA1
- RFC 7914 PBKDF2-HMAC-SHA256
- NIST PBKDF2-HMAC-SHA512
- NIST SP 800-38A F.2.1 AES-128-CBC
- FIPS 180-2 SHA1 / SHA256 of "abc"

## Build

```bash
# On Ludus (or any host with dotnet 10 + WASI SDK 24 + wasmforge-bin):
mkdir -p /tmp/wf-crypto-test/bridge
cp test/crypto-harness/{Program.cs,CryptoTest.csproj} /tmp/wf-crypto-test/
cp dotnet/bridge/{wf_bridge.h,wf_bridge.c,pinvoke_nativeaot.c} /tmp/wf-crypto-test/bridge/
cp /path/to/nuget.config /tmp/wf-crypto-test/  # needs dotnet-experimental feed

WASI_SDK_PATH=$HOME/.wasi-sdk/wasi-sdk-24.0 PATH=$HOME/.dotnet:$PATH \
  dotnet publish -c Release -r wasi-wasm /tmp/wf-crypto-test/

# Wrap with wasmforge → PE
wasmforge-bin build --wasm /tmp/wf-crypto-test/bin/Release/net10.0/wasi-wasm/native/CryptoTest.wasm \
  --nativeaot --win32-apis --no-sign -o /tmp/cryptotest.exe

# Run on Win11
labctl push --force /tmp/cryptotest.exe win11-ssh:'C:\WfBin\cryptotest.exe'
labctl exec win11-ssh 'C:\WfBin\cryptotest.exe'
```

## Expected output

```
=== Wf BCrypt Bridge Tests ===
PASS SHA1("abc")
PASS SHA256("abc")
PASS HMAC-SHA1 RFC2202 #1
PASS HMAC-SHA256 RFC4231 #1
PASS PBKDF2-SHA1 RFC6070 #1
PASS PBKDF2-SHA1 RFC6070 #2
PASS PBKDF2-SHA256 RFC7914 #1
PASS PBKDF2-SHA512 NIST #1
PASS AES-128-CBC NIST F.2.1 block 1
=== Result: 9 PASS, 0 FAIL ===
```

## How it found 3 bugs

See `memory/crypto-test-harness-triage.md` for the diagnostic walk:
1. Algorithm-name `.rodata` falling below wf_call's 0x10000 ptr-translation threshold
2. `wf_call` instead of `wf_call_v2` zeroing bytes 4-7 of 8-byte handle outputs
3. `cIterations` ULONGLONG mis-split into two args, shifting downstream args

All three are fixed in commit `0e4bde1`.

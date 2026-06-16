# Net Bridge Test Harness

Mirrors `wmi-harness/`, `crypto-harness/`, `lsa-harness/`. Minimal NativeAOT-
WASI C# program that exercises `net_tcpsendrecv` and `net_getdc` env imports
directly to triage the wasmforge network bridge.

## Build & run

```bash
make docker-run DOCKER_SRC=$(pwd)/test/net-harness DOCKER_PROJECT=nettest
labctl push --force out/nettest.exe win11-domainuser:'C:\WfBin\nettest.exe'
labctl exec win11-domainuser 'cmd /c "C:\WfBin\nettest.exe"'
```

## Layers

| L | Probe |
|---|-------|
| L1 | `WfGetDCName("sevenkingdoms.local", 0)` — DC discovery via DsGetDcNameW bridge |
| L2 | `WfTcpSendRecv("sevenkingdoms.local", 88, ...)` — DNS-name TCP via env `net_tcpsendrecv` |
| L2 | `WfTcpSendRecv("10.3.10.10", 88, ...)` — IP-literal TCP via env `net_tcpsendrecv` |
| L3 | `sock_open/connect/write/read` to `10.3.10.10:88` — WASI socket primitive chain |
| L3 | `sock_open/connect/write/read` to `kingslanding.sevenkingdoms.local:88` — same + `addr_resolve` |

If L1 fails, DsGetDcName isn't wired up. If L2 fails but L3 succeeds, the
fix is to route Rubeus through `sock_*` primitives (existing hostmod API) and
deprecate the broken `net_tcpsendrecv` env import path.

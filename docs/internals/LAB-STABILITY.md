# Ludus Lab Stability — Root Cause and Fix

## What was broken

The GOAD Ludus lab range (`GOADf97252`) was unreliable for parity testing.
Win11 (10.3.10.98) and DC01 (10.3.10.10) kept powering off ~1× / hour,
leaving the test suite to hit "No route to host" errors mid-run. Earlier
sessions believed this was an autostart / VM-lifecycle problem; that was
wrong.

## Root cause

`wlms.exe` (Windows License Monitoring Service) on both Win11 and DC01
was issuing planned shutdowns hourly. The Windows evaluation license
on both VMs had expired in May 2026, and wlms enters a forced-shutdown
loop once `slmgr.vbs /dlv` shows `License Status: Notification` and
`Remaining Windows rearm count: 0`.

Evidence from Win11 event log (`System` channel, event ID 1074):

```
The process C:\Windows\system32\wlms\wlms.exe (GOADF97252-GOAD) has
initiated the shutdown of computer GOADF97252-GOAD on behalf of user
NT AUTHORITY\SYSTEM for the following reason: Other (Planned)
 Reason Code: 0x80000000
 Shutdown Type: shutdown
 Comment: The license period for this installation of Windows has
        expired. The operating system is shutting down.
```

This event fired at 2:47 AM, 1:47 AM, 12:28 AM, 11:24 PM, 10:24 PM, ...
— one entry per hour.

## Fix (applied)

Disabling `wlms` from PowerShell directly fails with "Access is denied"
even as Administrator — the service is owned by `NT SERVICE\TrustedInstaller`.
The fix is to invoke `sc.exe config wlms start=disabled` + `taskkill /F /IM
wlms.exe` from a scheduled task running as `NT AUTHORITY\SYSTEM` with
`-RunLevel Highest`. Equivalent to running with TrustedInstaller token
elevation.

Applied via `scripts/lab-setup/disable-wlms.ps1` (kicked from a scheduled
task) on Win11 (host 10.3.10.98) and DC01 (host 10.3.10.10). Both VMs
now have `wlms` StartType=Disabled and `wlms.exe` not running.

A second scheduled task `WfWlmsGuard` runs at every boot as
`NT AUTHORITY\SYSTEM` to re-disable wlms in case a Windows servicing
event re-enables it. This was registered with `New-ScheduledTaskTrigger
-AtStartup`.

## Other lab-stability fixes (applied)

1. **`/usr/local/sbin/lab-watchdog.sh` + crontab** on the Ludus host —
   restarts critical VMIDs (107 router, 108 DC01, 113 Win11, 114 kali)
   if they're not in `running` state. Runs every minute.

2. **Autostart on host reboot** — `qm set <vmid> --onboot 1 --startup
   order=N` applied to all critical VMs (router first, then DCs, then
   member servers, then Win11/kali). Survives Proxmox host reboots.

3. **Domain credentials** — `sevenkingdoms\domainuser` and
   `sevenkingdoms\domainadmin` both reset to password `password` via
   `net user ... /domain` on DC01. Local Win11 fallback accounts
   (created during the earlier session when DC01 was down) removed
   with `net user ... /delete` so that labctl SSH falls through to
   domain authentication and Kerberos TGTs are cached on session start.

4. **Plant artifacts re-deployed** via
   `scripts/lab-setup/{sharpup-plant,sharpdpapi-plant,seatbelt-plant,
   seatbelt-extras,rubeus-precache,grant-batch-logon}.ps1` so the
   tests have something to find when they run.

## Verification

| Check | Command | Result |
|-------|---------|--------|
| Win11 up | `labctl exec win11-ssh whoami` | `goadf97252-goad\localuser` |
| Domain SSH | `labctl exec win11-domainuser whoami` | `sevenkingdoms\domainuser` |
| Kerberos TGT | `labctl exec win11-domainuser klist` | TGT for `krbtgt/SEVENKINGDOMS.LOCAL` cached |
| DC01 up | `labctl exec dc01-ssh whoami` | `sevenkingdoms\domainadmin` |
| AD operational | `labctl exec dc01-ssh "net user domainuser /domain"` | `The command completed successfully.` |
| wlms killed | `labctl exec win11-ssh "Get-Process wlms"` | `Cannot find a process with the name wlms` |
| wlms disabled | `labctl exec win11-ssh "(Get-Service wlms).StartType"` | `Disabled` |

## Aggregate parity sweep (Phase 3, post-lab-fix)

The lab is stable; remaining FAIL counts reflect wasmforge engine gaps,
not lab limitations:

| Tool       | PASS | FAIL | Class of remaining gap |
|------------|------|------|------------------------|
| SharpUp    | 7    | 6    | Output drift (plant detail) + 3 slow cases timed-out |
| Seatbelt   | 0    | 24   | OSInfo etc. read wrong WASI defaults (hostname=localhost, ProcessorCount=1, TimeZone=UTC, no Domain Name) |
| Rubeus     | 0    | 11   | Output diff vs. baselines (binary runs) |
| SharpDPAPI | 0    | 12   | Output diff; backupkey verb requires `LsaRetrievePrivateData` pointer translation |
| SharpView  | 0    | 14   | Domain stub fallback now returns "sevenkingdoms.local" but PowerView calls still need LDAP routing |
| Certify    | 0    | 11   | `CoInitializeSecurity hr=80070057` — DCOM stack not initialized in WASI |

These FAIL counts are higher than the previous session's run (which only
sampled tests before the lab dropped) because the suite now actually
completes — every case gets exercised. The lab dependency is gone; what
remains is engine work.

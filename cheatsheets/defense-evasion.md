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

**Exam tip:** `mailslot` + `HeapAlloc` + custom `magic_mz` values is the quietest combination. Avoid `readfile` (disk write) and `VirtualAlloc` with RWX pages (EDR hook bait).

After build, load the aggressor script:

```
Cobalt Strike → Script Manager → Load → <output_dir>/artifact.cna
```

## ThreatCheck  

```sh

```  

## Ghidra  

```

```  

## Artifact Kit  

```

```  




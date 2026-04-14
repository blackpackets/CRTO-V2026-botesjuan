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

---

1. Use the high-integrity Beacon to impersonate a domain admin (`dyork`).

    > We need DA to run DCSync. The medium-integrity beacon runs as a regular user. Find a process owned by `dyork` in the process browser and steal the token — this impersonates dyork's security context in-beacon with no process spawn.

2. DCSync *rsteel*'s AES256 hash from CONTOSO.

    ```Beacon-nocolor
    dcsync contoso.com CONTOSO\rsteel
    ```

    > **Why rsteel, not Administrator?** We need to authenticate to PARTNER **as rsteel** because rsteel is the account that is a member of "Partner Jump Users." Using the Administrator account would still work IF Administrator were also in "Partner Jump Users" — but rsteel is the designated bridge account here. We DCSync rsteel's hash because we need it to mint a legitimate TGT. Note the `aes256_hmac` value from the output — this is what gets passed to `krb_asktgt` next.
    >
    > **OPSEC-CAUTION** — DCSync generates Event 4662 on the DC. Use the AES256 hash, not RC4/NT — AES256 requests are less anomalous.

3. Obtain a TGT for *rsteel* from CONTOSO's KDC.

    ```Beacon-nocolor
    krb_asktgt /user:rsteel /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960
    ```

    > **What happens here:** An AS-REQ is sent to CONTOSO's KDC using rsteel's AES256 hash as the pre-authentication key. CONTOSO's KDC issues a TGT for `rsteel@CONTOSO.COM`. This TGT is encrypted with CONTOSO's `krbtgt` key — only CONTOSO's KDC can read it.
    >
    > **Ticket in hand:** `TGT_rsteel` — valid for CONTOSO only. Proves to CONTOSO KDC: "I am rsteel."
    >
    > **OPSEC-CAUTION** — Generates Event 4768 (AS-REQ) on CONTOSO DC. AES256 pre-auth is normal Kerberos behaviour.
    >
    > Note the base64 ticket from the output — this is `[TGT]` referenced in the next command.

4. Use the TGT to request an inter-realm referral ticket.

    ```Beacon-nocolor
    krb_asktgs /service:krbtgt/partner.com /ticket:[TGT]
    ```

    > **What happens here:** A TGS-REQ is sent to CONTOSO's KDC, presenting `TGT_rsteel` and asking for a ticket to access `krbtgt/partner.com`. Requesting the `krbtgt` service of a foreign realm is how Kerberos signals a cross-realm referral.
    >
    > CONTOSO's KDC checks: "Do I have an inbound trust with partner.com? Yes." It issues a cross-realm TGT (also called a referral ticket or inter-realm ticket), encrypted with the **inter-realm trust key** — a secret shared between CONTOSO's KDC and PARTNER's KDC, derived from the trust password they both hold.
    >
    > **Ticket in hand:** `INTER-REALM TGT` — encrypted with the trust key. Contains rsteel's identity and group SIDs, including the "Partner Jump Users" SID (S-1-5-21-3926355307-...-6102). ONLY PARTNER's KDC can decrypt this (it knows the inter-realm key too).
    >
    > **OPSEC-CAUTION** — Generates Event 4769 (TGS-REQ for krbtgt/partner.com) on CONTOSO DC. This is unusual traffic — normal users don't typically request cross-realm referrals directly.
    >
    > Note the base64 inter-realm ticket — this is `[INTER-REALM]` referenced in the next command.

5. Use the inter-realm ticket to request a service ticket for CIFS on *par-jmp-1*.

    ```Beacon-nocolor
    krb_asktgs /service:cifs/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:[INTER-REALM]
    ```

    > **What happens here:** A TGS-REQ is now sent to **PARTNER's KDC** (`/dc:par-dc-1.partner.com` — note we explicitly point at PARTNER's DC, not our own), presenting the inter-realm TGT and asking for a service ticket to `cifs/par-jmp-1.partner.com`.
    >
    > PARTNER's KDC:
    > 1. Decrypts the inter-realm TGT using the trust key — validates it came from CONTOSO
    > 2. Reads rsteel's SIDs from the PAC — sees SID `-6102` (Partner Jump Users)
    > 3. Looks up FSP: `-6102` maps to FSP → member of "Contoso Users" (SID `-1104`)
    > 4. Adds "Contoso Users" SID to rsteel's PAC in the new ticket
    > 5. Issues a service ticket for `cifs/par-jmp-1.partner.com`, encrypted with par-jmp-1's machine account key
    >
    > `/targetdomain:partner.com` tells the command which realm the service lives in.
    > `/dc:par-dc-1.partner.com` is required — we must send this TGS-REQ to PARTNER's KDC, not CONTOSO's.
    >
    > **Ticket in hand:** `SERVICE TICKET` for cifs/par-jmp-1 — encrypted with par-jmp-1's key. PAC inside contains "Contoso Users" (-1104) which GPO maps to local admin.
    >
    > **OPSEC-CAUTION** — Generates Event 4769 (TGS-REQ) on PARTNER's DC (`par-dc-1`). This is the first event generated on PARTNER's infrastructure.

6. Use the service ticket to access the service in the trusting domain.

    ```Beacon-nocolor
    ls \\par-jmp-1.partner.com\c$
    ```

    > The service ticket is presented to `par-jmp-1` over SMB. par-jmp-1 decrypts the ticket with its own machine account key, reads the PAC, sees "Contoso Users" (-1104) in the group list, maps that to local Administrators via the applied GPO, and grants access.
    >
    > **OPSEC-SAFE** — Generates Event 4624 Type 3 (network logon) on par-jmp-1. Looks like a normal admin SMB access. No lateral movement artifact, no service creation, no process on the remote host.

⚠️ In this lab, you have taken advantage of legit access assigned across a one-way inbound trust.

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
1. DCSync target user hash (need DA on source domain)
2. krb_asktgt           → TGT (source domain KDC)          → encrypted with source krbtgt
3. krb_asktgs krbtgt/foreign.domain  → INTER-REALM TGT     → encrypted with trust key
4. krb_asktgs cifs/target /dc:foreign-dc → SERVICE TICKET  → encrypted with target machine key
5. ls / download        → present service ticket over SMB   → access granted
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

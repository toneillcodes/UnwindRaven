#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <stdio.h>

#include "stack_blueprint.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

//
// NOTE:
//   This harvester ONLY outputs EXPORTED frames.
//   Non-exported frames are skipped because they cannot be reconstructed
//   safely in a different process (no stable RVA).
//

int main(int argc, char* argv[])
{
    EnableDebugPrivilege();

    if (argc < 3) {
        printf("Usage:\n");
        printf("  blueprint-callstack.exe --pid <PID> [--out <file>]\n");
        printf("  blueprint-callstack.exe --thread <PID> <TID> [--out <file>]\n");
        return 0;
    }

    FILE* fp = NULL;
    const char* outPath = NULL;

    // Parse optional --out <file>
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--out") == 0 && i + 1 < argc) {
            outPath = argv[i + 1];
            break;
        }
    }

    if (outPath) {
        fp = fopen(outPath, "w");
        if (!fp) {
            printf("[-] Failed to open output file: %s\n", outPath);
            return -1;
        }
        printf("[+] Also writing output to: %s\n\n", outPath);
    }

    int count = 0;

    if (_stricmp(argv[1], "--pid") == 0 && argc >= 3) {
        DWORD pid = strtoul(argv[2], NULL, 0);
        DWORD tid = 0;

        if (!FindFirstThreadInPid(pid, &tid)) {
            printf("[-] No threads found in PID %lu\n", pid);
            if (fp) fclose(fp);
            return -1;
        }

        printf("[+] Harvesting blueprint from PID %lu, TID %lu\n\n", pid, tid);
        count = HarvestBlueprintFromThread(pid, tid, fp);
    }
    else if (_stricmp(argv[1], "--thread") == 0 && argc >= 4) {
        DWORD pid = strtoul(argv[2], NULL, 0);
        DWORD tid = strtoul(argv[3], NULL, 0);

        printf("[+] Harvesting blueprint from PID %lu, TID %lu\n\n", pid, tid);
        count = HarvestBlueprintFromThread(pid, tid, fp);
    }
    else {
        printf("Usage:\n");
        printf("  blueprint-callstack.exe --pid <PID> [--out <file>]\n");
        printf("  blueprint-callstack.exe --thread <PID> <TID> [--out <file>]\n");
        if (fp) fclose(fp);
        return 0;
    }

    if (fp) fclose(fp);

    if (count <= 0) {
        printf("[-] No exported frames harvested.\n");
        return -1;
    }

    printf("\n[+] Exported frames harvested: %d\n", count);
    return 0;
}

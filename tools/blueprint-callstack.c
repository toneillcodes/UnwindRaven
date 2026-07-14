#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <stdio.h>

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

BOOL EnableDebugPrivilege(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    CloseHandle(hToken);
    return TRUE;
}

HMODULE ModuleFromAddress(HANDLE hProcess, DWORD64 addr, WCHAR* outPath)
{
    HMODULE mods[1024];
    DWORD needed = 0;

    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed))
        return NULL;

    int count = needed / sizeof(HMODULE);

    for (int i = 0; i < count; i++) {
        MODULEINFO mi = {0};
        if (!GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi)))
            continue;

        DWORD64 base = (DWORD64)mi.lpBaseOfDll;
        DWORD64 end  = base + mi.SizeOfImage;

        if (addr >= base && addr < end) {
            if (outPath)
                GetModuleFileNameExW(hProcess, mods[i], outPath, MAX_PATH);
            return mods[i];
        }
    }
    return NULL;
}

BOOL NormalizeModulePath(WCHAR* out, const WCHAR* in)
{
    WCHAR sysDir[MAX_PATH];
    if (!GetSystemDirectoryW(sysDir, MAX_PATH))
        return FALSE;

    const WCHAR* base = wcsrchr(in, L'\\');
    if (!base)
        return FALSE;

    swprintf_s(out, MAX_PATH, L"%s\\%s", sysDir, base + 1);
    return TRUE;
}

BOOL GetExportRva(HMODULE hMod, const char* name, DWORD* outRva)
{
    PBYTE base = (PBYTE)hMod;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt =
        (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY expDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (!expDir.Size) return FALSE;

    PIMAGE_EXPORT_DIRECTORY exp =
        (PIMAGE_EXPORT_DIRECTORY)(base + expDir.VirtualAddress);

    PDWORD funcs = (PDWORD)(base + exp->AddressOfFunctions);
    PDWORD names = (PDWORD)(base + exp->AddressOfNames);
    PWORD ords   = (PWORD)(base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* cur = (char*)(base + names[i]);
        if (_stricmp(cur, name) == 0) {
            *outRva = funcs[ords[i]];
            return TRUE;
        }
    }
    return FALSE;
}

BOOL FindFirstThreadInPid(DWORD pid, DWORD* outTid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    THREADENTRY32 te = {0};
    te.dwSize = sizeof(te);

    if (!Thread32First(snap, &te)) {
        CloseHandle(snap);
        return FALSE;
    }

    do {
        if (te.th32OwnerProcessID == pid) {
            *outTid = te.th32ThreadID;
            CloseHandle(snap);
            return TRUE;
        }
    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
    return FALSE;
}

int HarvestBlueprintFromThread(DWORD pid, DWORD tid, FILE* fp)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                                  PROCESS_VM_READ,
                                  FALSE,
                                  pid);
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT |
                                THREAD_SUSPEND_RESUME |
                                THREAD_QUERY_INFORMATION,
                                FALSE,
                                tid);

    if (!hProcess || !hThread) {
        printf("[-] OpenProcess/OpenThread failed\n");
        if (hThread) CloseHandle(hThread);
        if (hProcess) CloseHandle(hProcess);
        return 0;
    }

    SuspendThread(hThread);

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[-] GetThreadContext failed\n");
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 0;
    }

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    SymInitialize(hProcess, NULL, TRUE);

    STACKFRAME64 sf = {0};
    sf.AddrPC.Offset    = ctx.Rip;
    sf.AddrPC.Mode      = AddrModeFlat;
    sf.AddrFrame.Offset = ctx.Rbp;
    sf.AddrFrame.Mode   = AddrModeFlat;
    sf.AddrStack.Offset = ctx.Rsp;
    sf.AddrStack.Mode   = AddrModeFlat;

    int totalFrames    = 0;
    int exportedFrames = 0;

    while (StackWalk64(IMAGE_FILE_MACHINE_AMD64,
                       hProcess,
                       hThread,
                       &sf,
                       &ctx,
                       NULL,
                       SymFunctionTableAccess64,
                       SymGetModuleBase64,
                       NULL))
    {
        DWORD64 addr = sf.AddrPC.Offset;
        if (!addr) break;
        if (totalFrames >= 128) break;

        totalFrames++;

        WCHAR modPathRaw[MAX_PATH] = {0};
        HMODULE hMod = ModuleFromAddress(hProcess, addr, modPathRaw);
        if (!hMod) continue;

        WCHAR modPathNorm[MAX_PATH] = {0};
        if (!NormalizeModulePath(modPathNorm, modPathRaw))
            continue;

        char symBuf[sizeof(SYMBOL_INFO) + 256] = {0};
        PSYMBOL_INFO sym = (PSYMBOL_INFO)symBuf;
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen   = 255;

        DWORD64 disp = 0;
        if (!SymFromAddr(hProcess, addr, &disp, sym))
            continue;

        DWORD exportRva = 0;
        if (!GetExportRva(hMod, sym->Name, &exportRva))
            continue;  // ONLY EXPORTED FRAMES ARE LISTED

        DWORD64 modBase       = (DWORD64)hMod;
        DWORD64 rva           = addr - modBase;
        DWORD64 offsetFromExp = rva - exportRva;

        exportedFrames++;

        // Always stdout
        wprintf(L"%ls|%S|0x%llX|0\n",
                modPathNorm,
                sym->Name,
                offsetFromExp);

        // Optional file output
        if (fp) {
            fwprintf(fp, L"%ls|%S|0x%llX|0\n",
                     modPathNorm,
                     sym->Name,
                     offsetFromExp);
        }
    }

    SymCleanup(hProcess);
    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("[+] Total frames walked: %d\n", totalFrames);
    printf("[+] Exported frames listed: %d\n", exportedFrames);

    return exportedFrames;
}

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
#include "common.h"
#include <stdio.h>
#include <wchar.h>
#include <string.h>

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

BOOL IsProcessWow64(HANDLE hProcess, BOOL* pIsWow64)
{
    *pIsWow64 = FALSE;

    BOOL bWow = FALSE;
    if (!IsWow64Process(hProcess, &bWow))
        return FALSE;

    *pIsWow64 = bWow;
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

HMODULE GetCachedImageBase(UR_STACK_CONTEXT* ctx, const WCHAR* dllPath)
{
    int i;
    for (i = 0; i < ctx->CacheCount; i++) {
        if (_wcsicmp(ctx->ImageBaseCache[i].dllPath, dllPath) == 0) {
            return ctx->ImageBaseCache[i].hModule;
        }
    }
    return NULL;
}

void CacheImageBase(UR_STACK_CONTEXT* ctx, const WCHAR* dllPath, HMODULE hModule)
{
    if (ctx->CacheCount < 64) {
        wcscpy_s(ctx->ImageBaseCache[ctx->CacheCount].dllPath, MAX_PATH, dllPath);
        ctx->ImageBaseCache[ctx->CacheCount].hModule = hModule;
        ctx->CacheCount++;
    }
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

DWORD GetRvaFromName(HMODULE hModule, const char* functionName)
{
    PBYTE base = (PBYTE)hModule;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders =
        (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY exportDirInfo =
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDirInfo.Size == 0) {
        return 0;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory =
        (PIMAGE_EXPORT_DIRECTORY)(base + exportDirInfo.VirtualAddress);

    PDWORD addressOfFunctions =
        (PDWORD)(base + exportDirectory->AddressOfFunctions);
    PDWORD addressOfNames =
        (PDWORD)(base + exportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinals =
        (PWORD)(base + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* currentName = (char*)(base + addressOfNames[i]);
        if (strcmp(currentName, functionName) == 0) {
            return addressOfFunctions[addressOfNameOrdinals[i]];
        }
    }
    return 0;
}

int ProfileThreadToBlueprint(DWORD pid, DWORD tid, StackProfileEntry* out, int maxEntries)
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

    if (!hProcess || !hThread)
        return 0;

    BOOL isWow64 = FALSE;
    IsProcessWow64(hProcess, &isWow64);

    SuspendThread(hThread);

    CONTEXT ctx = {0};
    STACKFRAME64 sf = {0};

    if (!isWow64) {
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &ctx)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return 0;
        }

        sf.AddrPC.Offset    = ctx.Rip;
        sf.AddrPC.Mode      = AddrModeFlat;
        sf.AddrFrame.Offset = ctx.Rbp;
        sf.AddrFrame.Mode   = AddrModeFlat;
        sf.AddrStack.Offset = ctx.Rsp;
        sf.AddrStack.Mode   = AddrModeFlat;
    } else {
        WOW64_CONTEXT wctx = {0};
        wctx.ContextFlags = WOW64_CONTEXT_FULL;
        if (!Wow64GetThreadContext(hThread, &wctx)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return 0;
        }

        sf.AddrPC.Offset    = wctx.Eip;
        sf.AddrPC.Mode      = AddrModeFlat;
        sf.AddrFrame.Offset = wctx.Ebp;
        sf.AddrFrame.Mode   = AddrModeFlat;
        sf.AddrStack.Offset = wctx.Esp;
        sf.AddrStack.Mode   = AddrModeFlat;
    }

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    SymInitialize(hProcess, NULL, TRUE);

    int count = 0;

    while (StackWalk64(isWow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64,
                       hProcess,
                       hThread,
                       &sf,
                       isWow64 ? NULL : &ctx,
                       NULL,
                       SymFunctionTableAccess64,
                       SymGetModuleBase64,
                       NULL))
    {
        if (count >= maxEntries)
            break;

        DWORD64 addr = sf.AddrPC.Offset;
        if (!addr) break;

        WCHAR modPath[MAX_PATH] = {0};
        HMODULE hMod = ModuleFromAddress(hProcess, addr, modPath);
        if (!hMod) continue;

        char symBuf[sizeof(SYMBOL_INFO) + 256] = {0};
        PSYMBOL_INFO sym = (PSYMBOL_INFO)symBuf;
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen   = 255;

        DWORD64 disp = 0;
        if (!SymFromAddr(hProcess, addr, &disp, sym))
            continue;

        wcscpy_s(out[count].modulePath, MAX_PATH, modPath);
        strcpy_s(out[count].functionName, sizeof(out[count].functionName), sym->Name);
        out[count].offsetFromExport = (ULONG)disp;
        out[count].needLoad         = FALSE;
        out[count].hasOffset        = TRUE;
        out[count].absoluteAddress  = addr;

        count++;
    }

    SymCleanup(hProcess);
    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return count;
}


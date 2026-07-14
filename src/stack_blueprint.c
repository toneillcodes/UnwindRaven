#include "common.h"
#include <stdio.h>
#include <wchar.h>
#include <string.h>

BOOL IsProcessWow64(HANDLE hProcess, BOOL* pIsWow64)
{
    *pIsWow64 = FALSE;

    BOOL bWow = FALSE;
    if (!IsWow64Process(hProcess, &bWow))
        return FALSE;

    *pIsWow64 = bWow;
    return TRUE;
}

/* old definition
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
}*/

HMODULE ModuleFromAddress(HANDLE hProcess, DWORD64 addr, WCHAR* outPath)
{
    if (!hProcess || !addr)
        return NULL;

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
            MEMORY_BASIC_INFORMATION mbi = {0};
            if (VirtualQueryEx(hProcess, (LPCVOID)base, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (!(mbi.Type & MEM_IMAGE))
                    return NULL;
            }

            if (outPath)
                GetModuleFileNameExW(hProcess, mods[i], outPath, MAX_PATH);
            return mods[i];
        }
    }
    return NULL;
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

BOOL GetExportRvaRemote(HANDLE hProcess, HMODULE hMod, const char* name, DWORD* outRva)
{
    if (!hProcess || !hMod || !name || !outRva)
        return FALSE;

    BYTE dosBuf[sizeof(IMAGE_DOS_HEADER)] = {0};
    SIZE_T bytesRead = 0;

    PBYTE base = (PBYTE)hMod;

    // DOS header
    if (!ReadProcessMemory(hProcess, base, dosBuf, sizeof(dosBuf), &bytesRead) ||
        bytesRead != sizeof(dosBuf))
        return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dosBuf;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    if (dos->e_lfanew == 0 || dos->e_lfanew > 0x1000)
        return FALSE;

    // NT headers
    IMAGE_NT_HEADERS ntBuf = {0};
    PBYTE ntAddr = base + dos->e_lfanew;

    if (!ReadProcessMemory(hProcess, ntAddr, &ntBuf, sizeof(ntBuf), &bytesRead) ||
        bytesRead < sizeof(IMAGE_NT_HEADERS))
        return FALSE;

    PIMAGE_NT_HEADERS nt = &ntBuf;

    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return FALSE;

    IMAGE_DATA_DIRECTORY expDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (expDir.VirtualAddress == 0 || expDir.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
        return FALSE;

    // Export directory
    IMAGE_EXPORT_DIRECTORY expBuf = {0};
    PBYTE expAddr = base + expDir.VirtualAddress;

    if (!ReadProcessMemory(hProcess, expAddr, &expBuf, sizeof(expBuf), &bytesRead) ||
        bytesRead < sizeof(IMAGE_EXPORT_DIRECTORY))
        return FALSE;

    PIMAGE_EXPORT_DIRECTORY exp = &expBuf;

    if (exp->NumberOfFunctions == 0 || exp->NumberOfNames == 0)
        return FALSE;

    // Tables
    SIZE_T funcTableSize = exp->NumberOfFunctions * sizeof(DWORD);
    SIZE_T nameTableSize = exp->NumberOfNames    * sizeof(DWORD);
    SIZE_T ordTableSize  = exp->NumberOfNames    * sizeof(WORD);

    PDWORD funcs = (PDWORD)malloc(funcTableSize);
    PDWORD names = (PDWORD)malloc(nameTableSize);
    PWORD  ords  = (PWORD) malloc(ordTableSize);

    if (!funcs || !names || !ords) {
        free(funcs); free(names); free(ords);
        return FALSE;
    }

    BOOL ok =
        ReadProcessMemory(hProcess, base + exp->AddressOfFunctions,
                          funcs, funcTableSize, &bytesRead) &&
        bytesRead == funcTableSize &&
        ReadProcessMemory(hProcess, base + exp->AddressOfNames,
                          names, nameTableSize, &bytesRead) &&
        bytesRead == nameTableSize &&
        ReadProcessMemory(hProcess, base + exp->AddressOfNameOrdinals,
                          ords, ordTableSize, &bytesRead) &&
        bytesRead == ordTableSize;

    if (!ok) {
        free(funcs); free(names); free(ords);
        return FALSE;
    }

    BOOL found = FALSE;

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD nameRva = names[i];
        if (!nameRva)
            continue;

        char buf[256] = {0};
        SIZE_T maxLen = sizeof(buf) - 1;

        if (!ReadProcessMemory(hProcess, base + nameRva,
                               buf, maxLen, &bytesRead) ||
            bytesRead == 0)
            continue;

        buf[maxLen] = '\0';

        if (_stricmp(buf, name) == 0) {
            WORD ord = ords[i];
            if (ord >= exp->NumberOfFunctions)
                break;

            *outRva = funcs[ord];
            found = TRUE;
            break;
        }
    }

    free(funcs); free(names); free(ords);
    return found;
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

    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[-] SuspendThread failed\n");
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 0;
    }

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
    if (!SymInitialize(hProcess, NULL, TRUE)) {
        printf("[-] SymInitialize failed\n");
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 0;
    }

    STACKFRAME64 sf = {0};
    sf.AddrPC.Offset    = ctx.Rip;
    sf.AddrPC.Mode      = AddrModeFlat;
    sf.AddrFrame.Offset = ctx.Rbp;
    sf.AddrFrame.Mode   = AddrModeFlat;
    sf.AddrStack.Offset = ctx.Rsp;
    sf.AddrStack.Mode   = AddrModeFlat;

    int totalFrames    = 0;
    int exportedFrames = 0;
    DWORD64 lastPc     = 0;

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
        if (addr == lastPc) break;
        lastPc = addr;

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

        if (!(sym->Flags & SYMFLAG_FUNCTION) &&
            !(sym->Flags & SYMFLAG_EXPORT))
            continue;

        DWORD exportRva = 0;
        if (!GetExportRvaRemote(hProcess, hMod, sym->Name, &exportRva))
            continue;  // ONLY EXPORTED FRAMES ARE LISTED

        DWORD64 modBase       = (DWORD64)hMod;
        DWORD64 rva           = addr - modBase;
        if (rva < exportRva)
            continue;

        DWORD64 offsetFromExp = rva - exportRva;

        exportedFrames++;

        wprintf(L"%ls|%S|0x%llX|0\n",
                modPathNorm,
                sym->Name,
                offsetFromExp);

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
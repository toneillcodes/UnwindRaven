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

HMODULE GetCachedImageBase(UR_STACK_CONTEXT* ctx, const WCHAR* dllPath)
{
    for (int i = 0; i < ctx->CacheCount; i++) {
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

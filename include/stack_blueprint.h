#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOL EnableDebugPrivilege(void);

BOOL IsProcessWow64(HANDLE hProcess, BOOL* pIsWow64);

int ProfileThreadToBlueprint(
    DWORD pid,
    DWORD tid,
    StackProfileEntry* out,
    int maxEntries
);

BOOL NormalizeModulePath(WCHAR* out, const WCHAR* in);

HMODULE ModuleFromAddress(
    HANDLE hProcess,
    DWORD64 addr,
    WCHAR* outPath
);

DWORD GetRvaFromName(HMODULE hModule, const CHAR* functionName);

HMODULE GetCachedImageBase(const WCHAR* dllPath);
void CacheImageBase(const WCHAR* dllPath, HMODULE hModule);

#ifdef __cplusplus
}
#endif

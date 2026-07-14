#pragma once
#include "common.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL IsProcessWow64(HANDLE hProcess, BOOL* pIsWow64);

int ProfileThreadToBlueprint(
    DWORD pid,
    DWORD tid,
    StackProfileEntry* out,
    int maxEntries
);

HMODULE ModuleFromAddress(
    HANDLE hProcess,
    DWORD64 addr,
    WCHAR* outPath
);

BOOL GetExportRvaRemote(
    HANDLE hProcess, 
    HMODULE hMod, 
    const char* name, 
    DWORD* outRva
);

BOOL FindFirstThreadInPid(
    DWORD pid, 
    DWORD* outTid
);

int HarvestBlueprintFromThread(
    DWORD pid, 
    DWORD tid, 
    FILE* fp
);

#ifdef __cplusplus
}
#endif
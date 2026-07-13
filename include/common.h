#pragma once
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <dbghelp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef BOOL (WINAPI* FnDllMain)(HINSTANCE, DWORD, LPVOID);

#define MAX_STACK_FRAMES   64
#define MAX_STACK_SIZE     0x3000

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

/* ---------------------------------------------------------
   Missing type #1 — MUST be defined before UR_STACK_CONTEXT
   --------------------------------------------------------- */
typedef struct _ImageBaseEntry {
    WCHAR   dllPath[MAX_PATH];
    HMODULE hModule;
} ImageBaseEntry;

/* ---------------------------------------------------------
   Your existing types (correct)
   --------------------------------------------------------- */
typedef struct _StackFrame {
    WCHAR targetDll[MAX_PATH];
    ULONG offset;
    ULONG totalStackSize;
    BOOL  requiresLoadLibrary;
    BOOL  setsFramePointer;
    PVOID returnAddress;
    BOOL  pushRbp;
    ULONG countOfCodes;
    ULONG pushRbpIndex;
} StackFrame;

typedef struct _StackProfileEntry {
    WCHAR   modulePath[MAX_PATH];
    CHAR    functionName[64];
    ULONG   offsetFromExport;
    BOOL    needLoad;
    BOOL    hasOffset;
    DWORD64 absoluteAddress;
} StackProfileEntry;

typedef struct _MappedImageInfo {
    PBYTE Base;
    BOOL  IsDll;
    DWORD EntryRva;
} MappedImageInfo;

/* ---------------------------------------------------------
   Missing type #2 — loader context
   --------------------------------------------------------- */
typedef struct _UR_LOADER_CONTEXT {
    MappedImageInfo ImageInfo;
} UR_LOADER_CONTEXT;

/* ---------------------------------------------------------
   Your stack context — now valid because ImageBaseEntry exists
   --------------------------------------------------------- */
typedef struct _UR_STACK_CONTEXT {
    ImageBaseEntry ImageBaseCache[64];
    int CacheCount;
} UR_STACK_CONTEXT;

#ifdef __cplusplus
}
#endif

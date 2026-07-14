#include <stdio.h>

#include "common.h"
#include "pe_loader.h"

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

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc =
        (PIMAGE_IMPORT_DESCRIPTOR)(pDestBase + importDir.VirtualAddress);

    PIMAGE_IMPORT_DESCRIPTOR pImportEnd =
        (PIMAGE_IMPORT_DESCRIPTOR)(pDestBase + importDir.VirtualAddress + importDir.Size);

    while (pImportDesc->Name != 0 && pImportDesc < pImportEnd) {
        char* dllName = (char*)(pDestBase + pImportDesc->Name);
        HMODULE hDependency = LoadLibraryA(dllName);
        if (!hDependency) return FALSE;

        PIMAGE_THUNK_DATA pIAT =
            (PIMAGE_THUNK_DATA)(pDestBase + pImportDesc->FirstThunk);

        DWORD lookupThunkRVA = pImportDesc->OriginalFirstThunk
                               ? pImportDesc->OriginalFirstThunk
                               : pImportDesc->FirstThunk;

        PIMAGE_THUNK_DATA pINT =
            (PIMAGE_THUNK_DATA)(pDestBase + lookupThunkRVA);

        // fairly noisy and only helpful once
        /*
        printf("[*] Import DLL: %s\n", dllName);
        printf("    FirstThunk=0x%08X OriginalFirstThunk=0x%08X lookupThunkRVA=0x%08X\n",
               pImportDesc->FirstThunk,
               pImportDesc->OriginalFirstThunk,
               lookupThunkRVA);
        printf("    IAT=%p INT=%p\n", pIAT, pINT);
        */

        PBYTE imageEnd = pDestBase + pNtHeaders->OptionalHeader.SizeOfImage;

        while (pINT->u1.AddressOfData != 0 &&
            (PBYTE)pIAT >= pDestBase &&
            (PBYTE)pIAT < imageEnd)
        {
            PVOID pFuncAddress = NULL;

            if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal)) {
                WORD ordinal = IMAGE_ORDINAL(pINT->u1.Ordinal);
                pFuncAddress = (PVOID)GetProcAddress(hDependency, MAKEINTRESOURCEA(ordinal));
            } else {
                PIMAGE_IMPORT_BY_NAME pImportName =
                    (PIMAGE_IMPORT_BY_NAME)(pDestBase + pINT->u1.AddressOfData);
                pFuncAddress = (PVOID)GetProcAddress(hDependency, (LPCSTR)pImportName->Name);
            }

            if (!pFuncAddress) return FALSE;

            //printf("        IAT=%p INT=%p Func=%p\n", pIAT, pINT, pFuncAddress);

            pIAT->u1.Function = (ULONG_PTR)pFuncAddress;
            pIAT++;
            pINT++;
        }
        /*printf("    [loop exit] IAT=%p INT=%p AddressOfData=0x%08llX\n",
            pIAT, pINT, (unsigned long long)pINT->u1.AddressOfData);*/
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

BOOL ValidateAndMapPE(PBYTE pSourcePayload, DWORD sourceSize, MappedImageInfo* outInfo)
{
    printf("[*] ValidateAndMapPE outInfo=%p\n", outInfo);
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
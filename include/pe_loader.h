#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

PBYTE ReadPayloadFile(const CHAR* filePath, PDWORD pFileSize);

PBYTE RunRestorationPipeline(PBYTE pRawFile, DWORD size);

BOOL ValidateAndMapPE(
    PBYTE pSourcePayload,
    DWORD sourceSize,
    MappedImageInfo* outInfo
);

BOOL ResolveImageImports(
    PBYTE pDestBase,
    PIMAGE_NT_HEADERS pNtHeaders
);

void TuneSectionPermissions(
    PBYTE pDestBase,
    PIMAGE_NT_HEADERS pNtHeaders
);

#ifdef __cplusplus
}
#endif
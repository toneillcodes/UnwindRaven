#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOL LoadBlueprintFile(
    const CHAR* path,
    StackProfileEntry* out,
    int* outCount
);

BOOL BuildSyntheticStackFromBlueprint(
    const StackProfileEntry* bp,
    int bpCount,
    StackFrame* outFrames,
    int* outFrameCount
);

BOOL MapPayloadImage(
    const CHAR* dllPath,
    MappedImageInfo* outInfo
);

HANDLE StartSpoofedThread(
    const StackFrame* frames,
    int frameCount,
    const MappedImageInfo* imgInfo
);

#ifdef __cplusplus
}
#endif

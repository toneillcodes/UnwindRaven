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
    UR_STACK_CONTEXT* sctx,
    const StackProfileEntry* bp,
    int bpCount,
    StackFrame* outFrames,
    int* outFrameCount
);

/*
BOOL MapPayloadImage(
    const CHAR* dllPath,
    MappedImageInfo* outInfo
);*/

BOOL MapPayloadImage(
    const CHAR* dllPath,
    UR_LOADER_CONTEXT* lctx
);

/*
old version invoking an image
HANDLE StartSpoofedThread(
    const StackFrame* frames,
    int frameCount,
    const MappedImageInfo* imgInfo
);*/

/*
HANDLE StartSpoofedThread(
    const StackFrame* frames,
    int frameCount,
    void* entryPoint,
    void* userParam
);*/

HANDLE StartSpoofedThread(
    const StackFrame* frames,
    int frameCount,
    void* entryPoint,
    void* arg1,
    void* arg2,
    void* arg3,
    void* arg4
);

HANDLE StartSpoofedLoaderThread(
    const StackFrame* frames,
    int frameCount,
    UR_LOADER_CONTEXT* lctx
);

#ifdef __cplusplus
}
#endif

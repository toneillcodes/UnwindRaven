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

BOOL MapPayloadImage(
    const CHAR* dllPath,
    UR_LOADER_CONTEXT* lctx
);

/*
HANDLE StartSpoofedThread(
    const StackFrame* frames,
    int frameCount,
    void* entryPoint,
    void* userParam
);*/

// adding support for args
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
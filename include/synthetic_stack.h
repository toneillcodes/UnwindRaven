#pragma once
#include "common.h"
#include "unwind_info.h"

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS CalculateFunctionStackSize(
    PRUNTIME_FUNCTION pRuntimeFunction,
    DWORD64 ImageBase,
    StackFrame* stackFrame
);

NTSTATUS CalculateFunctionStackSizeWrapper(StackFrame* stackFrame);

void BuildDynamicStack(
    UR_STACK_CONTEXT* ctx,
    const StackProfileEntry* blueprint,
    int blueprintSize,
    StackFrame* outStack,
    int* outFrameCount
);

void InitializeFakeThreadState(
    CONTEXT* context,
    StackFrame* targetCallStack,
    int frameCount
);

void DumpSyntheticStack(
    const StackFrame* targetCallStack,
    int frameCount
);

#ifdef __cplusplus
}
#endif

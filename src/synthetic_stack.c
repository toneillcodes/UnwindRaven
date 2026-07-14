#include "common.h"
#include "unwind_info.h"
#include "stack_blueprint.h"
#include "synthetic_stack.h"

#include <stdio.h>
#include <wchar.h>
#include <string.h>

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

void BuildDynamicStack(
    UR_STACK_CONTEXT* ctx,
    const StackProfileEntry* blueprint,
    int blueprintSize,
    StackFrame* outStack,
    int* outFrameCount
)
{
    int i;
    *outFrameCount = 0;

    for (i = 0; i < blueprintSize; i++) {
        WCHAR normalized[MAX_PATH];
        HMODULE hMod;
        DWORD64 funcAddr;
        StackFrame* frame;

        if (!NormalizeModulePath(normalized, blueprint[i].modulePath))
            continue;

        hMod = GetCachedImageBase(ctx, normalized);
        if (!hMod) {
            hMod = GetModuleHandleW(normalized);
            if (!hMod || blueprint[i].needLoad) {
                hMod = LoadLibraryW(normalized);
            }
            if (hMod) {
                CacheImageBase(ctx, normalized, hMod);
            }
        }

        if (!hMod) {
            continue;
        }

        funcAddr = blueprint[i].absoluteAddress;

        if (!funcAddr) {
            FARPROC pFunc = GetProcAddress(hMod, blueprint[i].functionName);

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

        frame = &outStack[*outFrameCount];
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

        printf("[*] Frame %d: totalStackSize=0x%lx, pushRbp=%d, setsFP=%d\n",
               i, sf->totalStackSize, sf->pushRbp, sf->setsFramePointer);

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

            printf("    [FPREG case] childSp=0x%llX, new RSP=0x%llX\n",
                   childSp, context->Rsp);

            bPreviousFrameSetUWOP_SET_FPREG = FALSE;
        } else {
            context->Rsp -= sf->totalStackSize;
            *(ULONG64*)(context->Rsp) = (ULONG64)sf->returnAddress;

            printf("    [normal] new RSP=0x%llX\n", context->Rsp);
        }

        if (sf->setsFramePointer) {
            childSp = context->Rsp + 8;
            bPreviousFrameSetUWOP_SET_FPREG = TRUE;
        }
    }
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
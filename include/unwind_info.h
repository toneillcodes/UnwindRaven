#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

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

enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL      = 0,
    UWOP_ALLOC_LARGE      = 1,
    UWOP_ALLOC_SMALL      = 2,
    UWOP_SET_FPREG        = 3,
    UWOP_SAVE_NONVOL      = 4,
    UWOP_SAVE_NONVOL_FAR  = 5,
    UWOP_SAVE_XMM128      = 8,
    UWOP_SAVE_XMM128_FAR  = 9,
    UWOP_PUSH_MACHFRAME   = 10
};

#define UNW_FLAG_CHAININFO 0x4
#define RBP_OP_INFO        0x5

#ifdef __cplusplus
}
#endif

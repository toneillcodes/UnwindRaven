#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

extern DWORD gSpoofedThreadId;          //  tracking the thread for targeted VehCallback processing. todo: move to a context

LONG CALLBACK VehCallback(PEXCEPTION_POINTERS ExceptionInfo);

BOOL RegisterVeh(void);

#ifdef __cplusplus
}
#endif
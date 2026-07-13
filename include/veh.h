#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

extern DWORD gSpoofedThreadId;   // <‑‑ ADD THIS

LONG CALLBACK VehCallback(PEXCEPTION_POINTERS ExceptionInfo);

BOOL RegisterVeh(void);

#ifdef __cplusplus
}
#endif

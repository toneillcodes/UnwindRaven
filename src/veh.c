#include "common.h"
#include "veh.h"
#include <stdio.h>

DWORD gSpoofedThreadId = 0;

LONG CALLBACK VehCallback(PEXCEPTION_POINTERS ExceptionInfo)
{
    // Only handle AVs from the spoofed thread (PoC behavior)
    if (GetCurrentThreadId() != gSpoofedThreadId)
        return EXCEPTION_CONTINUE_SEARCH;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    printf("[+] VEH Exception Handler called\n");
    printf("[+] Redirecting spoofed thread to RtlExitUserThread\n");

    ExceptionInfo->ContextRecord->Rip =
        (DWORD64)GetProcAddress(GetModuleHandleA("ntdll"), "RtlExitUserThread");
    ExceptionInfo->ContextRecord->Rcx = 0;

    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL RegisterVeh(void)
{
    return AddVectoredExceptionHandler(1, VehCallback) != NULL;
}

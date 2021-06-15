#pragma once
#include "Struct.h"

namespace NtApiWork {




    EXTERN_C NTSTATUS NTAPI SyscallNtClose(
        IN HANDLE               ObjectHandle
    );
    EXTERN_C NTSTATUS NTAPI SyscallTerminateProc(
        IN HANDLE               ProcessHandle OPTIONAL,
        IN NTSTATUS             ExitStatus
    );




}
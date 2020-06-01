#pragma once

extern NTSTATUS WINAPI NtAllocateVirtualMemory
(
    HANDLE      ProcessHandle,
    PVOID       *BaseAddress,
    ULONG_PTR   ZeroBits,
    PSIZE_T     RegionSize,
    ULONG       AllocationType,
    ULONG       protect
);

namespace demo
{
    void hooksInstall();
    void hooksUninstall();

    void registerHandlers();
    void unregisterHandlers();

    void* allocateExecutableMemory(void* baseAddress, size_t size);

    inline void executeAddress(void* address)
    {
        reinterpret_cast<void(*)()>(address)();
    }
}
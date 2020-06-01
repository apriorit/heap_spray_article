#include "pch.h"
#include "demo.h"

namespace
{
    struct AllocationInfo
    {
        void*   baseAddress;
        size_t  size;
        ULONG   protect;
    };

    // globals
    std::vector<AllocationInfo> g_allocations;
    std::mutex g_mutex;
    void* g_exceptionHandler = nullptr;

    decltype(NtAllocateVirtualMemory)* g_origNtAllocateVirtualMemory = reinterpret_cast<decltype(g_origNtAllocateVirtualMemory)>
        (GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory"));

    // a simple workaround of recursive hook call
    thread_local bool g_ntAllocHookCalled = false;
    class HookGuard
    {
    public:
        explicit HookGuard(bool& guarded)
            : m_guarded(guarded)
        {
            if (!m_guarded)
            {
                m_guarded = true;
            }
        }

        ~HookGuard()
        {
            if (m_guarded)
            {
                m_guarded = false;
            }
        }

        explicit operator bool() const
        {
            return m_guarded;
        }

    private:
        bool& m_guarded;
    };

    // our hook
    NTSTATUS WINAPI hookNtAllocateVirtualMemory
    (
        HANDLE      ProcessHandle,
        PVOID       *BaseAddress,
        ULONG_PTR   ZeroBits,
        PSIZE_T     RegionSize,
        ULONG       AllocationType,
        ULONG       protect
    )
    {
        NTSTATUS status = 0;

        HookGuard hookGuard(g_ntAllocHookCalled);

        if (!(AllocationType & MEM_COMMIT) || !hookGuard)
        {
            return g_origNtAllocateVirtualMemory(ProcessHandle,
                BaseAddress,
                ZeroBits,
                RegionSize,
                AllocationType,
                protect
            );
        }

        AllocationInfo info {};

        if (protect & PAGE_EXECUTE_READWRITE)
        {
            info.protect = protect;
            protect &= ~PAGE_EXECUTE_READWRITE;
            protect |= PAGE_READWRITE;
        }

        status = g_origNtAllocateVirtualMemory(ProcessHandle,
            BaseAddress,
            ZeroBits,
            RegionSize,
            AllocationType,
            protect);

        if (status >= 0)
        {
            if (info.protect)
            {
                info.baseAddress = *BaseAddress;
                info.size = *RegionSize;
                // we affect this region
                std::lock_guard<std::mutex> lock(g_mutex);
                g_allocations.push_back(info);
            }
        }

        return status;
    }

    // handler for shellcode execution
LONG __stdcall vectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    PVOID executedAddress = ExceptionInfo->ExceptionRecord->ExceptionAddress;

    std::lock_guard<std::mutex> lock(g_mutex);
    auto infoIter = std::find_if(begin(g_allocations), end(g_allocations),
        [executedAddress](const AllocationInfo& info)
        {
            auto regionStart = reinterpret_cast<PBYTE>(info.baseAddress);
            auto regionEnd = regionStart + info.size;
            return executedAddress >= regionStart && executedAddress < regionEnd;
        });
    if (infoIter == end(g_allocations))
    {
        // not our region
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // good place for heap spray check!

    // restore protection
    DWORD oldProtect = 0;
    bool result = VirtualProtect(infoIter->baseAddress, infoIter->size, infoIter->protect, &oldProtect);
    if (!result)
    {
        throw std::runtime_error("VirtualProtect failed");
    }
    g_allocations.erase(infoIter);
    // just notify
    std::stringstream ss;
    ss << "Executed shellcode with address " << executedAddress << '\n';
    OutputDebugStringA(ss.str().c_str());
    return EXCEPTION_CONTINUE_EXECUTION;
}
}

namespace demo
{
    void hooksInstall()
    {
        if (!g_origNtAllocateVirtualMemory)
        {
            throw std::runtime_error("Orig NtAllocateVirtualMemory not found");
        }
        bool result = Mhook_SetHook(reinterpret_cast<void**>(&g_origNtAllocateVirtualMemory), hookNtAllocateVirtualMemory);
        if (!result)
        {
            throw std::runtime_error("mhook failed to set hook");
        }
    }

    void hooksUninstall()
    {
        Mhook_Unhook(reinterpret_cast<void**>(&g_origNtAllocateVirtualMemory));
    }

    void registerHandlers()
    {
        if (g_exceptionHandler)
        {
            throw std::runtime_error("The vectored handler is already registered");
        }
        g_exceptionHandler = AddVectoredExceptionHandler(1, vectoredHandler);
        if (!g_exceptionHandler)
        {
            throw std::runtime_error("Failed to register vectored handler");
        }
    }

    void unregisterHandlers()
    {
        RemoveVectoredExceptionHandler(g_exceptionHandler);
    }

    void* allocateExecutableMemory(void* baseAddress, size_t size)
    {
        void* result = VirtualAlloc
        (
            baseAddress,
            static_cast<SIZE_T>(size),
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
        if (!result)
        {
            throw std::runtime_error("VirtualAlloc failed");
        }
        // store shellcode - just nop + ret (x86)
        PBYTE page = reinterpret_cast<PBYTE>(result);
        page[0] = 0x90; // NOP
        page[1] = 0xC3; // RET
        return result;
    }
}
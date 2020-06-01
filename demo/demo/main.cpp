#include "pch.h"
#include "demo.h"

#define PAGE_SIZE 0x1000

int main()
{
    using namespace demo;
    try
    {
        registerHandlers();
        hooksInstall();

        void* pageAddr = allocateExecutableMemory(nullptr, PAGE_SIZE);
        executeAddress(pageAddr);

        hooksUninstall();
        unregisterHandlers();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}
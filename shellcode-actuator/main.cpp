#ifdef _WIN64
#ifdef _DEBUG
#include "../x64/Debug/payload.hpp"
#else
#include "../x64/Release/payload.hpp"
#endif
#else
#ifdef _DEBUG
#include "../Debug/payload.hpp"
#else
#include "../Release/payload.hpp"
#endif
#endif // _WIN64

#include <Windows.h>
int main() {
    LoadLibraryA("user32.dll");
    LoadLibraryA("kernel32.dll");
    LoadLibraryA("KernelBase.dll");
    LoadLibraryA("msvcrt.dll");
    LoadLibraryA("gdi32.dll");

    auto shell_address = VirtualAlloc(0, sizeof(shellcode::payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(shell_address, shellcode::payload, sizeof(shellcode::payload));

    reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<char *>(shell_address) +
                                             shellcode::rva::ShellCodeEntryPoint)((void *)0x9999999);

    reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<char *>(shell_address) +
                                             shellcode::rva::ShellCodeEntryPoint2)((void *)0x9999999);
    reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<char *>(shell_address) +
                                             shellcode::rva::ShellCodeEntryPoint3)((void *)0x9999999);

    return 0;
}
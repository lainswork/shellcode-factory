#include "shellcode.h"
#include "dwm-capture.h"
SC_EXPORT 
DWORD ShellCodeEntryPoint(LPVOID lpParameter) {
    CHAR buf[256] = {0};
    LI_FN(sprintf)
    (buf, xorstr_("函数%s 线程参数0x%p"), __FUNCDNAME__, lpParameter);
    LI_FN(MessageBoxA)(HWND(0), buf, xorstr_("来自shellcode的展示"), MB_OK);
    return 0;
}
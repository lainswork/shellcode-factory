#include "shellcode.h"


void ShellcodeFunctionCallExternExample(void) {

    //使用系统 API
    LI_FN(MessageBoxA)(HWND(0), "Shellcode Function Call Extern Example", xorstr_("Display from shellcode!"), MB_OK | MB_TOPMOST);

    return;
}
#include "shellcode.h"


extern void ShellcodeFunctionCallExternExample(void);

/* shallcode 入口示例 */
SC_EXPORT DWORD ShellcodeFunctionEntryPointExample(LPVOID lpParameter) {

    // 调试输出
    DbgPrint("Thread lpParameter 0x%p", lpParameter);

    // 使用 sprintf 、 字符串 、 以及编译器常量 
    CHAR buf[512] = {0};
    LI_FN(sprintf)(buf, "Hello The thread parameter is 0x%p and The function name is %s", lpParameter,__FUNCTION__);

    //使用系统 API
    LI_FN(MessageBoxA)(HWND(0), buf, xorstr_("Display from shellcode!"), MB_OK | MB_TOPMOST);

    //跨.cpp调用函数 可以通过 extern，也可以通过在共同头文件中给出声明
    ShellcodeFunctionCallExternExample();

    return 0;
}


/* shallcode VEH 示例  */
LONG WINAPI VehExampleHandler(EXCEPTION_POINTERS *pExceptionInfo) { return EXCEPTION_CONTINUE_SEARCH; }
SC_EXPORT DWORD ShellcodeVehExample(LPVOID lpParameter) {
    PVOID veh_hanle = LI_FN(AddVectoredExceptionHandler)(1, &VehExampleHandler);
    if (veh_hanle) {
        LI_FN(RemoveVectoredExceptionHandler)(veh_hanle);
    }
    return 0;
}


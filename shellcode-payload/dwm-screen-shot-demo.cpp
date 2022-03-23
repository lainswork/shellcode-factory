#include "dwm-capture.h"
#include "shellcode.h"
#include <dxgi.h>
#include <d3d11.h>
#include <wrl.h>
#define _GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8)                                                     \
    GUID name = {l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8};

// 这里直接把 Nt函数的定义给出来，取个巧，依靠 lazy_importer 获取函数并调用
PVOID NTAPI RtlAddVectoredExceptionHandler(IN ULONG FirstHandler, IN PVECTORED_EXCEPTION_HANDLER VectoredHandler);
ULONG NTAPI RtlRemoveVectoredExceptionHandler(IN PVOID VectoredHandlerHandle);

LONG WINAPI VehHandler(EXCEPTION_POINTERS *pExceptionInfo);
void        TakeDxgiCapture(IUnknown *pDXGISwapChain);
__int64 __fastcall HookFunCallBack(IUnknown *pDXGISwapChain, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6,
                                   __int64 a7, __int64 a8);

//可以将优化开到最大，那全局变量最好使用 volatile 修饰

//使用公开的静态和导出变量
SC_EXPORT_DATA(volatile __int64, hook_offsets[4]) // hook符号偏移，由注入器在注入shellcode前修正
SC_EXPORT_DATA(volatile __int64, CaptureBitmapPointer) // 公开变量 目的是让注入器确定偏移位置
SC_EXPORT_DATA(volatile unsigned int, CaptureWidth)
SC_EXPORT_DATA(volatile unsigned int, CaptureHeight)

// 使用全局和静态变量
volatile unsigned long hook_fun_execute      = 0; // hook函数是否执行
volatile unsigned long  hook_fun_done         = 0; //截图函数是否执行
volatile DWORD          hook_fun_memory_proct = 0; //被hook函数内存属性
volatile DWORD64         hook_fun_address      = 0; // hook函数地址

//使用内嵌函数 这个东西只在本cpp起作用，不要写在.h里面 写在每个cpp的最开头部分
extern "C" {
#pragma function(memset)
void *__cdecl memset(void *dest, int value, size_t num) {
    __stosb(static_cast<unsigned char *>(dest), static_cast<unsigned char>(value), num);
    return dest;
}
#pragma function(memcpy)
void *__cdecl memcpy(void *dest, const void *src, size_t num) {
    __movsb(static_cast<unsigned char *>(dest), static_cast<const unsigned char *>(src), num);
    return dest;
}
}

SC_EXPORT DWORD DwmCaptureScreen(LPVOID lpParameter) {

    DbgPrint("Dwm Capture Screen Thread Entered!");

#ifdef _DEBUG
    for (size_t idx = 0; idx < ArrNum(hook_offsets); idx++) {
        if (hook_offsets[idx] == 0) {
            DbgPrint("Null offset");
            return -1;
        } else {
            HMODULE hDxgi = LI_FN(GetModuleHandleA)("dxgi.dll");
            DbgPrint("Hook Offset 0x%p address 0x%p", hook_offsets[idx], hook_offsets[idx] + (DWORD64)hDxgi);
        }
    }
#endif // _DEBUG


    PVOID veh_hanle = LI_FN(RtlAddVectoredExceptionHandler)(1, VehHandler);
    if (!veh_hanle) {
        DbgPrint("veh erro !");
        return -1;
    }

    for (size_t idx = 0; idx < ArrNum(hook_offsets); idx++) {

        hook_fun_address = 0;

        HMODULE hDxgi = LI_FN(GetModuleHandleA)("dxgi.dll");

        hook_fun_address = (DWORD64)hDxgi + hook_offsets[idx];

        MEMORY_BASIC_INFORMATION mem_info;
        memset(&mem_info, 0, sizeof(mem_info));
        LI_FN(VirtualQuery)((LPCVOID)hook_fun_address, &mem_info, sizeof(mem_info));
        hook_fun_memory_proct = mem_info.Protect;

        DbgPrint("set hook at 0x%p\t ", hook_fun_address);

        LI_FN(VirtualProtect)((LPVOID)hook_fun_address, 1, mem_info.Protect | PAGE_GUARD, (PDWORD)&hook_fun_memory_proct);

        for (size_t i = 0;; i++) {
            LI_FN(Sleep)(100);
            if (i > 50 ) {
                DbgPrint("hook time out ");
                if (_InterlockedCompareExchange(&hook_fun_execute, 1, 1) == 0) {
                    break;
                }
            }
            if (_InterlockedCompareExchange(&hook_fun_done, 1, 1) == 1)
                break;
        }

        LI_FN(VirtualProtect)((LPVOID)hook_fun_address, 1, mem_info.Protect, (PDWORD)&hook_fun_memory_proct);

        if (_InterlockedCompareExchange(&hook_fun_execute, 1, 1) == 1)
            break;
        else
            continue;
    }

    LI_FN(RtlRemoveVectoredExceptionHandler)(veh_hanle);


    DbgPrint("fun_execute:[%d]\t fun_done:[%d]\t ", _InterlockedCompareExchange(&hook_fun_execute, 1, 1),
             _InterlockedCompareExchange(&hook_fun_done, 1, 1));

    if (_InterlockedCompareExchange(&hook_fun_execute, 1, 1) == 1 &&
        _InterlockedCompareExchange(&hook_fun_done, 1, 1) == 1) {
        return 1;
    }

    return -1;
}


LONG WINAPI VehHandler(EXCEPTION_POINTERS *pExceptionInfo) {

    DWORD64 page_start = ((DWORD64)(hook_fun_address)) & 0xFFFFFFFFFFFFF000;
    DWORD64 page_end   = page_start + 0x1000;

    LONG result;
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) //
    {
        if ((pExceptionInfo->ContextRecord->Rip >= page_start) && (pExceptionInfo->ContextRecord->Rip <= page_end)) {

            if (pExceptionInfo->ContextRecord->Rip == (DWORD64)(hook_fun_address)) {

                _InterlockedExchange(&hook_fun_execute, 1 );

                pExceptionInfo->ContextRecord->Rip = (DWORD64)&HookFunCallBack;

                return EXCEPTION_CONTINUE_EXECUTION;
            }

            pExceptionInfo->ContextRecord->EFlags |= 0x100;
        }

        result = EXCEPTION_CONTINUE_EXECUTION;
    }

    else if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
        DWORD dwOld;
        LI_FN(VirtualProtect)((LPVOID)hook_fun_address, 1, hook_fun_memory_proct | PAGE_GUARD, &dwOld);
        result = EXCEPTION_CONTINUE_EXECUTION;
    }

    else {
        result = EXCEPTION_CONTINUE_SEARCH;
    }

    return result;
}

__int64 __fastcall HookFunCallBack(IUnknown *pDXGISwapChain, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, __int64 a7,
                                   __int64 a8) {
   
    DbgPrint("HookFunCallBack IUnknown* [0x%p]", pDXGISwapChain);

    auto ret = // 调用原 hook 函数
        reinterpret_cast<decltype(HookFunCallBack) *>(hook_fun_address)(pDXGISwapChain, a2, a3, a4, a5, a6, a7, a8);
    
    //保存 dxgi 画面
    TakeDxgiCapture(pDXGISwapChain);

    return ret;
}

/*
从交换链获取D3D设备、上下文、和后备缓冲区（纹理），
将 和后备缓冲区 拷贝至我们创建的 pCaptureD3D11Texture2D(CPU可访问的)
map pCaptureD3D11Texture2D 然后将bitmap拷贝出来
*/
void TakeDxgiCapture(IUnknown *pDXGISwapChain) {

    // 使用 comptr 模板来避免手动管理 com资源
    Microsoft::WRL::ComPtr<ID3D11Device>        pD3D11Device;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> pID3D11DeviceContext;
    Microsoft::WRL::ComPtr<ID3D11Texture2D>     pD3D11Texture2D;
    Microsoft::WRL::ComPtr<ID3D11Texture2D>     pCaptureD3D11Texture2D;
    D3D11_TEXTURE2D_DESC                        SwapChanDesc{};

    // 不要直接使用 D3D SDK中的 IID_ID3D11Device 等全局变量，这些变量储存在dx系列的 lib和 dll中 
    _GUID(IID_ID3D11Device, 0xdb6f6ddb, 0xac77, 0x4e88, 0x82, 0x53, 0x81, 0x9d, 0xf9, 0xbb, 0xf1, 0x40);
    auto hr = reinterpret_cast<IDXGISwapChain*>(pDXGISwapChain)
                  ->GetDevice(IID_ID3D11Device, (void **)pD3D11Device.ReleaseAndGetAddressOf());

    if (hr == S_OK) {
        _GUID(IID_ID3D11Texture2D, 0x6f15aaf2, 0xd208, 0x4e89, 0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c);
        hr = reinterpret_cast<IDXGISwapChain *>(pDXGISwapChain)
                 ->GetBuffer(0,IID_ID3D11Texture2D, (void **)pD3D11Texture2D.ReleaseAndGetAddressOf());

        if (hr == S_OK) {
            pD3D11Texture2D->GetDesc(&SwapChanDesc);
            SwapChanDesc.BindFlags      = 0;
            SwapChanDesc.MiscFlags      = 0;
            // CPU可访问的纹理
            SwapChanDesc.CPUAccessFlags = 0x30000;
            SwapChanDesc.Usage          = D3D11_USAGE_STAGING;
            hr = pD3D11Device->CreateTexture2D(&SwapChanDesc, 0, pCaptureD3D11Texture2D.ReleaseAndGetAddressOf());

            if (hr == S_OK) {
                pD3D11Device->GetImmediateContext(pID3D11DeviceContext.ReleaseAndGetAddressOf());

                pID3D11DeviceContext->CopyResource(pCaptureD3D11Texture2D.Get(), pD3D11Texture2D.Get());

                D3D11_MAPPED_SUBRESOURCE MappedResource{};
                hr = pID3D11DeviceContext->Map(pCaptureD3D11Texture2D.Get(), 0, D3D11_MAP_READ_WRITE, 0,
                                               &MappedResource);

                if (hr == S_OK) {
                    LPVOID buffer =
                        LI_FN(VirtualAlloc)((LPVOID)0,
                                            static_cast<SIZE_T>(sizeof(D3D11_TEXTURE2D_DESC) +
                                            (static_cast<SIZE_T>(SwapChanDesc.Height) * SwapChanDesc.Width * 0x4)),
                                            MEM_COMMIT,
                                            PAGE_READWRITE);

                    // 申请的内存是 Height * Width * 4  + sizeof(D3D11_TEXTURE2D_DESC) 也就是把 desc也直接一起复制到了申请的内存中，这样我们在  dwm-screen-shot.exe中省了很多麻烦
                    memcpy(buffer, &SwapChanDesc, sizeof(D3D11_TEXTURE2D_DESC));
                    memcpy((char *)buffer + sizeof(D3D11_TEXTURE2D_DESC), MappedResource.pData,
                           (static_cast<SIZE_T>(SwapChanDesc.Height) * SwapChanDesc.Width * 0x4));
                    CaptureBitmapPointer = (__int64)buffer;
                    CaptureWidth         = SwapChanDesc.Width;
                    CaptureHeight        = SwapChanDesc.Height;
                    pID3D11DeviceContext->Unmap(pCaptureD3D11Texture2D.Get(), 0);

                    DbgPrint("Success at 0x%p [ %d * %d ]", CaptureBitmapPointer, CaptureWidth, CaptureHeight);

                    _InterlockedExchange(&hook_fun_done, 1);
                    return;

                } else {
                    goto Fail;
                }
            } else {
                goto Fail;
            }
        } else {
            goto Fail;
        }
    } else {
        goto Fail;
    }

    //由于过程不复杂，并且使用了智能指针，所以我们 goto！
Fail:
    DbgPrint("TakeDxgiCapture Fail !");
    _InterlockedExchange(&hook_fun_done, 1);
}
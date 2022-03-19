#include <intrin.h>
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

// 一些编译器内置函数可能需要用户手动定义 
// 参考代码 https://gist.github.com/mmozeiko/6a365d6c483fc721b63a

#ifdef _M_IX86 // use this file only for 32-bit architecture
extern "C" {

__declspec(naked) void _aullshr() {
    __asm {
        cmp     cl,64
        jae     short RETZERO

;
; Handle shifts of between 0 and 31 bits
;
        cmp     cl, 32
        jae     short MORE32
        shrd    eax,edx,cl
        shr     edx,cl
        ret

;
; Handle shifts of between 32 and 63 bits
;
MORE32:
        mov     eax,edx
        xor     edx,edx
        and     cl,31
        shr     eax,cl
        ret

;
; return 0 in edx:eax
;
RETZERO:
        xor     eax,eax
        xor     edx,edx
        ret
    }
}
}
#endif
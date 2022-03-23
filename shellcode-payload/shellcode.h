#pragma once
#include "lazy_importer.hpp"
#ifndef _M_IX86
#include "xorstr.hpp"
#else
#define xorstr_(str) (str)
#endif //

#include <Windows.h>
#include <cstdio>
#define SC_EXPORT extern "C" _declspec(dllexport)
#define SC_EXPORT_DATA(type, data)                                                                                     \
    extern "C" _declspec(dllexport) type data;                                                                         \
    type                                 data;

template <typename T, size_t N>
constexpr size_t ArrNum(T (&A)[N]) {
    return N;
}

template <typename... Args>
void __DbgPrint(const char *format, Args... args) {
    CHAR buf[512] = {0};
    LI_FN(sprintf)
    (buf, format, args...);
    LI_FN(OutputDebugStringA)(buf);
}

#ifdef _DEBUG
#define DbgPrint(format, ...) __DbgPrint("[ payload ]" format "\t --line: %05d \n", __VA_ARGS__, __LINE__)
#else
#define DbgPrint(format, ...)
#endif // _DEBUG


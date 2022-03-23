#pragma once
#include "rang.hpp"
template <typename... Args>
void __DbgPrint(const char *identifier, rang::fg color, const char *format, Args... args) {

    char buffer[2500] = {'\0'};
    sprintf_s(buffer + strlen(buffer), 2500 - strlen(buffer), format, args...);
    sprintf_s(buffer + strlen(buffer), 2500 - strlen(buffer), "\n");
    std::cout << "[ " << rang::style::bold << color << identifier << rang::style::reset << rang::fg::reset << " ]"
              << buffer;
}

#define erro(...) __DbgPrint("erro", rang::fg::red, __VA_ARGS__)
#define info(...) __DbgPrint("info", rang::fg::blue, __VA_ARGS__)
#define important(...) __DbgPrint("important", rang::fg::magenta, __VA_ARGS__)
#define success(...) __DbgPrint("success", rang::fg::green, __VA_ARGS__)

#define ERO(...) erro(__VA_ARGS__)
#define INF(...) info( __VA_ARGS__)
#define IMP(...) important(__VA_ARGS__)
#define SUC(...) success(__VA_ARGS__)
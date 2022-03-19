#pragma once
#include "span.hpp"

#include <Windows.h>
#include <winternl.h>

#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>
#include <regex>
#include <functional>
// /*https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#archive-library-file-format*/

namespace coff {
template <typename T>
using vector = std::vector<T>;

template <typename K, typename V>
using map = std::unordered_map<K, V>;

template <typename... T>
using pair = std::pair<T...>;

template <typename... T>
using tuple = std::tuple<T...>;

template <typename  T>
using span = tcb::span<T>;

using dword         = unsigned long;
using byte          = std::uint8_t;
using buffer_t      = std::vector<byte>;

struct buffer_view {
    buffer_view(byte *data, size_t size) : data(data), size(size) {}
    byte * data = 0;
    size_t size = 0;
};

using string        = std::string;
using coff_obj_info = tuple<string, buffer_view>;

template <size_t N>
constexpr bool same_str(const char *str, const char (&str_c)[N]) {
    return (strncmp(str, str_c, N - 1) == 0);
}
template <size_t N>
constexpr bool same_str(const char (&str_c)[N], const char *str) {
    return (strncmp(str, str_c, N - 1) == 0);
}


inline 
vector<string> split_str(const string &s, char delim = ' ') {
    vector<string> tokens;
    auto string_find_first_not = [s, delim](size_t pos = 0) -> size_t {
        for (size_t i = pos; i < s.size(); i++) {
            if (s[i] != delim)
                return i;
        }
        return string::npos;
    };
    size_t lastPos = string_find_first_not(0);
    size_t pos     = s.find(delim, lastPos);
    while (lastPos != string::npos) {
        tokens.emplace_back(s.substr(lastPos, pos - lastPos));
        lastPos = string_find_first_not(pos);
        pos     = s.find(delim, lastPos);
    }
    return tokens;
}


class lib;
class obj {
    friend class lib;

public:
    obj(byte *pObjBuffer, size_t bufferSize) : pObjBuffer(pObjBuffer), bufferSize(bufferSize) {}
    ~obj() {}
    byte *                obj_data() { return pObjBuffer; }
    PIMAGE_SYMBOL               get_symbol(string name);
    std::string                 name();
    void                        for_each_symbols(std::function<void(IMAGE_SYMBOL&)>);
    span<IMAGE_SYMBOL> &        symbols();
    const char *                symbol_name(IMAGE_SYMBOL &symbol);
    span<IMAGE_SECTION_HEADER> &sections();
    vector<string> &            exports();
    bool                        has_relocations(PIMAGE_SECTION_HEADER section_header);
    span<IMAGE_RELOCATION> &    relocations(PIMAGE_SECTION_HEADER section_header);

private:
    byte *                                             pObjBuffer;
    size_t                                             bufferSize;
    span<IMAGE_SYMBOL>                                 syms;
    span<IMAGE_SECTION_HEADER>                         _sections;
    vector<string>                                     _exports;
    map<PIMAGE_SECTION_HEADER, span<IMAGE_RELOCATION>> _relocations;
    span<IMAGE_RELOCATION>                             empty_relocations;
    const char *                                       strings = 0;
    lib *                                              _lib    = 0;
};

class lib {
public:
    lib(byte *pLibBuffer, size_t bufferSize) : pLibBuffer(pLibBuffer), bufferSize(bufferSize) {}
    ~lib() {}
    std::string  obj_name(obj &obj);
    vector<obj> &objs();

private:
    bool                         is_valid_lib();
    PIMAGE_ARCHIVE_MEMBER_HEADER pLongName_header = 0;
    byte *                       pLibBuffer;
    size_t                       bufferSize;
    vector<obj>                  _objs;
};
}; // namespace llnk

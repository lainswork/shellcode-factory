#include "coff.h"
#include <regex>
namespace coff {

PIMAGE_SYMBOL obj::get_symbol(string name) {
    auto &symbols = this->symbols();

    // 遍历所有符号
    for (size_t idx = 0; idx < symbols.size(); idx++) {
        auto &      symbol      = symbols[idx];
        const char *symbol_name = this->symbol_name(symbol);
        if (name == symbol_name) {
            return &symbol;
        }

        if (symbol.NumberOfAuxSymbols) {
            idx += symbol.NumberOfAuxSymbols;
        }
    }

    return 0;
}

std::string obj::name() { return _lib->obj_name(*this); }
void                obj::for_each_symbols(std::function<void(IMAGE_SYMBOL &)> _call) {
    auto &symbols = this->symbols();
    // 遍历所有符号
    for (size_t idx = 0; idx < symbols.size(); idx++) {
        _call(symbols[idx]);
        if (symbols[idx].NumberOfAuxSymbols) {
            idx += symbols[idx].NumberOfAuxSymbols;
        }
    }
}
span<IMAGE_SYMBOL> &obj::symbols() {
    if (syms.empty()) {
        PIMAGE_FILE_HEADER obj          = reinterpret_cast<PIMAGE_FILE_HEADER>(pObjBuffer);
        PIMAGE_SYMBOL      symbol_table = reinterpret_cast<PIMAGE_SYMBOL>(obj->PointerToSymbolTable + (byte *)obj);
        syms = span<IMAGE_SYMBOL>(symbol_table, static_cast<std::size_t>(obj->NumberOfSymbols));
    }
    return syms;
}

const char *obj::symbol_name(IMAGE_SYMBOL &symbol) {

    if (symbol.N.Name.Short != 0)
        return (reinterpret_cast<char *>(symbol.N.ShortName));
    else {
        if (!strings) {
            PIMAGE_FILE_HEADER    obj = reinterpret_cast<PIMAGE_FILE_HEADER>(pObjBuffer);
            PIMAGE_SECTION_HEADER section_headers =
                reinterpret_cast<PIMAGE_SECTION_HEADER>((byte *)obj + sizeof IMAGE_FILE_HEADER);

            PIMAGE_SYMBOL symbol_table = reinterpret_cast<PIMAGE_SYMBOL>(obj->PointerToSymbolTable + (byte *)obj);

            strings = reinterpret_cast<const char *>(reinterpret_cast<std::uintptr_t>(symbol_table) +
                                                     (obj->NumberOfSymbols * sizeof IMAGE_SYMBOL));
        }
        return (strings + symbol.N.Name.Long);
    }
}

span<IMAGE_SECTION_HEADER> &obj::sections() {
    if (_sections.empty()) {
        PIMAGE_FILE_HEADER    obj = reinterpret_cast<PIMAGE_FILE_HEADER>(pObjBuffer);
        PIMAGE_SECTION_HEADER section_headers =
            reinterpret_cast<PIMAGE_SECTION_HEADER>((byte *)obj + sizeof IMAGE_FILE_HEADER);
        _sections = span<IMAGE_SECTION_HEADER>(section_headers, static_cast<std::size_t>(obj->NumberOfSections));
    }
    return _sections;
}
vector<string> &obj::exports() {
    if (_exports.empty()) {
        PIMAGE_FILE_HEADER obj             = reinterpret_cast<PIMAGE_FILE_HEADER>(pObjBuffer);
        auto               symbols         = this->symbols();
        auto               section_headers = this->sections();

        for (size_t idx = 0; idx < symbols.size(); idx++) {

            auto &symbol = symbols[idx];

            if (symbol.SectionNumber > 0) {
                auto &section = section_headers[static_cast<size_t>(symbol.SectionNumber) - 1];

                // IMAGE_SCN_LNK_INFO
                if (coff::same_str((char *)section.Name, ".drectve")) {
                    // printf("%s\n", coff::obj::section_name(section.Name, string_table).c_str());
                    const char *data = section.PointerToRawData + (char *)obj;
                    // printf("%s\n", section.PointerToRawData + (char *)obj.data);
                    auto strs = coff::split_str(std::string(data, static_cast<size_t>(section.SizeOfRawData)), ' ');
                    for (auto str : strs) {

                        // msvc /EXPORT:?main2@@YAHXZ
                        // llvm /EXPORT:"?main2@@YAHXZ"
                        std::smatch base_match;
                        if (std::regex_match(str, base_match, std::regex("^(/EXPORT:)(.*?)|(\".*?\")"))) {
                            std::string export_name = base_match[2].str();
                            if (std::regex_match(export_name, base_match, std::regex("^\"(.*?)\""))) {
                                export_name = base_match[1].str();
                            }
                            if (std::regex_match(export_name, base_match, std::regex("(.*?),DATA$"))) {
                                export_name = base_match[1].str();
                            }
                            _exports.push_back(export_name);
                        }

                        // printf("%s\n",str.c_str());
                    }
                }
            }

            // NumberOfAuxSymbols 附加记录的数量。 也就是本 symbol 后面的附加symbol的数量
            if (symbol.NumberOfAuxSymbols)
                idx += symbol.NumberOfAuxSymbols;
        }
    }
    return _exports;
}

bool obj::has_relocations(PIMAGE_SECTION_HEADER section_header) {
    PIMAGE_FILE_HEADER obj = reinterpret_cast<PIMAGE_FILE_HEADER>(pObjBuffer);
    if (section_header->PointerToRelocations) {
        PIMAGE_RELOCATION reloc_dir =
            reinterpret_cast<PIMAGE_RELOCATION>(section_header->PointerToRelocations + reinterpret_cast<byte *>(obj));
        span<IMAGE_RELOCATION> relocation(reloc_dir, static_cast<std::size_t>(section_header->NumberOfRelocations));

        _relocations[section_header] = relocation;
        return true;
    } else {
        return false;
    }
}

span<IMAGE_RELOCATION> &obj::relocations(PIMAGE_SECTION_HEADER section_header) {
    auto iter = _relocations.find(section_header);
    if (iter != _relocations.end()) {
        return iter->second;
    } else {
        PIMAGE_FILE_HEADER obj = reinterpret_cast<PIMAGE_FILE_HEADER>(pObjBuffer);
        if (section_header->PointerToRelocations) {
            PIMAGE_RELOCATION reloc_dir = reinterpret_cast<PIMAGE_RELOCATION>(section_header->PointerToRelocations +
                                                                              reinterpret_cast<byte *>(obj));

            // 一种特殊情况，单个函数的依赖函数(重定位信息)超过 65535 时 ，这个 if 会生效
            // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
            if (section_header->NumberOfRelocations == 0xffff &&
                (section_header->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)) {
                span<IMAGE_RELOCATION> relocation(reloc_dir, static_cast<std::size_t>(reloc_dir->RelocCount));
                _relocations[section_header] = relocation;
                return _relocations[section_header];
            }

            span<IMAGE_RELOCATION> relocation(reloc_dir, static_cast<std::size_t>(section_header->NumberOfRelocations));

            _relocations[section_header] = relocation;
            return _relocations[section_header];
        }
    }
    return empty_relocations;
}

std::string lib::obj_name(obj &obj) {

    PIMAGE_ARCHIVE_MEMBER_HEADER coff_obj_header =
        reinterpret_cast<PIMAGE_ARCHIVE_MEMBER_HEADER>(obj.pObjBuffer - sizeof(IMAGE_ARCHIVE_MEMBER_HEADER));

    const char *pSlash = strchr(reinterpret_cast<const char *>(coff_obj_header->Name), '/');

    /*经典名称*/
    /* "name/" */
    if (pSlash && pSlash > reinterpret_cast<const char *>(coff_obj_header->Name)) {
        return string(reinterpret_cast<const char *>(coff_obj_header->Name),
                      pSlash - reinterpret_cast<const char *>(coff_obj_header->Name));
    }

    /*长名称 */
    /* "/xxx" */
    if (pSlash == reinterpret_cast<const char *>(coff_obj_header->Name) && coff_obj_header->Name[1] != 0x00) {

        size_t name_offset = std::atoi(
            string(reinterpret_cast<const char *>(&(coff_obj_header->Name[1])), sizeof(coff_obj_header->Name) - 1)
                .c_str());

        string      ret;
        const char *start = (char *)pLongName_header + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER) + name_offset;
        for (size_t i = 0;; i++) {
            if (start[i] != '\n' && start[i] != '\0')
                ret.push_back(start[i]);
            else
                return ret;
        }

        return string((char *)pLongName_header + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER) + name_offset);
    }

    return "";
}

vector<obj> &lib::objs() {
    if (_objs.empty()) {
        if (is_valid_lib()) {
            byte *cursor = pLibBuffer;

            auto step = [](PIMAGE_ARCHIVE_MEMBER_HEADER header) -> size_t {
                size_t member_size =
                    std::atoi(string(reinterpret_cast<const char *>(header->Size), sizeof(header->Size)).c_str());

                return sizeof(IMAGE_ARCHIVE_MEMBER_HEADER) + member_size + member_size % 2;
            };

            cursor += sizeof(IMAGE_ARCHIVE_START) - 1;

            while (cursor < pLibBuffer + bufferSize) {

                PIMAGE_ARCHIVE_MEMBER_HEADER coff_obj_header = reinterpret_cast<PIMAGE_ARCHIVE_MEMBER_HEADER>(cursor);
                /* '/' The archive member is one of the two linker members. Both of the
                 * linker members have this name. */
                /* '/' 存档成员是两个链接器成员之一。两个链接器成员都有此名称. */
                if (coff_obj_header->Name[0] == '/' &&
                    (coff_obj_header->Name[1] == 0x00 || coff_obj_header->Name[1] == ' ')) {
                    cursor += step(coff_obj_header);
                    continue;
                }

                /* '//' The longnames member is the third archive member and is
                 * optional.*/
                /* '//' longnames成员是第三个存档成员，是可选的.*/
                if (0 == std::memcmp(coff_obj_header->Name, "//", sizeof("//") - 1)) {
                    pLongName_header = coff_obj_header;
                    cursor += step(pLongName_header);
                    continue;
                }

                int obj_size = std::atoi(
                    string(reinterpret_cast<const char *>(coff_obj_header->Size), sizeof(coff_obj_header->Size))
                        .c_str());

                _objs.push_back(
                    {((byte *)coff_obj_header) + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER), static_cast<size_t>(obj_size)});
                _objs.back()._lib = this;
                cursor += step(coff_obj_header);
            }
        }
    }

    return _objs;
}

bool lib::is_valid_lib() {
    if (strncmp(reinterpret_cast<const char *>(pLibBuffer), IMAGE_ARCHIVE_START, sizeof IMAGE_ARCHIVE_START - 1))
        return false;
    else
        return true;
}

} // namespace coff
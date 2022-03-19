#include "coff.h"

#include "rang_impl.hpp"
#include <fstream>
#include <functional>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <intrin.h>
#include <iomanip>
#define ZH_CN


void open_binary_file(const std::string& file, std::vector<uint8_t>& data)
{
	std::ifstream fstr(file, std::ios::binary);
	fstr.unsetf(std::ios::skipws);
	fstr.seekg(0, std::ios::end);

	const auto file_size = fstr.tellg();

	fstr.seekg(NULL, std::ios::beg);
	data.reserve(static_cast<uint32_t>(file_size));
	data.insert(data.begin(), std::istream_iterator<uint8_t>(fstr), std::istream_iterator<uint8_t>());
}

void buffer_to_file_bin(unsigned char *buffer, size_t buffer_size, const std::string &filename) {
    std::ofstream file(filename, std::ios_base::out | std::ios_base::binary);
    file.write((const char *)buffer, buffer_size);
    file.close();
}



std::string &replace_all(std::string &str, const std::string &old_value, const std::string &new_value) {
    while (true) {
        std::string::size_type pos(0);
        if ((pos = str.find(old_value)) != std::string::npos)
            str.replace(pos, old_value.length(), new_value);
        else
            break;
    }
    return str;
}


struct relocation_info {
    std::string sym_name;
    uint32_t    va;
    uint32_t    type;
};
struct prepare_mapped_symbols {
    //before maped
    std::string sym_name;
    uint8_t *   bytes;
    uint32_t    bytes_size;
    //after maped
    uint32_t maped_va;
    uint32_t maped_size;

    std::vector<relocation_info> relocations;
};

// 递归查找函数的依赖，查看每个函数的重定位信息，并对重定位信息的重定位信息查找，循环往复
// involves 是最后形成的所有应该被链接的 符号
void recursive_lookup_relocations(std::set<std::string> &system_api,
                                  std::set<std::string> &not_found,
                                  std::map<std::string, prepare_mapped_symbols> &involves,
                                  std::vector<coff::lib> &libs,
                                  coff::obj &             obj,
                                  IMAGE_SYMBOL &          symbol) {
    if (symbol.SectionNumber == IMAGE_SYM_UNDEFINED) {

        std::string symbol_name = obj.symbol_name(symbol);
        for (auto &lib : libs) {
            for (auto &other_obj : lib.objs()) {
                auto new_symbol = other_obj.get_symbol(symbol_name);
                if (new_symbol /*&& other_obj.name() != obj.name()*/) {
                    if (new_symbol->SectionNumber > IMAGE_SYM_UNDEFINED)
                        recursive_lookup_relocations(system_api, not_found, involves, libs, other_obj, *new_symbol);
                }
            }
        }

        if (involves.find(symbol_name) == involves.end()) {
            if (_ReturnAddress() != (void *)&recursive_lookup_relocations) {

                //  这里的代码是为后续的: 由shellcode链接自动完成api的导入调用而写的，将来可以免去使用lazy_importer
                std::smatch base_match;
                if (std::regex_match(symbol_name, base_match, std::regex("^__imp_(.*?)"))) {
                    system_api.insert(symbol_name);
#ifdef ZH_CN
                    IMP("\t系统API: \"%s\"", base_match[1].str().c_str());
#else
                    IMP("\tWindows System API: \"%s\"", base_match[1].str().c_str());
#endif // ZH_CN
                } else {
                    not_found.insert(symbol_name);
#ifdef ZH_CN
                    ERO("\t\t无法找到的符号 \"%s\" >> 这是一个无效的符号，你未在任何.cpp文件中实现该符号的定义",
                        symbol_name.c_str());
#else
                    ERO("\t\tUnable to find symbol named \"%s\" >> This is an invalid symbol and you are not in any The "
                        "definition "
                        "of the symbol is implemented in the .cpp file",
                        symbol_name.c_str());
#endif // ZH_CN
                    
                }
            }
        }
    }

    // 要确保符号有效（当前obj内）
    if (symbol.SectionNumber > IMAGE_SYM_UNDEFINED) {
        
        //符号在本obj节
        IMAGE_SECTION_HEADER &section = obj.sections()[static_cast<size_t>(symbol.SectionNumber) - 1];

        prepare_mapped_symbols pre_sym;
        pre_sym.sym_name = obj.symbol_name(symbol);
        pre_sym.bytes    = static_cast<size_t>(section.PointerToRawData) + obj.obj_data();
        pre_sym.bytes_size = static_cast<uint32_t>(section.SizeOfRawData);
        involves.insert({pre_sym.sym_name, pre_sym});

        // 重定位信息
        auto &relocations = obj.relocations(&section);
        for (auto &reloc : relocations) {

            // 重定位符号
            auto &      reloc_symbol = obj.symbols()[reloc.SymbolTableIndex];
            std::string symbol_name  = obj.symbol_name(reloc_symbol);

            relocation_info reloc_info;
            reloc_info.va = reloc.VirtualAddress;
            reloc_info.sym_name = symbol_name;
            reloc_info.type     = reloc.Type;
            involves[pre_sym.sym_name].relocations.push_back(reloc_info);

            if (involves.find(symbol_name) == involves.end()) {
                //INF("%s       %s", obj.name().c_str(), symbol_name.c_str());
                recursive_lookup_relocations(system_api, not_found,involves, libs, obj, reloc_symbol);
            }
        }
    }
}


void print_exports(std::vector<coff::lib> &libs) {
    for (auto &lib : libs) {
        auto &objs = lib.objs();
        // 遍历 obj 文件查看导出
        for (auto &obj : objs) {
            for (auto &exp : obj.exports()) {
#ifdef ZH_CN
                INF("\"%s\"中具有导出函数:\"%s\"", obj.name().c_str(), exp.c_str());
#else
                INF("export symbol:\"%s\" in \"%s\"", exp.c_str(), obj.name().c_str());
#endif // ZH_CN
            }
        }
    }
}
std::vector<std::string> get_exports(std::vector<coff::lib> &libs) {
    std::vector<std::string> ret;
    for (auto &lib : libs) {
        auto &objs = lib.objs();
        for (auto &obj : objs) {
            for (auto &exp : obj.exports()) {
                ret.push_back(exp);
            }
        }
    }
    return ret;
}

void                     print_shellcode_hpp_file(std::string                                    resource_name,
                              std::vector<std::string>                      exports,
                              std::map<std::string, prepare_mapped_symbols> &involves,
                              std::vector<uint8_t> &                         shellcodebytes) {
    //打开输出文件
    std::ofstream outFile;
    outFile.open(resource_name + ".hpp", std::ios::out);

    //输出头部信息
    outFile << "#pragma once" << std::endl;
    outFile << "#include <cstdint>" << std::endl;
    outFile << "namespace shellcode\n{" << std::endl;

    outFile << "namespace rva\n{" << std::endl;
    for (auto &exp : exports) {




#ifdef _M_IX86 // 32位模式下 编译器会在函数前面加一个 _
        uint32_t maped_va = involves[exp].maped_va;
        if (exp.front() == '_') {
            exp.erase(exp.begin());
        }
        outFile << "const size_t " << exp << " = 0x" << std::hex << maped_va << ";\n";
#else
        outFile << "const size_t " << exp << " = 0x" << std::hex << involves[exp].maped_va << ";\n";
#endif // _M_IX86

        
    }
    outFile << "\n}\n" << std::endl;

    outFile << "const unsigned char " + resource_name + " [] = " << std::endl;
    outFile << "\t{" << std::endl << "\t";
    
    for (size_t idx = 0; idx < shellcodebytes.size(); idx++) {
        if (idx % 80 == 0)
            outFile << "\n"; 
        uint8_t code_byte = shellcodebytes[idx];
        outFile << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)code_byte << ",";
    }





    outFile << "\t};" << std::endl;

    outFile << "\n};\n" << std::endl;
    outFile.close();
}


int main() {

    // 未来会支持lib互相依赖，所以这里可能会载入多个lib
    std::vector<coff::lib> libs;

    std::vector<uint8_t> data;
    open_binary_file("shellcode-payload.lib", data);
    coff::lib payload(data.data(), data.size());

    libs.push_back(payload);

    // 所有涉及到的符号名
    std::map<std::string, prepare_mapped_symbols> involves;
    std::set<std::string> system_api;
    std::set<std::string> not_found;

    //打印所有的导出函数
    print_exports(libs);

    // 遍历 找出: 导出函数的依赖符号、系统api、 未定义的符号
    for (auto &lib : libs) {
        auto &objs = lib.objs();
        //遍历 obj 为导出函数寻找链接依赖项
        for (auto &obj : objs) {
            for (auto &exp : obj.exports()) {
                obj.for_each_symbols([&](IMAGE_SYMBOL &symbol) {
                    const char *symbol_name = obj.symbol_name(symbol);
                    if (symbol_name == exp) {
                        //involves.insert(symbol_name);
#ifdef ZH_CN
                        INF("为导出符号\"%s\"查找链接依赖", exp.c_str());
#else
                        INF("Find link dependency for export symbol:\"%s\"", exp.c_str());
#endif // ZH_CN
                        recursive_lookup_relocations(system_api, not_found, involves, libs, obj, symbol);
                    }
                });
            }
        }
    }


    
    if (!not_found.empty()) {
#ifdef ZH_CN
        ERO("存在无法找到的外部符号,链接停止");
#else
        INF("There is external symbols that cannot be found. The link is stopped");
#endif // ZH_CN
        std::system("pause");
        return 0;
    }


    // 计算所有有效符号的总大小，每个符号直接都会进行 4 字节对齐
    uint32_t shell_size = 0;
    for (auto &i : involves) {
        shell_size += i.second.bytes_size;
        shell_size += i.second.bytes_size % sizeof(uint32_t);
    }

    std::vector<uint8_t> shellcodebytes(static_cast<size_t>(shell_size), 0xcc );


    size_t   va     = 0;
    uint8_t *cursor = shellcodebytes.data();
    for (auto &symbol_info : involves) {
        memcpy(cursor, symbol_info.second.bytes, static_cast<size_t>(symbol_info.second.bytes_size));
        symbol_info.second.maped_va = va;
        symbol_info.second.maped_size =
            symbol_info.second.bytes_size + (symbol_info.second.bytes_size % sizeof(uint32_t));
        
        INF("符号\"%s\"分配在:\n\t\trva:0x%x/size:0x%x",
            symbol_info.first.c_str(),
            symbol_info.second.maped_va,
            symbol_info.second.maped_size);

        va += symbol_info.second.maped_size;
        cursor += symbol_info.second.maped_size; 
    }

    for (auto &symbol_info : involves) {
        for (auto &reloca : symbol_info.second.relocations) {
#ifdef _WIN64
            if (reloca.type == IMAGE_REL_AMD64_REL32) {
                *reinterpret_cast<int *>(static_cast<size_t>(reloca.va) + shellcodebytes.data() + symbol_info.second.maped_va) =
                    static_cast<int>(involves[reloca.sym_name].maped_va -
                                     (symbol_info.second.maped_va + reloca.va + sizeof(uint32_t))
                    );
            } else if (reloca.type == IMAGE_REL_AMD64_REL32_1) {
                *reinterpret_cast<int *>(static_cast<size_t>(reloca.va) + shellcodebytes.data() +
                                         symbol_info.second.maped_va) =
                    static_cast<int>(involves[reloca.sym_name].maped_va -
                                     (1 + symbol_info.second.maped_va + reloca.va + sizeof(uint32_t)));
            } else if (reloca.type == IMAGE_REL_AMD64_REL32_2) {
                *reinterpret_cast<int *>(static_cast<size_t>(reloca.va) + shellcodebytes.data() +
                                         symbol_info.second.maped_va) =
                    static_cast<int>(involves[reloca.sym_name].maped_va -
                                     (2 + symbol_info.second.maped_va + reloca.va + sizeof(uint32_t)));
            } else if (reloca.type == IMAGE_REL_AMD64_REL32_3) {
                *reinterpret_cast<int *>(static_cast<size_t>(reloca.va) + shellcodebytes.data() +
                                         symbol_info.second.maped_va) =
                    static_cast<int>(involves[reloca.sym_name].maped_va -
                                     (3 + symbol_info.second.maped_va + reloca.va + sizeof(uint32_t)));
            } else if (reloca.type == IMAGE_REL_AMD64_REL32_4) {
                *reinterpret_cast<int *>(static_cast<size_t>(reloca.va) + shellcodebytes.data() +
                                         symbol_info.second.maped_va) =
                    static_cast<int>(involves[reloca.sym_name].maped_va -
                                     (4 + symbol_info.second.maped_va + reloca.va + sizeof(uint32_t)));
            } else if (reloca.type == IMAGE_REL_AMD64_REL32_5) {
                *reinterpret_cast<int *>(static_cast<size_t>(reloca.va) + shellcodebytes.data() +
                                         symbol_info.second.maped_va) =
                    static_cast<int>(involves[reloca.sym_name].maped_va -
                                     (5 + symbol_info.second.maped_va + reloca.va + sizeof(uint32_t)));
            
            } 
#else
            if (reloca.type == IMAGE_REL_I386_REL32) {
                *reinterpret_cast<int *>(static_cast<size_t>(reloca.va) + shellcodebytes.data() +
                                         symbol_info.second.maped_va) =
                    static_cast<int>(involves[reloca.sym_name].maped_va -
                                     (symbol_info.second.maped_va + reloca.va + sizeof(uint32_t)));
            } 
#endif // _WIN64
            else {
#ifdef ZH_CN
                if (reloca.type == IMAGE_REL_I386_DIR32) {
                    ERO("当前尚未解决 IMAGE_REL_I386_DIR32 重定位问题");
                }
                ERO("存在无法处理的CPU重定位模式 [0x%x] 请查看 "
                    "pecoff(microsoft可移植可执行文件和通用目标文件格式文件规范).pdf: 5.2.1 类型指示符 "
                    "并修复此问题,链接停止",
                    reloca.type);
#else
                INF("There are CPU relocation modes that cannot be processed. The link is stopped");
#endif // ZH_CN
                std::system("pause");
                return 0;
            }
        }
    }

    buffer_to_file_bin(shellcodebytes.data(), shellcodebytes.size(), "shellcode-payload.bin");
    print_shellcode_hpp_file("payload", get_exports(libs), involves, shellcodebytes);
    
    INF("shellcode 生成成功");

    std::system("pause");

    return 0;
}


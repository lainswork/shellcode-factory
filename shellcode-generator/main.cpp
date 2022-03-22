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

#define ErroEnd(...) ERO(__VA_ARGS__); std::system("pause"); return-1; 


void open_binary_file(const std::string &file, std::vector<uint8_t> &data);
void buffer_to_file_bin(unsigned char *buffer, size_t buffer_size, const std::string &filename);
std::string &replace_all(std::string &str, const std::string &old_value, const std::string &new_value);

struct section_mapped_info {
    uint32_t maped_va;
    uint32_t maped_size;
};
void recursive_lookup_relocations(std::vector<coff::lib> &libs,
                                  std::tuple<PIMAGE_SYMBOL, coff::obj *>
                                                                                                 sym,
                                  std::map<std::string, std::tuple<PIMAGE_SYMBOL, coff::obj *>> &all_static_syms,
                                  std::map<std::string, PIMAGE_SYMBOL> &                         all_external_syms,
                                  std::map<PIMAGE_SECTION_HEADER, section_mapped_info> &         section_mapped,
                                  std::map<std::string, int> &                                   sym_mapped,
                                  std::vector<uint8_t> &                                         shellcodebytes);
void print_shellcode_hpp_file(std::string                                                    resource_name,
                              std::map<std::string, int> &                                   sym_mapped,
                              std::vector<uint8_t> &                                         shellcodebytes,
                              std::map<std::string, std::tuple<PIMAGE_SYMBOL, coff::obj *>> &export_syms);
int  main() {

    // 未来会支持lib互相依赖，所以这里可能会载入多个lib
    std::vector<coff::lib> libs;

    std::vector<uint8_t> data;
    open_binary_file("shellcode-payload.lib", data);
    coff::lib payload(data.data(), data.size());

    libs.push_back(payload);

    std::map<std::string, std::tuple<PIMAGE_SYMBOL,coff::obj*>> all_static_syms;
    std::map<std::string, PIMAGE_SYMBOL> all_external_syms;

    std::map<std::string,std::tuple<PIMAGE_SYMBOL, coff::obj *>> export_syms;
    for (auto &lib : libs) {
        for (auto& obj:lib.objs()) {
            for (auto &exp : obj.exports()) {
                INF("导出 %s",exp.c_str());
                obj.for_each_symbols([&](IMAGE_SYMBOL& Sym) {
                    if (exp == obj.symbol_name(Sym)) {
                        if (export_syms.find(exp) == export_syms.end()) {
                            export_syms.insert({exp, {&Sym, &obj}});
                        } else {
                            ERO("重复的导出符号:\"%s\"");
                        }
                    }

                    });
            }
        }
    }

    

    std::vector<uint8_t>                                 shellcodebytes;
    std::map<PIMAGE_SECTION_HEADER, section_mapped_info> section_mapped;
    std::map<std::string, int>                           sym_mapped;
    for (auto &exp : export_syms) {
        recursive_lookup_relocations(libs, exp.second, all_static_syms, all_external_syms, section_mapped, sym_mapped,
                                     shellcodebytes);
    }

    for (auto &i : sym_mapped)
        INF("[ 0x%06x ] %s",i.second,i.first.c_str());


    buffer_to_file_bin(shellcodebytes.data(), shellcodebytes.size(), "shellcode-payload.bin");
    print_shellcode_hpp_file("payload", sym_mapped, shellcodebytes, export_syms);
    
    INF("shellcode 生成成功");

    std::system("pause");

    return 0;
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
void buffer_to_file_bin(unsigned char *buffer, size_t buffer_size, const std::string &filename) {
    std::ofstream file(filename, std::ios_base::out | std::ios_base::binary);
    file.write((const char *)buffer, buffer_size);
    file.close();
}
void open_binary_file(const std::string &file, std::vector<uint8_t> &data) {
    std::ifstream fstr(file, std::ios::binary);
    fstr.unsetf(std::ios::skipws);
    fstr.seekg(0, std::ios::end);

    const auto file_size = fstr.tellg();

    fstr.seekg(NULL, std::ios::beg);
    data.reserve(static_cast<uint32_t>(file_size));
    data.insert(data.begin(), std::istream_iterator<uint8_t>(fstr), std::istream_iterator<uint8_t>());
}
void recursive_lookup_relocations(std::vector<coff::lib> &libs,
                                  std::tuple<PIMAGE_SYMBOL, coff::obj *>
                                                                                                 sym,
                                  std::map<std::string, std::tuple<PIMAGE_SYMBOL, coff::obj *>> &all_static_syms,
                                  std::map<std::string, PIMAGE_SYMBOL> &                         all_external_syms,
                                  std::map<PIMAGE_SECTION_HEADER, section_mapped_info> &         section_mapped,
                                  std::map<std::string, int> &                                   sym_mapped,
                                  std::vector<uint8_t> &                                         shellcodebytes) {

    const char *pSymName = std::get<coff::obj *>(sym)->symbol_name(*std::get<PIMAGE_SYMBOL>(sym));

    if (sym_mapped.find(pSymName) != sym_mapped.end()) {
        return;
    }

    if (std::get<PIMAGE_SYMBOL>(sym)->SectionNumber > IMAGE_SYM_UNDEFINED) {

        IMAGE_SECTION_HEADER &section =
            std::get<coff::obj *>(sym)
                ->sections()[static_cast<size_t>(std::get<PIMAGE_SYMBOL>(sym)->SectionNumber) - 1];

        all_static_syms.insert({pSymName, {std::get<PIMAGE_SYMBOL>(sym), std::get<coff::obj *>(sym)}});

        // STATIC 类型的一个节就是符号
        if (std::get<PIMAGE_SYMBOL>(sym)->Value == 0) {
            if (section_mapped.find(&section) == section_mapped.end()) {
                auto oldSize = shellcodebytes.size();
                shellcodebytes.resize(oldSize + section.SizeOfRawData, 0x00);
                sym_mapped[pSymName] = oldSize;
                memcpy(shellcodebytes.data() + oldSize,
                       static_cast<size_t>(section.PointerToRawData) + std::get<coff::obj *>(sym)->obj_data(),
                       section.SizeOfRawData);
                if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                    memset(shellcodebytes.data() + oldSize, 0x00, section.SizeOfRawData);
                }
                section_mapped_info smi{};
                smi.maped_va             = oldSize;
                smi.maped_size           = section.SizeOfRawData;
                section_mapped[&section] = smi;
                //INF("符号:\"%s\" Va:0x%x/Size:0x%x ", pSymName, oldSize, section.SizeOfRawData);
            }
            

           

            // 重定位
            for (auto &reloca : std::get<coff::obj *>(sym)->relocations(&section)) {

                // 重定位符号
                auto &      reloc_symbol = std::get<coff::obj *>(sym)->symbols()[reloca.SymbolTableIndex];
                std::string reloc_name   = std::get<coff::obj *>(sym)->symbol_name(reloc_symbol);

                recursive_lookup_relocations(libs, {&reloc_symbol, std::get<coff::obj *>(sym)}, all_static_syms,
                                             all_external_syms, section_mapped, sym_mapped, shellcodebytes);

                // INF("\t\t\t重定位符号:\"%s\" Va:0x%x", reloc_name.c_str(), sym_mapped[reloc_name]);
#ifdef _WIN64
                if (reloca.Type == IMAGE_REL_AMD64_REL32) {
                    *reinterpret_cast<int *>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                                             sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                                         (sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));
                } else if (reloca.Type == IMAGE_REL_AMD64_REL32_1) {
                    *reinterpret_cast<int *>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                                             sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                                         (1 + sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));
                } else if (reloca.Type == IMAGE_REL_AMD64_REL32_2) {
                    *reinterpret_cast<int *>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                                             sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                                         (2 + sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));
                } else if (reloca.Type == IMAGE_REL_AMD64_REL32_3) {
                    *reinterpret_cast<int *>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                                             sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                                         (3 + sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));
                } else if (reloca.Type == IMAGE_REL_AMD64_REL32_4) {
                    *reinterpret_cast<int *>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                                             sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                                         (4 + sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));
                } else if (reloca.Type == IMAGE_REL_AMD64_REL32_5) {
                    *reinterpret_cast<int *>(static_cast<size_t>(reloca.VirtualAddress) + shellcodebytes.data() +
                                             sym_mapped[pSymName]) =
                        static_cast<int>(sym_mapped[reloc_name] -
                                         (5 + sym_mapped[pSymName] + reloca.VirtualAddress + sizeof(uint32_t)));

                }
#else
                if (reloca.Type == IMAGE_REL_I386_REL32) {
                    *reinterpret_cast<int *>(static_cast<size_t>(reloca.va) + shellcodebytes.data() +
                                             symbol_info.second.maped_va) =
                        static_cast<int>(involves[reloca.sym_name].maped_va -
                                         (symbol_info.second.maped_va + reloca.va + sizeof(uint32_t)));
                }
#endif // _WIN64
                else {
#ifdef ZH_CN
                    if (reloca.Type == IMAGE_REL_I386_DIR32) {
                        ERO("当前尚未解决 IMAGE_REL_I386_DIR32 重定位问题");
                    }
                    ERO("存在无法处理的CPU重定位模式 [0x%x] 请查看 "
                        "pecoff(microsoft可移植可执行文件和通用目标文件格式文件规范).pdf: 5.2.1 类型指示符 "
                        "并修复此问题,链接停止",
                        reloca.Type);
#else
                    INF("There are CPU relocation modes that cannot be processed. The link is stopped");
#endif // ZH_CN
                }
            }
        } else {
            if (section_mapped.find(&section) != section_mapped.end()) {
                auto section_maped_va     = section_mapped[&section].maped_va;
                auto _sym_va          = std::get<PIMAGE_SYMBOL>(sym)->Value;
                sym_mapped[pSymName]      = section_maped_va + _sym_va;
                //IMP("静态数据\"%s\" Va:0x%x", pSymName, sym_mapped[pSymName]);
            } else {
                auto oldSize = shellcodebytes.size();
                shellcodebytes.resize(oldSize + section.SizeOfRawData, 0x00);
                
                memcpy(shellcodebytes.data() + oldSize,
                       static_cast<size_t>(section.PointerToRawData) + std::get<coff::obj *>(sym)->obj_data(),
                       section.SizeOfRawData);
                if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                    memset(shellcodebytes.data() + oldSize, 0x00, section.SizeOfRawData);
                }
                section_mapped_info smi{};
                smi.maped_va             = oldSize;
                smi.maped_size           = section.SizeOfRawData;
                section_mapped[&section] = smi;

                recursive_lookup_relocations(libs, {std::get<PIMAGE_SYMBOL>(sym), std::get<coff::obj *>(sym)},
                                             all_static_syms, all_external_syms, section_mapped, sym_mapped,
                                             shellcodebytes);
            }
        }

    } else {
        if (std::get<PIMAGE_SYMBOL>(sym)->StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
            std::get<PIMAGE_SYMBOL>(sym)->Value > 0) {
            if (sym_mapped.find(pSymName) == sym_mapped.end()) {
                auto oldSize = shellcodebytes.size();
                shellcodebytes.resize(oldSize + std::get<PIMAGE_SYMBOL>(sym)->Value, 0x00);
                sym_mapped[pSymName] = oldSize;
                IMP("External:\"%s\" Va:0x%x/Size:0x%x", pSymName, oldSize, std::get<PIMAGE_SYMBOL>(sym)->Value);
            }
        } else {

            //跨obj调用
            bool canResolve = false;
            for (auto &lib : libs) {
                for (auto &obj : lib.objs()) {
                    obj.for_each_symbols([&](IMAGE_SYMBOL &Sym) {
                        if (strcmp(pSymName, obj.symbol_name(Sym)) == 0) {
                            if (Sym.SectionNumber > IMAGE_SYM_UNDEFINED ||
                                (Sym.StorageClass == IMAGE_SYM_CLASS_EXTERNAL && Sym.Value > 0)) {
                                canResolve = true;
                                recursive_lookup_relocations(libs, {&Sym, &obj}, all_static_syms, all_external_syms,
                                                             section_mapped, sym_mapped, shellcodebytes);
                            }
                        }
                    });
                }
            }

            if (!canResolve) {
                ERO("无法解析的符号\"%s\" ", pSymName);
            }
        }
    }
}
#if 1
void print_shellcode_hpp_file(std::string                                                    resource_name,
                              std::map<std::string, int> &                                   sym_mapped,
                              std::vector<uint8_t> &                                         shellcodebytes,
                              std::map<std::string, std::tuple<PIMAGE_SYMBOL, coff::obj *>> &export_syms) {
    //打开输出文件
    std::ofstream outFile;
    outFile.open(resource_name + ".hpp", std::ios::out);

    //输出头部信息
    outFile << "#pragma once" << std::endl;
    outFile << "#include <cstdint>" << std::endl;
    outFile << "namespace shellcode\n{" << std::endl;

    outFile << "namespace rva\n{" << std::endl;


    for (auto& iter : export_syms) {
        INF("公开RVA %s",iter.first.c_str());
#ifdef _M_IX86 // 32位模式下 编译器会在函数前面加一个 _
        uint32_t maped_va = sym_mapped[iter.first];
        std::string exp      = iter.first;
        if (exp.front() == '_') {
            exp.erase(exp.begin());
        }
        outFile << "const size_t " << exp << " = 0x" << std::hex << maped_va << ";\n";
#else
        outFile << "const size_t " << iter.first << " = 0x" << std::hex << sym_mapped[iter.first] << ";\n";
#endif // _M_IX86
    }
    outFile << "\n}\n" << std::endl;

    outFile << "unsigned char " + resource_name + " [] = " << std::endl;
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
#endif
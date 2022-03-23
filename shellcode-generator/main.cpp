#include "coff.h"
#include "rang_impl.hpp"
#include "misc.hpp"

#include <fstream>
#include <functional>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <iomanip>
#include <exception>

#include <intrin.h>

struct section_mapped_info {
    uint32_t maped_va;
    uint32_t maped_size; // maped_size 好像用不到 先留着吧
};

void recursive_lookup_relocations(std::vector<coff::lib> &libs,
                                  std::tuple<PIMAGE_SYMBOL, coff::obj *>
                                                                                        sym,
                                  std::map<PIMAGE_SECTION_HEADER, section_mapped_info> &section_mapped,
                                  std::map<std::string, int> &                          sym_mapped,
                                  std::vector<uint8_t> &                                shellcodebytes);

void print_shellcode_hpp_file(std::string                                                    resource_name,
                              std::map<std::string, int> &                                   sym_mapped,
                              std::vector<uint8_t> &                                         shellcodebytes,
                              std::map<std::string, std::tuple<PIMAGE_SYMBOL, coff::obj *>> &export_syms);

constexpr char payload_lib_name[] = {"shellcode-payload.lib"};
constexpr char out_bin_name[]     = {"shellcode-payload.bin"};
constexpr char out_hpp_name[]     = {"payload"};
int  main() {

    try {
        // 未来会支持lib互相依赖，所以这里可能会载入多个lib
        std::vector<coff::lib> libs;
        // 读取的lib数据应保持其生命周期 因为coff.cpp中的所有方法都是使用的指针与引用
        std::vector<uint8_t> data;
        open_binary_file(payload_lib_name, data);
        coff::lib payload(data.data(), data.size());
        // todo: 框架当前不支持多个lib 但在未来应支持
        libs.push_back(payload);

        // 遍历获取所有obj中的导出符号
        std::map<std::string, std::tuple<PIMAGE_SYMBOL, coff::obj *>> export_syms;
        for (auto &lib : libs) {
            for (auto &obj : lib.objs()) {
                // obj.exports() 得到obj文件中的所有导出符号名称 ，接下来还需要借助名称寻找对应的 PIMAGE_SYMBOL
                for (auto &exp : obj.exports()) {
                    INF("find export %s", exp.c_str());
                    // for_each_symbols会跳过一些不必要的符号 .obj中很多符号并无实际意义
                    obj.for_each_symbols([&](IMAGE_SYMBOL &Sym) {
                        // 找到对应导出名称的符号 PIMAGE_SYMBOL
                        if (exp == obj.symbol_name(Sym)) {
                            if (export_syms.find(exp) == export_syms.end()) {
                                export_syms.insert({exp, {&Sym, &obj}});
                            } else {
                                throw std::exception("Duplicate export symbol:\"%s\"");
                            }
                        }
                    });
                }
            }
        }

        //从导出函数开始，顺着每个导出函数查找重定位以及重定位的重定位......
        std::vector<uint8_t>                                 shellcodebytes; //储存映射数据的内存
        std::map<PIMAGE_SECTION_HEADER, section_mapped_info> section_mapped; //所有被映射的节
        std::map<std::string, int>                           sym_mapped;     //所有被映射的符号
        for (auto &exp : export_syms) {
            recursive_lookup_relocations(libs, exp.second, section_mapped, sym_mapped, shellcodebytes);
        }

        //打印
        for (auto &i : sym_mapped)
            INF("[ 0x%06x ] for %s", i.second, i.first.c_str());

        //打印
        IMP("----------");
        for (auto &exp : export_syms)
            IMP("Export at [ 0x%06x ] for %s", sym_mapped[exp.first], exp.first.c_str());
        IMP("----------");

        //写出 bin
        buffer_to_file_bin(shellcodebytes.data(), shellcodebytes.size(), out_bin_name);
        //写出 hpp
        print_shellcode_hpp_file(out_hpp_name, sym_mapped, shellcodebytes, export_syms);

        SUC("shellcode generator success!");

    } catch (const std::exception & ex) {
        ERO(ex.what());
    }
    

    std::system("pause");
    return 0;
}


void recursive_lookup_relocations(std::vector<coff::lib> &libs,
                                  std::tuple<PIMAGE_SYMBOL, coff::obj *>
                                                                                                 sym,
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

                recursive_lookup_relocations(libs, {&reloc_symbol, std::get<coff::obj *>(sym)}, section_mapped, sym_mapped, shellcodebytes);

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
                    if (reloca.Type == IMAGE_REL_I386_DIR32) {
                        throw std::exception("Relocation Type IMAGE_REL_I386_DIR32 !");
                    }
                    throw std::exception("There is a CPU relocation mode that cannot be processed , Link stop!");
                }
            }
        } else {
            if (section_mapped.find(&section) != section_mapped.end()) {
                auto section_maped_va = section_mapped[&section].maped_va;
                auto _sym_va          = std::get<PIMAGE_SYMBOL>(sym)->Value;
                sym_mapped[pSymName]  = section_maped_va + _sym_va;
                // IMP("静态数据\"%s\" Va:0x%x", pSymName, sym_mapped[pSymName]);
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
                                             section_mapped, sym_mapped, shellcodebytes);
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
                                recursive_lookup_relocations(libs, {&Sym, &obj},section_mapped, sym_mapped, shellcodebytes);
                            }
                        }
                    });
                }
            }

            if (!canResolve) {
                ERO("Unresolved symbols \"%s\" ", pSymName);
                throw std::exception("Unresolved symbols");
            }
        }
    }
}

void print_shellcode_hpp_file(std::string                                                    resource_name,
                              std::map<std::string, int> &                                   sym_mapped,
                              std::vector<uint8_t> &                                         shellcodebytes,
                              std::map<std::string, std::tuple<PIMAGE_SYMBOL, coff::obj *>> &export_syms) {
    //打开输出文件
    std::ofstream outFile;
    outFile.open(resource_name + ".hpp", std::ios::out);

    if (outFile.is_open()) {
        //输出头部信息
        outFile << "#pragma once" << std::endl;
        outFile << "#include <cstdint>" << std::endl;
        outFile << "namespace shellcode\n{" << std::endl;

        outFile << "namespace rva\n{" << std::endl;

        for (auto &iter : export_syms) {
#ifdef _M_IX86 // 32位模式下 编译器会在函数前面加一个 _
            uint32_t    maped_va = sym_mapped[iter.first];
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
    } else {
        throw std::exception("Cannot open hpp file!");
    }

   
}
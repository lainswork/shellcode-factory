#pragma once
#include <fstream>
#include <cstdint>
#include <string>
#include <vector>
inline std::string &replace_all(std::string &str, const std::string &old_value, const std::string &new_value) {
    while (true) {
        std::string::size_type pos(0);
        if ((pos = str.find(old_value)) != std::string::npos)
            str.replace(pos, old_value.length(), new_value);
        else
            break;
    }
    return str;
}
inline void buffer_to_file_bin(unsigned char *buffer, size_t buffer_size, const std::string &filename) {
    std::ofstream file(filename, std::ios_base::out | std::ios_base::binary);
    file.write((const char *)buffer, buffer_size);
    file.close();
}
inline void open_binary_file(const std::string &file, std::vector<uint8_t> &data) {
    std::ifstream fstr(file, std::ios::binary);
    fstr.unsetf(std::ios::skipws);
    fstr.seekg(0, std::ios::end);

    const auto file_size = fstr.tellg();

    fstr.seekg(NULL, std::ios::beg);
    data.reserve(static_cast<uint32_t>(file_size));
    data.insert(data.begin(), std::istream_iterator<uint8_t>(fstr), std::istream_iterator<uint8_t>());
}
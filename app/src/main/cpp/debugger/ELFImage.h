#pragma once

#include <map>
#include <string>
#include <elf++.hh>
#include <debugger/taint/AnnotatedAddressSpace.h>

class ELFImage {
private:
    elf::elf elf_;
    const std::string path_;
public:
    ELFImage(std::string path);
    const std::string& get_path();
    /**
     * Get the region of bytes that contain the data for the specified symbol
     * @param symbol_name Symbol name
     * @return Data range relative to the start of the ELF image on disk
     */
    MemoryRegion get_symbol_region(const std::string& symbol_name) const;
    std::optional<std::string> get_enclosing_symbol(off_t file_offset, bool demangle = true);
    const unsigned char *mapped_image_base();
    void print_symbols();
};

/**
 * Store ELF images used to set breakpoints at symbols within an image,
 * or when printing stack traces with function names
 */
class CachedELFImageLoader {
private:
    inline static std::map<std::string, ELFImage> images_;
public:
    static ELFImage& get_image(const std::string& path);
};

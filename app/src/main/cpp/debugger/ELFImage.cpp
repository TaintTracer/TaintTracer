#include <fcntl.h>
#include "ELFImage.h"
#include <fmt/format.h>
#include <inttypes.h>
#include <android/logging.h>
#include <cxxabi.h>

ELFImage &CachedELFImageLoader::get_image(const std::string &path) {
    auto it = images_.find(path);
    if (it == images_.end()) {
        it = images_.emplace_hint(it, path, path);
    }
    return it->second;
}

ELFImage::ELFImage(std::string path) : path_(std::move(path)) {
    int fd = open(path_.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        throw std::runtime_error(fmt::format("Failed to open file descriptor to image {}", path));
    }

    elf_ = elf::elf(elf::create_mmap_loader(fd));
}

const std::string &ELFImage::get_path() {
    return path_;
}

MemoryRegion ELFImage::get_symbol_region(const std::string &symbol_name) const {
    std::vector<MemoryRegion> matches{};
    matches.reserve(1);

    for (auto &sec : elf_.sections()) {
        if (sec.get_hdr().type != elf::sht::symtab &&
            sec.get_hdr().type != elf::sht::dynsym)
            continue;
        for (auto sym : sec.as_symtab()) {
            if (sym.get_name() == symbol_name) {
                auto &d = sym.get_data();
                matches.emplace_back(MemoryRegion::from_start_and_size(d.value, d.size));
            }
        }
    }

    if (matches.size() == 0) {
        throw std::runtime_error("Failed to get symbol with name " + symbol_name);
    }
    auto it = matches.begin();
    auto res = *it;
    // Ignore duplicate entries
    for(it++; it != matches.end(); it++) {
        if (*it != res) {
            std::string err = fmt::format("Found {} matching regions for symbol {}. Expected 1 unique match. Matching regions:", matches.size(), symbol_name);
            for (auto r : matches) {
                err += (" " + r.str());
            }
            throw std::runtime_error(err);
        }
    }
    return res;
}

const unsigned char *ELFImage::mapped_image_base() {
    // HACK: We assume that the loader mapped the entire image via mmap()
    return (const unsigned char *) elf_.get_loader()->load(0, 0);
}

void ELFImage::print_symbols() {
    /* Taken from examples/dump-syms.cc */
    for (auto &sec : elf_.sections()) {
        if (sec.get_hdr().type != elf::sht::symtab &&
            sec.get_hdr().type != elf::sht::dynsym)
            continue;

        LOGD("Symbol table '%s':\n", sec.get_name().c_str());
        LOGD("%6s: %-16s %-5s %-7s %-7s %-5s %s\n",
             "Num", "Value", "Size", "Type", "Binding", "Index",
             "Name");
        int i = 0;
        for (auto sym : sec.as_symtab()) {
            auto &d = sym.get_data();
            LOGD("%6d: %016" PRIx64 " %5" PRId64 " %-7s %-7s %5s %s\n",
                 i++, d.value, d.size,
                 to_string(d.type()).c_str(),
                 to_string(d.binding()).c_str(),
                 to_string(d.shnxd).c_str(),
                 sym.get_name().c_str());
        }
    }
}

std::optional<std::string> ELFImage::get_enclosing_symbol(off_t file_offset, bool demangle) {
    // TODO: Make this more efficient by traversing the entire symbol table and storing
    //       (offset, (symname, size)) entries in a map
    for (auto &sec : elf_.sections()) {
        if (sec.get_hdr().type != elf::sht::symtab &&
            sec.get_hdr().type != elf::sht::dynsym)
            continue;

        for (auto sym : sec.as_symtab()) {
            auto &d = sym.get_data();
            if (d.value <= file_offset && file_offset < d.value + d.size) {
                if (!demangle)
                    return sym.get_name();
                int status;
                auto sym_name = sym.get_name();
                auto *demangled = abi::__cxa_demangle(sym_name.c_str(), 0, 0, &status);
                if (status) {
                    /*
                    switch (status) {
                        case -1:
                            LOGV("Demangle unsuccessful: A memory allocation failiure occurred");
                            break;
                        case -2:
                            LOGV("Demangle unsuccessful: Not a valid name under the C++ ABI mangling rules");
                            break;
                        case -3:
                            LOGV("Demangle unsuccessful: One of the arguments is invalid");
                            break;
                        default:
                            LOGV("Demangle unsuccessful: Unknown reason");
                    }
                    */
                    return sym_name;
                }
                auto res = std::string(demangled);
                free(demangled);
                return res;
            }
        }
    }
    return std::nullopt;
}

#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sstream>
#include <android/logging.h>
#include "ProcessMapsEntry.h"

ProcessMapsEntry::ProcessMapsEntry(const std::string& proc_maps_line)
    : prot(PROT_NONE)
    , flags(0)
    , offset(0)
    , device(0)
    , inode(0) {
//    LOGD("Processing string %s", proc_maps_line.c_str());
    std::istringstream ss(proc_maps_line);
    std::string buf;

    if(!getline(ss, buf, '-')) {
        throw std::runtime_error("Failed to read start address");
    }
//    LOGD("start: %s", buf.c_str());
    addr_start = (uint64_t)strtoull(buf.c_str(), nullptr, 16);

    if(!(ss >> buf)) {
        throw std::runtime_error("Failed to read end address");
    }
//    LOGD("end: %s", buf.c_str());
    addr_end = (uint64_t)strtoull(buf.c_str(), nullptr, 16);

    if(!(ss >> buf) || buf.length() != 4) {
        throw std::runtime_error("Failed to read map permissions and flags");
    }
//    LOGD("flags: %s", buf.c_str());

    for (char& c : buf) {
        switch (c) {
            case 'r':
                prot |= PROT_READ;
                break;
            case 'w':
                prot |= PROT_WRITE;
                break;
            case 'x':
                prot |= PROT_EXEC;
                break;
            case 's':
                flags |= MAP_SHARED;
                break;
            case 'p':
                flags |= MAP_PRIVATE;
                break;
            case '-':
                // Unset permission, ignore
                break;
            default:
                throw std::runtime_error("Unexpected character in permissions and flags: " + buf);
        }
    }

    if(!(ss >> buf)) {
        throw std::runtime_error("Failed to read file offset");
    }
//    LOGD("file offset: %s", buf.c_str());
    offset = strtoll(buf.c_str(), nullptr, 16);

    dev_t major_id;
    dev_t minor_id;
    if(!getline(ss, buf, ':')) {
        throw std::runtime_error("Failed to read major device id");
    }
//    LOGD("major: %s", buf.c_str());
    major_id = strtoull(buf.c_str(), nullptr, 16);
    if(!(ss >> buf)) {
        throw std::runtime_error("Failed to read minor device id");
    }
//    LOGD("minor: %s", buf.c_str());
    minor_id = strtoull(buf.c_str(), nullptr, 16);
    device = makedev(major_id, minor_id);

    if(!(ss >> buf)) {
        throw std::runtime_error("Failed to read inode");
    }
//    LOGD("inode: %s", buf.c_str());
    inode = strtoul(buf.c_str(), nullptr, 10);

    ss >> std::ws;
    if(!getline(ss, path)) {
//        LOGD("File path is empty");
    } else {
//        LOGD("File path: %s||", path.c_str());
    }

    is_file = path.rfind('/', 0) == 0;
}

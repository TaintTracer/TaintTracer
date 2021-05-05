#pragma once

#include <string>

struct ProcessMapsEntry {
    ProcessMapsEntry(const std::string &proc_maps_line);

    uint64_t addr_start;
    uint64_t addr_end;

    int prot;           ///< Memory protections of the mapping (rwx)
    int flags;          ///< Whether updates to the mapping are visible to other processes mapping the same region

    off_t offset;       ///< Offset in a memory-mapped file, 0 if no file is mapped
    dev_t device;       ///< Device id of memory-mapped file, or 00:00 if no file is mapped
    ino_t inode;        ///< Inode of memory-mapped file, or 0 if no file is mapped
    std::string path;   ///< Path of memory-mapped file or named mapping if no file is mapped

    bool is_file;        ///< If a file has been mapped
};
#pragma once

#include "ProcessMapsEntry.h"
#include <map>
#include <optional>

class ProcessMapState {
private:
    std::map<uint64_t, ProcessMapsEntry> maps_;
public:
    ProcessMapState(pid_t pid);
    /**
     * Find a memory map entry that maps a given address
     */
    std::optional<ProcessMapsEntry> find_map(uint64_t addr);
};

#include <fstream>
#include "ProcessMapState.h"

ProcessMapState::ProcessMapState(pid_t pid) {
    std::ifstream maps_file("/proc/" + std::to_string(pid) + "/maps");
    std::string map_line;
    while(getline(maps_file, map_line)) {
        auto entry = ProcessMapsEntry(map_line);
        maps_.try_emplace((uint64_t)entry.addr_start, std::move(entry));
    }
}

std::optional<ProcessMapsEntry> ProcessMapState::find_map(uint64_t addr) {
    auto map_entry = std::optional<std::reference_wrapper<ProcessMapsEntry>> {};
    if (auto it = maps_.upper_bound(addr); it != maps_.begin()) {
        it--;
        auto &e = it->second;
        if ((uint64_t) e.addr_start <= addr && addr < (uint64_t) e.addr_end) {
            map_entry = e;
        }
    }
    return map_entry;
}

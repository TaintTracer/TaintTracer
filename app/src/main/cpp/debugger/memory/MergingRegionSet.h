#pragma once

#include <cstdint>
#include <map>
#include "MemoryRegion.h"

/**
 * Set of ranges that merges overlapping and neighboring ranges on insert
 */
class MergingRegionSet {
private:
    std::map<uint64_t, uint64_t> regions_;

public:
    void insert(MemoryRegion r);

    std::vector<MemoryRegion> get_all();
};

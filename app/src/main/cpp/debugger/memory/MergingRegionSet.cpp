#include "MergingRegionSet.h"


void MergingRegionSet::insert(MemoryRegion r) {
    assert(r.start_address < r.end_address);
    auto next = regions_.upper_bound(r.start_address);
    auto inserted_it = decltype(regions_)::iterator {};

    if (next == regions_.begin() || std::prev(next)->second < r.start_address) {
        // There is no interval on the left of r that intersects r
        inserted_it = regions_.emplace_hint(next, r.start_address, r.end_address);
    } else {
        inserted_it = std::prev(next);
        if (r.end_address <= inserted_it->second) {
            // r is enclosed by an existing interval
            return;
        } else {
            // Extend the interval that partially intersects r from the left
            inserted_it->second = r.end_address;
        }
    }

    // Merge remaining overlaps
    while (next != regions_.end() && next->first <= r.end_address) {
        if (next->second > inserted_it->second) {
            inserted_it->second = next->second;
        }
        next = regions_.erase(next);
    }
}

std::vector<MemoryRegion> MergingRegionSet::get_all() {
    auto res = std::vector<MemoryRegion> {};
    for (const auto r : regions_) {
        res.emplace_back(MemoryRegion(r.first, r.second));
    }
    return res;
}

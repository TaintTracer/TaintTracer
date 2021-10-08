#include "MemoryRegion.h"
#include "MergingRegionSet.h"
#include <fmt/format.h>

MemoryRegion::MemoryRegion(uint64_t start_address, uint64_t end_address) : start_address(start_address),
                                                                           end_address(end_address) {
    if (start_address > end_address) {
        throw std::runtime_error("Tried to construct memory map with invalid range " + str());
    }
}

std::string MemoryRegion::str() const {
    return fmt::format("{:#x}-{:#x}", start_address, end_address);
}

std::optional<MemoryRegion> intersects(const MemoryRegion &left, const MemoryRegion &right) {
    auto single_end_intersection = [](const MemoryRegion& l, const MemoryRegion& r) -> std::optional<MemoryRegion>{
        if (l.start_address <= r.start_address && r.start_address < l.end_address) {
            return MemoryRegion(r.start_address, std::min(l.end_address, r.end_address));
        }
        return {};
    };
    if (auto i = single_end_intersection(left, right)) {
        return i;
    } else if (auto i = single_end_intersection(right, left)) {
        return i;
    }
    return {};
}

MemoryRegion merge_consecutive_regions(std::vector<MemoryRegion> regions) {
    if (regions.empty()) {
        throw std::runtime_error("Merging 0 intervals is not defined");
    }
    // Check if regions make up res
    std::sort(regions.begin(), regions.end(), [](const MemoryRegion& lhs, const MemoryRegion& rhs) {
        return lhs.start_address < rhs.start_address; });
    uint64_t min = regions.front().start_address;
    uint64_t max = regions.back().end_address;
    auto it = regions.begin();
    uint64_t prev_end = it->end_address;
    for (++it; it != regions.end(); it++) {
        if (prev_end != it->start_address) {
            throw std::runtime_error("Provided intervals are not consecutive");
        }
        prev_end = it->end_address;
    }
    return MemoryRegion(min, max);
}

std::vector<MemoryRegion> merge_regions(const std::vector<MemoryRegion> &regions) {
    MergingRegionSet s;
    for (const auto &r : regions) {
        s.insert(r);
    }
    return s.get_all();
}

bool MemoryRegion::contains(MemoryRegion other) const {
    return start_address <= other.start_address && other.end_address <= end_address;
}

bool MemoryRegion::operator<(const MemoryRegion &rhs) const {
    return start_address < rhs.start_address;
}

bool MemoryRegion::operator<(uint64_t rhs) const {
    return start_address < rhs;
}

bool MemoryRegion::operator==(const MemoryRegion &rhs) const {
    return start_address == rhs.start_address &&
           end_address == rhs.end_address;
}

bool MemoryRegion::operator!=(const MemoryRegion &rhs) const {
    return !(rhs == *this);
}

MemoryRegion MemoryRegion::from_start_and_size(uint64_t start, uint64_t size) {
    return MemoryRegion(start, start+size);
}

MemoryRegion MemoryRegion::from_start_and_size_signed(signed int start, signed int size) {
    if (start < 0) {
        throw std::runtime_error("Negative start address");
    }
    if (size < 0) {
        throw std::runtime_error("Negative size");
    }
    return from_start_and_size(static_cast<uint64_t>(start), static_cast<uint64_t>(size));
}

MemoryRegion MemoryRegion::domain() {
    return MemoryRegion(
            std::numeric_limits<uint64_t >::min(),
            std::numeric_limits<uint64_t >::max()
    );
}

MemoryRegion MemoryRegion::page_aligned() const {
    if (start_address == end_address) {
        throw std::runtime_error("Tried to get page_aligned region of memory of an empty region");
    }
    auto start = start_address - (start_address % PAGE_SIZE);
    auto end = end_address % PAGE_SIZE == 0 ? end_address : end_address + (PAGE_SIZE - (end_address % PAGE_SIZE));
    return {start, end};
}

std::optional<MemoryRegion> MemoryRegion::intersecting_pages() {
    auto start =  start_address % PAGE_SIZE == 0 ? start_address : start_address + (PAGE_SIZE - (start_address % PAGE_SIZE));
    auto end = end_address - (end_address % PAGE_SIZE);
    return start < end ? std::optional<MemoryRegion>(MemoryRegion {start, end}): std::nullopt;
}

MemoryRegion MemoryRegion::add_offset(uint64_t offset) const {
    return {start_address + offset, end_address + offset};
}

bool MemoryRegion::contains(uint64_t address) const {
    return start_address <= address && address < end_address;
}

std::vector<MemoryRegion>
split_regions(const std::vector<MemoryRegion> &regions, uint64_t max_size) {
    auto res = std::vector<MemoryRegion> {};
    for (auto r : regions) {
        while (r.size() > max_size) {
            auto slice = MemoryRegion::from_start_and_size(r.start_address, max_size);
            r.start_address = slice.end_address;
            res.push_back(slice);
        }
        assert(r.start_address < r.end_address);
        res.push_back(r);
    }
    return res;
}

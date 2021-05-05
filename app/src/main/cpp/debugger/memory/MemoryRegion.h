#pragma once

#include <cstdint>
#include <string>
#include <optional>
#include <vector>

struct MemoryRegion {
    uint64_t start_address; ///< Starting address of the memory region
    uint64_t end_address;   ///< Ending address of the memory region (exclusive)

    MemoryRegion(uint64_t start_address, uint64_t end_address);

    inline uint64_t size() const {
        return end_address - start_address;
    }

    bool operator==(const MemoryRegion &rhs) const;

    bool operator!=(const MemoryRegion &rhs) const;

    bool operator<(const MemoryRegion &rhs) const;

    bool operator<(uint64_t rhs) const;

    static MemoryRegion from_start_and_size(uint64_t start, uint64_t size);

    /* Convenience function that accepts a common type used by VEX */
    static MemoryRegion from_start_and_size_signed(signed int start, signed int size);

    /**
     * Get a region that spans the entire address space
     */
    static MemoryRegion domain();

    /**
     * Return the smallest page-aligned region of memory that contains the specified region
     */
    MemoryRegion page_aligned() const;

    /**
     * Return the largest page-aligned region of memory that is contained within the specified region
     */
    std::optional<MemoryRegion> intersecting_pages();

    MemoryRegion add_offset(uint64_t offset) const;

    /**
     * Whether an address lies within this address range
     */
    bool contains(uint64_t address) const;

    bool contains(MemoryRegion other) const;

    std::string str() const;
};


/**
 * Intersect two memory regions.
 * @return The intersection of the two regions. Returns std::nullopt if the regions do not intersect.
 */
std::optional<MemoryRegion> intersects(const MemoryRegion& left, const MemoryRegion& right);

MemoryRegion merge_consecutive_regions(std::vector<MemoryRegion> regions);

/**
 * Merge overlapping and neighboring regions
 */
std::vector<MemoryRegion> merge_regions(const std::vector<MemoryRegion> &regions);

/**
 * Returns list of regions that covers the same range but where each element has a bounded size
 * @param regions Non-overlapping regions
 * @param max_size Maximum size of each region
 */
std::vector<MemoryRegion> split_regions(const std::vector<MemoryRegion> &regions, uint64_t max_size);
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <optional>
#include <debugger/taint/AnnotatedAddressSpace.h>

struct PhysicalMemory;
class VirtualAddressSpace;

/**
 * A region of memory that has been mapped to an address space
 */
struct MemoryMap {
    /**
     * Construct a memory map with new physical memory that has not yet been shared with another
     * address space.
     * @param vspace Virtual address space that owns this mapping
     * @param vm_start First virtual address inside the region.
     * @param vm_end First virtual address outside the region.
     * @param is_shared Whether or not thi is a shared mapping.
     * @param Memory protection flags.
     */
    MemoryMap(VirtualAddressSpace *vspace, uint64_t vm_start, uint64_t vm_end, bool is_shared, int prot);

    /**
     * Construct a memory map from existing physical memory with a specified offset.
     * Example use-case: splitting a memory region with munmap() within 1 memory region
     * will result in a new memory map construction with the same original physical memory.
     * @param vspace Virtual address space that owns this mapping
     * @param vm_start First virtual address inside the region.
     * @param vm_end First virtual address outside the region.
     * @param is_shared Whether or not this is a shared mapping
     * @param prot Memory protection flags.
     * @param phy Physical memory.
     * @param phy_offset Offset into physical memory.
     */
    MemoryMap(VirtualAddressSpace *vspace, uint64_t vm_start, uint64_t vm_end,
              bool is_shared, int prot, std::shared_ptr<PhysicalMemory> phy, uint64_t phy_offset);
    /**
     * Construct a copy of the memory map for a particular address space.
     * If the page is private, a deep copy of the underlying physical memory is performed.
     * If the page is shared, the copy will share the same physical memory as the current object.
     * @param vspace
     * @param other
     */
    MemoryMap(VirtualAddressSpace *vspace, const MemoryMap& other);
    ~MemoryMap();

    MemoryMap(const MemoryMap&) = delete;
    MemoryMap& operator=(const MemoryMap&) = delete;
    MemoryMap(MemoryMap &&) = delete;

    PhysicalMemory& get_physical_memory();

    /**
     * Set protection flag of the single memory map
     * @param prot Protection flag to set as provided to mmap() or mprotect()
     */
    void set_protection_flag(int prot);

    /**
     * Translate physical memory region to the corresponding region in virtual address space
     * @param phy_region Physical memory region
     * @return Virtual memory region that maps to the provided address range in physical memory
     */
    MemoryRegion phy_to_virtual(MemoryRegion phy_region) const;
    MemoryRegion virtual_to_phy(MemoryRegion v_region) const;

    VirtualAddressSpace *vspace_;    ///< Virtual address space that owns this mapping.
    uint64_t vm_start_;    ///< First virtual address inside the region.
    uint64_t vm_end_;    ///< First virtual address outside the region.
    bool is_shared_;    /**< Whether updates to the mapping are visible to other processes
                             mapping the same region. */
    int prot_;          /**< Memory protection of the mapping, used to restore original protection
                             flags when triggering a memory breakpoint */

    std::shared_ptr<PhysicalMemory> phy_;    /**< Region of memory that acts as the physical memory
                                                  for this memory map. */
    uint64_t phy_offset_;    /**< Offset into physical memory.
                                  This field can be non-zero for anonymous mappings as a result
                                  of splitting a memory map. */
    std::optional<std::string> file_path; ///< Path to mapped file
};

#pragma once

struct PhysicalMemory;
class InstructionBreakpoint;
#include <vector>
#include <debugger/breakpoint/InstructionBreakpoint.h>
#include <debugger/taint/AnnotatedAddressSpace.h>
#include <debugger/taint/TaintEvent.h>
#include <list>

class Process;
struct MemoryMap;

struct PhysicalMemory {
    /**
     * Create an empty physical memory region
     * @param map Memory map that maps to this region
     */
    PhysicalMemory(MemoryMap *map);

    /**
     * Create a deep copy of a physical memory region
     * @param map Memory map that maps to the new region
     * @param other Region to copy
     */
    PhysicalMemory(MemoryMap *map, const PhysicalMemory& other);
    PhysicalMemory(const PhysicalMemory&) = delete;
    PhysicalMemory& operator=(const PhysicalMemory&) = delete;

    void add_map(MemoryMap *map);
    void remove_map(MemoryMap *map);

    /**
     * Get all memory maps of all virtual address spaces that map to a memory location of this
     * physical memory region.
     * @param phy_region Physical memory range to query
     * @param prefer_stopped Prefer to return process ids of processes that are currently stopped
     * @return A pair for every matching memory map of potentially different virtual address spaces.
     * The first element of each pair corresponds to an arbitrary process that is a member of the
     * address space. The second element is the virtual address in the address space of that process.
     */
    std::list<std::pair<Process&, MemoryRegion>> get_all_vaddrs(MemoryRegion phy_region, bool prefer_stopped = true);

    /**
     * Get all processes that can access at least 1 page of the specified range of physical memory
     * @param phy_region Physical memory range
     * @return List of Processes
     */
    std::vector<std::reference_wrapper<Process>> get_all_processes (MemoryRegion phy_region);

    /**
     * Insert a memory breakpoint at the specified memory range for all virtual address spaces
     * that contain a mapping to this region. Any process that accesses the memory region will raise
     * a SIGSEGV signal.
     * @param taint Taint info to associate with the memory region
     * @param phy_region Physical memory range to taint
     */
    void set_memory_taint_breakpoint(std::optional<TaintEvent> taint, MemoryRegion phy_region);

    /**
     * Memory maps using this object as physical memory.
     * When a process and its associated mappings are destroyed,
     * the associated pointer will be deleted.
     */
    std::vector<MemoryMap *> maps_;
    AnnotatedAddressSpace<TaintEvent> memory_taints_;
    AnnotatedAddressSpace<InstructionBreakpoint> ins_breakpoints_;
};

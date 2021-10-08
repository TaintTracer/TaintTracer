#pragma once

#include <vector>
#include <debugger/taint/TaintEvent.h>
#include <list>
#include "MemoryMap.h"
class VirtualAddressSpace;
class Process;

enum class BreakpointImpl {
    MMU,
    WATCHPOINT
};

enum class BreakpointImplPreference {
    MMU_ONLY,
    PREFER_WATCHPOINT,
    WATCHPOINT_ONLY
};

/**
 * Virtual memory address space of a process, which is potentially shared by multiple processes.
 * Calling clone() with the CLONE_VM flag will cause the cloned process to share the same
 * address space.
 * On Linux, all page tables and `struct mm_struct` of the process will be shared if CLONE_VM is set.
 */
class VirtualAddressSpace {
public:
    /**
     * Manages memory breakpoints according to the requested implementation preferences.
     * Memory breakpoints can be transferred from the MMU-based implementation to CPU watchpoints
     * and vice-versa.
     */
    class MemoryBreakpointManager {
    private:
        VirtualAddressSpace& parent_;

#if 0
        struct BreakpointEntry {
            BreakpointImpl impl;    ///< Breakpoint implementation type
            size_t watchpoint_id;   ///< Watchpoint number of CPU when applicable
        };

        /**
         * Bitset indicating whether a watchpoint is actively being used by us.
         */
        std::vector<bool> enabled_watchpoints_;

        /**
         * All memory breakpoints that have been set. Each entry might span a larger region than
         * the requested region as added by @ref set_memory_breakpoint depending on the chosen
         * implementation type (e.g. MMU-based memory breakpoints have a granularity of PAGE_SIZE.
         */
        AnnotatedAddressSpace<void> existing_mmu_bps_;
        /// \copydoc VirtualAddressSpace::MemoryBreakpointManager::existing_mmu_bps_
        AnnotatedAddressSpace<void> existing_hw_bps_;
#endif

        struct watchpoint_config {
            uint64_t address;   ///< Address stored in watchpoint register DBGWVRn_EL1
            uint32_t control;   ///< Control stored in watchpoint register DBGWCRn_EL1
            MemoryRegion trap_region;    ///< Virtual memory region that is covered by the watchpoint

            bool operator==(const watchpoint_config &rhs) const;

            bool operator!=(const watchpoint_config &rhs) const;
        };

        /**
         * Reference-counted memory breakpoint implementation override
         */
        struct impl_override_rc {
            int rc;
            BreakpointImplPreference preference;
        };

        std::vector<MemoryRegion> active_mmu_plan_;
        std::vector<VirtualAddressSpace::MemoryBreakpointManager::watchpoint_config> active_watchpoint_config_;

        /**
         * Override implementation preferences of demand_
         */
        AnnotatedAddressSpace<impl_override_rc> preference_override_;
        AnnotatedAddressSpace<BreakpointImplPreference> demand_;

        /**
         * Number of watchpoints supported by the CPU.
         * Set by debugger after attaching to at least 1 process.
         */
        static std::optional<size_t> watchpoint_count_;

        static watchpoint_config get_watchpoint_config(MemoryRegion region);

        /**
         * Enable memory breakpoints with the requested implementation method as defined by
         * @ref demand_
         */
        void commit(bool ignore_mmu_update = false);

    public:
        using breakpoint_collection = std::vector<AnnotatedMemoryRegion<BreakpointImplPreference>>;

        MemoryBreakpointManager(VirtualAddressSpace& parent);

        MemoryBreakpointManager(const MemoryBreakpointManager& other) = default;
        /**
         * Get the number of watchpoints supported by the CPU.
         */
        static size_t get_watchpoint_count();

        /**
         * Whether the watchpoint count has already been determined.
         */
        static bool watchpoint_count_determined();

        /**
         * Set the watchpoint count using ptrace()
         * @param pid Process ID of any stopped process
         */
        static void set_watchpoint_count(pid_t pid);

        /**
         * Create or change priority of a collection of memory breakpoints
         */
        void set_memory_breakpoint(breakpoint_collection &breakpoints);

        /**
         * Create or change priority of a memory breakpoint.
         * @param vm_region Virtual memory region of the memory breakpoint
         * @param impl_preference Implementation type requirements for the given memory region
         */
        void set_memory_breakpoint(MemoryRegion vm_region, BreakpointImplPreference impl_preference = BreakpointImplPreference::MMU_ONLY);

        /**
         * Change the implementation type of enabled breakpoints.
         * @param vm_regions Virtual address regions containing memory breakpoints of which to alter
         *                   the preferred implementation type of
         * @param impl Implementation type to change each matched breakpoint to
         * @param Changed memory breakpoints
         */
        breakpoint_collection
        update_memory_breakpoint_impl(std::vector<MemoryRegion> &vm_regions, BreakpointImplPreference impl);

        /**
         * Set the desired implementation type for breakpoints set within some virtual address range
         * with reference counting. Overriding the same region twice and removing the override a
         * single time will not cause the override to be destroyed.
         * @param vm_regions Virtual address range to override breakpoint implementations of
         * @param impl Implementation type to override. If std::nullopt is provided, the override is
         *             removed.
         */
        void override_impl_rc(std::vector<MemoryRegion> &vm_regions, std::optional<BreakpointImplPreference> impl);

        /**
         * Remove a memory breakpoint and deactivate it with the currently used breakpoint
         * implementation.
         * @param vm_region Virtual address range that should be free from memory breakpoints
         * @param ignore_mmu_update Whether to update page table permissions. This should be set to
         * true when the virtual memory region has been unmapped or remapped.
         * @return Deleted breakpoints, which can be later restored.
         */
        breakpoint_collection
        remove_memory_breakpoint(MemoryRegion vm_region, bool ignore_mmu_update = false);

        /**
         * Get the number of bytes of memory that is requested to be monitored for memory accesses.
         */
        uint64_t get_demand_size();

        /**
         * Get the number of bytes of memory that is watched for memory accesses.
         * The returned size may be greater than the size of memory that we need to monitor due to
         * the granularity of memory breakpoints.
         */
        uint64_t get_watch_size();

        void print_debug();

        //TODO: Remove watchpoint for 1 process only when handling process that accesses watchpoint mem
    };
private:
    std::list<Process*> procs_;   ///< List of processes that use this address space
    AnnotatedAddressSpace<std::unique_ptr<MemoryMap>> maps_;
    std::vector<MemoryRegion> debug_breakpoints_;   ///< Non-taint breakpoints for debugging
    std::optional<uint64_t> syscall_instruction_address_;
    MemoryBreakpointManager memory_breakpoint_manager_;

public:
    /**
     * Create a new, empty address space.
     */
    VirtualAddressSpace();

    /**
     * Create a new virtual address space based on an existing address space.
     * Private maps are copied, whereas shared maps share the underlying physical memory and
     * associated taints.add_process
     */
    explicit VirtualAddressSpace (const VirtualAddressSpace& vspace_parent);

    // Disallow reallocations or copies. Memory map has a raw pointer to this.
    VirtualAddressSpace operator=(const VirtualAddressSpace&) = delete;

    MemoryBreakpointManager& get_memory_breakpoint_manager();

    /**
     * Associate a new process with an existing virtual address space.
     * Processes cloned with CLONE_VM should call this function.
     * @param process Process to associate with
     */
    void associate_process(Process *process);

    /**
     * Disassociate a process from this virtual address space.
     * @param process Process to disassociate from
     */
    void disassociate_process(Process *process);

    /**
     * Add memory maps from any associated process by parsing /proc/[pid]/maps
     */
    void import_maps_from_procfs();

    /**
     * Add a new memory map that isn't shared yet with another virtual address space.
     * @param vm_start First virtual address inside the region
     * @param vm_end First virtual address outside the region
     * @param shared Whether the map should be shared or not
     * @param prot Memory protection flags
     * @param file_path Path of the mapped file, set to nullopt if the mapping is anonymous
     * @param file_offset Offset into the file that is mapped
     * @return Reference to inserted memory map
     */
    MemoryMap& add_memory_map(uint64_t vm_start, uint64_t vm_end, bool shared, int prot,
            std::optional<std::string> file_path = {}, uint64_t file_offset = -1);

    /**
     * Remove a region of memory that has been mapped in this virtual address space
     * @param vm_start Start address of the region to remove
     * @param vm_end End address of region to remove
     */
    void remove_memory_map(uint64_t vm_start, uint64_t vm_end);

    /**
     * Remap a virtual address range
     * @param old_vm Starting address of the memory map to move
     * @param old_size Size of the memory map to move. If it is zero, then a new mapping of the
     * same pages is created instead of moved
     * @param new_vm Destination address of the new memory map
     * @param new_size Size of the new memory map
     */
    void remap_memory_maps(uint64_t old_vm, uint64_t old_size, uint64_t new_vm, uint64_t new_size);

    /**
     * Get a memory map that maps the given virtual address range.
     * TODO: Currently throws an exception if multiple maps are found
     * @param vm_start Start of the virtual address range to query
     * @param vm_end End of the virtual address range to query
     * @return The matching memory map and physical address region, otherwise returns std::nullopt
     */
    std::optional<std::pair<MemoryMap&, MemoryRegion>> get_memory_map(uint64_t vm_start, uint64_t vm_end);

    /**
     * Set memory protection flags of
     * @param Virtual address range to apply the protection flags to
     * @param flag Memory protection flags given to mmap() or mprotect()
     */
    void set_protection_flag(MemoryRegion vaddr, int flag);

    /**
     * Return a process of an active process that uses this address space.
     * @param prefer_stopped Return a process ID that has been stopped if possible
     * @param only_stopped Exclude processes that are not stopped
     * @param exclude_syscall_in_progress Exclude processes that may have stopped in the middle of
     * a system call
     */
    Process& get_any_associated_process(bool prefer_stopped = false, bool only_stopped = false, bool exclude_syscall_in_progress = false);

    /**
     * Get the list of processes that use this virtual address space
     */
    std::vector<std::reference_wrapper<Process>> get_processes();

    /**
     * Get all proccesses that map a given virtual address range
     * @param vaddr Virtual address range
     * @return List of process references
     */
    std::vector<std::reference_wrapper<Process>> get_mapping_processes(MemoryRegion vaddr);

    /**
     * Place a memory breakpoint at the specified virtual address range to
     * all processes that share the underlying physical memory range.
     * @param taint
     * @param vm_region
     */
    void set_memory_taint(std::optional<TaintEvent> taint, MemoryRegion vm_region);

    /**
     * Return memory ranges that are mapped by this address space that intersect with a given
     * memory region.
     */
    std::vector<MemoryRegion> intersect_mapped(MemoryRegion vm_region);

    /**
     * Return the intersection of all memory taints with a given region
     * @param vm_region Region to intersect all taints with
     * @return Memory regions that both intersect r and any tainted memory
     */
    std::vector<MemoryRegion> intersect_with_taints(MemoryRegion vm_region);

    /**
     * Find all taints that intersect with a given virtual memory range
     * @param vm_region Virtual address region to query
     * @return List of references to matching taint events
     */
    std::vector<std::reference_wrapper<TaintEvent>> get_memory_taints(MemoryRegion vm_region);

    std::optional<MemoryRegion> get_memory_breakpoint_pages(MemoryRegion mem_access);

    /**
     * Remove all memory taints and memory breakpoints
     */
    void remove_all_ibp_and_mm_bkpts();

    void enable_debug_memory_breakpoint(Process &p, MemoryRegion vm_region);

    bool has_memory_breakpoint(MemoryRegion vm_region);

    uint64_t get_syscall_instruction_address();
};

void mm_resize_callback(std::unique_ptr<MemoryMap> &t, MemoryRegion old, MemoryRegion n);
std::unique_ptr<MemoryMap> mm_split_copy_callback(std::unique_ptr<MemoryMap> &t, MemoryRegion old, MemoryRegion n);

inline uint64_t round_to_page_boundary(uint64_t addr) {
    return addr + (addr % PAGE_SIZE == 0 ? 0 : PAGE_SIZE - (addr % PAGE_SIZE));
}

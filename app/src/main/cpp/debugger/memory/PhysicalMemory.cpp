#include "PhysicalMemory.h"

#include <sys/mman.h>
#include <debugger/Syscall.h>
#include <debugger/Process.h>
#include <android/logging.h>
#include "VirtualAddressSpace.h"


PhysicalMemory::PhysicalMemory(MemoryMap *map) {
    add_map(map);
}

PhysicalMemory::PhysicalMemory(MemoryMap *map, const PhysicalMemory &other)
        : memory_taints_(other.memory_taints_)
        , ins_breakpoints_(other.ins_breakpoints_) {
    add_map(map);
}

void PhysicalMemory::add_map(MemoryMap *map) {
    /*
     * TODO: Check if intersects with existing memory breakpoint, if so, mprotect() it
     * See mmap-test.cpp: anonymous shared memory persists, even after partial unmap
     */
    maps_.push_back(map);
}

void PhysicalMemory::remove_map(MemoryMap *map) {
    auto it = std::find(maps_.begin(), maps_.end(), map);
    if(maps_.end() == it) {
        throw std::runtime_error("Failed to remove MemoryMap backpointer in PhysicalMemory: map not found in collection!");
    }
    maps_.erase(it);
}


std::list<std::pair<Process &, MemoryRegion>>
PhysicalMemory::get_all_vaddrs(MemoryRegion phy_region, bool prefer_stopped) {
    auto list = std::list<std::pair<Process&, MemoryRegion>>{};
    for (auto map : maps_) {
        auto phy_intersection = intersects(phy_region,
                MemoryRegion(map->phy_offset_, map->phy_offset_ + (map->vm_end_ - map ->vm_start_)));
        if (phy_intersection) {
            list.emplace_back(map->vspace_->get_any_associated_process(prefer_stopped),
                    map->phy_to_virtual(*phy_intersection));
        }
    }
    return list;
}

std::vector<std::reference_wrapper<Process>> PhysicalMemory::get_all_processes(MemoryRegion phy_region) {
    auto res = std::vector<std::reference_wrapper<Process>> {};
    auto vspaces = std::set<VirtualAddressSpace*> {};
    for (auto map : maps_) {
        auto phy_intersection = intersects(phy_region,
                                           MemoryRegion(map->phy_offset_, map->phy_offset_ + (map->vm_end_ - map ->vm_start_)));
        if (phy_intersection) {
            vspaces.insert(map->vspace_);
        }
    }

    for (auto vspace : vspaces) {
        auto procs = vspace->get_processes();
        res.insert(res.end(), procs.begin(), procs.end());
    }
    return res;
}

void PhysicalMemory::set_memory_taint_breakpoint(std::optional<TaintEvent> taint, MemoryRegion phy_region) {
    auto vaddrs = get_all_vaddrs(phy_region, true);
    if (taint) {
        // Mark memory as tainted
        memory_taints_.insert(AnnotatedMemoryRegion(phy_region.start_address, phy_region.end_address, std::move(*taint)));
        // Set memory breakpoints for every mapping in each address space using mprotect()
        for (auto& [proc, v_region] : vaddrs) {
            if (proc.state != ProcessState::STOPPED) {
                throw std::runtime_error("NYI: Process must be stopped before setting a memory breakpoint");
            }
            proc.get_address_space().get_memory_breakpoint_manager().set_memory_breakpoint(v_region);
        }
    } else {
        if (memory_taints_.empty()) {
            LOGW("Ignoring request to restore memory permissions, as no memory taints were found");
            return;
        }
        // Mark memory as untainted
        memory_taints_.erase(phy_region);
        for (auto& [proc, v_region] : vaddrs) {
            if (proc.state != ProcessState::STOPPED) {
                throw std::runtime_error("NYI: Process must be stopped before removing a memory breakpoint");
            }
            proc.get_address_space().get_memory_breakpoint_manager().remove_memory_breakpoint(v_region);
        }
    }
}

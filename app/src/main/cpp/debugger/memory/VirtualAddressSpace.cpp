#include "VirtualAddressSpace.h"
#include <iostream>
#include <android/logging.h>
#include <fmt/format.h>
#include <debugger/Debugger.h>
#include "debugger/Process.h"
#include "MergingRegionSet.h"
#include <debugger/memory/PhysicalMemory.h>
#include <debugger/procfs/ProcessMapsEntry.h>
#include <sys/mman.h>
#include <fstream>
#include <linux/uio.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <debugger/Syscall.h>
#include <debugger/Config.h>

std::optional<size_t> VirtualAddressSpace::MemoryBreakpointManager::watchpoint_count_ = {};

size_t VirtualAddressSpace::MemoryBreakpointManager::get_watchpoint_count() {
    if (watchpoint_count_) {
        return *watchpoint_count_;
    }
    throw std::runtime_error("Number of watchpoints has not been determined yet!");
}

bool VirtualAddressSpace::MemoryBreakpointManager::watchpoint_count_determined() {
    return watchpoint_count_.has_value();
}

void VirtualAddressSpace::MemoryBreakpointManager::set_watchpoint_count(pid_t pid) {
    auto bp = user_hwdebug_state {};
    auto bp_iov = iovec {
            .iov_base = &bp,
            .iov_len = offsetof(user_hwdebug_state, dbg_regs),
    };
    TRYSYSFATAL(ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &bp_iov));
    // Mask number of watchpoint registers from dbg_info as defined in ptrace_hbp_get_resource_info()
    watchpoint_count_ = bp.dbg_info & 0xFF;
    return;
}

VirtualAddressSpace::MemoryBreakpointManager::watchpoint_config
VirtualAddressSpace::MemoryBreakpointManager::get_watchpoint_config(MemoryRegion region) {
    /*
     * Relevant Armv8 documentation:
     * Debug Watchpoint Control Registers: https://developer.arm.com/docs/ddi0595/h/aarch64-system-registers/dbgwcrn_el1
     * Debug Watchpoint Value Registers: https://developer.arm.com/docs/ddi0595/h/aarch64-system-registers/dbgwvrn_el1
     */
    // Common control bits: enable memory breakpoint for read and write accesses
    constexpr auto control_common = 0b11 << 3 | 1;
    if (region.size() <= 8) {
        // Use BAS to select which bytes to watch
        // MASK = 0
        uint8_t offset = static_cast<uint8_t>(region.start_address & 0x7);
        return {
            .address = region.start_address & (~0x7ULL), // Aligned address
            .control = (((uint32_t) 1 << region.size()) - 1) << (5 + offset) | control_common,
            .trap_region = region,
        };
    } else {
        throw std::runtime_error("NYI: Setting watchpoint with non-zero mask bits is not yet supported by the kernel");
        // Use address mask. Region too large to watch with only BAS
        assert(region.start_address != region.end_address);
        int lz = __builtin_clzll(region.start_address ^ (region.end_address - 1));
        uint32_t mask_bits = (uint32_t)(64 - lz); // Index of MSB that differs between start and end address
        assert(3 <= mask_bits);
        assert(mask_bits < 32);
        uint64_t aligned_addr = region.start_address & ~((1ULL << mask_bits)-1);
        return {
                .address = aligned_addr,
                .control = mask_bits << 24 | 0xff << 5 | control_common,
                .trap_region = MemoryRegion(aligned_addr, aligned_addr + (1ULL << mask_bits))
        };
    }
}

void VirtualAddressSpace::MemoryBreakpointManager::commit(bool ignore_mmu_update) {
    using MemoryBreakpointManager = VirtualAddressSpace::MemoryBreakpointManager;
    /* 1. Plan */

    // Compute effective demands after combining with overrides
    auto effective_demand = demand_;
    for (auto ref : preference_override_.get_all()) {
        auto &override = ref.get();
        if (override.annotation.rc < 1) {
            throw std::runtime_error("Reference count of preference override at region " + override.str() + " has a reference count of less than 1");
        }
        auto matching_demands = demand_.get_intersecting_regions(override);
        for (auto d : matching_demands) {
            auto demand_subregion_to_override = intersects(override, d).value();
            effective_demand.insert(
                    AnnotatedMemoryRegion(
                            demand_subregion_to_override.start_address,
                            demand_subregion_to_override.end_address,
                            override.annotation.preference
                    )
            );
        }
    }

    // Filter demand regions by type
    MergingRegionSet mrs_demand_watchpoint, mrs_prefer_watchpoint, mrs_demand_mmu;
    for (const auto ref : effective_demand.get_all()) {
        auto &r = ref.get();
        switch (r.annotation) {
            case BreakpointImplPreference::MMU_ONLY:
                mrs_demand_mmu.insert(r);
                break;
            case BreakpointImplPreference::PREFER_WATCHPOINT:
                mrs_prefer_watchpoint.insert(r);
                break;
            case BreakpointImplPreference::WATCHPOINT_ONLY:
                mrs_demand_watchpoint.insert(r);
                break;
        }
    }

    // Effective memory ranges, can cover a region that is potentially larger than the demand
    MergingRegionSet mrs_watchpoint_plan, mrs_mmu_plan;
    // Map each demand region to a separate breakpoint
    // TODO: Can be optimized by letting hw breakpoints handle multiple regions
    std::vector<MemoryBreakpointManager::watchpoint_config> watchpoint_configs;
    watchpoint_configs.reserve(get_watchpoint_count());

    auto add_watchpoint = [&] (MemoryRegion r) {
        for (auto watchpoint_region : split_regions({r}, 8)) {
            auto config = get_watchpoint_config(watchpoint_region);
            mrs_watchpoint_plan.insert(config.trap_region);
            watchpoint_configs.push_back(config);
        }
    };

    auto add_mmu = [&] (MemoryRegion r) {
        mrs_mmu_plan.insert(r.page_aligned());
    };

    for (const auto r : mrs_demand_watchpoint.get_all()) {
        add_watchpoint(r);
    }

    for (const auto r : mrs_prefer_watchpoint.get_all()) {
        if (watchpoint_configs.size() < get_watchpoint_count()) {
            add_watchpoint(r);
        } else {
            add_mmu(r);
        }
    }

    for (const auto r : mrs_demand_mmu.get_all()) {
        add_mmu(r);
    }

    /* 2. Install */

    // Reflect changes to MMU
    std::vector<MemoryRegion> mmu_to_remove, mmu_to_add;
    auto &old_mmu_plan = active_mmu_plan_;
    auto new_mmu_plan = mrs_mmu_plan.get_all();
    auto it_old = old_mmu_plan.begin();
    auto it_new = new_mmu_plan.begin();

    while (true) {
        if (it_old == old_mmu_plan.end()) {
            while(it_new != new_mmu_plan.end()) {
                mmu_to_add.push_back(*it_new++);
            }
            break;
        }
        if (it_new == new_mmu_plan.end()) {
            while(it_old != old_mmu_plan.end()) {
                mmu_to_remove.push_back(*it_old++);
            }
            break;
        }

        assert(it_old != old_mmu_plan.end());
        assert(it_new != new_mmu_plan.end());
        if (it_old->start_address < it_new->start_address) {
            mmu_to_remove.push_back(*it_old++);
        } else if (it_new->start_address < it_old->start_address) {
            mmu_to_add.push_back(*it_new++);
        } else if (it_old->end_address != it_new->end_address){
            mmu_to_remove.push_back(*it_old++);
            mmu_to_add.push_back(*it_new++);
        } else {
            it_old++;
            it_new++;
        }
    }

    active_mmu_plan_ = std::move(new_mmu_plan);

    if (ignore_mmu_update) {
        LOGD("commit(ignore_mmu_update = true): Ignoring MMU update");
    } else if (!mmu_to_add.empty() || !mmu_to_remove.empty()) {
        LOGV("A change has been made to MMU-based memory breakpoints");
        auto &p = parent_.get_any_associated_process(true, true, true);
        if (p.state != ProcessState::STOPPED) {
            p.get_debugger().stop_process(p);
        }

        // Restore memory permissions
        for (auto region_to_restore : mmu_to_remove) {
            auto curr = region_to_restore.start_address;
            while (curr < region_to_restore.end_address) {
                if (auto mm_opt = parent_.get_memory_map(curr, curr + 1)) {
                    auto [mm, _] = *mm_opt;
                    auto restore_range = MemoryRegion(curr, std::min(region_to_restore.end_address, mm.vm_end_));

                    auto prot = mm.prot_;
                    if (prot == PROT_NONE) {
#ifdef PROD
                        LOGW("Restored memory permissions is still PROT_NONE");
#else
                        throw std::runtime_error("Restored memory permissions is still PROT_NONE");
#endif
                    }

                    LOGD("Restoring memory accesses with mprotect() for range %s with prot flags %" PRIx64, restore_range.str().c_str(), prot);
                    auto sys_ret = p.syscall(aarch64::syscall_number::mprotect, {restore_range.start_address, restore_range.size(), (uint64_t)prot});
                    auto sys_err = syscall_errno(sys_ret);
                    if (sys_err) {
                        throw std::runtime_error("Failed to remove memory breakpoint using mprotect(): " + std::string(strerror(sys_err)));
                    }
                    curr = restore_range.end_address;
                } else {
                    throw std::runtime_error(fmt::format("No memory map found for virtual address {:x} while restoring memory permissions", curr));
                }
            }
        }

        // Set memory breakpoints where needed
        for (auto region_to_revoke : mmu_to_add) {
            LOGD("Revoking memory accesses with mprotect() for range %s with prot flags %" PRIx64, region_to_revoke.str().c_str(), 0);
            auto sys_ret = p.syscall(aarch64::syscall_number::mprotect, {region_to_revoke.start_address, region_to_revoke.size(), (uint64_t) 0});
            auto sys_err = syscall_errno(sys_ret);
            if (sys_err) {
                throw std::runtime_error("Failed to set memory breakpoint using mprotect(): " + std::string(strerror(sys_err)));
            }
        }
    }

    // Reflect changes to wachpoints
    if (watchpoint_configs != active_watchpoint_config_) {
        LOGV("A change has been made to hardware-based memory breakpoints");
        // We overwrite all watchpoint registers because the desired state can be set with just 1 system call
        auto bp = user_hwdebug_state {};
        auto bp_iov = iovec {
                .iov_base = &bp,
                .iov_len = sizeof(bp.dbg_info) + sizeof(bp.pad) + (get_watchpoint_count() * sizeof(bp.dbg_regs[0])),
        };
        if (get_watchpoint_count() < watchpoint_configs.size()) {
            throw std::runtime_error(fmt::format("Attempted to set {} watchpoint registers while hardware only has {} watchpoints", watchpoint_configs.size(), get_watchpoint_count()));
        }
        assert(get_watchpoint_count() >= watchpoint_configs.size());
        for (int i = 0; i < watchpoint_configs.size(); i++) {
            bp.dbg_regs[i] = {
                    .ctrl = watchpoint_configs[i].control,
                    .addr = watchpoint_configs[i].address,
            };
        }
        for (auto p_ref : parent_.get_processes()) {
            auto &p = p_ref.get();
            if (p.state != ProcessState::STOPPED) {
                Debugger::get_instance().stop_process(p);
            }
            TRYSYSFATAL(ptrace(PTRACE_SETREGSET, p.get_pid(), NT_ARM_HW_WATCH, &bp_iov));
        }
        active_watchpoint_config_ = std::move(watchpoint_configs);
    }

    Debugger::get_instance().log_taint_size();

    if (Config::print_watched_memory) {
        print_debug();
    }
}

void VirtualAddressSpace::MemoryBreakpointManager::set_memory_breakpoint(
        VirtualAddressSpace::MemoryBreakpointManager::breakpoint_collection &breakpoints) {
    for (auto &b : breakpoints) {
        demand_.insert(b);
    }
    commit();
}

void VirtualAddressSpace::MemoryBreakpointManager::set_memory_breakpoint(MemoryRegion vm_region,
                                                                         BreakpointImplPreference impl_preference) {
    auto collection = VirtualAddressSpace::MemoryBreakpointManager::breakpoint_collection {AnnotatedMemoryRegion(vm_region, impl_preference)};
    set_memory_breakpoint(collection);
}

VirtualAddressSpace::MemoryBreakpointManager::breakpoint_collection
VirtualAddressSpace::MemoryBreakpointManager::update_memory_breakpoint_impl(std::vector<MemoryRegion> &vm_regions,
                                                                            BreakpointImplPreference impl) {
    auto updated_demands = std::vector<AnnotatedMemoryRegion<BreakpointImplPreference>> {};
    for (const auto vm_region : vm_regions) {
        for (const auto &ref : demand_.get_intersecting_items(vm_region)) {
            auto &item = ref.get();
            if (item.annotation == impl) continue;
            auto updated_region = MemoryRegion(std::max(item.start_address, vm_region.start_address), std::min(item.end_address, vm_region.end_address));
            updated_demands.emplace_back(AnnotatedMemoryRegion<BreakpointImplPreference>(updated_region, item.annotation));
            demand_.insert(AnnotatedMemoryRegion<BreakpointImplPreference>(updated_region, impl));
        }
    }
    commit();
    return updated_demands;
}

void VirtualAddressSpace::MemoryBreakpointManager::override_impl_rc(
        std::vector<MemoryRegion> &vm_regions, std::optional<BreakpointImplPreference> impl) {
    if (vm_regions.empty()) return;
    if (impl) {
        for (auto r : vm_regions) {
            // Regions that have not been covered yet by an existing override
            auto new_overrides = AnnotatedAddressSpace<int>();
            new_overrides.insert(AnnotatedMemoryRegion<int>(r.start_address, r.end_address, 0)); // Dummy value
            for (auto existing_override_ref : preference_override_.get_intersecting_items(r)) {
                if (existing_override_ref.get().annotation.preference != impl.value()) {
                    throw std::runtime_error(fmt::format("Unable to increment reference count of existing override: preference differs"));
                }
                auto intersection = intersects(existing_override_ref.get(), r).value();
                // Overwrite intersections with incremented rc
                preference_override_.insert(AnnotatedMemoryRegion<impl_override_rc>(intersection.start_address, intersection.end_address, impl_override_rc {
                    .preference = impl.value(),
                    .rc = existing_override_ref.get().annotation.rc + 1
                }));
                new_overrides.erase(intersection);
            }
            // Insert override regions that were not present
            for (auto new_r : new_overrides.get_intersecting_regions(MemoryRegion::domain())) {
                preference_override_.insert(AnnotatedMemoryRegion<impl_override_rc>(new_r.start_address, new_r.end_address, impl_override_rc {
                        .preference = impl.value(),
                        .rc = 1
                }));
            }
        }
    } else {
        for (auto r : vm_regions) {
            for (auto existing_override_ref : preference_override_.get_intersecting_items(r)) {
                auto intersection = intersects(existing_override_ref.get(), r).value();
                auto new_rc = existing_override_ref.get().annotation.rc - 1;
                if (new_rc > 0) {
                    preference_override_.insert(AnnotatedMemoryRegion<impl_override_rc>(intersection.start_address, intersection.end_address, impl_override_rc {
                            .preference = existing_override_ref.get().annotation.preference,
                            .rc = new_rc
                    }));
                } else {
                    preference_override_.erase(intersection);
                }
            }
        }
    }
    commit();
}
VirtualAddressSpace::MemoryBreakpointManager::breakpoint_collection
VirtualAddressSpace::MemoryBreakpointManager::remove_memory_breakpoint(MemoryRegion vm_region, bool ignore_mmu_update) {
    // TODO: returned values contain previously set breakpoints.
    //       When re-enabling, we must check if region still contains tainted data after taintprop
    auto removed_demands = std::vector<AnnotatedMemoryRegion<BreakpointImplPreference>> {};
    for (const auto &ref : demand_.get_intersecting_items(vm_region)) {
        auto &item = ref.get();
        removed_demands.emplace_back(
                // Cut-off region that we don't remove from matching intersections
                AnnotatedMemoryRegion<BreakpointImplPreference> (
                        std::max(item.start_address, vm_region.start_address),
                        std::min(item.end_address, vm_region.end_address),
                        item.annotation
                )
        );
    }
    if (!removed_demands.empty()) {
        demand_.erase(vm_region);
        commit(ignore_mmu_update);
    }
    return removed_demands;
}

uint64_t VirtualAddressSpace::MemoryBreakpointManager::get_demand_size() {
    return demand_.total_region_size();
}

uint64_t VirtualAddressSpace::MemoryBreakpointManager::get_watch_size() {
    uint64_t size = 0;
    for (const auto &r : active_mmu_plan_) {
        size += r.size();
    }
    for (const auto &c : active_watchpoint_config_) {
        size += c.trap_region.size();
    }
    return size;
}

void VirtualAddressSpace::MemoryBreakpointManager::print_debug() {
    for (size_t i = 0; i < active_watchpoint_config_.size(); i++) {
        auto &config = active_watchpoint_config_[i];
        LOGD("Memory watched by HW watchpoint (%d out of %d):", i + 1, active_watchpoint_config_.size());
        LOGD("Watchpoint register value: 0x%" PRIx64 "\tcontrol:0x%" PRIx64, config.address, config.control);
        auto r = config.trap_region;
        parent_.get_any_associated_process(true, true).print_memory(r.start_address, r.size());
    }
}

VirtualAddressSpace::MemoryBreakpointManager::MemoryBreakpointManager(VirtualAddressSpace &parent)
    : parent_(parent) {}

VirtualAddressSpace::VirtualAddressSpace() : memory_breakpoint_manager_(*this) {}

VirtualAddressSpace::VirtualAddressSpace(const VirtualAddressSpace& vspace_parent)
    // Copy memory breakpoint manager state, as debug registers and memory breakpoints are active
    // after cloning a process. Registers, including debug registers, are copied after clone().
    : memory_breakpoint_manager_(vspace_parent.memory_breakpoint_manager_) {
    for (auto region : const_cast<AnnotatedAddressSpace<std::unique_ptr<MemoryMap>>&>(vspace_parent.maps_).get_all()) {
        auto& amr = region.get();
        maps_.insert(
                AnnotatedMemoryRegion<std::unique_ptr<MemoryMap>>(amr.start_address, amr.end_address,
                                                 std::make_unique<MemoryMap>(this, *amr.annotation)),
                [](std::unique_ptr<MemoryMap> &t, MemoryRegion old, MemoryRegion n) {
                    throw std::runtime_error("Resize callback executed during vspace copy");
                },
                [](std::unique_ptr<MemoryMap>&t, MemoryRegion old, MemoryRegion n) {
                    throw std::runtime_error("Split copy callback executed during vspace copy");
                    return nullptr;
                }
        );
    }
}

VirtualAddressSpace::MemoryBreakpointManager &VirtualAddressSpace::get_memory_breakpoint_manager() {
    return memory_breakpoint_manager_;
}

void VirtualAddressSpace::associate_process(Process *process) {
    procs_.push_back(process);
}

void VirtualAddressSpace::disassociate_process(Process *process) {
    auto it = std::find(procs_.begin(), procs_.end(), process);
    if (it == procs_.end()) {
        throw std::runtime_error("Can't disassociate a process if it wasn't associated to begin with");
    }
    procs_.erase(it);
}

void VirtualAddressSpace::import_maps_from_procfs() {
    auto pid = get_any_associated_process().get_pid();
    LOGV("Importing memory maps from procfs of process %d", pid);
    std::ifstream maps_file("/proc/" + std::to_string(pid) + "/maps");
    std::string map_line;
    while(getline(maps_file, map_line)) {
        auto mm_entry = ProcessMapsEntry(map_line);
        if (!syscall_instruction_address_ && mm_entry.is_file && mm_entry.prot & PROT_EXEC) {
            auto [path, offset] = get_any_associated_process().get_debugger().syscall_instruction_location;
            auto res = mm_entry.addr_start + offset - mm_entry.offset;
            if (mm_entry.path == path && mm_entry.addr_start <= res && res < mm_entry.addr_end) {
                syscall_instruction_address_ = res;
            }
        }
        add_memory_map(
                reinterpret_cast<uint64_t >(mm_entry.addr_start),
                reinterpret_cast<uint64_t >(mm_entry.addr_end),
                mm_entry.flags != MAP_PRIVATE,
                mm_entry.prot,
                mm_entry.is_file ? std::optional<std::string>(mm_entry.path ) : std::nullopt,
                (uint64_t) mm_entry.offset);
    }
}

MemoryMap& VirtualAddressSpace::add_memory_map(uint64_t vm_start, uint64_t vm_end, bool shared,
        int prot, std::optional<std::string> file_path, uint64_t file_offset) {
    if (file_path) {
        LOGD("Adding memory map of a file with map %s (offset 0x%" PRIx64 "): %s (prot %d)", file_path->c_str(), file_offset, MemoryRegion(vm_start, vm_end).str().c_str(), prot);
    } else {
        LOGD("Adding anonymous map: %s (prot %d)", MemoryRegion(vm_start, vm_end).str().c_str(), prot);
    }
    constexpr uint64_t alignment = 1ULL << 12;
    if (vm_start % alignment != 0 || vm_end % alignment != 0) {
        throw std::runtime_error(fmt::format("Attempted to insert memory map with unaligned start or end address. Start: {:#x}, end: {:#x}", vm_start, vm_end));
    }
    if (procs_.empty()) {
        throw std::runtime_error("Attempted to add a memory map to an address space without processes");
    }
    if (!(vm_start < vm_end)) {
        throw std::runtime_error("Attempted to add a memory map with a greater starting address than its end address");
    }

    auto &mm = *maps_.insert(
            AnnotatedMemoryRegion<std::unique_ptr<MemoryMap>>(vm_start, vm_end,
                                                              std::make_unique<MemoryMap>(this, vm_start, vm_end, shared, prot)),
            mm_resize_callback,
            mm_split_copy_callback
    );

    // Set breakpoints if we're loading an image with methods that we are asked to set breakpoints on
    // TODO: Refactor ELF files to OpenFileDescriptor
    if (file_path) {
        auto &proc = get_any_associated_process(true);
        auto image_breakpoints = proc.get_debugger().get_image_breakpoints(*file_path);
        auto mm_region = MemoryRegion(vm_start, vm_end);
        for (auto img_bp : image_breakpoints) {
            auto bp_file_offsets = img_bp.get().get_breakpoint_offsets(); // Offsets relative to start of file
            for (auto bp_file_offset : bp_file_offsets) {
                auto bp_vaddr = vm_start + (bp_file_offset - file_offset);
                if (mm_region.contains(bp_vaddr)) {
                    LOGD("Inserting instruction breakpoint @ vaddr: %" PRIx64 "(+0x%" PRIx64 " in module %s)",
                            bp_vaddr, bp_file_offset, file_path->c_str());

                    proc.insert_instruction_breakpoint(bp_vaddr, img_bp.get().get_reason(), false, false, img_bp.get());
                } else {
                    auto file_offset_region = MemoryRegion::from_start_and_size(file_offset, mm_region.size());
                    LOGW("Skipping insertion of breakpoint at file offset %" PRIx64 " because we only map %s", bp_file_offset, file_offset_region.str().c_str());
                }
            }
        }
    }

    return mm;
}

void VirtualAddressSpace::remove_memory_map(uint64_t vm_start, uint64_t vm_end) {
    auto r = MemoryRegion(vm_start, vm_end);
    maps_.erase(r, mm_resize_callback, mm_split_copy_callback);

    // Remove memory breakpoints but ignore permission restore for regions
    get_memory_breakpoint_manager().remove_memory_breakpoint(r, true);
}

void VirtualAddressSpace::remap_memory_maps(uint64_t old_vm, uint64_t old_size, uint64_t new_vm,
                                            uint64_t new_size) {
    /*
     * Linux only supports moving and resizing a single `struct vm_area_struct`.
     * Thus, all page table entries of the region to move have the same permissions.
     * Additionally, they share the same file or anonymous memory region.
     * It could be that multiple MemoryMap that we track exist for the given range, even though
     * the kernel tracks it as 1 large vm_area_struct due to the lack of merging.
     * We assert that all MemoryMap annotations point to the same PhysicalMemory though.
     */
    auto new_region = MemoryRegion::from_start_and_size(new_vm, new_size);

    auto is_shared = false;
    auto prot = 0;
    auto phy = std::shared_ptr<PhysicalMemory> {};
    auto phy_offset = (uint64_t) 0; // Starting offset into phy
    auto first_mm_end = (uint64_t) 0;

    if (auto mm_opt = get_memory_map(old_vm, old_vm + 1)) {
        auto &mm = mm_opt->first;
        prot = mm.prot_;
        phy = mm.phy_; // Keep phy alive after we remove the old memory map
        phy_offset = mm_opt->second.start_address;
        first_mm_end = mm.vm_end_;
        is_shared = mm.is_shared_;
        assert(old_vm < first_mm_end);
    } else {
        throw std::runtime_error("No memory map found to remap");
    }

    if (old_size) {
        auto old_region = MemoryRegion::from_start_and_size(old_vm, old_size);
        assert(!intersects(old_region, new_region)); // mremap() returns EINVAL if new overlaps old

        // Check that all matching memory maps of old_region share the same phy
        auto mm_start = first_mm_end;
        while(mm_start <  old_region.end_address) {
            if (auto mm_opt = get_memory_map(mm_start, mm_start + 1)) {
                auto &mm = mm_opt->first;
                assert(old_region.start_address < mm.vm_end_);
                if (prot != mm.prot_) {
                    throw std::runtime_error(fmt::format("Protection flags differ between first region {} (prot {}) and subregion {} (prot {})",
                            MemoryRegion(old_vm, first_mm_end).str(), prot, MemoryRegion(mm_start, mm.vm_end_).str()));
                }
                if (mm.phy_ != phy) {
                    throw std::runtime_error(fmt::format("Failed to move memory mapping {}: subregion {} has a different taint storage than the first map",
                            old_region.str(), MemoryRegion(mm_start, mm.vm_end_).str()));
                }
                mm_start = mm.vm_end_;
            } else {
                throw std::runtime_error(fmt::format("No memory map found in the middle of region at starting address {} to remap {}", mm_start, old_region.str()));
            }
        }
        remove_memory_map(old_region.start_address, old_region.end_address);
    } else {
        // Are we able to determine how much memory starting from old_size is copied?
        // Do we have to read maps via procfs?
        throw std::runtime_error("NYI: handle mremap() with old_size == 0");
    }

    // Insert memory map
    auto &mm = *maps_.insert(
            AnnotatedMemoryRegion<std::unique_ptr<MemoryMap>>(new_region.start_address, new_region.end_address,
                                                              std::make_unique<MemoryMap>(this, new_region.start_address, new_region.end_address, is_shared, prot, phy, phy_offset)),
            mm_resize_callback,
            mm_split_copy_callback
    );

    // Re-enable memory breakpoints
    // Assumption: there are no memory breakpoints that need to stay disabled
    std::vector<MemoryRegion> mem_bkpt_to_enable {};
    {
        MergingRegionSet s;
        for (const auto phy_tainted_region : mm.get_physical_memory().memory_taints_.get_intersecting_regions(mm.virtual_to_phy(new_region))) {
            s.insert(mm.phy_to_virtual(phy_tainted_region).page_aligned());
        }
        mem_bkpt_to_enable = s.get_all();
    }
    for (const auto m : mem_bkpt_to_enable) {
        get_memory_breakpoint_manager().set_memory_breakpoint(m);
    }
}

Process& VirtualAddressSpace::get_any_associated_process(bool prefer_stopped, bool only_stopped, bool exclude_syscall_in_progress) {
    if (procs_.empty()) {
        throw std::runtime_error("No active process found in virtual address space");
    }
    if (only_stopped) {
        for (auto &p : procs_) {
            if (p->state != ProcessState::STOPPED) {
                continue;
            }
            if (exclude_syscall_in_progress && p->has_syscall()) {
                auto syscall_state = p->get_current_syscall().state;
                if (syscall_state == SyscallEventState::RestartSyscallEntry ||
                    syscall_state == SyscallEventState::RestartSyscallExit) {
                    continue;
                }
            }
            return *p;
        }
        throw std::runtime_error("No process found that matches the desired criteria");
    }
    assert(!exclude_syscall_in_progress);
    if (prefer_stopped) {
        for (auto& p : procs_) {
            if (p->state == ProcessState::STOPPED) {
                return *p;
            }
        }
    }
    return *procs_.front();
}

std::vector<std::reference_wrapper<Process>> VirtualAddressSpace::get_processes() {
    if (procs_.empty()) {
        throw std::runtime_error("No active process found in virtual address space");
    }

    auto res = std::vector<std::reference_wrapper<Process>> {};
    if (procs_.empty()) {
        throw std::runtime_error("No active process found in virtual address space");
    }
    for (auto *p : procs_) {
        res.emplace_back(*p);
    }
    return res;
}

std::vector<std::reference_wrapper<Process>>
VirtualAddressSpace::get_mapping_processes(MemoryRegion vaddr) {
    auto mm_mr = get_memory_map(vaddr.start_address, vaddr.end_address);
    if (!mm_mr) {
        throw std::runtime_error("Can't find mapping processes: no memory maps found that maps the given virtual memory range");
    }
    auto [mm, phy_region] = *mm_mr;
    return mm.get_physical_memory().get_all_processes(phy_region);
}

std::optional<std::pair<MemoryMap&, MemoryRegion>> VirtualAddressSpace::get_memory_map(uint64_t vm_start, uint64_t vm_end) {
    if (!(vm_start < vm_end)) {
        throw std::runtime_error("Invalid arguments provided to get_memory_map: start address must be less than end address");
    }
    auto query_region = MemoryRegion(vm_start, vm_end);
    auto matches = maps_.get_annotations(query_region);
    if (matches.empty())
        return {};
    else if (matches.size() > 1)
        throw std::runtime_error("Provided region spans multiple maps");
    auto& map = *matches[0].get();
    if (intersects(query_region, MemoryRegion(map.vm_start_, map.vm_end_)) != query_region) {
        throw std::runtime_error("Couldn't find a memory map that maps the requested region in its entirety");
    }
    return std::pair<MemoryMap&, MemoryRegion>(map, map.virtual_to_phy(query_region));
}

void VirtualAddressSpace::set_protection_flag(MemoryRegion vaddr, int flag) {
    /*
     * The entire virtual address range must be accessible.
     * We assert that there exists a sequence of 1 or more memory maps that together map the
     * provided address range without any gaps in-between the memory maps.
     */
    if (vaddr.page_aligned() != vaddr) {
        throw std::runtime_error("Invalid arguments provided to set_protection_flag: virtual address range is not page-aligned");
    }

    auto matches = maps_.get_annotations(vaddr);
    if (matches.empty()) {
        throw std::runtime_error("Failed to set protection flag: no matching memory maps found for region " + vaddr.str());
    } else if (matches.size() == 1) {
        auto &mm = *matches[0].get();
        LOGV("Modify memory map protection flags: Found 1 memory map to modify: 0x%" PRIx64 "-0x%" PRIx64 " prot %d",
                mm.vm_start_, mm.vm_end_, mm.prot_);
        if (!MemoryRegion(mm.vm_start_, mm.vm_end_).contains(vaddr)) {
            throw std::runtime_error("Failed to set protection flag: Tracked memory map do not entirely map the provided region");
        }
        if (MemoryRegion(mm.vm_start_, mm.vm_end_) != vaddr) {
            // Create new memory map with the same shared physical memory
            maps_.insert(
                    AnnotatedMemoryRegion<std::unique_ptr<MemoryMap>>(vaddr, std::make_unique<MemoryMap>(
                            mm.vspace_, vaddr.start_address, vaddr.end_address, mm.is_shared_, flag, mm.phy_, mm.phy_offset_ + (vaddr.start_address - mm.vm_start_)
                    )),
                    mm_resize_callback,
                    mm_split_copy_callback
            );
        } else {
            mm.set_protection_flag(flag);
        }
    } else {
        assert(std::is_sorted(matches.begin(), matches.end(),
                [](const std::unique_ptr<MemoryMap> &m1, const std::unique_ptr<MemoryMap> &m2) {
                    return m1->vm_start_ < m2->vm_end_;
                }));
        std::vector<MemoryRegion> mapped_regions {};
        mapped_regions.reserve(matches.size());
        for (const auto &r : matches) {
            auto &mm = *r.get();
            mapped_regions.emplace_back(mm.vm_start_, mm.vm_end_);
        }
        auto mapped_vm_range = merge_consecutive_regions(mapped_regions); // Throws if maps have gaps
        if (!mapped_vm_range.contains(vaddr)) {
            throw std::runtime_error("Failed to set protection flag: Tracked memory maps do not entirely map the provided region");
        }

        // Split left-most memory map if we only need to modify permissions for a part of the memory map
        auto &mm_left = *matches[0].get();
        if (vaddr.start_address != mm_left.vm_start_){
            assert(mm_left.vm_start_ < vaddr.start_address);
            assert(vaddr.start_address < mm_left.vm_end_);
            assert(mm_left.vm_end_ < vaddr.end_address);
            auto intersection_left = intersects(MemoryRegion(mm_left.vm_start_, mm_left.vm_end_), vaddr).value();
            maps_.insert(
                    AnnotatedMemoryRegion<std::unique_ptr<MemoryMap>>(intersection_left, std::make_unique<MemoryMap>(
                            mm_left.vspace_, intersection_left.start_address, intersection_left.end_address, mm_left.is_shared_, flag, mm_left.phy_, mm_left.phy_offset_ + (intersection_left.start_address - mm_left.vm_start_)
                    )),
                    mm_resize_callback,
                    mm_split_copy_callback
            );
        }

        // Split right-most memory map if we only need to modify permissions for a part of the memory map
        auto &mm_right = *matches[matches.size()-1].get();
        if (vaddr.end_address != mm_right.vm_end_){
            auto intersection_right = intersects(MemoryRegion(mm_right.vm_start_, mm_right.vm_end_), vaddr).value();
            assert(intersection_right.start_address == mm_right.vm_start_);
            maps_.insert(
                    AnnotatedMemoryRegion<std::unique_ptr<MemoryMap>>(intersection_right, std::make_unique<MemoryMap>(
                            mm_right.vspace_, intersection_right.start_address, intersection_right.end_address, mm_right.is_shared_, flag, mm_right.phy_, mm_right.phy_offset_
                    )),
                    mm_resize_callback,
                    mm_split_copy_callback
            );
        }

        matches = maps_.get_annotations(vaddr);
        mapped_regions.clear();
        mapped_regions.reserve(matches.size());

        for (const auto &r : matches) {
            auto &mm = *r.get();
            mm.set_protection_flag(flag);
            mapped_regions.emplace_back(mm.vm_start_, mm.vm_end_);
        }
        mapped_vm_range = merge_consecutive_regions(mapped_regions); // Throws if maps have gaps
        if (mapped_vm_range != vaddr) {
            throw std::runtime_error("Memory page splitting was not successful");
        }
    }

}

void VirtualAddressSpace::set_memory_taint(std::optional<TaintEvent> taint, MemoryRegion vm_region) {
    if (taint) {
        Debugger::at_least_one_taint_event = true;
    }
    auto mm = get_memory_map(vm_region.start_address, vm_region.end_address);
    if (!mm) {
        throw std::runtime_error("Tried to set breakpoint on a non-mapped address");
    }
    auto& [map, phy_region] = *mm;
    // TODO: Pass by forwarding reference
    map.get_physical_memory().set_memory_taint_breakpoint(std::move(taint), phy_region);
}

std::vector<MemoryRegion> VirtualAddressSpace::intersect_mapped(MemoryRegion vm_region) {
    auto res = maps_.get_intersecting_regions(vm_region); // Contains regions that span outside vm_region
    // Cut off parts of res that lie outside vm_region
    for (auto &r : res) {
        r.start_address = std::max(r.start_address, vm_region.start_address);
        r.end_address = std::min(r.end_address, vm_region.end_address);
    }
    return res;
}

std::vector<MemoryRegion> VirtualAddressSpace::intersect_with_taints(MemoryRegion vm_region) {
    auto res = std::vector<MemoryRegion> {};
    auto next = vm_region.start_address;
    while(next < vm_region.end_address) {
        auto mm = get_memory_map(next, next + 1);
        if (!mm) {
            get_any_associated_process(true).print_procfs_maps();
            throw std::runtime_error(fmt::format("No memory map found for address {:x}", next));
        }
        auto &[map, phy_region] = *mm;
        auto size = std::min(map.vm_end_ - next, vm_region.end_address - next);
        phy_region = MemoryRegion::from_start_and_size(phy_region.start_address, size);
        LOGV("phy_region 0x%s", phy_region.str().c_str());
        for (const auto r : map.get_physical_memory().memory_taints_.get_intersecting_regions(phy_region)) {
            auto tainted_vm_range = map.phy_to_virtual(r);
            if (auto opt = intersects(tainted_vm_range, vm_region)) {
                res.push_back(*opt);
            } else {
                throw std::runtime_error("Queried taint doesn't even intersect the memory region we want to query");
            }
        }
        next += size;
    }
    return res;
}

std::vector<std::reference_wrapper<TaintEvent>>
VirtualAddressSpace::get_memory_taints(MemoryRegion vm_region) {
    auto res = std::vector<std::reference_wrapper<TaintEvent>> {};
    auto next = vm_region.start_address;
    while(next < vm_region.end_address) {
        auto mm = get_memory_map(next, next + 1);
        if (!mm) {
            get_any_associated_process(true).print_procfs_maps();
            get_any_associated_process(true).print_registers(true);
            get_any_associated_process(true).print_stack_trace(false, true);
            throw std::runtime_error(fmt::format("No memory map found for address {:x}", next));
        }
        auto &[map, phy_region] = *mm;
        auto size = std::min(map.vm_end_, vm_region.end_address) - next;
        phy_region = MemoryRegion::from_start_and_size(phy_region.start_address, size);
        for (const auto annotation : map.get_physical_memory().memory_taints_.get_annotations(phy_region)) {
            res.push_back(annotation);
        }
        next += size;
    }
    return res;
}

std::optional<MemoryRegion> VirtualAddressSpace::get_memory_breakpoint_pages(MemoryRegion mem_access) {
    MergingRegionSet s;

    for (const auto mem_bkpt : intersect_with_taints(mem_access.page_aligned())) {
        // mem_bkpt is the fine-grained tainted region and isn't page-aligned
        s.insert(mem_bkpt.page_aligned());
    }

    for (auto dbg_region : debug_breakpoints_) {
        if (auto intersection = intersects(dbg_region, mem_access.page_aligned())) {
            s.insert(intersection->page_aligned());
        }
    }

    auto breakpoint_pages = s.get_all();
    if (breakpoint_pages.empty()) {
        return std::nullopt;
    } else if (breakpoint_pages.size() == 1) {
        return breakpoint_pages[0];
    } else {
        throw std::runtime_error("Accessed memory breakpoint pages isn't a contiguous region");
    }
}

void VirtualAddressSpace::remove_all_ibp_and_mm_bkpts() {
    auto &proc = get_any_associated_process(true);
    for (auto r : debug_breakpoints_) {
        LOGV("Removing debug breakpoint %s", r.str().c_str());
        proc.get_address_space().get_memory_breakpoint_manager().remove_memory_breakpoint(r);
    }
    for (auto &mm_node : maps_.get_all()) {
        auto &mm = *mm_node.get().annotation;
        LOGV("Cleaning memory map 0x%" PRIx64 "-0x%" PRIx64, mm.vm_start_, mm.vm_end_);
        if (mm.prot_ != PROT_NONE) {
            // Remove memory breakpoints
            auto phy_region = mm.virtual_to_phy({mm.vm_start_, mm.vm_end_});
            mm.get_physical_memory().set_memory_taint_breakpoint(std::nullopt, phy_region);
        }
        LOGV("Cleaning instruction breakpoints");
        for (auto &phy_bp : mm.get_physical_memory().ins_breakpoints_.get_all()) {
            // Remove instruction breakpoints of all processes that share this vspace
            auto &ibp = phy_bp.get().annotation;
            auto bp_vaddr = mm.phy_to_virtual(MemoryRegion::from_start_and_size(phy_bp.get().start_address, aarch64::instruction_size));
            LOGV("Removing instruction breakpoints %s", bp_vaddr.str().c_str());
            if (ibp.is_empty()) {
                throw std::runtime_error("Invariant violated: Found instruction breakpoint that has no ibp entries");
            }
            if (ibp.contains_permanent_entry()) {
                ibp.remove_permanent_entry();
                proc.remove_instruction_breakpoint(bp_vaddr.start_address, false);
            }
            for (auto temp_pid : ibp.list_temporary_entries()) {
                ibp.remove_temporary_entry(temp_pid);
            }
            // HACK: Insert permanent entry for the stopped process, such that a call to
            // remove_instruction_breakpoint succeeds
            ibp.add_entry(proc.get_pid(), InstructionBreakpointEntry(BreakpointReason::UNKNOWN, false, false, {}));
            proc.remove_instruction_breakpoint(bp_vaddr.start_address, false);
        }
   }
}

void VirtualAddressSpace::enable_debug_memory_breakpoint(Process &p, MemoryRegion vm_region) {
    p.get_address_space().get_memory_breakpoint_manager().set_memory_breakpoint(vm_region);
    debug_breakpoints_.push_back(vm_region);
}

bool VirtualAddressSpace::has_memory_breakpoint(MemoryRegion vm_region) {
    if (!get_memory_taints(vm_region).empty()) {
        return true;
    }
    for (auto r : debug_breakpoints_) {
        if (intersects(r, vm_region)) {
            return true;
        }
    }
    return false;
}

uint64_t VirtualAddressSpace::get_syscall_instruction_address() {
    if (auto addr = syscall_instruction_address_) {
        return *addr;
    } else {
        throw std::runtime_error("No system call instruction address set");
    }
}

void mm_resize_callback(std::unique_ptr<MemoryMap> &t, MemoryRegion old, MemoryRegion n) {
    auto start_diff = n.start_address - old.start_address;
    auto end_diff = n.end_address - old.end_address;
    t->vm_start_ += start_diff;
    t->phy_offset_ += start_diff;
    t->vm_end_ += end_diff;
}

std::unique_ptr<MemoryMap> mm_split_copy_callback(std::unique_ptr<MemoryMap> &t, MemoryRegion old, MemoryRegion n) {
    auto start_diff = n.start_address - old.start_address;
    return std::make_unique<MemoryMap>(t->vspace_, n.start_address, n.end_address, t->is_shared_, t->prot_,
                     t->phy_, t->phy_offset_ + start_diff);
}

bool VirtualAddressSpace::MemoryBreakpointManager::watchpoint_config::operator==(
        const VirtualAddressSpace::MemoryBreakpointManager::watchpoint_config &rhs) const {
    return address == rhs.address &&
           control == rhs.control &&
           trap_region == rhs.trap_region;
}

bool VirtualAddressSpace::MemoryBreakpointManager::watchpoint_config::operator!=(
        const VirtualAddressSpace::MemoryBreakpointManager::watchpoint_config &rhs) const {
    return !(rhs == *this);
}

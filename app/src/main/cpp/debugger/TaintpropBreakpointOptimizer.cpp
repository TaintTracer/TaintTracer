#include <debugger/vex/VEXLifter.h>
#include <android/logging.h>
#include "TaintpropBreakpointOptimizer.h"
#include "Config.h"
#include <fmt/format.h>
#include <magic_enum.hpp>

TaintpropBreakpointOptimizer::TaintpropBreakpointOptimizer(Process &proc) : proc_(proc) {}

void TaintpropBreakpointOptimizer::add_code_block(TraceeMemory mem) {
    code_cache_.emplace(mem.tracee_address(), std::move(mem));
}

void TaintpropBreakpointOptimizer::visit_bb(uint64_t bb_addr) {
    visit_bb(bb_addr, 0);
}

void TaintpropBreakpointOptimizer::visit_bb(uint64_t bb_addr, int distance) {
    /**
     * Number of instructions to analyze at once. VEX will parse instructions as an IRSB only up
     * to the end of the basic block. Ideally, this should be big enough such that most basic blocks
     * fit in the window size. Otherwise, we interpret the remaining instructions that were not
     * included in the window as a separate basic block.
     */
    constexpr auto window_size = aarch64::instruction_size * 20;

    auto size = window_size;

    /**
     * How many levels of basic blocks we should visit
     */
    constexpr auto bb_distance_thresh = 2;

    LOGV("PropOpt: Visiting bb @ 0x%" PRIx64 " with distance %d", bb_addr, distance);

    auto visited_it = visited_.lower_bound(bb_addr);

    if (visited_it != visited_.end()) {
        if (*visited_it == bb_addr) {
            // We already visited this basic block. Do nothing!
            LOGV("PropOpt: block already visited");
            return;
        } else {
            // We visited a node with a larger address. We want to read instructions up until the
            // start of that basic block if the distance doesn't exceed window_size
            auto next_bb_dist = *visited_it - bb_addr;
            size = next_bb_dist < window_size ? next_bb_dist : size;
            LOGV("PropOpt: Reading %z bytes of instructions", size);
        }
    }

    auto ins_ptr = get_instructions(bb_addr, size);
    auto lifter = VEXLifter::get_instance();
    auto irsb_res = lifter.analyze(ins_ptr, size, bb_addr);
    auto tainted_regs = proc_.get_tainted_register_regions();
    assert(std::is_sorted(tainted_regs.begin(), tainted_regs.end()));
    /*
     * We consider the following taint propagation scenarios:
     *   - Load from tainted memory location to another register: ✓ Already handled by memory breakpoints
     *   - Move from tainted register to another register: Requires breakpoint placement
     *   - Store from tainted register to memory location: Requires breakpoint placement
     */
    for (size_t i = 0; i < irsb_res.get_ins_count(); ++i) {
        if (auto kind = irsb_res.get_llsc_kind(i)) {
            if (*kind == LLSC_Kind::CLEAR_EXCLUSIVE || *kind == LLSC_Kind::LOAD_LINKED) {
                // We must handle load-linked and clear-exclusive instructions to track which
                // load-linked instruction corresponds to a given store-conditional instruction
                LOGV("%s", fmt::format("Setting breakpoint on LLSC instruction of type {}", magic_enum::enum_name(*kind)).c_str());
                set_breakpoint(irsb_res.get_instruction_address(i));
            } else if (*kind == LLSC_Kind::STORE_CONDITIONAL) {
                // We now also break at SC instructions because we were single stepping and then
                // removing temporary breakpoint on a LL instruction. This causes SC to fail if not
                // handled by us...
                if (Config::set_breakpoint_after_store_conditional) {
                    // We set the breakpoint at the instruction after it to allow different threads to
                    // attempt the store conditional, otherwise if another unrelated thread executes
                    // the breakpoint instead of the store conditional, causing a ctx switch and fail
                    LOGV("Setting breakpoint on instruction after store-conditional");
                    set_breakpoint(irsb_res.get_instruction_address(i) + aarch64::instruction_size, BreakpointReason::TAINTPROP_BREAKPOINT_OPTIMIZER_STORE_CONDITIONAL);
                } else {
                    LOGV("%s", fmt::format("Setting breakpoint on LLSC instruction of type {}", magic_enum::enum_name(*kind)).c_str());
                    set_breakpoint(irsb_res.get_instruction_address(i));
                }
                // TODO: Avoid this by removing temporary breakpoint @ LL and not single stepping if
                //       no other process has a temporary breakpoint on it.
            }
            return;
        }
        auto modifications = irsb_res.get_guest_modifications(i, [] (Int vex_offset) { return 0xf00d0000; });
        for (const auto &m : modifications.rw_pairs) {
            for (const auto &r : m.reads) {
                if (r.target != AccessTarget::Register) continue;
                // Check if register read contains tainted info
                auto tainted_reg_it = std::lower_bound(tainted_regs.begin(),  tainted_regs.end(), r.region.start_address);
                if ((tainted_reg_it != tainted_regs.end() && intersects(*tainted_reg_it, r.region))
                || (tainted_reg_it != tainted_regs.begin() && --tainted_reg_it != tainted_regs.begin() && intersects(*tainted_reg_it, r.region))) {
                    LOGV("Setting breakpoint on tainted register read at 0x%" PRIx64, irsb_res.get_instruction_address(i));
                    set_breakpoint(irsb_res.get_instruction_address(i));
                    return;
                }
            }
            if (m.write.target != AccessTarget::Register) continue;
            // Check if register write contains tainted info
            auto tainted_reg_it = std::lower_bound(tainted_regs.begin(),  tainted_regs.end(), m.write.region.start_address);
            if ((tainted_reg_it != tainted_regs.end() && intersects(*tainted_reg_it, m.write.region))
                || (tainted_reg_it != tainted_regs.begin() && --tainted_reg_it != tainted_regs.begin() && intersects(*tainted_reg_it, m.write.region))) {
                LOGV("Setting breakpoint on tainted register write at 0x%" PRIx64, irsb_res.get_instruction_address(i));
                set_breakpoint(irsb_res.get_instruction_address(i));
                return;
            }
        }
    }

    // Done processing instructions of this block
    visited_.emplace(bb_addr);

    auto last_bb_ins = irsb_res.get_ins_count() -1;
    if (distance == bb_distance_thresh) {
        LOGV("PropOpt: Distance threshold reached. Setting breakpoint on jump");
        set_breakpoint(irsb_res.get_instruction_address(last_bb_ins));
        return;
    }

    // Process jump targets originating from this block
    auto targets = irsb_res.get_jump_targets();
    assert(irsb_res.get_ins_count() != 0);

    // Set breakpoint at the end of this basic block if one of the jump targets can't be determined
    // statically
    assert(!targets.empty());
    for (const auto &t : targets) {
        if (!t->is_static_target()) {
            LOGV("PropOpt: One of the jump targets is non-static. Setting breakpoint on jump");
            set_breakpoint(irsb_res.get_instruction_address(last_bb_ins));
            return;
        }
    }

    for (const auto &t : targets) {
        visit_bb(t->get_target(), distance + 1);
    }
}

void TaintpropBreakpointOptimizer::set_breakpoint(uint64_t addr, BreakpointReason reason) {
    if (placed_breakpoints_.find(addr) == placed_breakpoints_.end()) {
        proc_.insert_instruction_breakpoint(
                addr,
                reason,
                true,
                true);
        auto [it, inserted] = placed_breakpoints_.emplace(addr);
        assert(inserted);
    }
}

const unsigned char *TaintpropBreakpointOptimizer::get_instructions(uint64_t address, uint64_t size) {
    // Get memory location in cache whose address is less or equal to `address`
    auto mem_it = code_cache_.upper_bound(address);
    if (mem_it != code_cache_.begin()) {
        mem_it--;
        auto &mem = mem_it->second;
        assert(mem_it->first == mem.tracee_address());
        assert(mem.tracee_address() <= address);
        if (address + size <= mem.tracee_address() + mem.size()) {
            // Code cache match!
            return mem.data() + (address - mem.tracee_address());
        }
    }
    // Read from tracee memory via syscall
    auto mem = proc_.read_memory(address, size);
    auto res = mem.data() + (address - mem.tracee_address());
    add_code_block(std::move(mem));
    return res; // Reference is alive until the entire object is destroyed
}

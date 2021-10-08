#include "GenericNativeSink.h"
#include <debugger/Debugger.h>
#include <debugger/Process.h>
#include <debugger/memory/VirtualAddressSpace.h>
#include <debugger/taint/TaintEvent.h>
#include <debugger/taint/execution/InstructionUnit.h>
#include <android/logging.h>
#include <magic_enum.hpp>
#include <fmt/format.h>

void GenericNativeSink::on_breakpoint(Debugger &d, Process &p) {
    // Check if the values we need to check for contain tainted info
    std::vector<TaintEvent> tainted_value_events;
    for (auto reg : tainted_values_to_check_.regs) {
        auto reg_taints = p.get_register_taints(register_to_vex_region(reg));
        std::move(reg_taints.begin(), reg_taints.end(), back_inserter(tainted_value_events));
    }
    auto &regs = p.get_registers();
    for (auto &mem_reference : tainted_values_to_check_.mem) {
        uint64_t base = regs[mem_reference.address];
        uint64_t size = regs[mem_reference.size];
        auto mem_taints = p.get_address_space().get_memory_taints(
                MemoryRegion::from_start_and_size(base, size));
        std::move(mem_taints.begin(), mem_taints.end(), back_inserter(tainted_value_events));
    }
    if (tainted_value_events.empty()) {
        LOGD("No tainted data propagated to sink");
        return;
    }
    LOGD("Tainted data propagated to sink!");
    auto pc = p.get_registers().get_pc();
    d.add_data_leak(TaintEvent(std::move(tainted_value_events),
                               std::make_shared<InstructionUnit>(
                                       p.get_pid(),
                                       pc,
                                       p.read_instruction(pc))));
}

GenericNativeSink::GenericNativeSink(TaintValues tainted_values_to_check)
        : tainted_values_to_check_(std::move(tainted_values_to_check)) {}

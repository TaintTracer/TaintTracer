#include "GenericNativeSource.h"

#include <debugger/Debugger.h>
#include <debugger/Process.h>
#include <debugger/arch/aarch64.h>
#include <debugger/memory/VirtualAddressSpace.h>
#include <android/logging.h>
#include <fmt/format.h>
#include <magic_enum.hpp>
#include <debugger/taint/execution/InstructionUnit.h>

GenericNativeSource::GenericNativeSource(TaintValues tainted_values)
    : tainted_values_(std::move(tainted_values)) {}

void GenericNativeSource::on_breakpoint(Debugger &d, Process &p) {
    auto pc = p.get_registers().get_pc();
    auto taint_event = TaintEvent(static_cast<TaintSource&>(*this),
            std::make_shared<InstructionUnit>(
                    p.get_pid(),
                    pc,
                    p.read_instruction(pc)));
    for (auto reg : tainted_values_.regs) {
        LOGV("%s", fmt::format("Tainting register {} ({}) due to break on source method", magic_enum::enum_name(reg),
                               register_to_vex_region(reg).str()).c_str());
        p.taint_register(register_to_vex_region(reg), taint_event);
    }
    for (auto mem : tainted_values_.mem) {
        auto base_addr = p.get_registers()[mem.address];
        auto mem_region = MemoryRegion::from_start_and_size(
                p.get_registers()[mem.address],
                p.get_registers()[mem.size]
        );
        LOGV("Tainting memory region %s due to break on source method", mem_region.str().c_str());
        p.get_address_space().set_memory_taint(taint_event, mem_region);
    }
}

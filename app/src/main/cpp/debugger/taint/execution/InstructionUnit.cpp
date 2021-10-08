#include <debugger/InstructionAnalyzer.h>
#include "InstructionUnit.h"
#include <fmt/format.h>
#include <debugger/Process.h>

InstructionUnit::InstructionUnit(Process &p) : ExecutionUnit(p.get_pid()),
                                               ins_addr_(p.get_registers().get_pc()),
                                               ins_bytes_(p.read_instruction(p.get_registers().get_pc())) {
}

InstructionUnit::InstructionUnit(pid_t pid, uint64_t ins_addr,
                                 const std::array<unsigned char, 4> &ins_bytes) : ExecutionUnit(pid),
                                                                                 ins_addr_(ins_addr),
                                                                                 ins_bytes_(
                                                                                         ins_bytes) {}

std::string InstructionUnit::str() {
    auto &analyzer = InstructionAnalyzer::get_instance();
    auto analysis = analyzer.analyze_capstone(ins_bytes_.data(), ins_bytes_.size(), ins_addr_);
    return fmt::format("{:#x}\t{}", analysis.instruction_address(0), analysis.to_string(0));
}

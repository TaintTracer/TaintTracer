#pragma once

#include "ExecutionUnit.h"
#include "../../arch/aarch64.h"
#include <cstdint>
class Process;

class InstructionUnit : public ExecutionUnit {
private:
    uint64_t ins_addr_; ///< Address of the instruction
    std::array<unsigned char, 4> ins_bytes_;
    static_assert(sizeof(ins_bytes_) >= aarch64::instruction_size);

public:
    InstructionUnit(Process &p);
    InstructionUnit(pid_t pid, uint64_t ins_addr, const std::array<unsigned char, 4> &ins_bytes);

    virtual std::string str();

};

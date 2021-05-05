#pragma once

#include "ExecutionUnit.h"
#include <debugger/arch/aarch64.h>

class SystemCallUnit : public ExecutionUnit {
private:
    aarch64::syscall_number number_;
    std::array<uint64_t, 6> args_;
public:
    SystemCallUnit(pid_t pid, aarch64::syscall_number number, const std::array<uint64_t, 6> &args);

    std::string str() override;
};

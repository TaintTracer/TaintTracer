#include "SystemCallUnit.h"
#include <fmt/format.h>
#include <magic_enum.hpp>

SystemCallUnit::SystemCallUnit(pid_t pid, aarch64::syscall_number number,
                               const std::array<uint64_t, 6> &args) : ExecutionUnit(pid),
                                                                      number_(number),
                                                                      args_(args) {}

std::string SystemCallUnit::str() {
    return fmt::format("{}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
            magic_enum::enum_name(number_),
            args_[0], args_[1], args_[2], args_[3], args_[4], args_[5]);
}

#include "ExecutionUnit.h"

ExecutionUnit::ExecutionUnit(pid_t pid) : pid_(pid) {}

pid_t ExecutionUnit::get_pid() {
    return pid_;
}

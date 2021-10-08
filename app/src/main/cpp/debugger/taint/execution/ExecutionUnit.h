#pragma once

#include <string>
#include <sys/types.h>

/**
 * An abstract unit of execution that propagates taints
 * Examples of concrete implementations:
 *  - A single native instruction
 *  - A system call with associated arguments
 *  - An invocation of a Java method, equivalent to a sequence of native instructions, but easier
 *    to analyze as it abstracts away the implementation of the Java Virtual Machine
 */
class ExecutionUnit {
private:
    pid_t pid_; ///< id of the process in which the execution took place
public:

    ExecutionUnit(pid_t pid);
    virtual ~ExecutionUnit() = default;

    /**
     * Return the process id in which the execution of the current unit took place
     * @return
     */
    pid_t get_pid();

    /**
     * Return a human-readable representation
     */
    virtual std::string str() = 0;
};

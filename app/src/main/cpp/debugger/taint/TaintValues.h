#pragma once

#include <vector>
#include <capstone/arm64.h>

/**
 * Determines which registers and memory locations and sizes (referenced by registers)
 * Source methods could interpret it as values that are considered tainted.
 * Sink methods could interpret it as locations to check for tainted info that gets sent to the sink
 */
struct TaintValues {
    struct RefToTaintedRegion {
        arm64_reg address;
        arm64_reg size;
    };

    TaintValues(std::vector<arm64_reg> regs, std::vector<RefToTaintedRegion> mem);
    /**
     * Register contents whose values are tainted whenever any of the the associated breakpoints are hit
     */
    std::vector<arm64_reg> regs;

    /**
     * Registers that point to a memory location and size that contains tainted data whenever any
     * of the associated breakpoints are hit
     */
    std::vector<RefToTaintedRegion> mem;
};

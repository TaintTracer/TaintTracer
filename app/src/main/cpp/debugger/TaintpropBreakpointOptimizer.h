#pragma once

#include <set>
#include "Process.h"

class TaintpropBreakpointOptimizer {
private:
    Process &proc_;
    std::map<uint64_t, TraceeMemory> code_cache_;
    std::set<uint64_t> visited_;
    std::set<uint64_t> placed_breakpoints_;

    void visit_bb(uint64_t bb_addr, int distance);

    /**
     * Get a pointer to instructions of tracee memory.
     * It will attempt to read from the already-read code-cache first, to avoid making a redundant
     * syscall
     * @param address Virtual address of the tracee
     * @param size Number of bytes to read
     * @return Pointer to instruction memory
     */
    const unsigned char *get_instructions(uint64_t address, uint64_t size);

    /**
     * Set a breakpoint only once per address
     * @param addr Virtual address of tracee to place a breakpoint
     */
    void set_breakpoint(uint64_t addr, BreakpointReason reason = BreakpointReason::TAINTPROP_BREAKPOINT_OPTIMIZER);
public:
    TaintpropBreakpointOptimizer(Process &proc);

    /**
     * Add a region of memory to be used as code cache
     */
    void add_code_block(TraceeMemory mem);

    /**
     * Analyze a basic block.
     * Set temporary breakpoints for this process if there's tainted information in at least
     * 1 register. We try to place breakpoints as late as possible to improve run-time performance,
     * by placing them on locations where we write from a tainted register to memory.
     * @param bb_addr Virtual address of basic block of tracee
     */
    void visit_bb(uint64_t bb_addr);

};

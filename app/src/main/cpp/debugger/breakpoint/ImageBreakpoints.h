#pragma once

#include <vector>
#include <cstdint>
#include "InstructionBreakpoint.h"
#include "BreakpointHandler.h"

class ImageBreakpoints : public BreakpointHandler {
protected:
    /**
     * Offsets relative to the start of an ELF image to break on.
     */
    std::vector<uint64_t> breakpoint_offsets_;

    BreakpointReason reason_;

public:
    ImageBreakpoints(BreakpointReason reason) : reason_(reason) {}

    std::vector<uint64_t> get_breakpoint_offsets() {
        return breakpoint_offsets_;
    }

    BreakpointReason get_reason() const {
        return reason_;
    }
};

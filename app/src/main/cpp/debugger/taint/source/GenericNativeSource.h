#pragma once

#include "TaintSource.h"
#include <capstone/arm64.h>
#include <vector>
#include <debugger/taint/TaintValues.h>

/**
 * Describes which registers and memory locations and their lengths should be marked as tainted
 * when a breakpoint is triggered.
 */
class GenericNativeSource : public TaintSource , public BreakpointHandler {
public:
    GenericNativeSource(TaintValues tainted_values);

    virtual void on_breakpoint(Debugger &d, Process &p) override;

protected:
    /**
     * Reigsters and memory regions that are considered to be tainted on breakpoint hit
     */
    TaintValues tainted_values_;
};

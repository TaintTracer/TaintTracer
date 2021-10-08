#pragma once
#include <debugger/breakpoint/BreakpointHandler.h>
#include <debugger/taint/TaintValues.h>

class GenericNativeSink : public BreakpointHandler {
public:
    virtual void on_breakpoint(Debugger &d, Process &p);

    GenericNativeSink(TaintValues tainted_values_to_check);

protected:
    /**
     * Reigsters and memory regions that is checked for tainted values.
     * Tainted data flows towards this sink if any of the values described by this variable
     * contain tainted data.
     */
    TaintValues tainted_values_to_check_;
};
